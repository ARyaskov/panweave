//! Dynamic Link Key negotiation: ECDHE / SPEKE over Curve25519 with
//! AES-MMO-128 and HMAC-AES-MMO-128 (R23.2 §4.4.9, Annex J.1).
//!
//! Protocol summary (Annex J.1.3):
//!
//! 1. Both parties derive the generator `G = H*(PSK)` where `H*` is the
//!    128-bit AES-MMO digest repeated to 256 bits.
//! 2. Each party draws a random 32-octet scalar, clamps it per X25519 and
//!    computes its public point `Q = X25519(d, G)`.
//! 3. After exchanging `(A, Q)` the shared x-coordinate is
//!    `xk = X25519(d_local, Q_remote)`.
//! 4. The session identifier `I` is `A_low || Q_low || A_high || Q_high`
//!    ordered by the EUI-64 integer values (little-endian on the wire).
//! 5. `s = H(xk || I || G)` and the link key is `HMAC(s, 0x01)`.
//!
//! The anonymous variant uses the well-known PSK
//! [`WELL_KNOWN_PSK`] ("ZigBeeAlliance18"). Verified against the Annex
//! C.7.1 vectors. The SHA-256 variants and P-256 (Zigbee Direct) live in
//! `panweave-direct`.

use panweave_types::{CryptoRng, ExtendedAddress, Key128};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher::BlockCipher;
use crate::mmo;

/// `apscWellknownPSK` (R23.2 Table 4-37).
pub const WELL_KNOWN_PSK: &[u8; 16] = b"ZigBeeAlliance18";

/// Key negotiation method identifiers (Supported Key Negotiation Methods
/// TLV, R23.2 Annex I.4.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyNegotiationMethod {
    /// Static (symmetric) key request — no negotiation.
    StaticKeyRequest,
    /// SPEKE / Curve25519 / AES-MMO-128 / HMAC-AES-MMO-128.
    SpekeCurve25519AesMmo,
    /// SPEKE / Curve25519 / SHA-256 / HMAC-SHA-256.
    SpekeCurve25519Sha256,
    /// Unknown method bit.
    Unknown(u8),
}

impl KeyNegotiationMethod {
    /// Bit position in the Supported Key Negotiation Methods bitmask.
    pub const fn bit(self) -> u8 {
        match self {
            KeyNegotiationMethod::StaticKeyRequest => 0,
            KeyNegotiationMethod::SpekeCurve25519AesMmo => 1,
            KeyNegotiationMethod::SpekeCurve25519Sha256 => 2,
            KeyNegotiationMethod::Unknown(b) => b,
        }
    }
}

/// Errors during negotiation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DlkError {
    /// The remote public point yields a non-contributory (all-zero)
    /// shared secret (Annex J.1.4).
    NonContributory,
    /// A public point of the wrong length was supplied.
    InvalidPoint,
}

/// Derives the SPEKE generator `G = H*(PSK)` for AES-MMO-128.
pub fn generator<C: BlockCipher>(psk: &[u8]) -> [u8; 32] {
    let h = mmo::hash::<C>(psk);
    let mut g = [0u8; 32];
    g[..16].copy_from_slice(&h);
    g[16..].copy_from_slice(&h);
    g
}

/// Ephemeral key pair for one negotiation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ephemeral {
    secret: [u8; 32],
    #[zeroize(skip)]
    public: [u8; 32],
    #[zeroize(skip)]
    generator: [u8; 32],
}

impl Ephemeral {
    /// Generates a fresh ephemeral scalar from `rng` and computes the
    /// public point on the PSK-derived generator.
    pub fn generate<C: BlockCipher, R: CryptoRng>(rng: &mut R, psk: &[u8]) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self::from_secret::<C>(secret, psk)
    }

    /// Builds from a fixed scalar (test vectors, deterministic tests).
    pub fn from_secret<C: BlockCipher>(secret: [u8; 32], psk: &[u8]) -> Self {
        let generator = generator::<C>(psk);
        let public = x25519_dalek::x25519(secret, generator);
        Ephemeral {
            secret,
            public,
            generator,
        }
    }

    /// The public point to send to the peer.
    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// Completes the exchange with the peer's identity and public point.
    ///
    /// `local` / `remote` identify this device and the peer; the roles
    /// (initiator / responder) do not affect the derivation because the
    /// session identifier orders the pairs by EUI-64 value.
    pub fn derive<C: BlockCipher>(
        &self,
        local: ExtendedAddress,
        remote: ExtendedAddress,
        remote_public: &[u8],
    ) -> Result<Key128, DlkError> {
        let remote_public: [u8; 32] = remote_public
            .try_into()
            .map_err(|_| DlkError::InvalidPoint)?;
        let mut xk = x25519_dalek::x25519(self.secret, remote_public);
        if xk.iter().all(|b| *b == 0) {
            return Err(DlkError::NonContributory);
        }
        // Session identifier: (A, Q) pairs ordered by address value.
        let (first_a, first_q, second_a, second_q) = if local.0 < remote.0 {
            (local, &self.public, remote, &remote_public)
        } else {
            (remote, &remote_public, local, &self.public)
        };
        let mut h = mmo::MmoHasher::<C>::new();
        h.update(&xk);
        h.update(&first_a.to_le_bytes());
        h.update(first_q);
        h.update(&second_a.to_le_bytes());
        h.update(second_q);
        h.update(&self.generator);
        let mut s = h.finalize();
        let mut lk = mmo::hmac::<C>(&s, &[0x01]);
        let key = Key128::from_bytes(lk);
        xk.zeroize();
        s.zeroize();
        lk.zeroize();
        Ok(key)
    }
}

impl core::fmt::Debug for Ephemeral {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ephemeral([REDACTED])")
    }
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;
    use crate::cipher::SoftwareAes;

    const ALICE_SECRET: [u8; 32] = *b"AliceAliceAliceAliceAliceAliceAl";
    const BOB_SECRET: [u8; 32] = *b"BobBobBobBobBobBobBobBobBobBobBo";
    // EUI-64 A0:A0:0A:0A:A0:A0:00:AA is stored little-endian on the wire as
    // AA 00 A0 A0 0A 0A A0 A0, so the integer value is 0xA0A00A0AA0A000AA.
    const ALICE: ExtendedAddress = ExtendedAddress(0xA0A0_0A0A_A0A0_00AA);
    const BOB: ExtendedAddress = ExtendedAddress(0xB0B0_0B0B_B0B0_00BB);

    #[test]
    fn annex_c7_1_1_well_known_psk_vector() {
        let g = generator::<SoftwareAes>(WELL_KNOWN_PSK);
        assert_eq!(
            &g[..16],
            &[
                0x90, 0x2B, 0x44, 0x85, 0xC8, 0x4E, 0xC4, 0xA0, 0x59, 0x44, 0xAB, 0x34, 0x42, 0x92,
                0x68, 0x78
            ]
        );
        let alice = Ephemeral::from_secret::<SoftwareAes>(ALICE_SECRET, WELL_KNOWN_PSK);
        let bob = Ephemeral::from_secret::<SoftwareAes>(BOB_SECRET, WELL_KNOWN_PSK);
        assert_eq!(
            alice.public(),
            &[
                0xBA, 0xBB, 0xC4, 0xD7, 0x85, 0x6A, 0xBF, 0x56, 0x1B, 0xB4, 0x37, 0x8F, 0xD9, 0xFD,
                0x24, 0x92, 0xC1, 0xEA, 0x16, 0x02, 0x1B, 0x90, 0xD6, 0x1F, 0xCE, 0x3A, 0x96, 0x5B,
                0x04, 0x1C, 0xA2, 0x59
            ]
        );
        assert_eq!(
            bob.public(),
            &[
                0x47, 0x7D, 0xC0, 0x5F, 0xF5, 0x42, 0xAC, 0x83, 0xAD, 0xDF, 0x2B, 0x87, 0x87, 0x11,
                0x92, 0xDC, 0x6C, 0x59, 0x6A, 0xC5, 0x40, 0xC8, 0xD3, 0x5A, 0xFB, 0x7E, 0xC7, 0x25,
                0x9A, 0x71, 0x5B, 0x6C
            ]
        );
        let ka = alice
            .derive::<SoftwareAes>(ALICE, BOB, bob.public())
            .unwrap();
        let kb = bob
            .derive::<SoftwareAes>(BOB, ALICE, alice.public())
            .unwrap();
        assert_eq!(ka, kb);
        assert_eq!(
            ka.as_bytes(),
            &[
                0x25, 0x47, 0xF3, 0xAF, 0x96, 0x39, 0x1E, 0x1E, 0xBF, 0xF2, 0xA3, 0xB7, 0x6D, 0x6A,
                0x29, 0x29
            ]
        );
    }

    #[test]
    fn annex_c7_1_2_passphrase_vector_generator() {
        // The vector text prints two different generators; the AES-MMO
        // definition (H*(x) = H(x) || H(x)) gives the first one.
        let g = generator::<SoftwareAes>(b"ZigBeeAlliance20");
        assert_eq!(
            &g[..16],
            &[
                0xDE, 0xE6, 0x39, 0xE5, 0xFF, 0xF9, 0x46, 0xD7, 0xB1, 0x00, 0xCC, 0x5F, 0x3F, 0x9C,
                0xE8, 0x9C
            ]
        );
        assert_eq!(&g[16..], &g[..16]);
    }

    #[test]
    fn non_contributory_points_are_rejected() {
        let alice = Ephemeral::from_secret::<SoftwareAes>(ALICE_SECRET, WELL_KNOWN_PSK);
        let zero = [0u8; 32];
        assert_eq!(
            alice.derive::<SoftwareAes>(ALICE, BOB, &zero),
            Err(DlkError::NonContributory)
        );
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(
            alice.derive::<SoftwareAes>(ALICE, BOB, &one),
            Err(DlkError::NonContributory)
        );
        assert_eq!(
            alice.derive::<SoftwareAes>(ALICE, BOB, &[1, 2, 3]),
            Err(DlkError::InvalidPoint)
        );
    }

    #[test]
    fn random_ephemerals_agree() {
        struct FakeCrypto(panweave_types::rng::DeterministicRng);
        impl panweave_types::Rng for FakeCrypto {
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                self.0.fill_bytes(dest);
            }
        }
        // Test-only: the marker is asserted for a deterministic generator.
        impl CryptoRng for FakeCrypto {}
        let mut rng = FakeCrypto(panweave_types::rng::DeterministicRng::seed(1));
        let psk = b"secret-passphrase";
        let a = Ephemeral::generate::<SoftwareAes, _>(&mut rng, psk);
        let b = Ephemeral::generate::<SoftwareAes, _>(&mut rng, psk);
        let ka = a.derive::<SoftwareAes>(ALICE, BOB, b.public()).unwrap();
        let kb = b.derive::<SoftwareAes>(BOB, ALICE, a.public()).unwrap();
        assert_eq!(ka, kb);
        // A different passphrase yields a different key (both sides).
        let c = Ephemeral::generate::<SoftwareAes, _>(&mut rng, b"other");
        let kc = c.derive::<SoftwareAes>(BOB, ALICE, a.public()).unwrap();
        assert_ne!(kc, ka);
    }
}
