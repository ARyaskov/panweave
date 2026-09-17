//! APS frame counter synchronization challenge (R23.2 §4.6.3.8.2,
//! §4.6.3.8.3): the key and nonce derivation and the AES-CCM-128 MIC-64
//! that proves a responder's current outgoing APS frame counter.
//!
//! The MIC covers the APS Frame Counter Response TLV (tag, length,
//! responder EUI-64, challenge value, APS frame counter) with an empty
//! message. The key is the link key with octets 0, 4, 8 and 12 XORed
//! with the little-endian octets of the responder's outgoing APS frame
//! counter, and the nonce carries the responder address, the
//! `apsChallengeFrameCounter` and security level 2, so that several
//! challenges under the same outgoing counter never share a nonce.

use panweave_types::{ExtendedAddress, Key128};
use zeroize::Zeroize;

use crate::aux_header::{KeyIdentifier, SecurityControl, SecurityLevel};
use crate::ccm::{self, NONCE_LEN};
use crate::cipher::BlockCipher;

/// MIC length of a challenge response (security level 2).
pub const MIC_LEN: usize = 8;

/// The challenge key for `link_key` under `outgoing` (§4.6.3.8.2).
pub fn challenge_key(link_key: &Key128, outgoing: u32) -> Key128 {
    let mut k = [0u8; 16];
    k.copy_from_slice(link_key.as_bytes());
    let fc = outgoing.to_le_bytes();
    k[0] ^= fc[0];
    k[4] ^= fc[1];
    k[8] ^= fc[2];
    k[12] ^= fc[3];
    let key = Key128::from_bytes(k);
    k.zeroize();
    key
}

/// The challenge nonce: responder address, `apsChallengeFrameCounter`,
/// security control for level 2 (§4.6.3.8.2).
pub fn challenge_nonce(responder: ExtendedAddress, challenge_fc: u32) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..8].copy_from_slice(&responder.to_le_bytes());
    n[8..12].copy_from_slice(&challenge_fc.to_le_bytes());
    n[12] = SecurityControl {
        level: SecurityLevel::Mic64,
        key_id: KeyIdentifier::Data,
        extended_nonce: false,
    }
    .raw();
    n
}

/// Length of the authenticated octets of a response TLV (tag, length,
/// responder, challenge, APS frame counter).
pub const AUTHENTICATED_LEN: usize = 22;

/// The octets a response MIC covers: the APS Frame Counter Response TLV
/// header (tag 0, length octet of the 24-octet value) and its first
/// three fields (§2.4.4.4.8.2).
pub fn response_authenticated_octets(
    responder: ExtendedAddress,
    challenge: u64,
    aps_frame_counter: u32,
) -> [u8; AUTHENTICATED_LEN] {
    let mut a = [0u8; AUTHENTICATED_LEN];
    a[0] = 0;
    a[1] = 23;
    a[2..10].copy_from_slice(&responder.to_le_bytes());
    a[10..18].copy_from_slice(&challenge.to_le_bytes());
    a[18..22].copy_from_slice(&aps_frame_counter.to_le_bytes());
    a
}

/// Computes the MIC-64 over `authenticated` (the response TLV octets
/// without the MIC and challenge frame counter) for the responder's
/// `link_key`, `outgoing` counter and `challenge_fc` (§4.6.3.8.3).
pub fn challenge_mic<C: BlockCipher>(
    link_key: &Key128,
    outgoing: u32,
    responder: ExtendedAddress,
    challenge_fc: u32,
    authenticated: &[u8],
) -> [u8; MIC_LEN] {
    let key = challenge_key(link_key, outgoing);
    let cipher = C::new(&key);
    let nonce = challenge_nonce(responder, challenge_fc);
    let mut mic = [0u8; MIC_LEN];
    let mut empty: [u8; 0] = [];
    // Parameters are within CCM* limits: the failure branch is
    // unreachable for a 22-octet AAD and an empty message.
    let _ = ccm::encrypt_in_place(&cipher, &nonce, authenticated, &mut empty, &mut mic);
    mic
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;
    use crate::cipher::SoftwareAes;

    #[test]
    fn key_derivation_matches_the_worked_example() {
        // §4.6.3.8.2: counter 0x11223344 stored as {44 33 22 11}.
        let link = Key128::from_bytes([
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE,
            0xCF, 0xD0,
        ]);
        let k = challenge_key(&link, 0x1122_3344);
        assert_eq!(
            &k.as_bytes()[..16],
            &[
                0x84, 0xC1, 0xC2, 0xC3, 0xF7, 0xC5, 0xC6, 0xC7, 0xEA, 0xC9, 0xCA, 0xCB, 0xDC, 0xCE,
                0xCF, 0xD0
            ]
        );
    }

    #[test]
    fn mic_depends_on_every_input() {
        let link = Key128::from_bytes([7; 16]);
        let a = [1u8; 22];
        let m = challenge_mic::<SoftwareAes>(&link, 5, ExtendedAddress(1), 0, &a);
        assert_ne!(
            m,
            challenge_mic::<SoftwareAes>(&link, 6, ExtendedAddress(1), 0, &a)
        );
        assert_ne!(
            m,
            challenge_mic::<SoftwareAes>(&link, 5, ExtendedAddress(2), 0, &a)
        );
        assert_ne!(
            m,
            challenge_mic::<SoftwareAes>(&link, 5, ExtendedAddress(1), 1, &a)
        );
        let mut b = a;
        b[3] ^= 1;
        assert_ne!(
            m,
            challenge_mic::<SoftwareAes>(&link, 5, ExtendedAddress(1), 0, &b)
        );
        assert_eq!(
            m,
            challenge_mic::<SoftwareAes>(&link, 5, ExtendedAddress(1), 0, &a)
        );
    }
}
