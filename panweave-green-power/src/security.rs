//! GP stub security (GP Basic 1.1.2 §A.1.5.3, §A.3.7.1.2): CCM* with a
//! 4-octet MIC over the GP stub NWK header, the AES nonce built from the
//! GPD identity, key derivation of the NWK-key derived group key and the
//! individual GPD keys (HMAC with AES-MMO), and the TC-LK protection of a
//! GPD key exchanged in the Commissioning / Commissioning Reply GPDFs.

use panweave_security::ccm::{self, CcmError};
use panweave_security::cipher::BlockCipher;
use panweave_security::mmo;
use panweave_types::Key128;

use crate::gpdf::{ApplicationId, GpdId, MIC_LEN, SecurityLevel};

/// Direction of a protected GPDF relative to the GPD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Direction {
    /// Sent by the GPD (incoming at a proxy / sink).
    FromGpd,
    /// Sent to the GPD by a proxy / sink.
    ToGpd,
}

/// gpSecurityKeyType (Table 53).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyType {
    /// 0b000: no key.
    #[default]
    None,
    /// 0b001: the Zigbee NWK key.
    NwkKey,
    /// 0b010: the GPD group key.
    GroupKey,
    /// 0b011: the NWK-key derived GPD group key.
    NwkDerivedGroupKey,
    /// 0b100: an out-of-the-box individual GPD key.
    Individual,
    /// 0b111: an individual key derived from the group key.
    DerivedIndividual,
}

impl KeyType {
    /// Raw 3-bit value.
    pub const fn raw(self) -> u8 {
        match self {
            KeyType::None => 0b000,
            KeyType::NwkKey => 0b001,
            KeyType::GroupKey => 0b010,
            KeyType::NwkDerivedGroupKey => 0b011,
            KeyType::Individual => 0b100,
            KeyType::DerivedIndividual => 0b111,
        }
    }

    /// From the raw value; 0b101–0b110 are reserved.
    pub const fn from_raw(v: u8) -> Option<Self> {
        match v & 0x07 {
            0b000 => Some(KeyType::None),
            0b001 => Some(KeyType::NwkKey),
            0b010 => Some(KeyType::GroupKey),
            0b011 => Some(KeyType::NwkDerivedGroupKey),
            0b100 => Some(KeyType::Individual),
            0b111 => Some(KeyType::DerivedIndividual),
            _ => None,
        }
    }

    /// The SecurityKey sub-field value this key type maps to (Table 12):
    /// true for the individual key types.
    pub const fn is_individual(self) -> bool {
        matches!(self, KeyType::Individual | KeyType::DerivedIndividual)
    }
}

/// The AES nonce of a GPDF (§A.1.5.3.2).
pub fn nonce(gpd: &GpdId, frame_counter: u32, direction: Direction) -> [u8; 13] {
    let mut n = [0u8; 13];
    match (gpd, direction) {
        (GpdId::SrcId(s), Direction::FromGpd) => {
            n[..4].copy_from_slice(&s.to_le_bytes());
            n[4..8].copy_from_slice(&s.to_le_bytes());
        }
        (GpdId::SrcId(s), Direction::ToGpd) => {
            n[4..8].copy_from_slice(&s.to_le_bytes());
        }
        (GpdId::Ieee { address, .. }, _) => {
            n[..8].copy_from_slice(&address.0.to_le_bytes());
        }
    }
    n[8..12].copy_from_slice(&frame_counter.to_le_bytes());
    // Security control: level 0b101, key id 0, no extended nonce, and the
    // reserved bits set for frames to an IEEE-addressed GPD.
    n[12] = match (gpd.application_id(), direction) {
        (ApplicationId::Ieee, Direction::ToGpd) => 0xC5,
        _ => 0x05,
    };
    n
}

/// Security processing failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityError {
    /// The MIC did not verify.
    AuthFailed,
    /// Unsupported parameters (level 0b00, oversize frame).
    Invalid,
}

impl From<CcmError> for SecurityError {
    fn from(e: CcmError) -> Self {
        match e {
            CcmError::AuthenticationFailed => SecurityError::AuthFailed,
            _ => SecurityError::Invalid,
        }
    }
}

/// Protects an outgoing application payload in place (§A.1.5.3.4):
/// `header` is the GP stub NWK header, `payload` the CommandID and
/// payload (encrypted in place for level 0b11); returns the MIC.
pub fn protect<C: BlockCipher>(
    key: &Key128,
    level: SecurityLevel,
    gpd: &GpdId,
    frame_counter: u32,
    direction: Direction,
    header: &[u8],
    payload: &mut [u8],
) -> Result<[u8; MIC_LEN], SecurityError> {
    let cipher = C::new(key);
    let n = nonce(gpd, frame_counter, direction);
    let mut mic = [0u8; MIC_LEN];
    match level {
        SecurityLevel::None => return Err(SecurityError::Invalid),
        SecurityLevel::Mic => {
            let mut aad = [0u8; 128];
            let total = header.len() + payload.len();
            let a = aad.get_mut(..total).ok_or(SecurityError::Invalid)?;
            a.get_mut(..header.len())
                .ok_or(SecurityError::Invalid)?
                .copy_from_slice(header);
            a.get_mut(header.len()..)
                .ok_or(SecurityError::Invalid)?
                .copy_from_slice(payload);
            let mut empty: [u8; 0] = [];
            ccm::encrypt_in_place(&cipher, &n, a, &mut empty, &mut mic)?;
        }
        SecurityLevel::EncryptedMic => {
            ccm::encrypt_in_place(&cipher, &n, header, payload, &mut mic)?;
        }
    }
    Ok(mic)
}

/// Checks and, for level 0b11, decrypts an incoming application payload
/// in place (§A.1.5.3.5). On failure the payload is left untouched for
/// level 0b10 and zeroed for level 0b11 (no unauthenticated plaintext).
pub fn unprotect<C: BlockCipher>(
    key: &Key128,
    level: SecurityLevel,
    gpd: &GpdId,
    frame_counter: u32,
    direction: Direction,
    header: &[u8],
    payload: &mut [u8],
    mic: &[u8; MIC_LEN],
) -> Result<(), SecurityError> {
    let cipher = C::new(key);
    let n = nonce(gpd, frame_counter, direction);
    match level {
        SecurityLevel::None => Err(SecurityError::Invalid),
        SecurityLevel::Mic => {
            let mut aad = [0u8; 128];
            let total = header.len() + payload.len();
            let a = aad.get_mut(..total).ok_or(SecurityError::Invalid)?;
            a.get_mut(..header.len())
                .ok_or(SecurityError::Invalid)?
                .copy_from_slice(header);
            a.get_mut(header.len()..)
                .ok_or(SecurityError::Invalid)?
                .copy_from_slice(payload);
            let mut empty: [u8; 0] = [];
            ccm::decrypt_in_place(&cipher, &n, a, &mut empty, mic)?;
            Ok(())
        }
        SecurityLevel::EncryptedMic => {
            ccm::decrypt_in_place(&cipher, &n, header, payload, mic)?;
            Ok(())
        }
    }
}

/// The NWK-key derived GPD group key (§A.3.7.1.2.1): HMAC(NWK key, "ZGP").
pub fn derive_group_key<C: BlockCipher>(nwk_key: &Key128) -> Key128 {
    Key128::from_bytes(mmo::hmac::<C>(nwk_key.as_bytes(), b"ZGP"))
}

/// The individual GPD key derived from the group key (§A.3.7.1.2.2):
/// HMAC(group key, SrcID or IEEE address, little endian).
pub fn derive_individual_key<C: BlockCipher>(group_key: &Key128, gpd: &GpdId) -> Key128 {
    match gpd {
        GpdId::SrcId(s) => {
            Key128::from_bytes(mmo::hmac::<C>(group_key.as_bytes(), &s.to_le_bytes()))
        }
        GpdId::Ieee { address, .. } => Key128::from_bytes(mmo::hmac::<C>(
            group_key.as_bytes(),
            &address.0.to_le_bytes(),
        )),
    }
}

/// Nonce and header of the TC-LK protection of a GPD key
/// (§A.3.7.1.2.3).
fn key_transport_params(
    gpd: &GpdId,
    direction: Direction,
    reply_frame_counter: u32,
) -> ([u8; 13], [u8; 4]) {
    let (id32, header) = match gpd {
        GpdId::SrcId(s) => (*s, s.to_le_bytes()),
        GpdId::Ieee { address, .. } => {
            let low = (address.0 & 0xFFFF_FFFF) as u32;
            (low, low.to_le_bytes())
        }
    };
    let counter = match direction {
        Direction::FromGpd => id32,
        Direction::ToGpd => reply_frame_counter.wrapping_add(1),
    };
    (nonce(gpd, counter, direction), header)
}

/// Protects a GPD key with the gpLinkKey for the Commissioning GPDF
/// (`FromGpd`) or the Commissioning Reply (`ToGpd`, with the frame
/// counter of the GPDF that triggered the reply); returns the protected
/// key and its MIC (§A.3.7.1.2.3).
pub fn protect_gpd_key<C: BlockCipher>(
    link_key: &Key128,
    gpd: &GpdId,
    direction: Direction,
    reply_frame_counter: u32,
    key: &Key128,
) -> Result<([u8; 16], [u8; MIC_LEN]), SecurityError> {
    let (n, header) = key_transport_params(gpd, direction, reply_frame_counter);
    let cipher = C::new(link_key);
    let mut buf = *key.as_bytes();
    let mut mic = [0u8; MIC_LEN];
    ccm::encrypt_in_place(&cipher, &n, &header, &mut buf, &mut mic)?;
    Ok((buf, mic))
}

/// Recovers a TC-LK protected GPD key (§A.3.7.1.2.3).
pub fn unprotect_gpd_key<C: BlockCipher>(
    link_key: &Key128,
    gpd: &GpdId,
    direction: Direction,
    reply_frame_counter: u32,
    protected: &[u8; 16],
    mic: &[u8; MIC_LEN],
) -> Result<Key128, SecurityError> {
    let (n, header) = key_transport_params(gpd, direction, reply_frame_counter);
    let cipher = C::new(link_key);
    let mut buf = *protected;
    ccm::decrypt_in_place(&cipher, &n, &header, &mut buf, mic)?;
    Ok(Key128::from_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    const KEY: Key128 = Key128::from_bytes([
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF,
    ]);
    const GPD: GpdId = GpdId::SrcId(0x8765_4321);

    #[test]
    fn nonce_vectors() {
        // §A.1.5.4.2.3.
        assert_eq!(
            nonce(&GPD, 2, Direction::FromGpd),
            [
                0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00, 0x05
            ]
        );
        // §A.1.5.3.2 outgoing example.
        assert_eq!(
            nonce(&GPD, 2, Direction::ToGpd)[..8],
            [0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x65, 0x87]
        );
    }

    #[test]
    fn level_2_and_3_vectors_from_the_gpd() {
        // §A.1.5.4.2: MIC over header || payload.
        let header = [0x8c, 0x10, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00];
        let mut payload = [0x20];
        let mic = protect::<SoftwareAes>(
            &KEY,
            SecurityLevel::Mic,
            &GPD,
            2,
            Direction::FromGpd,
            &header,
            &mut payload,
        )
        .unwrap();
        assert_eq!(mic, [0xCF, 0x78, 0x7E, 0x72]);
        assert_eq!(payload, [0x20]);
        unprotect::<SoftwareAes>(
            &KEY,
            SecurityLevel::Mic,
            &GPD,
            2,
            Direction::FromGpd,
            &header,
            &mut payload,
            &mic,
        )
        .unwrap();
        // §A.1.5.4.3: encrypted.
        let header = [0x8c, 0x18, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00];
        let mut payload = [0x20];
        let mic = protect::<SoftwareAes>(
            &KEY,
            SecurityLevel::EncryptedMic,
            &GPD,
            2,
            Direction::FromGpd,
            &header,
            &mut payload,
        )
        .unwrap();
        assert_eq!(mic, [0xCA, 0x43, 0x24, 0xDD]);
        assert_eq!(payload, [0x83]);
        unprotect::<SoftwareAes>(
            &KEY,
            SecurityLevel::EncryptedMic,
            &GPD,
            2,
            Direction::FromGpd,
            &header,
            &mut payload,
            &mic,
        )
        .unwrap();
        assert_eq!(payload, [0x20]);
        // Tampered MIC fails and zeroes the plaintext.
        let mut payload = [0x83];
        let bad = [0xCA, 0x43, 0x24, 0xDE];
        assert_eq!(
            unprotect::<SoftwareAes>(
                &KEY,
                SecurityLevel::EncryptedMic,
                &GPD,
                2,
                Direction::FromGpd,
                &header,
                &mut payload,
                &bad,
            ),
            Err(SecurityError::AuthFailed)
        );
        assert_eq!(payload, [0]);
    }

    #[test]
    fn bidirectional_vectors() {
        // §A.1.5.6.2.1: outgoing Channel Configuration, level 0b10.
        let header = [0x8C, 0x90, 0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44];
        let mut payload = [0xF3, 0x00];
        let mic = protect::<SoftwareAes>(
            &KEY,
            SecurityLevel::Mic,
            &GPD,
            0x4433_2211,
            Direction::ToGpd,
            &header,
            &mut payload,
        )
        .unwrap();
        assert_eq!(mic, [0xCC, 0xA0, 0xBB, 0x2E]);
        // §A.1.5.6.2.2: outgoing, encrypted.
        let header = [0x8C, 0x98, 0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44];
        let mut payload = [0xF3, 0x00];
        let mic = protect::<SoftwareAes>(
            &KEY,
            SecurityLevel::EncryptedMic,
            &GPD,
            0x4433_2211,
            Direction::ToGpd,
            &header,
            &mut payload,
        )
        .unwrap();
        assert_eq!(payload, [0x9E, 0x7E]);
        assert_eq!(mic, [0x14, 0x0F, 0xB5, 0xDA]);
        // Incoming with RxAfterTx, level 0b11 (§A.1.5.6.2.2).
        let header = [0x8C, 0x58, 0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44];
        let mut payload = [0x2A];
        unprotect::<SoftwareAes>(
            &KEY,
            SecurityLevel::EncryptedMic,
            &GPD,
            0x4433_2211,
            Direction::FromGpd,
            &header,
            &mut payload,
            &[0x3D, 0x17, 0x0A, 0xAA],
        )
        .unwrap();
        assert_eq!(payload, [0x20]);
    }

    #[test]
    fn key_derivation_vectors() {
        // §A.1.5.7.1.
        let nwk = Key128::from_bytes([
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a,
            0x0c, 0x0d,
        ]);
        assert_eq!(
            derive_group_key::<SoftwareAes>(&nwk).as_bytes(),
            &[
                0xBA, 0x88, 0x86, 0x7f, 0xc0, 0x09, 0x39, 0x87, 0xeb, 0x88, 0x64, 0xce, 0xbe, 0x5f,
                0xc6, 0x13
            ]
        );
        // §A.1.5.7.2.
        assert_eq!(
            derive_individual_key::<SoftwareAes>(&KEY, &GPD).as_bytes(),
            &[
                0x7a, 0x3a, 0x73, 0x43, 0x8d, 0x6e, 0x47, 0x55, 0x28, 0x81, 0xa0, 0x28, 0xad, 0x59,
                0x23, 0x2e
            ]
        );
    }

    #[test]
    fn tc_lk_protection_vectors() {
        // §A.1.5.8.1: OOB key in the Commissioning GPDF.
        let gpd = GpdId::SrcId(0x1234_5678);
        let tclk = Key128::WELL_KNOWN_GLOBAL_TCLK;
        let (protected, mic) =
            protect_gpd_key::<SoftwareAes>(&tclk, &gpd, Direction::FromGpd, 0, &KEY).unwrap();
        assert_eq!(
            protected,
            [
                0x7D, 0x17, 0x7B, 0xD2, 0x9E, 0xA0, 0xFD, 0xA6, 0xB0, 0x17, 0x03, 0x65, 0x87, 0xDC,
                0x26, 0x00
            ]
        );
        assert_eq!(mic, [0x61, 0xF1, 0x63, 0xA9]);
        let back =
            unprotect_gpd_key::<SoftwareAes>(&tclk, &gpd, Direction::FromGpd, 0, &protected, &mic)
                .unwrap();
        assert_eq!(back, KEY);
        // §A.1.5.8.2.
        let other = Key128::from_bytes([
            0x16, 0x68, 0x16, 0x68, 0x16, 0x68, 0x16, 0x68, 0x16, 0x68, 0x16, 0x68, 0x16, 0x68,
            0x16, 0x68,
        ]);
        let (protected, mic) =
            protect_gpd_key::<SoftwareAes>(&tclk, &gpd, Direction::FromGpd, 0, &other).unwrap();
        assert_eq!(
            protected,
            [
                0xAB, 0xBE, 0xAF, 0x79, 0x4C, 0x0D, 0x2D, 0x09, 0x6E, 0xB6, 0xDF, 0xC6, 0x5D, 0x79,
                0xFE, 0xA7
            ]
        );
        assert_eq!(mic, [0x67, 0x31, 0x42, 0x6A]);
        // §A.1.5.8.3: the reply nonce uses counter + 1.
        let (n, _) = key_transport_params(&gpd, Direction::ToGpd, 3);
        assert_eq!(
            n,
            [
                0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x04, 0x00, 0x00, 0x00, 0x05
            ]
        );
    }
}
