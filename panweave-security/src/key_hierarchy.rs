//! Key derivation (R23.2 §4.5.3, BDB3.1 §6.11.1.2).
//!
//! * Key-transport key: `HMAC(link_key, 0x00)`.
//! * Key-load key: `HMAC(link_key, 0x02)`.
//! * Data key: the link key itself.
//! * Pre-configured link key from an install code: `AES-MMO(code || crc)`.
//! * Verify-key hash (§4.4.11.7): `HMAC(link_key, 0x03)`.

use panweave_types::{InstallCode, Key128};
use zeroize::Zeroize;

use crate::cipher::BlockCipher;
use crate::mmo;

/// Input octet for the key-transport key derivation.
const KEY_TRANSPORT_INPUT: [u8; 1] = [0x00];
/// Input octet for the key-load key derivation.
const KEY_LOAD_INPUT: [u8; 1] = [0x02];
/// Input octet for the Verify Key hash (R23.2 §4.4.11.7).
const VERIFY_KEY_INPUT: [u8; 1] = [0x03];

/// Derives the key-transport key from a link key.
pub fn key_transport_key<C: BlockCipher>(link_key: &Key128) -> Key128 {
    let mut h = mmo::hmac::<C>(link_key.as_bytes(), &KEY_TRANSPORT_INPUT);
    let k = Key128::from_bytes(h);
    h.zeroize();
    k
}

/// Derives the key-load key from a link key.
pub fn key_load_key<C: BlockCipher>(link_key: &Key128) -> Key128 {
    let mut h = mmo::hmac::<C>(link_key.as_bytes(), &KEY_LOAD_INPUT);
    let k = Key128::from_bytes(h);
    h.zeroize();
    k
}

/// Computes the Verify Key hash carried in the Verify Key command: the
/// keyed hash of the constant 0x03 under the link key (R23.2 §4.4.11.7).
pub fn verify_key_hash<C: BlockCipher>(link_key: &Key128) -> [u8; 16] {
    mmo::hmac::<C>(link_key.as_bytes(), &VERIFY_KEY_INPUT)
}

/// Derives the pre-configured Trust Center link key from an install code
/// (including its CRC), BDB3.1 §6.11.1.2. The CRC must have been validated
/// by the caller.
pub fn link_key_from_install_code<C: BlockCipher>(code: &InstallCode) -> Key128 {
    let mut h = mmo::hash::<C>(code.as_bytes());
    let k = Key128::from_bytes(h);
    h.zeroize();
    k
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;
    use crate::cipher::SoftwareAes;

    #[test]
    fn install_code_known_answer_from_bdb() {
        let bytes = [
            0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16,
            0xD5, 0x05, 0xC3, 0xB5,
        ];
        let ic = InstallCode::new(&bytes).unwrap();
        assert!(ic.crc_valid());
        let key = link_key_from_install_code::<SoftwareAes>(&ic);
        assert_eq!(
            key.as_bytes(),
            &[
                0x66, 0xB6, 0x90, 0x09, 0x81, 0xE1, 0xEE, 0x3C, 0xA4, 0x20, 0x6B, 0x6B, 0x86, 0x1C,
                0x02, 0xBB
            ]
        );
    }

    #[test]
    fn derived_keys_differ_and_are_deterministic() {
        let lk = Key128::WELL_KNOWN_GLOBAL_TCLK;
        let kt = key_transport_key::<SoftwareAes>(&lk);
        let kl = key_load_key::<SoftwareAes>(&lk);
        assert_ne!(kt, kl);
        assert_ne!(kt, lk);
        assert_eq!(kt, key_transport_key::<SoftwareAes>(&lk));
        // Hashed "ZigBeeAlliance09" key-transport key is a widely published
        // interoperability value.
        assert_eq!(
            kt.as_bytes(),
            &[
                0x4B, 0xAB, 0x0F, 0x17, 0x3E, 0x14, 0x34, 0xA2, 0xD5, 0x72, 0xE1, 0xC1, 0xEF, 0x47,
                0x87, 0x82
            ]
        );
    }
}
