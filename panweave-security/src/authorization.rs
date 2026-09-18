//! Zigbee Direct authorization keys (ZD 1.1 §6.3.2.1, Table 2; R23.2
//! §4.6.3.2.2.4): a Trust Center or ZDD derives a Zigbee Direct Virtual
//! Device's Basic authorization key from its EUI-64 and the network key,
//! and its Admin authorization key from its EUI-64 and the ZDD's Trust
//! Center link key, as `KDF(H(IEEE || key), {instance})` over
//! AES-MMO-128 / HMAC-AES-MMO-128 (R23.2 Annex J).

use panweave_types::{ExtendedAddress, Key128};

use crate::cipher::BlockCipher;
use crate::mmo;

/// KDF instance of the Basic authorization key.
pub const BASIC_INSTANCE: u8 = 0x03;
/// KDF instance of the Admin authorization key.
pub const ADMIN_INSTANCE: u8 = 0x04;

fn derive<C: BlockCipher>(zvd: ExtendedAddress, key: &Key128, instance: u8) -> Key128 {
    let mut input = [0u8; 24];
    input[..8].copy_from_slice(&zvd.0.to_le_bytes());
    input[8..].copy_from_slice(key.as_bytes());
    let s = mmo::hash::<C>(&input);
    Key128::from_bytes(mmo::hmac::<C>(&s, &[instance]))
}

/// The Basic authorization key of `zvd` for a network with `nwk_key`.
pub fn basic_key<C: BlockCipher>(zvd: ExtendedAddress, nwk_key: &Key128) -> Key128 {
    derive::<C>(zvd, nwk_key, BASIC_INSTANCE)
}

/// The Admin authorization key of `zvd` derived from the ZDD's Trust
/// Center link key.
pub fn admin_key<C: BlockCipher>(zvd: ExtendedAddress, tc_link_key: &Key128) -> Key128 {
    derive::<C>(zvd, tc_link_key, ADMIN_INSTANCE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::SoftwareAes;

    /// ZD 1.1 Annex B.3.
    #[test]
    fn annex_b3_vectors() {
        let zvd = ExtendedAddress(0x001F_EE00_0000_0001);
        let nwk = Key128::from_bytes([
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ]);
        assert_eq!(
            basic_key::<SoftwareAes>(zvd, &nwk).as_bytes(),
            &[
                0x5e, 0xe6, 0x7a, 0xdc, 0x0b, 0xa6, 0xeb, 0xd8, 0xaf, 0x0c, 0xb0, 0x43, 0xf2, 0x78,
                0x3c, 0xe9
            ]
        );
    }
}
