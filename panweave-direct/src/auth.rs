//! Authorization keys (ZD 1.1 §6.3.2.1, Table 2): the Basic key is
//! derived from the ZVD's EUI-64 and the network key, the Admin key from
//! the ZVD's EUI-64 and the ZDD's Trust Center link key, both with
//! `KDF(H(IEEE || key), {instance})` over AES-MMO-128 / HMAC-AES-MMO-128.

use panweave_security::cipher::BlockCipher;
use panweave_security::mmo;
use panweave_types::{ExtendedAddress, Key128};

/// KDF instance of the Basic authorization key.
pub const BASIC_INSTANCE: u8 = 0x03;
/// KDF instance of the Admin authorization key.
pub const ADMIN_INSTANCE: u8 = 0x04;

/// Authorization levels (§6.3.2.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Level {
    /// A provisioning session (Table 1 pre-shared secrets).
    Provisioning,
    /// Basic authorization: access to the network.
    Basic,
    /// Admin authorization: the Commissioning Service of a provisioned
    /// ZDD and access to the network.
    Admin,
}

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
/// Center link key (when no Admin key was provisioned).
pub fn admin_key<C: BlockCipher>(zvd: ExtendedAddress, tc_link_key: &Key128) -> Key128 {
    derive::<C>(zvd, tc_link_key, ADMIN_INSTANCE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    #[test]
    fn annex_b3_authorization_keys() {
        let zvd = ExtendedAddress(0x001F_EE00_0000_0001);
        let nwk = Key128::from_bytes([
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ]);
        let tclk = Key128::from_bytes([
            0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
            0xde, 0xdf,
        ]);
        assert_eq!(
            basic_key::<SoftwareAes>(zvd, &nwk).as_bytes(),
            &[
                0x5e, 0xe6, 0x7a, 0xdc, 0x0b, 0xa6, 0xeb, 0xd8, 0xaf, 0x0c, 0xb0, 0x43, 0xf2, 0x78,
                0x3c, 0xe9
            ]
        );
        assert_eq!(
            admin_key::<SoftwareAes>(zvd, &tclk).as_bytes(),
            &[
                0xa8, 0x3d, 0x8a, 0x58, 0x89, 0xc3, 0x03, 0x87, 0x75, 0xa0, 0xc3, 0x48, 0x05, 0x59,
                0x5c, 0x0a
            ]
        );
    }
}
