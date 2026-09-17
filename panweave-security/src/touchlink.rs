//! Touchlink network key transport (ZCL8 §13.3.4.11): the key index
//! algorithms that protect the network key inside Network Start / Join
//! inter-PAN commands. Index 0 (development) keys AES-ECB directly with
//! `"PhLi" || TrID || "CLSN" || RsID`; indices 4 (master) and 15
//! (certification) derive a transport key by encrypting the expanded
//! `TrID || TrID || RsID || RsID` with the touchlink key and then encrypt
//! the network key with it. The master key is a licensed secret the
//! application supplies; the certification key is public.

use panweave_types::Key128;

use crate::cipher::BlockCipher;

/// Key index of the development key (§13.3.4.11.4).
pub const KEY_INDEX_DEVELOPMENT: u8 = 0;
/// Key index of the master key (§13.3.4.11.5.1.1).
pub const KEY_INDEX_MASTER: u8 = 4;
/// Key index of the certification key (§13.3.4.11.5.1.2).
pub const KEY_INDEX_CERTIFICATION: u8 = 15;

/// The certification key (§13.3.4.11.5.1.2).
pub const CERTIFICATION_KEY: Key128 = Key128::from_bytes([
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
]);

/// The certification pre-installed link key used during classical
/// joining of touchlink devices (§13.3.4.11.2).
pub const CERTIFICATION_LINK_KEY: Key128 = Key128::from_bytes([
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
]);

/// The AES key of the development algorithm (§13.3.4.11.4).
fn development_key(transaction: u32, response: u32) -> Key128 {
    let mut k = [0u8; 16];
    k[..4].copy_from_slice(b"PhLi");
    k[4..8].copy_from_slice(&transaction.to_be_bytes());
    k[8..12].copy_from_slice(b"CLSN");
    k[12..].copy_from_slice(&response.to_be_bytes());
    Key128::from_bytes(k)
}

/// The transport key of the master / certification algorithm
/// (§13.3.4.11.5.2.3 steps 1–2).
pub fn transport_key<C: BlockCipher>(
    touchlink_key: &Key128,
    transaction: u32,
    response: u32,
) -> Key128 {
    // The §13.3.4.11.6 vectors expand 0x3eaa2009 as 3e aa 20 09: the
    // identifiers enter the block most significant octet first.
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&transaction.to_be_bytes());
    block[4..8].copy_from_slice(&transaction.to_be_bytes());
    block[8..12].copy_from_slice(&response.to_be_bytes());
    block[12..].copy_from_slice(&response.to_be_bytes());
    C::new(touchlink_key).encrypt_block(&mut block);
    Key128::from_bytes(block)
}

fn key_for<C: BlockCipher>(
    key_index: u8,
    master_key: Option<&Key128>,
    transaction: u32,
    response: u32,
) -> Option<Key128> {
    match key_index {
        KEY_INDEX_DEVELOPMENT => Some(development_key(transaction, response)),
        KEY_INDEX_CERTIFICATION => Some(transport_key::<C>(
            &CERTIFICATION_KEY,
            transaction,
            response,
        )),
        KEY_INDEX_MASTER => Some(transport_key::<C>(master_key?, transaction, response)),
        _ => None,
    }
}

/// Encrypts `network_key` for transport under `key_index`; the master
/// key (index 4) must be supplied. `None` for a reserved index or a
/// missing master key.
pub fn encrypt_network_key<C: BlockCipher>(
    key_index: u8,
    master_key: Option<&Key128>,
    transaction: u32,
    response: u32,
    network_key: &Key128,
) -> Option<[u8; 16]> {
    let k = key_for::<C>(key_index, master_key, transaction, response)?;
    let mut block = *network_key.as_bytes();
    C::new(&k).encrypt_block(&mut block);
    Some(block)
}

/// Decrypts a received encrypted network key (§13.3.4.11.5.2.2).
pub fn decrypt_network_key<C: BlockCipher>(
    key_index: u8,
    master_key: Option<&Key128>,
    transaction: u32,
    response: u32,
    encrypted: &[u8; 16],
) -> Option<Key128> {
    let k = key_for::<C>(key_index, master_key, transaction, response)?;
    let mut block = *encrypted;
    C::new(&k).decrypt_block(&mut block);
    Some(Key128::from_bytes(block))
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;
    use crate::cipher::SoftwareAes;

    const TRID: u32 = 0x3eaa_2009;
    const RSID: u32 = 0x8876_2fb1;
    const NWK: Key128 = Key128::from_bytes([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ]);
    const ENCRYPTED: [u8; 16] = [
        0x83, 0x22, 0x63, 0x68, 0x73, 0xa7, 0xbb, 0x2a, 0x18, 0x9a, 0x53, 0x70, 0x8c, 0x60, 0x7b,
        0xd0,
    ];

    #[test]
    fn certification_key_test_vectors() {
        // §13.3.4.11.6.1 / .2
        let t = transport_key::<SoftwareAes>(&CERTIFICATION_KEY, TRID, RSID);
        assert_eq!(
            t.as_bytes(),
            &[
                0x66, 0x9e, 0x08, 0xe4, 0x02, 0x77, 0xed, 0x9a, 0xb3, 0x6b, 0x25, 0x80, 0x45, 0x6b,
                0x41, 0x76
            ]
        );
        let e = encrypt_network_key::<SoftwareAes>(KEY_INDEX_CERTIFICATION, None, TRID, RSID, &NWK)
            .unwrap();
        assert_eq!(e, ENCRYPTED);
        let d = decrypt_network_key::<SoftwareAes>(
            KEY_INDEX_CERTIFICATION,
            None,
            TRID,
            RSID,
            &ENCRYPTED,
        )
        .unwrap();
        assert_eq!(d, NWK);
    }

    #[test]
    fn development_key_test_vector() {
        // §13.3.4.11.4 example: TrID 0xea9cd138, RsID 0x8f8dbab4.
        let k = development_key(0xea9c_d138, 0x8f8d_bab4);
        assert_eq!(
            k.as_bytes(),
            &[
                0x50, 0x68, 0x4c, 0x69, 0xea, 0x9c, 0xd1, 0x38, 0x43, 0x4c, 0x53, 0x4e, 0x8f, 0x8d,
                0xba, 0xb4
            ]
        );
        let encrypted = [
            0x48, 0x3c, 0x2b, 0x19, 0x7c, 0x27, 0xc3, 0xcc, 0x76, 0xa3, 0xd6, 0x3b, 0x2e, 0xa8,
            0xdb, 0x0b,
        ];
        let d = decrypt_network_key::<SoftwareAes>(
            KEY_INDEX_DEVELOPMENT,
            None,
            0xea9c_d138,
            0x8f8d_bab4,
            &encrypted,
        )
        .unwrap();
        assert_eq!(
            d.as_bytes(),
            &[
                0xac, 0xbe, 0xf1, 0x44, 0x70, 0x27, 0xd8, 0xd9, 0x5a, 0xfa, 0x42, 0xb0, 0x77, 0xe4,
                0x88, 0xa5
            ]
        );
    }

    #[test]
    fn master_key_requires_the_secret_and_reserved_indices_fail() {
        assert!(
            encrypt_network_key::<SoftwareAes>(KEY_INDEX_MASTER, None, TRID, RSID, &NWK).is_none()
        );
        let master = Key128::from_bytes([9; 16]);
        let e =
            encrypt_network_key::<SoftwareAes>(KEY_INDEX_MASTER, Some(&master), TRID, RSID, &NWK)
                .unwrap();
        let d = decrypt_network_key::<SoftwareAes>(KEY_INDEX_MASTER, Some(&master), TRID, RSID, &e)
            .unwrap();
        assert_eq!(d, NWK);
        assert!(encrypt_network_key::<SoftwareAes>(7, Some(&master), TRID, RSID, &NWK).is_none());
    }
}
