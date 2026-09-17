//! AES-128 block cipher abstraction (R23.2 Annex B.1.1).
//!
//! Hardware AES engines implement [`BlockCipher`]; the `crypto-software`
//! feature provides [`SoftwareAes`] built on the RustCrypto `aes` crate.

use panweave_types::Key128;

/// A 128-bit block cipher keyed with a 128-bit key.
///
/// Implementations must be constant time with respect to key and data.
pub trait BlockCipher {
    /// Creates a cipher instance keyed with `key`.
    fn new(key: &Key128) -> Self;

    /// Encrypts one 16-octet block in place.
    fn encrypt_block(&self, block: &mut [u8; 16]);
}

/// Software AES-128 from the RustCrypto project.
#[cfg(feature = "crypto-software")]
#[derive(Clone)]
pub struct SoftwareAes(aes::Aes128);

#[cfg(feature = "crypto-software")]
impl BlockCipher for SoftwareAes {
    fn new(key: &Key128) -> Self {
        use cipher::KeyInit;
        SoftwareAes(aes::Aes128::new(key.as_bytes().into()))
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        use cipher::BlockCipherEncrypt;
        self.0.encrypt_block(block.into());
    }
}

#[cfg(feature = "crypto-software")]
impl core::fmt::Debug for SoftwareAes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SoftwareAes([REDACTED])")
    }
}

/// A cipher that can be constructed from a key without generic plumbing
/// at every call site.
pub trait CipherProvider {
    /// The cipher type.
    type Cipher: BlockCipher;
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;

    #[test]
    fn fips197_known_answer() {
        // FIPS-197 Appendix C.1: AES-128 key 000102..0f, plaintext
        // 00112233..ff → 69c4e0d86a7b0430d8cdb78070b4c55a.
        let key = Key128::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let c = SoftwareAes::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        c.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }
}
