//! AES-MMO (Matyas-Meyer-Oseas) hash and HMAC (R23.2 Annex B.4, B.1.4).
//!
//! The hash operates on octet strings (bit lengths that are multiples of
//! 8) shorter than 2^32 bits. Two padding schemes apply depending on
//! whether the input is shorter than 2^16 bits (8192 octets):
//!
//! * short inputs: append `0x80`, zero-pad to 14 mod 16 octets, append the
//!   16-bit bit-length;
//! * long inputs: append `0x80`, zero-pad to 10 mod 16 octets, append the
//!   32-bit bit-length and two zero octets.
//!
//! Verified against the Annex C.5 and C.6 vectors.

use panweave_types::Key128;
use zeroize::Zeroize;

use crate::cipher::BlockCipher;

/// Digest length in octets.
pub const HASH_LEN: usize = 16;

/// HMAC block size `B` for this hash (octets).
pub const HMAC_BLOCK_LEN: usize = 16;

/// Threshold in octets above which the long-message padding applies
/// (`2^16` bits).
const LONG_THRESHOLD_OCTETS: usize = 8192;

/// Copies `src` into the start of `dst`, ignoring excess on either side.
#[inline]
fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
    }
}

/// Incremental AES-MMO hasher.
pub struct MmoHasher<C: BlockCipher> {
    state: [u8; 16],
    buf: [u8; 16],
    buf_len: usize,
    total_len: usize,
    _cipher: core::marker::PhantomData<C>,
}

impl<C: BlockCipher> Default for MmoHasher<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: BlockCipher> MmoHasher<C> {
    /// Creates a hasher with the all-zero IV.
    pub const fn new() -> Self {
        MmoHasher {
            state: [0u8; 16],
            buf: [0u8; 16],
            buf_len: 0,
            total_len: 0,
            _cipher: core::marker::PhantomData,
        }
    }

    fn compress(state: &mut [u8; 16], block: &[u8; 16]) {
        // Hash_j = E(Hash_{j-1}, M_j) XOR M_j
        let cipher = C::new(&Key128::from_bytes(*state));
        let mut out = *block;
        cipher.encrypt_block(&mut out);
        for (o, b) in out.iter_mut().zip(block) {
            *o ^= *b;
        }
        *state = out;
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        let mut rest = data;
        self.total_len = self.total_len.saturating_add(data.len());
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(rest.len());
            copy_prefix(
                self.buf.get_mut(self.buf_len..).unwrap_or(&mut []),
                rest.get(..take).unwrap_or(&[]),
            );
            self.buf_len += take;
            rest = rest.get(take..).unwrap_or(&[]);
            if self.buf_len == 16 {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while rest.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(rest.get(..16).unwrap_or(&[0; 16]));
            Self::compress(&mut self.state, &block);
            rest = rest.get(16..).unwrap_or(&[]);
        }
        if !rest.is_empty() {
            copy_prefix(&mut self.buf, rest);
            self.buf_len = rest.len();
        }
    }

    /// Finishes and returns the digest.
    pub fn finalize(mut self) -> [u8; 16] {
        let total = self.total_len;
        let bit_len = total.saturating_mul(8);
        // Append 0x80 then zeros, then the length encoding.
        let (tail_mod, len_enc): (usize, [u8; 6]) = if total < LONG_THRESHOLD_OCTETS {
            let l = u16::try_from(bit_len).unwrap_or(u16::MAX).to_be_bytes();
            (14, [l[0], l[1], 0, 0, 0, 0])
        } else {
            let l = u32::try_from(bit_len).unwrap_or(u32::MAX).to_be_bytes();
            (10, [l[0], l[1], l[2], l[3], 0, 0])
        };
        let len_enc_len = 16 - tail_mod;
        self.update_padding(&[0x80]);
        while self.buf_len != tail_mod {
            self.update_padding(&[0x00]);
        }
        self.update_padding(len_enc.get(..len_enc_len).unwrap_or(&[]));
        debug_assert_eq!(self.buf_len, 0);
        let out = self.state;
        self.state.zeroize();
        self.buf.zeroize();
        out
    }

    /// `update` without counting toward the message length.
    fn update_padding(&mut self, data: &[u8]) {
        let saved = self.total_len;
        self.update(data);
        self.total_len = saved;
    }
}

/// One-shot AES-MMO hash.
pub fn hash<C: BlockCipher>(data: &[u8]) -> [u8; 16] {
    let mut h = MmoHasher::<C>::new();
    h.update(data);
    h.finalize()
}

/// HMAC over AES-MMO with block size 16 (Annex B.1.4, FIPS 198).
///
/// Keys longer than 16 octets are first hashed, as in FIPS 198.
pub fn hmac<C: BlockCipher>(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut k0 = [0u8; 16];
    if key.len() > HMAC_BLOCK_LEN {
        k0 = hash::<C>(key);
    } else {
        copy_prefix(&mut k0, key);
    }
    let mut inner_key = k0;
    let mut outer_key = k0;
    for b in &mut inner_key {
        *b ^= 0x36;
    }
    for b in &mut outer_key {
        *b ^= 0x5C;
    }
    let mut inner = MmoHasher::<C>::new();
    inner.update(&inner_key);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = MmoHasher::<C>::new();
    outer.update(&outer_key);
    outer.update(&inner_hash);
    let out = outer.finalize();
    k0.zeroize();
    inner_key.zeroize();
    outer_key.zeroize();
    out
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;
    use crate::cipher::SoftwareAes;

    #[test]
    fn annex_c5_1_single_octet() {
        assert_eq!(
            hash::<SoftwareAes>(&[0xC0]),
            [
                0xAE, 0x3A, 0x10, 0x2A, 0x28, 0xD4, 0x3E, 0xE0, 0xD4, 0xA0, 0x9E, 0x22, 0x78, 0x8B,
                0x20, 0x6C
            ]
        );
    }

    #[test]
    fn annex_c5_2_sixteen_octets() {
        let m: [u8; 16] = core::array::from_fn(|i| 0xC0 + i as u8);
        assert_eq!(
            hash::<SoftwareAes>(&m),
            [
                0xA7, 0x97, 0x7E, 0x88, 0xBC, 0x0B, 0x61, 0xE8, 0x21, 0x08, 0x27, 0x10, 0x9A, 0x22,
                0x8F, 0x2D
            ]
        );
        // Streaming in odd chunks gives the same digest.
        let mut h = MmoHasher::<SoftwareAes>::new();
        h.update(&m[..5]);
        h.update(&m[5..7]);
        h.update(&m[7..]);
        assert_eq!(h.finalize(), hash::<SoftwareAes>(&m));
    }

    fn seq(n: usize) -> alloc_free_vec::SeqBuf {
        alloc_free_vec::SeqBuf::new(n)
    }

    mod alloc_free_vec {
        /// A fixed 8208-byte buffer holding the 0,1,2,...,255 sequence,
        /// so that the long-message vectors run without `alloc`.
        pub struct SeqBuf {
            data: [u8; 8208],
            len: usize,
        }
        impl SeqBuf {
            pub fn new(len: usize) -> Self {
                let mut data = [0u8; 8208];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i % 256) as u8;
                }
                SeqBuf { data, len }
            }
            pub fn as_slice(&self) -> &[u8] {
                &self.data[..self.len]
            }
        }
    }

    #[test]
    fn annex_c5_3_to_6_long_messages() {
        let cases: [(usize, [u8; 16]); 4] = [
            (
                8191,
                [
                    0x24, 0xEC, 0x2F, 0xE7, 0x5B, 0xBF, 0xFC, 0xB3, 0x47, 0x89, 0xBC, 0x06, 0x10,
                    0xE7, 0xF1, 0x65,
                ],
            ),
            (
                8192,
                [
                    0xDC, 0x6B, 0x06, 0x87, 0xF0, 0x9F, 0x86, 0x07, 0x13, 0x1C, 0x17, 0x0B, 0x3B,
                    0xD3, 0x15, 0x91,
                ],
            ),
            (
                8201,
                [
                    0x72, 0xC9, 0xB1, 0x5E, 0x17, 0x8A, 0xA8, 0x43, 0xE4, 0xA1, 0x6C, 0x58, 0xE3,
                    0x36, 0x43, 0xA3,
                ],
            ),
            (
                8202,
                [
                    0xBC, 0x98, 0x28, 0xD5, 0x9B, 0x2A, 0xA3, 0x23, 0xDA, 0xF2, 0x0B, 0xE5, 0xF2,
                    0xE6, 0x65, 0x11,
                ],
            ),
        ];
        for (len, expected) in cases {
            let buf = seq(len);
            assert_eq!(hash::<SoftwareAes>(buf.as_slice()), expected, "len {len}");
        }
    }

    #[test]
    fn annex_c6_hmac_vectors() {
        let key: [u8; 16] = core::array::from_fn(|i| 0x40 + i as u8);
        assert_eq!(
            hmac::<SoftwareAes>(&key, &[0xC0]),
            [
                0x45, 0x12, 0x80, 0x7B, 0xF9, 0x4C, 0xB3, 0x40, 0x0F, 0x0E, 0x2C, 0x25, 0xFB, 0x76,
                0xE9, 0x99
            ]
        );
        let key2: [u8; 32] = core::array::from_fn(|i| 0x40 + i as u8);
        let m: [u8; 16] = core::array::from_fn(|i| 0xC0 + i as u8);
        assert_eq!(
            hmac::<SoftwareAes>(&key2, &m),
            [
                0xA3, 0xB0, 0x07, 0x99, 0x84, 0xBF, 0x15, 0x57, 0xF7, 0x4A, 0x0D, 0x63, 0x87, 0xE0,
                0xA1, 0x1A
            ]
        );
    }
}
