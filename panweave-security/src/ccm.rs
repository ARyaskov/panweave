//! CCM* mode of operation (R23.2 Annex A, instantiated per Annex B.1.2:
//! AES-128, L = 2, M ∈ {0, 4, 8, 16}).
//!
//! CCM* differs from RFC 3610 CCM only in permitting M = 0 (encryption
//! without authentication, security level 4). Everything else is standard
//! CCM, and the Annex C.3/C.4 vectors are used as known-answer tests.
//!
//! All functions operate in place on caller-provided buffers and never
//! allocate. Decryption verifies the MIC before releasing plaintext
//! (Annex A.4): on failure the buffer is left holding ciphertext bytes
//! that have been overwritten with zeros.

use subtle::ConstantTimeEq;

use crate::cipher::BlockCipher;

/// Length of the message-length field `L` (octets).
pub const L: usize = 2;

/// Nonce length in octets (`15 - L`).
pub const NONCE_LEN: usize = 13;

/// Errors from CCM* operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CcmError {
    /// The MIC length is not one of 0, 4, 8, 16.
    InvalidMicLength,
    /// The message is longer than `2^(8L) - 1` octets or the buffer is too
    /// short to hold message plus MIC.
    LengthOverflow,
    /// The buffer is shorter than the MIC.
    Truncated,
    /// The authentication tag did not verify.
    AuthenticationFailed,
}

/// Copies `src` into the start of `dst`, ignoring any excess on either
/// side (panic-free by construction).
#[inline]
fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
    }
}

#[inline]
fn xor_into(dst: &mut [u8; 16], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// Runs the CBC-MAC authentication transformation (A.2.2) and returns the
/// full 16-octet `X_{t+1}`; the tag is its leftmost `mic_len` octets.
fn cbc_mac<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
    mic_len: usize,
) -> [u8; 16] {
    // B0 = Flags || Nonce || l(m)
    let m_field = if mic_len == 0 { 0 } else { (mic_len - 2) / 2 };
    let flags = (u8::from(!aad.is_empty()) << 6)
        | ((u8::try_from(m_field).unwrap_or(0) & 0x7) << 3)
        | (u8::try_from(L - 1).unwrap_or(1) & 0x7);
    let mut x = [0u8; 16];
    x[0] = flags;
    x[1..14].copy_from_slice(nonce);
    let len = u16::try_from(msg.len()).unwrap_or(u16::MAX).to_be_bytes();
    x[14] = len[0];
    x[15] = len[1];
    cipher.encrypt_block(&mut x);

    // AddAuthData = L(a) || a, zero-padded to a block multiple. Zigbee
    // frames keep l(a) far below 2^16 - 2^8, so the 2-octet encoding always
    // applies; longer inputs are rejected by callers via LengthOverflow.
    if !aad.is_empty() {
        let la = u16::try_from(aad.len()).unwrap_or(u16::MAX).to_be_bytes();
        let mut block = [0u8; 16];
        block[0] = la[0];
        block[1] = la[1];
        let first = aad.len().min(14);
        copy_prefix(
            block.get_mut(2..).unwrap_or(&mut []),
            aad.get(..first).unwrap_or(&[]),
        );
        xor_into(&mut x, &block);
        cipher.encrypt_block(&mut x);
        let mut rest = aad.get(first..).unwrap_or(&[]);
        while !rest.is_empty() {
            let n = rest.len().min(16);
            let mut block = [0u8; 16];
            copy_prefix(&mut block, rest.get(..n).unwrap_or(&[]));
            xor_into(&mut x, &block);
            cipher.encrypt_block(&mut x);
            rest = rest.get(n..).unwrap_or(&[]);
        }
    }

    let mut rest = msg;
    while !rest.is_empty() {
        let n = rest.len().min(16);
        let mut block = [0u8; 16];
        copy_prefix(&mut block, rest.get(..n).unwrap_or(&[]));
        xor_into(&mut x, &block);
        cipher.encrypt_block(&mut x);
        rest = rest.get(n..).unwrap_or(&[]);
    }
    x
}

/// Counter-mode keystream block `E(Key, A_i)` (A.2.3).
fn ctr_block<C: BlockCipher>(cipher: &C, nonce: &[u8; NONCE_LEN], counter: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = u8::try_from(L - 1).unwrap_or(1) & 0x7;
    a[1..14].copy_from_slice(nonce);
    let c = counter.to_be_bytes();
    a[14] = c[0];
    a[15] = c[1];
    cipher.encrypt_block(&mut a);
    a
}

fn ctr_xor<C: BlockCipher>(cipher: &C, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let counter = u16::try_from(i + 1).unwrap_or(u16::MAX);
        let ks = ctr_block(cipher, nonce, counter);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= *k;
        }
    }
}

fn check_params(aad_len: usize, msg_len: usize, mic_len: usize) -> Result<(), CcmError> {
    if !matches!(mic_len, 0 | 4 | 8 | 16) {
        return Err(CcmError::InvalidMicLength);
    }
    // l(m) < 2^(8L) and l(a) below the 2-octet encoding threshold.
    if msg_len > 0xFFFF || aad_len >= 0xFF00 {
        return Err(CcmError::LengthOverflow);
    }
    Ok(())
}

/// Encrypts `msg` in place and writes the encrypted tag `U` into `mic`
/// (whose length selects M).
///
/// `aad` is authenticated but not encrypted. For authentication-only
/// levels, pass the whole protected data as `aad` and an empty `msg`.
pub fn encrypt_in_place<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &mut [u8],
    mic: &mut [u8],
) -> Result<(), CcmError> {
    check_params(aad.len(), msg.len(), mic.len())?;
    let tag = cbc_mac(cipher, nonce, aad, msg, mic.len());
    ctr_xor(cipher, nonce, msg);
    let s0 = ctr_block(cipher, nonce, 0);
    for (u, (t, s)) in mic.iter_mut().zip(tag.iter().zip(s0.iter())) {
        *u = t ^ s;
    }
    Ok(())
}

/// Decrypts `msg` in place and verifies the encrypted tag `mic`.
///
/// On authentication failure the message buffer is zeroed so that no
/// unauthenticated plaintext is released (Annex A.4).
pub fn decrypt_in_place<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &mut [u8],
    mic: &[u8],
) -> Result<(), CcmError> {
    check_params(aad.len(), msg.len(), mic.len())?;
    // Recover T from U.
    let s0 = ctr_block(cipher, nonce, 0);
    let mut tag = [0u8; 16];
    for (t, (u, s)) in tag.iter_mut().zip(mic.iter().zip(s0.iter())) {
        *t = u ^ s;
    }
    ctr_xor(cipher, nonce, msg);
    let expected = cbc_mac(cipher, nonce, aad, msg, mic.len());
    let ok: bool = expected
        .get(..mic.len())
        .unwrap_or(&[])
        .ct_eq(tag.get(..mic.len()).unwrap_or(&[]))
        .into();
    if ok {
        Ok(())
    } else {
        msg.fill(0);
        Err(CcmError::AuthenticationFailed)
    }
}

/// Convenience: encrypts a buffer laid out as `msg || mic` where the last
/// `mic_len` bytes are the tag output.
pub fn encrypt_buffer<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    mic_len: usize,
) -> Result<(), CcmError> {
    if buf.len() < mic_len {
        return Err(CcmError::Truncated);
    }
    let split = buf.len() - mic_len;
    let (msg, mic) = buf.split_at_mut(split);
    encrypt_in_place(cipher, nonce, aad, msg, mic)
}

/// Convenience: decrypts a buffer laid out as `ciphertext || mic`.
pub fn decrypt_buffer<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    mic_len: usize,
) -> Result<(), CcmError> {
    if buf.len() < mic_len {
        return Err(CcmError::Truncated);
    }
    let split = buf.len() - mic_len;
    let (msg, mic) = buf.split_at_mut(split);
    decrypt_in_place(cipher, nonce, aad, msg, mic)
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;
    use crate::cipher::SoftwareAes;
    use panweave_types::Key128;

    const KEY: [u8; 16] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF,
    ];
    const NONCE: [u8; 13] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x03, 0x02, 0x01, 0x00, 0x06,
    ];
    const M: [u8; 23] = [
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    ];
    const A: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const C: [u8; 31] = [
        0x1A, 0x55, 0xA3, 0x6A, 0xBB, 0x6C, 0x61, 0x0D, 0x06, 0x6B, 0x33, 0x75, 0x64, 0x9C, 0xEF,
        0x10, 0xD4, 0x66, 0x4E, 0xCA, 0xD8, 0x54, 0xA8, 0x0A, 0x89, 0x5C, 0xC1, 0xD8, 0xFF, 0x94,
        0x69,
    ];

    #[test]
    fn annex_c3_encryption_vector() {
        let cipher = SoftwareAes::new(&Key128::from_bytes(KEY));
        let mut buf = [0u8; 31];
        buf[..23].copy_from_slice(&M);
        encrypt_buffer(&cipher, &NONCE, &A, &mut buf, 8).unwrap();
        assert_eq!(buf, C);
    }

    #[test]
    fn annex_c4_decryption_vector_and_tamper_detection() {
        let cipher = SoftwareAes::new(&Key128::from_bytes(KEY));
        let mut buf = C;
        decrypt_buffer(&cipher, &NONCE, &A, &mut buf, 8).unwrap();
        assert_eq!(&buf[..23], &M);

        let mut tampered = C;
        tampered[5] ^= 0x01;
        assert_eq!(
            decrypt_buffer(&cipher, &NONCE, &A, &mut tampered, 8),
            Err(CcmError::AuthenticationFailed)
        );
        assert!(
            tampered[..23].iter().all(|b| *b == 0),
            "plaintext not released"
        );

        let mut bad_aad = C;
        let mut a2 = A;
        a2[0] ^= 1;
        assert!(decrypt_buffer(&cipher, &NONCE, &a2, &mut bad_aad, 8).is_err());
    }

    #[test]
    fn mic_only_and_enc_only_round_trip() {
        let cipher = SoftwareAes::new(&Key128::from_bytes(KEY));
        // Authentication only (levels 1-3): message in aad, empty msg.
        for mic_len in [4usize, 8, 16] {
            let mut mic = [0u8; 16];
            let mut empty: [u8; 0] = [];
            encrypt_in_place(&cipher, &NONCE, &M, &mut empty, &mut mic[..mic_len]).unwrap();
            decrypt_in_place(&cipher, &NONCE, &M, &mut empty, &mic[..mic_len]).unwrap();
            let mut wrong = M;
            wrong[0] ^= 1;
            assert!(
                decrypt_in_place(&cipher, &NONCE, &wrong, &mut empty, &mic[..mic_len]).is_err()
            );
        }
        // Encryption only (level 4): M = 0.
        let mut buf = M;
        encrypt_in_place(&cipher, &NONCE, &A, &mut buf, &mut []).unwrap();
        assert_ne!(buf, M);
        decrypt_in_place(&cipher, &NONCE, &A, &mut buf, &[]).unwrap();
        assert_eq!(buf, M);
    }

    #[test]
    fn parameter_validation() {
        let cipher = SoftwareAes::new(&Key128::from_bytes(KEY));
        let mut buf = [0u8; 4];
        assert_eq!(
            encrypt_in_place(&cipher, &NONCE, &[], &mut buf, &mut [0u8; 3]),
            Err(CcmError::InvalidMicLength)
        );
        assert_eq!(
            encrypt_buffer(&cipher, &NONCE, &[], &mut buf, 8),
            Err(CcmError::Truncated)
        );
        // Empty everything with a MIC is valid.
        let mut mic = [0u8; 4];
        encrypt_in_place(&cipher, &NONCE, &[], &mut [], &mut mic).unwrap();
        decrypt_in_place(&cipher, &NONCE, &[], &mut [], &mic).unwrap();
    }

    #[test]
    fn multi_block_aad_and_message() {
        let cipher = SoftwareAes::new(&Key128::from_bytes(KEY));
        let aad: [u8; 40] = core::array::from_fn(|i| i as u8);
        let msg: [u8; 70] = core::array::from_fn(|i| (i * 3) as u8);
        let mut buf = [0u8; 86];
        buf[..70].copy_from_slice(&msg);
        encrypt_buffer(&cipher, &NONCE, &aad, &mut buf, 16).unwrap();
        assert_ne!(&buf[..70], &msg);
        decrypt_buffer(&cipher, &NONCE, &aad, &mut buf, 16).unwrap();
        assert_eq!(&buf[..70], &msg);
    }
}
