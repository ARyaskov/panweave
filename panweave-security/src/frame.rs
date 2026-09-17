//! Frame protection and unprotection for NWK (R23.2 §4.3.1) and APS
//! (§4.4.1) frames.
//!
//! Both layers use the same construction: the unsecured header `H` is
//! followed by the auxiliary header `A` and the payload `P`. With an
//! encrypting level, CCM* authenticates `H || A` and encrypts `P`;
//! otherwise it authenticates `H || A || P` with an empty message. The MIC
//! is appended and, on the air, the security-level bits of the security
//! control octet are zeroed (§4.3.1.1 step 8); the receiver restores them
//! from its configured level (§4.3.1.2 step 1).
//!
//! Key selection and frame-counter bookkeeping are the caller's
//! responsibility; this module only performs the cryptographic transform
//! over a caller-provided buffer.

use core::fmt;

use panweave_codec::{Decode, Encode, Reader, Writer};
use panweave_types::ExtendedAddress;

use crate::aux_header::{AuxHeader, SecurityLevel};
use crate::ccm::{self, CcmError};
use crate::cipher::BlockCipher;

/// Security processing failures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityError {
    /// The outgoing frame counter is exhausted or not reserved.
    FrameCounter,
    /// No key is available (unknown sequence number / partner).
    NoKey,
    /// Received frame counter is stale (`bad frame counter`).
    BadFrameCounter,
    /// The frame authenticated but the partner's incoming counter is
    /// not verified (`UNVERIFIED_FRAME_COUNTER`, §4.6.3.8): the frame is
    /// dropped and a challenge is due.
    UnverifiedFrameCounter,
    /// The auxiliary header or trailer could not be parsed.
    Malformed,
    /// The buffer cannot hold the secured frame.
    BufferTooSmall,
    /// CCM* reported a failure (authentication failure or bad parameters).
    Ccm(CcmError),
    /// The frame is secured with a level or key type this node does not
    /// accept.
    PolicyRejected,
}

impl From<CcmError> for SecurityError {
    fn from(e: CcmError) -> Self {
        SecurityError::Ccm(e)
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::FrameCounter => f.write_str("frame counter unavailable"),
            SecurityError::NoKey => f.write_str("no key"),
            SecurityError::BadFrameCounter => f.write_str("bad frame counter"),
            SecurityError::UnverifiedFrameCounter => f.write_str("unverified frame counter"),
            SecurityError::Malformed => f.write_str("malformed secured frame"),
            SecurityError::BufferTooSmall => f.write_str("buffer too small"),
            SecurityError::Ccm(_) => f.write_str("frame security failed"),
            SecurityError::PolicyRejected => f.write_str("rejected by security policy"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecurityError {}

/// Result alias.
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Outcome of unprotecting a frame: the parsed auxiliary header and the
/// byte range of the recovered payload inside the buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unprotected {
    /// The auxiliary header with the level restored.
    pub aux: AuxHeader,
    /// Start of the payload (immediately after the auxiliary header).
    pub payload_start: usize,
    /// End of the payload (exclusive; the MIC follows).
    pub payload_end: usize,
}

/// Parses the auxiliary header at `offset` without any cryptography, so
/// the caller can select the key (sequence number / sender).
pub fn peek_aux(buf: &[u8], offset: usize) -> SecurityResult<AuxHeader> {
    let slice = buf.get(offset..).ok_or(SecurityError::Malformed)?;
    let mut r = Reader::new(slice);
    AuxHeader::decode(&mut r).map_err(|_| SecurityError::Malformed)
}

/// Secures the frame in `buf` in place.
///
/// Expected layout on entry: `buf[..header_len]` holds the unsecured
/// header, `buf[header_len..header_len + aux.encoded_len()]` is reserved
/// (its contents are overwritten), and the payload of `payload_len` bytes
/// follows. The buffer must have room for the MIC. Returns the total
/// secured frame length.
///
/// `aux.control.level` selects the CCM* parameters; the on-air control
/// octet has its level bits cleared.
pub fn protect_in_place<C: BlockCipher>(
    cipher: &C,
    aux: &AuxHeader,
    nonce_source: ExtendedAddress,
    buf: &mut [u8],
    header_len: usize,
    payload_len: usize,
) -> SecurityResult<usize> {
    let level = aux.control.level;
    let aux_len = aux.encoded_len();
    let mic_len = level.mic_len();
    let payload_start = header_len
        .checked_add(aux_len)
        .ok_or(SecurityError::BufferTooSmall)?;
    let payload_end = payload_start
        .checked_add(payload_len)
        .ok_or(SecurityError::BufferTooSmall)?;
    let total = payload_end
        .checked_add(mic_len)
        .ok_or(SecurityError::BufferTooSmall)?;
    if total > buf.len() {
        return Err(SecurityError::BufferTooSmall);
    }
    {
        let aux_slot = buf
            .get_mut(header_len..payload_start)
            .ok_or(SecurityError::BufferTooSmall)?;
        let mut w = Writer::new(aux_slot);
        aux.encode(&mut w).map_err(|_| SecurityError::Malformed)?;
    }
    let nonce = aux.nonce(nonce_source);
    if level.encrypts() {
        let (aad, rest) = buf.split_at_mut(payload_start);
        let (msg, tail) = rest.split_at_mut(payload_len);
        let mic = tail
            .get_mut(..mic_len)
            .ok_or(SecurityError::BufferTooSmall)?;
        ccm::encrypt_in_place(cipher, &nonce, aad, msg, mic)?;
    } else {
        let (aad, tail) = buf.split_at_mut(payload_end);
        let mic = tail
            .get_mut(..mic_len)
            .ok_or(SecurityError::BufferTooSmall)?;
        ccm::encrypt_in_place(cipher, &nonce, aad, &mut [], mic)?;
    }
    // Zero the security level bits on the air.
    if let Some(ctrl) = buf.get_mut(header_len) {
        *ctrl &= !0x07;
    }
    Ok(total)
}

/// Unprotects a secured frame in place.
///
/// `buf[..header_len]` is the unsecured header; the auxiliary header,
/// payload and MIC follow to the end of `buf`. `level` is the locally
/// configured security level (`nwkSecurityLevel`), restored into the
/// control octet before processing. `nonce_source` is used when the
/// auxiliary header carries no extended nonce.
///
/// On success the decrypted payload is available at the returned range
/// and the level bits in the buffer are restored. On failure the payload
/// bytes are zeroed.
pub fn unprotect_in_place<C: BlockCipher>(
    cipher: &C,
    level: SecurityLevel,
    nonce_source: ExtendedAddress,
    buf: &mut [u8],
    header_len: usize,
) -> SecurityResult<Unprotected> {
    let mut aux = peek_aux(buf, header_len)?;
    aux.control = aux.control.with_level(level);
    let aux_len = aux.encoded_len();
    let mic_len = level.mic_len();
    let payload_start = header_len
        .checked_add(aux_len)
        .ok_or(SecurityError::Malformed)?;
    if buf.len() < payload_start + mic_len {
        return Err(SecurityError::Malformed);
    }
    let payload_end = buf.len() - mic_len;
    // Restore the level bits so that `a` matches the sender's view.
    if let Some(ctrl) = buf.get_mut(header_len) {
        *ctrl = aux.control.raw();
    }
    let nonce = aux.nonce(nonce_source);
    if level.encrypts() {
        let (aad, rest) = buf.split_at_mut(payload_start);
        let (msg, mic) = rest.split_at_mut(payload_end - payload_start);
        ccm::decrypt_in_place(cipher, &nonce, aad, msg, mic)?;
    } else {
        let (aad, mic) = buf.split_at_mut(payload_end);
        ccm::decrypt_in_place(cipher, &nonce, aad, &mut [], mic)?;
    }
    Ok(Unprotected {
        aux,
        payload_start,
        payload_end,
    })
}

#[cfg(all(test, feature = "crypto-software"))]
mod tests {
    use super::*;
    use crate::aux_header::KeyIdentifier;
    use crate::cipher::SoftwareAes;
    use panweave_types::{FrameCounter, Key128, KeySequenceNumber};

    #[test]
    fn nwk_frame_protect_unprotect_round_trip() {
        let key = Key128::from_bytes([0x01; 16]);
        let cipher = SoftwareAes::new(&key);
        let src = ExtendedAddress(0x0011_2233_4455_6677);
        let aux = AuxHeader::network(
            SecurityLevel::EncMic32,
            FrameCounter(42),
            src,
            KeySequenceNumber(0),
        );
        let header = [0x08, 0x02, 0x00, 0x00, 0x01, 0x00, 0x1E, 0x55];
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        let mut buf = [0u8; 64];
        buf[..8].copy_from_slice(&header);
        let ps = 8 + aux.encoded_len();
        buf[ps..ps + 5].copy_from_slice(&payload);
        let total = protect_in_place(&cipher, &aux, src, &mut buf, 8, 5).unwrap();
        assert_eq!(total, 8 + 14 + 5 + 4);
        assert_eq!(buf[8] & 0x07, 0, "level zeroed on air");
        assert_ne!(&buf[ps..ps + 5], &payload, "payload encrypted");
        assert_eq!(&buf[..8], &header, "header untouched");

        let peek = peek_aux(&buf[..total], 8).unwrap();
        assert_eq!(peek.key_sequence, Some(KeySequenceNumber(0)));
        assert_eq!(peek.frame_counter, FrameCounter(42));

        let mut rx = buf;
        let u = unprotect_in_place(
            &cipher,
            SecurityLevel::EncMic32,
            ExtendedAddress::ZERO,
            &mut rx[..total],
            8,
        )
        .unwrap();
        assert_eq!(&rx[u.payload_start..u.payload_end], &payload);
        assert_eq!(u.aux.control.level, SecurityLevel::EncMic32);

        // Tampered header fails authentication and zeroes the payload.
        let mut bad = buf;
        bad[2] ^= 0x01;
        assert!(matches!(
            unprotect_in_place(
                &cipher,
                SecurityLevel::EncMic32,
                ExtendedAddress::ZERO,
                &mut bad[..total],
                8
            ),
            Err(SecurityError::Ccm(CcmError::AuthenticationFailed))
        ));
        assert!(bad[ps..ps + 5].iter().all(|b| *b == 0));

        // Wrong key fails.
        let other = SoftwareAes::new(&Key128::from_bytes([0x02; 16]));
        let mut bad2 = buf;
        assert!(
            unprotect_in_place(
                &other,
                SecurityLevel::EncMic32,
                ExtendedAddress::ZERO,
                &mut bad2[..total],
                8
            )
            .is_err()
        );

        // Truncated frames never panic.
        for len in 0..total {
            let mut t = buf;
            let _ = unprotect_in_place(
                &cipher,
                SecurityLevel::EncMic32,
                ExtendedAddress::ZERO,
                &mut t[..len],
                8,
            );
        }
    }

    #[test]
    fn aps_frame_without_extended_nonce_uses_supplied_source() {
        let key = Key128::WELL_KNOWN_GLOBAL_TCLK;
        let cipher = SoftwareAes::new(&key);
        let sender = ExtendedAddress(0xAABB);
        let aux = AuxHeader::link(
            SecurityLevel::EncMic32,
            KeyIdentifier::KeyTransport,
            FrameCounter(7),
            None,
        );
        let mut buf = [0u8; 64];
        buf[..3].copy_from_slice(&[0x21, 0x05, 0x01]);
        let ps = 3 + aux.encoded_len();
        buf[ps..ps + 4].copy_from_slice(&[1, 2, 3, 4]);
        let total = protect_in_place(&cipher, &aux, sender, &mut buf, 3, 4).unwrap();
        let mut rx = buf;
        let u = unprotect_in_place(
            &cipher,
            SecurityLevel::EncMic32,
            sender,
            &mut rx[..total],
            3,
        )
        .unwrap();
        assert_eq!(&rx[u.payload_start..u.payload_end], &[1, 2, 3, 4]);
        // Wrong sender address → wrong nonce → failure.
        let mut rx2 = buf;
        assert!(
            unprotect_in_place(
                &cipher,
                SecurityLevel::EncMic32,
                ExtendedAddress(0xAABC),
                &mut rx2[..total],
                3
            )
            .is_err()
        );
    }

    #[test]
    fn mic_only_level_authenticates_payload_in_clear() {
        let cipher = SoftwareAes::new(&Key128::from_bytes([9; 16]));
        let src = ExtendedAddress(5);
        let aux = AuxHeader::network(
            SecurityLevel::Mic64,
            FrameCounter(1),
            src,
            KeySequenceNumber(3),
        );
        let mut buf = [0u8; 48];
        buf[..2].copy_from_slice(&[0xAA, 0xBB]);
        let ps = 2 + aux.encoded_len();
        buf[ps..ps + 3].copy_from_slice(&[7, 8, 9]);
        let total = protect_in_place(&cipher, &aux, src, &mut buf, 2, 3).unwrap();
        assert_eq!(total, 2 + 14 + 3 + 8);
        assert_eq!(&buf[ps..ps + 3], &[7, 8, 9], "payload stays in clear");
        let mut rx = buf;
        let u =
            unprotect_in_place(&cipher, SecurityLevel::Mic64, src, &mut rx[..total], 2).unwrap();
        assert_eq!(&rx[u.payload_start..u.payload_end], &[7, 8, 9]);
        let mut bad = buf;
        bad[ps] ^= 1;
        assert!(
            unprotect_in_place(&cipher, SecurityLevel::Mic64, src, &mut bad[..total], 2).is_err()
        );
    }

    #[test]
    fn buffer_too_small_is_reported() {
        let cipher = SoftwareAes::new(&Key128::ZERO);
        let aux = AuxHeader::network(
            SecurityLevel::EncMic32,
            FrameCounter(1),
            ExtendedAddress(1),
            KeySequenceNumber(0),
        );
        let mut buf = [0u8; 20];
        assert_eq!(
            protect_in_place(&cipher, &aux, ExtendedAddress(1), &mut buf, 8, 5),
            Err(SecurityError::BufferTooSmall)
        );
    }
}
