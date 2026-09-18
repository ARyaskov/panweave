//! Cryptographic key material types.
//!
//! All secret-bearing types redact their `Debug` output, compare in
//! constant time and are zeroized on drop.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 128-bit AES key (network key, link key, derived key).
///
/// `Debug` prints `Key128([REDACTED])`. Equality is constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Key128([u8; 16]);

impl Key128 {
    /// The well-known default global Trust Center link key
    /// ("ZigBeeAlliance09"), R23.2 §4.7.2 / BDB3.1 §6.2.
    ///
    /// Its use is restricted by Trust Center policy; see
    /// `docs/security-model.md`.
    pub const WELL_KNOWN_GLOBAL_TCLK: Key128 = Key128(*b"ZigBeeAlliance09");

    /// The distributed security global link key (BDB3.1 §6.2, only
    /// available to certified devices; the value used here is the
    /// development value published for testing).
    pub const DISTRIBUTED_GLOBAL_DEVELOPMENT: Key128 = Key128([
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
        0xDF,
    ]);

    /// The all-zero key, used as the "unset" marker in tables.
    pub const ZERO: Key128 = Key128([0; 16]);

    /// Builds a key from raw bytes.
    #[inline]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Key128(b)
    }

    /// Returns the raw key bytes.
    ///
    /// Security: callers must not log or persist the result outside of the
    /// storage layer.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// True when every byte is zero (unset marker).
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.ct_eq(&[0u8; 16]).into()
    }
}

impl PartialEq for Key128 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Key128 {}

impl fmt::Debug for Key128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key128([REDACTED])")
    }
}

impl Default for Key128 {
    fn default() -> Self {
        Key128::ZERO
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Key128 {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "Key128([REDACTED])");
    }
}

/// The `StandardKeyType` enumeration used by Transport Key, Verify Key,
/// Confirm Key and Request Key commands (R23.2 §4.4.2, Table 4-9).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyType {
    /// Standard network key (`0x01`).
    StandardNetworkKey,
    /// Application link key shared with a partner device (`0x03`).
    ApplicationLinkKey,
    /// Trust Center link key (`0x04`).
    TrustCenterLinkKey,
    /// Ephemeral global link key (`0xB0`), used by Zigbee Direct
    /// ephemeral authorization sessions.
    EphemeralGlobal,
    /// Ephemeral unique authorization key (`0xB1`, Zigbee Direct).
    EphemeralUnique,
    /// Basic authorization key of a Zigbee Direct Virtual Device
    /// (`0xB2`, R23.2 Table 4-9 / ZD 1.1 §6.3.2.1).
    BasicAuthorization,
    /// Administrative authorization key (`0xB3`, Zigbee Direct).
    AdministrativeAuthorization,
    /// A value not defined by the specification revision this crate
    /// implements; preserved for forward compatibility.
    Unknown(u8),
}

impl KeyType {
    /// Wire value.
    #[inline]
    pub const fn raw(self) -> u8 {
        match self {
            KeyType::StandardNetworkKey => 0x01,
            KeyType::ApplicationLinkKey => 0x03,
            KeyType::TrustCenterLinkKey => 0x04,
            KeyType::EphemeralGlobal => 0xB0,
            KeyType::EphemeralUnique => 0xB1,
            KeyType::BasicAuthorization => 0xB2,
            KeyType::AdministrativeAuthorization => 0xB3,
            KeyType::Unknown(v) => v,
        }
    }

    /// Parses the wire value; reserved values become `Unknown`.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x01 => KeyType::StandardNetworkKey,
            0x03 => KeyType::ApplicationLinkKey,
            0x04 => KeyType::TrustCenterLinkKey,
            0xB0 => KeyType::EphemeralGlobal,
            0xB1 => KeyType::EphemeralUnique,
            0xB2 => KeyType::BasicAuthorization,
            0xB3 => KeyType::AdministrativeAuthorization,
            other => KeyType::Unknown(other),
        }
    }
}

crate::impl_defmt_via_debug!(KeyType);

/// Link key attributes from the key-pair descriptor (R23.2 §4.4.12,
/// Table 4-36 `KeyAttributes`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyAttributes {
    /// Provisional key: the initial preconfigured/derived key that must be
    /// replaced by a unique key (value `0x00`).
    ProvisionalKey,
    /// A unique key that has been received but not yet verified (`0x01`).
    UnverifiedKey,
    /// A unique key whose possession has been verified (`0x02`).
    VerifiedKey,
    /// Unknown attribute value preserved from storage.
    Unknown(u8),
}

impl KeyAttributes {
    /// Wire/storage value.
    #[inline]
    pub const fn raw(self) -> u8 {
        match self {
            KeyAttributes::ProvisionalKey => 0,
            KeyAttributes::UnverifiedKey => 1,
            KeyAttributes::VerifiedKey => 2,
            KeyAttributes::Unknown(v) => v,
        }
    }

    /// Parses a storage value.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0 => KeyAttributes::ProvisionalKey,
            1 => KeyAttributes::UnverifiedKey,
            2 => KeyAttributes::VerifiedKey,
            other => KeyAttributes::Unknown(other),
        }
    }
}

crate::impl_defmt_via_debug!(KeyAttributes);

/// An install code with CRC (BDB3.1 §6.11).
///
/// Valid lengths are 6, 8, 12 or 16 code octets, each followed by a 2-octet
/// CRC-16 (total 8, 10, 14 or 18 octets). The code is hashed with AES-MMO to
/// derive the pre-configured link key; that derivation lives in
/// `panweave-security` because it needs the block cipher.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InstallCode {
    bytes: [u8; 18],
    len: u8,
}

impl InstallCode {
    /// Builds an install code from `code || crc16` bytes of a valid total
    /// length (8, 10, 14 or 18). The CRC is verified by
    /// [`InstallCode::crc_valid`], not here, so that callers can report
    /// the two failure modes separately.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if !matches!(bytes.len(), 8 | 10 | 14 | 18) {
            return None;
        }
        let mut buf = [0u8; 18];
        buf.get_mut(..bytes.len())?.copy_from_slice(bytes);
        // Length is at most 18 so the narrowing cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        Some(InstallCode {
            bytes: buf,
            len: bytes.len() as u8,
        })
    }

    /// The full `code || crc` bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// The code bytes without the trailing CRC.
    #[inline]
    pub fn code(&self) -> &[u8] {
        let n = usize::from(self.len).saturating_sub(2);
        self.bytes.get(..n).unwrap_or(&[])
    }

    /// The trailing CRC-16 as transmitted (little-endian on the wire /
    /// label).
    #[inline]
    pub fn crc(&self) -> u16 {
        let n = usize::from(self.len);
        match (
            self.bytes.get(n.wrapping_sub(2)),
            self.bytes.get(n.wrapping_sub(1)),
        ) {
            (Some(lo), Some(hi)) => u16::from_le_bytes([*lo, *hi]),
            _ => 0,
        }
    }

    /// Verifies the CRC-16 (CRC-16/X-25 style: polynomial 0x1021 reflected,
    /// init 0xFFFF, final XOR 0xFFFF) over the code bytes, as required by
    /// BDB3.1 §6.11.
    pub fn crc_valid(&self) -> bool {
        crc16_x25(self.code()) == self.crc()
    }
}

impl fmt::Debug for InstallCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InstallCode(len={}, [REDACTED])", self.len)
    }
}

/// CRC-16 with the reflected polynomial 0x8408 (0x1021 reversed), initial
/// value 0xFFFF and final complement, as used for install codes.
pub fn crc16_x25(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_debug_is_redacted() {
        let k = Key128::WELL_KNOWN_GLOBAL_TCLK;
        let mut buf = [0u8; 64];
        let len = {
            let mut w = Writer(&mut buf, 0);
            fmt::write(&mut w, format_args!("{k:?}")).ok();
            w.1
        };
        let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
        assert_eq!(s, "Key128([REDACTED])");
        assert!(!s.contains("Zig"));
    }

    struct Writer<'a>(&'a mut [u8], usize);
    impl fmt::Write for Writer<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.1 + s.len();
            if end > self.0.len() {
                return Err(fmt::Error);
            }
            self.0[self.1..end].copy_from_slice(s.as_bytes());
            self.1 = end;
            Ok(())
        }
    }

    #[test]
    fn key_type_round_trip() {
        for v in [0x01u8, 0x03, 0x04, 0xB0, 0x00, 0x02, 0x7F] {
            assert_eq!(KeyType::from_raw(v).raw(), v);
        }
        assert_eq!(KeyType::from_raw(0x02), KeyType::Unknown(0x02));
    }

    #[test]
    fn install_code_crc_known_answer() {
        // Example install code from BDB3.1 §6.11 style documentation:
        // 83FED3407A939723A5C639B26916D505 with CRC C3B5.
        let bytes = [
            0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16,
            0xD5, 0x05, 0xC3, 0xB5,
        ];
        let ic = InstallCode::new(&bytes).expect("valid length");
        assert_eq!(ic.code().len(), 16);
        assert_eq!(ic.crc(), 0xB5C3);
        assert!(ic.crc_valid());
        let mut bad = bytes;
        bad[0] ^= 1;
        let ic2 = InstallCode::new(&bad).expect("valid length");
        assert!(!ic2.crc_valid());
        assert!(InstallCode::new(&bytes[..7]).is_none());
    }
}
