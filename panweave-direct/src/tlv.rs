//! Local TLVs of the Zigbee Direct Security Service (ZD 1.1 §6.5.2) in
//! the general Zigbee TLV format (R23.2 Annex I): tag, length − 1, value.

use panweave_codec::tlv::{TlvSet, write_tlv};
use panweave_codec::{CodecError, Writer};
use panweave_types::ExtendedAddress;

/// Zigbee Direct Key Negotiation Method TLV.
pub const TAG_METHOD: u8 = 0;
/// Zigbee Direct Key Negotiation P-256 Public Point TLV.
pub const TAG_P256_POINT: u8 = 1;
/// Zigbee Direct Key Negotiation Curve25519 Public Point TLV.
pub const TAG_CURVE25519_POINT: u8 = 2;
/// Network Key Sequence Number TLV.
pub const TAG_KEY_SEQUENCE: u8 = 3;
/// MacTag TLV.
pub const TAG_MAC_TAG: u8 = 4;

/// Selected Key Negotiation Method (Table 15).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Method {
    /// 1: ECDHE (SPEKE) using Curve25519 with AES-MMO-128.
    Curve25519AesMmo,
    /// 2: ECDHE using Curve25519 with SHA-256 (reserved).
    Curve25519Sha256,
    /// 3: ECDHE-PSK using P-256 with SHA-256.
    P256Sha256,
}

impl Method {
    /// Raw enumeration value.
    pub const fn raw(self) -> u8 {
        match self {
            Method::Curve25519AesMmo => 1,
            Method::Curve25519Sha256 => 2,
            Method::P256Sha256 => 3,
        }
    }

    /// From the raw value.
    pub const fn from_raw(v: u8) -> Option<Self> {
        match v {
            1 => Some(Method::Curve25519AesMmo),
            2 => Some(Method::Curve25519Sha256),
            3 => Some(Method::P256Sha256),
            _ => None,
        }
    }

    /// The public point TLV tag this method uses.
    pub const fn point_tag(self) -> u8 {
        match self {
            Method::P256Sha256 => TAG_P256_POINT,
            _ => TAG_CURVE25519_POINT,
        }
    }

    /// Public point length in octets.
    pub const fn point_len(self) -> usize {
        match self {
            Method::P256Sha256 => 64,
            _ => 32,
        }
    }

    /// MacTag length in octets (HMAC-SHA-256: 32, HMAC-AES-MMO-128: 16).
    pub const fn mac_tag_len(self) -> usize {
        match self {
            Method::P256Sha256 | Method::Curve25519Sha256 => 32,
            Method::Curve25519AesMmo => 16,
        }
    }
}

/// Selected Pre-shared Secret (Table 16).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Psk {
    /// 0: symmetric authentication token.
    SymmetricToken,
    /// 1: link key derived from the installation code.
    InstallCode,
    /// 2: variable-length passcode (PAKE only).
    Passcode,
    /// 3: Basic authorization key.
    BasicAuthorization,
    /// 4: Administrative authorization key.
    AdminAuthorization,
    /// 255: the anonymous well-known secret "ZigbeeAlliance18".
    Anonymous,
}

impl Psk {
    /// Raw enumeration value.
    pub const fn raw(self) -> u8 {
        match self {
            Psk::SymmetricToken => 0,
            Psk::InstallCode => 1,
            Psk::Passcode => 2,
            Psk::BasicAuthorization => 3,
            Psk::AdminAuthorization => 4,
            Psk::Anonymous => 255,
        }
    }

    /// From the raw value.
    pub const fn from_raw(v: u8) -> Option<Self> {
        match v {
            0 => Some(Psk::SymmetricToken),
            1 => Some(Psk::InstallCode),
            2 => Some(Psk::Passcode),
            3 => Some(Psk::BasicAuthorization),
            4 => Some(Psk::AdminAuthorization),
            255 => Some(Psk::Anonymous),
            _ => None,
        }
    }

    /// True for the pre-shared secrets that establish a provisioning
    /// session (§6.3.1).
    pub const fn is_provisioning(self) -> bool {
        matches!(self, Psk::Anonymous | Psk::InstallCode | Psk::Passcode)
    }
}

/// Writes the Key Negotiation Method TLV.
pub fn write_method(w: &mut Writer<'_>, method: Method, psk: Psk) -> Result<(), CodecError> {
    write_tlv(w, TAG_METHOD, &[method.raw(), psk.raw()])
}

/// Reads the Key Negotiation Method TLV.
pub fn method(set: &TlvSet<'_>) -> Option<(Method, Psk)> {
    let v = set.find(TAG_METHOD)?.value;
    match v {
        [m, p, ..] => Some((Method::from_raw(*m)?, Psk::from_raw(*p)?)),
        _ => None,
    }
}

/// Writes a public point TLV (`tag` selects the curve): EUI-64 (little
/// endian) followed by the point.
pub fn write_point(
    w: &mut Writer<'_>,
    tag: u8,
    device: ExtendedAddress,
    point: &[u8],
) -> Result<(), CodecError> {
    let mut buf = [0u8; 72];
    let n = 8 + point.len();
    let too_small = || CodecError::BufferTooSmall {
        needed: n,
        available: 72,
    };
    let b = buf.get_mut(..n).ok_or_else(too_small)?;
    b.get_mut(..8)
        .ok_or_else(too_small)?
        .copy_from_slice(&device.0.to_le_bytes());
    b.get_mut(8..).ok_or_else(too_small)?.copy_from_slice(point);
    write_tlv(w, tag, b)
}

/// Reads a public point TLV for `method`: the device EUI-64 and the
/// point.
pub fn point<'a>(set: &TlvSet<'a>, method: Method) -> Option<(ExtendedAddress, &'a [u8])> {
    let v = set.find(method.point_tag())?.value;
    if v.len() != 8 + method.point_len() {
        return None;
    }
    let (a, p) = v.split_at(8);
    let mut le = [0u8; 8];
    le.copy_from_slice(a);
    Some((ExtendedAddress(u64::from_le_bytes(le)), p))
}

/// Writes the Network Key Sequence Number TLV.
pub fn write_key_sequence(w: &mut Writer<'_>, sequence: u8) -> Result<(), CodecError> {
    write_tlv(w, TAG_KEY_SEQUENCE, &[sequence])
}

/// Reads the Network Key Sequence Number TLV.
pub fn key_sequence(set: &TlvSet<'_>) -> Option<u8> {
    set.find(TAG_KEY_SEQUENCE)?.value.first().copied()
}

/// Writes the MacTag TLV.
pub fn write_mac_tag(w: &mut Writer<'_>, tag: &[u8]) -> Result<(), CodecError> {
    write_tlv(w, TAG_MAC_TAG, tag)
}

/// Reads the MacTag TLV.
pub fn mac_tag<'a>(set: &TlvSet<'a>) -> Option<&'a [u8]> {
    set.find(TAG_MAC_TAG).map(|t| t.value)
}
