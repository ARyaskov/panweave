//! Auxiliary security header (R23.2 §4.5.1) and CCM nonce (§4.5.2.2).

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{ExtendedAddress, FrameCounter, KeySequenceNumber};

use crate::ccm::NONCE_LEN;

/// Security level (Table 4-38).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SecurityLevel {
    /// No security.
    None,
    /// MIC-32.
    Mic32,
    /// MIC-64.
    Mic64,
    /// MIC-128.
    Mic128,
    /// Encryption only.
    Enc,
    /// Encryption with MIC-32 (the Zigbee PRO default).
    EncMic32,
    /// Encryption with MIC-64.
    EncMic64,
    /// Encryption with MIC-128.
    EncMic128,
}

impl SecurityLevel {
    /// Parses the 3-bit field.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        match v & 0x7 {
            0 => SecurityLevel::None,
            1 => SecurityLevel::Mic32,
            2 => SecurityLevel::Mic64,
            3 => SecurityLevel::Mic128,
            4 => SecurityLevel::Enc,
            5 => SecurityLevel::EncMic32,
            6 => SecurityLevel::EncMic64,
            _ => SecurityLevel::EncMic128,
        }
    }

    /// The 3-bit wire value.
    #[inline]
    pub const fn raw(self) -> u8 {
        match self {
            SecurityLevel::None => 0,
            SecurityLevel::Mic32 => 1,
            SecurityLevel::Mic64 => 2,
            SecurityLevel::Mic128 => 3,
            SecurityLevel::Enc => 4,
            SecurityLevel::EncMic32 => 5,
            SecurityLevel::EncMic64 => 6,
            SecurityLevel::EncMic128 => 7,
        }
    }

    /// MIC length `M` in octets.
    #[inline]
    pub const fn mic_len(self) -> usize {
        match self {
            SecurityLevel::None | SecurityLevel::Enc => 0,
            SecurityLevel::Mic32 | SecurityLevel::EncMic32 => 4,
            SecurityLevel::Mic64 | SecurityLevel::EncMic64 => 8,
            SecurityLevel::Mic128 | SecurityLevel::EncMic128 => 16,
        }
    }

    /// True when the payload is encrypted.
    #[inline]
    pub const fn encrypts(self) -> bool {
        self.raw() & 0x4 != 0
    }
}

/// Key identifier (Table 4-39).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyIdentifier {
    /// Data key (link key).
    Data,
    /// Network key.
    Network,
    /// Key-transport key.
    KeyTransport,
    /// Key-load key.
    KeyLoad,
}

impl KeyIdentifier {
    #[inline]
    const fn from_raw(v: u8) -> Self {
        match v & 0x3 {
            0 => KeyIdentifier::Data,
            1 => KeyIdentifier::Network,
            2 => KeyIdentifier::KeyTransport,
            _ => KeyIdentifier::KeyLoad,
        }
    }

    #[inline]
    const fn raw(self) -> u8 {
        match self {
            KeyIdentifier::Data => 0,
            KeyIdentifier::Network => 1,
            KeyIdentifier::KeyTransport => 2,
            KeyIdentifier::KeyLoad => 3,
        }
    }
}

/// The 1-octet security control field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityControl {
    /// Security level.
    pub level: SecurityLevel,
    /// Key identifier.
    pub key_id: KeyIdentifier,
    /// Extended nonce: the source address field is present.
    pub extended_nonce: bool,
}

impl SecurityControl {
    /// Parses the octet. Reserved bits 6–7 are ignored on reception
    /// (R23.2 §1.2.6 style tolerance); they are always transmitted as
    /// zero.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        SecurityControl {
            level: SecurityLevel::from_raw(v),
            key_id: KeyIdentifier::from_raw(v >> 3),
            extended_nonce: v & 0x20 != 0,
        }
    }

    /// The wire octet.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.level.raw() | (self.key_id.raw() << 3) | ((self.extended_nonce as u8) << 5)
    }

    /// Returns a copy with the level replaced (used when the on-air level
    /// field is zeroed per §4.3.1.1 step 8 and restored per §4.3.1.2).
    #[inline]
    pub const fn with_level(self, level: SecurityLevel) -> Self {
        SecurityControl { level, ..self }
    }
}

/// The auxiliary security header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AuxHeader {
    /// Security control.
    pub control: SecurityControl,
    /// Frame counter.
    pub frame_counter: FrameCounter,
    /// Source (extended) address, present iff `control.extended_nonce`.
    pub source: Option<ExtendedAddress>,
    /// Key sequence number, present iff the key identifier is `Network`.
    pub key_sequence: Option<KeySequenceNumber>,
}

impl AuxHeader {
    /// Builds a NWK-layer header: network key, extended nonce, sequence
    /// number present.
    pub const fn network(
        level: SecurityLevel,
        frame_counter: FrameCounter,
        source: ExtendedAddress,
        key_sequence: KeySequenceNumber,
    ) -> Self {
        AuxHeader {
            control: SecurityControl {
                level,
                key_id: KeyIdentifier::Network,
                extended_nonce: true,
            },
            frame_counter,
            source: Some(source),
            key_sequence: Some(key_sequence),
        }
    }

    /// Builds an APS-layer header with a link-derived key.
    pub const fn link(
        level: SecurityLevel,
        key_id: KeyIdentifier,
        frame_counter: FrameCounter,
        source: Option<ExtendedAddress>,
    ) -> Self {
        AuxHeader {
            control: SecurityControl {
                level,
                key_id,
                extended_nonce: source.is_some(),
            },
            frame_counter,
            source,
            key_sequence: None,
        }
    }

    /// Length of the encoded header.
    #[inline]
    pub const fn encoded_len(&self) -> usize {
        1 + 4
            + if self.source.is_some() { 8 } else { 0 }
            + if self.key_sequence.is_some() { 1 } else { 0 }
    }

    /// Builds the 13-octet CCM nonce: source address, frame counter,
    /// security control (§4.5.2.2). `source` overrides the header's own
    /// source field when the extended nonce is absent (the receiver
    /// supplies the sender's address from its tables).
    pub fn nonce(&self, source: ExtendedAddress) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[..8].copy_from_slice(&self.source.unwrap_or(source).to_le_bytes());
        n[8..12].copy_from_slice(&self.frame_counter.0.to_le_bytes());
        n[12] = self.control.raw();
        n
    }
}

impl<'a> Decode<'a> for AuxHeader {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let control = SecurityControl::from_raw(r.u8()?);
        let frame_counter = FrameCounter(r.u32_le()?);
        let source = if control.extended_nonce {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        let key_sequence = if control.key_id == KeyIdentifier::Network {
            Some(KeySequenceNumber(r.u8()?))
        } else {
            None
        };
        Ok(AuxHeader {
            control,
            frame_counter,
            source,
            key_sequence,
        })
    }
}

impl Encode for AuxHeader {
    fn encoded_len(&self) -> usize {
        AuxHeader::encoded_len(self)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if self.control.extended_nonce != self.source.is_some() {
            return Err(CodecError::InvalidField {
                field: "extended nonce",
                value: u32::from(self.control.extended_nonce),
            });
        }
        if (self.control.key_id == KeyIdentifier::Network) != self.key_sequence.is_some() {
            return Err(CodecError::InvalidField {
                field: "key sequence number",
                value: u32::from(self.key_sequence.is_some()),
            });
        }
        w.u8(self.control.raw())?;
        w.u32_le(self.frame_counter.0)?;
        if let Some(s) = self.source {
            w.u64_le(s.0)?;
        }
        if let Some(k) = self.key_sequence {
            w.u8(k.0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nwk_aux_header_round_trip_and_nonce() {
        let h = AuxHeader::network(
            SecurityLevel::EncMic32,
            FrameCounter(0x0102_0304),
            ExtendedAddress(0x1122_3344_5566_7788),
            KeySequenceNumber(7),
        );
        assert_eq!(h.encoded_len(), 14);
        let mut buf = [0u8; 16];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            &[
                0x2D, 0x04, 0x03, 0x02, 0x01, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x07
            ]
        );
        assert_eq!(AuxHeader::decode_exact(&buf[..n]).unwrap(), h);
        let nonce = h.nonce(ExtendedAddress::ZERO);
        assert_eq!(
            nonce,
            [
                0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x04, 0x03, 0x02, 0x01, 0x2D
            ]
        );
        // On-air level zeroed: control 0x28, restored with with_level.
        let zeroed = h.control.with_level(SecurityLevel::None);
        assert_eq!(zeroed.raw(), 0x28);
        assert_eq!(zeroed.with_level(SecurityLevel::EncMic32), h.control);
    }

    #[test]
    fn aps_aux_header_without_extended_nonce() {
        let h = AuxHeader::link(
            SecurityLevel::EncMic32,
            KeyIdentifier::KeyTransport,
            FrameCounter(1),
            None,
        );
        assert_eq!(h.encoded_len(), 5);
        let mut buf = [0u8; 8];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x15, 1, 0, 0, 0]);
        let d = AuxHeader::decode_exact(&buf[..n]).unwrap();
        assert_eq!(d, h);
        assert_eq!(d.nonce(ExtendedAddress(0xAA))[0], 0xAA);
        assert!(AuxHeader::decode_exact(&[0x2D, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn security_level_properties() {
        for v in 0..8u8 {
            let l = SecurityLevel::from_raw(v);
            assert_eq!(l.raw(), v);
        }
        assert_eq!(SecurityLevel::EncMic32.mic_len(), 4);
        assert!(SecurityLevel::EncMic32.encrypts());
        assert!(!SecurityLevel::Mic128.encrypts());
        assert_eq!(SecurityLevel::Mic128.mic_len(), 16);
        assert_eq!(SecurityLevel::Enc.mic_len(), 0);
    }
}
