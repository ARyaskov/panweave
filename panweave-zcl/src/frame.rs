//! ZCL frame header (ZCL8 §2.4.1) and status enumeration (§2.6.3,
//! Table 2-12).

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{CommandId, ManufacturerCode, TransactionSequence};

/// Frame type sub-field (Figure 2-4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameType {
    /// Global command (§2.5).
    Global,
    /// Cluster-specific command.
    ClusterSpecific,
    /// Reserved values 2 and 3.
    Reserved(u8),
}

/// Direction sub-field (§2.4.1.1.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Direction {
    /// Client to server.
    ToServer,
    /// Server to client.
    ToClient,
}

impl Direction {
    /// The opposite direction (for responses).
    pub const fn reverse(self) -> Self {
        match self {
            Direction::ToServer => Direction::ToClient,
            Direction::ToClient => Direction::ToServer,
        }
    }
}

/// The frame control octet (§2.4.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FrameControl {
    /// Frame type.
    pub frame_type: FrameType,
    /// Manufacturer specific: the manufacturer code follows.
    pub manufacturer_specific: bool,
    /// Direction.
    pub direction: Direction,
    /// Disable Default Response.
    pub disable_default_response: bool,
}

impl FrameControl {
    /// Parses the octet (reserved bits ignored).
    pub const fn from_raw(v: u8) -> Self {
        FrameControl {
            frame_type: match v & 0x3 {
                0 => FrameType::Global,
                1 => FrameType::ClusterSpecific,
                r => FrameType::Reserved(r),
            },
            manufacturer_specific: v & 0x04 != 0,
            direction: if v & 0x08 != 0 {
                Direction::ToClient
            } else {
                Direction::ToServer
            },
            disable_default_response: v & 0x10 != 0,
        }
    }

    /// The octet.
    pub const fn raw(self) -> u8 {
        let ft = match self.frame_type {
            FrameType::Global => 0,
            FrameType::ClusterSpecific => 1,
            FrameType::Reserved(r) => r & 0x3,
        };
        ft | ((self.manufacturer_specific as u8) << 2)
            | ((matches!(self.direction, Direction::ToClient) as u8) << 3)
            | ((self.disable_default_response as u8) << 4)
    }
}

/// ZCL header (§2.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    /// Frame control.
    pub control: FrameControl,
    /// Manufacturer code, present iff `control.manufacturer_specific`.
    pub manufacturer: Option<ManufacturerCode>,
    /// Transaction sequence number.
    pub seq: TransactionSequence,
    /// Command identifier.
    pub command: CommandId,
}

impl Header {
    /// A global command header.
    pub const fn global(
        seq: TransactionSequence,
        command: CommandId,
        direction: Direction,
    ) -> Self {
        Header {
            control: FrameControl {
                frame_type: FrameType::Global,
                manufacturer_specific: false,
                direction,
                disable_default_response: false,
            },
            manufacturer: None,
            seq,
            command,
        }
    }

    /// A cluster-specific command header.
    pub const fn cluster_specific(
        seq: TransactionSequence,
        command: CommandId,
        direction: Direction,
    ) -> Self {
        Header {
            control: FrameControl {
                frame_type: FrameType::ClusterSpecific,
                manufacturer_specific: false,
                direction,
                disable_default_response: false,
            },
            manufacturer: None,
            seq,
            command,
        }
    }

    /// Adds a manufacturer code.
    pub const fn with_manufacturer(mut self, code: ManufacturerCode) -> Self {
        self.control.manufacturer_specific = true;
        self.manufacturer = Some(code);
        self
    }

    /// Sets Disable Default Response.
    pub const fn disable_default_response(mut self, v: bool) -> Self {
        self.control.disable_default_response = v;
        self
    }

    /// Header of a response to `self` (§2.4.1.3): same sequence number
    /// and manufacturer code, reversed direction, Disable Default
    /// Response set.
    pub const fn response(&self, command: CommandId, frame_type: FrameType) -> Self {
        Header {
            control: FrameControl {
                frame_type,
                manufacturer_specific: self.control.manufacturer_specific,
                direction: self.control.direction.reverse(),
                disable_default_response: true,
            },
            manufacturer: self.manufacturer,
            seq: self.seq,
            command,
        }
    }

    /// Decodes the header at the start of `bytes`, returning it and its
    /// length.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Header, usize), CodecError> {
        let mut r = Reader::new(bytes);
        let h = Header::decode(&mut r)?;
        Ok((h, r.position()))
    }
}

impl<'a> Decode<'a> for Header {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let control = FrameControl::from_raw(r.u8()?);
        let manufacturer = if control.manufacturer_specific {
            Some(ManufacturerCode(r.u16_le()?))
        } else {
            None
        };
        let seq = TransactionSequence(r.u8()?);
        let command = CommandId(r.u8()?);
        Ok(Header {
            control,
            manufacturer,
            seq,
            command,
        })
    }
}

impl Encode for Header {
    fn encoded_len(&self) -> usize {
        3 + if self.manufacturer.is_some() { 2 } else { 0 }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut c = self.control;
        c.manufacturer_specific = self.manufacturer.is_some();
        w.u8(c.raw())?;
        if let Some(m) = self.manufacturer {
            w.u16_le(m.0)?;
        }
        w.u8(self.seq.0)?;
        w.u8(self.command.0)
    }
}

/// A ZCL frame: header and payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Frame<'a> {
    /// Header.
    pub header: Header,
    /// Payload.
    pub payload: &'a [u8],
}

impl<'a> Decode<'a> for Frame<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(Frame {
            header: Header::decode(r)?,
            payload: r.take_rest(),
        })
    }
}

impl Encode for Frame<'_> {
    fn encoded_len(&self) -> usize {
        self.header.encoded_len() + self.payload.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        self.header.encode(w)?;
        w.bytes(self.payload)
    }
}

/// ZCL status (Table 2-12). Deprecated values are kept for reception.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ZclStatus {
    /// SUCCESS.
    Success,
    /// FAILURE.
    Failure,
    /// NOT_AUTHORIZED.
    NotAuthorized,
    /// MALFORMED_COMMAND.
    MalformedCommand,
    /// UNSUP_CLUSTER_COMMAND (UNSUP_COMMAND in ZCL8).
    UnsupportedClusterCommand,
    /// UNSUP_GENERAL_COMMAND.
    UnsupportedGeneralCommand,
    /// UNSUP_MANUF_CLUSTER_COMMAND.
    UnsupportedManufacturerClusterCommand,
    /// UNSUP_MANUF_GENERAL_COMMAND.
    UnsupportedManufacturerGeneralCommand,
    /// INVALID_FIELD.
    InvalidField,
    /// UNSUPPORTED_ATTRIBUTE.
    UnsupportedAttribute,
    /// INVALID_VALUE.
    InvalidValue,
    /// READ_ONLY.
    ReadOnly,
    /// INSUFFICIENT_SPACE.
    InsufficientSpace,
    /// DUPLICATE_EXISTS.
    DuplicateExists,
    /// NOT_FOUND.
    NotFound,
    /// UNREPORTABLE_ATTRIBUTE.
    UnreportableAttribute,
    /// INVALID_DATA_TYPE.
    InvalidDataType,
    /// INVALID_SELECTOR.
    InvalidSelector,
    /// WRITE_ONLY.
    WriteOnly,
    /// INCONSISTENT_STARTUP_STATE.
    InconsistentStartupState,
    /// DEFINED_OUT_OF_BAND.
    DefinedOutOfBand,
    /// INCONSISTENT.
    Inconsistent,
    /// ACTION_DENIED.
    ActionDenied,
    /// TIMEOUT.
    Timeout,
    /// ABORT.
    Abort,
    /// INVALID_IMAGE.
    InvalidImage,
    /// WAIT_FOR_DATA.
    WaitForData,
    /// NO_IMAGE_AVAILABLE.
    NoImageAvailable,
    /// REQUIRE_MORE_IMAGE.
    RequireMoreImage,
    /// NOTIFICATION_PENDING.
    NotificationPending,
    /// HARDWARE_FAILURE.
    HardwareFailure,
    /// SOFTWARE_FAILURE.
    SoftwareFailure,
    /// CALIBRATION_ERROR.
    CalibrationError,
    /// UNSUPPORTED_CLUSTER.
    UnsupportedCluster,
    /// LIMIT_REACHED.
    LimitReached,
    /// Any other value.
    Unknown(u8),
}

impl ZclStatus {
    /// Parses the octet.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x00 => ZclStatus::Success,
            0x01 => ZclStatus::Failure,
            0x7e => ZclStatus::NotAuthorized,
            0x80 => ZclStatus::MalformedCommand,
            0x81 => ZclStatus::UnsupportedClusterCommand,
            0x82 => ZclStatus::UnsupportedGeneralCommand,
            0x83 => ZclStatus::UnsupportedManufacturerClusterCommand,
            0x84 => ZclStatus::UnsupportedManufacturerGeneralCommand,
            0x85 => ZclStatus::InvalidField,
            0x86 => ZclStatus::UnsupportedAttribute,
            0x87 => ZclStatus::InvalidValue,
            0x88 => ZclStatus::ReadOnly,
            0x89 => ZclStatus::InsufficientSpace,
            0x8a => ZclStatus::DuplicateExists,
            0x8b => ZclStatus::NotFound,
            0x8c => ZclStatus::UnreportableAttribute,
            0x8d => ZclStatus::InvalidDataType,
            0x8e => ZclStatus::InvalidSelector,
            0x8f => ZclStatus::WriteOnly,
            0x90 => ZclStatus::InconsistentStartupState,
            0x91 => ZclStatus::DefinedOutOfBand,
            0x92 => ZclStatus::Inconsistent,
            0x93 => ZclStatus::ActionDenied,
            0x94 => ZclStatus::Timeout,
            0x95 => ZclStatus::Abort,
            0x96 => ZclStatus::InvalidImage,
            0x97 => ZclStatus::WaitForData,
            0x98 => ZclStatus::NoImageAvailable,
            0x99 => ZclStatus::RequireMoreImage,
            0x9a => ZclStatus::NotificationPending,
            0xc0 => ZclStatus::HardwareFailure,
            0xc1 => ZclStatus::SoftwareFailure,
            0xc2 => ZclStatus::CalibrationError,
            0xc3 => ZclStatus::UnsupportedCluster,
            0xc4 => ZclStatus::LimitReached,
            other => ZclStatus::Unknown(other),
        }
    }

    /// The octet.
    pub const fn raw(self) -> u8 {
        match self {
            ZclStatus::Success => 0x00,
            ZclStatus::Failure => 0x01,
            ZclStatus::NotAuthorized => 0x7e,
            ZclStatus::MalformedCommand => 0x80,
            ZclStatus::UnsupportedClusterCommand => 0x81,
            ZclStatus::UnsupportedGeneralCommand => 0x82,
            ZclStatus::UnsupportedManufacturerClusterCommand => 0x83,
            ZclStatus::UnsupportedManufacturerGeneralCommand => 0x84,
            ZclStatus::InvalidField => 0x85,
            ZclStatus::UnsupportedAttribute => 0x86,
            ZclStatus::InvalidValue => 0x87,
            ZclStatus::ReadOnly => 0x88,
            ZclStatus::InsufficientSpace => 0x89,
            ZclStatus::DuplicateExists => 0x8a,
            ZclStatus::NotFound => 0x8b,
            ZclStatus::UnreportableAttribute => 0x8c,
            ZclStatus::InvalidDataType => 0x8d,
            ZclStatus::InvalidSelector => 0x8e,
            ZclStatus::WriteOnly => 0x8f,
            ZclStatus::InconsistentStartupState => 0x90,
            ZclStatus::DefinedOutOfBand => 0x91,
            ZclStatus::Inconsistent => 0x92,
            ZclStatus::ActionDenied => 0x93,
            ZclStatus::Timeout => 0x94,
            ZclStatus::Abort => 0x95,
            ZclStatus::InvalidImage => 0x96,
            ZclStatus::WaitForData => 0x97,
            ZclStatus::NoImageAvailable => 0x98,
            ZclStatus::RequireMoreImage => 0x99,
            ZclStatus::NotificationPending => 0x9a,
            ZclStatus::HardwareFailure => 0xc0,
            ZclStatus::SoftwareFailure => 0xc1,
            ZclStatus::CalibrationError => 0xc2,
            ZclStatus::UnsupportedCluster => 0xc3,
            ZclStatus::LimitReached => 0xc4,
            ZclStatus::Unknown(v) => v,
        }
    }

    /// True for SUCCESS.
    #[inline]
    pub const fn is_success(self) -> bool {
        matches!(self, ZclStatus::Success)
    }
}

impl<'a> Decode<'a> for ZclStatus {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(ZclStatus::from_raw(r.u8()?))
    }
}

impl Encode for ZclStatus {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let h = Header::global(TransactionSequence(9), CommandId(0x00), Direction::ToServer);
        let mut buf = [0u8; 8];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x00, 9, 0]);
        let m = Header::cluster_specific(TransactionSequence(1), CommandId(2), Direction::ToClient)
            .with_manufacturer(ManufacturerCode(0x1234))
            .disable_default_response(true);
        let n = m.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x1D, 0x34, 0x12, 1, 2]);
        let (d, len) = Header::decode_prefix(&buf[..n]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(d, m);
        let r = m.response(CommandId(0x0B), FrameType::Global);
        assert_eq!(r.control.direction, Direction::ToServer);
        assert!(r.control.disable_default_response);
        assert_eq!(r.seq, TransactionSequence(1));
        assert_eq!(r.manufacturer, Some(ManufacturerCode(0x1234)));
        assert!(Header::decode_prefix(&[0x04, 1]).is_err());
    }

    #[test]
    fn status_round_trip() {
        for v in 0..=255u8 {
            assert_eq!(ZclStatus::from_raw(v).raw(), v);
        }
    }
}
