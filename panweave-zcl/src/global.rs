//! General (global) command frames (ZCL8 §2.5, Table 2-3).
//!
//! Records are decoded lazily through iterators over the borrowed
//! payload; builders append records to a [`Writer`].

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{AttributeId, CommandId};

use crate::frame::ZclStatus;
use crate::structured::Selector;
use crate::types::{DataType, Value};

/// Global command identifiers (Table 2-3).
pub mod command {
    use panweave_types::CommandId;

    /// Read Attributes.
    pub const READ_ATTRIBUTES: CommandId = CommandId(0x00);
    /// Read Attributes Response.
    pub const READ_ATTRIBUTES_RESPONSE: CommandId = CommandId(0x01);
    /// Write Attributes.
    pub const WRITE_ATTRIBUTES: CommandId = CommandId(0x02);
    /// Write Attributes Undivided.
    pub const WRITE_ATTRIBUTES_UNDIVIDED: CommandId = CommandId(0x03);
    /// Write Attributes Response.
    pub const WRITE_ATTRIBUTES_RESPONSE: CommandId = CommandId(0x04);
    /// Write Attributes No Response.
    pub const WRITE_ATTRIBUTES_NO_RESPONSE: CommandId = CommandId(0x05);
    /// Configure Reporting.
    pub const CONFIGURE_REPORTING: CommandId = CommandId(0x06);
    /// Configure Reporting Response.
    pub const CONFIGURE_REPORTING_RESPONSE: CommandId = CommandId(0x07);
    /// Read Reporting Configuration.
    pub const READ_REPORTING_CONFIGURATION: CommandId = CommandId(0x08);
    /// Read Reporting Configuration Response.
    pub const READ_REPORTING_CONFIGURATION_RESPONSE: CommandId = CommandId(0x09);
    /// Report Attributes.
    pub const REPORT_ATTRIBUTES: CommandId = CommandId(0x0a);
    /// Default Response.
    pub const DEFAULT_RESPONSE: CommandId = CommandId(0x0b);
    /// Discover Attributes.
    pub const DISCOVER_ATTRIBUTES: CommandId = CommandId(0x0c);
    /// Discover Attributes Response.
    pub const DISCOVER_ATTRIBUTES_RESPONSE: CommandId = CommandId(0x0d);
    /// Read Attributes Structured.
    pub const READ_ATTRIBUTES_STRUCTURED: CommandId = CommandId(0x0e);
    /// Write Attributes Structured.
    pub const WRITE_ATTRIBUTES_STRUCTURED: CommandId = CommandId(0x0f);
    /// Write Attributes Structured Response.
    pub const WRITE_ATTRIBUTES_STRUCTURED_RESPONSE: CommandId = CommandId(0x10);
    /// Discover Commands Received.
    pub const DISCOVER_COMMANDS_RECEIVED: CommandId = CommandId(0x11);
    /// Discover Commands Received Response.
    pub const DISCOVER_COMMANDS_RECEIVED_RESPONSE: CommandId = CommandId(0x12);
    /// Discover Commands Generated.
    pub const DISCOVER_COMMANDS_GENERATED: CommandId = CommandId(0x13);
    /// Discover Commands Generated Response.
    pub const DISCOVER_COMMANDS_GENERATED_RESPONSE: CommandId = CommandId(0x14);
    /// Discover Attributes Extended.
    pub const DISCOVER_ATTRIBUTES_EXTENDED: CommandId = CommandId(0x15);
    /// Discover Attributes Extended Response.
    pub const DISCOVER_ATTRIBUTES_EXTENDED_RESPONSE: CommandId = CommandId(0x16);
}

/// Iterator over the attribute identifiers of a Read Attributes command
/// (§2.5.1).
#[derive(Clone, Debug)]
pub struct AttributeIds<'a>(pub &'a [u8]);

impl Iterator for AttributeIds<'_> {
    type Item = AttributeId;

    fn next(&mut self) -> Option<AttributeId> {
        let (head, rest) = self.0.split_first_chunk::<2>()?;
        self.0 = rest;
        Some(AttributeId(u16::from_le_bytes(*head)))
    }
}

/// Writes an attribute identifier list (Read Attributes payload).
pub fn write_attribute_ids(w: &mut Writer<'_>, ids: &[AttributeId]) -> Result<(), CodecError> {
    for id in ids {
        w.u16_le(id.0)?;
    }
    Ok(())
}

/// A read attribute status record (§2.5.2.1).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ReadAttributeStatus<'a> {
    /// Attribute identifier.
    pub id: AttributeId,
    /// Status.
    pub status: ZclStatus,
    /// Value on SUCCESS.
    pub value: Option<Value<'a>>,
}

impl<'a> Decode<'a> for ReadAttributeStatus<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let id = AttributeId(r.u16_le()?);
        let status = ZclStatus::decode(r)?;
        let value = if status.is_success() {
            let ty = DataType::from_id(r.u8()?);
            Some(Value::decode(r, ty)?)
        } else {
            None
        };
        Ok(ReadAttributeStatus { id, status, value })
    }
}

impl Encode for ReadAttributeStatus<'_> {
    fn encoded_len(&self) -> usize {
        3 + self.value.as_ref().map_or(0, |v| 1 + v.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.id.0)?;
        w.u8(self.status.raw())?;
        if let Some(v) = &self.value {
            w.u8(v.data_type().id())?;
            v.encode(w)?;
        }
        Ok(())
    }
}

/// A write attribute record (§2.5.3.1) and a report attribute record
/// (§2.5.11.1): identifier, data type and value.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct AttributeValue<'a> {
    /// Attribute identifier.
    pub id: AttributeId,
    /// Value (carries its data type).
    pub value: Value<'a>,
}

impl<'a> Decode<'a> for AttributeValue<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let id = AttributeId(r.u16_le()?);
        let ty = DataType::from_id(r.u8()?);
        let value = Value::decode(r, ty)?;
        Ok(AttributeValue { id, value })
    }
}

impl Encode for AttributeValue<'_> {
    fn encoded_len(&self) -> usize {
        3 + self.value.encoded_len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.id.0)?;
        w.u8(self.value.data_type().id())?;
        self.value.encode(w)
    }
}

/// A write attribute status record (§2.5.5.1); the identifier is omitted
/// in the single SUCCESS record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WriteAttributeStatus {
    /// Status.
    pub status: ZclStatus,
    /// Attribute identifier (absent for the lone SUCCESS record).
    pub id: Option<AttributeId>,
}

impl<'a> Decode<'a> for WriteAttributeStatus {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZclStatus::decode(r)?;
        let id = if status.is_success() && r.remaining() < 2 {
            None
        } else {
            Some(AttributeId(r.u16_le()?))
        };
        Ok(WriteAttributeStatus { status, id })
    }
}

impl Encode for WriteAttributeStatus {
    fn encoded_len(&self) -> usize {
        1 + self.id.map_or(0, |_| 2)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        if let Some(id) = self.id {
            w.u16_le(id.0)?;
        }
        Ok(())
    }
}

/// A Read Attributes Structured record: identifier and selector
/// (§2.5.15.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReadStructured {
    /// Attribute identifier.
    pub id: AttributeId,
    /// Selector.
    pub selector: Selector,
}

impl ReadStructured {
    /// Encodes the record.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.id.0)?;
        self.selector.encode(w)
    }
}

/// A Write Attributes Structured record (Figure 2-32).
#[derive(Clone, PartialEq, Debug)]
pub struct WriteStructured<'a> {
    /// Attribute identifier.
    pub id: AttributeId,
    /// Selector.
    pub selector: Selector,
    /// Value (carries the element's data type).
    pub value: Value<'a>,
}

impl WriteStructured<'_> {
    /// Encodes the record.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.id.0)?;
        self.selector.encode(w)?;
        w.u8(self.value.data_type().id())?;
        self.value.encode(w)
    }
}

/// A Write Attributes Structured status record (Figure 2-35): the lone
/// SUCCESS record carries neither identifier nor selector.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WriteStructuredStatus {
    /// Status.
    pub status: ZclStatus,
    /// Attribute identifier and the selector of the failing element.
    pub target: Option<(AttributeId, Selector)>,
}

impl<'a> Decode<'a> for WriteStructuredStatus {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZclStatus::decode(r)?;
        if status.is_success() && r.remaining() < 3 {
            return Ok(WriteStructuredStatus {
                status,
                target: None,
            });
        }
        let id = AttributeId(r.u16_le()?);
        let selector = Selector::decode(r)?.unwrap_or_default();
        Ok(WriteStructuredStatus {
            status,
            target: Some((id, selector)),
        })
    }
}

impl Encode for WriteStructuredStatus {
    fn encoded_len(&self) -> usize {
        1 + self
            .target
            .as_ref()
            .map_or(0, |(_, s)| 3 + 2 * s.indices.len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        if let Some((id, selector)) = &self.target {
            w.u16_le(id.0)?;
            selector.encode(w)?;
        }
        Ok(())
    }
}

/// Direction field of reporting configuration records (§2.5.7.1.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReportDirection {
    /// 0x00: the attribute is reported by the receiver of the command.
    Reported,
    /// 0x01: the sender reports; the receiver expects reports (timeout).
    Received,
}

/// An attribute reporting configuration record (§2.5.7.1).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ReportingConfig<'a> {
    /// Direction 0x00.
    Reported {
        /// Attribute identifier.
        id: AttributeId,
        /// Attribute data type.
        ty: DataType,
        /// Minimum reporting interval (seconds).
        min: u16,
        /// Maximum reporting interval (seconds; 0xffff terminates).
        max: u16,
        /// Reportable change (analog types only).
        change: Option<Value<'a>>,
    },
    /// Direction 0x01.
    Received {
        /// Attribute identifier.
        id: AttributeId,
        /// Timeout period (seconds).
        timeout: u16,
    },
}

impl ReportingConfig<'_> {
    /// The attribute identifier.
    pub const fn id(&self) -> AttributeId {
        match self {
            ReportingConfig::Reported { id, .. } | ReportingConfig::Received { id, .. } => *id,
        }
    }

    /// The direction.
    pub const fn direction(&self) -> ReportDirection {
        match self {
            ReportingConfig::Reported { .. } => ReportDirection::Reported,
            ReportingConfig::Received { .. } => ReportDirection::Received,
        }
    }
}

impl<'a> Decode<'a> for ReportingConfig<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let dir = r.u8()?;
        let id = AttributeId(r.u16_le()?);
        match dir {
            0x00 => {
                let ty = DataType::from_id(r.u8()?);
                let min = r.u16_le()?;
                let max = r.u16_le()?;
                let change = if ty.is_analog() {
                    Some(Value::decode(r, ty)?)
                } else {
                    None
                };
                Ok(ReportingConfig::Reported {
                    id,
                    ty,
                    min,
                    max,
                    change,
                })
            }
            0x01 => Ok(ReportingConfig::Received {
                id,
                timeout: r.u16_le()?,
            }),
            v => Err(CodecError::InvalidField {
                field: "direction",
                value: u32::from(v),
            }),
        }
    }
}

impl Encode for ReportingConfig<'_> {
    fn encoded_len(&self) -> usize {
        match self {
            ReportingConfig::Reported { change, .. } => {
                8 + change.as_ref().map_or(0, Value::encoded_len)
            }
            ReportingConfig::Received { .. } => 5,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            ReportingConfig::Reported {
                id,
                ty,
                min,
                max,
                change,
            } => {
                w.u8(0)?;
                w.u16_le(id.0)?;
                w.u8(ty.id())?;
                w.u16_le(*min)?;
                w.u16_le(*max)?;
                if let Some(c) = change {
                    c.encode(w)?;
                }
                Ok(())
            }
            ReportingConfig::Received { id, timeout } => {
                w.u8(1)?;
                w.u16_le(id.0)?;
                w.u16_le(*timeout)
            }
        }
    }
}

/// An attribute status record of Configure Reporting Response (§2.5.8.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfigureReportingStatus {
    /// Status.
    pub status: ZclStatus,
    /// Direction and identifier (absent for the lone SUCCESS record).
    pub target: Option<(ReportDirection, AttributeId)>,
}

impl<'a> Decode<'a> for ConfigureReportingStatus {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZclStatus::decode(r)?;
        let target = if status.is_success() && r.remaining() < 3 {
            None
        } else {
            let dir = match r.u8()? {
                0 => ReportDirection::Reported,
                1 => ReportDirection::Received,
                v => {
                    return Err(CodecError::InvalidField {
                        field: "direction",
                        value: u32::from(v),
                    });
                }
            };
            Some((dir, AttributeId(r.u16_le()?)))
        };
        Ok(ConfigureReportingStatus { status, target })
    }
}

impl Encode for ConfigureReportingStatus {
    fn encoded_len(&self) -> usize {
        1 + self.target.map_or(0, |_| 3)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        if let Some((dir, id)) = self.target {
            w.u8(u8::from(dir == ReportDirection::Received))?;
            w.u16_le(id.0)?;
        }
        Ok(())
    }
}

/// A Read Reporting Configuration record (§2.5.9.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReadReportingConfig {
    /// Direction.
    pub direction: ReportDirection,
    /// Attribute identifier.
    pub id: AttributeId,
}

impl<'a> Decode<'a> for ReadReportingConfig {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let direction = match r.u8()? {
            0 => ReportDirection::Reported,
            1 => ReportDirection::Received,
            v => {
                return Err(CodecError::InvalidField {
                    field: "direction",
                    value: u32::from(v),
                });
            }
        };
        Ok(ReadReportingConfig {
            direction,
            id: AttributeId(r.u16_le()?),
        })
    }
}

impl Encode for ReadReportingConfig {
    fn encoded_len(&self) -> usize {
        3
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(u8::from(self.direction == ReportDirection::Received))?;
        w.u16_le(self.id.0)
    }
}

/// A Read Reporting Configuration Response record (§2.5.10.1).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ReadReportingConfigStatus<'a> {
    /// Status.
    pub status: ZclStatus,
    /// The configuration on SUCCESS (identifier and direction are always
    /// present; on failure `config` carries only them).
    pub config: ReportingConfig<'a>,
}

impl<'a> Decode<'a> for ReadReportingConfigStatus<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZclStatus::decode(r)?;
        if status.is_success() {
            return Ok(ReadReportingConfigStatus {
                status,
                config: ReportingConfig::decode(r)?,
            });
        }
        let dir = r.u8()?;
        let id = AttributeId(r.u16_le()?);
        let config = if dir == 0 {
            ReportingConfig::Reported {
                id,
                ty: DataType::NoData,
                min: 0,
                max: 0,
                change: None,
            }
        } else {
            ReportingConfig::Received { id, timeout: 0 }
        };
        Ok(ReadReportingConfigStatus { status, config })
    }
}

impl Encode for ReadReportingConfigStatus<'_> {
    fn encoded_len(&self) -> usize {
        1 + if self.status.is_success() {
            self.config.encoded_len()
        } else {
            3
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        if self.status.is_success() {
            self.config.encode(w)
        } else {
            w.u8(u8::from(
                self.config.direction() == ReportDirection::Received,
            ))?;
            w.u16_le(self.config.id().0)
        }
    }
}

/// Default Response (§2.5.12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DefaultResponse {
    /// The command being responded to.
    pub command: CommandId,
    /// Status.
    pub status: ZclStatus,
}

impl<'a> Decode<'a> for DefaultResponse {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(DefaultResponse {
            command: CommandId(r.u8()?),
            status: ZclStatus::decode(r)?,
        })
    }
}

impl Encode for DefaultResponse {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.command.0)?;
        w.u8(self.status.raw())
    }
}

/// Discover Attributes / Discover Attributes Extended request (§2.5.13,
/// §2.5.22).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoverAttributes {
    /// Start attribute identifier.
    pub start: AttributeId,
    /// Maximum attribute identifiers to return.
    pub max: u8,
}

impl<'a> Decode<'a> for DiscoverAttributes {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(DiscoverAttributes {
            start: AttributeId(r.u16_le()?),
            max: r.u8()?,
        })
    }
}

impl Encode for DiscoverAttributes {
    fn encoded_len(&self) -> usize {
        3
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.start.0)?;
        w.u8(self.max)
    }
}

/// An attribute report record of Discover Attributes Response
/// (§2.5.14.1) or the extended form with access control (§2.5.23.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttributeInfo {
    /// Attribute identifier.
    pub id: AttributeId,
    /// Data type.
    pub ty: DataType,
    /// Access control (extended form only): bit 0 readable, bit 1
    /// writable, bit 2 reportable.
    pub access: Option<u8>,
}

impl AttributeInfo {
    /// Access control bit: readable.
    pub const READABLE: u8 = 0x01;
    /// Access control bit: writable.
    pub const WRITABLE: u8 = 0x02;
    /// Access control bit: reportable.
    pub const REPORTABLE: u8 = 0x04;
}

impl Encode for AttributeInfo {
    fn encoded_len(&self) -> usize {
        3 + self.access.map_or(0, |_| 1)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.id.0)?;
        w.u8(self.ty.id())?;
        if let Some(a) = self.access {
            w.u8(a)?;
        }
        Ok(())
    }
}

/// Discover Attributes (Extended) Response (§2.5.14, §2.5.23).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiscoverAttributesResponse<'a> {
    /// Discovery complete.
    pub complete: bool,
    /// Encoded attribute information records.
    pub records: &'a [u8],
    /// Records carry the access control octet (extended form).
    pub extended: bool,
}

impl<'a> DiscoverAttributesResponse<'a> {
    /// Decodes with the given form.
    pub fn parse(bytes: &'a [u8], extended: bool) -> Result<Self, CodecError> {
        let (complete, records) = bytes.split_first().ok_or(CodecError::Truncated {
            needed: 1,
            available: 0,
        })?;
        Ok(DiscoverAttributesResponse {
            complete: *complete != 0,
            records,
            extended,
        })
    }

    /// Iterates the records.
    pub fn iter(&self) -> impl Iterator<Item = AttributeInfo> + 'a {
        let ext = self.extended;
        let size = if ext { 4 } else { 3 };
        self.records.chunks_exact(size).map(move |c| AttributeInfo {
            id: AttributeId(u16::from_le_bytes([c[0], c[1]])),
            ty: DataType::from_id(c[2]),
            access: if ext { c.get(3).copied() } else { None },
        })
    }
}

/// Discover Commands Received / Generated request (§2.5.18, §2.5.20).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoverCommands {
    /// Start command identifier.
    pub start: CommandId,
    /// Maximum identifiers.
    pub max: u8,
}

impl<'a> Decode<'a> for DiscoverCommands {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(DiscoverCommands {
            start: CommandId(r.u8()?),
            max: r.u8()?,
        })
    }
}

impl Encode for DiscoverCommands {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.start.0)?;
        w.u8(self.max)
    }
}

/// Discover Commands Received / Generated Response (§2.5.19, §2.5.21).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiscoverCommandsResponse<'a> {
    /// Discovery complete.
    pub complete: bool,
    /// Command identifiers.
    pub commands: &'a [u8],
}

impl<'a> Decode<'a> for DiscoverCommandsResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(DiscoverCommandsResponse {
            complete: r.u8()? != 0,
            commands: r.take_rest(),
        })
    }
}

impl Encode for DiscoverCommandsResponse<'_> {
    fn encoded_len(&self) -> usize {
        1 + self.commands.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(u8::from(self.complete))?;
        w.bytes(self.commands)
    }
}

/// Iterator over consecutive records of type `T` in a payload.
#[derive(Clone, Debug)]
pub struct Records<'a, T> {
    reader: Reader<'a>,
    failed: bool,
    _t: core::marker::PhantomData<T>,
}

impl<'a, T: Decode<'a>> Records<'a, T> {
    /// Creates the iterator over `payload`.
    pub const fn new(payload: &'a [u8]) -> Self {
        Records {
            reader: Reader::new(payload),
            failed: false,
            _t: core::marker::PhantomData,
        }
    }
}

impl<'a, T: Decode<'a>> Iterator for Records<'a, T> {
    type Item = Result<T, CodecError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.reader.is_empty() {
            return None;
        }
        match T::decode(&mut self.reader) {
            Ok(v) => Some(Ok(v)),
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_write_records() {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        write_attribute_ids(&mut w, &[AttributeId(0), AttributeId(0x4000)]).unwrap();
        let ids: heapless::Vec<_, 4> = AttributeIds(w.written()).collect();
        assert_eq!(ids.as_slice(), &[AttributeId(0), AttributeId(0x4000)]);

        let rec = ReadAttributeStatus {
            id: AttributeId(1),
            status: ZclStatus::Success,
            value: Some(Value::Uint { width: 1, value: 3 }),
        };
        let fail = ReadAttributeStatus {
            id: AttributeId(2),
            status: ZclStatus::UnsupportedAttribute,
            value: None,
        };
        let mut w = Writer::new(&mut buf);
        rec.encode(&mut w).unwrap();
        fail.encode(&mut w).unwrap();
        assert_eq!(w.written(), &[1, 0, 0, 0x20, 3, 2, 0, 0x86]);
        let recs: heapless::Vec<_, 4> = Records::<ReadAttributeStatus>::new(w.written())
            .map(Result::unwrap)
            .collect();
        assert_eq!(recs.as_slice(), &[rec, fail]);

        let wr = AttributeValue {
            id: AttributeId(0x10),
            value: Value::String {
                ty: DataType::CharString,
                bytes: Some(b"hi"),
            },
        };
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        wr.encode(&mut w).unwrap();
        assert_eq!(w.written(), &[0x10, 0, 0x42, 2, b'h', b'i']);
        assert_eq!(
            Records::<AttributeValue>::new(w.written())
                .next()
                .unwrap()
                .unwrap(),
            wr
        );
        let ok = WriteAttributeStatus {
            status: ZclStatus::Success,
            id: None,
        };
        let mut buf2 = [0u8; 8];
        let mut w = Writer::new(&mut buf2);
        ok.encode(&mut w).unwrap();
        assert_eq!(w.written(), &[0]);
        assert_eq!(WriteAttributeStatus::decode_exact(&[0]).unwrap(), ok);
        assert_eq!(
            WriteAttributeStatus::decode_exact(&[0x88, 5, 0]).unwrap(),
            WriteAttributeStatus {
                status: ZclStatus::ReadOnly,
                id: Some(AttributeId(5))
            }
        );
    }

    #[test]
    fn reporting_records() {
        let mut buf = [0u8; 64];
        let cfg = ReportingConfig::Reported {
            id: AttributeId(0),
            ty: DataType::Uint(2),
            min: 1,
            max: 300,
            change: Some(Value::Uint { width: 2, value: 5 }),
        };
        let mut w = Writer::new(&mut buf);
        cfg.encode(&mut w).unwrap();
        assert_eq!(w.written(), &[0, 0, 0, 0x21, 1, 0, 0x2c, 1, 5, 0]);
        assert_eq!(ReportingConfig::decode_exact(w.written()).unwrap(), cfg);
        let disc = ReportingConfig::Reported {
            id: AttributeId(0),
            ty: DataType::Bool,
            min: 0,
            max: 0xffff,
            change: None,
        };
        let mut w = Writer::new(&mut buf);
        disc.encode(&mut w).unwrap();
        assert_eq!(w.written().len(), 8);
        let rcv = ReportingConfig::Received {
            id: AttributeId(7),
            timeout: 60,
        };
        let mut w = Writer::new(&mut buf);
        rcv.encode(&mut w).unwrap();
        assert_eq!(ReportingConfig::decode_exact(w.written()).unwrap(), rcv);

        let st = ConfigureReportingStatus {
            status: ZclStatus::UnreportableAttribute,
            target: Some((ReportDirection::Reported, AttributeId(9))),
        };
        let mut w = Writer::new(&mut buf);
        st.encode(&mut w).unwrap();
        assert_eq!(w.written(), &[0x8c, 0, 9, 0]);
        assert_eq!(
            ConfigureReportingStatus::decode_exact(&[0]).unwrap().target,
            None
        );

        let rr = ReadReportingConfigStatus {
            status: ZclStatus::Success,
            config: cfg,
        };
        let mut w = Writer::new(&mut buf);
        rr.encode(&mut w).unwrap();
        assert_eq!(
            ReadReportingConfigStatus::decode_exact(w.written()).unwrap(),
            rr
        );
        let rf = ReadReportingConfigStatus {
            status: ZclStatus::UnsupportedAttribute,
            config: ReportingConfig::Received {
                id: AttributeId(3),
                timeout: 0,
            },
        };
        let mut w = Writer::new(&mut buf);
        rf.encode(&mut w).unwrap();
        assert_eq!(w.written(), &[0x86, 1, 3, 0]);
        assert_eq!(
            ReadReportingConfigStatus::decode_exact(w.written()).unwrap(),
            rf
        );
    }

    #[test]
    fn discovery_and_default_response() {
        let mut buf = [0u8; 64];
        let d = DefaultResponse {
            command: CommandId(0x42),
            status: ZclStatus::UnsupportedClusterCommand,
        };
        let n = d.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x42, 0x81]);
        assert_eq!(DefaultResponse::decode_exact(&buf[..n]).unwrap(), d);

        let mut w = Writer::new(&mut buf);
        w.u8(1).unwrap();
        AttributeInfo {
            id: AttributeId(0),
            ty: DataType::Bool,
            access: None,
        }
        .encode(&mut w)
        .unwrap();
        AttributeInfo {
            id: AttributeId(0x4000),
            ty: DataType::Uint(1),
            access: None,
        }
        .encode(&mut w)
        .unwrap();
        let rsp = DiscoverAttributesResponse::parse(w.written(), false).unwrap();
        assert!(rsp.complete);
        let infos: heapless::Vec<_, 4> = rsp.iter().collect();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[1].ty, DataType::Uint(1));

        let dc = DiscoverCommandsResponse {
            complete: false,
            commands: &[0, 1, 2],
        };
        let n = dc.encode_to_slice(&mut buf).unwrap();
        assert_eq!(
            DiscoverCommandsResponse::decode_exact(&buf[..n]).unwrap(),
            dc
        );
    }
}
