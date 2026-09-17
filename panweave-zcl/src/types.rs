//! ZCL data types (ZCL8 §2.6.2, Table 2-11) and wire values.
//!
//! [`DataType`] carries the data type identifier, its wire size class and
//! the analog/discrete classification used by attribute reporting
//! (§2.5.11.2). [`Value`] is a borrowed decoded value; attribute storage
//! keeps the raw little-endian encoding (see [`crate::attribute`]).

use panweave_codec::{CodecError, Reader, Writer};

/// A ZCL data type identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DataType {
    /// 0x00 no data.
    NoData,
    /// 0x08–0x0f general data, `n` octets (1–8).
    Data(u8),
    /// 0x10 boolean.
    Bool,
    /// 0x18–0x1f bitmap, `n` octets (1–8).
    Bitmap(u8),
    /// 0x20–0x27 unsigned integer, `n` octets (1–8).
    Uint(u8),
    /// 0x28–0x2f signed integer, `n` octets (1–8).
    Int(u8),
    /// 0x30 8-bit enumeration.
    Enum8,
    /// 0x31 16-bit enumeration.
    Enum16,
    /// 0x38 semi-precision float.
    Semi,
    /// 0x39 single-precision float.
    Single,
    /// 0x3a double-precision float.
    Double,
    /// 0x41 octet string (1-octet length).
    OctetString,
    /// 0x42 character string (1-octet length).
    CharString,
    /// 0x43 long octet string (2-octet length).
    LongOctetString,
    /// 0x44 long character string (2-octet length).
    LongCharString,
    /// 0x48 array.
    Array,
    /// 0x4c structure.
    Struct,
    /// 0x50 set.
    Set,
    /// 0x51 bag.
    Bag,
    /// 0xe0 time of day.
    TimeOfDay,
    /// 0xe1 date.
    Date,
    /// 0xe2 UTC time.
    UtcTime,
    /// 0xe8 cluster identifier.
    ClusterId,
    /// 0xe9 attribute identifier.
    AttributeId,
    /// 0xea BACnet OID.
    BacnetOid,
    /// 0xf0 IEEE address.
    Eui64,
    /// 0xf1 128-bit security key.
    Key128,
    /// 0xff unknown.
    Unknown,
    /// Any identifier not listed in Table 2-11.
    Reserved(u8),
}

impl DataType {
    /// Parses a data type identifier.
    pub const fn from_id(id: u8) -> Self {
        match id {
            0x00 => DataType::NoData,
            0x08..=0x0f => DataType::Data(id - 0x07),
            0x10 => DataType::Bool,
            0x18..=0x1f => DataType::Bitmap(id - 0x17),
            0x20..=0x27 => DataType::Uint(id - 0x1f),
            0x28..=0x2f => DataType::Int(id - 0x27),
            0x30 => DataType::Enum8,
            0x31 => DataType::Enum16,
            0x38 => DataType::Semi,
            0x39 => DataType::Single,
            0x3a => DataType::Double,
            0x41 => DataType::OctetString,
            0x42 => DataType::CharString,
            0x43 => DataType::LongOctetString,
            0x44 => DataType::LongCharString,
            0x48 => DataType::Array,
            0x4c => DataType::Struct,
            0x50 => DataType::Set,
            0x51 => DataType::Bag,
            0xe0 => DataType::TimeOfDay,
            0xe1 => DataType::Date,
            0xe2 => DataType::UtcTime,
            0xe8 => DataType::ClusterId,
            0xe9 => DataType::AttributeId,
            0xea => DataType::BacnetOid,
            0xf0 => DataType::Eui64,
            0xf1 => DataType::Key128,
            0xff => DataType::Unknown,
            other => DataType::Reserved(other),
        }
    }

    /// The data type identifier.
    pub const fn id(self) -> u8 {
        match self {
            DataType::NoData => 0x00,
            DataType::Data(n) => 0x07 + n,
            DataType::Bool => 0x10,
            DataType::Bitmap(n) => 0x17 + n,
            DataType::Uint(n) => 0x1f + n,
            DataType::Int(n) => 0x27 + n,
            DataType::Enum8 => 0x30,
            DataType::Enum16 => 0x31,
            DataType::Semi => 0x38,
            DataType::Single => 0x39,
            DataType::Double => 0x3a,
            DataType::OctetString => 0x41,
            DataType::CharString => 0x42,
            DataType::LongOctetString => 0x43,
            DataType::LongCharString => 0x44,
            DataType::Array => 0x48,
            DataType::Struct => 0x4c,
            DataType::Set => 0x50,
            DataType::Bag => 0x51,
            DataType::TimeOfDay => 0xe0,
            DataType::Date => 0xe1,
            DataType::UtcTime => 0xe2,
            DataType::ClusterId => 0xe8,
            DataType::AttributeId => 0xe9,
            DataType::BacnetOid => 0xea,
            DataType::Eui64 => 0xf0,
            DataType::Key128 => 0xf1,
            DataType::Unknown => 0xff,
            DataType::Reserved(v) => v,
        }
    }

    /// Wire size for fixed-size types; `None` for variable-length and
    /// unknown types.
    pub const fn fixed_len(self) -> Option<usize> {
        Some(match self {
            DataType::NoData => 0,
            DataType::Data(n) | DataType::Bitmap(n) | DataType::Uint(n) | DataType::Int(n) => {
                n as usize
            }
            DataType::Bool | DataType::Enum8 => 1,
            DataType::Enum16 | DataType::Semi | DataType::ClusterId | DataType::AttributeId => 2,
            DataType::Single
            | DataType::TimeOfDay
            | DataType::Date
            | DataType::UtcTime
            | DataType::BacnetOid => 4,
            DataType::Double | DataType::Eui64 => 8,
            DataType::Key128 => 16,
            _ => return None,
        })
    }

    /// Analog types (§2.6.2): integers, floats and times; changes are
    /// reported against a reportable change threshold.
    pub const fn is_analog(self) -> bool {
        matches!(
            self,
            DataType::Uint(_)
                | DataType::Int(_)
                | DataType::Semi
                | DataType::Single
                | DataType::Double
                | DataType::TimeOfDay
                | DataType::Date
                | DataType::UtcTime
        )
    }

    /// Discrete types: everything reportable that is not analog.
    pub const fn is_discrete(self) -> bool {
        !self.is_analog() && !self.is_composite() && !matches!(self, DataType::NoData)
    }

    /// Array, structure, set and bag (not reportable, §2.5.7.3).
    pub const fn is_composite(self) -> bool {
        matches!(
            self,
            DataType::Array | DataType::Struct | DataType::Set | DataType::Bag
        )
    }

    /// Length of the encoded value starting at the reader position
    /// without consuming it; `None` when the type is unknown or the
    /// data is truncated.
    pub fn value_len(self, bytes: &[u8]) -> Option<usize> {
        if let Some(n) = self.fixed_len() {
            return (bytes.len() >= n).then_some(n);
        }
        match self {
            DataType::OctetString | DataType::CharString => {
                let n = *bytes.first()?;
                let n = if n == 0xff { 0 } else { usize::from(n) };
                (bytes.len() > n).then_some(1 + n)
            }
            DataType::LongOctetString | DataType::LongCharString => {
                let n = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
                let n = if n == 0xffff { 0 } else { usize::from(n) };
                (bytes.len() >= 2 + n).then_some(2 + n)
            }
            DataType::Array | DataType::Set | DataType::Bag => {
                // Element type (1) + count (2) + elements.
                let elem = DataType::from_id(*bytes.first()?);
                let count = u16::from_le_bytes([*bytes.get(1)?, *bytes.get(2)?]);
                let mut pos = 3;
                if count != 0xffff {
                    for _ in 0..count {
                        let n = elem.value_len(bytes.get(pos..)?)?;
                        pos += n;
                    }
                }
                Some(pos)
            }
            DataType::Struct => {
                let count = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
                let mut pos = 2;
                if count != 0xffff {
                    for _ in 0..count {
                        let elem = DataType::from_id(*bytes.get(pos)?);
                        pos += 1;
                        let n = elem.value_len(bytes.get(pos..)?)?;
                        pos += n;
                    }
                }
                Some(pos)
            }
            _ => None,
        }
    }
}

/// A borrowed decoded ZCL value.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Value<'a> {
    /// No data.
    NoData,
    /// Boolean; `None` is the invalid value 0xff.
    Bool(Option<bool>),
    /// General data or bitmap of `width` octets.
    Bits {
        /// Octets.
        width: u8,
        /// Value.
        bits: u64,
    },
    /// Unsigned integer of `width` octets.
    Uint {
        /// Octets.
        width: u8,
        /// Value.
        value: u64,
    },
    /// Signed integer of `width` octets (sign-extended).
    Int {
        /// Octets.
        width: u8,
        /// Value.
        value: i64,
    },
    /// 8-bit enumeration.
    Enum8(u8),
    /// 16-bit enumeration.
    Enum16(u16),
    /// Semi-precision float (raw 16-bit encoding).
    Semi(u16),
    /// Single-precision float.
    Single(f32),
    /// Double-precision float.
    Double(f64),
    /// Octet or character string (short or long) — the bytes without the
    /// length prefix; `None` is the invalid string (length 0xff/0xffff).
    String {
        /// The data type (one of the four string types).
        ty: DataType,
        /// Bytes.
        bytes: Option<&'a [u8]>,
    },
    /// Array, structure, set or bag as raw encoded bytes (including the
    /// element type/count prefix).
    Composite {
        /// The data type.
        ty: DataType,
        /// Raw encoding.
        bytes: &'a [u8],
    },
    /// Time of day, date or UTC time (raw 32 bits).
    Time {
        /// The data type.
        ty: DataType,
        /// Raw value.
        raw: u32,
    },
    /// Cluster identifier.
    ClusterId(u16),
    /// Attribute identifier.
    AttributeId(u16),
    /// BACnet OID.
    BacnetOid(u32),
    /// IEEE address.
    Eui64(u64),
    /// Security key. Never printed in full by `Debug`.
    Key128([u8; 16]),
    /// Unknown type with raw bytes.
    Unknown(&'a [u8]),
}

impl<'a> Value<'a> {
    /// The data type this value encodes as.
    pub const fn data_type(&self) -> DataType {
        match self {
            Value::NoData => DataType::NoData,
            Value::Bool(_) => DataType::Bool,
            Value::Bits { width, .. } => DataType::Bitmap(*width),
            Value::Uint { width, .. } => DataType::Uint(*width),
            Value::Int { width, .. } => DataType::Int(*width),
            Value::Enum8(_) => DataType::Enum8,
            Value::Enum16(_) => DataType::Enum16,
            Value::Semi(_) => DataType::Semi,
            Value::Single(_) => DataType::Single,
            Value::Double(_) => DataType::Double,
            Value::String { ty, .. } | Value::Composite { ty, .. } | Value::Time { ty, .. } => *ty,
            Value::ClusterId(_) => DataType::ClusterId,
            Value::AttributeId(_) => DataType::AttributeId,
            Value::BacnetOid(_) => DataType::BacnetOid,
            Value::Eui64(_) => DataType::Eui64,
            Value::Key128(_) => DataType::Key128,
            Value::Unknown(_) => DataType::Unknown,
        }
    }

    /// Decodes a value of type `ty`.
    pub fn decode(r: &mut Reader<'a>, ty: DataType) -> Result<Self, CodecError> {
        Ok(match ty {
            DataType::NoData => Value::NoData,
            DataType::Bool => Value::Bool(match r.u8()? {
                0 => Some(false),
                1 => Some(true),
                0xff => None,
                v => {
                    return Err(CodecError::InvalidField {
                        field: "bool",
                        value: u32::from(v),
                    });
                }
            }),
            DataType::Data(n) | DataType::Bitmap(n) => Value::Bits {
                width: n,
                bits: r.uint_le(usize::from(n))?,
            },
            DataType::Uint(n) => Value::Uint {
                width: n,
                value: r.uint_le(usize::from(n))?,
            },
            DataType::Int(n) => {
                let raw = r.uint_le(usize::from(n))?;
                let shift = 64 - 8 * u32::from(n);
                #[allow(clippy::cast_possible_wrap)]
                let value = ((raw << shift) as i64) >> shift;
                Value::Int { width: n, value }
            }
            DataType::Enum8 => Value::Enum8(r.u8()?),
            DataType::Enum16 => Value::Enum16(r.u16_le()?),
            DataType::Semi => Value::Semi(r.u16_le()?),
            DataType::Single => Value::Single(f32::from_bits(r.u32_le()?)),
            DataType::Double => Value::Double(f64::from_bits(r.u64_le()?)),
            DataType::OctetString | DataType::CharString => {
                let n = r.u8()?;
                let bytes = if n == 0xff {
                    None
                } else {
                    Some(r.bytes(usize::from(n))?)
                };
                Value::String { ty, bytes }
            }
            DataType::LongOctetString | DataType::LongCharString => {
                let n = r.u16_le()?;
                let bytes = if n == 0xffff {
                    None
                } else {
                    Some(r.bytes(usize::from(n))?)
                };
                Value::String { ty, bytes }
            }
            DataType::Array | DataType::Struct | DataType::Set | DataType::Bag => {
                let n = ty.value_len(r.peek_rest()).ok_or(CodecError::Truncated {
                    needed: 3,
                    available: r.remaining(),
                })?;
                Value::Composite {
                    ty,
                    bytes: r.bytes(n)?,
                }
            }
            DataType::TimeOfDay | DataType::Date | DataType::UtcTime => Value::Time {
                ty,
                raw: r.u32_le()?,
            },
            DataType::ClusterId => Value::ClusterId(r.u16_le()?),
            DataType::AttributeId => Value::AttributeId(r.u16_le()?),
            DataType::BacnetOid => Value::BacnetOid(r.u32_le()?),
            DataType::Eui64 => Value::Eui64(r.u64_le()?),
            DataType::Key128 => Value::Key128(r.array::<16>()?),
            DataType::Unknown | DataType::Reserved(_) => {
                return Err(CodecError::Unsupported {
                    what: "ZCL data type",
                });
            }
        })
    }

    /// Encoded length of the value (without the type identifier).
    pub fn encoded_len(&self) -> usize {
        match self {
            Value::NoData => 0,
            Value::Bool(_) | Value::Enum8(_) => 1,
            Value::Bits { width, .. } | Value::Uint { width, .. } | Value::Int { width, .. } => {
                usize::from(*width)
            }
            Value::Enum16(_) | Value::Semi(_) | Value::ClusterId(_) | Value::AttributeId(_) => 2,
            Value::Single(_) | Value::Time { .. } | Value::BacnetOid(_) => 4,
            Value::Double(_) | Value::Eui64(_) => 8,
            Value::Key128(_) => 16,
            Value::String { ty, bytes } => {
                let prefix = if matches!(ty, DataType::OctetString | DataType::CharString) {
                    1
                } else {
                    2
                };
                prefix + bytes.map_or(0, <[u8]>::len)
            }
            Value::Composite { bytes, .. } | Value::Unknown(bytes) => bytes.len(),
        }
    }

    /// Encodes the value (without the type identifier).
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            Value::NoData => Ok(()),
            Value::Bool(b) => w.u8(b.map_or(0xff, u8::from)),
            Value::Bits { width, bits } => w.uint_le(*bits, usize::from(*width)),
            Value::Uint { width, value } => w.uint_le(*value, usize::from(*width)),
            Value::Int { width, value } =>
            {
                #[allow(clippy::cast_sign_loss)]
                w.uint_le(*value as u64, usize::from(*width))
            }
            Value::Enum8(v) => w.u8(*v),
            Value::Enum16(v) | Value::Semi(v) | Value::ClusterId(v) | Value::AttributeId(v) => {
                w.u16_le(*v)
            }
            Value::Single(v) => w.u32_le(v.to_bits()),
            Value::Double(v) => w.u64_le(v.to_bits()),
            Value::String { ty, bytes } => {
                let long = matches!(ty, DataType::LongOctetString | DataType::LongCharString);
                match bytes {
                    None => {
                        if long {
                            w.u16_le(0xffff)
                        } else {
                            w.u8(0xff)
                        }
                    }
                    Some(b) => {
                        if long {
                            if b.len() > 0xfffe {
                                return Err(CodecError::Unrepresentable { field: "string" });
                            }
                            #[allow(clippy::cast_possible_truncation)]
                            w.u16_le(b.len() as u16)?;
                        } else {
                            if b.len() > 0xfe {
                                return Err(CodecError::Unrepresentable { field: "string" });
                            }
                            #[allow(clippy::cast_possible_truncation)]
                            w.u8(b.len() as u8)?;
                        }
                        w.bytes(b)
                    }
                }
            }
            Value::Composite { bytes, .. } | Value::Unknown(bytes) => w.bytes(bytes),
            Value::Time { raw, .. } | Value::BacnetOid(raw) => w.u32_le(*raw),
            Value::Eui64(v) => w.u64_le(*v),
            Value::Key128(k) => w.bytes(k),
        }
    }

    /// The value as an unsigned magnitude for analog comparisons
    /// (integers, enumerations, times); floats are returned as their raw
    /// bit patterns.
    pub fn as_u64(&self) -> Option<u64> {
        Some(match self {
            Value::Bool(b) => u64::from(b.unwrap_or(false)),
            Value::Bits { bits, .. } => *bits,
            Value::Uint { value, .. } => *value,
            #[allow(clippy::cast_sign_loss)]
            Value::Int { value, .. } => *value as u64,
            Value::Enum8(v) => u64::from(*v),
            Value::Enum16(v) | Value::Semi(v) | Value::ClusterId(v) | Value::AttributeId(v) => {
                u64::from(*v)
            }
            Value::Single(v) => u64::from(v.to_bits()),
            Value::Double(v) => v.to_bits(),
            Value::Time { raw, .. } | Value::BacnetOid(raw) => u64::from(*raw),
            Value::Eui64(v) => *v,
            _ => return None,
        })
    }

    /// The value as a signed integer, when integral.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int { value, .. } => Some(*value),
            Value::Uint { value, .. } => i64::try_from(*value).ok(),
            Value::Bool(b) => Some(i64::from(b.unwrap_or(false))),
            Value::Enum8(v) => Some(i64::from(*v)),
            Value::Enum16(v) => Some(i64::from(*v)),
            _ => None,
        }
    }
}

/// Absolute difference between two analog values of the same type
/// (§2.5.11.2.3), saturating.
pub fn analog_delta(a: &Value<'_>, b: &Value<'_>) -> Option<u64> {
    match (a, b) {
        (Value::Int { value: x, .. }, Value::Int { value: y, .. }) => Some(x.abs_diff(*y)),
        (Value::Single(x), Value::Single(y)) =>
        {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Some((x - y).abs() as u64)
        }
        (Value::Double(x), Value::Double(y)) =>
        {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Some((x - y).abs() as u64)
        }
        _ => {
            let x = a.as_u64()?;
            let y = b.as_u64()?;
            Some(x.abs_diff(y))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_ids_round_trip() {
        for id in 0..=255u8 {
            let t = DataType::from_id(id);
            assert_eq!(t.id(), id, "{id:#x}");
        }
        assert_eq!(DataType::Uint(2).id(), 0x21);
        assert_eq!(DataType::Int(8).id(), 0x2f);
        assert_eq!(DataType::Bitmap(1).id(), 0x18);
        assert!(DataType::Uint(2).is_analog());
        assert!(DataType::Bitmap(1).is_discrete());
        assert!(!DataType::Array.is_discrete());
        assert_eq!(DataType::Key128.fixed_len(), Some(16));
        assert_eq!(DataType::CharString.fixed_len(), None);
    }

    #[test]
    fn value_round_trips() {
        let mut buf = [0u8; 32];
        let cases: [(DataType, &[u8]); 9] = [
            (DataType::Uint(1), &[0x7f]),
            (DataType::Uint(3), &[1, 2, 3]),
            (DataType::Int(2), &[0xff, 0xff]),
            (DataType::Bool, &[1]),
            (DataType::CharString, &[3, b'a', b'b', b'c']),
            (DataType::LongOctetString, &[2, 0, 9, 9]),
            (DataType::Eui64, &[1, 2, 3, 4, 5, 6, 7, 8]),
            (DataType::Array, &[0x20, 2, 0, 5, 6]),
            (DataType::Struct, &[1, 0, 0x21, 7, 0]),
        ];
        for (ty, bytes) in cases {
            let mut r = Reader::new(bytes);
            let v = Value::decode(&mut r, ty).unwrap();
            assert!(r.is_empty(), "{ty:?}");
            assert_eq!(v.data_type(), ty);
            assert_eq!(v.encoded_len(), bytes.len());
            let mut w = Writer::new(&mut buf);
            v.encode(&mut w).unwrap();
            assert_eq!(w.written(), bytes, "{ty:?}");
        }
        let mut r = Reader::new(&[0xff, 0xff]);
        assert_eq!(
            Value::decode(&mut r, DataType::Int(2)).unwrap(),
            Value::Int {
                width: 2,
                value: -1
            }
        );
        let mut r = Reader::new(&[0xff]);
        assert_eq!(
            Value::decode(&mut r, DataType::CharString).unwrap(),
            Value::String {
                ty: DataType::CharString,
                bytes: None
            }
        );
        let mut r = Reader::new(&[0x20, 3, 0, 1]);
        assert!(Value::decode(&mut r, DataType::Array).is_err());
        let mut r = Reader::new(&[2]);
        assert!(Value::decode(&mut r, DataType::Bool).is_err());
    }

    #[test]
    fn deltas() {
        let a = Value::Int {
            width: 1,
            value: -5,
        };
        let b = Value::Int { width: 1, value: 3 };
        assert_eq!(analog_delta(&a, &b), Some(8));
        let a = Value::Uint {
            width: 2,
            value: 10,
        };
        let b = Value::Uint {
            width: 2,
            value: 25,
        };
        assert_eq!(analog_delta(&a, &b), Some(15));
        assert_eq!(
            analog_delta(&Value::Single(1.5), &Value::Single(4.0)),
            Some(2)
        );
        assert_eq!(analog_delta(&Value::NoData, &Value::NoData), None);
    }
}
