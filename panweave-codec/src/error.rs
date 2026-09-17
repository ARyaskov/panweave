//! Codec error type.

use core::fmt;

/// Errors produced while decoding or encoding wire data.
///
/// The variants are deliberately specific so that higher layers can decide
/// between "drop silently" (R23.2 §1.2.5), "respond with a status" and
/// "this is a bug in the caller" without string matching.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CodecError {
    /// The input ended before a field could be read.
    Truncated {
        /// Bytes required by the field being read.
        needed: usize,
        /// Bytes actually available.
        available: usize,
    },
    /// The input contained bytes after the last expected field.
    TrailingBytes {
        /// Number of unexpected bytes.
        count: usize,
    },
    /// A field carried a value the protocol does not allow at this
    /// position.
    InvalidField {
        /// Name of the field (static protocol vocabulary).
        field: &'static str,
        /// The offending value, widened.
        value: u32,
    },
    /// A reserved field or bit that must be zero was not.
    ReservedBitsSet {
        /// Name of the field.
        field: &'static str,
    },
    /// A length or count field is inconsistent with the available data.
    LengthMismatch {
        /// Name of the field.
        field: &'static str,
    },
    /// The output buffer is too small.
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The value is not representable in the wire format (e.g. a list
    /// longer than its count field allows).
    Unrepresentable {
        /// Name of the field.
        field: &'static str,
    },
    /// A TLV-specific violation (R23.2 Annex I).
    Tlv(TlvError),
    /// The frame uses a feature that this implementation does not
    /// support; the caller decides whether to drop or reject.
    Unsupported {
        /// What is unsupported.
        what: &'static str,
    },
}

/// TLV processing failures (R23.2 Annex I.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlvError {
    /// A TLV header or value was cut short by the end of the message.
    Truncated,
    /// The same tag (other than Manufacturer Specific) appeared twice.
    DuplicateTag {
        /// The duplicated tag.
        tag: u8,
    },
    /// A known TLV was shorter than its minimum length or its contents were
    /// internally truncated.
    Malformed {
        /// The offending tag.
        tag: u8,
    },
    /// An encapsulation TLV contained another encapsulation TLV.
    NestedEncapsulation {
        /// The outer tag.
        tag: u8,
    },
    /// A required TLV was absent.
    Missing {
        /// The missing tag.
        tag: u8,
    },
}

impl From<TlvError> for CodecError {
    fn from(e: TlvError) -> Self {
        CodecError::Tlv(e)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Truncated { needed, available } => {
                write!(
                    f,
                    "truncated input: needed {needed} bytes, {available} available"
                )
            }
            CodecError::TrailingBytes { count } => write!(f, "{count} trailing bytes"),
            CodecError::InvalidField { field, value } => {
                write!(f, "invalid value {value:#x} for field {field}")
            }
            CodecError::ReservedBitsSet { field } => write!(f, "reserved bits set in {field}"),
            CodecError::LengthMismatch { field } => write!(f, "length mismatch in {field}"),
            CodecError::BufferTooSmall { needed, available } => {
                write!(
                    f,
                    "buffer too small: needed {needed} bytes, {available} available"
                )
            }
            CodecError::Unrepresentable { field } => write!(f, "{field} is not representable"),
            CodecError::Tlv(e) => write!(f, "TLV error: {e}"),
            CodecError::Unsupported { what } => write!(f, "unsupported: {what}"),
        }
    }
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlvError::Truncated => f.write_str("truncated TLV"),
            TlvError::DuplicateTag { tag } => write!(f, "duplicate TLV tag {tag}"),
            TlvError::Malformed { tag } => write!(f, "malformed TLV tag {tag}"),
            TlvError::NestedEncapsulation { tag } => {
                write!(f, "nested encapsulation in TLV tag {tag}")
            }
            TlvError::Missing { tag } => write!(f, "missing TLV tag {tag}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CodecError {}

#[cfg(feature = "std")]
impl std::error::Error for TlvError {}
