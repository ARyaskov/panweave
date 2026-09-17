//! Bounded, panic-free binary codec primitives for Panweave.
//!
//! * [`Reader`] / [`Writer`] — cursor types over caller-provided slices with
//!   explicit truncation and capacity errors. No method panics on any
//!   input.
//! * [`Decode`] / [`Encode`] — the traits implemented by every frame,
//!   command and descriptor type across the stack.
//! * [`tlv`] — Type-Length-Value framing per R23.2 Annex I, including the
//!   duplicate, unknown-tag, malformed and encapsulation rules.
//!
//! All wire integers are little-endian (R23.2 §1.2.2, §1.2.3).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub mod reader;
pub mod tlv;
pub mod writer;

pub use error::CodecError;
pub use reader::Reader;
pub use writer::Writer;

/// A value that can be parsed from a byte cursor.
///
/// Implementations must be total: any input either yields a value or a
/// [`CodecError`]; they never panic and never read past the cursor's end.
pub trait Decode<'a>: Sized {
    /// Parses a value, advancing the reader past the consumed bytes.
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError>;

    /// Parses a value from a complete slice and requires the whole slice to
    /// be consumed.
    fn decode_exact(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(input);
        let v = Self::decode(&mut r)?;
        if r.is_empty() {
            Ok(v)
        } else {
            Err(CodecError::TrailingBytes {
                count: r.remaining(),
            })
        }
    }
}

/// A value that can be serialised into a byte cursor.
pub trait Encode {
    /// Number of bytes [`Encode::encode`] will write.
    fn encoded_len(&self) -> usize;

    /// Serialises the value, advancing the writer.
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError>;

    /// Serialises into `out`, returning the number of bytes written.
    fn encode_to_slice(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        self.encode(&mut w)?;
        Ok(w.position())
    }
}

/// Convenience for types whose wire form is a fixed-size integer.
macro_rules! impl_int_codec {
    ($($t:ty => $rd:ident, $wr:ident);* $(;)?) => {
        $(
            impl<'a> Decode<'a> for $t {
                #[inline]
                fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
                    r.$rd()
                }
            }
            impl Encode for $t {
                #[inline]
                fn encoded_len(&self) -> usize {
                    core::mem::size_of::<$t>()
                }
                #[inline]
                fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
                    w.$wr(*self)
                }
            }
        )*
    };
}

impl_int_codec! {
    u8 => u8, u8;
    u16 => u16_le, u16_le;
    u32 => u32_le, u32_le;
    u64 => u64_le, u64_le;
    i8 => i8, i8;
    i16 => i16_le, i16_le;
    i32 => i32_le, i32_le;
    i64 => i64_le, i64_le;
}

impl<'a, const N: usize> Decode<'a> for [u8; N] {
    #[inline]
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        r.array::<N>()
    }
}

impl<const N: usize> Encode for [u8; N] {
    #[inline]
    fn encoded_len(&self) -> usize {
        N
    }
    #[inline]
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.bytes(self)
    }
}

impl Encode for &[u8] {
    #[inline]
    fn encoded_len(&self) -> usize {
        self.len()
    }
    #[inline]
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.bytes(self)
    }
}

mod types_impl {
    //! `Decode`/`Encode` for the `panweave-types` newtypes.
    use super::{CodecError, Decode, Encode, Reader, Writer};
    use panweave_types::{
        AttributeId, ClusterId, CommandId, DeviceId, Endpoint, ExtendedAddress, FrameCounter,
        GroupAddress, KeySequenceNumber, ManufacturerCode, PanId, ProfileId, ShortAddress,
        TransactionSequence,
    };

    macro_rules! wrap {
        ($($t:ident => $inner:ty);* $(;)?) => {
            $(
                impl<'a> Decode<'a> for $t {
                    #[inline]
                    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
                        <$inner as Decode>::decode(r).map($t)
                    }
                }
                impl Encode for $t {
                    #[inline]
                    fn encoded_len(&self) -> usize {
                        core::mem::size_of::<$inner>()
                    }
                    #[inline]
                    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
                        self.0.encode(w)
                    }
                }
            )*
        };
    }

    wrap! {
        PanId => u16;
        ShortAddress => u16;
        ExtendedAddress => u64;
        GroupAddress => u16;
        ProfileId => u16;
        ClusterId => u16;
        AttributeId => u16;
        CommandId => u8;
        ManufacturerCode => u16;
        DeviceId => u16;
        FrameCounter => u32;
        KeySequenceNumber => u8;
        TransactionSequence => u8;
        Endpoint => u8;
    }

    impl<'a> Decode<'a> for panweave_types::MacCapability {
        #[inline]
        fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
            r.u8().map(panweave_types::MacCapability::from_raw)
        }
    }

    impl Encode for panweave_types::MacCapability {
        #[inline]
        fn encoded_len(&self) -> usize {
            1
        }
        #[inline]
        fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
            w.u8(self.raw())
        }
    }

    impl<'a> Decode<'a> for panweave_types::Key128 {
        #[inline]
        fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
            r.array::<16>().map(panweave_types::Key128::from_bytes)
        }
    }

    impl Encode for panweave_types::Key128 {
        #[inline]
        fn encoded_len(&self) -> usize {
            16
        }
        #[inline]
        fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
            w.bytes(self.as_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::{ExtendedAddress, ShortAddress};

    #[test]
    fn integer_round_trip() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        0x12u8.encode(&mut w).unwrap();
        0x3456u16.encode(&mut w).unwrap();
        0x789a_bcdeu32.encode(&mut w).unwrap();
        ShortAddress(0xFFFD).encode(&mut w).unwrap();
        ExtendedAddress(0x0102_0304_0506_0708)
            .encode(&mut w)
            .unwrap();
        let n = w.position();
        assert_eq!(n, 1 + 2 + 4 + 2 + 8);
        let mut r = Reader::new(&buf[..n]);
        assert_eq!(u8::decode(&mut r).unwrap(), 0x12);
        assert_eq!(u16::decode(&mut r).unwrap(), 0x3456);
        assert_eq!(u32::decode(&mut r).unwrap(), 0x789a_bcde);
        assert_eq!(ShortAddress::decode(&mut r).unwrap(), ShortAddress(0xFFFD));
        assert_eq!(
            ExtendedAddress::decode(&mut r).unwrap(),
            ExtendedAddress(0x0102_0304_0506_0708)
        );
        assert!(r.is_empty());
        assert_eq!(&buf[..3], &[0x12, 0x56, 0x34]);
    }

    #[test]
    fn decode_exact_rejects_trailing() {
        assert!(matches!(
            u16::decode_exact(&[1, 2, 3]),
            Err(CodecError::TrailingBytes { count: 1 })
        ));
        assert_eq!(u16::decode_exact(&[1, 2]).unwrap(), 0x0201);
    }
}
