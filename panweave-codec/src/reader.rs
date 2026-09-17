//! Bounded byte reader.

use crate::CodecError;

/// A cursor over an immutable byte slice.
///
/// Every accessor checks bounds and returns [`CodecError::Truncated`]
/// instead of panicking. Borrowed sub-slices returned by
/// [`Reader::bytes`] keep the input lifetime so that frame types can hold
/// zero-copy payload references.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader at the start of `buf`.
    #[inline]
    pub const fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// True when every byte has been consumed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Current offset from the start of the input.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// The unconsumed tail as a slice (does not advance).
    #[inline]
    pub fn peek_rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// The bytes consumed so far.
    #[inline]
    pub fn consumed(&self) -> &'a [u8] {
        self.buf.get(..self.pos).unwrap_or(&[])
    }

    /// The whole underlying input.
    #[inline]
    pub const fn input(&self) -> &'a [u8] {
        self.buf
    }

    /// Consumes and returns the rest of the input.
    #[inline]
    pub fn take_rest(&mut self) -> &'a [u8] {
        let rest = self.peek_rest();
        self.pos = self.buf.len();
        rest
    }

    /// Consumes `n` bytes and returns them.
    #[inline]
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::Truncated {
            needed: n,
            available: self.remaining(),
        })?;
        match self.buf.get(self.pos..end) {
            Some(s) => {
                self.pos = end;
                Ok(s)
            }
            None => Err(CodecError::Truncated {
                needed: n,
                available: self.remaining(),
            }),
        }
    }

    /// Consumes `N` bytes into an array.
    #[inline]
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let s = self.bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    /// Skips `n` bytes.
    #[inline]
    pub fn skip(&mut self, n: usize) -> Result<(), CodecError> {
        self.bytes(n).map(|_| ())
    }

    /// Returns the next byte without consuming it.
    #[inline]
    pub fn peek_u8(&self) -> Result<u8, CodecError> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or(CodecError::Truncated {
                needed: 1,
                available: 0,
            })
    }

    /// Reads one byte.
    #[inline]
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        self.array::<1>().map(|b| b[0])
    }

    /// Reads a signed byte.
    #[inline]
    pub fn i8(&mut self) -> Result<i8, CodecError> {
        self.u8().map(|b| i8::from_le_bytes([b]))
    }

    /// Reads a little-endian `u16`.
    #[inline]
    pub fn u16_le(&mut self) -> Result<u16, CodecError> {
        self.array::<2>().map(u16::from_le_bytes)
    }

    /// Reads a little-endian `i16`.
    #[inline]
    pub fn i16_le(&mut self) -> Result<i16, CodecError> {
        self.array::<2>().map(i16::from_le_bytes)
    }

    /// Reads a little-endian 24-bit unsigned value.
    #[inline]
    pub fn u24_le(&mut self) -> Result<u32, CodecError> {
        let b = self.array::<3>()?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], 0]))
    }

    /// Reads a little-endian `u32`.
    #[inline]
    pub fn u32_le(&mut self) -> Result<u32, CodecError> {
        self.array::<4>().map(u32::from_le_bytes)
    }

    /// Reads a little-endian `i32`.
    #[inline]
    pub fn i32_le(&mut self) -> Result<i32, CodecError> {
        self.array::<4>().map(i32::from_le_bytes)
    }

    /// Reads a little-endian `u64`.
    #[inline]
    pub fn u64_le(&mut self) -> Result<u64, CodecError> {
        self.array::<8>().map(u64::from_le_bytes)
    }

    /// Reads a little-endian `i64`.
    #[inline]
    pub fn i64_le(&mut self) -> Result<i64, CodecError> {
        self.array::<8>().map(i64::from_le_bytes)
    }

    /// Reads a little-endian unsigned integer of `width` bytes (1..=8).
    pub fn uint_le(&mut self, width: usize) -> Result<u64, CodecError> {
        if width == 0 || width > 8 {
            return Err(CodecError::InvalidField {
                field: "integer width",
                value: u32::try_from(width).unwrap_or(u32::MAX),
            });
        }
        let s = self.bytes(width)?;
        let mut v: u64 = 0;
        for (i, b) in s.iter().enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
        Ok(v)
    }

    /// Returns a sub-reader over the next `n` bytes and advances past them.
    #[inline]
    pub fn sub(&mut self, n: usize) -> Result<Reader<'a>, CodecError> {
        self.bytes(n).map(Reader::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_bounds() {
        let data = [1u8, 2, 3, 4, 5, 6, 7];
        let mut r = Reader::new(&data);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16_le().unwrap(), 0x0302);
        assert_eq!(r.u24_le().unwrap(), 0x0006_0504);
        assert_eq!(r.remaining(), 1);
        assert!(matches!(
            r.u16_le(),
            Err(CodecError::Truncated {
                needed: 2,
                available: 1
            })
        ));
        assert_eq!(r.remaining(), 1, "failed read must not advance");
        assert_eq!(r.take_rest(), &[7]);
        assert!(r.is_empty());
        assert!(r.peek_u8().is_err());
    }

    #[test]
    fn uint_le_widths() {
        let data = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut r = Reader::new(&data);
        assert_eq!(r.uint_le(5).unwrap(), 0x00EE_DDCC_BBAA);
        assert!(r.uint_le(0).is_err());
        assert!(Reader::new(&data).uint_le(9).is_err());
    }

    #[test]
    fn sub_reader_isolates_range() {
        let data = [1u8, 2, 3, 4];
        let mut r = Reader::new(&data);
        let mut s = r.sub(2).unwrap();
        assert_eq!(s.u16_le().unwrap(), 0x0201);
        assert!(s.is_empty());
        assert_eq!(r.remaining(), 2);
        assert!(r.sub(3).is_err());
    }
}
