//! Bounded byte writer.

use crate::CodecError;

/// A cursor over a mutable output slice.
///
/// Every write checks capacity and returns [`CodecError::BufferTooSmall`]
/// instead of panicking. The writer never grows the buffer: frames are
/// serialised into caller-provided storage.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Creates a writer at the start of `buf`.
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, pos: 0 }
    }

    /// Bytes written so far.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Remaining capacity.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Total capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// The bytes written so far.
    #[inline]
    pub fn written(&self) -> &[u8] {
        self.buf.get(..self.pos).unwrap_or(&[])
    }

    /// Consumes the writer and returns the written prefix.
    #[inline]
    pub fn finish(self) -> &'a mut [u8] {
        let pos = self.pos;
        self.buf.get_mut(..pos).unwrap_or(&mut [])
    }

    /// Reserves `n` bytes and returns them for in-place filling.
    #[inline]
    pub fn reserve(&mut self, n: usize) -> Result<&mut [u8], CodecError> {
        let available = self.remaining();
        let end = self.pos.checked_add(n).ok_or(CodecError::BufferTooSmall {
            needed: n,
            available,
        })?;
        match self.buf.get_mut(self.pos..end) {
            Some(s) => {
                self.pos = end;
                Ok(s)
            }
            None => Err(CodecError::BufferTooSmall {
                needed: n,
                available,
            }),
        }
    }

    /// Returns a mutable view of already written bytes in `range`, for
    /// back-patching fields such as length counts.
    #[inline]
    pub fn patch(&mut self, start: usize, len: usize) -> Result<&mut [u8], CodecError> {
        let end = start.checked_add(len).ok_or(CodecError::BufferTooSmall {
            needed: len,
            available: 0,
        })?;
        if end > self.pos {
            return Err(CodecError::BufferTooSmall {
                needed: end,
                available: self.pos,
            });
        }
        self.buf
            .get_mut(start..end)
            .ok_or(CodecError::BufferTooSmall {
                needed: len,
                available: 0,
            })
    }

    /// Writes a byte slice.
    #[inline]
    pub fn bytes(&mut self, src: &[u8]) -> Result<(), CodecError> {
        self.reserve(src.len())?.copy_from_slice(src);
        Ok(())
    }

    /// Writes one byte.
    #[inline]
    pub fn u8(&mut self, v: u8) -> Result<(), CodecError> {
        self.bytes(&[v])
    }

    /// Writes a signed byte.
    #[inline]
    pub fn i8(&mut self, v: i8) -> Result<(), CodecError> {
        self.bytes(&v.to_le_bytes())
    }

    /// Writes a little-endian `u16`.
    #[inline]
    pub fn u16_le(&mut self, v: u16) -> Result<(), CodecError> {
        self.bytes(&v.to_le_bytes())
    }

    /// Writes a little-endian `i16`.
    #[inline]
    pub fn i16_le(&mut self, v: i16) -> Result<(), CodecError> {
        self.bytes(&v.to_le_bytes())
    }

    /// Writes the low 24 bits of `v` little-endian.
    #[inline]
    pub fn u24_le(&mut self, v: u32) -> Result<(), CodecError> {
        let b = v.to_le_bytes();
        self.bytes(&[b[0], b[1], b[2]])
    }

    /// Writes a little-endian `u32`.
    #[inline]
    pub fn u32_le(&mut self, v: u32) -> Result<(), CodecError> {
        self.bytes(&v.to_le_bytes())
    }

    /// Writes a little-endian `i32`.
    #[inline]
    pub fn i32_le(&mut self, v: i32) -> Result<(), CodecError> {
        self.bytes(&v.to_le_bytes())
    }

    /// Writes a little-endian `u64`.
    #[inline]
    pub fn u64_le(&mut self, v: u64) -> Result<(), CodecError> {
        self.bytes(&v.to_le_bytes())
    }

    /// Writes a little-endian `i64`.
    #[inline]
    pub fn i64_le(&mut self, v: i64) -> Result<(), CodecError> {
        self.bytes(&v.to_le_bytes())
    }

    /// Writes the low `width` bytes of `v` little-endian (1..=8).
    pub fn uint_le(&mut self, v: u64, width: usize) -> Result<(), CodecError> {
        if width == 0 || width > 8 {
            return Err(CodecError::InvalidField {
                field: "integer width",
                value: u32::try_from(width).unwrap_or(u32::MAX),
            });
        }
        let b = v.to_le_bytes();
        self.bytes(b.get(..width).unwrap_or(&[]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_capacity() {
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        w.u8(1).unwrap();
        w.u16_le(0x0302).unwrap();
        assert_eq!(w.remaining(), 1);
        assert!(matches!(
            w.u16_le(9),
            Err(CodecError::BufferTooSmall {
                needed: 2,
                available: 1
            })
        ));
        assert_eq!(w.position(), 3, "failed write must not advance");
        w.u8(4).unwrap();
        assert_eq!(w.finish(), &[1, 2, 3, 4]);
    }

    #[test]
    fn patch_back_fills_length() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        w.u8(0).unwrap();
        w.bytes(&[9, 9, 9]).unwrap();
        let count = u8::try_from(w.position() - 1).unwrap();
        w.patch(0, 1).unwrap()[0] = count;
        assert!(w.patch(0, 9).is_err());
        assert_eq!(w.written(), &[3, 9, 9, 9]);
    }

    #[test]
    fn uint_le_width() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        w.uint_le(0x0102_0304, 3).unwrap();
        assert_eq!(w.written(), &[4, 3, 2]);
        assert!(w.uint_le(0, 9).is_err());
    }
}
