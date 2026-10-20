//! Byte-stream framing of protocol messages.
//!
//! A frame on the wire is
//!
//! ```text
//! 0x00 | COBS(body | CRC-16/CCITT-FALSE(body), little endian) | 0x00
//! ```
//!
//! COBS removes every zero octet from the encoded body, so `0x00` only
//! ever delimits frames: a receiver that starts mid-stream, loses bytes
//! or sees garbage (a panic message printed by the boot ROM, a
//! disconnect) resynchronizes at the next delimiter, and the CRC
//! rejects whatever is left of a damaged frame. Bodies are at most
//! [`MAX_BODY`] octets; longer input is discarded up to the next
//! delimiter without buffering it.

/// Frame delimiter.
pub const DELIMITER: u8 = 0x00;

/// Largest message body.
pub const MAX_BODY: usize = 512;

/// Largest frame on the wire: the body, its CRC, the COBS overhead (one
/// octet per 254) and the two delimiters.
pub const MAX_WIRE: usize = MAX_BODY + 2 + (MAX_BODY + 2) / 254 + 1 + 2;

/// Framing errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameError {
    /// The body exceeds [`MAX_BODY`] (encoding) or the frame exceeded
    /// [`MAX_WIRE`] before its delimiter (decoding).
    TooLarge,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The COBS encoding is invalid.
    Corrupt,
    /// The CRC does not match.
    Crc,
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xffff), as `panweave-storage`
/// uses for its records.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &b in bytes {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn put(out: &mut [u8], at: usize, b: u8) -> Result<(), FrameError> {
    *out.get_mut(at).ok_or(FrameError::BufferTooSmall)? = b;
    Ok(())
}

/// Encodes `body` as a complete frame into `out`; returns its length.
pub fn encode(body: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    if body.len() > MAX_BODY {
        return Err(FrameError::TooLarge);
    }
    let crc = crc16(body).to_le_bytes();
    put(out, 0, DELIMITER)?;
    let mut code_at = 1;
    let mut pos = 2;
    let mut code: u8 = 1;
    for &b in body.iter().chain(crc.iter()) {
        if b == 0 {
            put(out, code_at, code)?;
            code_at = pos;
            pos += 1;
            code = 1;
        } else {
            put(out, pos, b)?;
            pos += 1;
            code += 1;
            if code == 0xff {
                put(out, code_at, code)?;
                code_at = pos;
                pos += 1;
                code = 1;
            }
        }
    }
    put(out, code_at, code)?;
    put(out, pos, DELIMITER)?;
    Ok(pos + 1)
}

/// Decodes COBS `raw` into `out`; returns the decoded length.
fn cobs_decode(raw: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    let mut i = 0;
    let mut o = 0;
    while i < raw.len() {
        let code = raw[i];
        if code == 0 {
            return Err(FrameError::Corrupt);
        }
        i += 1;
        let n = usize::from(code - 1);
        let block = raw.get(i..i + n).ok_or(FrameError::Corrupt)?;
        out.get_mut(o..o + n)
            .ok_or(FrameError::TooLarge)?
            .copy_from_slice(block);
        i += n;
        o += n;
        if code != 0xff && i < raw.len() {
            put(out, o, 0).map_err(|_| FrameError::TooLarge)?;
            o += 1;
        }
    }
    Ok(o)
}

/// Incremental frame decoder: push received octets, get bodies back.
pub struct FrameDecoder {
    raw: [u8; MAX_WIRE],
    len: usize,
    /// The frame being received outgrew the buffer: drop it at the next
    /// delimiter.
    overflow: bool,
    body: [u8; MAX_BODY + 2],
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("len", &self.len)
            .field("overflow", &self.overflow)
            .finish_non_exhaustive()
    }
}

impl FrameDecoder {
    /// An empty decoder.
    pub const fn new() -> Self {
        FrameDecoder {
            raw: [0; MAX_WIRE],
            len: 0,
            overflow: false,
            body: [0; MAX_BODY + 2],
        }
    }

    /// Discards a partially received frame.
    pub fn reset(&mut self) {
        self.len = 0;
        self.overflow = false;
    }

    /// Feeds one octet. At a delimiter that ends a non-empty frame,
    /// returns the frame's body or why it was rejected; otherwise `None`.
    pub fn push(&mut self, byte: u8) -> Option<Result<&[u8], FrameError>> {
        if byte != DELIMITER {
            match self.raw.get_mut(self.len) {
                Some(slot) if !self.overflow => {
                    *slot = byte;
                    self.len += 1;
                }
                _ => self.overflow = true,
            }
            return None;
        }
        let len = core::mem::take(&mut self.len);
        if core::mem::take(&mut self.overflow) {
            return Some(Err(FrameError::TooLarge));
        }
        if len == 0 {
            return None;
        }
        let n = match cobs_decode(&self.raw[..len], &mut self.body) {
            Ok(n) => n,
            Err(e) => return Some(Err(e)),
        };
        if n < 2 {
            return Some(Err(FrameError::Corrupt));
        }
        let (body, crc) = self.body[..n].split_at(n - 2);
        if crc16(body).to_le_bytes() != [crc[0], crc[1]] {
            return Some(Err(FrameError::Crc));
        }
        if body.len() > MAX_BODY {
            return Some(Err(FrameError::TooLarge));
        }
        Some(Ok(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(dec: &mut FrameDecoder, wire: &[u8]) -> Vec<Result<Vec<u8>, FrameError>> {
        let mut out = Vec::new();
        for &b in wire {
            if let Some(r) = dec.push(b) {
                out.push(r.map(<[u8]>::to_vec));
            }
        }
        out
    }

    #[test]
    fn frames_round_trip_including_zero_runs_and_long_blocks() {
        let bodies: [Vec<u8>; 6] = [
            vec![1],
            vec![0],
            vec![0, 0, 0],
            (0..=255u8).collect(),
            vec![0xaa; 300],
            vec![7; MAX_BODY],
        ];
        let mut dec = FrameDecoder::new();
        for body in bodies {
            let mut wire = [0u8; MAX_WIRE];
            let n = encode(&body, &mut wire).unwrap();
            assert!(n <= MAX_WIRE);
            assert_eq!(wire[0], 0);
            assert_eq!(wire[n - 1], 0);
            assert!(!wire[1..n - 1].contains(&0), "COBS leaves no zero inside");
            assert_eq!(decode_all(&mut dec, &wire[..n]), vec![Ok(body)]);
        }
    }

    #[test]
    fn oversized_bodies_are_refused_and_oversized_frames_dropped() {
        let mut wire = [0u8; MAX_WIRE + 8];
        assert_eq!(
            encode(&[1; MAX_BODY + 1], &mut wire),
            Err(FrameError::TooLarge)
        );
        assert_eq!(
            encode(&[1; 4], &mut [0u8; 4]),
            Err(FrameError::BufferTooSmall)
        );
        let mut dec = FrameDecoder::new();
        let mut stream = vec![0u8];
        stream.extend(core::iter::repeat_n(5u8, MAX_WIRE + 10));
        stream.push(0);
        let mut ok = [0u8; MAX_WIRE];
        let n = encode(&[9, 9], &mut ok).unwrap();
        stream.extend_from_slice(&ok[..n]);
        assert_eq!(
            decode_all(&mut dec, &stream),
            vec![Err(FrameError::TooLarge), Ok(vec![9, 9])]
        );
    }

    #[test]
    fn corruption_is_detected_and_the_stream_resynchronizes() {
        let mut wire = [0u8; MAX_WIRE];
        let n = encode(&[1, 2, 3, 4], &mut wire).unwrap();
        let mut bad = wire[..n].to_vec();
        bad[3] ^= 0x40;
        let mut stream = b"garbage text\r\n".to_vec();
        stream.extend_from_slice(&bad);
        stream.extend_from_slice(&wire[..n]);
        let mut dec = FrameDecoder::new();
        let got = decode_all(&mut dec, &stream);
        assert_eq!(got.len(), 3);
        assert!(
            got[0].is_err(),
            "text before the first delimiter is rejected"
        );
        assert_eq!(got[1], Err(FrameError::Crc));
        assert_eq!(got[2], Ok(vec![1, 2, 3, 4]));
        // A zero code octet inside a frame is a COBS violation.
        assert_eq!(
            cobs_decode(&[2, 1, 0], &mut [0; 8]),
            Err(FrameError::Corrupt)
        );
        assert_eq!(cobs_decode(&[5, 1], &mut [0; 8]), Err(FrameError::Corrupt));
    }

    #[test]
    fn crc_matches_the_reference_check_value() {
        assert_eq!(crc16(b"123456789"), 0x29b1);
    }
}
