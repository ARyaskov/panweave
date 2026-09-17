//! Short device setup codes (BDB 3.1 §6.12): the modified base32
//! alphabet of §6.12.1 (no `0`/`O`, `1`/`I`/`l`), the mapping of a code
//! to the variable-length pass code stored in `apsDeviceKeyPairSet` and
//! used by SPEKE (§6.12.2: 5-bit groups concatenated little-endian and
//! zero-padded to 128 bits), and the reverse encoding for display.

use panweave_types::Key128;

/// The §6.12.1 alphabet, indexed by the 5-bit value.
pub const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Longest code: 25 characters fill the 125 bits that fit a 128-bit
/// pass code; 26 would spill.
pub const MAX_CHARS: usize = 25;

/// Value of a character, ignoring case; `None` for a character outside
/// the alphabet.
pub const fn value_of(c: u8) -> Option<u8> {
    let c = c.to_ascii_uppercase();
    let mut i: u8 = 0;
    while (i as usize) < ALPHABET.len() {
        if ALPHABET[i as usize] == c {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Why a code could not be decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SetupCodeError {
    /// A character outside the §6.12.1 alphabet at this index.
    InvalidCharacter(usize),
    /// Empty, or longer than [`MAX_CHARS`].
    Length,
}

/// A decoded pass code: `bits` significant bits in the little-endian
/// `bytes`, the rest zero (the padding procedure of §6.12.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PassCode {
    /// The 128-bit padded value, little-endian.
    pub bytes: [u8; 16],
    /// Bits of entropy carried by the code (5 per character).
    pub bits: u8,
}

impl PassCode {
    /// The value as a `Key128` for the device key-pair set entry.
    pub const fn link_key(&self) -> Key128 {
        Key128::from_bytes(self.bytes)
    }

    /// The pass code as SPEKE consumes it: the significant bytes only.
    pub fn as_psk(&self) -> &[u8] {
        let n = usize::from(self.bits).div_ceil(8);
        self.bytes.get(..n).unwrap_or(&[])
    }
}

/// Decodes a displayed code (separators `-` and spaces are ignored).
pub fn decode(code: &str) -> Result<PassCode, SetupCodeError> {
    let mut bytes = [0u8; 16];
    let mut bit = 0usize;
    let mut chars = 0usize;
    for (i, c) in code.bytes().enumerate() {
        if c == b'-' || c == b' ' {
            continue;
        }
        let v = value_of(c).ok_or(SetupCodeError::InvalidCharacter(i))?;
        chars += 1;
        if chars > MAX_CHARS {
            return Err(SetupCodeError::Length);
        }
        for k in 0..5 {
            if v & (1 << k) != 0 {
                let pos = bit + k;
                bytes[pos / 8] |= 1 << (pos % 8);
            }
        }
        bit += 5;
    }
    if chars == 0 {
        return Err(SetupCodeError::Length);
    }
    Ok(PassCode {
        bytes,
        bits: u8::try_from(bit).unwrap_or(u8::MAX),
    })
}

/// Encodes `bits` bits of a little-endian pass code as characters,
/// writing to `out`; returns the characters written. `bits` is rounded
/// up to a multiple of 5.
pub fn encode(bytes: &[u8; 16], bits: u8, out: &mut [u8]) -> usize {
    let chars = usize::from(bits).div_ceil(5).min(MAX_CHARS);
    let mut n = 0;
    for c in 0..chars {
        let mut v = 0u8;
        for k in 0..5 {
            let pos = c * 5 + k;
            if bytes[pos / 8] & (1 << (pos % 8)) != 0 {
                v |= 1 << k;
            }
        }
        let Some(slot) = out.get_mut(n) else {
            break;
        };
        *slot = ALPHABET[usize::from(v)];
        n += 1;
    }
    n
}

/// Recommended entropy for a short setup code (§6.12): 20–30 bits.
pub const fn recommended_bits(bits: u8) -> bool {
    bits >= 20 && bits <= 30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_of_6_12_2() {
        let p = decode("U4DXS2").unwrap();
        assert_eq!(p.bits, 30);
        assert_eq!(&p.bytes[..4], &[0x52, 0x8F, 0x0A, 0x31]);
        assert!(p.bytes[4..].iter().all(|b| *b == 0));
        assert_eq!(p.link_key().as_bytes()[..4], [0x52, 0x8F, 0x0A, 0x31]);
        assert_eq!(p.as_psk(), &[0x52, 0x8F, 0x0A, 0x31]);
        assert!(recommended_bits(p.bits));
        let mut out = [0u8; 8];
        let n = encode(&p.bytes, p.bits, &mut out);
        assert_eq!(&out[..n], b"U4DXS2");
        // Separators and lower case are tolerated; ambiguous characters
        // are not in the alphabet.
        assert_eq!(decode("u4d-xs2").unwrap(), p);
        assert_eq!(decode("U4DXS0"), Err(SetupCodeError::InvalidCharacter(5)));
        assert_eq!(decode("U4DXSO"), Err(SetupCodeError::InvalidCharacter(5)));
        assert_eq!(decode("U4DXSI"), Err(SetupCodeError::InvalidCharacter(5)));
        assert_eq!(decode(""), Err(SetupCodeError::Length));
        assert_eq!(
            decode("ABCDEFGHJKLMNPQRSTUVWXYZ23"),
            Err(SetupCodeError::Length)
        );
        let full = decode("ABCDEFGHJKLMNPQRSTUVWXYZ2").unwrap();
        assert_eq!(full.bits, 125);
        assert_eq!(value_of(b'9'), Some(31));
        assert_eq!(value_of(b'a'), Some(0));
    }
}
