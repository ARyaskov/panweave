//! Type-Length-Value framing (R23.2 Annex I).
//!
//! Wire layout: one tag octet, one length octet whose value is the actual
//! value length minus one, then the value. Tags `0..=63` are local to a
//! message; `64..=255` are global. The rules implemented here:
//!
//! * duplicate tags (other than Manufacturer Specific, tag 64) reject the
//!   whole message (I.2.1);
//! * unknown tags are skipped (I.2.3);
//! * a TLV header or value cut short by the end of the message is
//!   malformed and rejects the whole message (I.2.5);
//! * encapsulation TLVs may not nest (I.2.6).
//!
//! Minimum-length checks for *known* TLVs belong to the typed decoders of
//! the layer that defines them; they report [`TlvError::Malformed`].

use crate::error::TlvError;
use crate::{CodecError, Writer};

/// Tag of the Manufacturer Specific global TLV, the only tag that may be
/// repeated in one message (R23.2 Annex I.4.1).
pub const MANUFACTURER_SPECIFIC_TAG: u8 = 64;

/// First global tag id (R23.2 Annex I, Table I-2).
pub const FIRST_GLOBAL_TAG: u8 = 64;

/// True for global tags.
#[inline]
pub const fn is_global_tag(tag: u8) -> bool {
    tag >= FIRST_GLOBAL_TAG
}

/// A borrowed TLV.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tlv<'a> {
    /// Tag identifier.
    pub tag: u8,
    /// Value bytes (at least one byte on a well-formed wire).
    pub value: &'a [u8],
}

impl Tlv<'_> {
    /// Encoded length including the two-octet header.
    #[inline]
    pub const fn encoded_len(&self) -> usize {
        2 + self.value.len()
    }
}

/// Iterator over the TLVs in a byte slice.
///
/// Yields `Err(TlvError::Truncated)` once and then `None` if the input is
/// cut short; callers that need the strict Annex I behaviour should use
/// [`TlvSet::validate`] first.
#[derive(Clone, Debug)]
pub struct TlvIter<'a> {
    rest: &'a [u8],
    failed: bool,
}

impl<'a> TlvIter<'a> {
    /// Creates an iterator over `bytes`.
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        TlvIter {
            rest: bytes,
            failed: false,
        }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<Tlv<'a>, TlvError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        let (Some(&tag), Some(&len_minus_one)) = (self.rest.first(), self.rest.get(1)) else {
            self.failed = true;
            return Some(Err(TlvError::Truncated));
        };
        let len = usize::from(len_minus_one) + 1;
        let end = 2 + len;
        if let Some(value) = self.rest.get(2..end) {
            self.rest = self.rest.get(end..).unwrap_or(&[]);
            Some(Ok(Tlv { tag, value }))
        } else {
            self.failed = true;
            Some(Err(TlvError::Truncated))
        }
    }
}

/// A validated set of TLVs borrowed from a message.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TlvSet<'a> {
    bytes: &'a [u8],
}

impl<'a> TlvSet<'a> {
    /// An empty set.
    pub const EMPTY: TlvSet<'static> = TlvSet { bytes: &[] };

    /// Validates `bytes` according to the general TLV processing rules
    /// (Annex I.2.7) and returns a set on success.
    ///
    /// `is_encapsulation` identifies encapsulation tags so that nesting can
    /// be rejected. Global encapsulation tags are always checked; pass a
    /// closure for message-local ones or `|_| false`.
    pub fn validate(
        bytes: &'a [u8],
        is_encapsulation: impl Fn(u8) -> bool,
    ) -> Result<Self, TlvError> {
        let mut seen = [0u64; 4];
        for item in TlvIter::new(bytes) {
            let tlv = item?;
            if tlv.tag != MANUFACTURER_SPECIFIC_TAG {
                let idx = usize::from(tlv.tag / 64);
                let bit = 1u64 << (tlv.tag % 64);
                let slot = seen
                    .get_mut(idx)
                    .ok_or(TlvError::Malformed { tag: tlv.tag })?;
                if *slot & bit != 0 {
                    return Err(TlvError::DuplicateTag { tag: tlv.tag });
                }
                *slot |= bit;
            }
            if is_global_encapsulation(tlv.tag) || is_encapsulation(tlv.tag) {
                // Inner TLVs must themselves be well formed and must not
                // contain encapsulation TLVs.
                for inner in TlvIter::new(tlv.value) {
                    let inner = inner.map_err(|_| TlvError::Malformed { tag: tlv.tag })?;
                    if is_global_encapsulation(inner.tag) || is_encapsulation(inner.tag) {
                        return Err(TlvError::NestedEncapsulation { tag: tlv.tag });
                    }
                }
            }
        }
        Ok(TlvSet { bytes })
    }

    /// Wraps bytes without validation. Only for data produced locally.
    #[inline]
    pub const fn from_trusted(bytes: &'a [u8]) -> Self {
        TlvSet { bytes }
    }

    /// The raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// True when the set is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Iterates the TLVs. On a validated set every item is `Ok`.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = Tlv<'a>> + 'a {
        TlvIter::new(self.bytes).filter_map(Result::ok)
    }

    /// Finds the first TLV with `tag`.
    pub fn find(&self, tag: u8) -> Option<Tlv<'a>> {
        self.iter().find(|t| t.tag == tag)
    }

    /// Finds the value of the first TLV with `tag`.
    #[inline]
    pub fn value(&self, tag: u8) -> Option<&'a [u8]> {
        self.find(tag).map(|t| t.value)
    }

    /// Finds a TLV that must be present.
    pub fn require(&self, tag: u8) -> Result<Tlv<'a>, TlvError> {
        self.find(tag).ok_or(TlvError::Missing { tag })
    }

    /// Iterates every Manufacturer Specific TLV.
    pub fn manufacturer_specific(&self) -> impl Iterator<Item = Tlv<'a>> + 'a {
        self.iter().filter(|t| t.tag == MANUFACTURER_SPECIFIC_TAG)
    }
}

/// Global encapsulation TLV tags (R23.2 Annex I.4.9, I.4.10).
#[inline]
pub const fn is_global_encapsulation(tag: u8) -> bool {
    matches!(tag, 72 | 73)
}

/// Writes one TLV. The value must be 1..=256 bytes.
pub fn write_tlv(w: &mut Writer<'_>, tag: u8, value: &[u8]) -> Result<(), CodecError> {
    if value.is_empty() || value.len() > 256 {
        return Err(CodecError::Unrepresentable { field: "tlv value" });
    }
    // `value.len() - 1` is at most 255, so the narrowing is lossless.
    #[allow(clippy::cast_possible_truncation)]
    let len_minus_one = (value.len() - 1) as u8;
    w.u8(tag)?;
    w.u8(len_minus_one)?;
    w.bytes(value)
}

/// Starts a TLV whose value is produced by `body`; the length octet is
/// back-patched. The body must write 1..=256 bytes.
pub fn write_tlv_with(
    w: &mut Writer<'_>,
    tag: u8,
    body: impl FnOnce(&mut Writer<'_>) -> Result<(), CodecError>,
) -> Result<(), CodecError> {
    let start = w.position();
    w.u8(tag)?;
    w.u8(0)?;
    body(w)?;
    let len = w.position().saturating_sub(start + 2);
    if len == 0 || len > 256 {
        return Err(CodecError::Unrepresentable { field: "tlv value" });
    }
    #[allow(clippy::cast_possible_truncation)]
    let len_minus_one = (len - 1) as u8;
    if let Some(b) = w.patch(start + 1, 1)?.first_mut() {
        *b = len_minus_one;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterates_well_formed_tlvs() {
        // tag 1 len-1=0 value [0xAA]; tag 65 len-1=1 value [1,2]
        let bytes = [1, 0, 0xAA, 65, 1, 1, 2];
        let set = TlvSet::validate(&bytes, |_| false).unwrap();
        let items: [Tlv<'_>; 2] = [set.iter().next().unwrap(), set.iter().nth(1).unwrap()];
        assert_eq!(
            items[0],
            Tlv {
                tag: 1,
                value: &[0xAA]
            }
        );
        assert_eq!(
            items[1],
            Tlv {
                tag: 65,
                value: &[1, 2]
            }
        );
        assert_eq!(set.value(65), Some(&[1u8, 2][..]));
        assert!(set.find(2).is_none());
        assert!(matches!(set.require(2), Err(TlvError::Missing { tag: 2 })));
    }

    #[test]
    fn truncated_header_or_value_is_rejected() {
        assert!(matches!(
            TlvSet::validate(&[1], |_| false),
            Err(TlvError::Truncated)
        ));
        assert!(matches!(
            TlvSet::validate(&[1, 2, 0xAA], |_| false),
            Err(TlvError::Truncated)
        ));
        // Length 0 on the wire means one value byte; the iterator must not
        // treat it as zero-length.
        assert!(matches!(
            TlvSet::validate(&[1, 0], |_| false),
            Err(TlvError::Truncated)
        ));
    }

    #[test]
    fn duplicate_tags_rejected_except_manufacturer_specific() {
        assert!(matches!(
            TlvSet::validate(&[5, 0, 1, 5, 0, 2], |_| false),
            Err(TlvError::DuplicateTag { tag: 5 })
        ));
        let ms = [64, 0, 1, 64, 0, 2];
        let set = TlvSet::validate(&ms, |_| false).unwrap();
        assert_eq!(set.manufacturer_specific().count(), 2);
    }

    #[test]
    fn nested_encapsulation_rejected() {
        // Tag 72 (Joiner Encapsulation) containing tag 73.
        let inner = [73, 0, 0xFF];
        let outer = [72, 2, 73, 0, 0xFF];
        assert_eq!(inner.len(), 3);
        assert!(matches!(
            TlvSet::validate(&outer, |_| false),
            Err(TlvError::NestedEncapsulation { tag: 72 })
        ));
        // Encapsulation with a well-formed non-encapsulation inner TLV.
        let ok = [72, 2, 1, 0, 0xFF];
        assert!(TlvSet::validate(&ok, |_| false).is_ok());
        // Encapsulation with a truncated inner TLV is malformed.
        let bad_inner = [72, 1, 1, 5];
        assert!(matches!(
            TlvSet::validate(&bad_inner, |_| false),
            Err(TlvError::Malformed { tag: 72 })
        ));
        // Message-local encapsulation tags are honoured too.
        let local = [3, 2, 4, 0, 0xEE];
        assert!(matches!(
            TlvSet::validate(&local, |t| t == 3 || t == 4),
            Err(TlvError::NestedEncapsulation { tag: 3 })
        ));
    }

    #[test]
    fn write_helpers_round_trip() {
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        write_tlv(&mut w, 7, &[1, 2, 3]).unwrap();
        write_tlv_with(&mut w, 8, |w| w.u16_le(0xBEEF)).unwrap();
        assert!(write_tlv(&mut w, 9, &[]).is_err());
        let n = w.position();
        let set = TlvSet::validate(&buf[..n], |_| false).unwrap();
        assert_eq!(set.value(7), Some(&[1u8, 2, 3][..]));
        assert_eq!(set.value(8), Some(&[0xEFu8, 0xBE][..]));
    }

    #[test]
    fn empty_set() {
        let set = TlvSet::validate(&[], |_| false).unwrap();
        assert!(set.is_empty());
        assert_eq!(set.iter().count(), 0);
    }
}
