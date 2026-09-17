//! Read / Write Attributes Structured (ZCL8 §2.5.15 – §2.5.17): the
//! selector field, element lookup inside the raw encoding of arrays,
//! structures, sets and bags, element replacement, and set / bag
//! element addition and removal. Element indices count from 1; index 0
//! of an array or structure is its element count (uint16). Selector
//! depth is limited to [`MAX_DEPTH`] ("may be further limited by an
//! application", §2.5.15.1.3).

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};

use crate::attribute::MAX_ATTRIBUTE_BYTES;
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Nesting depth a selector may address.
pub const MAX_DEPTH: usize = 4;

/// Set / bag operations in the upper nibble of the indicator
/// (§2.5.16.1.5).
pub mod op {
    /// Write the whole value (or the addressed element).
    pub const WRITE: u8 = 0;
    /// Add an element to the set / bag.
    pub const ADD: u8 = 1;
    /// Remove an element from the set / bag.
    pub const REMOVE: u8 = 2;
}

/// A selector (Figure 2-30 / 2-33).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Selector {
    /// Set / bag operation (upper nibble of the indicator).
    pub op: u8,
    /// Element indices, outermost first.
    pub indices: Vec<u16, MAX_DEPTH>,
}

impl Selector {
    /// Whole-attribute selector.
    pub const WHOLE: Selector = Selector {
        op: op::WRITE,
        indices: Vec::new(),
    };

    /// Selects one element by its indices.
    pub fn element(indices: &[u16]) -> Option<Selector> {
        Vec::from_slice(indices).ok().map(|indices| Selector {
            op: op::WRITE,
            indices,
        })
    }

    /// Decodes a selector; a depth beyond [`MAX_DEPTH`] or a reserved
    /// operation is `InvalidSelector`, a short payload `Truncated`.
    pub fn decode(r: &mut Reader<'_>) -> Result<Result<Selector, ZclStatus>, CodecError> {
        let indicator = r.u8()?;
        let depth = usize::from(indicator & 0x0f);
        let op = indicator >> 4;
        let mut indices = Vec::new();
        let mut ok = op <= op::REMOVE;
        for _ in 0..depth {
            let i = r.u16_le()?;
            if indices.push(i).is_err() {
                ok = false;
            }
        }
        Ok(if ok {
            Ok(Selector { op, indices })
        } else {
            Err(ZclStatus::InvalidSelector)
        })
    }

    /// Encodes the selector.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let depth = u8::try_from(self.indices.len()).unwrap_or(0x0f);
        w.u8((self.op << 4) | depth)?;
        for i in &self.indices {
            w.u16_le(*i)?;
        }
        Ok(())
    }

    /// Whether the whole attribute is addressed.
    pub fn is_whole(&self) -> bool {
        self.indices.is_empty()
    }
}

/// An addressed element.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Element<'a> {
    /// Index 0: the number of elements.
    Count(u16),
    /// An element's type and raw value.
    Value {
        /// Data type.
        ty: DataType,
        /// Raw encoding (without a type prefix).
        bytes: &'a [u8],
    },
}

/// One level of a composite: where its elements live.
struct Layout<'a> {
    /// The composite's type.
    ty: DataType,
    /// Element type of arrays, sets and bags.
    elem: DataType,
    /// Element count (0xffff: invalid / unknown).
    count: u16,
    /// Bytes after the prefix.
    body: &'a [u8],
    /// Prefix length (3 for arrays, sets and bags; 2 for structures).
    prefix: usize,
}

fn layout(ty: DataType, bytes: &[u8]) -> Option<Layout<'_>> {
    match ty {
        DataType::Array | DataType::Set | DataType::Bag => Some(Layout {
            ty,
            elem: DataType::from_id(*bytes.first()?),
            count: u16::from_le_bytes([*bytes.get(1)?, *bytes.get(2)?]),
            body: bytes.get(3..)?,
            prefix: 3,
        }),
        DataType::Struct => Some(Layout {
            ty,
            elem: DataType::Unknown,
            count: u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]),
            body: bytes.get(2..)?,
            prefix: 2,
        }),
        _ => None,
    }
}

/// The byte range and type of element `index` (1-based) within a
/// composite level.
fn locate(l: &Layout<'_>, index: u16) -> Option<(usize, usize, DataType)> {
    if index == 0 || l.count == 0xffff || index > l.count {
        return None;
    }
    let mut pos = 0;
    for i in 1..=index {
        let (ty, head) = if l.ty == DataType::Struct {
            (DataType::from_id(*l.body.get(pos)?), 1)
        } else {
            (l.elem, 0)
        };
        let n = ty.value_len(l.body.get(pos + head..)?)?;
        if i == index {
            return Some((l.prefix + pos + head, n, ty));
        }
        pos += head + n;
    }
    None
}

/// Resolves `indices` inside the raw encoding `bytes` of a `ty`
/// composite (§2.5.15.1.3).
pub fn select<'a>(
    ty: DataType,
    bytes: &'a [u8],
    indices: &[u16],
) -> Result<Element<'a>, ZclStatus> {
    let Some((first, rest)) = indices.split_first() else {
        return Err(ZclStatus::InvalidSelector);
    };
    let l = layout(ty, bytes).ok_or(ZclStatus::InvalidSelector)?;
    if *first == 0 {
        return if rest.is_empty() && matches!(ty, DataType::Array | DataType::Struct) {
            Ok(Element::Count(l.count))
        } else {
            Err(ZclStatus::InvalidSelector)
        };
    }
    let (start, len, elem_ty) = locate(&l, *first).ok_or(ZclStatus::InvalidSelector)?;
    let elem = bytes
        .get(start..start + len)
        .ok_or(ZclStatus::InvalidSelector)?;
    if rest.is_empty() {
        Ok(Element::Value {
            ty: elem_ty,
            bytes: elem,
        })
    } else {
        select(elem_ty, elem, rest)
    }
}

/// A rebuilt composite encoding.
pub type Rebuilt = Vec<u8, MAX_ATTRIBUTE_BYTES>;

fn splice(bytes: &[u8], start: usize, len: usize, with: &[u8]) -> Result<Rebuilt, ZclStatus> {
    let mut out = Rebuilt::new();
    let head = bytes.get(..start).ok_or(ZclStatus::InvalidSelector)?;
    let tail = bytes.get(start + len..).ok_or(ZclStatus::InvalidSelector)?;
    out.extend_from_slice(head)
        .and_then(|()| out.extend_from_slice(with))
        .and_then(|()| out.extend_from_slice(tail))
        .map_err(|_| ZclStatus::InsufficientSpace)?;
    Ok(out)
}

/// Replaces the element at `indices` of the `ty` composite `bytes`
/// with `value` (§2.5.16.1.4): the element's type must match
/// (`InvalidDataType`); index 0 of an array sets its length (uint16,
/// truncating or padding with `fill` from the application, `None`
/// meaning the length is read-only); structures' index 0 is read-only.
pub fn replace(
    ty: DataType,
    bytes: &[u8],
    indices: &[u16],
    value: &Value<'_>,
    fill: Option<&Value<'_>>,
) -> Result<Rebuilt, ZclStatus> {
    let Some((first, rest)) = indices.split_first() else {
        return Err(ZclStatus::InvalidSelector);
    };
    let l = layout(ty, bytes).ok_or(ZclStatus::InvalidSelector)?;
    if *first == 0 {
        if !rest.is_empty() || ty != DataType::Array {
            return Err(ZclStatus::InvalidSelector);
        }
        let Value::Uint { width: 2, value: n } = value else {
            return Err(ZclStatus::InvalidDataType);
        };
        let fill = fill.ok_or(ZclStatus::ReadOnly)?;
        let n = u16::try_from(*n).map_err(|_| ZclStatus::InvalidValue)?;
        if n == 0xffff {
            return Err(ZclStatus::InvalidValue);
        }
        if fill.data_type() != l.elem {
            return Err(ZclStatus::InvalidDataType);
        }
        let mut out = Rebuilt::new();
        let mut w_prefix = [0u8; 3];
        w_prefix[0] = l.elem.id();
        w_prefix[1..].copy_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&w_prefix)
            .map_err(|_| ZclStatus::InsufficientSpace)?;
        let keep = n.min(if l.count == 0xffff { 0 } else { l.count });
        let mut pos = 0;
        for _ in 0..keep {
            let len = l
                .elem
                .value_len(l.body.get(pos..).ok_or(ZclStatus::InvalidValue)?)
                .ok_or(ZclStatus::InvalidValue)?;
            out.extend_from_slice(l.body.get(pos..pos + len).ok_or(ZclStatus::InvalidValue)?)
                .map_err(|_| ZclStatus::InsufficientSpace)?;
            pos += len;
        }
        let mut buf = [0u8; MAX_ATTRIBUTE_BYTES];
        let mut w = Writer::new(&mut buf);
        fill.encode(&mut w)
            .map_err(|_| ZclStatus::InsufficientSpace)?;
        let fill_len = w.position();
        for _ in keep..n {
            out.extend_from_slice(buf.get(..fill_len).unwrap_or(&[]))
                .map_err(|_| ZclStatus::InsufficientSpace)?;
        }
        return Ok(out);
    }
    let (start, len, elem_ty) = locate(&l, *first).ok_or(ZclStatus::InvalidSelector)?;
    let elem = bytes
        .get(start..start + len)
        .ok_or(ZclStatus::InvalidSelector)?;
    if rest.is_empty() {
        if value.data_type() != elem_ty {
            return Err(ZclStatus::InvalidDataType);
        }
        let mut buf = [0u8; MAX_ATTRIBUTE_BYTES];
        let mut w = Writer::new(&mut buf);
        value
            .encode(&mut w)
            .map_err(|_| ZclStatus::InsufficientSpace)?;
        let n = w.position();
        splice(bytes, start, len, buf.get(..n).unwrap_or(&[]))
    } else {
        let inner = replace(elem_ty, elem, rest, value, fill)?;
        splice(bytes, start, len, &inner)
    }
}

/// Adds (`add`) or removes an element of a set or bag at `indices`
/// (empty: the attribute itself) (§2.5.16.1.5): a duplicate in a set is
/// `DuplicateExists`, a missing element to remove `NotFound`.
pub fn add_remove(
    ty: DataType,
    bytes: &[u8],
    indices: &[u16],
    value: &Value<'_>,
    add: bool,
) -> Result<Rebuilt, ZclStatus> {
    if let Some((first, rest)) = indices.split_first() {
        let l = layout(ty, bytes).ok_or(ZclStatus::InvalidSelector)?;
        let (start, len, elem_ty) = locate(&l, *first).ok_or(ZclStatus::InvalidSelector)?;
        let elem = bytes
            .get(start..start + len)
            .ok_or(ZclStatus::InvalidSelector)?;
        let inner = add_remove(elem_ty, elem, rest, value, add)?;
        return splice(bytes, start, len, &inner);
    }
    if !matches!(ty, DataType::Set | DataType::Bag) {
        return Err(ZclStatus::InvalidSelector);
    }
    let l = layout(ty, bytes).ok_or(ZclStatus::InvalidSelector)?;
    if value.data_type() != l.elem {
        return Err(ZclStatus::InvalidDataType);
    }
    let mut buf = [0u8; MAX_ATTRIBUTE_BYTES];
    let mut w = Writer::new(&mut buf);
    value
        .encode(&mut w)
        .map_err(|_| ZclStatus::InsufficientSpace)?;
    let needle_len = w.position();
    let needle = buf.get(..needle_len).unwrap_or(&[]);
    let count = if l.count == 0xffff { 0 } else { l.count };
    // Find an equal element.
    let mut found: Option<(usize, usize)> = None;
    let mut pos = 0;
    for _ in 0..count {
        let n = l
            .elem
            .value_len(l.body.get(pos..).ok_or(ZclStatus::InvalidValue)?)
            .ok_or(ZclStatus::InvalidValue)?;
        if l.body.get(pos..pos + n) == Some(needle) {
            found = Some((l.prefix + pos, n));
            break;
        }
        pos += n;
    }
    if add {
        if ty == DataType::Set && found.is_some() {
            return Err(ZclStatus::DuplicateExists);
        }
        let mut out = splice(bytes, bytes.len(), 0, needle)?;
        let new_count = count.checked_add(1).ok_or(ZclStatus::InsufficientSpace)?;
        if let Some(c) = out.get_mut(1..3) {
            c.copy_from_slice(&new_count.to_le_bytes());
        }
        Ok(out)
    } else {
        let (start, len) = found.ok_or(ZclStatus::NotFound)?;
        let mut out = splice(bytes, start, len, &[])?;
        if let Some(c) = out.get_mut(1..3) {
            c.copy_from_slice(&(count - 1).to_le_bytes());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Array of 3 uint8: [10, 20, 30].
    const ARR: [u8; 6] = [0x20, 3, 0, 10, 20, 30];

    fn u8v(v: u8) -> Value<'static> {
        Value::Uint {
            width: 1,
            value: u64::from(v),
        }
    }

    #[test]
    fn selectors_round_trip_and_reject_depth() {
        let s = Selector::element(&[5, 3]).unwrap();
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        s.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(&buf[..n], &[2, 5, 0, 3, 0]);
        let mut r = Reader::new(&buf[..5]);
        assert_eq!(Selector::decode(&mut r).unwrap().unwrap(), s);
        let deep = [5u8, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
        let mut r = Reader::new(&deep);
        assert_eq!(
            Selector::decode(&mut r).unwrap(),
            Err(ZclStatus::InvalidSelector)
        );
        assert!(Selector::decode(&mut Reader::new(&[1])).is_err());
    }

    #[test]
    fn select_elements_and_counts() {
        assert_eq!(select(DataType::Array, &ARR, &[0]), Ok(Element::Count(3)));
        assert_eq!(
            select(DataType::Array, &ARR, &[2]),
            Ok(Element::Value {
                ty: DataType::Uint(1),
                bytes: &[20]
            })
        );
        assert_eq!(
            select(DataType::Array, &ARR, &[4]),
            Err(ZclStatus::InvalidSelector)
        );
        assert_eq!(
            select(DataType::Uint(1), &[1], &[1]),
            Err(ZclStatus::InvalidSelector)
        );
        let st: [u8; 12] = [2, 0, 0x20, 7, 0x48, 0x21, 2, 0, 1, 0, 2, 0];
        assert_eq!(
            select(DataType::Struct, &st, &[1]),
            Ok(Element::Value {
                ty: DataType::Uint(1),
                bytes: &[7]
            })
        );
        assert_eq!(
            select(DataType::Struct, &st, &[2, 2]),
            Ok(Element::Value {
                ty: DataType::Uint(2),
                bytes: &[2, 0]
            })
        );
        assert_eq!(
            select(DataType::Struct, &st, &[2, 0]),
            Ok(Element::Count(2))
        );
        assert_eq!(
            select(DataType::Struct, &st, &[2, 0, 1]),
            Err(ZclStatus::InvalidSelector)
        );
    }

    #[test]
    fn replace_elements_and_resize_arrays() {
        let out = replace(DataType::Array, &ARR, &[3], &u8v(99), None).unwrap();
        assert_eq!(out.as_slice(), &[0x20, 3, 0, 10, 20, 99]);
        assert_eq!(
            replace(
                DataType::Array,
                &ARR,
                &[1],
                &Value::Uint { width: 2, value: 1 },
                None
            ),
            Err(ZclStatus::InvalidDataType)
        );
        // Length: read-only without a fill, else truncate / pad.
        let len = Value::Uint { width: 2, value: 5 };
        assert_eq!(
            replace(DataType::Array, &ARR, &[0], &len, None),
            Err(ZclStatus::ReadOnly)
        );
        let out = replace(DataType::Array, &ARR, &[0], &len, Some(&u8v(0))).unwrap();
        assert_eq!(out.as_slice(), &[0x20, 5, 0, 10, 20, 30, 0, 0]);
        let short = Value::Uint { width: 2, value: 1 };
        let out = replace(DataType::Array, &ARR, &[0], &short, Some(&u8v(0))).unwrap();
        assert_eq!(out.as_slice(), &[0x20, 1, 0, 10]);
        // Nested: the second element of the array inside the struct.
        let st: [u8; 12] = [2, 0, 0x20, 7, 0x48, 0x21, 2, 0, 1, 0, 2, 0];
        let out = replace(
            DataType::Struct,
            &st,
            &[2, 2],
            &Value::Uint {
                width: 2,
                value: 0x1234,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            out.as_slice(),
            &[2, 0, 0x20, 7, 0x48, 0x21, 2, 0, 1, 0, 0x34, 0x12]
        );
        assert_eq!(
            replace(DataType::Struct, &st, &[0], &len, None),
            Err(ZclStatus::InvalidSelector)
        );
    }

    #[test]
    fn sets_and_bags_add_and_remove() {
        let set: [u8; 5] = [0x20, 2, 0, 1, 2];
        let out = add_remove(DataType::Set, &set, &[], &u8v(3), true).unwrap();
        assert_eq!(out.as_slice(), &[0x20, 3, 0, 1, 2, 3]);
        assert_eq!(
            add_remove(DataType::Set, &set, &[], &u8v(2), true),
            Err(ZclStatus::DuplicateExists)
        );
        let bag: [u8; 5] = [0x20, 2, 0, 1, 2];
        let out = add_remove(DataType::Bag, &bag, &[], &u8v(2), true).unwrap();
        assert_eq!(
            out.as_slice(),
            &[0x20, 3, 0, 1, 2, 2],
            "bags keep duplicates"
        );
        let out = add_remove(DataType::Set, &set, &[], &u8v(1), false).unwrap();
        assert_eq!(out.as_slice(), &[0x20, 1, 0, 2]);
        assert_eq!(
            add_remove(DataType::Set, &set, &[], &u8v(9), false),
            Err(ZclStatus::NotFound)
        );
        assert_eq!(
            add_remove(DataType::Array, &ARR, &[], &u8v(9), true),
            Err(ZclStatus::InvalidSelector)
        );
        assert_eq!(
            add_remove(
                DataType::Set,
                &set,
                &[],
                &Value::Uint { width: 2, value: 1 },
                true
            ),
            Err(ZclStatus::InvalidDataType)
        );
    }
}
