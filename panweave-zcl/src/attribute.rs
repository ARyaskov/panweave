//! Attribute definitions and storage (ZCL8 §2.3.4) with the reporting
//! state of §2.5.7 / §2.5.11.
//!
//! Values are stored in their wire encoding so that any data type can be
//! held without a large enum; typed accessors decode on demand. A value
//! of up to eight octets (every integer, enumeration, bitmap, float,
//! time and identifier type) lives inline in its attribute entry with
//! its factory default; strings, composites and keys draw the largest
//! attribute value from a byte pool the cluster's attributes share. A
//! cluster of a few dozen small attributes therefore costs about as
//! much as two full buffers, not one per attribute. Each entry carries
//! its reporting configuration and state.

use heapless::Vec;
use panweave_codec::{Reader, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ManufacturerCode};

use crate::frame::ZclStatus;
use crate::types::{DataType, Value, semi_to_f32};

/// Largest stored attribute value in octets (long strings and composites
/// beyond this are rejected with INSUFFICIENT_SPACE).
pub const MAX_ATTRIBUTE_BYTES: usize = 36;

/// Octets of value storage one cluster's wide attributes (strings,
/// composites, keys) share: each takes [`MAX_ATTRIBUTE_BYTES`] twice,
/// for its value and its factory default.
pub const ATTRIBUTE_POOL: usize = 384;

/// Largest value kept inline in an attribute entry.
const INLINE: usize = 8;

/// Attribute access flags (§2.3.4.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Access(pub u8);

impl Access {
    /// Readable.
    pub const READ: Access = Access(0x01);
    /// Writable.
    pub const WRITE: Access = Access(0x02);
    /// Reportable.
    pub const REPORT: Access = Access(0x04);
    /// Read-only.
    pub const RO: Access = Access(0x01);
    /// Read/write.
    pub const RW: Access = Access(0x03);
    /// Read-only and reportable.
    pub const RO_REPORT: Access = Access(0x05);
    /// Read/write and reportable.
    pub const RW_REPORT: Access = Access(0x07);
    /// A credential: never readable over the air (reads answer
    /// NOT_AUTHORIZED) and redacted from `Debug` output.
    pub const SECRET: Access = Access(0x08);
    /// Write-only credential.
    pub const WO_SECRET: Access = Access(0x0a);

    /// True when all bits of `flag` are set.
    #[inline]
    pub const fn has(self, flag: Access) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// Union.
    #[inline]
    pub const fn or(self, other: Access) -> Access {
        Access(self.0 | other.0)
    }
}

/// Static description of an attribute.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AttributeDef {
    /// Identifier.
    pub id: AttributeId,
    /// Data type.
    pub ty: DataType,
    /// Access.
    pub access: Access,
    /// Manufacturer code for manufacturer-specific attributes.
    pub manufacturer: Option<ManufacturerCode>,
}

impl AttributeDef {
    /// A standard attribute.
    pub const fn new(id: u16, ty: DataType, access: Access) -> Self {
        AttributeDef {
            id: AttributeId(id),
            ty,
            access,
            manufacturer: None,
        }
    }

    /// The `ClusterRevision` global attribute (§2.3.4.5.1).
    pub const CLUSTER_REVISION: AttributeDef =
        AttributeDef::new(0xFFFD, DataType::Uint(2), Access::RO);

    /// The `AttributeReportingStatus` global attribute (§2.3.4.5.2).
    pub const ATTRIBUTE_REPORTING_STATUS: AttributeDef =
        AttributeDef::new(0xFFFE, DataType::Enum8, Access::RO);
}

/// Reporting configuration and state of one attribute (§2.5.7.1).
#[derive(Clone, Copy, Debug)]
pub struct ReportState {
    /// Reportable change magnitude (analog types).
    pub change: u64,
    /// The analog key of the value last reported (see [`analog_key`]).
    last_reported: u64,
    /// Milliseconds of the last report (`NEVER` before the first).
    last_report: u64,
    /// Minimum reporting interval.
    pub min: u16,
    /// Maximum reporting interval (0 = change-only, 0xffff = off).
    pub max: u16,
    /// Timeout period configured for received reports.
    pub timeout: u16,
    pending: bool,
}

impl ReportState {
    const NEVER: u64 = u64::MAX;

    /// No configuration at all.
    const UNSET: ReportState = ReportState {
        change: 0,
        last_reported: 0,
        last_report: Self::NEVER,
        min: 0,
        max: 0xffff,
        timeout: 0,
        pending: false,
    };

    /// True when reports are generated (§2.5.7.1.6).
    pub const fn active(&self) -> bool {
        self.max != 0xffff
    }

    /// True when anything is configured: reports out, or a timeout for
    /// reports in.
    const fn configured(&self) -> bool {
        self.active() || self.timeout != 0
    }

    fn last(&self) -> Option<Instant> {
        (self.last_report != Self::NEVER).then(|| Instant::from_millis(self.last_report))
    }

    /// True when a report is due at `now` (§2.5.11.2.1–§2.5.11.2.3).
    fn due(&self, now: Instant) -> bool {
        if !self.active() {
            return false;
        }
        let since = self
            .last()
            .map_or(Duration::from_secs(u64::from(u16::MAX)), |t| {
                now.saturating_duration_since(t)
            });
        let min_ok = since.as_secs() >= u64::from(self.min);
        if self.pending && min_ok {
            return true;
        }
        self.max != 0 && since.as_secs() >= u64::from(self.max)
    }

    /// Time of the next report if one is scheduled.
    fn next(&self) -> Option<Instant> {
        if !self.active() {
            return None;
        }
        let last = self.last()?;
        let mut next: Option<Instant> = None;
        if self.pending {
            next = Some(last.saturating_add(Duration::from_secs(u64::from(self.min))));
        }
        if self.max != 0 {
            let at_max = last.saturating_add(Duration::from_secs(u64::from(self.max)));
            next = Some(match next {
                Some(n) if n.as_millis() < at_max.as_millis() => n,
                _ => at_max,
            });
        }
        next
    }
}

/// A default reporting configuration (BDB 3.1 §6.5): applied when the
/// instance is created and restored by Reset to Factory Defaults.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DefaultReporting {
    /// Minimum reporting interval (seconds).
    pub min: u16,
    /// Maximum reporting interval (seconds; 0 = change-only).
    pub max: u16,
    /// Reportable change (analog types): the magnitude for integer
    /// types, [`float_change`] for single / double precision types.
    pub change: u64,
}

/// The reportable-change encoding of a floating-point magnitude (the
/// `f64` bit pattern), as stored in [`DefaultReporting::change`] and
/// [`ReportState::change`] for single / double precision attributes.
pub const fn float_change(magnitude: f64) -> u64 {
    magnitude.to_bits()
}

/// The comparison key of an analog value for reportable-change checks:
/// the `f64` bit pattern for floating-point types, the two's complement
/// value for integer and time types.
fn analog_key(v: &Value<'_>) -> u64 {
    match v {
        Value::Single(f) => f64::from(*f).to_bits(),
        Value::Double(f) => f.to_bits(),
        Value::Semi(bits) => f64::from(semi_to_f32(*bits)).to_bits(),
        Value::Int { value, .. } => value.cast_unsigned(),
        other => other.as_u64().unwrap_or(0),
    }
}

/// Whether the analog value `now` differs from the key `last` by at
/// least `change` (a change of zero reports every change).
fn change_reached(ty: DataType, last: u64, now: &Value<'_>, change: u64) -> bool {
    match ty {
        DataType::Single | DataType::Double | DataType::Semi => {
            let a = f64::from_bits(last);
            let b = f64::from_bits(analog_key(now));
            let delta = (a - b).abs();
            delta > 0.0 && delta >= f64::from_bits(change)
        }
        DataType::Int(_) => {
            let a = last.cast_signed();
            let b = analog_key(now).cast_signed();
            a.abs_diff(b) >= change.max(1)
        }
        _ => last.abs_diff(analog_key(now)) >= change.max(1),
    }
}

/// An attribute's bookkeeping: its definition, its value and factory
/// default (inline, or their place in the cluster's pool), and its
/// reporting configuration, current and default.
#[derive(Clone, Copy)]
pub struct Attribute {
    /// Definition.
    pub def: AttributeDef,
    reporting: ReportState,
    /// The value and, from `INLINE` on, the default of an inline
    /// attribute.
    inline: [u8; 2 * INLINE],
    // The default reporting configuration, flattened (a nested struct
    // would pad the entry to the next multiple of eight).
    default_change: u64,
    default_min: u16,
    default_max: u16,
    /// Offset of a wide value in the pool; the default follows at
    /// `offset + capacity()`.
    offset: u16,
    len: u8,
    default_len: u8,
}

impl core::fmt::Debug for Attribute {
    /// The definition and reporting state; the value is
    /// [`AttrRef`]'s to show (redacted when secret).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attribute")
            .field("def", &self.def)
            .field("reporting", &self.reporting)
            .finish_non_exhaustive()
    }
}

impl Attribute {
    /// Octets reserved for the value (and again for the default).
    fn capacity(&self) -> usize {
        capacity_of(self.def.ty)
    }

    /// True when the value lives in the entry itself.
    fn is_inline(&self) -> bool {
        self.capacity() <= INLINE
    }

    /// The default reporting configuration.
    pub const fn default_reporting(&self) -> Option<DefaultReporting> {
        if self.default_max == 0xffff {
            None
        } else {
            Some(DefaultReporting {
                min: self.default_min,
                max: self.default_max,
                change: self.default_change,
            })
        }
    }
}

/// Octets a value of `ty` reserves: its fixed size, or the largest
/// attribute value for variable-length types.
fn capacity_of(ty: DataType) -> usize {
    ty.fixed_len()
        .filter(|n| *n <= MAX_ATTRIBUTE_BYTES)
        .unwrap_or(MAX_ATTRIBUTE_BYTES)
}

/// A read view of one attribute in its table.
#[derive(Clone, Copy)]
pub struct AttrRef<'a> {
    /// Definition.
    pub def: AttributeDef,
    /// Reporting state when configured.
    pub reporting: Option<&'a ReportState>,
    meta: &'a Attribute,
    bytes: &'a [u8],
}

impl core::fmt::Debug for AttrRef<'_> {
    /// Keys and `SECRET` attributes are redacted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let secret = self.def.ty == DataType::Key128 || self.def.access.has(Access::SECRET);
        let mut d = f.debug_struct("Attribute");
        d.field("def", &self.def);
        if secret {
            d.field("value", &"[REDACTED]");
        } else {
            d.field("value", &self.bytes);
        }
        d.field("reporting", &self.reporting)
            .finish_non_exhaustive()
    }
}

impl<'a> AttrRef<'a> {
    /// The raw encoded value.
    pub fn raw(&self) -> &'a [u8] {
        self.bytes
    }

    /// The decoded value.
    pub fn value(&self) -> Value<'a> {
        let mut r = Reader::new(self.bytes);
        Value::decode(&mut r, self.def.ty).unwrap_or(Value::NoData)
    }

    /// The default reporting configuration.
    pub const fn default_reporting(&self) -> Option<DefaultReporting> {
        self.meta.default_reporting()
    }

    /// True when a report is due at `now` (§2.5.11.2.1–§2.5.11.2.3).
    pub fn report_due(&self, now: Instant) -> bool {
        self.reporting.is_some_and(|r| r.due(now))
    }

    /// Time of the next report if one is scheduled.
    pub fn next_report(&self) -> Option<Instant> {
        self.reporting.and_then(ReportState::next)
    }
}

/// A write handle to one attribute in its table.
pub struct AttrMut<'a, const N: usize> {
    table: &'a mut AttributeTable<N>,
    index: usize,
}

impl<const N: usize> AttrMut<'_, N> {
    /// Definition.
    pub fn def(&self) -> AttributeDef {
        self.table.attrs[self.index].def
    }

    /// Read view.
    pub fn as_ref(&self) -> AttrRef<'_> {
        self.table.at(self.index)
    }

    /// The decoded value.
    pub fn value(&self) -> Value<'_> {
        self.as_ref().value()
    }

    /// Sets the value (type checked). Returns whether it changed and
    /// updates the reporting state.
    pub fn set(&mut self, v: &Value<'_>) -> Result<bool, ZclStatus> {
        self.table.store(self.index, v, false)
    }

    /// Configures reporting (direction 0x00). `change` is the reportable
    /// change magnitude for analog types.
    pub fn configure_reporting(&mut self, min: u16, max: u16, change: u64, now: Instant) {
        self.table
            .configure_reporting(self.index, min, max, change, now);
    }

    /// Sets the timeout for received reports (direction 0x01).
    pub fn set_report_timeout(&mut self, timeout: u16) {
        self.table.attrs[self.index].reporting.timeout = timeout;
    }

    /// Marks the current value as reported at `now`.
    pub fn mark_reported(&mut self, now: Instant) {
        self.table.mark_reported(self.index, now);
    }

    /// Restores the factory default value and reporting configuration
    /// (Basic Reset to Factory Defaults, ZCL8 §3.2.2.3.1).
    pub fn reset_to_default(&mut self, now: Instant) {
        self.table.reset_one(self.index, now);
    }
}

/// Fixed-capacity attribute table of one cluster instance: up to `N`
/// attributes, the wide ones over one [`ATTRIBUTE_POOL`]-octet pool.
#[derive(Clone)]
pub struct AttributeTable<const N: usize> {
    attrs: Vec<Attribute, N>,
    pool: Vec<u8, ATTRIBUTE_POOL>,
}

impl<const N: usize> core::fmt::Debug for AttributeTable<N> {
    /// Lists the attributes (each redacting a secret), never the pool.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<const N: usize> Default for AttributeTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AttributeTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        AttributeTable {
            attrs: Vec::new(),
            pool: Vec::new(),
        }
    }

    /// Adds an attribute; fails with `InsufficientSpace` when the table
    /// or the pool is full, `DuplicateExists` for a known identifier and
    /// `InvalidDataType` when the initial value is of another type.
    pub fn add(&mut self, def: AttributeDef, initial: &Value<'_>) -> Result<(), ZclStatus> {
        if self.get(def.id, def.manufacturer).is_some() {
            return Err(ZclStatus::DuplicateExists);
        }
        if initial.data_type() != def.ty {
            return Err(ZclStatus::InvalidDataType);
        }
        if self.attrs.is_full() {
            return Err(ZclStatus::InsufficientSpace);
        }
        let capacity = capacity_of(def.ty);
        let mut buf = [0u8; MAX_ATTRIBUTE_BYTES];
        let mut w = Writer::new(&mut buf);
        initial
            .encode(&mut w)
            .map_err(|_| ZclStatus::InsufficientSpace)?;
        let n = w.position();
        if n > capacity {
            return Err(ZclStatus::InsufficientSpace);
        }
        let mut inline = [0u8; 2 * INLINE];
        let mut offset = 0;
        if capacity <= INLINE {
            inline[..n].copy_from_slice(&buf[..n]);
            inline[INLINE..INLINE + n].copy_from_slice(&buf[..n]);
        } else {
            offset = self.pool.len();
            if offset + 2 * capacity > ATTRIBUTE_POOL {
                return Err(ZclStatus::InsufficientSpace);
            }
            let _ = self.pool.resize_default(offset + 2 * capacity);
            self.pool[offset..offset + n].copy_from_slice(&buf[..n]);
            self.pool[offset + capacity..offset + capacity + n].copy_from_slice(&buf[..n]);
        }
        #[allow(clippy::cast_possible_truncation)]
        let attr = Attribute {
            def,
            reporting: ReportState::UNSET,
            inline,
            default_change: 0,
            default_min: 0,
            default_max: 0xffff,
            offset: offset as u16,
            len: n as u8,
            default_len: n as u8,
        };
        let _ = self.attrs.push(attr);
        Ok(())
    }

    /// Adds an attribute with a default reporting configuration (BDB 3.1
    /// §6.5), active from `now`.
    pub fn add_reported(
        &mut self,
        def: AttributeDef,
        initial: &Value<'_>,
        cfg: DefaultReporting,
        now: Instant,
    ) -> Result<(), ZclStatus> {
        self.add(def, initial)?;
        let index = self.attrs.len() - 1;
        let a = &mut self.attrs[index];
        a.default_change = cfg.change;
        a.default_min = cfg.min;
        a.default_max = cfg.max;
        self.configure_reporting(index, cfg.min, cfg.max, cfg.change, now);
        Ok(())
    }

    /// Restores every attribute's factory default (§3.2.2.3.1).
    pub fn reset_to_defaults(&mut self, now: Instant) {
        for i in 0..self.attrs.len() {
            self.reset_one(i, now);
        }
    }

    /// Number of attributes.
    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    fn index_of(&self, id: AttributeId, manufacturer: Option<ManufacturerCode>) -> Option<usize> {
        self.attrs
            .iter()
            .position(|a| a.def.id == id && a.def.manufacturer == manufacturer)
    }

    fn value_bytes(&self, index: usize) -> &[u8] {
        let a = &self.attrs[index];
        let n = usize::from(a.len);
        if a.is_inline() {
            &a.inline[..n]
        } else {
            let start = usize::from(a.offset);
            &self.pool[start..start + n]
        }
    }

    /// The stored default of attribute `index`.
    fn default_bytes(&self, index: usize) -> &[u8] {
        let a = &self.attrs[index];
        let n = usize::from(a.default_len);
        if a.is_inline() {
            &a.inline[INLINE..INLINE + n]
        } else {
            let start = usize::from(a.offset) + a.capacity();
            &self.pool[start..start + n]
        }
    }

    /// Overwrites the value (or, with `default`, the factory default) of
    /// attribute `index` with `bytes` (already checked against the
    /// capacity).
    fn write_bytes(&mut self, index: usize, default: bool, bytes: &[u8]) {
        let a = &mut self.attrs[index];
        let n = bytes.len();
        #[allow(clippy::cast_possible_truncation)]
        if default {
            a.default_len = n as u8;
        } else {
            a.len = n as u8;
        }
        if a.is_inline() {
            let start = if default { INLINE } else { 0 };
            a.inline[start..start + n].copy_from_slice(bytes);
        } else {
            let start = usize::from(a.offset) + if default { a.capacity() } else { 0 };
            self.pool[start..start + n].copy_from_slice(bytes);
        }
    }

    fn report_state(&self, index: usize) -> Option<&ReportState> {
        let r = &self.attrs[index].reporting;
        r.configured().then_some(r)
    }

    /// The attribute at `index` (insertion order).
    pub fn at(&self, index: usize) -> AttrRef<'_> {
        AttrRef {
            def: self.attrs[index].def,
            reporting: self.report_state(index),
            meta: &self.attrs[index],
            bytes: self.value_bytes(index),
        }
    }

    /// The attribute at `index`, mutably.
    pub fn at_mut(&mut self, index: usize) -> AttrMut<'_, N> {
        AttrMut { table: self, index }
    }

    /// Typed read of an unsigned integer / enumeration / bitmap / bool
    /// attribute as `u64` (`None` when absent or of another type).
    pub fn u64(&self, id: AttributeId) -> Option<u64> {
        self.value(id).and_then(|v| v.as_u64())
    }

    /// Looks up an attribute.
    pub fn get(
        &self,
        id: AttributeId,
        manufacturer: Option<ManufacturerCode>,
    ) -> Option<AttrRef<'_>> {
        self.index_of(id, manufacturer).map(|i| self.at(i))
    }

    /// Looks up an attribute mutably.
    pub fn get_mut(
        &mut self,
        id: AttributeId,
        manufacturer: Option<ManufacturerCode>,
    ) -> Option<AttrMut<'_, N>> {
        let index = self.index_of(id, manufacturer)?;
        Some(AttrMut { table: self, index })
    }

    /// Current value of a standard attribute.
    pub fn value(&self, id: AttributeId) -> Option<Value<'_>> {
        let i = self.index_of(id, None)?;
        Some(self.at(i).value())
    }

    /// Sets a standard attribute (application-side write, ignoring
    /// access flags). Returns whether the value changed.
    pub fn set(&mut self, id: AttributeId, v: &Value<'_>) -> Result<bool, ZclStatus> {
        let i = self
            .index_of(id, None)
            .ok_or(ZclStatus::UnsupportedAttribute)?;
        self.store(i, v, false)
    }

    /// Iterates attributes in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = AttrRef<'_>> {
        (0..self.attrs.len()).map(|i| self.at(i))
    }

    /// Earliest scheduled report of any attribute.
    pub fn next_report(&self) -> Option<Instant> {
        self.attrs
            .iter()
            .filter_map(|a| a.reporting.next())
            .min_by_key(|t| t.as_millis())
    }

    /// Writes `v` into attribute `index` (type checked; `as_default`
    /// also makes it the factory default). Returns whether it changed.
    fn store(&mut self, index: usize, v: &Value<'_>, as_default: bool) -> Result<bool, ZclStatus> {
        let a = self.attrs[index];
        if v.data_type() != a.def.ty {
            return Err(ZclStatus::InvalidDataType);
        }
        let mut buf = [0u8; MAX_ATTRIBUTE_BYTES];
        let mut w = Writer::new(&mut buf);
        v.encode(&mut w).map_err(|_| ZclStatus::InsufficientSpace)?;
        let n = w.position();
        if n > a.capacity() {
            return Err(ZclStatus::InsufficientSpace);
        }
        let changed = self.value_bytes(index) != &buf[..n];
        self.write_bytes(index, false, &buf[..n]);
        if as_default {
            self.write_bytes(index, true, &buf[..n]);
        }
        if changed {
            self.note_change(index);
        }
        Ok(changed)
    }

    /// Records a change for reporting purposes (§2.5.11.2.2, §2.5.11.2.3).
    fn note_change(&mut self, index: usize) {
        let ty = self.attrs[index].def.ty;
        let current = self.at(index).value();
        let r = &self.attrs[index].reporting;
        if !r.active() {
            return;
        }
        if !ty.is_analog() || change_reached(ty, r.last_reported, &current, r.change) {
            self.attrs[index].reporting.pending = true;
        }
    }

    fn configure_reporting(&mut self, index: usize, min: u16, max: u16, change: u64, now: Instant) {
        let r = &mut self.attrs[index].reporting;
        if max == 0xffff {
            // Reporting off; a timeout for received reports stays.
            r.max = 0xffff;
            r.pending = false;
            return;
        }
        let timeout = r.timeout;
        let last_reported = analog_key(&self.at(index).value());
        self.attrs[index].reporting = ReportState {
            change,
            last_reported,
            last_report: now.as_millis(),
            min,
            max,
            timeout,
            pending: false,
        };
    }

    fn mark_reported(&mut self, index: usize, now: Instant) {
        let key = analog_key(&self.at(index).value());
        let r = &mut self.attrs[index].reporting;
        r.last_report = now.as_millis();
        r.pending = false;
        r.last_reported = key;
    }

    fn reset_one(&mut self, index: usize, now: Instant) {
        let a = self.attrs[index];
        let mut buf = [0u8; MAX_ATTRIBUTE_BYTES];
        let n = usize::from(a.default_len);
        buf[..n].copy_from_slice(self.default_bytes(index));
        self.write_bytes(index, false, &buf[..n]);
        match a.default_reporting() {
            Some(cfg) => self.configure_reporting(index, cfg.min, cfg.max, cfg.change, now),
            None => self.configure_reporting(index, 0, 0xffff, 0, now),
        }
    }

    /// Attributes with identifier ≥ `start` (for discovery), sorted by
    /// identifier.
    pub fn discover(
        &self,
        start: AttributeId,
        manufacturer: Option<ManufacturerCode>,
        mut f: impl FnMut(AttrRef<'_>) -> bool,
    ) -> bool {
        // Table sizes are small: repeated minimum search keeps this
        // allocation-free.
        let mut last: Option<u16> = None;
        loop {
            let next = (0..self.attrs.len())
                .map(|i| (i, self.attrs[i].def))
                .filter(|(_, d)| d.manufacturer == manufacturer && d.id >= start)
                .filter(|(_, d)| last.is_none_or(|l| d.id.0 > l))
                .min_by_key(|(_, d)| d.id.0);
            let Some((i, d)) = next else {
                return true;
            };
            if !f(self.at(i)) {
                return false;
            }
            last = Some(d.id.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_type_check() {
        let mut t = AttributeTable::<4>::new();
        t.add(
            AttributeDef::new(0, DataType::Bool, Access::RW_REPORT),
            &Value::Bool(Some(false)),
        )
        .unwrap();
        t.add(
            AttributeDef::new(1, DataType::Uint(2), Access::RO),
            &Value::Uint { width: 2, value: 7 },
        )
        .unwrap();
        assert_eq!(
            t.add(
                AttributeDef::new(1, DataType::Uint(2), Access::RO),
                &Value::NoData
            ),
            Err(ZclStatus::DuplicateExists)
        );
        assert_eq!(
            t.value(AttributeId(1)),
            Some(Value::Uint { width: 2, value: 7 })
        );
        assert_eq!(
            t.set(AttributeId(1), &Value::Uint { width: 1, value: 1 }),
            Err(ZclStatus::InvalidDataType)
        );
        assert_eq!(t.set(AttributeId(0), &Value::Bool(Some(true))), Ok(true));
        assert_eq!(t.set(AttributeId(0), &Value::Bool(Some(true))), Ok(false));
        assert_eq!(
            t.set(AttributeId(9), &Value::Bool(Some(true))),
            Err(ZclStatus::UnsupportedAttribute)
        );
        let mut ids = Vec::<u16, 4>::new();
        assert!(t.discover(AttributeId(0), None, |a| {
            ids.push(a.def.id.0).unwrap();
            true
        }));
        assert_eq!(ids.as_slice(), &[0, 1]);
        // A bool and a uint16 live inline; strings take the largest
        // value each way from the pool and shrink or grow within it.
        assert_eq!(t.pool.len(), 0);
        t.add(
            AttributeDef::new(2, DataType::CharString, Access::RW),
            &Value::String {
                ty: DataType::CharString,
                bytes: Some(b"abc"),
            },
        )
        .unwrap();
        assert_eq!(t.pool.len(), 2 * MAX_ATTRIBUTE_BYTES);
        assert_eq!(
            t.set(
                AttributeId(2),
                &Value::String {
                    ty: DataType::CharString,
                    bytes: Some(b"a much longer string value"),
                }
            ),
            Ok(true)
        );
        assert_eq!(
            t.value(AttributeId(2)),
            Some(Value::String {
                ty: DataType::CharString,
                bytes: Some(b"a much longer string value"),
            })
        );
        assert_eq!(
            t.set(
                AttributeId(2),
                &Value::String {
                    ty: DataType::CharString,
                    bytes: Some(&[b'x'; 40]),
                }
            ),
            Err(ZclStatus::InsufficientSpace)
        );
        // Reset restores the factory value.
        t.reset_to_defaults(Instant::from_millis(0));
        assert_eq!(
            t.value(AttributeId(2)),
            Some(Value::String {
                ty: DataType::CharString,
                bytes: Some(b"abc"),
            })
        );
        assert_eq!(t.value(AttributeId(0)), Some(Value::Bool(Some(false))));
    }

    #[test]
    fn reporting_schedule() {
        let t0 = Instant::from_millis(0);
        let mut t = AttributeTable::<4>::new();
        t.add(
            AttributeDef::new(0, DataType::Uint(1), Access::RO_REPORT),
            &Value::Uint {
                width: 1,
                value: 10,
            },
        )
        .unwrap();
        t.add(
            AttributeDef::new(1, DataType::Bool, Access::RO_REPORT),
            &Value::Bool(Some(false)),
        )
        .unwrap();
        let id = AttributeId(0);
        assert!(!t.get(id, None).unwrap().report_due(t0));
        t.get_mut(id, None)
            .unwrap()
            .configure_reporting(5, 60, 3, t0);
        assert!(!t.get(id, None).unwrap().report_due(t0));
        // Small change: below the reportable change.
        t.set(
            id,
            &Value::Uint {
                width: 1,
                value: 12,
            },
        )
        .unwrap();
        assert!(
            !t.get(id, None)
                .unwrap()
                .report_due(Instant::from_millis(10_000))
        );
        // Change of 3 from the last reported value (10 -> 13).
        t.set(
            id,
            &Value::Uint {
                width: 1,
                value: 13,
            },
        )
        .unwrap();
        assert!(
            !t.get(id, None)
                .unwrap()
                .report_due(Instant::from_millis(4_000)),
            "min interval"
        );
        assert!(
            t.get(id, None)
                .unwrap()
                .report_due(Instant::from_millis(5_000))
        );
        t.get_mut(id, None)
            .unwrap()
            .mark_reported(Instant::from_millis(5_000));
        assert!(
            !t.get(id, None)
                .unwrap()
                .report_due(Instant::from_millis(6_000))
        );
        // Periodic at max.
        assert!(
            t.get(id, None)
                .unwrap()
                .report_due(Instant::from_millis(65_000))
        );
        assert_eq!(
            t.get(id, None).unwrap().next_report(),
            Some(Instant::from_millis(65_000))
        );
        assert_eq!(t.next_report(), Some(Instant::from_millis(65_000)));
        // Discrete attribute: any change.
        let b = AttributeId(1);
        t.get_mut(b, None).unwrap().configure_reporting(0, 0, 0, t0);
        t.set(b, &Value::Bool(Some(true))).unwrap();
        assert!(t.get(b, None).unwrap().report_due(t0));
        t.get_mut(b, None).unwrap().mark_reported(t0);
        assert!(
            !t.get(b, None)
                .unwrap()
                .report_due(Instant::from_millis(100_000)),
            "max 0: change only"
        );
        t.get_mut(b, None)
            .unwrap()
            .configure_reporting(0, 0xffff, 0, t0);
        t.set(b, &Value::Bool(Some(false))).unwrap();
        assert!(!t.get(b, None).unwrap().report_due(t0), "reporting off");
        assert!(t.get(b, None).unwrap().reporting.is_none(), "slot released");
        // A receive timeout survives reporting being switched off.
        t.get_mut(b, None).unwrap().set_report_timeout(30);
        t.get_mut(b, None).unwrap().configure_reporting(1, 2, 0, t0);
        t.get_mut(b, None)
            .unwrap()
            .configure_reporting(0, 0xffff, 0, t0);
        assert_eq!(
            t.get(b, None).unwrap().reporting.map(|r| r.timeout),
            Some(30)
        );
        // Signed and floating-point changes.
        let mut s = AttributeTable::<2>::new();
        s.add(
            AttributeDef::new(0, DataType::Int(2), Access::RO_REPORT),
            &Value::Int {
                width: 2,
                value: -5,
            },
        )
        .unwrap();
        s.add(
            AttributeDef::new(1, DataType::Single, Access::RO_REPORT),
            &Value::Single(1.0),
        )
        .unwrap();
        s.get_mut(AttributeId(0), None)
            .unwrap()
            .configure_reporting(0, 0, 4, t0);
        s.set(
            AttributeId(0),
            &Value::Int {
                width: 2,
                value: -2,
            },
        )
        .unwrap();
        assert!(!s.get(AttributeId(0), None).unwrap().report_due(t0));
        s.set(AttributeId(0), &Value::Int { width: 2, value: 3 })
            .unwrap();
        assert!(s.get(AttributeId(0), None).unwrap().report_due(t0));
        s.get_mut(AttributeId(1), None)
            .unwrap()
            .configure_reporting(0, 0, float_change(0.5), t0);
        s.set(AttributeId(1), &Value::Single(1.25)).unwrap();
        assert!(!s.get(AttributeId(1), None).unwrap().report_due(t0));
        s.set(AttributeId(1), &Value::Single(1.75)).unwrap();
        assert!(s.get(AttributeId(1), None).unwrap().report_due(t0));
    }

    #[test]
    #[cfg(feature = "std")]
    fn debug_output_redacts_keys_and_secrets() {
        let mut t = AttributeTable::<4>::new();
        let key = [0x5a; 16];
        t.add(
            AttributeDef::new(0, DataType::Key128, Access::WO_SECRET),
            &Value::Key128(key),
        )
        .unwrap();
        t.add(
            AttributeDef::new(1, DataType::OctetString, Access::SECRET),
            &Value::String {
                ty: DataType::OctetString,
                bytes: Some(b"pin"),
            },
        )
        .unwrap();
        t.add(
            AttributeDef::new(2, DataType::Uint(1), Access::RO),
            &Value::Uint {
                width: 1,
                value: 0x77,
            },
        )
        .unwrap();
        let s = std::format!("{t:?}");
        assert!(!s.contains("90, 90"), "{s}");
        assert!(!s.contains("112, 105, 110"), "{s}");
        assert!(s.contains("[REDACTED]") && s.contains("119"), "{s}");
        let s = std::format!("{:?}", t.at(0).meta);
        assert!(!s.contains("90, 90"), "{s}");
    }

    #[test]
    fn every_attribute_can_report() {
        let t0 = Instant::from_millis(0);
        let mut t = AttributeTable::<12>::new();
        for i in 0..12u16 {
            t.add(
                AttributeDef::new(i, DataType::Uint(1), Access::RO_REPORT),
                &Value::Uint { width: 1, value: 0 },
            )
            .unwrap();
            t.get_mut(AttributeId(i), None)
                .unwrap()
                .configure_reporting(0, 10, 1, t0);
        }
        assert!(t.iter().all(|a| a.reporting.is_some()));
        // A timeout for received reports is a configuration of its own
        // and survives reporting being switched off.
        let mut a = t.get_mut(AttributeId(3), None).unwrap();
        a.set_report_timeout(5);
        a.configure_reporting(0, 0xffff, 0, t0);
        let a = t.get(AttributeId(3), None).unwrap();
        assert_eq!(a.reporting.map(|r| (r.max, r.timeout)), Some((0xffff, 5)));
        assert!(a.next_report().is_none());
    }
}
