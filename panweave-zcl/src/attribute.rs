//! Attribute definitions and storage (ZCL8 §2.3.4) with the reporting
//! state of §2.5.7 / §2.5.11.
//!
//! Values are stored in their wire encoding so that any data type can be
//! held without a large enum; typed accessors decode on demand.

use heapless::Vec;
use panweave_codec::{Reader, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ManufacturerCode};

use crate::frame::ZclStatus;
use crate::types::{DataType, Value, analog_delta, semi_to_f32};

/// Largest stored attribute value in octets (long strings and composites
/// beyond this are rejected with INSUFFICIENT_SPACE).
pub const MAX_ATTRIBUTE_BYTES: usize = 36;

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
#[derive(Clone, Debug)]
pub struct ReportState {
    /// Minimum reporting interval.
    pub min: u16,
    /// Maximum reporting interval (0 = change-only, 0xffff = off).
    pub max: u16,
    /// Reportable change magnitude (analog types).
    pub change: u64,
    /// Timeout period configured for received reports.
    pub timeout: u16,
    last_report: Option<Instant>,
    last_reported: Vec<u8, MAX_ATTRIBUTE_BYTES>,
    pending: bool,
}

impl ReportState {
    /// True when reports are generated (§2.5.7.1.6).
    pub const fn active(&self) -> bool {
        self.max != 0xffff
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

/// An attribute with its current value.
#[derive(Clone)]
pub struct Attribute {
    /// Definition.
    pub def: AttributeDef,
    value: Vec<u8, MAX_ATTRIBUTE_BYTES>,
    /// Factory default (the initial value).
    default: Vec<u8, MAX_ATTRIBUTE_BYTES>,
    /// Default reporting configuration, if any.
    default_reporting: Option<DefaultReporting>,
    /// Reporting state when configured.
    pub reporting: Option<ReportState>,
}

impl core::fmt::Debug for Attribute {
    /// Keys and `SECRET` attributes are redacted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let secret = self.def.ty == DataType::Key128 || self.def.access.has(Access::SECRET);
        let mut d = f.debug_struct("Attribute");
        d.field("def", &self.def);
        if secret {
            d.field("value", &"[REDACTED]");
        } else {
            d.field("value", &self.value.as_slice());
        }
        d.field("reporting", &self.reporting)
            .finish_non_exhaustive()
    }
}

impl Attribute {
    /// Creates the attribute with an encoded initial value.
    pub fn new(def: AttributeDef, initial: &Value<'_>) -> Result<Self, ZclStatus> {
        let mut a = Attribute {
            def,
            value: Vec::new(),
            default: Vec::new(),
            default_reporting: None,
            reporting: None,
        };
        a.store(initial)?;
        a.default = a.value.clone();
        Ok(a)
    }

    /// Installs the default reporting configuration (BDB 3.1 §6.5) and
    /// activates it now.
    pub fn with_default_reporting(mut self, cfg: DefaultReporting, now: Instant) -> Self {
        self.default_reporting = Some(cfg);
        self.configure_reporting(cfg.min, cfg.max, cfg.change, now);
        self
    }

    /// The default reporting configuration.
    pub const fn default_reporting(&self) -> Option<DefaultReporting> {
        self.default_reporting
    }

    /// Restores the factory default value and reporting configuration
    /// (Basic Reset to Factory Defaults, ZCL8 §3.2.2.3.1).
    pub fn reset_to_default(&mut self, now: Instant) {
        self.value = self.default.clone();
        match self.default_reporting {
            Some(cfg) => self.configure_reporting(cfg.min, cfg.max, cfg.change, now),
            None => self.reporting = None,
        }
    }

    /// The raw encoded value.
    pub fn raw(&self) -> &[u8] {
        &self.value
    }

    /// The decoded value.
    pub fn value(&self) -> Value<'_> {
        let mut r = Reader::new(&self.value);
        Value::decode(&mut r, self.def.ty).unwrap_or(Value::NoData)
    }

    fn store(&mut self, v: &Value<'_>) -> Result<(), ZclStatus> {
        if v.data_type() != self.def.ty {
            return Err(ZclStatus::InvalidDataType);
        }
        let mut buf = [0u8; MAX_ATTRIBUTE_BYTES];
        let mut w = Writer::new(&mut buf);
        v.encode(&mut w).map_err(|_| ZclStatus::InsufficientSpace)?;
        let n = w.position();
        self.value.clear();
        self.value
            .extend_from_slice(&buf[..n])
            .map_err(|_| ZclStatus::InsufficientSpace)
    }

    /// Sets the value (type checked). Returns whether it changed and
    /// updates the reporting state.
    pub fn set(&mut self, v: &Value<'_>) -> Result<bool, ZclStatus> {
        let mut before: Vec<u8, MAX_ATTRIBUTE_BYTES> = Vec::new();
        let _ = before.extend_from_slice(&self.value);
        self.store(v)?;
        let changed = before.as_slice() != self.value.as_slice();
        if changed {
            self.note_change();
        }
        Ok(changed)
    }

    /// Records a change for reporting purposes (§2.5.11.2.2, §2.5.11.2.3).
    fn note_change(&mut self) {
        let ty = self.def.ty;
        let Some(rep) = self.reporting.as_mut() else {
            return;
        };
        if !rep.active() {
            return;
        }
        if ty.is_analog() {
            let mut r = Reader::new(&rep.last_reported);
            let last = Value::decode(&mut r, ty).ok();
            let mut r = Reader::new(&self.value);
            let now_v = Value::decode(&mut r, ty).ok();
            let reached = match (last, now_v) {
                // Floating-point types compare magnitudes; a change of
                // zero reports every change.
                (Some(Value::Single(a)), Some(Value::Single(b))) => {
                    let delta = f64::from((a - b).abs());
                    delta > 0.0 && delta >= f64::from_bits(rep.change)
                }
                (Some(Value::Double(a)), Some(Value::Double(b))) => {
                    let delta = (a - b).abs();
                    delta > 0.0 && delta >= f64::from_bits(rep.change)
                }
                (Some(Value::Semi(a)), Some(Value::Semi(b))) => {
                    let delta = f64::from((semi_to_f32(a) - semi_to_f32(b)).abs());
                    delta > 0.0 && delta >= f64::from_bits(rep.change)
                }
                (Some(a), Some(b)) => analog_delta(&a, &b).unwrap_or(u64::MAX) >= rep.change.max(1),
                _ => true,
            };
            if reached {
                rep.pending = true;
            }
        } else {
            rep.pending = true;
        }
    }

    /// Configures reporting (direction 0x00). `change` is the reportable
    /// change magnitude for analog types.
    pub fn configure_reporting(&mut self, min: u16, max: u16, change: u64, now: Instant) {
        if max == 0xffff {
            self.reporting = None;
            return;
        }
        let mut last_reported = Vec::new();
        let _ = last_reported.extend_from_slice(&self.value);
        let timeout = self.reporting.as_ref().map_or(0, |r| r.timeout);
        self.reporting = Some(ReportState {
            min,
            max,
            change,
            timeout,
            last_report: Some(now),
            last_reported,
            pending: false,
        });
    }

    /// Sets the timeout for received reports (direction 0x01).
    pub fn set_report_timeout(&mut self, timeout: u16) {
        match self.reporting.as_mut() {
            Some(r) => r.timeout = timeout,
            None => {
                self.reporting = Some(ReportState {
                    min: 0,
                    max: 0xffff,
                    change: 0,
                    timeout,
                    last_report: None,
                    last_reported: Vec::new(),
                    pending: false,
                });
            }
        }
    }

    /// True when a report is due at `now` (§2.5.11.2.1–§2.5.11.2.3).
    pub fn report_due(&self, now: Instant) -> bool {
        let Some(rep) = &self.reporting else {
            return false;
        };
        if !rep.active() {
            return false;
        }
        let since = rep
            .last_report
            .map_or(Duration::from_secs(u64::from(u16::MAX)), |t| {
                now.saturating_duration_since(t)
            });
        let min_ok = since.as_secs() >= u64::from(rep.min);
        if rep.pending && min_ok {
            return true;
        }
        rep.max != 0 && since.as_secs() >= u64::from(rep.max)
    }

    /// Time of the next report if one is scheduled.
    pub fn next_report(&self) -> Option<Instant> {
        let rep = self.reporting.as_ref()?;
        if !rep.active() {
            return None;
        }
        let last = rep.last_report?;
        let mut next: Option<Instant> = None;
        if rep.pending {
            next = Some(last.saturating_add(Duration::from_secs(u64::from(rep.min))));
        }
        if rep.max != 0 {
            let at_max = last.saturating_add(Duration::from_secs(u64::from(rep.max)));
            next = Some(match next {
                Some(n) if n.as_millis() < at_max.as_millis() => n,
                _ => at_max,
            });
        }
        next
    }

    /// Marks the current value as reported at `now`.
    pub fn mark_reported(&mut self, now: Instant) {
        if let Some(rep) = self.reporting.as_mut() {
            rep.last_report = Some(now);
            rep.pending = false;
            rep.last_reported.clear();
            let _ = rep.last_reported.extend_from_slice(&self.value);
        }
    }
}

/// Fixed-capacity attribute table of one cluster instance.
#[derive(Clone, Debug)]
pub struct AttributeTable<const N: usize> {
    attrs: Vec<Attribute, N>,
}

impl<const N: usize> Default for AttributeTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AttributeTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        AttributeTable { attrs: Vec::new() }
    }

    /// Adds an attribute; fails with TABLE_FULL-like `InsufficientSpace`
    /// or `DuplicateExists`.
    pub fn add(&mut self, def: AttributeDef, initial: &Value<'_>) -> Result<(), ZclStatus> {
        if self.get(def.id, def.manufacturer).is_some() {
            return Err(ZclStatus::DuplicateExists);
        }
        self.add_attribute(Attribute::new(def, initial)?)
    }

    /// Adds a prepared attribute.
    pub fn add_attribute(&mut self, a: Attribute) -> Result<(), ZclStatus> {
        if self.get(a.def.id, a.def.manufacturer).is_some() {
            return Err(ZclStatus::DuplicateExists);
        }
        self.attrs.push(a).map_err(|_| ZclStatus::InsufficientSpace)
    }

    /// Restores every attribute's factory default (§3.2.2.3.1).
    pub fn reset_to_defaults(&mut self, now: Instant) {
        for a in &mut self.attrs {
            a.reset_to_default(now);
        }
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
    ) -> Option<&Attribute> {
        self.attrs
            .iter()
            .find(|a| a.def.id == id && a.def.manufacturer == manufacturer)
    }

    /// Looks up an attribute mutably.
    pub fn get_mut(
        &mut self,
        id: AttributeId,
        manufacturer: Option<ManufacturerCode>,
    ) -> Option<&mut Attribute> {
        self.attrs
            .iter_mut()
            .find(|a| a.def.id == id && a.def.manufacturer == manufacturer)
    }

    /// Current value of a standard attribute.
    pub fn value(&self, id: AttributeId) -> Option<Value<'_>> {
        self.get(id, None).map(Attribute::value)
    }

    /// Sets a standard attribute (application-side write, ignoring
    /// access flags). Returns whether the value changed.
    pub fn set(&mut self, id: AttributeId, v: &Value<'_>) -> Result<bool, ZclStatus> {
        self.get_mut(id, None)
            .ok_or(ZclStatus::UnsupportedAttribute)?
            .set(v)
    }

    /// Iterates attributes in identifier order of insertion.
    pub fn iter(&self) -> impl Iterator<Item = &Attribute> {
        self.attrs.iter()
    }

    /// Iterates mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Attribute> {
        self.attrs.iter_mut()
    }

    /// Attributes with identifier ≥ `start` (for discovery), sorted by
    /// identifier.
    pub fn discover(
        &self,
        start: AttributeId,
        manufacturer: Option<ManufacturerCode>,
        mut f: impl FnMut(&Attribute) -> bool,
    ) -> bool {
        // Table sizes are small: repeated minimum search keeps this
        // allocation-free.
        let mut last: Option<u16> = None;
        loop {
            let next = self
                .attrs
                .iter()
                .filter(|a| a.def.manufacturer == manufacturer && a.def.id >= start)
                .filter(|a| last.is_none_or(|l| a.def.id.0 > l))
                .min_by_key(|a| a.def.id.0);
            let Some(a) = next else {
                return true;
            };
            if !f(a) {
                return false;
            }
            last = Some(a.def.id.0);
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
    }

    #[test]
    fn reporting_schedule() {
        let t0 = Instant::from_millis(0);
        let mut a = Attribute::new(
            AttributeDef::new(0, DataType::Uint(1), Access::RO_REPORT),
            &Value::Uint {
                width: 1,
                value: 10,
            },
        )
        .unwrap();
        assert!(!a.report_due(t0));
        a.configure_reporting(5, 60, 3, t0);
        assert!(!a.report_due(t0));
        // Small change: below the reportable change.
        a.set(&Value::Uint {
            width: 1,
            value: 12,
        })
        .unwrap();
        assert!(!a.report_due(Instant::from_millis(10_000)));
        // Change of 3 from the last reported value (10 -> 13).
        a.set(&Value::Uint {
            width: 1,
            value: 13,
        })
        .unwrap();
        assert!(!a.report_due(Instant::from_millis(4_000)), "min interval");
        assert!(a.report_due(Instant::from_millis(5_000)));
        a.mark_reported(Instant::from_millis(5_000));
        assert!(!a.report_due(Instant::from_millis(6_000)));
        // Periodic at max.
        assert!(a.report_due(Instant::from_millis(65_000)));
        assert_eq!(a.next_report(), Some(Instant::from_millis(65_000)));
        // Discrete attribute: any change.
        let mut b = Attribute::new(
            AttributeDef::new(1, DataType::Bool, Access::RO_REPORT),
            &Value::Bool(Some(false)),
        )
        .unwrap();
        b.configure_reporting(0, 0, 0, t0);
        b.set(&Value::Bool(Some(true))).unwrap();
        assert!(b.report_due(t0));
        b.mark_reported(t0);
        assert!(
            !b.report_due(Instant::from_millis(100_000)),
            "max 0: change only"
        );
        b.configure_reporting(0, 0xffff, 0, t0);
        b.set(&Value::Bool(Some(false))).unwrap();
        assert!(!b.report_due(t0), "reporting off");
    }
}
