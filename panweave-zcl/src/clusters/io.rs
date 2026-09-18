//! Input, Output and Value clusters (ZCL8 §3.14): the nine BACnet-style
//! Analog / Binary / Multistate Input, Output and Value clusters over
//! one attribute set — `OutOfService`, `PresentValue`, `StatusFlags`,
//! `Reliability`, `Description`, the analog range / units / resolution,
//! the binary polarity and texts, the multistate state count — with
//! the §3.14.11 rules: an input's `PresentValue` is writable only out of
//! service, `StatusFlags` mirrors `Reliability` and `OutOfService`, and
//! `PresentValue` / `StatusFlags` are reported.
//!
//! `PriorityArray` (an array of structures) and `StateText` are not
//! instantiated: `PresentValue` is written directly (priority 16).

use panweave_types::{AttributeId, ClusterId};

use crate::attribute::{Access, AttributeDef, AttributeTable, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// `ActiveText` (string ≤ 16, binary clusters).
pub const ACTIVE_TEXT: AttributeDef = AttributeDef::new(0x0004, DataType::CharString, Access::RW);
/// `Description` (string ≤ 16).
pub const DESCRIPTION: AttributeDef = AttributeDef::new(0x001c, DataType::CharString, Access::RW);
/// `InactiveText` (string ≤ 16, binary clusters).
pub const INACTIVE_TEXT: AttributeDef = AttributeDef::new(0x002e, DataType::CharString, Access::RW);
/// `MaxPresentValue` (single, analog clusters).
pub const MAX_PRESENT_VALUE: AttributeDef = AttributeDef::new(0x0041, DataType::Single, Access::RW);
/// `MinimumOffTime` (uint32 s, binary output / value).
pub const MINIMUM_OFF_TIME: AttributeDef = AttributeDef::new(0x0042, DataType::Uint(4), Access::RW);
/// `MinimumOnTime` (uint32 s, binary output / value).
pub const MINIMUM_ON_TIME: AttributeDef = AttributeDef::new(0x0043, DataType::Uint(4), Access::RW);
/// `MinPresentValue` (single, analog clusters).
pub const MIN_PRESENT_VALUE: AttributeDef = AttributeDef::new(0x0045, DataType::Single, Access::RW);
/// `NumberOfStates` (uint16, multistate clusters).
pub const NUMBER_OF_STATES: AttributeDef = AttributeDef::new(0x004a, DataType::Uint(2), Access::RW);
/// `OutOfService` (bool).
pub const OUT_OF_SERVICE: AttributeDef = AttributeDef::new(0x0051, DataType::Bool, Access::RW);
/// `Polarity` (enum8, binary clusters: 0 normal, 1 reverse).
pub const POLARITY: AttributeDef = AttributeDef::new(0x0054, DataType::Enum8, Access::RO);
/// `PresentValue` identifier (single / bool / uint16 by kind).
pub const PRESENT_VALUE: AttributeId = AttributeId(0x0055);
/// `Reliability` (enum8, §3.14.11.9).
pub const RELIABILITY: AttributeDef = AttributeDef::new(0x0067, DataType::Enum8, Access::RW);
/// `RelinquishDefault` identifier (same type as `PresentValue`).
pub const RELINQUISH_DEFAULT: AttributeId = AttributeId(0x0068);
/// `Resolution` (single, analog clusters).
pub const RESOLUTION: AttributeDef = AttributeDef::new(0x006a, DataType::Single, Access::RW);
/// `StatusFlags` (map8, reportable).
pub const STATUS_FLAGS: AttributeDef =
    AttributeDef::new(0x006f, DataType::Bitmap(1), Access::RO_REPORT);
/// `EngineeringUnits` (enum16, analog clusters; BACnet clause 21).
pub const ENGINEERING_UNITS: AttributeDef = AttributeDef::new(0x0075, DataType::Enum16, Access::RO);
/// `ApplicationType` (uint32).
pub const APPLICATION_TYPE: AttributeDef = AttributeDef::new(0x0100, DataType::Uint(4), Access::RO);

/// `StatusFlags` bits (§3.14.11.3).
pub mod status_flags {
    /// In alarm.
    pub const IN_ALARM: u8 = 0x01;
    /// Fault (`Reliability` other than no fault detected).
    pub const FAULT: u8 = 0x02;
    /// Overridden locally.
    pub const OVERRIDDEN: u8 = 0x04;
    /// Out of service.
    pub const OUT_OF_SERVICE: u8 = 0x08;
}

/// `Reliability` values (§3.14.11.9).
pub mod reliability {
    /// No fault detected.
    pub const NO_FAULT_DETECTED: u8 = 0;
    /// No sensor (input clusters).
    pub const NO_SENSOR: u8 = 1;
    /// Over range.
    pub const OVER_RANGE: u8 = 2;
    /// Under range.
    pub const UNDER_RANGE: u8 = 3;
    /// Open loop.
    pub const OPEN_LOOP: u8 = 4;
    /// Shorted loop.
    pub const SHORTED_LOOP: u8 = 5;
    /// No output (input clusters).
    pub const NO_OUTPUT: u8 = 6;
    /// Unreliable, other.
    pub const UNRELIABLE_OTHER: u8 = 7;
    /// Process error.
    pub const PROCESS_ERROR: u8 = 8;
    /// Multistate fault (multistate clusters).
    pub const MULTI_STATE_FAULT: u8 = 9;
    /// Configuration error.
    pub const CONFIGURATION_ERROR: u8 = 10;
}

/// `EngineeringUnits` value for "other".
pub const UNITS_OTHER: u16 = 0x00ff;

/// The nine clusters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Kind {
    /// Analog Input (0x000c).
    AnalogInput,
    /// Analog Output (0x000d).
    AnalogOutput,
    /// Analog Value (0x000e).
    AnalogValue,
    /// Binary Input (0x000f).
    BinaryInput,
    /// Binary Output (0x0010).
    BinaryOutput,
    /// Binary Value (0x0011).
    BinaryValue,
    /// Multistate Input (0x0012).
    MultistateInput,
    /// Multistate Output (0x0013).
    MultistateOutput,
    /// Multistate Value (0x0014).
    MultistateValue,
}

impl Kind {
    /// Cluster identifier.
    pub const fn id(self) -> ClusterId {
        ClusterId(match self {
            Kind::AnalogInput => 0x000c,
            Kind::AnalogOutput => 0x000d,
            Kind::AnalogValue => 0x000e,
            Kind::BinaryInput => 0x000f,
            Kind::BinaryOutput => 0x0010,
            Kind::BinaryValue => 0x0011,
            Kind::MultistateInput => 0x0012,
            Kind::MultistateOutput => 0x0013,
            Kind::MultistateValue => 0x0014,
        })
    }

    /// The kind of `cluster`, when it is one of the nine.
    pub const fn of(cluster: ClusterId) -> Option<Kind> {
        Some(match cluster.0 {
            0x000c => Kind::AnalogInput,
            0x000d => Kind::AnalogOutput,
            0x000e => Kind::AnalogValue,
            0x000f => Kind::BinaryInput,
            0x0010 => Kind::BinaryOutput,
            0x0011 => Kind::BinaryValue,
            0x0012 => Kind::MultistateInput,
            0x0013 => Kind::MultistateOutput,
            0x0014 => Kind::MultistateValue,
            _ => return None,
        })
    }

    /// An input cluster (a sensor).
    pub const fn is_input(self) -> bool {
        matches!(
            self,
            Kind::AnalogInput | Kind::BinaryInput | Kind::MultistateInput
        )
    }

    /// An analog cluster (`PresentValue` single precision).
    pub const fn is_analog(self) -> bool {
        matches!(
            self,
            Kind::AnalogInput | Kind::AnalogOutput | Kind::AnalogValue
        )
    }

    /// A binary cluster (`PresentValue` boolean).
    pub const fn is_binary(self) -> bool {
        matches!(
            self,
            Kind::BinaryInput | Kind::BinaryOutput | Kind::BinaryValue
        )
    }

    /// The `PresentValue` data type.
    pub const fn value_type(self) -> DataType {
        if self.is_analog() {
            DataType::Single
        } else if self.is_binary() {
            DataType::Bool
        } else {
            DataType::Uint(2)
        }
    }

    /// Cluster definition.
    pub const fn def(self) -> ClusterDef {
        ClusterDef {
            id: self.id(),
            revision: 1,
            received: &[],
            generated: &[],
        }
    }
}

/// A `PresentValue`.
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PresentValue {
    /// Analog.
    Analog(f32),
    /// Binary.
    Binary(bool),
    /// Multistate (1 … `NumberOfStates`).
    Multistate(u16),
}

impl PresentValue {
    fn value(self) -> Value<'static> {
        match self {
            PresentValue::Analog(v) => Value::Single(v),
            PresentValue::Binary(b) => Value::Bool(Some(b)),
            PresentValue::Multistate(s) => Value::Uint {
                width: 2,
                value: u64::from(s),
            },
        }
    }
}

/// Default reporting of `PresentValue` and `StatusFlags`.
pub const REPORTING: DefaultReporting = DefaultReporting {
    min: 1,
    max: 300,
    change: 0,
};

const fn text_ok(v: &Value<'_>) -> bool {
    matches!(v, Value::String { bytes: Some(b), .. } if b.len() <= 16)
}

/// Write guard (§3.14.11): an input's `PresentValue` is writable only
/// while `OutOfService`; a multistate `PresentValue` is within
/// 1…`NumberOfStates` (which is at least 1); `Reliability` is a defined
/// value; texts are at most 16 characters; analog values within the
/// min / max range when both are given.
fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
    match id {
        i if i == PRESENT_VALUE => {
            // Inputs carry no RelinquishDefault: their PresentValue is
            // written over the air only while out of service.
            let is_input = t.value(RELINQUISH_DEFAULT).is_none();
            let out_of_service =
                matches!(t.value(OUT_OF_SERVICE.id), Some(Value::Bool(Some(true))));
            if is_input && !out_of_service {
                return ZclStatus::NotAuthorized;
            }
            match v {
                Value::Uint { value, .. } => {
                    let n = t
                        .value(NUMBER_OF_STATES.id)
                        .and_then(|n| n.as_u64())
                        .unwrap_or(0);
                    if *value == 0 || *value > n {
                        return ZclStatus::InvalidValue;
                    }
                }
                Value::Single(x) => {
                    let min = t.value(MIN_PRESENT_VALUE.id).and_then(single);
                    let max = t.value(MAX_PRESENT_VALUE.id).and_then(single);
                    if let (Some(lo), Some(hi)) = (min, max)
                        && !lo.is_nan()
                        && !hi.is_nan()
                        && (*x < lo || *x > hi)
                    {
                        return ZclStatus::InvalidValue;
                    }
                }
                _ => {}
            }
            ZclStatus::Success
        }
        i if i == NUMBER_OF_STATES.id => {
            if v.as_u64().is_some_and(|n| n >= 1) {
                ZclStatus::Success
            } else {
                ZclStatus::InvalidValue
            }
        }
        i if i == RELIABILITY.id => {
            if v.as_u64()
                .is_some_and(|r| r <= u64::from(reliability::CONFIGURATION_ERROR))
            {
                ZclStatus::Success
            } else {
                ZclStatus::InvalidValue
            }
        }
        i if i == DESCRIPTION.id || i == ACTIVE_TEXT.id || i == INACTIVE_TEXT.id => {
            if text_ok(v) {
                ZclStatus::Success
            } else {
                ZclStatus::InvalidValue
            }
        }
        _ => ZclStatus::Success,
    }
}

fn single(v: Value<'_>) -> Option<f32> {
    match v {
        Value::Single(x) => Some(x),
        _ => None,
    }
}

/// Refreshes `StatusFlags` from `Reliability` and `OutOfService`
/// (§3.14.11.3), keeping the In Alarm and Overridden bits.
pub fn refresh_status<const A: usize>(c: &mut ClusterInstance<A>) -> u8 {
    let kept =
        c.u8(STATUS_FLAGS.id).unwrap_or(0) & (status_flags::IN_ALARM | status_flags::OVERRIDDEN);
    let fault = c
        .u8(RELIABILITY.id)
        .is_some_and(|r| r != reliability::NO_FAULT_DETECTED);
    let out = c.bool(OUT_OF_SERVICE.id);
    let flags = kept
        | if fault { status_flags::FAULT } else { 0 }
        | if out { status_flags::OUT_OF_SERVICE } else { 0 };
    c.set(
        STATUS_FLAGS.id,
        &Value::Bits {
            width: 1,
            bits: u64::from(flags),
        },
    );
    flags
}

fn after_write<const A: usize>(c: &mut ClusterInstance<A>, id: AttributeId) {
    if id == RELIABILITY.id || id == OUT_OF_SERVICE.id {
        refresh_status(c);
    }
}

/// Builds a server of `kind`: `OutOfService`, `PresentValue` (reported;
/// `initial`), `StatusFlags` (reported), `Reliability`, `Description`
/// and, by kind, `EngineeringUnits` (`units`) with the min / max /
/// resolution range for analog clusters, `Polarity` and the active /
/// inactive texts for binary clusters, `NumberOfStates` (`states`) for
/// multistate clusters; output and value clusters get
/// `RelinquishDefault`.
pub fn server<const A: usize>(
    kind: Kind,
    initial: PresentValue,
    units: u16,
    states: u16,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let matches = matches!(
        (kind.is_analog(), kind.is_binary(), initial),
        (true, false, PresentValue::Analog(_))
            | (false, true, PresentValue::Binary(_))
            | (false, false, PresentValue::Multistate(_))
    );
    if !matches {
        return Err(ZclStatus::InvalidDataType);
    }
    if let PresentValue::Multistate(s) = initial
        && (states == 0 || s == 0 || s > states)
    {
        return Err(ZclStatus::InvalidValue);
    }
    let mut c = ClusterInstance::new(kind.def(), Role::Server);
    let empty = Value::String {
        ty: DataType::CharString,
        bytes: Some(&[]),
    };
    c.add_attribute(DESCRIPTION, &empty)?;
    c.add_attribute(OUT_OF_SERVICE, &Value::Bool(Some(false)))?;
    // Every kind allows network writes of PresentValue in principle; the
    // guard limits inputs to out-of-service writes.
    c.add_reported_attribute(
        AttributeDef::new(PRESENT_VALUE.0, kind.value_type(), Access::RW_REPORT),
        &initial.value(),
        REPORTING,
    )?;
    c.add_attribute(RELIABILITY, &Value::Enum8(reliability::NO_FAULT_DETECTED))?;
    c.add_reported_attribute(STATUS_FLAGS, &Value::Bits { width: 1, bits: 0 }, REPORTING)?;
    if kind.is_analog() {
        c.add_attribute(MIN_PRESENT_VALUE, &Value::Single(f32::NAN))?;
        c.add_attribute(MAX_PRESENT_VALUE, &Value::Single(f32::NAN))?;
        c.add_attribute(RESOLUTION, &Value::Single(f32::NAN))?;
        c.add_attribute(ENGINEERING_UNITS, &Value::Enum16(units))?;
    } else if kind.is_binary() {
        c.add_attribute(ACTIVE_TEXT, &empty)?;
        c.add_attribute(INACTIVE_TEXT, &empty)?;
        c.add_attribute(POLARITY, &Value::Enum8(0))?;
    } else {
        c.add_attribute(
            NUMBER_OF_STATES,
            &Value::Uint {
                width: 2,
                value: u64::from(states),
            },
        )?;
    }
    if !kind.is_input() {
        c.add_attribute(
            AttributeDef::new(RELINQUISH_DEFAULT.0, kind.value_type(), Access::RW),
            &initial.value(),
        )?;
    }
    if matches!(kind, Kind::BinaryOutput | Kind::BinaryValue) {
        c.add_attribute(
            MINIMUM_OFF_TIME,
            &Value::Uint {
                width: 4,
                value: 0xffff_ffff,
            },
        )?;
        c.add_attribute(
            MINIMUM_ON_TIME,
            &Value::Uint {
                width: 4,
                value: 0xffff_ffff,
            },
        )?;
    }
    c.write_guard = Some(guard::<A>);
    c.after_write = Some(after_write::<A>);
    Ok(c)
}

/// Builds a client instance of `kind`.
pub fn client<const A: usize>(kind: Kind) -> ClusterInstance<A> {
    ClusterInstance::new(kind.def().mirrored(), Role::Client)
}

/// The kind of a server instance.
pub fn kind_of<const A: usize>(c: &ClusterInstance<A>) -> Option<Kind> {
    Kind::of(c.def.id)
}

/// Sets `PresentValue` from the physical input / the application
/// (§3.14.11.1: an input out of service keeps its value; returns
/// `false` then, or on a type mismatch or an out-of-range multistate).
pub fn set_present_value<const A: usize>(c: &mut ClusterInstance<A>, value: PresentValue) -> bool {
    let Some(kind) = kind_of(c) else {
        return false;
    };
    if kind.is_input() && c.bool(OUT_OF_SERVICE.id) {
        return false;
    }
    if value.value().data_type() != kind.value_type() {
        return false;
    }
    if let PresentValue::Multistate(s) = value {
        let n = c.u16(NUMBER_OF_STATES.id).unwrap_or(0);
        if s == 0 || s > n {
            return false;
        }
    }
    c.set(PRESENT_VALUE, &value.value())
}

/// The `PresentValue`.
pub fn present_value<const A: usize>(c: &ClusterInstance<A>) -> Option<PresentValue> {
    match c.attributes.value(PRESENT_VALUE)? {
        Value::Single(x) => Some(PresentValue::Analog(x)),
        Value::Bool(Some(b)) => Some(PresentValue::Binary(b)),
        Value::Uint { value, .. } => Some(PresentValue::Multistate(u16::try_from(value).ok()?)),
        _ => None,
    }
}

/// Sets `Reliability` and refreshes the Fault flag.
pub fn set_reliability<const A: usize>(c: &mut ClusterInstance<A>, reliability: u8) -> u8 {
    c.set(RELIABILITY.id, &Value::Enum8(reliability));
    refresh_status(c)
}

/// Sets the Overridden flag (a local override of the point).
pub fn set_overridden<const A: usize>(c: &mut ClusterInstance<A>, overridden: bool) -> u8 {
    let mut flags = c.u8(STATUS_FLAGS.id).unwrap_or(0) & !status_flags::OVERRIDDEN;
    if overridden {
        flags |= status_flags::OVERRIDDEN;
    }
    c.set(
        STATUS_FLAGS.id,
        &Value::Bits {
            width: 1,
            bits: u64::from(flags),
        },
    );
    refresh_status(c)
}

/// Sets the analog range and resolution of an analog server.
pub fn set_analog_range<const A: usize>(
    c: &mut ClusterInstance<A>,
    min: f32,
    max: f32,
    resolution: f32,
) -> bool {
    if !kind_of(c).is_some_and(Kind::is_analog) || min > max {
        return false;
    }
    c.set(MIN_PRESENT_VALUE.id, &Value::Single(min));
    c.set(MAX_PRESENT_VALUE.id, &Value::Single(max));
    c.set(RESOLUTION.id, &Value::Single(resolution));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write<const A: usize>(
        c: &mut ClusterInstance<A>,
        id: AttributeId,
        v: &Value<'_>,
    ) -> ZclStatus {
        let g = c.write_guard.unwrap();
        let status = g(&c.attributes, id, v);
        if status.is_success() {
            c.set(id, v);
            if let Some(h) = c.after_write {
                h(c, id);
            }
        }
        status
    }

    #[test]
    fn analog_input_is_writable_out_of_service_and_flags_follow() {
        let mut c: ClusterInstance<16> =
            server(Kind::AnalogInput, PresentValue::Analog(0.0), 62, 0).unwrap();
        assert!(server::<16>(Kind::AnalogInput, PresentValue::Binary(true), 0, 0).is_err());
        assert_eq!(c.def.id, ClusterId(0x000c));
        assert_eq!(c.u16(ENGINEERING_UNITS.id), Some(62));
        assert!(c.attributes.get(RELINQUISH_DEFAULT, None).is_none());
        // In service: the physical reading updates the value, a network
        // write is refused.
        assert!(set_present_value(&mut c, PresentValue::Analog(21.5)));
        assert_eq!(present_value(&c), Some(PresentValue::Analog(21.5)));
        assert_eq!(
            write(&mut c, PRESENT_VALUE, &Value::Single(1.0)),
            ZclStatus::NotAuthorized
        );
        // Out of service: the flag follows, the network may write and
        // the physical reading is ignored.
        assert_eq!(
            write(&mut c, OUT_OF_SERVICE.id, &Value::Bool(Some(true))),
            ZclStatus::Success
        );
        assert_eq!(c.u8(STATUS_FLAGS.id), Some(status_flags::OUT_OF_SERVICE));
        assert_eq!(
            write(&mut c, PRESENT_VALUE, &Value::Single(1.0)),
            ZclStatus::Success
        );
        assert!(!set_present_value(&mut c, PresentValue::Analog(30.0)));
        assert_eq!(present_value(&c), Some(PresentValue::Analog(1.0)));
        // A range limits network writes; reliability sets the fault bit.
        assert!(set_analog_range(&mut c, -10.0, 50.0, 0.5));
        assert_eq!(
            write(&mut c, PRESENT_VALUE, &Value::Single(60.0)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            write(
                &mut c,
                RELIABILITY.id,
                &Value::Enum8(reliability::OVER_RANGE)
            ),
            ZclStatus::Success
        );
        assert_eq!(
            c.u8(STATUS_FLAGS.id),
            Some(status_flags::OUT_OF_SERVICE | status_flags::FAULT)
        );
        assert_eq!(
            write(&mut c, RELIABILITY.id, &Value::Enum8(11)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            set_reliability(&mut c, reliability::NO_FAULT_DETECTED),
            status_flags::OUT_OF_SERVICE
        );
        assert_eq!(
            set_overridden(&mut c, true),
            status_flags::OUT_OF_SERVICE | status_flags::OVERRIDDEN
        );
        let long = [b'd'; 17];
        assert_eq!(
            write(
                &mut c,
                DESCRIPTION.id,
                &Value::String {
                    ty: DataType::CharString,
                    bytes: Some(&long)
                }
            ),
            ZclStatus::InvalidValue
        );
    }

    #[test]
    fn binary_output_and_multistate_value() {
        let mut b: ClusterInstance<16> =
            server(Kind::BinaryOutput, PresentValue::Binary(false), 0, 0).unwrap();
        assert!(b.attributes.get(MINIMUM_ON_TIME.id, None).is_some());
        assert!(b.attributes.get(RELINQUISH_DEFAULT, None).is_some());
        assert_eq!(b.u8(POLARITY.id), Some(0));
        // An output's PresentValue is written over the air in service.
        assert_eq!(
            write(&mut b, PRESENT_VALUE, &Value::Bool(Some(true))),
            ZclStatus::Success
        );
        assert_eq!(present_value(&b), Some(PresentValue::Binary(true)));
        assert!(!set_present_value(&mut b, PresentValue::Analog(1.0)));

        let mut m: ClusterInstance<16> =
            server(Kind::MultistateValue, PresentValue::Multistate(1), 0, 3).unwrap();
        assert!(server::<16>(Kind::MultistateValue, PresentValue::Multistate(4), 0, 3).is_err());
        assert_eq!(
            write(&mut m, PRESENT_VALUE, &Value::Uint { width: 2, value: 4 }),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            write(&mut m, PRESENT_VALUE, &Value::Uint { width: 2, value: 3 }),
            ZclStatus::Success
        );
        assert!(!set_present_value(&mut m, PresentValue::Multistate(0)));
        assert!(set_present_value(&mut m, PresentValue::Multistate(2)));
        assert_eq!(present_value(&m), Some(PresentValue::Multistate(2)));
        assert_eq!(
            write(
                &mut m,
                NUMBER_OF_STATES.id,
                &Value::Uint { width: 2, value: 0 }
            ),
            ZclStatus::InvalidValue
        );
        assert_eq!(Kind::of(ClusterId(0x0013)), Some(Kind::MultistateOutput));
        assert_eq!(Kind::of(ClusterId(0x0015)), None);
        let i: ClusterInstance<16> =
            server(Kind::MultistateInput, PresentValue::Multistate(1), 0, 2).unwrap();
        assert!(i.attributes.get(RELINQUISH_DEFAULT, None).is_none());
    }
}
