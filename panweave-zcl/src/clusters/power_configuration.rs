//! Power Configuration cluster (ZCL8 §3.3): the mains and battery
//! information / settings attributes for up to three battery sources,
//! the alarm masks and codes, the threshold evaluation that turns
//! readings into `BatteryAlarmState` bits and Alarms-cluster codes
//! (§3.3.2.2.4.6–§3.3.2.2.4.9) and the mains voltage dwell timer
//! (§3.3.2.2.2.2).

use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId};

use crate::attribute::{Access, AttributeDef, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0001);

// Mains Information (Table 3-18).
/// `MainsVoltage` (uint16, 100 mV).
pub const MAINS_VOLTAGE: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(2), Access::RO);
/// `MainsFrequency` (uint8, half hertz; 0x00 too low, 0xfe too high, 0xff unknown).
pub const MAINS_FREQUENCY: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(1), Access::RO);
// Mains Settings (Table 3-19).
/// `MainsAlarmMask` (map8).
pub const MAINS_ALARM_MASK: AttributeDef =
    AttributeDef::new(0x0010, DataType::Bitmap(1), Access::RW);
/// `MainsVoltageMinThreshold` (uint16, 100 mV; 0xffff disables).
pub const MAINS_VOLTAGE_MIN_THRESHOLD: AttributeDef =
    AttributeDef::new(0x0011, DataType::Uint(2), Access::RW);
/// `MainsVoltageMaxThreshold` (uint16, 100 mV; 0xffff disables).
pub const MAINS_VOLTAGE_MAX_THRESHOLD: AttributeDef =
    AttributeDef::new(0x0012, DataType::Uint(2), Access::RW);
/// `MainsVoltageDwellTripPoint` (uint16 seconds).
pub const MAINS_VOLTAGE_DWELL_TRIP_POINT: AttributeDef =
    AttributeDef::new(0x0013, DataType::Uint(2), Access::RW);
// Battery Information (Table 3-21).
/// `BatteryVoltage` (uint8, 100 mV; 0xff unknown).
pub const BATTERY_VOLTAGE: AttributeDef = AttributeDef::new(0x0020, DataType::Uint(1), Access::RO);
/// `BatteryPercentageRemaining` (uint8, half percent; 0xff unknown; reportable).
pub const BATTERY_PERCENTAGE_REMAINING: AttributeDef =
    AttributeDef::new(0x0021, DataType::Uint(1), Access::RO_REPORT);
// Battery Settings (Table 3-22).
/// `BatteryManufacturer` (string).
pub const BATTERY_MANUFACTURER: AttributeDef =
    AttributeDef::new(0x0030, DataType::CharString, Access::RW);
/// `BatterySize` (enum8).
pub const BATTERY_SIZE: AttributeDef = AttributeDef::new(0x0031, DataType::Enum8, Access::RW);
/// `BatteryAHrRating` (uint16, 10 mAHr).
pub const BATTERY_AHR_RATING: AttributeDef =
    AttributeDef::new(0x0032, DataType::Uint(2), Access::RW);
/// `BatteryQuantity` (uint8).
pub const BATTERY_QUANTITY: AttributeDef = AttributeDef::new(0x0033, DataType::Uint(1), Access::RW);
/// `BatteryRatedVoltage` (uint8, 100 mV).
pub const BATTERY_RATED_VOLTAGE: AttributeDef =
    AttributeDef::new(0x0034, DataType::Uint(1), Access::RW);
/// `BatteryAlarmMask` (map8).
pub const BATTERY_ALARM_MASK: AttributeDef =
    AttributeDef::new(0x0035, DataType::Bitmap(1), Access::RW);
/// `BatteryVoltageMinThreshold` (uint8, 100 mV).
pub const BATTERY_VOLTAGE_MIN_THRESHOLD: AttributeDef =
    AttributeDef::new(0x0036, DataType::Uint(1), Access::RW);
/// `BatteryVoltageThreshold1`.
pub const BATTERY_VOLTAGE_THRESHOLD_1: AttributeDef =
    AttributeDef::new(0x0037, DataType::Uint(1), Access::RW);
/// `BatteryVoltageThreshold2`.
pub const BATTERY_VOLTAGE_THRESHOLD_2: AttributeDef =
    AttributeDef::new(0x0038, DataType::Uint(1), Access::RW);
/// `BatteryVoltageThreshold3`.
pub const BATTERY_VOLTAGE_THRESHOLD_3: AttributeDef =
    AttributeDef::new(0x0039, DataType::Uint(1), Access::RW);
/// `BatteryPercentageMinThreshold` (half percent).
pub const BATTERY_PERCENTAGE_MIN_THRESHOLD: AttributeDef =
    AttributeDef::new(0x003a, DataType::Uint(1), Access::RW);
/// `BatteryPercentageThreshold1`.
pub const BATTERY_PERCENTAGE_THRESHOLD_1: AttributeDef =
    AttributeDef::new(0x003b, DataType::Uint(1), Access::RW);
/// `BatteryPercentageThreshold2`.
pub const BATTERY_PERCENTAGE_THRESHOLD_2: AttributeDef =
    AttributeDef::new(0x003c, DataType::Uint(1), Access::RW);
/// `BatteryPercentageThreshold3`.
pub const BATTERY_PERCENTAGE_THRESHOLD_3: AttributeDef =
    AttributeDef::new(0x003d, DataType::Uint(1), Access::RW);
/// `BatteryAlarmState` (map32, reportable).
pub const BATTERY_ALARM_STATE: AttributeDef =
    AttributeDef::new(0x003e, DataType::Bitmap(4), Access::RO_REPORT);

/// Unknown battery voltage / percentage.
pub const UNKNOWN: u8 = 0xff;
/// Disabled mains threshold.
pub const MAINS_THRESHOLD_DISABLED: u16 = 0xffff;
/// 100 % remaining.
pub const PERCENT_100: u8 = 0xc8;

/// `MainsAlarmMask` bits (Table 3-20).
pub mod mains_alarm {
    /// Mains voltage too low.
    pub const VOLTAGE_TOO_LOW: u8 = 0x01;
    /// Mains voltage too high.
    pub const VOLTAGE_TOO_HIGH: u8 = 0x02;
    /// Mains power supply lost / unavailable.
    pub const POWER_LOST: u8 = 0x04;
}

/// `BatteryAlarmMask` bits (Table 3-24).
pub mod battery_alarm {
    /// Voltage too low to operate the radio (minimum threshold).
    pub const MIN_THRESHOLD: u8 = 0x01;
    /// Battery alarm 1.
    pub const THRESHOLD_1: u8 = 0x02;
    /// Battery alarm 2.
    pub const THRESHOLD_2: u8 = 0x04;
    /// Battery alarm 3.
    pub const THRESHOLD_3: u8 = 0x08;
}

/// Alarm codes (§3.3.2.2.2, Table 3-25).
pub mod alarm_code {
    /// Mains voltage too low.
    pub const MAINS_VOLTAGE_TOO_LOW: u8 = 0x00;
    /// Mains voltage too high.
    pub const MAINS_VOLTAGE_TOO_HIGH: u8 = 0x01;
    /// Mains power lost (device running on battery).
    pub const MAINS_POWER_LOST: u8 = 0x3a;
    /// No alarm.
    pub const NONE: u8 = 0xff;

    /// The code for battery `source` (1–3) reaching threshold `level`
    /// (0 = minimum, 1–3).
    pub const fn battery(source: u8, level: u8) -> u8 {
        (source << 4) | level
    }
}

/// `BatteryAlarmState` bits (§3.3.2.2.4.9): bit `10 · (source − 1) +
/// level`, and bit 30 for mains power lost.
pub const fn battery_alarm_state_bit(source: u8, level: u8) -> u32 {
    1u32 << (10 * (source as u32 - 1) + level as u32)
}
/// The `BatteryAlarmState` bits of one source (levels 0–3).
const fn battery_alarm_state_bits(source: u8) -> u32 {
    0b1111 << (10 * (source as u32 - 1))
}

/// The attribute of battery `source` (1–3) corresponding to the source
/// 1 attribute `base` (§3.3.2.2.3, Table 3-27: sources 2 and 3 repeat
/// the set at 0x0040 and 0x0060).
pub const fn battery_attr(source: u8, base: AttributeDef) -> AttributeDef {
    AttributeDef::new(base.id.0 + 0x20 * (source as u16 - 1), base.ty, base.access)
}
/// `BatteryAlarmState` bit 30: mains power supply lost.
pub const BATTERY_ALARM_STATE_MAINS_LOST: u32 = 1 << 30;

/// Default reporting of `BatteryPercentageRemaining` (every hour or on
/// a 5 % change) and `BatteryAlarmState` (on change).
pub const PERCENTAGE_REPORTING: DefaultReporting = DefaultReporting {
    min: 60,
    max: 3600,
    change: 10,
};
/// Default reporting of `BatteryAlarmState`.
pub const ALARM_STATE_REPORTING: DefaultReporting = DefaultReporting {
    min: 1,
    max: 3600,
    change: 0,
};

/// Cluster definition (attribute-only).
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[],
    generated: &[],
};

/// The battery source 1 threshold attributes, level 0 (minimum) to 3.
pub const VOLTAGE_THRESHOLDS: [AttributeDef; 4] = [
    BATTERY_VOLTAGE_MIN_THRESHOLD,
    BATTERY_VOLTAGE_THRESHOLD_1,
    BATTERY_VOLTAGE_THRESHOLD_2,
    BATTERY_VOLTAGE_THRESHOLD_3,
];
/// The battery source 1 percentage threshold attributes.
pub const PERCENTAGE_THRESHOLDS: [AttributeDef; 4] = [
    BATTERY_PERCENTAGE_MIN_THRESHOLD,
    BATTERY_PERCENTAGE_THRESHOLD_1,
    BATTERY_PERCENTAGE_THRESHOLD_2,
    BATTERY_PERCENTAGE_THRESHOLD_3,
];

fn u8v(v: u8) -> Value<'static> {
    Value::Uint {
        width: 1,
        value: u64::from(v),
    }
}

/// Builds a battery-powered device's server: the battery information
/// set with reporting, the alarm mask, the four voltage and percentage
/// thresholds (all 0 = disabled) and `BatteryAlarmState`.
pub fn battery_server<const A: usize>(rated_voltage: u8) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    add_battery_source(&mut c, 1, rated_voltage)?;
    c.add_reported_attribute(
        BATTERY_ALARM_STATE,
        &Value::Bits { width: 4, bits: 0 },
        ALARM_STATE_REPORTING,
    )?;
    Ok(c)
}

/// Adds the information and settings set of battery `source` (1–3,
/// Table 3-27) to a server: voltage, reported percentage, rated
/// voltage, alarm mask and the eight thresholds (0 = disabled).
pub fn add_battery_source<const A: usize>(
    c: &mut ClusterInstance<A>,
    source: u8,
    rated_voltage: u8,
) -> Result<(), ZclStatus> {
    if !(1..=3).contains(&source) {
        return Err(ZclStatus::InvalidValue);
    }
    c.add_attribute(battery_attr(source, BATTERY_VOLTAGE), &u8v(UNKNOWN))?;
    c.add_reported_attribute(
        battery_attr(source, BATTERY_PERCENTAGE_REMAINING),
        &u8v(UNKNOWN),
        PERCENTAGE_REPORTING,
    )?;
    c.add_attribute(
        battery_attr(source, BATTERY_RATED_VOLTAGE),
        &u8v(rated_voltage),
    )?;
    c.add_attribute(
        battery_attr(source, BATTERY_ALARM_MASK),
        &Value::Bits { width: 1, bits: 0 },
    )?;
    for t in VOLTAGE_THRESHOLDS.iter().chain(&PERCENTAGE_THRESHOLDS) {
        c.add_attribute(battery_attr(source, *t), &u8v(0))?;
    }
    Ok(())
}

/// Builds a mains-powered device's server: mains information and the
/// mains settings (thresholds disabled).
pub fn mains_server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(MAINS_VOLTAGE, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(MAINS_FREQUENCY, &u8v(UNKNOWN))?;
    c.add_attribute(MAINS_ALARM_MASK, &Value::Bits { width: 1, bits: 0 })?;
    c.add_attribute(
        MAINS_VOLTAGE_MIN_THRESHOLD,
        &Value::Uint {
            width: 2,
            value: u64::from(MAINS_THRESHOLD_DISABLED),
        },
    )?;
    c.add_attribute(
        MAINS_VOLTAGE_MAX_THRESHOLD,
        &Value::Uint {
            width: 2,
            value: u64::from(MAINS_THRESHOLD_DISABLED),
        },
    )?;
    c.add_attribute(
        MAINS_VOLTAGE_DWELL_TRIP_POINT,
        &Value::Uint { width: 2, value: 0 },
    )?;
    c.state = ClusterState::Mains(MainsDwell::default());
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// Alarms to raise after a battery reading, as `(code, alarm-state bit)`.
pub type BatteryAlarms = heapless::Vec<(u8, u32), 4>;

/// Records a battery reading for source 1 (`voltage` in 100 mV,
/// `percentage` in half percent, either `None` when unknown), updates
/// `BatteryAlarmState` from the thresholds and returns the alarm codes
/// enabled by `BatteryAlarmMask` that newly became active
/// (§3.3.2.2.4.7–§3.3.2.2.4.9). A threshold of 0 is disabled.
pub fn set_battery<const A: usize>(
    c: &mut ClusterInstance<A>,
    voltage: Option<u8>,
    percentage: Option<u8>,
) -> BatteryAlarms {
    set_battery_source(c, 1, voltage, percentage)
}

/// [`set_battery`] for battery `source` (1–3): its own thresholds and
/// mask, its own ten `BatteryAlarmState` bits and alarm codes
/// `0x{source}{level}`; the other sources' bits are left alone.
pub fn set_battery_source<const A: usize>(
    c: &mut ClusterInstance<A>,
    source: u8,
    voltage: Option<u8>,
    percentage: Option<u8>,
) -> BatteryAlarms {
    let source = source.clamp(1, 3);
    c.set_u8(
        battery_attr(source, BATTERY_VOLTAGE).id,
        voltage.unwrap_or(UNKNOWN),
    );
    c.set_u8(
        battery_attr(source, BATTERY_PERCENTAGE_REMAINING).id,
        percentage.unwrap_or(UNKNOWN),
    );
    let mask = c
        .u8(battery_attr(source, BATTERY_ALARM_MASK).id)
        .unwrap_or(0);
    let previous = c
        .u64(BATTERY_ALARM_STATE.id)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let mut state = previous & !battery_alarm_state_bits(source);
    let mut alarms = BatteryAlarms::new();
    for level in 0..4u8 {
        let vt = c
            .u8(battery_attr(source, VOLTAGE_THRESHOLDS[usize::from(level)]).id)
            .unwrap_or(0);
        let pt = c
            .u8(battery_attr(source, PERCENTAGE_THRESHOLDS[usize::from(level)]).id)
            .unwrap_or(0);
        let reached = matches!(voltage, Some(v) if vt != 0 && v < vt)
            || matches!(percentage, Some(p) if pt != 0 && p < pt);
        if !reached {
            continue;
        }
        let bit = battery_alarm_state_bit(source, level);
        state |= bit;
        if previous & bit == 0 && mask & (1 << level) != 0 {
            let _ = alarms.push((alarm_code::battery(source, level), bit));
        }
    }
    c.set(
        BATTERY_ALARM_STATE.id,
        &Value::Bits {
            width: 4,
            bits: u64::from(state),
        },
    );
    alarms
}

/// Records whether mains power is available (a device that also has a
/// battery); returns the alarm code to raise when it was just lost and
/// the mask enables it.
pub fn set_mains_available<const A: usize>(
    c: &mut ClusterInstance<A>,
    available: bool,
) -> Option<u8> {
    let previous = c
        .u64(BATTERY_ALARM_STATE.id)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let state = if available {
        previous & !BATTERY_ALARM_STATE_MAINS_LOST
    } else {
        previous | BATTERY_ALARM_STATE_MAINS_LOST
    };
    if state != previous {
        c.set(
            BATTERY_ALARM_STATE.id,
            &Value::Bits {
                width: 4,
                bits: u64::from(state),
            },
        );
    }
    let mask = c.u8(MAINS_ALARM_MASK.id).unwrap_or(0);
    (!available
        && previous & BATTERY_ALARM_STATE_MAINS_LOST == 0
        && mask & mains_alarm::POWER_LOST != 0)
        .then_some(alarm_code::MAINS_POWER_LOST)
}

/// The mains voltage dwell timer of a mains server (§3.3.2.2.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MainsDwell {
    /// The alarm the current reading calls for and when the reading
    /// has dwelt beyond the threshold long enough to raise it.
    pub pending: Option<(u8, Instant)>,
    /// The pending alarm was raised; nothing more until the voltage
    /// comes back within the thresholds.
    pub raised: bool,
}

fn dwell<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut MainsDwell> {
    match &mut c.state {
        ClusterState::Mains(d) => Some(d),
        _ => None,
    }
}

/// The alarm a mains reading calls for under the enabled thresholds
/// and mask, before the dwell.
fn mains_condition<const A: usize>(c: &ClusterInstance<A>, voltage: u16) -> Option<u8> {
    let mask = c.u8(MAINS_ALARM_MASK.id).unwrap_or(0);
    let min = c
        .u16(MAINS_VOLTAGE_MIN_THRESHOLD.id)
        .unwrap_or(MAINS_THRESHOLD_DISABLED);
    let max = c
        .u16(MAINS_VOLTAGE_MAX_THRESHOLD.id)
        .unwrap_or(MAINS_THRESHOLD_DISABLED);
    if min != MAINS_THRESHOLD_DISABLED && voltage < min && mask & mains_alarm::VOLTAGE_TOO_LOW != 0
    {
        Some(alarm_code::MAINS_VOLTAGE_TOO_LOW)
    } else if max != MAINS_THRESHOLD_DISABLED
        && voltage > max
        && mask & mains_alarm::VOLTAGE_TOO_HIGH != 0
    {
        Some(alarm_code::MAINS_VOLTAGE_TOO_HIGH)
    } else {
        None
    }
}

/// Records a mains voltage reading (§3.3.2.2.2.2): `Some(code)` when the
/// reading has been beyond an enabled threshold for
/// `MainsVoltageDwellTripPoint` seconds (at once when that is 0). A
/// condition that starts now arms the dwell timer instead; the layer
/// raises the alarm from [`mains_tick`] when it expires without a
/// further reading. Each excursion is reported once.
pub fn set_mains_voltage<const A: usize>(
    c: &mut ClusterInstance<A>,
    voltage: u16,
    now: Instant,
) -> Option<u8> {
    c.set_u16(MAINS_VOLTAGE.id, voltage);
    let condition = mains_condition(c, voltage);
    let dwell_secs = c.u16(MAINS_VOLTAGE_DWELL_TRIP_POINT.id).unwrap_or(0);
    let Some(d) = dwell(c) else {
        // A server without the dwell state (built by hand): immediate.
        return condition;
    };
    match condition {
        None => {
            *d = MainsDwell::default();
            c.tick = None;
            None
        }
        Some(code) => {
            match d.pending {
                Some((pending, _)) if pending == code => {}
                _ => {
                    d.pending = Some((code, now + Duration::from_secs(u64::from(dwell_secs))));
                    d.raised = false;
                }
            }
            mains_tick(c, now)
        }
    }
}

/// Raises the pending mains alarm once its dwell has elapsed (`None`
/// otherwise); arms the cluster tick for the dwell's end.
pub fn mains_tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<u8> {
    let d = dwell(c)?;
    let (code, due) = d.pending?;
    if d.raised {
        c.tick = None;
        return None;
    }
    if now.has_reached(due) {
        d.raised = true;
        c.tick = None;
        Some(code)
    } else {
        c.tick = Some(due);
        None
    }
}

/// The `MainsVoltageDwellTripPoint` attribute identifier.
pub const fn dwell_trip_point_id() -> AttributeId {
    MAINS_VOLTAGE_DWELL_TRIP_POINT.id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn battery_thresholds_drive_alarm_state_and_codes() {
        let mut c: ClusterInstance<16> = battery_server(30).unwrap();
        c.set_u8(BATTERY_VOLTAGE_MIN_THRESHOLD.id, 20);
        c.set_u8(BATTERY_VOLTAGE_THRESHOLD_1.id, 22);
        c.set_u8(BATTERY_VOLTAGE_THRESHOLD_2.id, 24);
        c.set_u8(BATTERY_PERCENTAGE_THRESHOLD_3.id, 40);
        c.set(
            BATTERY_ALARM_MASK.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(
                    battery_alarm::MIN_THRESHOLD
                        | battery_alarm::THRESHOLD_1
                        | battery_alarm::THRESHOLD_3,
                ),
            },
        );
        assert!(set_battery(&mut c, Some(29), Some(180)).is_empty());
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some(0));
        // Below threshold 2 and 1: state bits 1 and 2; only alarm 1 is
        // masked in.
        let a = set_battery(&mut c, Some(21), Some(100));
        assert_eq!(a.as_slice(), &[(0x11, 1 << 1)]);
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some(0b110));
        // Unchanged: no new alarms.
        assert!(set_battery(&mut c, Some(21), Some(100)).is_empty());
        // Below the minimum and the percentage threshold 3.
        let a = set_battery(&mut c, Some(19), Some(30));
        assert_eq!(a.as_slice(), &[(0x10, 1), (0x13, 1 << 3)]);
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some(0b1111));
        // Recovery clears the bits.
        assert!(set_battery(&mut c, Some(29), None).is_empty());
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some(0));
        assert_eq!(c.u8(BATTERY_PERCENTAGE_REMAINING.id), Some(UNKNOWN));
        // Mains lost with the mask set.
        c.add_attribute(
            MAINS_ALARM_MASK,
            &Value::Bits {
                width: 1,
                bits: u64::from(mains_alarm::POWER_LOST),
            },
        )
        .unwrap();
        assert_eq!(
            set_mains_available(&mut c, false),
            Some(alarm_code::MAINS_POWER_LOST)
        );
        assert_eq!(set_mains_available(&mut c, false), None);
        assert_eq!(
            c.u64(BATTERY_ALARM_STATE.id),
            Some(u64::from(BATTERY_ALARM_STATE_MAINS_LOST))
        );
        assert_eq!(set_mains_available(&mut c, true), None);
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some(0));

        let t0 = Instant::from_millis(0);
        let mut m: ClusterInstance<16> = mains_server().unwrap();
        assert_eq!(set_mains_voltage(&mut m, 1000, t0), None);
        m.set_u16(MAINS_VOLTAGE_MIN_THRESHOLD.id, 2000);
        m.set_u16(MAINS_VOLTAGE_MAX_THRESHOLD.id, 2600);
        m.set(
            MAINS_ALARM_MASK.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(mains_alarm::VOLTAGE_TOO_LOW | mains_alarm::VOLTAGE_TOO_HIGH),
            },
        );
        assert_eq!(
            set_mains_voltage(&mut m, 1900, t0),
            Some(alarm_code::MAINS_VOLTAGE_TOO_LOW)
        );
        // Reported once per excursion.
        assert_eq!(set_mains_voltage(&mut m, 1800, t0), None);
        assert_eq!(
            set_mains_voltage(&mut m, 2700, t0),
            Some(alarm_code::MAINS_VOLTAGE_TOO_HIGH)
        );
        assert_eq!(set_mains_voltage(&mut m, 2300, t0), None);
        assert_eq!(alarm_code::battery(2, 3), 0x23);
        assert_eq!(battery_alarm_state_bit(3, 0), 1 << 20);
    }

    #[test]
    fn mains_dwell_delays_the_alarm() {
        let t0 = Instant::from_millis(0);
        let mut m: ClusterInstance<16> = mains_server().unwrap();
        m.set_u16(MAINS_VOLTAGE_MIN_THRESHOLD.id, 2000);
        m.set_u16(MAINS_VOLTAGE_DWELL_TRIP_POINT.id, 5);
        m.set(
            MAINS_ALARM_MASK.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(mains_alarm::VOLTAGE_TOO_LOW),
            },
        );
        // Below the threshold: the timer is armed, nothing raised yet.
        assert_eq!(set_mains_voltage(&mut m, 1900, t0), None);
        assert_eq!(m.tick, Some(t0 + Duration::from_secs(5)));
        assert_eq!(mains_tick(&mut m, t0 + Duration::from_secs(4)), None);
        // A recovery in between disarms it.
        assert_eq!(
            set_mains_voltage(&mut m, 2100, t0 + Duration::from_secs(2)),
            None
        );
        assert_eq!(m.tick, None);
        assert_eq!(mains_tick(&mut m, t0 + Duration::from_secs(6)), None);
        // Persisting for the dwell raises the alarm from the tick, once.
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(set_mains_voltage(&mut m, 1900, t1), None);
        assert_eq!(
            set_mains_voltage(&mut m, 1950, t1 + Duration::from_secs(3)),
            None
        );
        assert_eq!(
            mains_tick(&mut m, t1 + Duration::from_secs(5)),
            Some(alarm_code::MAINS_VOLTAGE_TOO_LOW)
        );
        assert_eq!(m.tick, None);
        assert_eq!(
            set_mains_voltage(&mut m, 1900, t1 + Duration::from_secs(9)),
            None
        );
        assert_eq!(mains_tick(&mut m, t1 + Duration::from_secs(20)), None);
        // A reading arriving after the dwell raises it directly.
        set_mains_voltage(&mut m, 2100, t1 + Duration::from_secs(20));
        let t2 = t1 + Duration::from_secs(30);
        assert_eq!(set_mains_voltage(&mut m, 1900, t2), None);
        assert_eq!(
            set_mains_voltage(&mut m, 1900, t2 + Duration::from_secs(5)),
            Some(alarm_code::MAINS_VOLTAGE_TOO_LOW)
        );
    }

    #[test]
    fn battery_sources_two_and_three_have_their_own_sets() {
        let mut c: ClusterInstance<48> = battery_server(30).unwrap();
        add_battery_source(&mut c, 2, 36).unwrap();
        add_battery_source(&mut c, 3, 90).unwrap();
        assert!(add_battery_source(&mut c, 4, 1).is_err());
        assert_eq!(battery_attr(2, BATTERY_VOLTAGE).id.0, 0x0040);
        assert_eq!(battery_attr(3, BATTERY_PERCENTAGE_THRESHOLD_3).id.0, 0x007d);
        assert_eq!(c.u8(AttributeId(0x0074)), Some(90));
        // Source 2 below its minimum: bit 10 and code 0x20; source 1 and
        // 3 untouched, and a source 3 reading keeps source 2's bit.
        c.set_u8(battery_attr(2, BATTERY_VOLTAGE_MIN_THRESHOLD).id, 30);
        c.set(
            battery_attr(2, BATTERY_ALARM_MASK).id,
            &Value::Bits {
                width: 1,
                bits: u64::from(battery_alarm::MIN_THRESHOLD),
            },
        );
        let a = set_battery_source(&mut c, 2, Some(25), None);
        assert_eq!(a.as_slice(), &[(0x20, 1 << 10)]);
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some(1 << 10));
        assert_eq!(c.u8(battery_attr(2, BATTERY_VOLTAGE).id), Some(25));
        assert_eq!(c.u8(BATTERY_VOLTAGE.id), Some(UNKNOWN));
        c.set_u8(battery_attr(3, BATTERY_PERCENTAGE_THRESHOLD_2).id, 50);
        assert!(set_battery_source(&mut c, 3, None, Some(20)).is_empty());
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some((1 << 10) | (1 << 22)));
        assert!(set_battery_source(&mut c, 2, Some(31), None).is_empty());
        assert_eq!(c.u64(BATTERY_ALARM_STATE.id), Some(1 << 22));
    }
}
