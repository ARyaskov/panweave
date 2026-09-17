//! Power Configuration cluster (ZCL8 §3.3): the mains and battery
//! information / settings attributes, the alarm masks and codes, and the
//! threshold evaluation that turns readings into `BatteryAlarmState`
//! bits and Alarms-cluster codes (§3.3.2.2.4.6–§3.3.2.2.4.9).

use panweave_types::{AttributeId, ClusterId};

use crate::attribute::{Access, AttributeDef, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
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
    c.add_attribute(BATTERY_VOLTAGE, &u8v(UNKNOWN))?;
    c.add_reported_attribute(
        BATTERY_PERCENTAGE_REMAINING,
        &u8v(UNKNOWN),
        PERCENTAGE_REPORTING,
    )?;
    c.add_attribute(BATTERY_RATED_VOLTAGE, &u8v(rated_voltage))?;
    c.add_attribute(BATTERY_ALARM_MASK, &Value::Bits { width: 1, bits: 0 })?;
    for t in VOLTAGE_THRESHOLDS.iter().chain(&PERCENTAGE_THRESHOLDS) {
        c.add_attribute(*t, &u8v(0))?;
    }
    c.add_reported_attribute(
        BATTERY_ALARM_STATE,
        &Value::Bits { width: 4, bits: 0 },
        ALARM_STATE_REPORTING,
    )?;
    Ok(c)
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
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
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
    c.set_u8(BATTERY_VOLTAGE.id, voltage.unwrap_or(UNKNOWN));
    c.set_u8(
        BATTERY_PERCENTAGE_REMAINING.id,
        percentage.unwrap_or(UNKNOWN),
    );
    let mask = c.u8(BATTERY_ALARM_MASK.id).unwrap_or(0);
    let previous = c
        .u64(BATTERY_ALARM_STATE.id)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let mut state = previous & BATTERY_ALARM_STATE_MAINS_LOST;
    let mut alarms = BatteryAlarms::new();
    for level in 0..4u8 {
        let vt = c.u8(VOLTAGE_THRESHOLDS[usize::from(level)].id).unwrap_or(0);
        let pt = c
            .u8(PERCENTAGE_THRESHOLDS[usize::from(level)].id)
            .unwrap_or(0);
        let reached = matches!(voltage, Some(v) if vt != 0 && v < vt)
            || matches!(percentage, Some(p) if pt != 0 && p < pt);
        if !reached {
            continue;
        }
        let bit = battery_alarm_state_bit(1, level);
        state |= bit;
        if previous & bit == 0 && mask & (1 << level) != 0 {
            let _ = alarms.push((alarm_code::battery(1, level), bit));
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

/// Mains voltage evaluation: `Some(code)` when the reading is beyond an
/// enabled threshold (the dwell timer of §3.3.2.2.2.2 is the
/// application's: raise the alarm once the condition persisted for
/// `MainsVoltageDwellTripPoint` seconds).
pub fn set_mains_voltage<const A: usize>(c: &mut ClusterInstance<A>, voltage: u16) -> Option<u8> {
    c.set_u16(MAINS_VOLTAGE.id, voltage);
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

        let mut m: ClusterInstance<16> = mains_server().unwrap();
        assert_eq!(set_mains_voltage(&mut m, 1000), None);
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
            set_mains_voltage(&mut m, 1900),
            Some(alarm_code::MAINS_VOLTAGE_TOO_LOW)
        );
        assert_eq!(
            set_mains_voltage(&mut m, 2700),
            Some(alarm_code::MAINS_VOLTAGE_TOO_HIGH)
        );
        assert_eq!(set_mains_voltage(&mut m, 2300), None);
        assert_eq!(alarm_code::battery(2, 3), 0x23);
        assert_eq!(battery_alarm_state_bit(3, 0), 1 << 20);
    }
}
