//! Electrical Measurement cluster (ZCL8 §4.9): `MeasurementType`, the
//! DC and single-phase AC measurement sets with their formatting
//! (multiplier / divisor) attributes, the min / max tracking of the
//! readings, the DC and AC overload alarm masks and thresholds, and
//! the Get Profile Info / Get Measurement Profile codecs. The
//! application feeds readings with [`set_dc`] / [`set_ac`], which return
//! the alarms to raise through the Alarms cluster (§4.9.2.1). The
//! measurement profile itself (interval history) is the application's;
//! the server answers Get Profile Info with no profiles and Get
//! Measurement Profile with "attribute profile not supported" unless the
//! application handles the indication.

use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0b04);

/// `MeasurementType` (map32, Table 4-30).
pub const MEASUREMENT_TYPE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Bitmap(4), Access::RO);

/// `MeasurementType` bits (Table 4-30).
pub mod measurement_type {
    /// Active measurement (AC).
    pub const ACTIVE: u32 = 1 << 0;
    /// Reactive measurement (AC).
    pub const REACTIVE: u32 = 1 << 1;
    /// Apparent measurement (AC).
    pub const APPARENT: u32 = 1 << 2;
    /// Phase A.
    pub const PHASE_A: u32 = 1 << 3;
    /// Phase B.
    pub const PHASE_B: u32 = 1 << 4;
    /// Phase C.
    pub const PHASE_C: u32 = 1 << 5;
    /// DC measurement.
    pub const DC: u32 = 1 << 6;
    /// Harmonics.
    pub const HARMONICS: u32 = 1 << 7;
    /// Power quality.
    pub const POWER_QUALITY: u32 = 1 << 8;
}

/// DC measurement set (Table 4-31), all int16 with 0x8000 unknown.
pub mod dc {
    use super::*;

    /// `DCVoltage` (V, reportable).
    pub const VOLTAGE: AttributeDef =
        AttributeDef::new(0x0100, DataType::Int(2), Access::RO_REPORT);
    /// `DCVoltageMin`.
    pub const VOLTAGE_MIN: AttributeDef = AttributeDef::new(0x0101, DataType::Int(2), Access::RO);
    /// `DCVoltageMax`.
    pub const VOLTAGE_MAX: AttributeDef = AttributeDef::new(0x0102, DataType::Int(2), Access::RO);
    /// `DCCurrent` (A, reportable).
    pub const CURRENT: AttributeDef =
        AttributeDef::new(0x0103, DataType::Int(2), Access::RO_REPORT);
    /// `DCCurrentMin`.
    pub const CURRENT_MIN: AttributeDef = AttributeDef::new(0x0104, DataType::Int(2), Access::RO);
    /// `DCCurrentMax`.
    pub const CURRENT_MAX: AttributeDef = AttributeDef::new(0x0105, DataType::Int(2), Access::RO);
    /// `DCPower` (W, reportable).
    pub const POWER: AttributeDef = AttributeDef::new(0x0106, DataType::Int(2), Access::RO_REPORT);
    /// `DCPowerMin`.
    pub const POWER_MIN: AttributeDef = AttributeDef::new(0x0107, DataType::Int(2), Access::RO);
    /// `DCPowerMax`.
    pub const POWER_MAX: AttributeDef = AttributeDef::new(0x0108, DataType::Int(2), Access::RO);
    /// `DCVoltageMultiplier` (Table 4-32).
    pub const VOLTAGE_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0200, DataType::Uint(2), Access::RO_REPORT);
    /// `DCVoltageDivisor`.
    pub const VOLTAGE_DIVISOR: AttributeDef =
        AttributeDef::new(0x0201, DataType::Uint(2), Access::RO_REPORT);
    /// `DCCurrentMultiplier`.
    pub const CURRENT_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0202, DataType::Uint(2), Access::RO_REPORT);
    /// `DCCurrentDivisor`.
    pub const CURRENT_DIVISOR: AttributeDef =
        AttributeDef::new(0x0203, DataType::Uint(2), Access::RO_REPORT);
    /// `DCPowerMultiplier`.
    pub const POWER_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0204, DataType::Uint(2), Access::RO_REPORT);
    /// `DCPowerDivisor`.
    pub const POWER_DIVISOR: AttributeDef =
        AttributeDef::new(0x0205, DataType::Uint(2), Access::RO_REPORT);
    /// `DCOverloadAlarmsMask` (map8, Table 4-37).
    pub const OVERLOAD_ALARMS_MASK: AttributeDef =
        AttributeDef::new(0x0700, DataType::Bitmap(1), Access::RW);
    /// `DCVoltageOverload`.
    pub const VOLTAGE_OVERLOAD: AttributeDef =
        AttributeDef::new(0x0701, DataType::Int(2), Access::RO);
    /// `DCCurrentOverload`.
    pub const CURRENT_OVERLOAD: AttributeDef =
        AttributeDef::new(0x0702, DataType::Int(2), Access::RO);

    /// Unknown reading.
    pub const UNKNOWN: i16 = i16::MIN;
    /// Alarm mask bit / alarm code: voltage overload.
    pub const ALARM_VOLTAGE_OVERLOAD: u8 = 0;
    /// Alarm mask bit / alarm code: current overload.
    pub const ALARM_CURRENT_OVERLOAD: u8 = 1;
}

/// AC measurement sets (Tables 4-33 – 4-36, 4-38): the non-phase
/// frequency and the single-phase / phase A readings.
pub mod ac {
    use super::*;

    /// `ACFrequency` (Hz, uint16, 0xffff unknown, reportable).
    pub const FREQUENCY: AttributeDef =
        AttributeDef::new(0x0300, DataType::Uint(2), Access::RO_REPORT);
    /// `ACFrequencyMultiplier` (Table 4-34).
    pub const FREQUENCY_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0400, DataType::Uint(2), Access::RO_REPORT);
    /// `ACFrequencyDivisor`.
    pub const FREQUENCY_DIVISOR: AttributeDef =
        AttributeDef::new(0x0401, DataType::Uint(2), Access::RO_REPORT);
    /// `RMSVoltage` (V, uint16, 0xffff unknown, reportable).
    pub const RMS_VOLTAGE: AttributeDef =
        AttributeDef::new(0x0505, DataType::Uint(2), Access::RO_REPORT);
    /// `RMSVoltageMin`.
    pub const RMS_VOLTAGE_MIN: AttributeDef =
        AttributeDef::new(0x0506, DataType::Uint(2), Access::RO);
    /// `RMSVoltageMax`.
    pub const RMS_VOLTAGE_MAX: AttributeDef =
        AttributeDef::new(0x0507, DataType::Uint(2), Access::RO);
    /// `RMSCurrent` (A, uint16, 0xffff unknown, reportable).
    pub const RMS_CURRENT: AttributeDef =
        AttributeDef::new(0x0508, DataType::Uint(2), Access::RO_REPORT);
    /// `RMSCurrentMin`.
    pub const RMS_CURRENT_MIN: AttributeDef =
        AttributeDef::new(0x0509, DataType::Uint(2), Access::RO);
    /// `RMSCurrentMax`.
    pub const RMS_CURRENT_MAX: AttributeDef =
        AttributeDef::new(0x050a, DataType::Uint(2), Access::RO);
    /// `ActivePower` (W, int16, 0x8000 unknown, reportable).
    pub const ACTIVE_POWER: AttributeDef =
        AttributeDef::new(0x050b, DataType::Int(2), Access::RO_REPORT);
    /// `ActivePowerMin`.
    pub const ACTIVE_POWER_MIN: AttributeDef =
        AttributeDef::new(0x050c, DataType::Int(2), Access::RO);
    /// `ActivePowerMax`.
    pub const ACTIVE_POWER_MAX: AttributeDef =
        AttributeDef::new(0x050d, DataType::Int(2), Access::RO);
    /// `ReactivePower` (VAr, int16, reportable).
    pub const REACTIVE_POWER: AttributeDef =
        AttributeDef::new(0x050e, DataType::Int(2), Access::RO_REPORT);
    /// `ApparentPower` (VA, uint16, reportable).
    pub const APPARENT_POWER: AttributeDef =
        AttributeDef::new(0x050f, DataType::Uint(2), Access::RO_REPORT);
    /// `PowerFactor` (int8, −100..100).
    pub const POWER_FACTOR: AttributeDef = AttributeDef::new(0x0510, DataType::Int(1), Access::RO);
    /// `ACVoltageMultiplier` (Table 4-36).
    pub const VOLTAGE_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0600, DataType::Uint(2), Access::RO_REPORT);
    /// `ACVoltageDivisor`.
    pub const VOLTAGE_DIVISOR: AttributeDef =
        AttributeDef::new(0x0601, DataType::Uint(2), Access::RO_REPORT);
    /// `ACCurrentMultiplier`.
    pub const CURRENT_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0602, DataType::Uint(2), Access::RO_REPORT);
    /// `ACCurrentDivisor`.
    pub const CURRENT_DIVISOR: AttributeDef =
        AttributeDef::new(0x0603, DataType::Uint(2), Access::RO_REPORT);
    /// `ACPowerMultiplier`.
    pub const POWER_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0604, DataType::Uint(2), Access::RO_REPORT);
    /// `ACPowerDivisor`.
    pub const POWER_DIVISOR: AttributeDef =
        AttributeDef::new(0x0605, DataType::Uint(2), Access::RO_REPORT);
    /// `ACAlarmsMask` (map16, Table 4-38).
    pub const ALARMS_MASK: AttributeDef =
        AttributeDef::new(0x0800, DataType::Bitmap(2), Access::RW);
    /// `ACVoltageOverload`.
    pub const VOLTAGE_OVERLOAD: AttributeDef =
        AttributeDef::new(0x0801, DataType::Int(2), Access::RO);
    /// `ACCurrentOverload`.
    pub const CURRENT_OVERLOAD: AttributeDef =
        AttributeDef::new(0x0802, DataType::Int(2), Access::RO);
    /// `ACActivePowerOverload`.
    pub const ACTIVE_POWER_OVERLOAD: AttributeDef =
        AttributeDef::new(0x0803, DataType::Int(2), Access::RO);

    /// Unknown unsigned reading.
    pub const UNKNOWN_U16: u16 = u16::MAX;
    /// Unknown signed reading.
    pub const UNKNOWN_I16: i16 = i16::MIN;
    /// Alarm mask bit / alarm code: voltage overload.
    pub const ALARM_VOLTAGE_OVERLOAD: u8 = 0;
    /// Alarm mask bit / alarm code: current overload.
    pub const ALARM_CURRENT_OVERLOAD: u8 = 1;
    /// Alarm mask bit / alarm code: active power overload.
    pub const ALARM_ACTIVE_POWER_OVERLOAD: u8 = 2;
    /// Alarm mask bit / alarm code: reactive power overload.
    pub const ALARM_REACTIVE_POWER_OVERLOAD: u8 = 3;
    /// Alarm mask bit / alarm code: average RMS over voltage.
    pub const ALARM_AVERAGE_RMS_OVER_VOLTAGE: u8 = 4;
    /// Alarm mask bit / alarm code: average RMS under voltage.
    pub const ALARM_AVERAGE_RMS_UNDER_VOLTAGE: u8 = 5;
    /// Alarm mask bit / alarm code: RMS extreme over voltage.
    pub const ALARM_RMS_EXTREME_OVER_VOLTAGE: u8 = 6;
    /// Alarm mask bit / alarm code: RMS extreme under voltage.
    pub const ALARM_RMS_EXTREME_UNDER_VOLTAGE: u8 = 7;
    /// Alarm mask bit / alarm code: RMS voltage sag.
    pub const ALARM_RMS_VOLTAGE_SAG: u8 = 8;
    /// Alarm mask bit / alarm code: RMS voltage swell.
    pub const ALARM_RMS_VOLTAGE_SWELL: u8 = 9;

    /// `ACReactivePowerOverload`.
    pub const REACTIVE_POWER_OVERLOAD: AttributeDef =
        AttributeDef::new(0x0804, DataType::Int(2), Access::RO);
    /// `AverageRMSOverVoltage` threshold.
    pub const AVERAGE_RMS_OVER_VOLTAGE: AttributeDef =
        AttributeDef::new(0x0805, DataType::Int(2), Access::RO);
    /// `AverageRMSUnderVoltage` threshold.
    pub const AVERAGE_RMS_UNDER_VOLTAGE: AttributeDef =
        AttributeDef::new(0x0806, DataType::Int(2), Access::RO);
    /// `RMSExtremeOverVoltage` threshold (writable).
    pub const RMS_EXTREME_OVER_VOLTAGE: AttributeDef =
        AttributeDef::new(0x0807, DataType::Int(2), Access::RW);
    /// `RMSExtremeUnderVoltage` threshold (writable).
    pub const RMS_EXTREME_UNDER_VOLTAGE: AttributeDef =
        AttributeDef::new(0x0808, DataType::Int(2), Access::RW);
    /// `RMSVoltageSag` threshold (writable).
    pub const RMS_VOLTAGE_SAG: AttributeDef =
        AttributeDef::new(0x0809, DataType::Int(2), Access::RW);
    /// `RMSVoltageSwell` threshold (writable).
    pub const RMS_VOLTAGE_SWELL: AttributeDef =
        AttributeDef::new(0x080a, DataType::Int(2), Access::RW);
    /// `AverageRMSVoltageMeasurementPeriod` (uint16 s, writable).
    pub const AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD: AttributeDef =
        AttributeDef::new(0x0511, DataType::Uint(2), Access::RW);
    /// `AverageRMSOverVoltageCounter` (writable to reset).
    pub const AVERAGE_RMS_OVER_VOLTAGE_COUNTER: AttributeDef =
        AttributeDef::new(0x0512, DataType::Uint(2), Access::RW);
    /// `AverageRMSUnderVoltageCounter`.
    pub const AVERAGE_RMS_UNDER_VOLTAGE_COUNTER: AttributeDef =
        AttributeDef::new(0x0513, DataType::Uint(2), Access::RW);
    /// `RMSExtremeOverVoltagePeriod`.
    pub const RMS_EXTREME_OVER_VOLTAGE_PERIOD: AttributeDef =
        AttributeDef::new(0x0514, DataType::Uint(2), Access::RW);
    /// `RMSExtremeUnderVoltagePeriod`.
    pub const RMS_EXTREME_UNDER_VOLTAGE_PERIOD: AttributeDef =
        AttributeDef::new(0x0515, DataType::Uint(2), Access::RW);
    /// `RMSVoltageSagPeriod`.
    pub const RMS_VOLTAGE_SAG_PERIOD: AttributeDef =
        AttributeDef::new(0x0516, DataType::Uint(2), Access::RW);
    /// `RMSVoltageSwellPeriod`.
    pub const RMS_VOLTAGE_SWELL_PERIOD: AttributeDef =
        AttributeDef::new(0x0517, DataType::Uint(2), Access::RW);
}

/// The AC non-phase-specific set (§4.9.2.2.4, Table 4-32): frequency
/// extremes, neutral current, the three-phase totals and the current
/// harmonics, with their formatting (Table 4-33).
pub mod ac_total {
    use super::*;

    /// `ACFrequency`, `ACFrequencyMultiplier` and `ACFrequencyDivisor`
    /// belong to this set and are instantiated by the single-phase
    /// server already.
    pub use super::ac::{FREQUENCY, FREQUENCY_DIVISOR, FREQUENCY_MULTIPLIER};
    /// `ACFrequencyMin`.
    pub const FREQUENCY_MIN: AttributeDef =
        AttributeDef::new(0x0301, DataType::Uint(2), Access::RO);
    /// `ACFrequencyMax`.
    pub const FREQUENCY_MAX: AttributeDef =
        AttributeDef::new(0x0302, DataType::Uint(2), Access::RO);
    /// `NeutralCurrent` (uint16, reportable).
    pub const NEUTRAL_CURRENT: AttributeDef =
        AttributeDef::new(0x0303, DataType::Uint(2), Access::RO_REPORT);
    /// `TotalActivePower` (int32, reportable).
    pub const TOTAL_ACTIVE_POWER: AttributeDef =
        AttributeDef::new(0x0304, DataType::Int(4), Access::RO_REPORT);
    /// `TotalReactivePower` (int32, reportable).
    pub const TOTAL_REACTIVE_POWER: AttributeDef =
        AttributeDef::new(0x0305, DataType::Int(4), Access::RO_REPORT);
    /// `TotalApparentPower` (uint32, reportable).
    pub const TOTAL_APPARENT_POWER: AttributeDef =
        AttributeDef::new(0x0306, DataType::Uint(4), Access::RO_REPORT);
    /// `Measured1stHarmonicCurrent` … `Measured11thHarmonicCurrent`
    /// (int16, reportable), harmonics 1, 3, 5, 7, 9, 11.
    pub const HARMONIC_CURRENT: [AttributeDef; 6] = [
        AttributeDef::new(0x0307, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x0308, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x0309, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x030a, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x030b, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x030c, DataType::Int(2), Access::RO_REPORT),
    ];
    /// `MeasuredPhase1stHarmonicCurrent` … (int16, reportable).
    pub const PHASE_HARMONIC_CURRENT: [AttributeDef; 6] = [
        AttributeDef::new(0x030d, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x030e, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x030f, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x0310, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x0311, DataType::Int(2), Access::RO_REPORT),
        AttributeDef::new(0x0312, DataType::Int(2), Access::RO_REPORT),
    ];
    /// `PowerMultiplier` (uint32).
    pub const POWER_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0402, DataType::Uint(4), Access::RO_REPORT);
    /// `PowerDivisor` (uint32).
    pub const POWER_DIVISOR: AttributeDef =
        AttributeDef::new(0x0403, DataType::Uint(4), Access::RO_REPORT);
    /// `HarmonicCurrentMultiplier` (int8 power of ten).
    pub const HARMONIC_CURRENT_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0404, DataType::Int(1), Access::RO_REPORT);
    /// `PhaseHarmonicCurrentMultiplier` (int8 power of ten).
    pub const PHASE_HARMONIC_CURRENT_MULTIPLIER: AttributeDef =
        AttributeDef::new(0x0405, DataType::Int(1), Access::RO_REPORT);
    /// Unknown int32 total.
    pub const UNKNOWN_I32: i32 = i32::MIN;
    /// Unknown uint32 total.
    pub const UNKNOWN_U32: u32 = u32::MAX;
}

/// A phase of a polyphase AC measurement (§4.9.2.2.10–11): the phase
/// B and C sets repeat the phase A layout at 0x0900 and 0x0a00.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Phase {
    /// Phase A (the single-phase set, 0x05xx).
    A,
    /// Phase B (0x09xx).
    B,
    /// Phase C (0x0axx).
    C,
}

impl Phase {
    const fn offset(self) -> u16 {
        match self {
            Phase::A => 0,
            Phase::B => 0x0400,
            Phase::C => 0x0500,
        }
    }

    /// The `MeasurementType` bit of the phase.
    pub const fn measurement_bit(self) -> u32 {
        match self {
            Phase::A => measurement_type::PHASE_A,
            Phase::B => measurement_type::PHASE_B,
            Phase::C => measurement_type::PHASE_C,
        }
    }
}

/// The attribute of `phase` corresponding to the phase A attribute
/// `base` (Tables 4-39 / 4-40: the same layout at 0x0900 and 0x0a00).
pub const fn phase_attr(phase: Phase, base: AttributeDef) -> AttributeDef {
    AttributeDef::new(base.id.0 + phase.offset(), base.ty, base.access)
}

/// Get Profile Info (client → server).
pub const CMD_GET_PROFILE_INFO: CommandId = CommandId(0x00);
/// Get Measurement Profile (client → server).
pub const CMD_GET_MEASUREMENT_PROFILE: CommandId = CommandId(0x01);
/// Get Profile Info Response.
pub const CMD_GET_PROFILE_INFO_RESPONSE: CommandId = CommandId(0x00);
/// Get Measurement Profile Response.
pub const CMD_GET_MEASUREMENT_PROFILE_RESPONSE: CommandId = CommandId(0x01);

/// `ProfileIntervalPeriod` values (Figure 4-7).
pub mod interval_period {
    /// Daily.
    pub const DAILY: u8 = 0;
    /// 60 minutes.
    pub const MINUTES_60: u8 = 1;
    /// 30 minutes.
    pub const MINUTES_30: u8 = 2;
    /// 15 minutes.
    pub const MINUTES_15: u8 = 3;
    /// 10 minutes.
    pub const MINUTES_10: u8 = 4;
    /// 7.5 minutes.
    pub const MINUTES_7_5: u8 = 5;
    /// 5 minutes.
    pub const MINUTES_5: u8 = 6;
    /// 2.5 minutes.
    pub const MINUTES_2_5: u8 = 7;
}

/// Get Measurement Profile Response statuses (Table 4-42).
pub mod profile_status {
    /// Success.
    pub const SUCCESS: u8 = 0;
    /// Attribute profile not supported.
    pub const NOT_SUPPORTED: u8 = 1;
    /// Invalid start time.
    pub const INVALID_START_TIME: u8 = 2;
    /// More intervals requested than can be returned.
    pub const TOO_MANY_INTERVALS: u8 = 3;
    /// No intervals available for the requested time.
    pub const NO_INTERVALS: u8 = 4;
}

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[CMD_GET_PROFILE_INFO, CMD_GET_MEASUREMENT_PROFILE],
    generated: &[
        CMD_GET_PROFILE_INFO_RESPONSE,
        CMD_GET_MEASUREMENT_PROFILE_RESPONSE,
    ],
};

/// Default reporting of the readings: on a change of one unit, at
/// least every 5 minutes.
pub const READING_REPORTING: DefaultReporting = DefaultReporting {
    min: 10,
    max: 300,
    change: 1,
};

/// Reporting of the formatting attributes: on change only.
const FORMAT_REPORTING: DefaultReporting = DefaultReporting {
    min: 0,
    max: 0xffff,
    change: 0,
};

/// A multiplier / divisor pair (§4.9.1.4), both non-zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Scale {
    /// Multiplier.
    pub multiplier: u16,
    /// Divisor.
    pub divisor: u16,
}

impl Scale {
    /// Unity.
    pub const UNITY: Scale = Scale {
        multiplier: 1,
        divisor: 1,
    };
}

/// What a server measures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Capability {
    /// DC voltage, current and power with `voltage`, `current` and
    /// `power` scales.
    pub dc: Option<[Scale; 3]>,
    /// Single-phase AC: frequency, RMS voltage / current, active /
    /// reactive / apparent power and power factor with `frequency`,
    /// `voltage`, `current` and `power` scales.
    pub ac: Option<[Scale; 4]>,
}

impl Capability {
    /// DC only, unity scales.
    pub const DC: Capability = Capability {
        dc: Some([Scale::UNITY; 3]),
        ac: None,
    };
    /// Single-phase AC only, unity scales.
    pub const AC: Capability = Capability {
        dc: None,
        ac: Some([Scale::UNITY; 4]),
    };
}

const fn i16v(v: i16) -> Value<'static> {
    Value::Int {
        width: 2,
        value: v as i64,
    }
}

const fn u16v(v: u16) -> Value<'static> {
    Value::Uint {
        width: 2,
        value: v as u64,
    }
}

fn add_scale<const A: usize>(
    c: &mut ClusterInstance<A>,
    multiplier: AttributeDef,
    divisor: AttributeDef,
    scale: Scale,
) -> Result<(), ZclStatus> {
    if scale.multiplier == 0 || scale.divisor == 0 {
        return Err(ZclStatus::InvalidValue);
    }
    c.add_reported_attribute(multiplier, &u16v(scale.multiplier), FORMAT_REPORTING)?;
    c.add_reported_attribute(divisor, &u16v(scale.divisor), FORMAT_REPORTING)
}

/// Builds a server measuring per `capability`, with the overload alarm
/// masks cleared and the thresholds unknown (0xffff). The AC set keeps
/// the RMS voltage extremes only (the current and active power minima /
/// maxima are defined but not instantiated, to stay within the
/// attribute capacity).
pub fn server<const A: usize>(capability: Capability) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    let mut kind = 0u32;
    if capability.dc.is_some() {
        kind |= measurement_type::DC;
    }
    if capability.ac.is_some() {
        kind |= measurement_type::ACTIVE
            | measurement_type::REACTIVE
            | measurement_type::APPARENT
            | measurement_type::PHASE_A;
    }
    c.add_attribute(
        MEASUREMENT_TYPE,
        &Value::Bits {
            width: 4,
            bits: u64::from(kind),
        },
    )?;
    if let Some([voltage, current, power]) = capability.dc {
        for (reading, min, max) in [
            (dc::VOLTAGE, dc::VOLTAGE_MIN, dc::VOLTAGE_MAX),
            (dc::CURRENT, dc::CURRENT_MIN, dc::CURRENT_MAX),
            (dc::POWER, dc::POWER_MIN, dc::POWER_MAX),
        ] {
            c.add_reported_attribute(reading, &i16v(dc::UNKNOWN), READING_REPORTING)?;
            c.add_attribute(min, &i16v(dc::UNKNOWN))?;
            c.add_attribute(max, &i16v(dc::UNKNOWN))?;
        }
        add_scale(&mut c, dc::VOLTAGE_MULTIPLIER, dc::VOLTAGE_DIVISOR, voltage)?;
        add_scale(&mut c, dc::CURRENT_MULTIPLIER, dc::CURRENT_DIVISOR, current)?;
        add_scale(&mut c, dc::POWER_MULTIPLIER, dc::POWER_DIVISOR, power)?;
        c.add_attribute(dc::OVERLOAD_ALARMS_MASK, &Value::Bits { width: 1, bits: 0 })?;
        c.add_attribute(dc::VOLTAGE_OVERLOAD, &i16v(-1))?;
        c.add_attribute(dc::CURRENT_OVERLOAD, &i16v(-1))?;
    }
    if let Some([frequency, voltage, current, power]) = capability.ac {
        c.add_reported_attribute(ac::FREQUENCY, &u16v(ac::UNKNOWN_U16), READING_REPORTING)?;
        add_scale(
            &mut c,
            ac::FREQUENCY_MULTIPLIER,
            ac::FREQUENCY_DIVISOR,
            frequency,
        )?;
        c.add_reported_attribute(ac::RMS_VOLTAGE, &u16v(ac::UNKNOWN_U16), READING_REPORTING)?;
        c.add_attribute(ac::RMS_VOLTAGE_MIN, &u16v(ac::UNKNOWN_U16))?;
        c.add_attribute(ac::RMS_VOLTAGE_MAX, &u16v(ac::UNKNOWN_U16))?;
        c.add_reported_attribute(ac::RMS_CURRENT, &u16v(ac::UNKNOWN_U16), READING_REPORTING)?;
        c.add_reported_attribute(ac::ACTIVE_POWER, &i16v(ac::UNKNOWN_I16), READING_REPORTING)?;
        c.add_reported_attribute(
            ac::REACTIVE_POWER,
            &i16v(ac::UNKNOWN_I16),
            READING_REPORTING,
        )?;
        c.add_reported_attribute(
            ac::APPARENT_POWER,
            &u16v(ac::UNKNOWN_U16),
            READING_REPORTING,
        )?;
        c.add_attribute(ac::POWER_FACTOR, &Value::Int { width: 1, value: 0 })?;
        add_scale(&mut c, ac::VOLTAGE_MULTIPLIER, ac::VOLTAGE_DIVISOR, voltage)?;
        add_scale(&mut c, ac::CURRENT_MULTIPLIER, ac::CURRENT_DIVISOR, current)?;
        add_scale(&mut c, ac::POWER_MULTIPLIER, ac::POWER_DIVISOR, power)?;
        c.add_attribute(ac::ALARMS_MASK, &Value::Bits { width: 2, bits: 0 })?;
        c.add_attribute(ac::VOLTAGE_OVERLOAD, &i16v(-1))?;
        c.add_attribute(ac::CURRENT_OVERLOAD, &i16v(-1))?;
        c.add_attribute(ac::ACTIVE_POWER_OVERLOAD, &i16v(-1))?;
    }
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

/// Adds the RMS current and active power extremes of the single-phase
/// set (Table 4-34); `set_ac` tracks them from then on.
pub fn enable_ac_extremes<const A: usize>(c: &mut ClusterInstance<A>) -> Result<(), ZclStatus> {
    c.add_attribute(ac::RMS_CURRENT_MIN, &u16v(ac::UNKNOWN_U16))?;
    c.add_attribute(ac::RMS_CURRENT_MAX, &u16v(ac::UNKNOWN_U16))?;
    c.add_attribute(ac::ACTIVE_POWER_MIN, &i16v(ac::UNKNOWN_I16))?;
    c.add_attribute(ac::ACTIVE_POWER_MAX, &i16v(ac::UNKNOWN_I16))
}

/// Adds the voltage quality attributes of Table 4-34 (measurement
/// period, over / under voltage counters and periods, sag / swell
/// periods) and the Table 4-38 thresholds beyond the overloads; the
/// alarms are evaluated by `set_ac` against the readings.
pub fn enable_voltage_quality<const A: usize>(c: &mut ClusterInstance<A>) -> Result<(), ZclStatus> {
    for a in [
        ac::AVERAGE_RMS_VOLTAGE_MEASUREMENT_PERIOD,
        ac::AVERAGE_RMS_OVER_VOLTAGE_COUNTER,
        ac::AVERAGE_RMS_UNDER_VOLTAGE_COUNTER,
        ac::RMS_EXTREME_OVER_VOLTAGE_PERIOD,
        ac::RMS_EXTREME_UNDER_VOLTAGE_PERIOD,
        ac::RMS_VOLTAGE_SAG_PERIOD,
        ac::RMS_VOLTAGE_SWELL_PERIOD,
    ] {
        c.add_attribute(a, &u16v(0))?;
    }
    for a in [
        ac::REACTIVE_POWER_OVERLOAD,
        ac::AVERAGE_RMS_OVER_VOLTAGE,
        ac::AVERAGE_RMS_UNDER_VOLTAGE,
        ac::RMS_EXTREME_OVER_VOLTAGE,
        ac::RMS_EXTREME_UNDER_VOLTAGE,
        ac::RMS_VOLTAGE_SAG,
        ac::RMS_VOLTAGE_SWELL,
    ] {
        c.add_attribute(a, &i16v(-1))?;
    }
    Ok(())
}

/// Adds the rest of the AC non-phase-specific set (Table 4-32) to a
/// single-phase server: the frequency extremes, the neutral current
/// and totals of a polyphase meter, `harmonics` orders of current
/// harmonics (0…6, with their phase counterparts) and the Table 4-33
/// formatting: the `power` scale and the harmonic multipliers as
/// powers of ten.
pub fn enable_ac_totals<const A: usize>(
    c: &mut ClusterInstance<A>,
    power: Scale,
    harmonics: usize,
    harmonic_multiplier: i8,
) -> Result<(), ZclStatus> {
    if harmonics > ac_total::HARMONIC_CURRENT.len() || power.divisor == 0 || power.multiplier == 0 {
        return Err(ZclStatus::InvalidValue);
    }
    c.add_attribute(ac_total::FREQUENCY_MIN, &u16v(ac::UNKNOWN_U16))?;
    c.add_attribute(ac_total::FREQUENCY_MAX, &u16v(ac::UNKNOWN_U16))?;
    c.add_reported_attribute(
        ac_total::NEUTRAL_CURRENT,
        &u16v(ac::UNKNOWN_U16),
        READING_REPORTING,
    )?;
    let i32v = |v: i32| Value::Int {
        width: 4,
        value: i64::from(v),
    };
    c.add_reported_attribute(
        ac_total::TOTAL_ACTIVE_POWER,
        &i32v(ac_total::UNKNOWN_I32),
        READING_REPORTING,
    )?;
    c.add_reported_attribute(
        ac_total::TOTAL_REACTIVE_POWER,
        &i32v(ac_total::UNKNOWN_I32),
        READING_REPORTING,
    )?;
    c.add_reported_attribute(
        ac_total::TOTAL_APPARENT_POWER,
        &Value::Uint {
            width: 4,
            value: u64::from(ac_total::UNKNOWN_U32),
        },
        READING_REPORTING,
    )?;
    for i in 0..harmonics {
        if let (Some(h), Some(p)) = (
            ac_total::HARMONIC_CURRENT.get(i),
            ac_total::PHASE_HARMONIC_CURRENT.get(i),
        ) {
            c.add_reported_attribute(*h, &i16v(ac::UNKNOWN_I16), READING_REPORTING)?;
            c.add_reported_attribute(*p, &i16v(ac::UNKNOWN_I16), READING_REPORTING)?;
        }
    }
    let u32v = |v: u16| Value::Uint {
        width: 4,
        value: u64::from(v),
    };
    c.add_reported_attribute(
        ac_total::POWER_MULTIPLIER,
        &u32v(power.multiplier),
        FORMAT_REPORTING,
    )?;
    c.add_reported_attribute(
        ac_total::POWER_DIVISOR,
        &u32v(power.divisor),
        FORMAT_REPORTING,
    )?;
    if harmonics > 0 {
        let m = Value::Int {
            width: 1,
            value: i64::from(harmonic_multiplier),
        };
        c.add_reported_attribute(ac_total::HARMONIC_CURRENT_MULTIPLIER, &m, FORMAT_REPORTING)?;
        c.add_reported_attribute(
            ac_total::PHASE_HARMONIC_CURRENT_MULTIPLIER,
            &m,
            FORMAT_REPORTING,
        )?;
    }
    Ok(())
}

/// Adds the measurement set of `phase` B or C (Tables 4-39 / 4-40):
/// RMS voltage with extremes, RMS current, active / reactive / apparent
/// power and power factor, and marks the phase in `MeasurementType`.
pub fn enable_phase<const A: usize>(
    c: &mut ClusterInstance<A>,
    phase: Phase,
) -> Result<(), ZclStatus> {
    if phase == Phase::A {
        return Err(ZclStatus::InvalidValue);
    }
    let p = |base: AttributeDef| phase_attr(phase, base);
    c.add_reported_attribute(
        p(ac::RMS_VOLTAGE),
        &u16v(ac::UNKNOWN_U16),
        READING_REPORTING,
    )?;
    c.add_attribute(p(ac::RMS_VOLTAGE_MIN), &u16v(ac::UNKNOWN_U16))?;
    c.add_attribute(p(ac::RMS_VOLTAGE_MAX), &u16v(ac::UNKNOWN_U16))?;
    c.add_reported_attribute(
        p(ac::RMS_CURRENT),
        &u16v(ac::UNKNOWN_U16),
        READING_REPORTING,
    )?;
    c.add_reported_attribute(
        p(ac::ACTIVE_POWER),
        &i16v(ac::UNKNOWN_I16),
        READING_REPORTING,
    )?;
    c.add_reported_attribute(
        p(ac::REACTIVE_POWER),
        &i16v(ac::UNKNOWN_I16),
        READING_REPORTING,
    )?;
    c.add_reported_attribute(
        p(ac::APPARENT_POWER),
        &u16v(ac::UNKNOWN_U16),
        READING_REPORTING,
    )?;
    c.add_attribute(p(ac::POWER_FACTOR), &Value::Int { width: 1, value: 0 })?;
    let kind = c.u64(MEASUREMENT_TYPE.id).unwrap_or(0) | u64::from(phase.measurement_bit());
    c.set(
        MEASUREMENT_TYPE.id,
        &Value::Bits {
            width: 4,
            bits: kind,
        },
    );
    Ok(())
}

/// Records the readings of phase B or C (voltage extremes tracked; no
/// alarms, which the phase A thresholds cover).
pub fn set_ac_phase<const A: usize>(c: &mut ClusterInstance<A>, phase: Phase, r: AcReading) {
    if phase == Phase::A {
        set_ac(c, r);
        return;
    }
    let p = |base: AttributeDef| phase_attr(phase, base);
    track_u16(
        c,
        p(ac::RMS_VOLTAGE),
        p(ac::RMS_VOLTAGE_MIN),
        p(ac::RMS_VOLTAGE_MAX),
        r.rms_voltage,
    );
    c.set_u16(
        p(ac::RMS_CURRENT).id,
        r.rms_current.unwrap_or(ac::UNKNOWN_U16),
    );
    c.set_i16(
        p(ac::ACTIVE_POWER).id,
        r.active_power.unwrap_or(ac::UNKNOWN_I16),
    );
    c.set_i16(
        p(ac::REACTIVE_POWER).id,
        r.reactive_power.unwrap_or(ac::UNKNOWN_I16),
    );
    c.set_u16(
        p(ac::APPARENT_POWER).id,
        r.apparent_power.unwrap_or(ac::UNKNOWN_U16),
    );
    c.set(
        p(ac::POWER_FACTOR).id,
        &Value::Int {
            width: 1,
            value: i64::from(r.power_factor.clamp(-100, 100)),
        },
    );
}

/// Polyphase totals and the non-phase-specific readings (`None` =
/// unknown); the frequency extremes are tracked.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AcTotals {
    /// `ACFrequency`.
    pub frequency: Option<u16>,
    /// `NeutralCurrent`.
    pub neutral_current: Option<u16>,
    /// `TotalActivePower`.
    pub active_power: Option<i32>,
    /// `TotalReactivePower`.
    pub reactive_power: Option<i32>,
    /// `TotalApparentPower`.
    pub apparent_power: Option<u32>,
}

/// Records the totals of Table 4-32.
pub fn set_ac_totals<const A: usize>(c: &mut ClusterInstance<A>, t: AcTotals) {
    track_u16(
        c,
        ac::FREQUENCY,
        ac_total::FREQUENCY_MIN,
        ac_total::FREQUENCY_MAX,
        t.frequency,
    );
    c.set_u16(
        ac_total::NEUTRAL_CURRENT.id,
        t.neutral_current.unwrap_or(ac::UNKNOWN_U16),
    );
    let i32v = |v: i32| Value::Int {
        width: 4,
        value: i64::from(v),
    };
    c.set(
        ac_total::TOTAL_ACTIVE_POWER.id,
        &i32v(t.active_power.unwrap_or(ac_total::UNKNOWN_I32)),
    );
    c.set(
        ac_total::TOTAL_REACTIVE_POWER.id,
        &i32v(t.reactive_power.unwrap_or(ac_total::UNKNOWN_I32)),
    );
    c.set(
        ac_total::TOTAL_APPARENT_POWER.id,
        &Value::Uint {
            width: 4,
            value: u64::from(t.apparent_power.unwrap_or(ac_total::UNKNOWN_U32)),
        },
    );
}

/// Records the measured current harmonics (order index 0…5 for the 1st,
/// 3rd, 5th, 7th, 9th and 11th) and their phase counterparts.
pub fn set_harmonics<const A: usize>(
    c: &mut ClusterInstance<A>,
    magnitudes: &[i16],
    phases: &[i16],
) {
    for (i, m) in magnitudes.iter().enumerate() {
        if let Some(a) = ac_total::HARMONIC_CURRENT.get(i) {
            c.set_i16(a.id, *m);
        }
    }
    for (i, p) in phases.iter().enumerate() {
        if let Some(a) = ac_total::PHASE_HARMONIC_CURRENT.get(i) {
            c.set_i16(a.id, *p);
        }
    }
}

/// Sets a manufacturer overload threshold (the `*Overload` attributes;
/// unknown thresholds never alarm).
pub fn set_threshold<const A: usize>(
    c: &mut ClusterInstance<A>,
    id: AttributeId,
    value: i16,
) -> bool {
    c.set_i16(id, value)
}

fn track_i16<const A: usize>(
    c: &mut ClusterInstance<A>,
    reading: AttributeDef,
    min: AttributeDef,
    max: AttributeDef,
    value: Option<i16>,
    unknown: i16,
) -> bool {
    let changed = c.set_i16(reading.id, value.unwrap_or(unknown));
    if let Some(v) = value {
        let lo = c
            .i16(min.id)
            .filter(|m| *m != unknown)
            .map_or(v, |m| m.min(v));
        let hi = c
            .i16(max.id)
            .filter(|m| *m != unknown)
            .map_or(v, |m| m.max(v));
        c.set_i16(min.id, lo);
        c.set_i16(max.id, hi);
    }
    changed
}

fn track_u16<const A: usize>(
    c: &mut ClusterInstance<A>,
    reading: AttributeDef,
    min: AttributeDef,
    max: AttributeDef,
    value: Option<u16>,
) -> bool {
    let changed = c.set_u16(reading.id, value.unwrap_or(ac::UNKNOWN_U16));
    if let Some(v) = value {
        let lo = c
            .u16(min.id)
            .filter(|m| *m != ac::UNKNOWN_U16)
            .map_or(v, |m| m.min(v));
        let hi = c
            .u16(max.id)
            .filter(|m| *m != ac::UNKNOWN_U16)
            .map_or(v, |m| m.max(v));
        c.set_u16(min.id, lo);
        c.set_u16(max.id, hi);
    }
    changed
}

/// Alarms raised by a reading: at most three codes.
pub type Alarms = heapless::Vec<u8, 10>;

fn overload(mask: u64, bit: u8, threshold: Option<i16>, value: i64) -> bool {
    mask & (1 << bit) != 0 && threshold.is_some_and(|t| t != -1 && value > i64::from(t))
}

/// Records DC readings (`None` = unknown), tracks the minima / maxima
/// and returns the overload alarm codes enabled by
/// `DCOverloadAlarmsMask` whose threshold the reading exceeds.
pub fn set_dc<const A: usize>(
    c: &mut ClusterInstance<A>,
    voltage: Option<i16>,
    current: Option<i16>,
    power: Option<i16>,
) -> Alarms {
    track_i16(
        c,
        dc::VOLTAGE,
        dc::VOLTAGE_MIN,
        dc::VOLTAGE_MAX,
        voltage,
        dc::UNKNOWN,
    );
    track_i16(
        c,
        dc::CURRENT,
        dc::CURRENT_MIN,
        dc::CURRENT_MAX,
        current,
        dc::UNKNOWN,
    );
    track_i16(
        c,
        dc::POWER,
        dc::POWER_MIN,
        dc::POWER_MAX,
        power,
        dc::UNKNOWN,
    );
    let mask = c.u64(dc::OVERLOAD_ALARMS_MASK.id).unwrap_or(0);
    let mut alarms = Alarms::new();
    if let Some(v) = voltage
        && overload(
            mask,
            dc::ALARM_VOLTAGE_OVERLOAD,
            c.i16(dc::VOLTAGE_OVERLOAD.id),
            i64::from(v),
        )
    {
        let _ = alarms.push(dc::ALARM_VOLTAGE_OVERLOAD);
    }
    if let Some(i) = current
        && overload(
            mask,
            dc::ALARM_CURRENT_OVERLOAD,
            c.i16(dc::CURRENT_OVERLOAD.id),
            i64::from(i),
        )
    {
        let _ = alarms.push(dc::ALARM_CURRENT_OVERLOAD);
    }
    alarms
}

/// Single-phase AC readings (`None` = unknown).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AcReading {
    /// Frequency (Hz, scaled).
    pub frequency: Option<u16>,
    /// RMS voltage.
    pub rms_voltage: Option<u16>,
    /// RMS current.
    pub rms_current: Option<u16>,
    /// Active power (signed).
    pub active_power: Option<i16>,
    /// Reactive power (signed).
    pub reactive_power: Option<i16>,
    /// Apparent power.
    pub apparent_power: Option<u16>,
    /// Power factor (−100..100).
    pub power_factor: i8,
}

/// Records AC readings, tracks the minima / maxima and returns the
/// overload alarm codes enabled by `ACAlarmsMask` whose threshold the
/// reading exceeds.
pub fn set_ac<const A: usize>(c: &mut ClusterInstance<A>, r: AcReading) -> Alarms {
    if c.attributes.get(ac_total::FREQUENCY_MIN.id, None).is_some() {
        track_u16(
            c,
            ac::FREQUENCY,
            ac_total::FREQUENCY_MIN,
            ac_total::FREQUENCY_MAX,
            r.frequency,
        );
    } else {
        c.set_u16(ac::FREQUENCY.id, r.frequency.unwrap_or(ac::UNKNOWN_U16));
    }
    track_u16(
        c,
        ac::RMS_VOLTAGE,
        ac::RMS_VOLTAGE_MIN,
        ac::RMS_VOLTAGE_MAX,
        r.rms_voltage,
    );
    if c.attributes.get(ac::RMS_CURRENT_MIN.id, None).is_some() {
        track_u16(
            c,
            ac::RMS_CURRENT,
            ac::RMS_CURRENT_MIN,
            ac::RMS_CURRENT_MAX,
            r.rms_current,
        );
    } else {
        c.set_u16(ac::RMS_CURRENT.id, r.rms_current.unwrap_or(ac::UNKNOWN_U16));
    }
    if c.attributes.get(ac::ACTIVE_POWER_MIN.id, None).is_some() {
        track_i16(
            c,
            ac::ACTIVE_POWER,
            ac::ACTIVE_POWER_MIN,
            ac::ACTIVE_POWER_MAX,
            r.active_power,
            ac::UNKNOWN_I16,
        );
    } else {
        c.set_i16(
            ac::ACTIVE_POWER.id,
            r.active_power.unwrap_or(ac::UNKNOWN_I16),
        );
    }
    c.set_i16(
        ac::REACTIVE_POWER.id,
        r.reactive_power.unwrap_or(ac::UNKNOWN_I16),
    );
    c.set_u16(
        ac::APPARENT_POWER.id,
        r.apparent_power.unwrap_or(ac::UNKNOWN_U16),
    );
    c.set(
        ac::POWER_FACTOR.id,
        &Value::Int {
            width: 1,
            value: i64::from(r.power_factor.clamp(-100, 100)),
        },
    );
    let mask = c.u64(ac::ALARMS_MASK.id).unwrap_or(0);
    let mut alarms = Alarms::new();
    if let Some(v) = r.rms_voltage
        && overload(
            mask,
            ac::ALARM_VOLTAGE_OVERLOAD,
            c.i16(ac::VOLTAGE_OVERLOAD.id),
            i64::from(v),
        )
    {
        let _ = alarms.push(ac::ALARM_VOLTAGE_OVERLOAD);
    }
    if let Some(i) = r.rms_current
        && overload(
            mask,
            ac::ALARM_CURRENT_OVERLOAD,
            c.i16(ac::CURRENT_OVERLOAD.id),
            i64::from(i),
        )
    {
        let _ = alarms.push(ac::ALARM_CURRENT_OVERLOAD);
    }
    if let Some(p) = r.active_power
        && overload(
            mask,
            ac::ALARM_ACTIVE_POWER_OVERLOAD,
            c.i16(ac::ACTIVE_POWER_OVERLOAD.id),
            i64::from(p),
        )
    {
        let _ = alarms.push(ac::ALARM_ACTIVE_POWER_OVERLOAD);
    }
    if let Some(q) = r.reactive_power
        && overload(
            mask,
            ac::ALARM_REACTIVE_POWER_OVERLOAD,
            c.i16(ac::REACTIVE_POWER_OVERLOAD.id),
            i64::from(q),
        )
    {
        let _ = alarms.push(ac::ALARM_REACTIVE_POWER_OVERLOAD);
    }
    // Voltage quality (Table 4-38): above the over / swell thresholds,
    // below the under / sag thresholds; the counters count the
    // average-RMS excursions.
    if let Some(v) = r.rms_voltage {
        let v = i64::from(v);
        let above = |c: &ClusterInstance<A>, id: AttributeId| {
            c.i16(id)
                .filter(|t| *t >= 0)
                .is_some_and(|t| v > i64::from(t))
        };
        let below = |c: &ClusterInstance<A>, id: AttributeId| {
            c.i16(id)
                .filter(|t| *t >= 0)
                .is_some_and(|t| v < i64::from(t))
        };
        let checks = [
            (
                ac::ALARM_AVERAGE_RMS_OVER_VOLTAGE,
                above(c, ac::AVERAGE_RMS_OVER_VOLTAGE.id),
                Some(ac::AVERAGE_RMS_OVER_VOLTAGE_COUNTER),
            ),
            (
                ac::ALARM_AVERAGE_RMS_UNDER_VOLTAGE,
                below(c, ac::AVERAGE_RMS_UNDER_VOLTAGE.id),
                Some(ac::AVERAGE_RMS_UNDER_VOLTAGE_COUNTER),
            ),
            (
                ac::ALARM_RMS_EXTREME_OVER_VOLTAGE,
                above(c, ac::RMS_EXTREME_OVER_VOLTAGE.id),
                None,
            ),
            (
                ac::ALARM_RMS_EXTREME_UNDER_VOLTAGE,
                below(c, ac::RMS_EXTREME_UNDER_VOLTAGE.id),
                None,
            ),
            (
                ac::ALARM_RMS_VOLTAGE_SAG,
                below(c, ac::RMS_VOLTAGE_SAG.id),
                None,
            ),
            (
                ac::ALARM_RMS_VOLTAGE_SWELL,
                above(c, ac::RMS_VOLTAGE_SWELL.id),
                None,
            ),
        ];
        for (code, hit, counter) in checks {
            if !hit {
                continue;
            }
            if let Some(counter) = counter {
                let n = c.u16(counter.id).unwrap_or(0);
                c.set_u16(counter.id, n.saturating_add(1));
            }
            if mask & (1 << code) != 0 {
                let _ = alarms.push(code);
            }
        }
    }
    alarms
}

/// Get Profile Info Response (§4.9.2.3.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProfileInfo<'a> {
    /// Number of supported profiles.
    pub profile_count: u8,
    /// Interval period (Figure 4-7).
    pub interval_period: u8,
    /// Intervals per response.
    pub max_intervals: u8,
    /// Profiled attribute identifiers (little-endian pairs).
    pub attributes: &'a [u8],
}

impl<'a> ProfileInfo<'a> {
    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(self.profile_count)?;
        w.u8(self.interval_period)?;
        w.u8(self.max_intervals)?;
        w.bytes(self.attributes)?;
        Ok(w.position())
    }

    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(ProfileInfo {
            profile_count: r.u8()?,
            interval_period: r.u8()?,
            max_intervals: r.u8()?,
            attributes: r.take_rest(),
        })
    }
}

/// Get Measurement Profile (§4.9.2.4.1.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MeasurementProfileRequest {
    /// Attribute to profile.
    pub attribute: AttributeId,
    /// Start time (UTC).
    pub start_time: u32,
    /// Intervals requested.
    pub intervals: u8,
}

impl MeasurementProfileRequest {
    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u16_le(self.attribute.0)?;
        w.u32_le(self.start_time)?;
        w.u8(self.intervals)?;
        Ok(w.position())
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(MeasurementProfileRequest {
            attribute: AttributeId(r.u16_le()?),
            start_time: r.u32_le()?,
            intervals: r.u8()?,
        })
    }
}

/// Get Measurement Profile Response (§4.9.2.3.1.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MeasurementProfile<'a> {
    /// End time of the most recent interval (UTC).
    pub start_time: u32,
    /// Status (Table 4-42).
    pub status: u8,
    /// Interval period.
    pub interval_period: u8,
    /// Intervals delivered.
    pub intervals_delivered: u8,
    /// Profiled attribute.
    pub attribute: AttributeId,
    /// Interval values, oldest first, in the attribute's encoding.
    pub intervals: &'a [u8],
}

impl<'a> MeasurementProfile<'a> {
    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u32_le(self.start_time)?;
        w.u8(self.status)?;
        w.u8(self.interval_period)?;
        w.u8(self.intervals_delivered)?;
        w.u16_le(self.attribute.0)?;
        w.bytes(self.intervals)?;
        Ok(w.position())
    }

    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(MeasurementProfile {
            start_time: r.u32_le()?,
            status: r.u8()?,
            interval_period: r.u8()?,
            intervals_delivered: r.u8()?,
            attribute: AttributeId(r.u16_le()?),
            intervals: r.take_rest(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_server_tracks_extremes_and_alarms() {
        let mut c: ClusterInstance<36> = server(Capability::DC).unwrap();
        assert_eq!(
            c.u64(MEASUREMENT_TYPE.id),
            Some(u64::from(measurement_type::DC))
        );
        assert_eq!(c.i16(dc::VOLTAGE.id), Some(dc::UNKNOWN));
        assert!(set_dc(&mut c, Some(120), Some(5), Some(600)).is_empty());
        set_dc(&mut c, Some(110), Some(7), None);
        assert_eq!(
            (c.i16(dc::VOLTAGE_MIN.id), c.i16(dc::VOLTAGE_MAX.id)),
            (Some(110), Some(120))
        );
        assert_eq!(
            (c.i16(dc::CURRENT_MIN.id), c.i16(dc::CURRENT_MAX.id)),
            (Some(5), Some(7))
        );
        assert_eq!(c.i16(dc::POWER.id), Some(dc::UNKNOWN));
        assert_eq!(
            c.i16(dc::POWER_MAX.id),
            Some(600),
            "unknown keeps the extremes"
        );
        // Thresholds only alarm when enabled by the mask.
        set_threshold(&mut c, dc::VOLTAGE_OVERLOAD.id, 125);
        assert!(set_dc(&mut c, Some(130), None, None).is_empty());
        c.set(
            dc::OVERLOAD_ALARMS_MASK.id,
            &Value::Bits {
                width: 1,
                bits: 0x03,
            },
        );
        assert_eq!(
            set_dc(&mut c, Some(130), Some(9), None).as_slice(),
            &[dc::ALARM_VOLTAGE_OVERLOAD]
        );
        assert!(
            server::<24>(Capability {
                dc: Some(
                    [Scale {
                        multiplier: 0,
                        divisor: 1
                    }; 3]
                ),
                ac: None
            })
            .is_err()
        );
    }

    #[test]
    fn ac_server_readings_and_alarms() {
        let mut c: ClusterInstance<36> = server(Capability::AC).unwrap();
        assert_eq!(c.u16(ac::RMS_VOLTAGE.id), Some(ac::UNKNOWN_U16));
        c.set(
            ac::ALARMS_MASK.id,
            &Value::Bits {
                width: 2,
                bits: 0x07,
            },
        );
        set_threshold(&mut c, ac::CURRENT_OVERLOAD.id, 16);
        set_threshold(&mut c, ac::ACTIVE_POWER_OVERLOAD.id, 3000);
        let alarms = set_ac(
            &mut c,
            AcReading {
                frequency: Some(50),
                rms_voltage: Some(230),
                rms_current: Some(20),
                active_power: Some(4000),
                reactive_power: Some(-100),
                apparent_power: Some(4600),
                power_factor: 120,
            },
        );
        assert_eq!(
            alarms.as_slice(),
            &[ac::ALARM_CURRENT_OVERLOAD, ac::ALARM_ACTIVE_POWER_OVERLOAD]
        );
        assert_eq!(c.u16(ac::RMS_VOLTAGE_MAX.id), Some(230));
        assert_eq!(c.i16(ac::ACTIVE_POWER.id), Some(4000));
        assert_eq!(
            c.attributes.value(ac::POWER_FACTOR.id).unwrap().as_i64(),
            Some(100)
        );
        assert!(set_ac(&mut c, AcReading::default()).is_empty());
        assert_eq!(c.u16(ac::FREQUENCY.id), Some(ac::UNKNOWN_U16));
    }

    #[test]
    fn profile_codecs_round_trip() {
        let mut buf = [0u8; 32];
        let info = ProfileInfo {
            profile_count: 1,
            interval_period: interval_period::MINUTES_15,
            max_intervals: 8,
            attributes: &[0x0b, 0x05],
        };
        let n = info.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[1, 3, 8, 0x0b, 0x05]);
        assert_eq!(ProfileInfo::parse(&buf[..n]).unwrap(), info);
        let req = MeasurementProfileRequest {
            attribute: ac::ACTIVE_POWER.id,
            start_time: 0x1000_0000,
            intervals: 4,
        };
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(MeasurementProfileRequest::parse(&buf[..n]).unwrap(), req);
        let rsp = MeasurementProfile {
            start_time: 0x1000_0000,
            status: profile_status::SUCCESS,
            interval_period: interval_period::MINUTES_15,
            intervals_delivered: 2,
            attribute: ac::ACTIVE_POWER.id,
            intervals: &[0x10, 0x00, 0x20, 0x00],
        };
        let n = rsp.encode(&mut buf).unwrap();
        assert_eq!(MeasurementProfile::parse(&buf[..n]).unwrap(), rsp);
    }

    #[test]
    fn polyphase_totals_harmonics_and_voltage_quality() {
        let mut c: ClusterInstance<96> = server(Capability::AC).unwrap();
        enable_ac_extremes(&mut c).unwrap();
        enable_voltage_quality(&mut c).unwrap();
        enable_ac_totals(&mut c, Scale::UNITY, 3, -3).unwrap();
        enable_phase(&mut c, Phase::B).unwrap();
        enable_phase(&mut c, Phase::C).unwrap();
        assert!(enable_phase(&mut c, Phase::A).is_err());
        assert_eq!(
            c.u64(MEASUREMENT_TYPE.id).unwrap() & u64::from(measurement_type::PHASE_C),
            u64::from(measurement_type::PHASE_C)
        );
        assert_eq!(phase_attr(Phase::B, ac::RMS_VOLTAGE).id.0, 0x0905);
        assert_eq!(phase_attr(Phase::C, ac::POWER_FACTOR).id.0, 0x0a10);
        // Phase A extremes are tracked once enabled.
        let read = |v: u16, i: u16, p: i16| AcReading {
            frequency: Some(50),
            rms_voltage: Some(v),
            rms_current: Some(i),
            active_power: Some(p),
            reactive_power: Some(0),
            apparent_power: Some(0),
            power_factor: 100,
        };
        assert!(set_ac(&mut c, read(230, 10, 2300)).is_empty());
        set_ac(&mut c, read(231, 12, 2500));
        set_ac(&mut c, read(229, 8, 1800));
        assert_eq!(c.u16(ac::RMS_CURRENT_MIN.id), Some(8));
        assert_eq!(c.u16(ac::RMS_CURRENT_MAX.id), Some(12));
        assert_eq!(c.i16(ac::ACTIVE_POWER_MIN.id), Some(1800));
        assert_eq!(c.i16(ac::ACTIVE_POWER_MAX.id), Some(2500));
        // Voltage quality: a swell above 250 V and an average over
        // voltage above 245 V are counted and, when masked in, alarmed.
        c.set_i16(ac::RMS_VOLTAGE_SWELL.id, 250);
        c.set_i16(ac::AVERAGE_RMS_OVER_VOLTAGE.id, 245);
        c.set_i16(ac::RMS_VOLTAGE_SAG.id, 200);
        c.set(
            ac::ALARMS_MASK.id,
            &Value::Bits {
                width: 2,
                bits: (1 << ac::ALARM_RMS_VOLTAGE_SWELL) | (1 << ac::ALARM_RMS_VOLTAGE_SAG),
            },
        );
        let a = set_ac(&mut c, read(255, 10, 2300));
        assert_eq!(a.as_slice(), &[ac::ALARM_RMS_VOLTAGE_SWELL]);
        assert_eq!(c.u16(ac::AVERAGE_RMS_OVER_VOLTAGE_COUNTER.id), Some(1));
        let a = set_ac(&mut c, read(190, 10, 2300));
        assert_eq!(a.as_slice(), &[ac::ALARM_RMS_VOLTAGE_SAG]);
        assert_eq!(c.u16(ac::AVERAGE_RMS_OVER_VOLTAGE_COUNTER.id), Some(1));
        // Phases B / C and the totals.
        set_ac_phase(&mut c, Phase::B, read(228, 9, 2000));
        set_ac_phase(&mut c, Phase::C, read(232, 11, 2600));
        assert_eq!(c.u16(phase_attr(Phase::B, ac::RMS_VOLTAGE).id), Some(228));
        assert_eq!(c.i16(phase_attr(Phase::C, ac::ACTIVE_POWER).id), Some(2600));
        assert_eq!(
            c.u16(phase_attr(Phase::C, ac::RMS_VOLTAGE_MAX).id),
            Some(232)
        );
        set_ac_totals(
            &mut c,
            AcTotals {
                frequency: Some(50),
                neutral_current: Some(1),
                active_power: Some(6_900),
                reactive_power: Some(-100),
                apparent_power: Some(7_000),
            },
        );
        set_ac_totals(
            &mut c,
            AcTotals {
                frequency: Some(49),
                ..AcTotals::default()
            },
        );
        assert_eq!(c.u16(ac_total::FREQUENCY_MIN.id), Some(49));
        assert_eq!(c.u16(ac_total::FREQUENCY_MAX.id), Some(50));
        assert_eq!(
            c.attributes
                .value(ac_total::TOTAL_ACTIVE_POWER.id)
                .and_then(|v| v.as_i64()),
            Some(i64::from(ac_total::UNKNOWN_I32))
        );
        set_harmonics(&mut c, &[1000, 50, 20], &[0, 10, 20]);
        assert_eq!(c.i16(ac_total::HARMONIC_CURRENT[1].id), Some(50));
        assert_eq!(c.i16(ac_total::PHASE_HARMONIC_CURRENT[2].id), Some(20));
        assert!(
            c.attributes
                .get(ac_total::HARMONIC_CURRENT[3].id, None)
                .is_none()
        );
        assert_eq!(
            c.attributes
                .value(ac_total::HARMONIC_CURRENT_MULTIPLIER.id)
                .and_then(|v| v.as_i64()),
            Some(-3)
        );
        assert!(
            enable_ac_totals::<96>(&mut server(Capability::AC).unwrap(), Scale::UNITY, 7, 0)
                .is_err()
        );
    }
}
