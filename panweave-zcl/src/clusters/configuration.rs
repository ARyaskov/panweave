//! Configuration and small control clusters (ZCL8): Device Temperature
//! Configuration (§3.4), On/Off Switch Configuration (§3.9), Ballast
//! Configuration (§5.3), Pump Configuration and Control (§6.2),
//! Dehumidification Control (§6.5), Thermostat User Interface
//! Configuration (§6.6), Shade Configuration (§7.2) and Barrier Control
//! (§7.5). They are attribute servers with the range and consistency
//! rules of their tables enforced on writes; the alarm-raising ones
//! evaluate their thresholds against readings the application records.

use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, AttributeTable, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

const fn u8v(v: u8) -> Value<'static> {
    Value::Uint {
        width: 1,
        value: v as u64,
    }
}

const fn u16v(v: u16) -> Value<'static> {
    Value::Uint {
        width: 2,
        value: v as u64,
    }
}

const fn u24v(v: u32) -> Value<'static> {
    Value::Uint {
        width: 3,
        value: v as u64,
    }
}

const fn i16v(v: i16) -> Value<'static> {
    Value::Int {
        width: 2,
        value: v as i64,
    }
}

const fn bits8(v: u8) -> Value<'static> {
    Value::Bits {
        width: 1,
        bits: v as u64,
    }
}

const fn def(id: ClusterId, revision: u16) -> ClusterDef {
    ClusterDef {
        id,
        revision,
        received: &[],
        generated: &[],
    }
}

/// A dwell timer shared by the clusters that raise an alarm once a
/// reading has stayed beyond a threshold for a configured time.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Dwell {
    /// The alarm the current reading calls for and when it is due.
    pub pending: Option<(u8, Instant)>,
    /// The pending alarm was raised; nothing more until recovery.
    pub raised: bool,
}

impl Dwell {
    /// Records the alarm `condition` of a new reading at `now`
    /// (`secs` the dwell): `Some(code)` when it is due at once.
    fn update(&mut self, condition: Option<u8>, secs: u32, now: Instant) -> Option<u8> {
        match condition {
            None => {
                *self = Dwell::default();
                None
            }
            Some(code) => {
                match self.pending {
                    Some((pending, _)) if pending == code => {}
                    _ => {
                        self.pending = Some((code, now + Duration::from_secs(u64::from(secs))));
                        self.raised = false;
                    }
                }
                self.tick(now)
            }
        }
    }

    /// Raises the pending alarm once due; `None` otherwise.
    fn tick(&mut self, now: Instant) -> Option<u8> {
        let (code, due) = self.pending?;
        if self.raised || !now.has_reached(due) {
            return None;
        }
        self.raised = true;
        Some(code)
    }

    /// The timer to arm.
    const fn deadline(&self) -> Option<Instant> {
        match self.pending {
            Some((_, due)) if !self.raised => Some(due),
            _ => None,
        }
    }
}

/// Device Temperature Configuration cluster (§3.4).
pub mod device_temperature {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0002);
    /// `CurrentTemperature` (int16 °C, −200…200).
    pub const CURRENT_TEMPERATURE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Int(2), Access::RO);
    /// `MinTempExperienced`.
    pub const MIN_TEMP_EXPERIENCED: AttributeDef =
        AttributeDef::new(0x0001, DataType::Int(2), Access::RO);
    /// `MaxTempExperienced`.
    pub const MAX_TEMP_EXPERIENCED: AttributeDef =
        AttributeDef::new(0x0002, DataType::Int(2), Access::RO);
    /// `OverTempTotalDwell` (uint16 hours).
    pub const OVER_TEMP_TOTAL_DWELL: AttributeDef =
        AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
    /// `DeviceTempAlarmMask` (map8: bit 0 too low, bit 1 too high).
    pub const DEVICE_TEMP_ALARM_MASK: AttributeDef =
        AttributeDef::new(0x0010, DataType::Bitmap(1), Access::RW);
    /// `LowTempThreshold` (int16 °C).
    pub const LOW_TEMP_THRESHOLD: AttributeDef =
        AttributeDef::new(0x0011, DataType::Int(2), Access::RW);
    /// `HighTempThreshold` (int16 °C).
    pub const HIGH_TEMP_THRESHOLD: AttributeDef =
        AttributeDef::new(0x0012, DataType::Int(2), Access::RW);
    /// `LowTempDwellTripPoint` (uint24 seconds).
    pub const LOW_TEMP_DWELL_TRIP_POINT: AttributeDef =
        AttributeDef::new(0x0013, DataType::Uint(3), Access::RW);
    /// `HighTempDwellTripPoint` (uint24 seconds).
    pub const HIGH_TEMP_DWELL_TRIP_POINT: AttributeDef =
        AttributeDef::new(0x0014, DataType::Uint(3), Access::RW);

    /// Temperature non-value.
    pub const UNKNOWN: i16 = i16::MIN;
    /// Dwell non-value (alarm disabled).
    pub const NO_DWELL: u32 = 0x00ff_ffff;
    /// Alarm code: device temperature too low.
    pub const ALARM_TOO_LOW: u8 = 0x00;
    /// Alarm code: device temperature too high.
    pub const ALARM_TOO_HIGH: u8 = 0x01;
    /// `DeviceTempAlarmMask` bit: too low.
    pub const MASK_TOO_LOW: u8 = 0x01;
    /// `DeviceTempAlarmMask` bit: too high.
    pub const MASK_TOO_HIGH: u8 = 0x02;

    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID, 1);

    fn in_range(v: &Value<'_>) -> bool {
        v.as_i64()
            .is_some_and(|t| (-200..=200).contains(&t) || t == i64::from(UNKNOWN))
    }

    /// Write guard: temperatures within −200…200 (or the non-value),
    /// `LowTempThreshold` below `HighTempThreshold`, mask bits 0–1.
    fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let ok = match id {
            i if i == LOW_TEMP_THRESHOLD.id => {
                in_range(v)
                    && t.value(HIGH_TEMP_THRESHOLD.id)
                        .and_then(|h| h.as_i64())
                        .is_none_or(|h| {
                            h == i64::from(UNKNOWN) || v.as_i64().is_some_and(|l| l < h)
                        })
            }
            i if i == HIGH_TEMP_THRESHOLD.id => {
                in_range(v)
                    && t.value(LOW_TEMP_THRESHOLD.id)
                        .and_then(|l| l.as_i64())
                        .is_none_or(|l| {
                            l == i64::from(UNKNOWN) || v.as_i64().is_some_and(|h| h > l)
                        })
            }
            i if i == DEVICE_TEMP_ALARM_MASK.id => v.as_u64().is_some_and(|m| m <= 0x03),
            _ => true,
        };
        if ok {
            ZclStatus::Success
        } else {
            ZclStatus::InvalidValue
        }
    }

    /// Builds a server: the information set and, with `alarms`, the
    /// settings set (an Alarms server is then expected on the endpoint).
    pub fn server<const A: usize>(alarms: bool) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(CURRENT_TEMPERATURE, &i16v(UNKNOWN))?;
        c.add_attribute(MIN_TEMP_EXPERIENCED, &i16v(UNKNOWN))?;
        c.add_attribute(MAX_TEMP_EXPERIENCED, &i16v(UNKNOWN))?;
        c.add_attribute(OVER_TEMP_TOTAL_DWELL, &u16v(0))?;
        if alarms {
            c.add_attribute(DEVICE_TEMP_ALARM_MASK, &bits8(0))?;
            c.add_attribute(LOW_TEMP_THRESHOLD, &i16v(UNKNOWN))?;
            c.add_attribute(HIGH_TEMP_THRESHOLD, &i16v(UNKNOWN))?;
            c.add_attribute(LOW_TEMP_DWELL_TRIP_POINT, &u24v(NO_DWELL))?;
            c.add_attribute(HIGH_TEMP_DWELL_TRIP_POINT, &u24v(NO_DWELL))?;
            c.state = ClusterState::Dwell(Dwell::default());
        }
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    fn dwell_secs<const A: usize>(c: &ClusterInstance<A>, id: AttributeId) -> Option<u32> {
        c.u64(id)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|s| *s != NO_DWELL)
    }

    /// The alarm a reading calls for before the dwell (§3.4.2.2.2.2–3):
    /// below the low threshold or above the high one, with the
    /// threshold and dwell set and the mask bit on.
    fn condition<const A: usize>(c: &ClusterInstance<A>, temp: i16) -> Option<(u8, u32)> {
        let mask = c.u8(DEVICE_TEMP_ALARM_MASK.id).unwrap_or(0);
        let low = c.i16(LOW_TEMP_THRESHOLD.id).filter(|t| *t != UNKNOWN);
        let high = c.i16(HIGH_TEMP_THRESHOLD.id).filter(|t| *t != UNKNOWN);
        if let Some(l) = low
            && temp < l
            && mask & MASK_TOO_LOW != 0
            && let Some(secs) = dwell_secs(c, LOW_TEMP_DWELL_TRIP_POINT.id)
        {
            return Some((ALARM_TOO_LOW, secs));
        }
        if let Some(h) = high
            && temp > h
            && mask & MASK_TOO_HIGH != 0
            && let Some(secs) = dwell_secs(c, HIGH_TEMP_DWELL_TRIP_POINT.id)
        {
            return Some((ALARM_TOO_HIGH, secs));
        }
        None
    }

    /// Records the internal temperature (`None` = invalid): tracks the
    /// extremes experienced, runs the threshold dwell timers and returns
    /// the alarm code due now (the layer raises one due later from
    /// [`tick`]).
    pub fn set_temperature<const A: usize>(
        c: &mut ClusterInstance<A>,
        temp: Option<i16>,
        now: Instant,
    ) -> Option<u8> {
        let t = temp.unwrap_or(UNKNOWN);
        c.set_i16(CURRENT_TEMPERATURE.id, t);
        if let Some(t) = temp {
            let min = c.i16(MIN_TEMP_EXPERIENCED.id).unwrap_or(UNKNOWN);
            if min == UNKNOWN || t < min {
                c.set_i16(MIN_TEMP_EXPERIENCED.id, t);
            }
            let max = c.i16(MAX_TEMP_EXPERIENCED.id).unwrap_or(UNKNOWN);
            if max == UNKNOWN || t > max {
                c.set_i16(MAX_TEMP_EXPERIENCED.id, t);
            }
        }
        let condition = temp.and_then(|t| condition(c, t));
        let ClusterState::Dwell(d) = &mut c.state else {
            return None;
        };
        let due = match condition {
            Some((code, secs)) => d.update(Some(code), secs, now),
            None => d.update(None, 0, now),
        };
        c.tick = match &c.state {
            ClusterState::Dwell(d) => d.deadline(),
            _ => None,
        };
        due
    }

    /// Raises a threshold alarm whose dwell elapsed (`None` otherwise).
    pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<u8> {
        let ClusterState::Dwell(d) = &mut c.state else {
            return None;
        };
        let due = d.tick(now);
        c.tick = match &c.state {
            ClusterState::Dwell(d) => d.deadline(),
            _ => None,
        };
        due
    }
}

/// On/Off Switch Configuration cluster (§3.9).
pub mod switch_configuration {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0007);
    /// `SwitchType` (enum8, Table 3-52).
    pub const SWITCH_TYPE: AttributeDef = AttributeDef::new(0x0000, DataType::Enum8, Access::RO);
    /// `SwitchActions` (enum8, Table 3-54, writable).
    pub const SWITCH_ACTIONS: AttributeDef = AttributeDef::new(0x0010, DataType::Enum8, Access::RW);

    /// `SwitchType` values.
    pub mod switch_type {
        /// Toggle.
        pub const TOGGLE: u8 = 0x00;
        /// Momentary.
        pub const MOMENTARY: u8 = 0x01;
        /// Multifunction.
        pub const MULTIFUNCTION: u8 = 0x02;
    }

    /// `SwitchActions` values.
    pub mod switch_actions {
        /// On when arriving at state 2, Off at state 1.
        pub const ON_OFF: u8 = 0x00;
        /// Off at state 2, On at state 1.
        pub const OFF_ON: u8 = 0x01;
        /// Toggle either way.
        pub const TOGGLE: u8 = 0x02;
    }

    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID, 1);

    fn guard<const A: usize>(_t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        if id == SWITCH_ACTIONS.id && v.as_u64().is_none_or(|a| a > 2) {
            ZclStatus::InvalidValue
        } else {
            ZclStatus::Success
        }
    }

    /// Builds a server for a switch of `switch_type` (the endpoint also
    /// carries an On/Off client, §3.9.2.1).
    pub fn server<const A: usize>(switch_type: u8) -> Result<ClusterInstance<A>, ZclStatus> {
        if switch_type > switch_type::MULTIFUNCTION {
            return Err(ZclStatus::InvalidValue);
        }
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(SWITCH_TYPE, &Value::Enum8(switch_type))?;
        c.add_attribute(SWITCH_ACTIONS, &Value::Enum8(switch_actions::ON_OFF))?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    /// The On/Off command to send when the switch arrives at state 2
    /// (`to_state_2`) or returns to state 1 (Table 3-54).
    pub fn command_for<const A: usize>(c: &ClusterInstance<A>, to_state_2: bool) -> CommandId {
        use crate::clusters::on_off::{CMD_OFF, CMD_ON, CMD_TOGGLE};
        match (c.u8(SWITCH_ACTIONS.id).unwrap_or(0), to_state_2) {
            (switch_actions::ON_OFF, true) | (switch_actions::OFF_ON, false) => CMD_ON,
            (switch_actions::ON_OFF, false) | (switch_actions::OFF_ON, true) => CMD_OFF,
            _ => CMD_TOGGLE,
        }
    }
}

/// Ballast Configuration cluster (§5.3).
pub mod ballast {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0301);
    /// `PhysicalMinLevel` (uint8 1…254).
    pub const PHYSICAL_MIN_LEVEL: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(1), Access::RO);
    /// `PhysicalMaxLevel`.
    pub const PHYSICAL_MAX_LEVEL: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(1), Access::RO);
    /// `BallastStatus` (map8: bit 0 non-operational, bit 1 lamp failure).
    pub const BALLAST_STATUS: AttributeDef =
        AttributeDef::new(0x0002, DataType::Bitmap(1), Access::RO);
    /// `MinLevel` (uint8, ≥ PhysicalMinLevel, ≤ MaxLevel).
    pub const MIN_LEVEL: AttributeDef = AttributeDef::new(0x0010, DataType::Uint(1), Access::RW);
    /// `MaxLevel` (uint8, ≤ PhysicalMaxLevel, ≥ MinLevel).
    pub const MAX_LEVEL: AttributeDef = AttributeDef::new(0x0011, DataType::Uint(1), Access::RW);
    /// `PowerOnLevel` (deprecated).
    pub const POWER_ON_LEVEL: AttributeDef =
        AttributeDef::new(0x0012, DataType::Uint(1), Access::RW);
    /// `PowerOnFadeTime` (deprecated).
    pub const POWER_ON_FADE_TIME: AttributeDef =
        AttributeDef::new(0x0013, DataType::Uint(2), Access::RW);
    /// `IntrinsicBallastFactor` (uint8 %, 0xff invalid).
    pub const INTRINSIC_BALLAST_FACTOR: AttributeDef =
        AttributeDef::new(0x0014, DataType::Uint(1), Access::RW);
    /// `BallastFactorAdjustment` (uint8 %, ≥ 100, 0xff = not in use).
    pub const BALLAST_FACTOR_ADJUSTMENT: AttributeDef =
        AttributeDef::new(0x0015, DataType::Uint(1), Access::RW);
    /// `LampQuantity`.
    pub const LAMP_QUANTITY: AttributeDef =
        AttributeDef::new(0x0020, DataType::Uint(1), Access::RO);
    /// `LampType` (string ≤ 16).
    pub const LAMP_TYPE: AttributeDef = AttributeDef::new(0x0030, DataType::CharString, Access::RW);
    /// `LampManufacturer` (string ≤ 16).
    pub const LAMP_MANUFACTURER: AttributeDef =
        AttributeDef::new(0x0031, DataType::CharString, Access::RW);
    /// `LampRatedHours` (uint24, 0xffffff unknown).
    pub const LAMP_RATED_HOURS: AttributeDef =
        AttributeDef::new(0x0032, DataType::Uint(3), Access::RW);
    /// `LampBurnHours` (uint24).
    pub const LAMP_BURN_HOURS: AttributeDef =
        AttributeDef::new(0x0033, DataType::Uint(3), Access::RW);
    /// `LampAlarmMode` (map8: bit 0 LampBurnHours).
    pub const LAMP_ALARM_MODE: AttributeDef =
        AttributeDef::new(0x0034, DataType::Bitmap(1), Access::RW);
    /// `LampBurnHoursTripPoint` (uint24, 0xffffff = no alarm).
    pub const LAMP_BURN_HOURS_TRIP_POINT: AttributeDef =
        AttributeDef::new(0x0035, DataType::Uint(3), Access::RW);

    /// Unknown hours.
    pub const UNKNOWN_HOURS: u32 = 0x00ff_ffff;
    /// Factor not in use / invalid.
    pub const NO_FACTOR: u8 = 0xff;
    /// `BallastStatus` bit: not fully operational.
    pub const STATUS_NON_OPERATIONAL: u8 = 0x01;
    /// `BallastStatus` bit: lamp failure.
    pub const STATUS_LAMP_FAILURE: u8 = 0x02;
    /// Alarm code: lamp burn hours reached the trip point.
    pub const ALARM_LAMP_BURN_HOURS: u8 = 0x01;

    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID, 4);

    fn u8_of<const A: usize>(t: &AttributeTable<A>, id: AttributeId) -> Option<u64> {
        t.value(id).and_then(|v| v.as_u64())
    }

    /// Write guard (§5.3.2.2.2): `MinLevel` within PhysicalMinLevel…
    /// MaxLevel, `MaxLevel` within MinLevel…PhysicalMaxLevel, the
    /// adjustment ≥ 100 % or not in use, strings ≤ 16, hours ≤ 0xfffffe
    /// (trip point may be the non-value), the alarm mode bit 0.
    fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = v.as_u64().unwrap_or(u64::MAX);
        let ok = match id {
            i if i == MIN_LEVEL.id => {
                let lo = u8_of(t, PHYSICAL_MIN_LEVEL.id).unwrap_or(1);
                let hi = u8_of(t, MAX_LEVEL.id).unwrap_or(0xfe);
                (lo..=hi).contains(&val)
            }
            i if i == MAX_LEVEL.id => {
                let lo = u8_of(t, MIN_LEVEL.id).unwrap_or(1);
                let hi = u8_of(t, PHYSICAL_MAX_LEVEL.id).unwrap_or(0xfe);
                (lo..=hi).contains(&val)
            }
            i if i == INTRINSIC_BALLAST_FACTOR.id => val <= 0xfe || val == u64::from(NO_FACTOR),
            i if i == BALLAST_FACTOR_ADJUSTMENT.id => {
                (0x64..=0xfe).contains(&val) || val == u64::from(NO_FACTOR)
            }
            i if i == LAMP_TYPE.id || i == LAMP_MANUFACTURER.id => {
                matches!(v, Value::String { bytes: Some(b), .. } if b.len() <= 16)
            }
            i if i == LAMP_RATED_HOURS.id || i == LAMP_BURN_HOURS.id => val <= 0x00ff_fffe,
            i if i == LAMP_BURN_HOURS_TRIP_POINT.id => val <= 0x00ff_ffff,
            i if i == LAMP_ALARM_MODE.id => val <= 0x01,
            _ => true,
        };
        if ok {
            ZclStatus::Success
        } else {
            ZclStatus::InvalidValue
        }
    }

    /// Builds a server for a ballast with the given physical level range
    /// and lamp count: the ballast information / settings sets and the
    /// lamp information / settings sets.
    pub fn server<const A: usize>(
        physical_min: u8,
        physical_max: u8,
        lamps: u8,
    ) -> Result<ClusterInstance<A>, ZclStatus> {
        if physical_min == 0 || physical_max == 0xff || physical_min > physical_max {
            return Err(ZclStatus::InvalidValue);
        }
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(PHYSICAL_MIN_LEVEL, &u8v(physical_min))?;
        c.add_attribute(PHYSICAL_MAX_LEVEL, &u8v(physical_max))?;
        c.add_attribute(BALLAST_STATUS, &bits8(0))?;
        c.add_attribute(MIN_LEVEL, &u8v(physical_min))?;
        c.add_attribute(MAX_LEVEL, &u8v(physical_max))?;
        c.add_attribute(INTRINSIC_BALLAST_FACTOR, &u8v(NO_FACTOR))?;
        c.add_attribute(BALLAST_FACTOR_ADJUSTMENT, &u8v(NO_FACTOR))?;
        c.add_attribute(LAMP_QUANTITY, &u8v(lamps))?;
        let empty = Value::String {
            ty: DataType::CharString,
            bytes: Some(&[]),
        };
        c.add_attribute(LAMP_TYPE, &empty)?;
        c.add_attribute(LAMP_MANUFACTURER, &empty)?;
        c.add_attribute(LAMP_RATED_HOURS, &u24v(UNKNOWN_HOURS))?;
        c.add_attribute(LAMP_BURN_HOURS, &u24v(0))?;
        c.add_attribute(LAMP_ALARM_MODE, &bits8(0))?;
        c.add_attribute(LAMP_BURN_HOURS_TRIP_POINT, &u24v(UNKNOWN_HOURS))?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    /// Sets `BallastStatus`.
    pub fn set_status<const A: usize>(c: &mut ClusterInstance<A>, status: u8) -> bool {
        c.set(BALLAST_STATUS.id, &bits8(status & 0x03))
    }

    /// Adds `hours` of lamp operation to `LampBurnHours` (saturating at
    /// the range) and returns the alarm code when the trip point is
    /// reached with `LampAlarmMode` bit 0 set (§5.3.2.2.4.6), once per
    /// crossing.
    pub fn add_burn_hours<const A: usize>(c: &mut ClusterInstance<A>, hours: u32) -> Option<u8> {
        let before = c
            .u64(LAMP_BURN_HOURS.id)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0);
        if before == UNKNOWN_HOURS {
            return None;
        }
        let after = before.saturating_add(hours).min(0x00ff_fffe);
        c.set(LAMP_BURN_HOURS.id, &u24v(after));
        let trip = c
            .u64(LAMP_BURN_HOURS_TRIP_POINT.id)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(UNKNOWN_HOURS);
        let armed = c.u8(LAMP_ALARM_MODE.id).unwrap_or(0) & 0x01 != 0;
        (armed && trip != UNKNOWN_HOURS && before < trip && after >= trip)
            .then_some(ALARM_LAMP_BURN_HOURS)
    }

    /// The light output for a Level Control `CurrentLevel` (1…254) on
    /// the ballast's dimming curve between `MinLevel` and `MaxLevel`
    /// (§5.3.2.2.2.1–2), scaled by `BallastFactorAdjustment` when in use.
    pub fn output_for_level<const A: usize>(c: &ClusterInstance<A>, level: u8) -> u8 {
        let min = u32::from(c.u8(MIN_LEVEL.id).unwrap_or(1));
        let max = u32::from(c.u8(MAX_LEVEL.id).unwrap_or(0xfe));
        let level = u32::from(level.clamp(1, 0xfe));
        let out = min + (max.saturating_sub(min)) * (level - 1) / 253;
        let adjust = c.u8(BALLAST_FACTOR_ADJUSTMENT.id).unwrap_or(NO_FACTOR);
        let out = if adjust == NO_FACTOR {
            out
        } else {
            out * u32::from(adjust) / 100
        };
        u8::try_from(out.min(0xfe)).unwrap_or(0xfe)
    }
}

/// Pump Configuration and Control cluster (§6.2).
pub mod pump {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0200);
    /// `MaxPressure` (int16 kPa).
    pub const MAX_PRESSURE: AttributeDef = AttributeDef::new(0x0000, DataType::Int(2), Access::RO);
    /// `MaxSpeed` (uint16 RPM).
    pub const MAX_SPEED: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
    /// `MaxFlow` (uint16 m³/h × 10).
    pub const MAX_FLOW: AttributeDef = AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
    /// `MinConstPressure`.
    pub const MIN_CONST_PRESSURE: AttributeDef =
        AttributeDef::new(0x0003, DataType::Int(2), Access::RO);
    /// `MaxConstPressure`.
    pub const MAX_CONST_PRESSURE: AttributeDef =
        AttributeDef::new(0x0004, DataType::Int(2), Access::RO);
    /// `MinCompPressure`.
    pub const MIN_COMP_PRESSURE: AttributeDef =
        AttributeDef::new(0x0005, DataType::Int(2), Access::RO);
    /// `MaxCompPressure`.
    pub const MAX_COMP_PRESSURE: AttributeDef =
        AttributeDef::new(0x0006, DataType::Int(2), Access::RO);
    /// `MinConstSpeed`.
    pub const MIN_CONST_SPEED: AttributeDef =
        AttributeDef::new(0x0007, DataType::Uint(2), Access::RO);
    /// `MaxConstSpeed`.
    pub const MAX_CONST_SPEED: AttributeDef =
        AttributeDef::new(0x0008, DataType::Uint(2), Access::RO);
    /// `MinConstFlow`.
    pub const MIN_CONST_FLOW: AttributeDef =
        AttributeDef::new(0x0009, DataType::Uint(2), Access::RO);
    /// `MaxConstFlow`.
    pub const MAX_CONST_FLOW: AttributeDef =
        AttributeDef::new(0x000a, DataType::Uint(2), Access::RO);
    /// `MinConstTemp` (int16 0.01 °C).
    pub const MIN_CONST_TEMP: AttributeDef =
        AttributeDef::new(0x000b, DataType::Int(2), Access::RO);
    /// `MaxConstTemp`.
    pub const MAX_CONST_TEMP: AttributeDef =
        AttributeDef::new(0x000c, DataType::Int(2), Access::RO);
    /// `PumpStatus` (map16, Table 6-5, reportable).
    pub const PUMP_STATUS: AttributeDef =
        AttributeDef::new(0x0010, DataType::Bitmap(2), Access::RO_REPORT);
    /// `EffectiveOperationMode` (enum8).
    pub const EFFECTIVE_OPERATION_MODE: AttributeDef =
        AttributeDef::new(0x0011, DataType::Enum8, Access::RO);
    /// `EffectiveControlMode` (enum8).
    pub const EFFECTIVE_CONTROL_MODE: AttributeDef =
        AttributeDef::new(0x0012, DataType::Enum8, Access::RO);
    /// `Capacity` (int16 0.5 %, reportable).
    pub const CAPACITY: AttributeDef =
        AttributeDef::new(0x0013, DataType::Int(2), Access::RO_REPORT);
    /// `Speed` (uint16 RPM).
    pub const SPEED: AttributeDef = AttributeDef::new(0x0014, DataType::Uint(2), Access::RO);
    /// `LifetimeRunningHours` (uint24, writable to reset).
    pub const LIFETIME_RUNNING_HOURS: AttributeDef =
        AttributeDef::new(0x0015, DataType::Uint(3), Access::RW);
    /// `Power` (uint24 W).
    pub const POWER: AttributeDef = AttributeDef::new(0x0016, DataType::Uint(3), Access::RW);
    /// `LifetimeEnergyConsumed` (uint32 kWh).
    pub const LIFETIME_ENERGY_CONSUMED: AttributeDef =
        AttributeDef::new(0x0017, DataType::Uint(4), Access::RO);
    /// `OperationMode` (enum8, Table 6-7).
    pub const OPERATION_MODE: AttributeDef = AttributeDef::new(0x0020, DataType::Enum8, Access::RW);
    /// `ControlMode` (enum8, Table 6-8).
    pub const CONTROL_MODE: AttributeDef = AttributeDef::new(0x0021, DataType::Enum8, Access::RW);
    /// `AlarmMask` (map16, one bit per Table 6-9 code).
    pub const ALARM_MASK: AttributeDef = AttributeDef::new(0x0022, DataType::Bitmap(2), Access::RO);

    /// `OperationMode` values (Table 6-7).
    pub mod operation_mode {
        /// Normal: controlled by the setpoint.
        pub const NORMAL: u8 = 0;
        /// Minimum speed.
        pub const MINIMUM: u8 = 1;
        /// Maximum speed.
        pub const MAXIMUM: u8 = 2;
        /// Local settings.
        pub const LOCAL: u8 = 3;
    }

    /// `ControlMode` values (Table 6-8).
    pub mod control_mode {
        /// Constant speed.
        pub const CONSTANT_SPEED: u8 = 0;
        /// Constant pressure.
        pub const CONSTANT_PRESSURE: u8 = 1;
        /// Proportional pressure.
        pub const PROPORTIONAL_PRESSURE: u8 = 2;
        /// Constant flow.
        pub const CONSTANT_FLOW: u8 = 3;
        /// Constant temperature.
        pub const CONSTANT_TEMPERATURE: u8 = 5;
        /// Automatic.
        pub const AUTOMATIC: u8 = 7;
    }

    /// `PumpStatus` bits (Table 6-5).
    pub mod status {
        /// Device fault.
        pub const DEVICE_FAULT: u16 = 1 << 0;
        /// Supply fault.
        pub const SUPPLY_FAULT: u16 = 1 << 1;
        /// Setpoint too low to achieve.
        pub const SPEED_LOW: u16 = 1 << 2;
        /// Setpoint too high to achieve.
        pub const SPEED_HIGH: u16 = 1 << 3;
        /// Overridden by local control.
        pub const LOCAL_OVERRIDE: u16 = 1 << 4;
        /// Running.
        pub const RUNNING: u16 = 1 << 5;
        /// A remote pressure sensor regulates the pump.
        pub const REMOTE_PRESSURE: u16 = 1 << 6;
        /// A remote flow sensor regulates the pump.
        pub const REMOTE_FLOW: u16 = 1 << 7;
        /// A remote temperature sensor regulates the pump.
        pub const REMOTE_TEMPERATURE: u16 = 1 << 8;
    }

    /// Alarm codes (Table 6-9); the `AlarmMask` bit is the code.
    pub mod alarm_code {
        /// Supply voltage too low.
        pub const SUPPLY_VOLTAGE_TOO_LOW: u8 = 0;
        /// Supply voltage too high.
        pub const SUPPLY_VOLTAGE_TOO_HIGH: u8 = 1;
        /// Power missing phase.
        pub const POWER_MISSING_PHASE: u8 = 2;
        /// System pressure too low.
        pub const SYSTEM_PRESSURE_TOO_LOW: u8 = 3;
        /// System pressure too high.
        pub const SYSTEM_PRESSURE_TOO_HIGH: u8 = 4;
        /// Dry running.
        pub const DRY_RUNNING: u8 = 5;
        /// Motor temperature too high.
        pub const MOTOR_TEMPERATURE_TOO_HIGH: u8 = 6;
        /// Pump motor fatal failure.
        pub const MOTOR_FATAL_FAILURE: u8 = 7;
        /// Electronic temperature too high.
        pub const ELECTRONIC_TEMPERATURE_TOO_HIGH: u8 = 8;
        /// Pump blocked.
        pub const PUMP_BLOCKED: u8 = 9;
        /// Sensor failure.
        pub const SENSOR_FAILURE: u8 = 10;
        /// Electronic non-fatal failure.
        pub const ELECTRONIC_NON_FATAL_FAILURE: u8 = 11;
        /// Electronic fatal failure.
        pub const ELECTRONIC_FATAL_FAILURE: u8 = 12;
        /// General fault.
        pub const GENERAL_FAULT: u8 = 13;
        /// Highest code.
        pub const MAX: u8 = 13;
    }

    /// The physical limits of a pump (the mandatory information set).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Limits {
        /// `MaxPressure` (kPa).
        pub max_pressure: i16,
        /// `MaxSpeed` (RPM).
        pub max_speed: u16,
        /// `MaxFlow` (m³/h × 10).
        pub max_flow: u16,
    }

    /// Default reporting of `PumpStatus` and `Capacity` (§6.2.2.4).
    pub const REPORTING: DefaultReporting = DefaultReporting {
        min: 10,
        max: 300,
        change: 2,
    };

    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID, 3);

    /// A remote sensor the pump may be connected to (§6.2.2.2.3.1).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum RemoteSensor {
        /// Pressure sensor.
        Pressure,
        /// Flow sensor.
        Flow,
        /// Temperature sensor.
        Temperature,
    }

    fn guard<const A: usize>(_t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = v.as_u64().unwrap_or(u64::MAX);
        let ok = match id {
            i if i == OPERATION_MODE.id => val <= u64::from(operation_mode::LOCAL),
            i if i == CONTROL_MODE.id => matches!(val, 0 | 1 | 2 | 3 | 5 | 7),
            i if i == LIFETIME_RUNNING_HOURS.id || i == POWER.id => val <= 0x00ff_fffe,
            _ => true,
        };
        if ok {
            ZclStatus::Success
        } else {
            ZclStatus::InvalidValue
        }
    }

    /// Builds a server with the mandatory information, dynamic
    /// information and settings attributes; `alarm_mask` names the
    /// alarms the pump can raise.
    pub fn server<const A: usize>(
        limits: Limits,
        alarm_mask: u16,
    ) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(MAX_PRESSURE, &i16v(limits.max_pressure))?;
        c.add_attribute(MAX_SPEED, &u16v(limits.max_speed))?;
        c.add_attribute(MAX_FLOW, &u16v(limits.max_flow))?;
        c.add_reported_attribute(PUMP_STATUS, &Value::Bits { width: 2, bits: 0 }, REPORTING)?;
        c.add_attribute(
            EFFECTIVE_OPERATION_MODE,
            &Value::Enum8(operation_mode::NORMAL),
        )?;
        c.add_attribute(
            EFFECTIVE_CONTROL_MODE,
            &Value::Enum8(control_mode::CONSTANT_SPEED),
        )?;
        c.add_reported_attribute(CAPACITY, &i16v(0), REPORTING)?;
        c.add_attribute(OPERATION_MODE, &Value::Enum8(operation_mode::NORMAL))?;
        c.add_attribute(CONTROL_MODE, &Value::Enum8(control_mode::CONSTANT_SPEED))?;
        c.add_attribute(
            ALARM_MASK,
            &Value::Bits {
                width: 2,
                bits: u64::from(alarm_mask & 0x3fff),
            },
        )?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    /// Resolves the effective operation and control modes (Figure 6-3):
    /// Minimum / Maximum / Local operation modes decide themselves; in
    /// Normal a connected remote sensor decides the control mode, else
    /// `ControlMode` does. Updates the effective attributes and the
    /// remote-sensor status bits; returns `(operation, control)`.
    pub fn resolve_modes<const A: usize>(
        c: &mut ClusterInstance<A>,
        remote: Option<RemoteSensor>,
    ) -> (u8, u8) {
        let op = c.u8(OPERATION_MODE.id).unwrap_or(operation_mode::NORMAL);
        let configured = c
            .u8(CONTROL_MODE.id)
            .unwrap_or(control_mode::CONSTANT_SPEED);
        let control = match (op, remote) {
            (operation_mode::NORMAL, Some(RemoteSensor::Pressure)) => {
                control_mode::CONSTANT_PRESSURE
            }
            (operation_mode::NORMAL, Some(RemoteSensor::Flow)) => control_mode::CONSTANT_FLOW,
            (operation_mode::NORMAL, Some(RemoteSensor::Temperature)) => {
                control_mode::CONSTANT_TEMPERATURE
            }
            _ => configured,
        };
        c.set(EFFECTIVE_OPERATION_MODE.id, &Value::Enum8(op));
        c.set(EFFECTIVE_CONTROL_MODE.id, &Value::Enum8(control));
        let remote_bits = match (op, remote) {
            (operation_mode::NORMAL, Some(RemoteSensor::Pressure)) => status::REMOTE_PRESSURE,
            (operation_mode::NORMAL, Some(RemoteSensor::Flow)) => status::REMOTE_FLOW,
            (operation_mode::NORMAL, Some(RemoteSensor::Temperature)) => status::REMOTE_TEMPERATURE,
            _ => 0,
        };
        let current = c.u16(PUMP_STATUS.id).unwrap_or(0);
        let status = (current
            & !(status::REMOTE_PRESSURE | status::REMOTE_FLOW | status::REMOTE_TEMPERATURE))
            | remote_bits;
        set_status(c, status);
        (op, control)
    }

    /// Sets `PumpStatus`; returns whether it changed.
    pub fn set_status<const A: usize>(c: &mut ClusterInstance<A>, status: u16) -> bool {
        c.set(
            PUMP_STATUS.id,
            &Value::Bits {
                width: 2,
                bits: u64::from(status),
            },
        )
    }

    /// Records the running state: `Capacity` (0.5 %), `Speed` and the
    /// Running status bit.
    pub fn set_running<const A: usize>(c: &mut ClusterInstance<A>, capacity: i16, speed: u16) {
        c.set_i16(CAPACITY.id, capacity);
        if c.attributes.get(SPEED.id, None).is_some() {
            c.set_u16(SPEED.id, speed);
        }
        let current = c.u16(PUMP_STATUS.id).unwrap_or(0);
        let status = if capacity > 0 {
            current | status::RUNNING
        } else {
            current & !status::RUNNING
        };
        set_status(c, status);
    }

    /// The alarm code to raise for a Table 6-9 condition when its
    /// `AlarmMask` bit is set; the matching fault status bit is set.
    pub fn alarm<const A: usize>(c: &mut ClusterInstance<A>, code: u8) -> Option<u8> {
        if code > alarm_code::MAX {
            return None;
        }
        let fault = if (alarm_code::MOTOR_TEMPERATURE_TOO_HIGH
            ..=alarm_code::ELECTRONIC_FATAL_FAILURE)
            .contains(&code)
        {
            status::DEVICE_FAULT
        } else {
            status::SUPPLY_FAULT
        };
        let current = c.u16(PUMP_STATUS.id).unwrap_or(0);
        set_status(c, current | fault);
        let mask = c.u16(ALARM_MASK.id).unwrap_or(0);
        (mask & (1 << code) != 0).then_some(code)
    }
}

/// Dehumidification Control cluster (§6.5).
pub mod dehumidification {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0203);
    /// `RelativeHumidity` (uint8 %, 0…100).
    pub const RELATIVE_HUMIDITY: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(1), Access::RO);
    /// `DehumidificationCooling` (uint8 %, reportable).
    pub const DEHUMIDIFICATION_COOLING: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(1), Access::RO_REPORT);
    /// `RHDehumidificationSetpoint` (uint8 %, 30…100).
    pub const RH_DEHUMIDIFICATION_SETPOINT: AttributeDef =
        AttributeDef::new(0x0010, DataType::Uint(1), Access::RW);
    /// `RelativeHumidityMode` (enum8, Table 6-46).
    pub const RELATIVE_HUMIDITY_MODE: AttributeDef =
        AttributeDef::new(0x0011, DataType::Enum8, Access::RW);
    /// `DehumidificationLockout` (enum8, Table 6-47).
    pub const DEHUMIDIFICATION_LOCKOUT: AttributeDef =
        AttributeDef::new(0x0012, DataType::Enum8, Access::RW);
    /// `DehumidificationHysteresis` (uint8 %, 2…20).
    pub const DEHUMIDIFICATION_HYSTERESIS: AttributeDef =
        AttributeDef::new(0x0013, DataType::Uint(1), Access::RW);
    /// `DehumidificationMaxCool` (uint8 %, 20…100).
    pub const DEHUMIDIFICATION_MAX_COOL: AttributeDef =
        AttributeDef::new(0x0014, DataType::Uint(1), Access::RW);
    /// `RelativeHumidityDisplay` (enum8, Table 6-48).
    pub const RELATIVE_HUMIDITY_DISPLAY: AttributeDef =
        AttributeDef::new(0x0015, DataType::Enum8, Access::RW);

    /// Default reporting of `DehumidificationCooling` (§6.5.2.3: on a
    /// change of 1 %).
    pub const COOLING_REPORTING: DefaultReporting = DefaultReporting {
        min: 10,
        max: 300,
        change: 1,
    };

    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID, 2);

    fn guard<const A: usize>(_t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = v.as_u64().unwrap_or(u64::MAX);
        let ok = match id {
            i if i == RH_DEHUMIDIFICATION_SETPOINT.id => (0x1e..=0x64).contains(&val),
            i if i == DEHUMIDIFICATION_HYSTERESIS.id => (0x02..=0x14).contains(&val),
            i if i == DEHUMIDIFICATION_MAX_COOL.id => (0x14..=0x64).contains(&val),
            i if i == RELATIVE_HUMIDITY_MODE.id
                || i == DEHUMIDIFICATION_LOCKOUT.id
                || i == RELATIVE_HUMIDITY_DISPLAY.id =>
            {
                val <= 1
            }
            _ => true,
        };
        if ok {
            ZclStatus::Success
        } else {
            ZclStatus::InvalidValue
        }
    }

    /// Builds a server with the full attribute set at its defaults.
    pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(RELATIVE_HUMIDITY, &u8v(0))?;
        c.add_reported_attribute(DEHUMIDIFICATION_COOLING, &u8v(0), COOLING_REPORTING)?;
        c.add_attribute(RH_DEHUMIDIFICATION_SETPOINT, &u8v(0x32))?;
        c.add_attribute(RELATIVE_HUMIDITY_MODE, &Value::Enum8(0))?;
        c.add_attribute(DEHUMIDIFICATION_LOCKOUT, &Value::Enum8(1))?;
        c.add_attribute(DEHUMIDIFICATION_HYSTERESIS, &u8v(0x02))?;
        c.add_attribute(DEHUMIDIFICATION_MAX_COOL, &u8v(0x14))?;
        c.add_attribute(RELATIVE_HUMIDITY_DISPLAY, &Value::Enum8(0))?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    /// Records the relative humidity (0…100 %) and derives the cooling
    /// demand: full `DehumidificationMaxCool` above the setpoint, none
    /// once the humidity has fallen by the hysteresis below it, the
    /// previous demand in between; nothing while locked out. Returns
    /// the demand.
    pub fn set_humidity<const A: usize>(c: &mut ClusterInstance<A>, humidity: u8) -> u8 {
        let h = humidity.min(100);
        c.set_u8(RELATIVE_HUMIDITY.id, h);
        let setpoint = c.u8(RH_DEHUMIDIFICATION_SETPOINT.id).unwrap_or(0x32);
        let hysteresis = c.u8(DEHUMIDIFICATION_HYSTERESIS.id).unwrap_or(2);
        let max_cool = c.u8(DEHUMIDIFICATION_MAX_COOL.id).unwrap_or(0x14);
        let allowed = c.u8(DEHUMIDIFICATION_LOCKOUT.id).unwrap_or(1) == 1;
        let previous = c.u8(DEHUMIDIFICATION_COOLING.id).unwrap_or(0);
        let demand = if !allowed {
            0
        } else if h > setpoint {
            max_cool
        } else if h + hysteresis <= setpoint {
            0
        } else {
            previous.min(max_cool)
        };
        c.set_u8(DEHUMIDIFICATION_COOLING.id, demand);
        demand
    }
}

/// Thermostat User Interface Configuration cluster (§6.6).
pub mod thermostat_ui {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0204);
    /// `TemperatureDisplayMode` (enum8: 0 °C, 1 °F).
    pub const TEMPERATURE_DISPLAY_MODE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Enum8, Access::RW);
    /// `KeypadLockout` (enum8: 0 none … 5 least functionality).
    pub const KEYPAD_LOCKOUT: AttributeDef = AttributeDef::new(0x0001, DataType::Enum8, Access::RW);
    /// `ScheduleProgrammingVisibility` (enum8: 0 enabled, 1 disabled).
    pub const SCHEDULE_PROGRAMMING_VISIBILITY: AttributeDef =
        AttributeDef::new(0x0002, DataType::Enum8, Access::RW);

    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID, 2);

    fn guard<const A: usize>(_t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = v.as_u64().unwrap_or(u64::MAX);
        let ok = match id {
            i if i == TEMPERATURE_DISPLAY_MODE.id => val <= 1,
            i if i == KEYPAD_LOCKOUT.id => val <= 5,
            i if i == SCHEDULE_PROGRAMMING_VISIBILITY.id => val <= 1,
            _ => true,
        };
        if ok {
            ZclStatus::Success
        } else {
            ZclStatus::InvalidValue
        }
    }

    /// Builds a server (Celsius, no lockout, schedule programming
    /// visible; the optional visibility attribute is included).
    pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(TEMPERATURE_DISPLAY_MODE, &Value::Enum8(0))?;
        c.add_attribute(KEYPAD_LOCKOUT, &Value::Enum8(0))?;
        c.add_attribute(SCHEDULE_PROGRAMMING_VISIBILITY, &Value::Enum8(0))?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }
}

/// Shade Configuration cluster (§7.2).
pub mod shade {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0100);
    /// `PhysicalClosedLimit` (uint16 steps).
    pub const PHYSICAL_CLOSED_LIMIT: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(2), Access::RO);
    /// `MotorStepSize` (uint8).
    pub const MOTOR_STEP_SIZE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(1), Access::RO);
    /// `Status` (map8, Table 7-4).
    pub const STATUS: AttributeDef = AttributeDef::new(0x0002, DataType::Bitmap(1), Access::RW);
    /// `ClosedLimit` (uint16 steps, writable).
    pub const CLOSED_LIMIT: AttributeDef = AttributeDef::new(0x0010, DataType::Uint(2), Access::RW);
    /// `Mode` (enum8: 0 normal, 1 configure).
    pub const MODE: AttributeDef = AttributeDef::new(0x0011, DataType::Enum8, Access::RW);

    /// `Status` bits (Table 7-4).
    pub mod status {
        /// Shade operational.
        pub const OPERATIONAL: u8 = 0x01;
        /// Shade adjusting.
        pub const ADJUSTING: u8 = 0x02;
        /// Shade direction (1 = opening).
        pub const DIRECTION: u8 = 0x04;
        /// Forward direction of the motor (1 = opening; writable).
        pub const MOTOR_FORWARD: u8 = 0x08;
    }

    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID, 2);

    /// Write guard: only the motor-direction bit of `Status` is
    /// writable, `Mode` is 0 or 1, `ClosedLimit` is 1…0xfffe.
    fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = v.as_u64().unwrap_or(u64::MAX);
        let ok = match id {
            i if i == STATUS.id => {
                let current = t.value(STATUS.id).and_then(|s| s.as_u64()).unwrap_or(0);
                val <= 0x0f && (val ^ current) & !u64::from(status::MOTOR_FORWARD) == 0
            }
            i if i == MODE.id => val <= 1,
            i if i == CLOSED_LIMIT.id => (1..=0xfffe).contains(&val),
            _ => true,
        };
        if ok {
            ZclStatus::Success
        } else {
            ZclStatus::InvalidValue
        }
    }

    /// Builds a server for a shade whose motor takes `closed_limit`
    /// steps of `step_size` to close.
    pub fn server<const A: usize>(
        closed_limit: u16,
        step_size: u8,
    ) -> Result<ClusterInstance<A>, ZclStatus> {
        if closed_limit == 0 || closed_limit == 0xffff {
            return Err(ZclStatus::InvalidValue);
        }
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(PHYSICAL_CLOSED_LIMIT, &u16v(closed_limit))?;
        c.add_attribute(MOTOR_STEP_SIZE, &u8v(step_size))?;
        c.add_attribute(STATUS, &bits8(status::OPERATIONAL))?;
        c.add_attribute(CLOSED_LIMIT, &u16v(closed_limit))?;
        c.add_attribute(MODE, &Value::Enum8(0))?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    /// Records the motion state: adjusting and its direction (`opening`).
    pub fn set_motion<const A: usize>(c: &mut ClusterInstance<A>, adjusting: bool, opening: bool) {
        let mut s = c.u8(STATUS.id).unwrap_or(0) & !(status::ADJUSTING | status::DIRECTION);
        if adjusting {
            s |= status::ADJUSTING;
        }
        if opening {
            s |= status::DIRECTION;
        }
        c.set(STATUS.id, &bits8(s));
    }
}

/// Barrier Control cluster (§7.5).
pub mod barrier_control {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0103);
    /// `MovingState` (enum8, Table 7-47, reportable).
    pub const MOVING_STATE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Enum8, Access::RO_REPORT);
    /// `SafetyStatus` (map16, Table 7-48, reportable).
    pub const SAFETY_STATUS: AttributeDef =
        AttributeDef::new(0x0002, DataType::Bitmap(2), Access::RO_REPORT);
    /// `Capabilities` (map8: bit 0 partial barrier).
    pub const CAPABILITIES: AttributeDef =
        AttributeDef::new(0x0003, DataType::Bitmap(1), Access::RO);
    /// `OpenEvents`.
    pub const OPEN_EVENTS: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(2), Access::RW);
    /// `CloseEvents`.
    pub const CLOSE_EVENTS: AttributeDef = AttributeDef::new(0x0005, DataType::Uint(2), Access::RW);
    /// `CommandOpenEvents`.
    pub const COMMAND_OPEN_EVENTS: AttributeDef =
        AttributeDef::new(0x0006, DataType::Uint(2), Access::RW);
    /// `CommandCloseEvents`.
    pub const COMMAND_CLOSE_EVENTS: AttributeDef =
        AttributeDef::new(0x0007, DataType::Uint(2), Access::RW);
    /// `OpenPeriod` (uint16 tenths of a second).
    pub const OPEN_PERIOD: AttributeDef = AttributeDef::new(0x0008, DataType::Uint(2), Access::RW);
    /// `ClosePeriod`.
    pub const CLOSE_PERIOD: AttributeDef = AttributeDef::new(0x0009, DataType::Uint(2), Access::RW);
    /// `BarrierPosition` (uint8 % open, 0xff unknown, reportable, scene).
    pub const BARRIER_POSITION: AttributeDef =
        AttributeDef::new(0x000a, DataType::Uint(1), Access::RO_REPORT);

    /// Go To Percent.
    pub const CMD_GO_TO_PERCENT: CommandId = CommandId(0x00);
    /// Stop.
    pub const CMD_STOP: CommandId = CommandId(0x01);

    /// `MovingState` values.
    pub mod moving_state {
        /// Stopped.
        pub const STOPPED: u8 = 0x00;
        /// Closing.
        pub const CLOSING: u8 = 0x01;
        /// Opening.
        pub const OPENING: u8 = 0x02;
    }

    /// `SafetyStatus` bits (the bit is the alarm code).
    pub mod safety {
        /// Remote lockout: commands are ignored.
        pub const REMOTE_LOCKOUT: u16 = 1 << 0;
        /// Tamper detected.
        pub const TAMPER_DETECTED: u16 = 1 << 1;
        /// Failed communication with safety equipment.
        pub const FAILED_COMMUNICATION: u16 = 1 << 2;
        /// Position failure.
        pub const POSITION_FAILURE: u16 = 1 << 3;
    }

    /// `Capabilities` bit: partial positions supported.
    pub const CAPABILITY_PARTIAL_BARRIER: u8 = 0x01;
    /// Unknown position.
    pub const POSITION_UNKNOWN: u8 = 0xff;
    /// Event counters stick at this value (§7.5.2.1.4).
    pub const EVENTS_MAX: u16 = 0xfffe;

    /// Cluster definition.
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 1,
        received: &[CMD_GO_TO_PERCENT, CMD_STOP],
        generated: &[],
    };

    /// Default reporting of the state, safety status and position.
    pub const REPORTING: DefaultReporting = DefaultReporting {
        min: 1,
        max: 300,
        change: 1,
    };

    /// Result of a received command.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Outcome {
        /// Move the barrier to this percentage open.
        GoTo(u8),
        /// Halt the barrier.
        Stop,
        /// Refused with this status.
        Default(ZclStatus),
    }

    fn guard<const A: usize>(_t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = v.as_u64().unwrap_or(u64::MAX);
        let counters = [
            OPEN_EVENTS.id,
            CLOSE_EVENTS.id,
            COMMAND_OPEN_EVENTS.id,
            COMMAND_CLOSE_EVENTS.id,
            OPEN_PERIOD.id,
            CLOSE_PERIOD.id,
        ];
        if counters.contains(&id) && val > u64::from(EVENTS_MAX) {
            ZclStatus::InvalidValue
        } else {
            ZclStatus::Success
        }
    }

    /// Builds a server: `partial` sets the PartialBarrier capability;
    /// `open_period` / `close_period` are the expected travel times in
    /// tenths of a second.
    pub fn server<const A: usize>(
        partial: bool,
        open_period: u16,
        close_period: u16,
    ) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(
            MOVING_STATE,
            &Value::Enum8(moving_state::STOPPED),
            REPORTING,
        )?;
        c.add_reported_attribute(SAFETY_STATUS, &Value::Bits { width: 2, bits: 0 }, REPORTING)?;
        c.add_attribute(
            CAPABILITIES,
            &bits8(if partial {
                CAPABILITY_PARTIAL_BARRIER
            } else {
                0
            }),
        )?;
        c.add_attribute(OPEN_EVENTS, &u16v(0))?;
        c.add_attribute(CLOSE_EVENTS, &u16v(0))?;
        c.add_attribute(COMMAND_OPEN_EVENTS, &u16v(0))?;
        c.add_attribute(COMMAND_CLOSE_EVENTS, &u16v(0))?;
        c.add_attribute(OPEN_PERIOD, &u16v(open_period.min(EVENTS_MAX)))?;
        c.add_attribute(CLOSE_PERIOD, &u16v(close_period.min(EVENTS_MAX)))?;
        c.add_reported_attribute(BARRIER_POSITION, &u8v(POSITION_UNKNOWN), REPORTING)?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    fn bump<const A: usize>(c: &mut ClusterInstance<A>, id: AttributeId) {
        let n = c.u16(id).unwrap_or(0);
        if n < EVENTS_MAX {
            c.set_u16(id, n + 1);
        }
    }

    /// Handles Go To Percent / Stop (§7.5.2.2): a lockout ignores
    /// position commands (FAILURE); a barrier without the partial
    /// capability accepts 0 and 100 only (INVALID_VALUE). An accepted Go
    /// To Percent counts a command open / close event.
    pub fn handle<const A: usize>(
        c: &mut ClusterInstance<A>,
        cmd: CommandId,
        payload: &[u8],
    ) -> Outcome {
        match cmd {
            CMD_GO_TO_PERCENT => {
                let [percent] = payload else {
                    return Outcome::Default(ZclStatus::MalformedCommand);
                };
                let partial = c.u8(CAPABILITIES.id).unwrap_or(0) & CAPABILITY_PARTIAL_BARRIER != 0;
                if *percent > 100 || (!partial && *percent != 0 && *percent != 100) {
                    return Outcome::Default(ZclStatus::InvalidValue);
                }
                if c.u16(SAFETY_STATUS.id).unwrap_or(0) & safety::REMOTE_LOCKOUT != 0 {
                    return Outcome::Default(ZclStatus::Failure);
                }
                let position = c.u8(BARRIER_POSITION.id).unwrap_or(POSITION_UNKNOWN);
                if position != POSITION_UNKNOWN {
                    if *percent > position {
                        bump(c, COMMAND_OPEN_EVENTS.id);
                    } else if *percent < position {
                        bump(c, COMMAND_CLOSE_EVENTS.id);
                    }
                }
                Outcome::GoTo(*percent)
            }
            CMD_STOP => Outcome::Stop,
            _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
        }
    }

    /// Records the barrier's motion and position (`None` = unknown):
    /// counts open / close events on the transitions of §7.5.2.1.4–5 and
    /// keeps the position unknown while a non-partial barrier moves.
    pub fn set_state<const A: usize>(c: &mut ClusterInstance<A>, moving: u8, position: Option<u8>) {
        let partial = c.u8(CAPABILITIES.id).unwrap_or(0) & CAPABILITY_PARTIAL_BARRIER != 0;
        let before = c.u8(BARRIER_POSITION.id).unwrap_or(POSITION_UNKNOWN);
        let shown = match position {
            Some(p) if moving == moving_state::STOPPED || partial => p.min(100),
            _ => POSITION_UNKNOWN,
        };
        c.set(
            MOVING_STATE.id,
            &Value::Enum8(moving.min(moving_state::OPENING)),
        );
        c.set_u8(BARRIER_POSITION.id, shown);
        if before != POSITION_UNKNOWN && shown != POSITION_UNKNOWN {
            if before == 0 && shown != 0 {
                bump(c, OPEN_EVENTS.id);
            } else if before != 0 && shown == 0 {
                bump(c, CLOSE_EVENTS.id);
            }
        }
    }

    /// Sets `SafetyStatus`; returns the alarm codes (bit numbers) that
    /// newly became active for the Alarms cluster.
    pub fn set_safety<const A: usize>(
        c: &mut ClusterInstance<A>,
        status: u16,
    ) -> heapless::Vec<u8, 4> {
        let previous = c.u16(SAFETY_STATUS.id).unwrap_or(0);
        c.set(
            SAFETY_STATUS.id,
            &Value::Bits {
                width: 2,
                bits: u64::from(status & 0x0f),
            },
        );
        let mut codes = heapless::Vec::new();
        for bit in 0..4u8 {
            if status & (1 << bit) != 0 && previous & (1 << bit) == 0 {
                let _ = codes.push(bit);
            }
        }
        codes
    }

    /// Scene extension field set (§7.5.2.4): `BarrierPosition`.
    pub fn scene_fields<const A: usize>(c: &ClusterInstance<A>) -> [u8; 1] {
        [c.u8(BARRIER_POSITION.id).unwrap_or(POSITION_UNKNOWN)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_temperature_alarms_after_the_dwell() {
        use device_temperature::*;
        let t0 = Instant::from_millis(0);
        let mut c: ClusterInstance<16> = server(true).unwrap();
        let g = c.write_guard.unwrap();
        c.set_i16(HIGH_TEMP_THRESHOLD.id, 80);
        // The low threshold must stay below the high one and in range.
        assert_eq!(
            g(&c.attributes, LOW_TEMP_THRESHOLD.id, &i16v(90)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, LOW_TEMP_THRESHOLD.id, &i16v(-250)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, LOW_TEMP_THRESHOLD.id, &i16v(-10)),
            ZclStatus::Success
        );
        assert_eq!(
            g(&c.attributes, DEVICE_TEMP_ALARM_MASK.id, &bits8(4)),
            ZclStatus::InvalidValue
        );
        c.set_i16(LOW_TEMP_THRESHOLD.id, -10);
        c.set(
            DEVICE_TEMP_ALARM_MASK.id,
            &bits8(MASK_TOO_LOW | MASK_TOO_HIGH),
        );
        c.set(HIGH_TEMP_DWELL_TRIP_POINT.id, &u24v(30));
        // Extremes are tracked; 85 °C arms the high dwell.
        assert_eq!(set_temperature(&mut c, Some(25), t0), None);
        assert_eq!(set_temperature(&mut c, Some(85), t0), None);
        assert_eq!(c.i16(MIN_TEMP_EXPERIENCED.id), Some(25));
        assert_eq!(c.i16(MAX_TEMP_EXPERIENCED.id), Some(85));
        assert_eq!(c.tick, Some(t0 + Duration::from_secs(30)));
        assert_eq!(tick(&mut c, t0 + Duration::from_secs(29)), None);
        assert_eq!(
            tick(&mut c, t0 + Duration::from_secs(30)),
            Some(ALARM_TOO_HIGH)
        );
        assert_eq!(c.tick, None);
        // Still hot: nothing more; recovery then a new excursion rearms.
        assert_eq!(
            set_temperature(&mut c, Some(90), t0 + Duration::from_secs(40)),
            None
        );
        assert_eq!(
            set_temperature(&mut c, Some(70), t0 + Duration::from_secs(50)),
            None
        );
        assert_eq!(
            set_temperature(&mut c, Some(90), t0 + Duration::from_secs(60)),
            None
        );
        assert_eq!(
            set_temperature(&mut c, Some(90), t0 + Duration::from_secs(90)),
            Some(ALARM_TOO_HIGH)
        );
        // The low alarm needs its dwell trip point set.
        assert_eq!(
            set_temperature(&mut c, Some(-20), t0 + Duration::from_secs(100)),
            None
        );
        assert_eq!(c.tick, None);
        c.set(LOW_TEMP_DWELL_TRIP_POINT.id, &u24v(0));
        assert_eq!(
            set_temperature(&mut c, Some(-20), t0 + Duration::from_secs(101)),
            Some(ALARM_TOO_LOW)
        );
        // An invalid reading clears the timer.
        assert_eq!(
            set_temperature(&mut c, None, t0 + Duration::from_secs(102)),
            None
        );
        assert_eq!(c.i16(CURRENT_TEMPERATURE.id), Some(UNKNOWN));
        let plain: ClusterInstance<16> = server(false).unwrap();
        assert!(plain.attributes.get(LOW_TEMP_THRESHOLD.id, None).is_none());
    }

    #[test]
    fn switch_configuration_maps_actions_to_commands() {
        use crate::clusters::on_off::{CMD_OFF, CMD_ON, CMD_TOGGLE};
        use switch_configuration::*;
        let mut c: ClusterInstance<8> = server(switch_type::MOMENTARY).unwrap();
        assert!(server::<8>(3).is_err());
        let g = c.write_guard.unwrap();
        assert_eq!(
            g(&c.attributes, SWITCH_ACTIONS.id, &Value::Enum8(3)),
            ZclStatus::InvalidValue
        );
        assert_eq!(command_for(&c, true), CMD_ON);
        assert_eq!(command_for(&c, false), CMD_OFF);
        c.set(SWITCH_ACTIONS.id, &Value::Enum8(switch_actions::OFF_ON));
        assert_eq!(command_for(&c, true), CMD_OFF);
        assert_eq!(command_for(&c, false), CMD_ON);
        c.set(SWITCH_ACTIONS.id, &Value::Enum8(switch_actions::TOGGLE));
        assert_eq!(command_for(&c, true), CMD_TOGGLE);
    }

    #[test]
    fn ballast_levels_factor_and_burn_hours() {
        use ballast::*;
        let mut c: ClusterInstance<24> = server(10, 250, 2).unwrap();
        assert!(server::<24>(0, 250, 1).is_err());
        let g = c.write_guard.unwrap();
        // MinLevel within [PhysicalMinLevel, MaxLevel]; MaxLevel within
        // [MinLevel, PhysicalMaxLevel].
        assert_eq!(
            g(&c.attributes, MIN_LEVEL.id, &u8v(5)),
            ZclStatus::InvalidValue
        );
        assert_eq!(g(&c.attributes, MIN_LEVEL.id, &u8v(20)), ZclStatus::Success);
        c.set_u8(MIN_LEVEL.id, 20);
        assert_eq!(
            g(&c.attributes, MAX_LEVEL.id, &u8v(19)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, MAX_LEVEL.id, &u8v(251)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, MAX_LEVEL.id, &u8v(220)),
            ZclStatus::Success
        );
        c.set_u8(MAX_LEVEL.id, 220);
        assert_eq!(
            g(&c.attributes, BALLAST_FACTOR_ADJUSTMENT.id, &u8v(50)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, BALLAST_FACTOR_ADJUSTMENT.id, &u8v(110)),
            ZclStatus::Success
        );
        let long = [b'x'; 17];
        assert_eq!(
            g(
                &c.attributes,
                LAMP_TYPE.id,
                &Value::String {
                    ty: DataType::CharString,
                    bytes: Some(&long)
                }
            ),
            ZclStatus::InvalidValue
        );
        // The dimming curve maps 1…254 onto MinLevel…MaxLevel.
        assert_eq!(output_for_level(&c, 1), 20);
        assert_eq!(output_for_level(&c, 254), 220);
        c.set_u8(BALLAST_FACTOR_ADJUSTMENT.id, 110);
        assert_eq!(output_for_level(&c, 254), 242);
        // Burn hours alarm once at the trip point with the mode bit set.
        c.set(LAMP_BURN_HOURS_TRIP_POINT.id, &u24v(1000));
        assert_eq!(add_burn_hours(&mut c, 999), None);
        c.set(LAMP_ALARM_MODE.id, &bits8(1));
        assert_eq!(add_burn_hours(&mut c, 1), Some(ALARM_LAMP_BURN_HOURS));
        assert_eq!(add_burn_hours(&mut c, 1), None);
        assert_eq!(c.u64(LAMP_BURN_HOURS.id), Some(1001));
        assert!(set_status(&mut c, STATUS_LAMP_FAILURE));
    }

    #[test]
    fn pump_modes_status_and_alarms() {
        use pump::*;
        let limits = Limits {
            max_pressure: 1000,
            max_speed: 3000,
            max_flow: 500,
        };
        let mut c: ClusterInstance<24> = server(
            limits,
            (1 << alarm_code::DRY_RUNNING) | (1 << alarm_code::PUMP_BLOCKED),
        )
        .unwrap();
        let g = c.write_guard.unwrap();
        assert_eq!(
            g(&c.attributes, OPERATION_MODE.id, &Value::Enum8(4)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, CONTROL_MODE.id, &Value::Enum8(4)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, CONTROL_MODE.id, &Value::Enum8(7)),
            ZclStatus::Success
        );
        // Normal + remote flow sensor: constant flow, remote flow bit.
        c.set(
            CONTROL_MODE.id,
            &Value::Enum8(control_mode::CONSTANT_PRESSURE),
        );
        assert_eq!(
            resolve_modes(&mut c, Some(RemoteSensor::Flow)),
            (operation_mode::NORMAL, control_mode::CONSTANT_FLOW)
        );
        assert_eq!(c.u16(PUMP_STATUS.id), Some(status::REMOTE_FLOW));
        // Normal without a sensor: the configured control mode.
        assert_eq!(
            resolve_modes(&mut c, None),
            (operation_mode::NORMAL, control_mode::CONSTANT_PRESSURE)
        );
        assert_eq!(c.u16(PUMP_STATUS.id), Some(0));
        // Maximum overrides regardless of the sensor.
        c.set(OPERATION_MODE.id, &Value::Enum8(operation_mode::MAXIMUM));
        assert_eq!(
            resolve_modes(&mut c, Some(RemoteSensor::Pressure)),
            (operation_mode::MAXIMUM, control_mode::CONSTANT_PRESSURE)
        );
        set_running(&mut c, 150, 2000);
        assert_eq!(c.u16(PUMP_STATUS.id), Some(status::RUNNING));
        set_running(&mut c, 0, 0);
        assert_eq!(c.u16(PUMP_STATUS.id), Some(0));
        // Alarms: masked codes are raised, faults flag the status.
        assert_eq!(
            alarm(&mut c, alarm_code::DRY_RUNNING),
            Some(alarm_code::DRY_RUNNING)
        );
        assert_eq!(c.u16(PUMP_STATUS.id), Some(status::SUPPLY_FAULT));
        assert_eq!(alarm(&mut c, alarm_code::MOTOR_FATAL_FAILURE), None);
        assert_eq!(
            c.u16(PUMP_STATUS.id),
            Some(status::SUPPLY_FAULT | status::DEVICE_FAULT)
        );
        assert_eq!(alarm(&mut c, 14), None);
    }

    #[test]
    fn dehumidification_demand_follows_setpoint_and_hysteresis() {
        use dehumidification::*;
        let mut c: ClusterInstance<16> = server().unwrap();
        let g = c.write_guard.unwrap();
        assert_eq!(
            g(&c.attributes, RH_DEHUMIDIFICATION_SETPOINT.id, &u8v(20)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, DEHUMIDIFICATION_HYSTERESIS.id, &u8v(21)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, DEHUMIDIFICATION_MAX_COOL.id, &u8v(10)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, DEHUMIDIFICATION_LOCKOUT.id, &Value::Enum8(2)),
            ZclStatus::InvalidValue
        );
        c.set_u8(RH_DEHUMIDIFICATION_SETPOINT.id, 50);
        c.set_u8(DEHUMIDIFICATION_HYSTERESIS.id, 5);
        c.set_u8(DEHUMIDIFICATION_MAX_COOL.id, 60);
        assert_eq!(set_humidity(&mut c, 40), 0);
        assert_eq!(set_humidity(&mut c, 55), 60);
        // Within the hysteresis band the demand holds.
        assert_eq!(set_humidity(&mut c, 48), 60);
        assert_eq!(set_humidity(&mut c, 45), 0);
        // Locked out: no cooling.
        c.set(DEHUMIDIFICATION_LOCKOUT.id, &Value::Enum8(0));
        assert_eq!(set_humidity(&mut c, 90), 0);
        assert_eq!(c.u8(RELATIVE_HUMIDITY.id), Some(90));
    }

    #[test]
    fn thermostat_ui_and_shade_guards() {
        {
            use thermostat_ui::*;
            let c: ClusterInstance<8> = server().unwrap();
            let g = c.write_guard.unwrap();
            assert_eq!(
                g(&c.attributes, KEYPAD_LOCKOUT.id, &Value::Enum8(5)),
                ZclStatus::Success
            );
            assert_eq!(
                g(&c.attributes, KEYPAD_LOCKOUT.id, &Value::Enum8(6)),
                ZclStatus::InvalidValue
            );
            assert_eq!(
                g(&c.attributes, TEMPERATURE_DISPLAY_MODE.id, &Value::Enum8(2)),
                ZclStatus::InvalidValue
            );
        }
        use shade::*;
        let mut c: ClusterInstance<8> = server(2000, 4).unwrap();
        assert!(server::<8>(0, 4).is_err());
        let g = c.write_guard.unwrap();
        // Only the motor-direction bit of Status may be written.
        assert_eq!(
            g(
                &c.attributes,
                STATUS.id,
                &bits8(status::OPERATIONAL | status::MOTOR_FORWARD)
            ),
            ZclStatus::Success
        );
        assert_eq!(
            g(&c.attributes, STATUS.id, &bits8(status::MOTOR_FORWARD)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, MODE.id, &Value::Enum8(2)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, CLOSED_LIMIT.id, &u16v(0)),
            ZclStatus::InvalidValue
        );
        set_motion(&mut c, true, true);
        assert_eq!(
            c.u8(STATUS.id),
            Some(status::OPERATIONAL | status::ADJUSTING | status::DIRECTION)
        );
        set_motion(&mut c, false, false);
        assert_eq!(c.u8(STATUS.id), Some(status::OPERATIONAL));
    }

    #[test]
    fn barrier_commands_events_and_safety() {
        use barrier_control::*;
        let mut c: ClusterInstance<16> = server(false, 150, 150).unwrap();
        // A non-partial barrier takes 0 and 100 only.
        assert_eq!(
            handle(&mut c, CMD_GO_TO_PERCENT, &[50]),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        assert_eq!(
            handle(&mut c, CMD_GO_TO_PERCENT, &[101]),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        assert_eq!(
            handle(&mut c, CMD_GO_TO_PERCENT, &[]),
            Outcome::Default(ZclStatus::MalformedCommand)
        );
        // Unknown position: no command event counted yet.
        assert_eq!(
            handle(&mut c, CMD_GO_TO_PERCENT, &[100]),
            Outcome::GoTo(100)
        );
        assert_eq!(c.u16(COMMAND_OPEN_EVENTS.id), Some(0));
        // Moving without the partial capability hides the position.
        set_state(&mut c, moving_state::OPENING, Some(30));
        assert_eq!(c.u8(BARRIER_POSITION.id), Some(POSITION_UNKNOWN));
        set_state(&mut c, moving_state::STOPPED, Some(0));
        set_state(&mut c, moving_state::STOPPED, Some(100));
        assert_eq!(c.u16(OPEN_EVENTS.id), Some(1));
        assert_eq!(handle(&mut c, CMD_GO_TO_PERCENT, &[0]), Outcome::GoTo(0));
        assert_eq!(c.u16(COMMAND_CLOSE_EVENTS.id), Some(1));
        set_state(&mut c, moving_state::STOPPED, Some(0));
        assert_eq!(c.u16(CLOSE_EVENTS.id), Some(1));
        assert_eq!(handle(&mut c, CMD_STOP, &[]), Outcome::Stop);
        // A remote lockout refuses position commands; new safety bits
        // are the alarm codes.
        assert_eq!(
            set_safety(&mut c, safety::REMOTE_LOCKOUT | safety::TAMPER_DETECTED).as_slice(),
            &[0, 1]
        );
        assert!(set_safety(&mut c, safety::REMOTE_LOCKOUT).is_empty());
        assert_eq!(
            handle(&mut c, CMD_GO_TO_PERCENT, &[100]),
            Outcome::Default(ZclStatus::Failure)
        );
        assert_eq!(scene_fields(&c), [0]);
        let mut p: ClusterInstance<16> = server(true, 150, 150).unwrap();
        assert_eq!(handle(&mut p, CMD_GO_TO_PERCENT, &[50]), Outcome::GoTo(50));
        set_state(&mut p, moving_state::OPENING, Some(30));
        assert_eq!(p.u8(BARRIER_POSITION.id), Some(30));
    }
}
