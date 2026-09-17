//! HVAC clusters (ZCL8 chapter 6): the Thermostat core — information
//! and settings attributes, the setpoint limit and dead-band rules
//! enforced on writes, Setpoint Raise/Lower, the running-mode
//! interpretation of Table 6-17 and the scene extension — and Fan
//! Control. The weekly schedule, relay status log and AC information
//! sets are not implemented.

use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, AttributeTable, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Thermostat cluster (§6.3).
pub mod thermostat {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0201);
    /// `LocalTemperature` (int16, 0.01 °C, reportable).
    pub const LOCAL_TEMPERATURE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Int(2), Access::RO_REPORT);
    /// `OutdoorTemperature` (int16).
    pub const OUTDOOR_TEMPERATURE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Int(2), Access::RO);
    /// `Occupancy` (map8, bit 0 = occupied).
    pub const OCCUPANCY: AttributeDef = AttributeDef::new(0x0002, DataType::Bitmap(1), Access::RO);
    /// `AbsMinHeatSetpointLimit`.
    pub const ABS_MIN_HEAT_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0003, DataType::Int(2), Access::RO);
    /// `AbsMaxHeatSetpointLimit`.
    pub const ABS_MAX_HEAT_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0004, DataType::Int(2), Access::RO);
    /// `AbsMinCoolSetpointLimit`.
    pub const ABS_MIN_COOL_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0005, DataType::Int(2), Access::RO);
    /// `AbsMaxCoolSetpointLimit`.
    pub const ABS_MAX_COOL_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0006, DataType::Int(2), Access::RO);
    /// `PICoolingDemand` (uint8 %, reportable).
    pub const PI_COOLING_DEMAND: AttributeDef =
        AttributeDef::new(0x0007, DataType::Uint(1), Access::RO_REPORT);
    /// `PIHeatingDemand` (uint8 %, reportable).
    pub const PI_HEATING_DEMAND: AttributeDef =
        AttributeDef::new(0x0008, DataType::Uint(1), Access::RO_REPORT);
    /// `LocalTemperatureCalibration` (int8, 0.1 °C, writable).
    pub const LOCAL_TEMPERATURE_CALIBRATION: AttributeDef =
        AttributeDef::new(0x0010, DataType::Int(1), Access::RW);
    /// `OccupiedCoolingSetpoint` (int16, scene).
    pub const OCCUPIED_COOLING_SETPOINT: AttributeDef =
        AttributeDef::new(0x0011, DataType::Int(2), Access::RW);
    /// `OccupiedHeatingSetpoint` (int16, scene).
    pub const OCCUPIED_HEATING_SETPOINT: AttributeDef =
        AttributeDef::new(0x0012, DataType::Int(2), Access::RW);
    /// `UnoccupiedCoolingSetpoint`.
    pub const UNOCCUPIED_COOLING_SETPOINT: AttributeDef =
        AttributeDef::new(0x0013, DataType::Int(2), Access::RW);
    /// `UnoccupiedHeatingSetpoint`.
    pub const UNOCCUPIED_HEATING_SETPOINT: AttributeDef =
        AttributeDef::new(0x0014, DataType::Int(2), Access::RW);
    /// `MinHeatSetpointLimit`.
    pub const MIN_HEAT_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0015, DataType::Int(2), Access::RW);
    /// `MaxHeatSetpointLimit`.
    pub const MAX_HEAT_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0016, DataType::Int(2), Access::RW);
    /// `MinCoolSetpointLimit`.
    pub const MIN_COOL_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0017, DataType::Int(2), Access::RW);
    /// `MaxCoolSetpointLimit`.
    pub const MAX_COOL_SETPOINT_LIMIT: AttributeDef =
        AttributeDef::new(0x0018, DataType::Int(2), Access::RW);
    /// `MinSetpointDeadBand` (int8, 0.1 °C).
    pub const MIN_SETPOINT_DEAD_BAND: AttributeDef =
        AttributeDef::new(0x0019, DataType::Int(1), Access::RW);
    /// `RemoteSensing` (map8).
    pub const REMOTE_SENSING: AttributeDef =
        AttributeDef::new(0x001a, DataType::Bitmap(1), Access::RW);
    /// `ControlSequenceOfOperation` (enum8).
    pub const CONTROL_SEQUENCE_OF_OPERATION: AttributeDef =
        AttributeDef::new(0x001b, DataType::Enum8, Access::RW);
    /// `SystemMode` (enum8, scene).
    pub const SYSTEM_MODE: AttributeDef = AttributeDef::new(0x001c, DataType::Enum8, Access::RW);
    /// `AlarmMask` (map8).
    pub const ALARM_MASK: AttributeDef = AttributeDef::new(0x001d, DataType::Bitmap(1), Access::RO);
    /// `ThermostatRunningMode` (enum8).
    pub const THERMOSTAT_RUNNING_MODE: AttributeDef =
        AttributeDef::new(0x001e, DataType::Enum8, Access::RO);

    /// Unknown temperature (non-value).
    pub const UNKNOWN: i16 = i16::MIN;
    /// Defaults of Table 6-11 / 6-13 in 0.01 °C.
    pub const DEFAULT_ABS_MIN_HEAT: i16 = 0x02bc;
    /// 30 °C.
    pub const DEFAULT_ABS_MAX_HEAT: i16 = 0x0bb8;
    /// 16 °C.
    pub const DEFAULT_ABS_MIN_COOL: i16 = 0x0640;
    /// 32 °C.
    pub const DEFAULT_ABS_MAX_COOL: i16 = 0x0c80;
    /// 26 °C.
    pub const DEFAULT_COOLING_SETPOINT: i16 = 0x0a28;
    /// 20 °C.
    pub const DEFAULT_HEATING_SETPOINT: i16 = 0x07d0;
    /// 2.5 °C.
    pub const DEFAULT_DEAD_BAND: i8 = 0x19;

    /// Setpoint Raise/Lower.
    pub const CMD_SETPOINT_RAISE_LOWER: CommandId = CommandId(0x00);

    /// `ControlSequenceOfOperation` values (Table 6-15).
    pub mod control_sequence {
        /// Cooling only.
        pub const COOLING_ONLY: u8 = 0x00;
        /// Cooling with reheat.
        pub const COOLING_WITH_REHEAT: u8 = 0x01;
        /// Heating only.
        pub const HEATING_ONLY: u8 = 0x02;
        /// Heating with reheat.
        pub const HEATING_WITH_REHEAT: u8 = 0x03;
        /// Cooling and heating (4 pipes).
        pub const COOLING_AND_HEATING: u8 = 0x04;
        /// Cooling and heating with reheat.
        pub const COOLING_AND_HEATING_WITH_REHEAT: u8 = 0x05;
    }

    /// `SystemMode` values (Table 6-16).
    pub mod system_mode {
        /// Off.
        pub const OFF: u8 = 0x00;
        /// Auto.
        pub const AUTO: u8 = 0x01;
        /// Cool.
        pub const COOL: u8 = 0x03;
        /// Heat.
        pub const HEAT: u8 = 0x04;
        /// Emergency heating.
        pub const EMERGENCY_HEATING: u8 = 0x05;
        /// Precooling.
        pub const PRECOOLING: u8 = 0x06;
        /// Fan only.
        pub const FAN_ONLY: u8 = 0x07;
        /// Dry.
        pub const DRY: u8 = 0x08;
        /// Sleep.
        pub const SLEEP: u8 = 0x09;
    }

    /// Setpoint Raise/Lower modes (Table 6-36).
    pub mod raise_lower_mode {
        /// Heat setpoint.
        pub const HEAT: u8 = 0x00;
        /// Cool setpoint.
        pub const COOL: u8 = 0x01;
        /// Both.
        pub const BOTH: u8 = 0x02;
    }

    /// Cluster definition (Setpoint Raise/Lower only).
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 3,
        received: &[CMD_SETPOINT_RAISE_LOWER],
        generated: &[],
    };

    /// Default reporting of `LocalTemperature` (0.5 °C) and the demands.
    pub const TEMPERATURE_REPORTING: DefaultReporting = DefaultReporting {
        min: 10,
        max: 300,
        change: 50,
    };
    /// Default reporting of the PI demands (5 %).
    pub const DEMAND_REPORTING: DefaultReporting = DefaultReporting {
        min: 10,
        max: 300,
        change: 5,
    };

    const fn i16v(v: i16) -> Value<'static> {
        Value::Int {
            width: 2,
            value: v as i64,
        }
    }

    fn i16_of<const A: usize>(t: &AttributeTable<A>, id: AttributeId) -> Option<i16> {
        t.value(id)
            .and_then(|v| v.as_i64())
            .and_then(|v| i16::try_from(v).ok())
    }

    /// Whether `SystemMode` `mode` is allowed under `sequence`
    /// (Table 6-15).
    pub const fn mode_allowed(sequence: u8, mode: u8) -> bool {
        match sequence {
            control_sequence::COOLING_ONLY | control_sequence::COOLING_WITH_REHEAT => {
                !matches!(mode, system_mode::HEAT | system_mode::EMERGENCY_HEATING)
            }
            control_sequence::HEATING_ONLY | control_sequence::HEATING_WITH_REHEAT => {
                !matches!(mode, system_mode::COOL | system_mode::PRECOOLING)
            }
            _ => true,
        }
    }

    /// Write guard: setpoint limits and the dead band (§6.3.2.2.2),
    /// `SystemMode` against the control sequence, the dead-band range.
    fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = v.as_i64().unwrap_or(0);
        let dead_band = i64::from(i16_of(t, MIN_SETPOINT_DEAD_BAND.id).unwrap_or(0)) * 10;
        let lim = |id: AttributeId, fallback: AttributeId, default: i16| {
            i64::from(
                i16_of(t, id)
                    .or_else(|| i16_of(t, fallback))
                    .unwrap_or(default),
            )
        };
        let min_heat = lim(
            MIN_HEAT_SETPOINT_LIMIT.id,
            ABS_MIN_HEAT_SETPOINT_LIMIT.id,
            DEFAULT_ABS_MIN_HEAT,
        );
        let max_heat = lim(
            MAX_HEAT_SETPOINT_LIMIT.id,
            ABS_MAX_HEAT_SETPOINT_LIMIT.id,
            DEFAULT_ABS_MAX_HEAT,
        );
        let min_cool = lim(
            MIN_COOL_SETPOINT_LIMIT.id,
            ABS_MIN_COOL_SETPOINT_LIMIT.id,
            DEFAULT_ABS_MIN_COOL,
        );
        let max_cool = lim(
            MAX_COOL_SETPOINT_LIMIT.id,
            ABS_MAX_COOL_SETPOINT_LIMIT.id,
            DEFAULT_ABS_MAX_COOL,
        );
        let heat = |id: AttributeId| i16_of(t, id).map(i64::from);
        match id {
            i if i == OCCUPIED_COOLING_SETPOINT.id || i == UNOCCUPIED_COOLING_SETPOINT.id => {
                let other = if i == OCCUPIED_COOLING_SETPOINT.id {
                    heat(OCCUPIED_HEATING_SETPOINT.id)
                } else {
                    heat(UNOCCUPIED_HEATING_SETPOINT.id)
                };
                if val < min_cool || val > max_cool || other.is_some_and(|h| val - h < dead_band) {
                    ZclStatus::InvalidValue
                } else {
                    ZclStatus::Success
                }
            }
            i if i == OCCUPIED_HEATING_SETPOINT.id || i == UNOCCUPIED_HEATING_SETPOINT.id => {
                let other = if i == OCCUPIED_HEATING_SETPOINT.id {
                    heat(OCCUPIED_COOLING_SETPOINT.id)
                } else {
                    heat(UNOCCUPIED_COOLING_SETPOINT.id)
                };
                if val < min_heat || val > max_heat || other.is_some_and(|c| c - val < dead_band) {
                    ZclStatus::InvalidValue
                } else {
                    ZclStatus::Success
                }
            }
            i if i == MIN_HEAT_SETPOINT_LIMIT.id || i == MAX_HEAT_SETPOINT_LIMIT.id => {
                let (lo, hi) = (
                    i64::from(
                        i16_of(t, ABS_MIN_HEAT_SETPOINT_LIMIT.id).unwrap_or(DEFAULT_ABS_MIN_HEAT),
                    ),
                    i64::from(
                        i16_of(t, ABS_MAX_HEAT_SETPOINT_LIMIT.id).unwrap_or(DEFAULT_ABS_MAX_HEAT),
                    ),
                );
                if val < lo || val > hi {
                    ZclStatus::InvalidValue
                } else {
                    ZclStatus::Success
                }
            }
            i if i == MIN_COOL_SETPOINT_LIMIT.id || i == MAX_COOL_SETPOINT_LIMIT.id => {
                let (lo, hi) = (
                    i64::from(
                        i16_of(t, ABS_MIN_COOL_SETPOINT_LIMIT.id).unwrap_or(DEFAULT_ABS_MIN_COOL),
                    ),
                    i64::from(
                        i16_of(t, ABS_MAX_COOL_SETPOINT_LIMIT.id).unwrap_or(DEFAULT_ABS_MAX_COOL),
                    ),
                );
                if val < lo || val > hi {
                    ZclStatus::InvalidValue
                } else {
                    ZclStatus::Success
                }
            }
            i if i == MIN_SETPOINT_DEAD_BAND.id => {
                if (0..=0x19).contains(&val) {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == SYSTEM_MODE.id => {
                let seq = t.u64(CONTROL_SEQUENCE_OF_OPERATION.id).unwrap_or(4);
                let mode = u8::try_from(val).unwrap_or(0xff);
                let known = matches!(
                    mode,
                    system_mode::OFF
                        | system_mode::AUTO
                        | system_mode::COOL
                        | system_mode::HEAT
                        | system_mode::EMERGENCY_HEATING
                        | system_mode::PRECOOLING
                        | system_mode::FAN_ONLY
                        | system_mode::DRY
                        | system_mode::SLEEP
                );
                if known && mode_allowed(u8::try_from(seq).unwrap_or(4), mode) {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == CONTROL_SEQUENCE_OF_OPERATION.id => {
                if val <= 0x05 {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            _ => ZclStatus::Success,
        }
    }

    /// The setpoints a server implements.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Capability {
        /// Heating only (a radiator valve): the heating setpoint.
        Heating,
        /// Cooling only.
        Cooling,
        /// Both setpoints.
        HeatingAndCooling,
    }

    /// Builds a server with the mandatory attributes for `capability`,
    /// the user limits, dead band, control sequence and system mode.
    pub fn server<const A: usize>(capability: Capability) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(LOCAL_TEMPERATURE, &i16v(UNKNOWN), TEMPERATURE_REPORTING)?;
        c.add_attribute(OCCUPANCY, &Value::Bits { width: 1, bits: 1 })?;
        let (heat, cool, seq) = match capability {
            Capability::Heating => (true, false, control_sequence::HEATING_ONLY),
            Capability::Cooling => (false, true, control_sequence::COOLING_ONLY),
            Capability::HeatingAndCooling => (true, true, control_sequence::COOLING_AND_HEATING),
        };
        if heat {
            c.add_attribute(ABS_MIN_HEAT_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MIN_HEAT))?;
            c.add_attribute(ABS_MAX_HEAT_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MAX_HEAT))?;
            c.add_reported_attribute(
                PI_HEATING_DEMAND,
                &Value::Uint { width: 1, value: 0 },
                DEMAND_REPORTING,
            )?;
            c.add_attribute(OCCUPIED_HEATING_SETPOINT, &i16v(DEFAULT_HEATING_SETPOINT))?;
            c.add_attribute(MIN_HEAT_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MIN_HEAT))?;
            c.add_attribute(MAX_HEAT_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MAX_HEAT))?;
        }
        if cool {
            c.add_attribute(ABS_MIN_COOL_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MIN_COOL))?;
            c.add_attribute(ABS_MAX_COOL_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MAX_COOL))?;
            c.add_reported_attribute(
                PI_COOLING_DEMAND,
                &Value::Uint { width: 1, value: 0 },
                DEMAND_REPORTING,
            )?;
            c.add_attribute(OCCUPIED_COOLING_SETPOINT, &i16v(DEFAULT_COOLING_SETPOINT))?;
            c.add_attribute(MIN_COOL_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MIN_COOL))?;
            c.add_attribute(MAX_COOL_SETPOINT_LIMIT, &i16v(DEFAULT_ABS_MAX_COOL))?;
        }
        if heat && cool {
            c.add_attribute(
                MIN_SETPOINT_DEAD_BAND,
                &Value::Int {
                    width: 1,
                    value: i64::from(DEFAULT_DEAD_BAND),
                },
            )?;
        }
        c.add_attribute(CONTROL_SEQUENCE_OF_OPERATION, &Value::Enum8(seq))?;
        c.add_attribute(SYSTEM_MODE, &Value::Enum8(system_mode::AUTO))?;
        c.add_attribute(THERMOSTAT_RUNNING_MODE, &Value::Enum8(system_mode::OFF))?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF, Role::Client)
    }

    /// Sets `LocalTemperature` (0.01 °C, `None` = unknown) and updates
    /// `ThermostatRunningMode` per Table 6-17; returns whether the
    /// temperature changed.
    pub fn set_local_temperature<const A: usize>(
        c: &mut ClusterInstance<A>,
        t: Option<i16>,
    ) -> bool {
        let changed = c.set_i16(LOCAL_TEMPERATURE.id, t.unwrap_or(UNKNOWN));
        let running = running_mode(c);
        c.set(THERMOSTAT_RUNNING_MODE.id, &Value::Enum8(running));
        changed
    }

    /// The running mode implied by `SystemMode`, the setpoints and the
    /// local temperature (Table 6-17): Off, Cool or Heat.
    pub fn running_mode<const A: usize>(c: &ClusterInstance<A>) -> u8 {
        let mode = c.u8(SYSTEM_MODE.id).unwrap_or(system_mode::OFF);
        let temp = c.i16(LOCAL_TEMPERATURE.id).filter(|t| *t != UNKNOWN);
        let heat_sp = c.i16(OCCUPIED_HEATING_SETPOINT.id);
        let cool_sp = c.i16(OCCUPIED_COOLING_SETPOINT.id);
        let Some(t) = temp else {
            return system_mode::OFF;
        };
        let below_heat = heat_sp.is_some_and(|h| t < h);
        let above_cool = cool_sp.is_some_and(|k| t > k);
        match mode {
            system_mode::HEAT | system_mode::EMERGENCY_HEATING if below_heat => system_mode::HEAT,
            system_mode::COOL | system_mode::PRECOOLING if above_cool => system_mode::COOL,
            system_mode::AUTO if below_heat => system_mode::HEAT,
            system_mode::AUTO if above_cool => system_mode::COOL,
            _ => system_mode::OFF,
        }
    }

    /// Result of a received command.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Outcome {
        /// The setpoints were adjusted (heat, cool) in 0.01 °C.
        Adjusted {
            /// New heating setpoint, when implemented.
            heat: Option<i16>,
            /// New cooling setpoint, when implemented.
            cool: Option<i16>,
        },
        /// Refused with this status.
        Default(ZclStatus),
    }

    /// Handles Setpoint Raise/Lower (§6.3.2.3.1): each addressed
    /// setpoint moves by `amount` tenths of a degree, clamped to its
    /// limits and the dead band.
    pub fn handle<const A: usize>(
        c: &mut ClusterInstance<A>,
        cmd: CommandId,
        payload: &[u8],
    ) -> Outcome {
        if cmd != CMD_SETPOINT_RAISE_LOWER {
            return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
        }
        let [mode, amount] = payload else {
            return Outcome::Default(ZclStatus::MalformedCommand);
        };
        let delta = i64::from(i8::from_le_bytes([*amount])) * 10;
        let (do_heat, do_cool) = match *mode {
            raise_lower_mode::HEAT => (true, false),
            raise_lower_mode::COOL => (false, true),
            raise_lower_mode::BOTH => (true, true),
            _ => return Outcome::Default(ZclStatus::InvalidValue),
        };
        let dead = i64::from(c.i16(MIN_SETPOINT_DEAD_BAND.id).unwrap_or(0)) * 10;
        let mut heat = c.i16(OCCUPIED_HEATING_SETPOINT.id).map(i64::from);
        let mut cool = c.i16(OCCUPIED_COOLING_SETPOINT.id).map(i64::from);
        let min_heat = i64::from(
            c.i16(MIN_HEAT_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MIN_HEAT),
        );
        let max_heat = i64::from(
            c.i16(MAX_HEAT_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MAX_HEAT),
        );
        let min_cool = i64::from(
            c.i16(MIN_COOL_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MIN_COOL),
        );
        let max_cool = i64::from(
            c.i16(MAX_COOL_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MAX_COOL),
        );
        if do_heat && let Some(h) = heat {
            let mut n = (h + delta).clamp(min_heat, max_heat);
            if let Some(k) = cool
                && !do_cool
            {
                n = n.min(k - dead);
            }
            heat = Some(n);
        }
        if do_cool && let Some(k) = cool {
            let mut n = (k + delta).clamp(min_cool, max_cool);
            if let Some(h) = heat
                && !do_heat
            {
                n = n.max(h + dead);
            }
            cool = Some(n);
        }
        if do_heat
            && do_cool
            && let (Some(h), Some(k)) = (heat, cool)
            && k - h < dead
        {
            // Keep the dead band by pushing the trailing setpoint.
            if delta >= 0 {
                cool = Some((h + dead).min(max_cool));
            } else {
                heat = Some((k - dead).max(min_heat));
            }
        }
        if let Some(h) = heat {
            c.set_i16(
                OCCUPIED_HEATING_SETPOINT.id,
                i16::try_from(h).unwrap_or(DEFAULT_HEATING_SETPOINT),
            );
        }
        if let Some(k) = cool {
            c.set_i16(
                OCCUPIED_COOLING_SETPOINT.id,
                i16::try_from(k).unwrap_or(DEFAULT_COOLING_SETPOINT),
            );
        }
        let running = running_mode(c);
        c.set(THERMOSTAT_RUNNING_MODE.id, &Value::Enum8(running));
        Outcome::Adjusted {
            heat: heat.and_then(|h| i16::try_from(h).ok()),
            cool: cool.and_then(|k| i16::try_from(k).ok()),
        }
    }

    /// Scene extension field set (§6.3.2.6): OccupiedCoolingSetpoint,
    /// OccupiedHeatingSetpoint, SystemMode.
    pub fn scene_fields<const A: usize>(c: &ClusterInstance<A>) -> [u8; 5] {
        let mut f = [0u8; 5];
        f[..2].copy_from_slice(
            &c.i16(OCCUPIED_COOLING_SETPOINT.id)
                .unwrap_or(UNKNOWN)
                .to_le_bytes(),
        );
        f[2..4].copy_from_slice(
            &c.i16(OCCUPIED_HEATING_SETPOINT.id)
                .unwrap_or(UNKNOWN)
                .to_le_bytes(),
        );
        f[4] = c.u8(SYSTEM_MODE.id).unwrap_or(system_mode::OFF);
        f
    }

    /// Applies a scene extension field set (unknown values skipped).
    pub fn apply_scene_fields<const A: usize>(c: &mut ClusterInstance<A>, fields: &[u8]) {
        if let [c0, c1, h0, h1, mode, ..] = fields {
            let cool = i16::from_le_bytes([*c0, *c1]);
            let heat = i16::from_le_bytes([*h0, *h1]);
            if heat != UNKNOWN
                && c.attributes
                    .get(OCCUPIED_HEATING_SETPOINT.id, None)
                    .is_some()
            {
                c.set_i16(OCCUPIED_HEATING_SETPOINT.id, heat);
            }
            if cool != UNKNOWN
                && c.attributes
                    .get(OCCUPIED_COOLING_SETPOINT.id, None)
                    .is_some()
            {
                c.set_i16(OCCUPIED_COOLING_SETPOINT.id, cool);
            }
            c.set(SYSTEM_MODE.id, &Value::Enum8(*mode));
            let running = running_mode(c);
            c.set(THERMOSTAT_RUNNING_MODE.id, &Value::Enum8(running));
        }
    }
}

/// Fan Control cluster (§6.4).
pub mod fan_control {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0202);
    /// `FanMode` (enum8, writable).
    pub const FAN_MODE: AttributeDef = AttributeDef::new(0x0000, DataType::Enum8, Access::RW);
    /// `FanModeSequence` (enum8, writable).
    pub const FAN_MODE_SEQUENCE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Enum8, Access::RW);

    /// `FanMode` values (Table 6-41).
    pub mod fan_mode {
        /// Off.
        pub const OFF: u8 = 0x00;
        /// Low.
        pub const LOW: u8 = 0x01;
        /// Medium.
        pub const MEDIUM: u8 = 0x02;
        /// High.
        pub const HIGH: u8 = 0x03;
        /// On.
        pub const ON: u8 = 0x04;
        /// Auto.
        pub const AUTO: u8 = 0x05;
        /// Smart.
        pub const SMART: u8 = 0x06;
    }

    /// `FanModeSequence` values (Table 6-42).
    pub mod sequence {
        /// Low / Med / High.
        pub const LOW_MED_HIGH: u8 = 0x00;
        /// Low / High.
        pub const LOW_HIGH: u8 = 0x01;
        /// Low / Med / High / Auto.
        pub const LOW_MED_HIGH_AUTO: u8 = 0x02;
        /// Low / High / Auto.
        pub const LOW_HIGH_AUTO: u8 = 0x03;
        /// On / Auto.
        pub const ON_AUTO: u8 = 0x04;
    }

    /// Cluster definition (attribute-only).
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 2,
        received: &[],
        generated: &[],
    };

    /// Whether `mode` is offered by `sequence` (Off and Smart are always
    /// acceptable).
    pub const fn mode_in_sequence(sequence: u8, mode: u8) -> bool {
        match mode {
            fan_mode::OFF | fan_mode::SMART => true,
            fan_mode::LOW => sequence != sequence::ON_AUTO,
            fan_mode::MEDIUM => matches!(
                sequence,
                sequence::LOW_MED_HIGH | sequence::LOW_MED_HIGH_AUTO
            ),
            fan_mode::HIGH => sequence != sequence::ON_AUTO,
            fan_mode::ON => sequence == sequence::ON_AUTO,
            fan_mode::AUTO => matches!(
                sequence,
                sequence::LOW_MED_HIGH_AUTO | sequence::LOW_HIGH_AUTO | sequence::ON_AUTO
            ),
            _ => false,
        }
    }

    fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
        let val = u8::try_from(v.as_i64().unwrap_or(-1)).unwrap_or(0xff);
        if id == FAN_MODE.id {
            let seq = u8::try_from(t.u64(FAN_MODE_SEQUENCE.id).unwrap_or(2)).unwrap_or(2);
            if mode_in_sequence(seq, val) {
                ZclStatus::Success
            } else {
                ZclStatus::InvalidValue
            }
        } else if id == FAN_MODE_SEQUENCE.id {
            if val <= sequence::ON_AUTO {
                ZclStatus::Success
            } else {
                ZclStatus::InvalidValue
            }
        } else {
            ZclStatus::Success
        }
    }

    /// Builds a server offering `sequence`.
    pub fn server<const A: usize>(sequence: u8) -> Result<ClusterInstance<A>, ZclStatus> {
        if sequence > sequence::ON_AUTO {
            return Err(ZclStatus::InvalidValue);
        }
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(FAN_MODE, &Value::Enum8(fan_mode::AUTO))?;
        c.add_attribute(FAN_MODE_SEQUENCE, &Value::Enum8(sequence))?;
        c.write_guard = Some(guard::<A>);
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF, Role::Client)
    }

    /// Current `FanMode`.
    pub fn fan_mode<const A: usize>(c: &ClusterInstance<A>) -> u8 {
        c.u8(FAN_MODE.id).unwrap_or(fan_mode::OFF)
    }
}

#[cfg(test)]
mod tests {
    use super::thermostat::*;
    use super::*;

    fn i16v(v: i16) -> Value<'static> {
        Value::Int {
            width: 2,
            value: i64::from(v),
        }
    }

    #[test]
    fn setpoints_limits_dead_band_and_running_mode() {
        let mut c: ClusterInstance<36> = server(Capability::HeatingAndCooling).unwrap();
        let g = c.write_guard.unwrap();
        // 20 °C heat / 26 °C cool; a cool setpoint within 2.5 °C of heat
        // is INVALID_VALUE, as is one beyond the limits.
        assert_eq!(
            g(&c.attributes, OCCUPIED_COOLING_SETPOINT.id, &i16v(2100)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, OCCUPIED_COOLING_SETPOINT.id, &i16v(2250)),
            ZclStatus::Success
        );
        assert_eq!(
            g(&c.attributes, OCCUPIED_COOLING_SETPOINT.id, &i16v(3300)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, OCCUPIED_HEATING_SETPOINT.id, &i16v(2400)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, OCCUPIED_HEATING_SETPOINT.id, &i16v(600)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(
                &c.attributes,
                MIN_SETPOINT_DEAD_BAND.id,
                &Value::Int {
                    width: 1,
                    value: 30
                }
            ),
            ZclStatus::InvalidValue
        );
        // SystemMode follows the control sequence.
        c.set(
            CONTROL_SEQUENCE_OF_OPERATION.id,
            &Value::Enum8(control_sequence::HEATING_ONLY),
        );
        assert_eq!(
            g(
                &c.attributes,
                SYSTEM_MODE.id,
                &Value::Enum8(system_mode::COOL)
            ),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(
                &c.attributes,
                SYSTEM_MODE.id,
                &Value::Enum8(system_mode::HEAT)
            ),
            ZclStatus::Success
        );
        c.set(
            CONTROL_SEQUENCE_OF_OPERATION.id,
            &Value::Enum8(control_sequence::COOLING_AND_HEATING),
        );
        // Running mode per Table 6-17.
        c.set(SYSTEM_MODE.id, &Value::Enum8(system_mode::AUTO));
        assert!(set_local_temperature(&mut c, Some(1800)));
        assert_eq!(c.u8(THERMOSTAT_RUNNING_MODE.id), Some(system_mode::HEAT));
        set_local_temperature(&mut c, Some(2300));
        assert_eq!(c.u8(THERMOSTAT_RUNNING_MODE.id), Some(system_mode::OFF));
        set_local_temperature(&mut c, Some(2800));
        assert_eq!(c.u8(THERMOSTAT_RUNNING_MODE.id), Some(system_mode::COOL));
        c.set(SYSTEM_MODE.id, &Value::Enum8(system_mode::HEAT));
        assert_eq!(running_mode(&c), system_mode::OFF);
        // Setpoint Raise/Lower: +1.5 °C on both, then -10 °C on heat is
        // clamped to the limit, then cool pushed by the dead band.
        assert_eq!(
            handle(
                &mut c,
                CMD_SETPOINT_RAISE_LOWER,
                &[raise_lower_mode::BOTH, 15]
            ),
            Outcome::Adjusted {
                heat: Some(2150),
                cool: Some(2750)
            }
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_SETPOINT_RAISE_LOWER,
                &[raise_lower_mode::HEAT, 100u8.wrapping_neg()]
            ),
            Outcome::Adjusted {
                heat: Some(1150),
                cool: Some(2750)
            }
        );
        c.set_i16(OCCUPIED_HEATING_SETPOINT.id, 2500);
        assert_eq!(
            handle(
                &mut c,
                CMD_SETPOINT_RAISE_LOWER,
                &[raise_lower_mode::COOL, 50u8.wrapping_neg()]
            ),
            Outcome::Adjusted {
                heat: Some(2500),
                cool: Some(2750)
            }
        );
        assert_eq!(
            handle(&mut c, CMD_SETPOINT_RAISE_LOWER, &[9, 1]),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        // Scene fields round trip.
        let f = scene_fields(&c);
        c.set_i16(OCCUPIED_HEATING_SETPOINT.id, 1000);
        apply_scene_fields(&mut c, &f);
        assert_eq!(c.i16(OCCUPIED_HEATING_SETPOINT.id), Some(2500));
        // A heating-only valve has no cooling setpoint or dead band.
        let v: ClusterInstance<36> = server(Capability::Heating).unwrap();
        assert!(v.i16(OCCUPIED_COOLING_SETPOINT.id).is_none());
        assert_eq!(
            v.u8(CONTROL_SEQUENCE_OF_OPERATION.id),
            Some(control_sequence::HEATING_ONLY)
        );
    }

    #[test]
    fn fan_modes_follow_the_sequence() {
        use super::fan_control::*;
        let c: ClusterInstance<8> = server(sequence::LOW_HIGH).unwrap();
        let g = c.write_guard.unwrap();
        assert_eq!(
            g(&c.attributes, FAN_MODE.id, &Value::Enum8(fan_mode::MEDIUM)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, FAN_MODE.id, &Value::Enum8(fan_mode::HIGH)),
            ZclStatus::Success
        );
        assert_eq!(
            g(&c.attributes, FAN_MODE.id, &Value::Enum8(fan_mode::AUTO)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, FAN_MODE_SEQUENCE.id, &Value::Enum8(9)),
            ZclStatus::InvalidValue
        );
        assert!(mode_in_sequence(sequence::ON_AUTO, fan_mode::ON));
        assert!(!mode_in_sequence(sequence::ON_AUTO, fan_mode::LOW));
        assert_eq!(fan_mode(&c), fan_mode::AUTO);
        assert!(server::<8>(7).is_err());
    }
}
