//! HVAC clusters (ZCL8 chapter 6): the Thermostat core — information
//! and settings attributes, the setpoint limit and dead-band rules
//! enforced on writes, Setpoint Raise/Lower, the running-mode
//! interpretation of Table 6-17, the weekly setpoint schedule, the
//! setpoint change tracking, AC information and relay status log sets
//! and the scene extension — and Fan Control.

use heapless::Vec;
use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, AttributeTable, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
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
    /// `StartOfWeek` (enum8, Table 6-21): present when the weekly
    /// schedule is supported.
    pub const START_OF_WEEK: AttributeDef = AttributeDef::new(0x0020, DataType::Enum8, Access::RO);
    /// `NumberOfWeeklyTransitions` (uint8).
    pub const NUMBER_OF_WEEKLY_TRANSITIONS: AttributeDef =
        AttributeDef::new(0x0021, DataType::Uint(1), Access::RO);
    /// `NumberOfDailyTransitions` (uint8).
    pub const NUMBER_OF_DAILY_TRANSITIONS: AttributeDef =
        AttributeDef::new(0x0022, DataType::Uint(1), Access::RO);
    /// `TemperatureSetpointHold` (enum8, Table 6-22): while on, the
    /// schedule leaves the setpoints alone.
    pub const TEMPERATURE_SETPOINT_HOLD: AttributeDef =
        AttributeDef::new(0x0023, DataType::Enum8, Access::RW);
    /// `TemperatureSetpointHoldDuration` (uint16 minutes, 0…1440, 0xffff
    /// unused).
    pub const TEMPERATURE_SETPOINT_HOLD_DURATION: AttributeDef =
        AttributeDef::new(0x0024, DataType::Uint(2), Access::RW);
    /// `ThermostatProgrammingOperationMode` (map8, Table 6-23, reported).
    pub const THERMOSTAT_PROGRAMMING_OPERATION_MODE: AttributeDef =
        AttributeDef::new(0x0025, DataType::Bitmap(1), Access::RW_REPORT);
    /// `ThermostatRunningState` (map16, Table 6-24).
    pub const THERMOSTAT_RUNNING_STATE: AttributeDef =
        AttributeDef::new(0x0029, DataType::Bitmap(2), Access::RO);
    /// `SetpointChangeSource` (enum8, Table 6-26).
    pub const SETPOINT_CHANGE_SOURCE: AttributeDef =
        AttributeDef::new(0x0030, DataType::Enum8, Access::RO);
    /// `SetpointChangeAmount` (int16 0.01 °C, 0x8000 unknown).
    pub const SETPOINT_CHANGE_AMOUNT: AttributeDef =
        AttributeDef::new(0x0031, DataType::Int(2), Access::RO);
    /// `SetpointChangeSourceTimestamp` (UTC).
    pub const SETPOINT_CHANGE_SOURCE_TIMESTAMP: AttributeDef =
        AttributeDef::new(0x0032, DataType::UtcTime, Access::RO);
    /// `OccupiedSetback` (uint8 0.1 °C, 0xff unused).
    pub const OCCUPIED_SETBACK: AttributeDef =
        AttributeDef::new(0x0034, DataType::Uint(1), Access::RW);
    /// `OccupiedSetbackMin`.
    pub const OCCUPIED_SETBACK_MIN: AttributeDef =
        AttributeDef::new(0x0035, DataType::Uint(1), Access::RO);
    /// `OccupiedSetbackMax`.
    pub const OCCUPIED_SETBACK_MAX: AttributeDef =
        AttributeDef::new(0x0036, DataType::Uint(1), Access::RO);
    /// `UnoccupiedSetback`.
    pub const UNOCCUPIED_SETBACK: AttributeDef =
        AttributeDef::new(0x0037, DataType::Uint(1), Access::RW);
    /// `UnoccupiedSetbackMin`.
    pub const UNOCCUPIED_SETBACK_MIN: AttributeDef =
        AttributeDef::new(0x0038, DataType::Uint(1), Access::RO);
    /// `UnoccupiedSetbackMax`.
    pub const UNOCCUPIED_SETBACK_MAX: AttributeDef =
        AttributeDef::new(0x0039, DataType::Uint(1), Access::RO);
    /// `EmergencyHeatDelta` (uint8 0.1 °C, 0xff unused).
    pub const EMERGENCY_HEAT_DELTA: AttributeDef =
        AttributeDef::new(0x003a, DataType::Uint(1), Access::RW);
    /// `ACType` (enum8, Table 6-29).
    pub const AC_TYPE: AttributeDef = AttributeDef::new(0x0040, DataType::Enum8, Access::RW);
    /// `ACCapacity` (uint16, in `ACCapacityFormat`).
    pub const AC_CAPACITY: AttributeDef = AttributeDef::new(0x0041, DataType::Uint(2), Access::RW);
    /// `ACRefrigerantType` (enum8, Table 6-30).
    pub const AC_REFRIGERANT_TYPE: AttributeDef =
        AttributeDef::new(0x0042, DataType::Enum8, Access::RW);
    /// `ACCompressorType` (enum8, Table 6-31).
    pub const AC_COMPRESSOR_TYPE: AttributeDef =
        AttributeDef::new(0x0043, DataType::Enum8, Access::RW);
    /// `ACErrorCode` (map32, Table 6-32).
    pub const AC_ERROR_CODE: AttributeDef =
        AttributeDef::new(0x0044, DataType::Bitmap(4), Access::RW);
    /// `ACLouverPosition` (enum8, Table 6-33).
    pub const AC_LOUVER_POSITION: AttributeDef =
        AttributeDef::new(0x0045, DataType::Enum8, Access::RW);
    /// `ACCoilTemperature` (int16 0.01 °C).
    pub const AC_COIL_TEMPERATURE: AttributeDef =
        AttributeDef::new(0x0046, DataType::Int(2), Access::RO);
    /// `ACCapacityFormat` (enum8, Table 6-34: 0 BTUh).
    pub const AC_CAPACITY_FORMAT: AttributeDef =
        AttributeDef::new(0x0047, DataType::Enum8, Access::RW);

    /// Setback non-value.
    pub const SETBACK_UNUSED: u8 = 0xff;
    /// Hold duration non-value.
    pub const HOLD_DURATION_UNUSED: u16 = 0xffff;

    /// `SetpointChangeSource` values (Table 6-26).
    pub mod setpoint_source {
        /// Manual change at the thermostat.
        pub const MANUAL: u8 = 0x00;
        /// The schedule / internal programming.
        pub const SCHEDULE: u8 = 0x01;
        /// External: a command or attribute write.
        pub const EXTERNAL: u8 = 0x02;
    }

    /// `ThermostatProgrammingOperationMode` bits (Table 6-23).
    pub mod programming_mode {
        /// Schedule programming enabled.
        pub const SCHEDULE: u8 = 0x01;
        /// Auto / recovery.
        pub const RECOVERY: u8 = 0x02;
        /// Economy / EnergyStar.
        pub const ECONOMY: u8 = 0x04;
    }

    /// `ThermostatRunningState` bits (Table 6-24).
    pub mod running_state {
        /// Heat relay.
        pub const HEAT: u16 = 1 << 0;
        /// Cool relay.
        pub const COOL: u16 = 1 << 1;
        /// Fan relay.
        pub const FAN: u16 = 1 << 2;
        /// Heat second stage.
        pub const HEAT_STAGE_2: u16 = 1 << 3;
        /// Cool second stage.
        pub const COOL_STAGE_2: u16 = 1 << 4;
        /// Fan second stage.
        pub const FAN_STAGE_2: u16 = 1 << 5;
        /// Fan third stage.
        pub const FAN_STAGE_3: u16 = 1 << 6;
    }

    /// Get Relay Status Log (§6.3.2.3.5).
    pub const CMD_GET_RELAY_STATUS_LOG: CommandId = CommandId(0x04);
    /// Get Relay Status Log Response (§6.3.2.4.2, server command).
    pub const CMD_GET_RELAY_STATUS_LOG_RESPONSE: CommandId = CommandId(0x01);
    /// Relay status log capacity.
    pub const MAX_RELAY_LOG: usize = 8;

    /// One relay status log record (§6.3.2.4.2).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct RelayLogEntry {
        /// Minutes since midnight when captured.
        pub time_of_day: u16,
        /// Relay bits (manufacturer mapping).
        pub relay_status: u8,
        /// `LocalTemperature` when captured (0.01 °C).
        pub local_temperature: i16,
        /// Humidity in percent (0xff unknown).
        pub humidity: u8,
        /// The target setpoint when captured (0.01 °C).
        pub setpoint: i16,
    }

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
    /// Set Weekly Schedule (§6.3.2.3.2).
    pub const CMD_SET_WEEKLY_SCHEDULE: CommandId = CommandId(0x01);
    /// Get Weekly Schedule (§6.3.2.3.3).
    pub const CMD_GET_WEEKLY_SCHEDULE: CommandId = CommandId(0x02);
    /// Clear Weekly Schedule (§6.3.2.3.4).
    pub const CMD_CLEAR_WEEKLY_SCHEDULE: CommandId = CommandId(0x03);
    /// Get Weekly Schedule Response (§6.3.2.4.1, server to client).
    pub const CMD_GET_WEEKLY_SCHEDULE_RESPONSE: CommandId = CommandId(0x00);

    /// Day of Week for Sequence bits (Table 6-37).
    pub mod day_of_week {
        /// Sunday.
        pub const SUNDAY: u8 = 0x01;
        /// Monday.
        pub const MONDAY: u8 = 0x02;
        /// Tuesday.
        pub const TUESDAY: u8 = 0x04;
        /// Wednesday.
        pub const WEDNESDAY: u8 = 0x08;
        /// Thursday.
        pub const THURSDAY: u8 = 0x10;
        /// Friday.
        pub const FRIDAY: u8 = 0x20;
        /// Saturday.
        pub const SATURDAY: u8 = 0x40;
        /// Away or vacation.
        pub const AWAY: u8 = 0x80;
    }

    /// Mode for Sequence bits (Table 6-38).
    pub mod schedule_mode {
        /// Heat setpoints present.
        pub const HEAT: u8 = 0x01;
        /// Cool setpoints present.
        pub const COOL: u8 = 0x02;
    }

    /// Most transitions a single day may hold: a Get Weekly Schedule
    /// Response for one day then always fits one frame (§6.3.2.3.2.2
    /// sends larger schedules in several commands).
    pub const MAX_DAILY_TRANSITIONS: usize = 10;
    /// Capacity of the schedule store across the seven days and the
    /// away day.
    pub const MAX_WEEKLY_TRANSITIONS: usize = 28;
    /// Minutes in a day (transition times are minutes since midnight).
    const MINUTES_PER_DAY: u16 = 24 * 60;
    /// Index of the away day in [`Transition::day`].
    pub const AWAY_DAY: u8 = 7;

    /// One scheduled setpoint change.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Transition {
        /// Day: 0 Sunday … 6 Saturday, [`AWAY_DAY`] for the away set.
        pub day: u8,
        /// Minutes since midnight.
        pub time: u16,
        /// Heat setpoint (0.01 °C) when the sequence carried one.
        pub heat: Option<i16>,
        /// Cool setpoint (0.01 °C) when the sequence carried one.
        pub cool: Option<i16>,
    }

    /// The weekly setpoint schedule of a server (§6.3.2.2.3) and its
    /// relay status log (§6.3.2.3.5).
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    pub struct Schedule {
        /// Transitions ordered by day then time.
        pub transitions: Vec<Transition, MAX_WEEKLY_TRANSITIONS>,
        /// `NumberOfWeeklyTransitions` (0: no schedule extension).
        pub weekly: u8,
        /// `NumberOfDailyTransitions`.
        pub daily: u8,
        /// The transition last applied to the setpoints, so it is applied
        /// once.
        pub applied: Option<(u8, u16)>,
        /// The schedule changed and has not been run against the clock.
        pub dirty: bool,
        /// Relay status log, oldest first.
        pub relay_log: Vec<RelayLogEntry, MAX_RELAY_LOG>,
        /// Unread relay log entries.
        pub unread: u8,
    }

    /// Longest Get Weekly Schedule Response payload: the header and
    /// [`MAX_DAILY_TRANSITIONS`] heat-and-cool transitions.
    pub const RESPONSE_MAX: usize = 3 + MAX_DAILY_TRANSITIONS * 6;

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

    /// Cluster definition of a server with the weekly schedule.
    pub const SCHEDULE_DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 3,
        received: &[
            CMD_SETPOINT_RAISE_LOWER,
            CMD_SET_WEEKLY_SCHEDULE,
            CMD_GET_WEEKLY_SCHEDULE,
            CMD_CLEAR_WEEKLY_SCHEDULE,
        ],
        generated: &[CMD_GET_WEEKLY_SCHEDULE_RESPONSE],
    };

    /// Cluster definition of a server with the weekly schedule and the
    /// relay status log.
    pub const FULL_DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 3,
        received: &[
            CMD_SETPOINT_RAISE_LOWER,
            CMD_SET_WEEKLY_SCHEDULE,
            CMD_GET_WEEKLY_SCHEDULE,
            CMD_CLEAR_WEEKLY_SCHEDULE,
            CMD_GET_RELAY_STATUS_LOG,
        ],
        generated: &[
            CMD_GET_WEEKLY_SCHEDULE_RESPONSE,
            CMD_GET_RELAY_STATUS_LOG_RESPONSE,
        ],
    };

    /// Cluster definition of a server with the relay status log only.
    pub const RELAY_LOG_DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 3,
        received: &[CMD_SETPOINT_RAISE_LOWER, CMD_GET_RELAY_STATUS_LOG],
        generated: &[CMD_GET_RELAY_STATUS_LOG_RESPONSE],
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
            i if i == TEMPERATURE_SETPOINT_HOLD.id => {
                if val <= 0x01 {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == TEMPERATURE_SETPOINT_HOLD_DURATION.id => {
                if val <= 0x05a0 || val == i64::from(HOLD_DURATION_UNUSED) {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == THERMOSTAT_PROGRAMMING_OPERATION_MODE.id => {
                if v.as_u64().is_some_and(|m| m <= 0x07) {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == AC_TYPE.id => {
                if val <= 0x04 {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == AC_REFRIGERANT_TYPE.id || i == AC_COMPRESSOR_TYPE.id => {
                if val <= 0x03 {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == AC_LOUVER_POSITION.id => {
                if (1..=5).contains(&val) {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            i if i == AC_CAPACITY_FORMAT.id => {
                if val == 0 {
                    ZclStatus::Success
                } else {
                    ZclStatus::InvalidValue
                }
            }
            _ => ZclStatus::Success,
        }
    }

    /// Clamps a written setback into its min / max (§6.3.2.2.4.4: the
    /// write succeeds with the bound).
    fn after_write<const A: usize>(c: &mut ClusterInstance<A>, id: AttributeId) {
        let (min_id, max_id) = if id == OCCUPIED_SETBACK.id {
            (OCCUPIED_SETBACK_MIN.id, OCCUPIED_SETBACK_MAX.id)
        } else if id == UNOCCUPIED_SETBACK.id {
            (UNOCCUPIED_SETBACK_MIN.id, UNOCCUPIED_SETBACK_MAX.id)
        } else {
            return;
        };
        let Some(v) = c.u8(id) else {
            return;
        };
        if v == SETBACK_UNUSED {
            return;
        }
        let min = c.u8(min_id).unwrap_or(0);
        let max = c.u8(max_id).unwrap_or(SETBACK_UNUSED);
        let clamped = if min != SETBACK_UNUSED && v < min {
            min
        } else if max != SETBACK_UNUSED && v > max {
            max
        } else {
            v
        };
        if clamped != v {
            c.set_u8(id, clamped);
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

    /// Adds the weekly schedule extension (§6.3.2.2.3) to a server:
    /// `StartOfWeek` (Table 6-21), the transition capacities (`daily` at
    /// most [`MAX_DAILY_TRANSITIONS`], `weekly` at most
    /// [`MAX_WEEKLY_TRANSITIONS`]), `TemperatureSetpointHold` and the
    /// Set / Get / Clear Weekly Schedule commands.
    pub fn enable_weekly_schedule<const A: usize>(
        c: &mut ClusterInstance<A>,
        start_of_week: u8,
        weekly: u8,
        daily: u8,
    ) -> Result<(), ZclStatus> {
        if start_of_week > 6
            || usize::from(daily) > MAX_DAILY_TRANSITIONS
            || usize::from(weekly) > MAX_WEEKLY_TRANSITIONS
            || daily > weekly
        {
            return Err(ZclStatus::InvalidValue);
        }
        c.add_attribute(START_OF_WEEK, &Value::Enum8(start_of_week))?;
        c.add_attribute(
            NUMBER_OF_WEEKLY_TRANSITIONS,
            &Value::Uint {
                width: 1,
                value: u64::from(weekly),
            },
        )?;
        c.add_attribute(
            NUMBER_OF_DAILY_TRANSITIONS,
            &Value::Uint {
                width: 1,
                value: u64::from(daily),
            },
        )?;
        c.add_attribute(TEMPERATURE_SETPOINT_HOLD, &Value::Enum8(0))?;
        c.def = if c.def.received.contains(&CMD_GET_RELAY_STATUS_LOG) {
            FULL_DEF
        } else {
            SCHEDULE_DEF
        };
        let s = extras_mut(c);
        s.weekly = weekly;
        s.daily = daily;
        s.dirty = true;
        Ok(())
    }

    /// The weekly schedule of a server (`None` without the extension).
    pub fn schedule<const A: usize>(c: &ClusterInstance<A>) -> Option<&Schedule> {
        match &c.state {
            ClusterState::Thermostat(s) if s.weekly > 0 => Some(s),
            _ => None,
        }
    }

    fn extras_mut<const A: usize>(c: &mut ClusterInstance<A>) -> &mut Schedule {
        if !matches!(c.state, ClusterState::Thermostat(_)) {
            c.state = ClusterState::Thermostat(Schedule::default());
        }
        match &mut c.state {
            ClusterState::Thermostat(s) => s,
            _ => unreachable!(),
        }
    }

    /// Adds the setpoint change tracking set (§6.3.2.2.4): the change
    /// source / amount / timestamp, the occupied and unoccupied setbacks
    /// with their bounds (0.1 °C; `SETBACK_UNUSED` disables one) and
    /// `EmergencyHeatDelta`. Setback writes beyond the bounds are clamped.
    pub fn enable_setpoint_tracking<const A: usize>(
        c: &mut ClusterInstance<A>,
        occupied: (u8, u8),
        unoccupied: (u8, u8),
    ) -> Result<(), ZclStatus> {
        let bounds_ok =
            |(lo, hi): (u8, u8)| lo == SETBACK_UNUSED || hi == SETBACK_UNUSED || lo < hi;
        if !bounds_ok(occupied) || !bounds_ok(unoccupied) {
            return Err(ZclStatus::InvalidValue);
        }
        let u8v = |v: u8| Value::Uint {
            width: 1,
            value: u64::from(v),
        };
        c.add_attribute(
            SETPOINT_CHANGE_SOURCE,
            &Value::Enum8(setpoint_source::MANUAL),
        )?;
        c.add_attribute(SETPOINT_CHANGE_AMOUNT, &i16v(UNKNOWN))?;
        c.add_attribute(
            SETPOINT_CHANGE_SOURCE_TIMESTAMP,
            &Value::Time {
                ty: DataType::UtcTime,
                raw: 0,
            },
        )?;
        c.add_attribute(OCCUPIED_SETBACK, &u8v(SETBACK_UNUSED))?;
        c.add_attribute(OCCUPIED_SETBACK_MIN, &u8v(occupied.0))?;
        c.add_attribute(OCCUPIED_SETBACK_MAX, &u8v(occupied.1))?;
        c.add_attribute(UNOCCUPIED_SETBACK, &u8v(SETBACK_UNUSED))?;
        c.add_attribute(UNOCCUPIED_SETBACK_MIN, &u8v(unoccupied.0))?;
        c.add_attribute(UNOCCUPIED_SETBACK_MAX, &u8v(unoccupied.1))?;
        c.add_attribute(EMERGENCY_HEAT_DELTA, &u8v(SETBACK_UNUSED))?;
        c.after_write = Some(after_write::<A>);
        Ok(())
    }

    /// Adds the AC information set (§6.3.2.2.5) at its defaults, plus
    /// `TemperatureSetpointHoldDuration`,
    /// `ThermostatProgrammingOperationMode` and `ThermostatRunningState`.
    pub fn enable_ac_information<const A: usize>(
        c: &mut ClusterInstance<A>,
    ) -> Result<(), ZclStatus> {
        c.add_attribute(
            TEMPERATURE_SETPOINT_HOLD_DURATION,
            &Value::Uint {
                width: 2,
                value: u64::from(HOLD_DURATION_UNUSED),
            },
        )?;
        c.add_reported_attribute(
            THERMOSTAT_PROGRAMMING_OPERATION_MODE,
            &Value::Bits { width: 1, bits: 0 },
            DEMAND_REPORTING,
        )?;
        c.add_attribute(THERMOSTAT_RUNNING_STATE, &Value::Bits { width: 2, bits: 0 })?;
        c.add_attribute(AC_TYPE, &Value::Enum8(0))?;
        c.add_attribute(AC_CAPACITY, &Value::Uint { width: 2, value: 0 })?;
        c.add_attribute(AC_REFRIGERANT_TYPE, &Value::Enum8(0))?;
        c.add_attribute(AC_COMPRESSOR_TYPE, &Value::Enum8(0))?;
        c.add_attribute(AC_ERROR_CODE, &Value::Bits { width: 4, bits: 0 })?;
        c.add_attribute(AC_LOUVER_POSITION, &Value::Enum8(1))?;
        c.add_attribute(AC_COIL_TEMPERATURE, &i16v(UNKNOWN))?;
        c.add_attribute(AC_CAPACITY_FORMAT, &Value::Enum8(0))?;
        Ok(())
    }

    /// Enables the relay status log (§6.3.2.3.5) and its command.
    pub fn enable_relay_log<const A: usize>(c: &mut ClusterInstance<A>) {
        let _ = extras_mut(c);
        c.def = if c.def.received.contains(&CMD_SET_WEEKLY_SCHEDULE) {
            FULL_DEF
        } else {
            RELAY_LOG_DEF
        };
    }

    /// Records a relay status sample (§6.3.2.3.5): the relay bits with
    /// the current local temperature, `humidity` (0xff unknown) and the
    /// running mode's setpoint; the oldest record makes room. Also
    /// mirrors the heat / cool bits into `ThermostatRunningState`.
    pub fn record_relay_status<const A: usize>(
        c: &mut ClusterInstance<A>,
        time_of_day: u16,
        relay_status: u8,
        humidity: u8,
    ) {
        let temp = c.i16(LOCAL_TEMPERATURE.id).unwrap_or(UNKNOWN);
        let setpoint = match c.u8(THERMOSTAT_RUNNING_MODE.id) {
            Some(system_mode::COOL) => c.i16(OCCUPIED_COOLING_SETPOINT.id),
            _ => c.i16(OCCUPIED_HEATING_SETPOINT.id),
        }
        .unwrap_or(UNKNOWN);
        if c.attributes
            .get(THERMOSTAT_RUNNING_STATE.id, None)
            .is_some()
        {
            c.set(
                THERMOSTAT_RUNNING_STATE.id,
                &Value::Bits {
                    width: 2,
                    bits: u64::from(relay_status),
                },
            );
        }
        let s = extras_mut(c);
        if s.relay_log.is_full() {
            s.relay_log.remove(0);
        }
        let _ = s.relay_log.push(RelayLogEntry {
            time_of_day: time_of_day.min(1439),
            relay_status,
            local_temperature: temp,
            humidity,
            setpoint,
        });
        s.unread = s
            .unread
            .saturating_add(1)
            .min(u8::try_from(MAX_RELAY_LOG).unwrap_or(u8::MAX));
    }

    /// Records a setpoint change for the tracking set (§6.3.2.2.4):
    /// `source`, the delta from `previous` to `new` and, when known, the
    /// UTC time.
    pub fn note_setpoint_change<const A: usize>(
        c: &mut ClusterInstance<A>,
        source: u8,
        previous: i16,
        new: i16,
        utc: Option<u32>,
    ) {
        if c.attributes.get(SETPOINT_CHANGE_SOURCE.id, None).is_none() {
            return;
        }
        c.set(SETPOINT_CHANGE_SOURCE.id, &Value::Enum8(source));
        let delta = i16::try_from(i32::from(new) - i32::from(previous)).unwrap_or(UNKNOWN);
        c.set_i16(SETPOINT_CHANGE_AMOUNT.id, delta);
        if let Some(t) = utc {
            c.set(
                SETPOINT_CHANGE_SOURCE_TIMESTAMP.id,
                &Value::Time {
                    ty: DataType::UtcTime,
                    raw: t,
                },
            );
        }
    }

    /// Stamps the last recorded setpoint change with the UTC time (the
    /// dispatcher supplies it from the endpoint's Time server).
    pub fn stamp_setpoint_change<const A: usize>(c: &mut ClusterInstance<A>, utc: u32) {
        if c.attributes
            .get(SETPOINT_CHANGE_SOURCE_TIMESTAMP.id, None)
            .is_some()
        {
            c.set(
                SETPOINT_CHANGE_SOURCE_TIMESTAMP.id,
                &Value::Time {
                    ty: DataType::UtcTime,
                    raw: utc,
                },
            );
        }
    }

    /// The Get Relay Status Log Response (§6.3.2.4.2): the newest unread
    /// record (LIFO), or the newest record again once all were read.
    fn relay_status_log_response<const A: usize>(
        c: &mut ClusterInstance<A>,
    ) -> Option<Vec<u8, 10>> {
        let s = extras_mut(c);
        let n = s.relay_log.len();
        // The unread records are the newest `unread`; LIFO hands out the
        // newest of them first.
        let index = if s.unread == 0 {
            n.checked_sub(1)?
        } else {
            usize::from(s.unread).min(n).checked_sub(1)?
        };
        let e = *s.relay_log.get(index)?;
        s.unread = s.unread.saturating_sub(1);
        let unread = s.unread;
        let mut out = Vec::new();
        let _ = out.extend_from_slice(&e.time_of_day.to_le_bytes());
        let _ = out.push(e.relay_status);
        let _ = out.extend_from_slice(&e.local_temperature.to_le_bytes());
        let _ = out.push(e.humidity);
        let _ = out.extend_from_slice(&e.setpoint.to_le_bytes());
        let _ = out.extend_from_slice(&u16::from(unread).to_le_bytes());
        Some(out)
    }

    fn schedule_mut<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut Schedule> {
        match &mut c.state {
            ClusterState::Thermostat(s) if s.weekly > 0 => Some(s),
            _ => None,
        }
    }

    /// Whether the schedule needs running: it changed, or its next
    /// transition is due.
    pub fn schedule_due<const A: usize>(c: &ClusterInstance<A>, now: Instant) -> bool {
        schedule(c).is_some_and(|s| s.dirty) || c.tick.is_some_and(|t| now.has_reached(t))
    }

    /// The transition in force at `minutes` on `day`: the latest one
    /// today at or before `minutes`, else the last one of the nearest
    /// earlier day that has any (the away set is never selected).
    pub fn transition_in_force(s: &Schedule, day: u8, minutes: u16) -> Option<Transition> {
        if day > 6 {
            return None;
        }
        (0..=7u8).find_map(|back| {
            let d = (day + 7 - back) % 7;
            s.transitions
                .iter()
                .filter(|t| t.day == d && (back != 0 || t.time <= minutes))
                .max_by_key(|t| t.time)
                .copied()
        })
    }

    /// Seconds from `minutes` on `day` to the next transition (today
    /// after `minutes`, else the first of the next day with any).
    fn seconds_to_next(s: &Schedule, day: u8, seconds_of_day: u32) -> Option<u32> {
        let minutes = seconds_of_day / 60;
        (0..=7u32).find_map(|ahead| {
            let d = u8::try_from((u32::from(day) + ahead) % 7).unwrap_or(0);
            s.transitions
                .iter()
                .filter(|t| t.day == d && (ahead != 0 || u32::from(t.time) > minutes))
                .map(|t| u32::from(t.time) * 60 + ahead * 86_400)
                .min()
                .map(|at| at.saturating_sub(seconds_of_day).max(1))
        })
    }

    /// Runs the schedule against the local time (§6.3.2.3.2.8):
    /// `local_time` is the ZCL local time (seconds since 2000-01-01, a
    /// Saturday) or `u32::MAX` when unknown. Applies the transition in
    /// force once (not while `TemperatureSetpointHold` is on), arms
    /// `tick` for the next one and returns the setpoints it applied.
    pub fn tick<const A: usize>(
        c: &mut ClusterInstance<A>,
        now: Instant,
        local_time: u32,
    ) -> Option<(Option<i16>, Option<i16>)> {
        // A hold, or schedule programming switched off in
        // ThermostatProgrammingOperationMode (Table 6-23 bit 0), keeps
        // the schedule off the setpoints.
        let hold = c.u8(TEMPERATURE_SETPOINT_HOLD.id) == Some(1)
            || c.u8(THERMOSTAT_PROGRAMMING_OPERATION_MODE.id)
                .is_some_and(|m| m & programming_mode::SCHEDULE == 0);
        let has_heat = c
            .attributes
            .get(OCCUPIED_HEATING_SETPOINT.id, None)
            .is_some();
        let has_cool = c
            .attributes
            .get(OCCUPIED_COOLING_SETPOINT.id, None)
            .is_some();
        schedule(c)?;
        if local_time == u32::MAX {
            c.tick = None;
            return None;
        }
        let day = u8::try_from((local_time / 86_400 + 6) % 7).unwrap_or(0);
        let seconds_of_day = local_time % 86_400;
        let minutes = u16::try_from(seconds_of_day / 60).unwrap_or(0);
        let s = schedule_mut(c)?;
        s.dirty = false;
        let next = seconds_to_next(s, day, seconds_of_day);
        let t = transition_in_force(s, day, minutes);
        let applied = s.applied;
        c.tick = next.map(|secs| now + Duration::from_secs(u64::from(secs)));
        let t = t?;
        if hold || applied == Some((t.day, t.time)) {
            return None;
        }
        schedule_mut(c)?.applied = Some((t.day, t.time));
        let heat = t.heat.filter(|_| has_heat);
        let cool = t.cool.filter(|_| has_cool);
        if let Some(h) = heat {
            let before = c.i16(OCCUPIED_HEATING_SETPOINT.id).unwrap_or(h);
            c.set_i16(OCCUPIED_HEATING_SETPOINT.id, h);
            note_setpoint_change(c, setpoint_source::SCHEDULE, before, h, None);
        }
        if let Some(k) = cool {
            let before = c.i16(OCCUPIED_COOLING_SETPOINT.id).unwrap_or(k);
            c.set_i16(OCCUPIED_COOLING_SETPOINT.id, k);
            note_setpoint_change(c, setpoint_source::SCHEDULE, before, k, None);
        }
        if heat.is_none() && cool.is_none() {
            return None;
        }
        let running = running_mode(c);
        c.set(THERMOSTAT_RUNNING_MODE.id, &Value::Enum8(running));
        Some((heat, cool))
    }

    /// Abs limits of the setpoints (Table 6-11 defaults when absent).
    fn abs_limits<const A: usize>(c: &ClusterInstance<A>) -> (i16, i16, i16, i16) {
        (
            c.i16(ABS_MIN_HEAT_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MIN_HEAT),
            c.i16(ABS_MAX_HEAT_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MAX_HEAT),
            c.i16(ABS_MIN_COOL_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MIN_COOL),
            c.i16(ABS_MAX_COOL_SETPOINT_LIMIT.id)
                .unwrap_or(DEFAULT_ABS_MAX_COOL),
        )
    }

    /// The Mode for Sequence bits a server implements.
    fn supported_modes<const A: usize>(c: &ClusterInstance<A>) -> u8 {
        let mut m = 0;
        if c.attributes
            .get(OCCUPIED_HEATING_SETPOINT.id, None)
            .is_some()
        {
            m |= schedule_mode::HEAT;
        }
        if c.attributes
            .get(OCCUPIED_COOLING_SETPOINT.id, None)
            .is_some()
        {
            m |= schedule_mode::COOL;
        }
        m
    }

    /// Set Weekly Schedule (§6.3.2.3.2.8): the transitions replace those
    /// of every day named; the whole command is refused before anything
    /// changes.
    fn set_weekly_schedule<const A: usize>(
        c: &mut ClusterInstance<A>,
        payload: &[u8],
    ) -> ZclStatus {
        let supported = supported_modes(c);
        let (min_heat, max_heat, min_cool, max_cool) = abs_limits(c);
        let Some(s) = schedule(c) else {
            return ZclStatus::UnsupportedClusterCommand;
        };
        let [n, days, mode, rest @ ..] = payload else {
            return ZclStatus::MalformedCommand;
        };
        let (n, days, mode) = (usize::from(*n), *days, *mode);
        if mode & !(schedule_mode::HEAT | schedule_mode::COOL) != 0 || mode == 0 || days == 0 {
            return ZclStatus::InvalidField;
        }
        if mode & !supported != 0 {
            return ZclStatus::InvalidField;
        }
        let heat = mode & schedule_mode::HEAT != 0;
        let cool = mode & schedule_mode::COOL != 0;
        let size = 2 + 2 * usize::from(heat) + 2 * usize::from(cool);
        if rest.len() != n * size {
            return ZclStatus::MalformedCommand;
        }
        if n > usize::from(s.daily) {
            return ZclStatus::InsufficientSpace;
        }
        let mut parsed: Vec<Transition, MAX_DAILY_TRANSITIONS> = Vec::new();
        for chunk in rest.chunks_exact(size) {
            let time = u16::from_le_bytes([chunk[0], chunk[1]]);
            if time >= MINUTES_PER_DAY {
                return ZclStatus::InvalidValue;
            }
            let mut at = 2;
            let mut take = || {
                let v = i16::from_le_bytes([chunk[at], chunk[at + 1]]);
                at += 2;
                v
            };
            let h = heat.then(&mut take);
            let k = cool.then(&mut take);
            if h.is_some_and(|h| h < min_heat || h > max_heat)
                || k.is_some_and(|k| k < min_cool || k > max_cool)
            {
                return ZclStatus::InvalidValue;
            }
            if parsed.iter().any(|t| t.time == time) {
                return ZclStatus::Failure;
            }
            let _ = parsed.push(Transition {
                day: 0,
                time,
                heat: h,
                cool: k,
            });
        }
        let kept = s
            .transitions
            .iter()
            .filter(|t| days & (1 << t.day) == 0)
            .count();
        let day_count = usize::try_from(days.count_ones()).unwrap_or(8);
        if kept + n * day_count > usize::from(s.weekly) {
            return ZclStatus::InsufficientSpace;
        }
        let Some(s) = schedule_mut(c) else {
            return ZclStatus::UnsupportedClusterCommand;
        };
        s.transitions.retain(|t| days & (1 << t.day) == 0);
        for day in 0..8u8 {
            if days & (1 << day) == 0 {
                continue;
            }
            for t in &parsed {
                let _ = s.transitions.push(Transition { day, ..*t });
            }
        }
        s.transitions.sort_unstable_by_key(|t| (t.day, t.time));
        s.applied = None;
        s.dirty = true;
        ZclStatus::Success
    }

    /// Get Weekly Schedule (§6.3.2.3.3): one day at a time (several
    /// days cannot share one response, so INVALID_FIELD as allowed); the
    /// modes returned are those asked for that the server implements,
    /// a setpoint a transition lacks reads as [`UNKNOWN`].
    fn get_weekly_schedule<const A: usize>(
        c: &ClusterInstance<A>,
        payload: &[u8],
    ) -> Result<Vec<u8, RESPONSE_MAX>, ZclStatus> {
        let s = schedule(c).ok_or(ZclStatus::UnsupportedClusterCommand)?;
        let [days, mode] = payload else {
            return Err(ZclStatus::MalformedCommand);
        };
        if days.count_ones() != 1 || *mode & !(schedule_mode::HEAT | schedule_mode::COOL) != 0 {
            return Err(ZclStatus::InvalidField);
        }
        let mode = *mode & supported_modes(c);
        if mode == 0 {
            return Err(ZclStatus::InvalidField);
        }
        let day = u8::try_from(days.trailing_zeros()).unwrap_or(0);
        let heat = mode & schedule_mode::HEAT != 0;
        let cool = mode & schedule_mode::COOL != 0;
        let mut out: Vec<u8, RESPONSE_MAX> = Vec::new();
        let _ = out.extend_from_slice(&[0, *days, mode]);
        let mut n = 0u8;
        for t in s.transitions.iter().filter(|t| t.day == day) {
            if !((heat && t.heat.is_some()) || (cool && t.cool.is_some())) {
                continue;
            }
            let _ = out.extend_from_slice(&t.time.to_le_bytes());
            if heat {
                let _ = out.extend_from_slice(&t.heat.unwrap_or(UNKNOWN).to_le_bytes());
            }
            if cool {
                let _ = out.extend_from_slice(&t.cool.unwrap_or(UNKNOWN).to_le_bytes());
            }
            n = n.saturating_add(1);
        }
        if let Some(b) = out.first_mut() {
            *b = n;
        }
        Ok(out)
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
        // §6.3.2.2.4.10: far enough below the heating setpoint, heating
        // runs in emergency heat mode.
        let emergency = c
            .u8(EMERGENCY_HEAT_DELTA.id)
            .filter(|d| *d != SETBACK_UNUSED)
            .zip(heat_sp)
            .is_some_and(|(d, h)| i32::from(h) - i32::from(t) >= i32::from(d) * 10);
        match mode {
            system_mode::HEAT | system_mode::AUTO if below_heat && emergency => {
                system_mode::EMERGENCY_HEATING
            }
            system_mode::HEAT | system_mode::EMERGENCY_HEATING if below_heat => system_mode::HEAT,
            system_mode::COOL | system_mode::PRECOOLING if above_cool => system_mode::COOL,
            system_mode::AUTO if below_heat => system_mode::HEAT,
            system_mode::AUTO if above_cool => system_mode::COOL,
            _ => system_mode::OFF,
        }
    }

    /// Result of a received command.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum Outcome {
        /// The setpoints were adjusted (heat, cool) in 0.01 °C.
        Adjusted {
            /// New heating setpoint, when implemented.
            heat: Option<i16>,
            /// New cooling setpoint, when implemented.
            cool: Option<i16>,
        },
        /// The weekly schedule was set or cleared (default response
        /// SUCCESS); the schedule is due to run.
        Scheduled,
        /// A Get Weekly Schedule Response payload.
        Response(Vec<u8, RESPONSE_MAX>),
        /// A Get Relay Status Log Response payload.
        RelayLog(Vec<u8, 10>),
        /// Refused with this status.
        Default(ZclStatus),
    }

    /// Handles Setpoint Raise/Lower (§6.3.2.3.1) — each addressed
    /// setpoint moves by `amount` tenths of a degree, clamped to its
    /// limits and the dead band — and the weekly schedule commands
    /// (§6.3.2.3.2–4) when the extension is enabled.
    pub fn handle<const A: usize>(
        c: &mut ClusterInstance<A>,
        cmd: CommandId,
        payload: &[u8],
    ) -> Outcome {
        match cmd {
            CMD_SETPOINT_RAISE_LOWER => {}
            CMD_SET_WEEKLY_SCHEDULE => {
                return match set_weekly_schedule(c, payload) {
                    ZclStatus::Success => Outcome::Scheduled,
                    status => Outcome::Default(status),
                };
            }
            CMD_GET_WEEKLY_SCHEDULE => {
                return match get_weekly_schedule(c, payload) {
                    Ok(p) => Outcome::Response(p),
                    Err(status) => Outcome::Default(status),
                };
            }
            CMD_GET_RELAY_STATUS_LOG => {
                if !c.def.received.contains(&CMD_GET_RELAY_STATUS_LOG) {
                    return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
                }
                return match relay_status_log_response(c) {
                    Some(p) => Outcome::RelayLog(p),
                    None => Outcome::Default(ZclStatus::NotFound),
                };
            }
            CMD_CLEAR_WEEKLY_SCHEDULE => {
                let Some(s) = schedule_mut(c).filter(|s| s.weekly > 0) else {
                    return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
                };
                s.transitions.clear();
                s.applied = None;
                s.dirty = true;
                return Outcome::Scheduled;
            }
            _ => return Outcome::Default(ZclStatus::UnsupportedClusterCommand),
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
        let before_heat = c.i16(OCCUPIED_HEATING_SETPOINT.id);
        let before_cool = c.i16(OCCUPIED_COOLING_SETPOINT.id);
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
        // §6.3.2.2.4: the active setpoint's change is tracked.
        let tracked = match (before_heat, heat, before_cool, cool) {
            (Some(b), Some(n), _, _) if do_heat => Some((b, i16::try_from(n).unwrap_or(b))),
            (_, _, Some(b), Some(n)) if do_cool => Some((b, i16::try_from(n).unwrap_or(b))),
            _ => None,
        };
        if let Some((b, n)) = tracked {
            note_setpoint_change(c, setpoint_source::EXTERNAL, b, n, None);
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

    fn scheduled() -> ClusterInstance<36> {
        let mut c: ClusterInstance<36> = server(Capability::HeatingAndCooling).unwrap();
        enable_weekly_schedule(&mut c, 1, 12, 4).unwrap();
        c
    }

    /// Set Weekly Schedule payload: header then (time, heat, cool) rows.
    fn set_payload(days: u8, mode: u8, rows: &[(u16, Option<i16>, Option<i16>)]) -> Vec<u8, 64> {
        let mut p: Vec<u8, 64> = Vec::new();
        let _ = p.extend_from_slice(&[rows.len() as u8, days, mode]);
        for (t, h, k) in rows {
            let _ = p.extend_from_slice(&t.to_le_bytes());
            if let Some(h) = h {
                let _ = p.extend_from_slice(&h.to_le_bytes());
            }
            if let Some(k) = k {
                let _ = p.extend_from_slice(&k.to_le_bytes());
            }
        }
        p
    }

    #[test]
    fn weekly_schedule_set_get_clear() {
        let mut c = scheduled();
        assert_eq!(c.u8(START_OF_WEEK.id), Some(1));
        assert_eq!(c.u8(NUMBER_OF_WEEKLY_TRANSITIONS.id), Some(12));
        assert_eq!(c.u8(NUMBER_OF_DAILY_TRANSITIONS.id), Some(4));
        assert!(c.def.received.contains(&CMD_SET_WEEKLY_SCHEDULE));
        let weekdays = day_of_week::MONDAY
            | day_of_week::TUESDAY
            | day_of_week::WEDNESDAY
            | day_of_week::THURSDAY
            | day_of_week::FRIDAY;
        let both = schedule_mode::HEAT | schedule_mode::COOL;
        // Two heat-and-cool transitions for every weekday.
        let p = set_payload(
            weekdays,
            both,
            &[
                (360, Some(2100), Some(2600)),
                (1320, Some(1800), Some(2800)),
            ],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &p),
            Outcome::Scheduled
        );
        assert_eq!(schedule(&c).unwrap().transitions.len(), 10);
        // Get Monday, heat only: the heat setpoints in time order.
        assert_eq!(
            handle(
                &mut c,
                CMD_GET_WEEKLY_SCHEDULE,
                &[day_of_week::MONDAY, schedule_mode::HEAT]
            ),
            Outcome::Response(
                Vec::from_slice(&[
                    2,
                    day_of_week::MONDAY,
                    schedule_mode::HEAT,
                    0x68,
                    0x01,
                    0x34,
                    0x08,
                    0x28,
                    0x05,
                    0x08,
                    0x07
                ])
                .unwrap()
            )
        );
        // Several days cannot share one response.
        assert_eq!(
            handle(
                &mut c,
                CMD_GET_WEEKLY_SCHEDULE,
                &[day_of_week::MONDAY | day_of_week::TUESDAY, both]
            ),
            Outcome::Default(ZclStatus::InvalidField)
        );
        // Refusals leave the schedule untouched: too many transitions
        // for a day, a setpoint beyond the Abs limits, a duplicate time,
        // no mode, a malformed length, and the weekly capacity.
        let five = set_payload(
            day_of_week::SATURDAY,
            schedule_mode::HEAT,
            &[
                (0, Some(2000), None),
                (60, Some(2000), None),
                (120, Some(2000), None),
                (180, Some(2000), None),
                (240, Some(2000), None),
            ],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &five),
            Outcome::Default(ZclStatus::InsufficientSpace)
        );
        let cold = set_payload(
            day_of_week::SATURDAY,
            schedule_mode::HEAT,
            &[(0, Some(500), None)],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &cold),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        let dup = set_payload(
            day_of_week::SATURDAY,
            schedule_mode::HEAT,
            &[(0, Some(2000), None), (0, Some(2100), None)],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &dup),
            Outcome::Default(ZclStatus::Failure)
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_SET_WEEKLY_SCHEDULE,
                &[1, day_of_week::SATURDAY, 0, 0, 0]
            ),
            Outcome::Default(ZclStatus::InvalidField)
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_SET_WEEKLY_SCHEDULE,
                &[1, day_of_week::SATURDAY, 1, 0, 0]
            ),
            Outcome::Default(ZclStatus::MalformedCommand)
        );
        let weekend = set_payload(
            day_of_week::SATURDAY | day_of_week::SUNDAY,
            schedule_mode::HEAT,
            &[(480, Some(2000), None), (1380, Some(1700), None)],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &weekend),
            Outcome::Default(ZclStatus::InsufficientSpace)
        );
        assert_eq!(schedule(&c).unwrap().transitions.len(), 10);
        // Replacing Monday's set with one heat-only transition.
        let monday = set_payload(
            day_of_week::MONDAY,
            schedule_mode::HEAT,
            &[(420, Some(1950), None)],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &monday),
            Outcome::Scheduled
        );
        assert_eq!(schedule(&c).unwrap().transitions.len(), 9);
        // Asked for both modes, the missing cool setpoint reads unknown.
        assert_eq!(
            handle(
                &mut c,
                CMD_GET_WEEKLY_SCHEDULE,
                &[day_of_week::MONDAY, both]
            ),
            Outcome::Response(
                Vec::from_slice(&[
                    1,
                    day_of_week::MONDAY,
                    both,
                    0xa4,
                    0x01,
                    0x9e,
                    0x07,
                    0x00,
                    0x80
                ])
                .unwrap()
            )
        );
        // Clear, then an empty Tuesday.
        assert_eq!(
            handle(&mut c, CMD_CLEAR_WEEKLY_SCHEDULE, &[]),
            Outcome::Scheduled
        );
        assert!(schedule(&c).unwrap().transitions.is_empty());
        assert_eq!(
            handle(
                &mut c,
                CMD_GET_WEEKLY_SCHEDULE,
                &[day_of_week::TUESDAY, schedule_mode::COOL]
            ),
            Outcome::Response(
                Vec::from_slice(&[0, day_of_week::TUESDAY, schedule_mode::COOL]).unwrap()
            )
        );
        // A heating-only server refuses cool sequences; a server without
        // the extension does not know the commands.
        let mut h: ClusterInstance<36> = server(Capability::Heating).unwrap();
        enable_weekly_schedule(&mut h, 0, 7, 1).unwrap();
        let cool = set_payload(
            day_of_week::MONDAY,
            schedule_mode::COOL,
            &[(0, None, Some(2600))],
        );
        assert_eq!(
            handle(&mut h, CMD_SET_WEEKLY_SCHEDULE, &cool),
            Outcome::Default(ZclStatus::InvalidField)
        );
        let mut plain: ClusterInstance<36> = server(Capability::Heating).unwrap();
        assert_eq!(
            handle(&mut plain, CMD_CLEAR_WEEKLY_SCHEDULE, &[]),
            Outcome::Default(ZclStatus::UnsupportedClusterCommand)
        );
        assert!(enable_weekly_schedule(&mut plain, 0, 4, 11).is_err());
    }

    #[test]
    fn weekly_schedule_runs_against_the_clock() {
        let mut c = scheduled();
        let monday = set_payload(
            day_of_week::MONDAY,
            schedule_mode::HEAT,
            &[(360, Some(2100), None), (1320, Some(1800), None)],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &monday),
            Outcome::Scheduled
        );
        let now = Instant::from_millis(1_000);
        assert!(schedule_due(&c, now));
        // 2000-01-03 is a Monday: 07:00 is after the 06:00 transition.
        let monday_0700 = 2 * 86_400 + 7 * 3_600;
        assert_eq!(tick(&mut c, now, monday_0700), Some((Some(2100), None)));
        assert_eq!(c.i16(OCCUPIED_HEATING_SETPOINT.id), Some(2100));
        assert_eq!(c.tick, Some(now + Duration::from_secs(15 * 3_600)));
        assert!(!schedule_due(&c, now));
        // Applied once.
        assert_eq!(tick(&mut c, now, monday_0700), None);
        let monday_2300 = monday_0700 + 16 * 3_600;
        assert_eq!(tick(&mut c, now, monday_2300), Some((Some(1800), None)));
        // Tuesday inherits Monday's last transition (already applied),
        // and the next one is next Monday 06:00.
        let tuesday_0300 = 3 * 86_400 + 3 * 3_600;
        assert_eq!(tick(&mut c, now, tuesday_0300), None);
        assert_eq!(
            c.tick,
            Some(now + Duration::from_secs(6 * 86_400 + 3 * 3_600))
        );
        // A hold keeps the schedule off the setpoints; no clock, no tick.
        c.set(TEMPERATURE_SETPOINT_HOLD.id, &Value::Enum8(1));
        c.set_i16(OCCUPIED_HEATING_SETPOINT.id, 2000);
        assert_eq!(
            handle(&mut c, CMD_CLEAR_WEEKLY_SCHEDULE, &[]),
            Outcome::Scheduled
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &monday),
            Outcome::Scheduled
        );
        assert_eq!(tick(&mut c, now, monday_0700), None);
        assert_eq!(c.i16(OCCUPIED_HEATING_SETPOINT.id), Some(2000));
        assert_eq!(tick(&mut c, now, u32::MAX), None);
        assert_eq!(c.tick, None);
        // A factory reset wipes the transitions and keeps the capacity.
        c.reset_to_defaults(now);
        assert!(schedule(&c).unwrap().transitions.is_empty());
        assert_eq!(schedule(&c).unwrap().weekly, 12);
    }

    #[test]
    fn setpoint_tracking_ac_information_and_relay_log() {
        let mut c: ClusterInstance<64> = server(Capability::HeatingAndCooling).unwrap();
        enable_setpoint_tracking(&mut c, (5, 30), (10, 40)).unwrap();
        enable_ac_information(&mut c).unwrap();
        enable_relay_log(&mut c);
        assert!(
            enable_setpoint_tracking::<64>(
                &mut server(Capability::Heating).unwrap(),
                (30, 5),
                (0xff, 0xff)
            )
            .is_err()
        );
        // A Setpoint Raise/Lower is an external change of +1.5 °C.
        assert!(matches!(
            handle(
                &mut c,
                CMD_SETPOINT_RAISE_LOWER,
                &[raise_lower_mode::HEAT, 15]
            ),
            Outcome::Adjusted { .. }
        ));
        assert_eq!(
            c.u8(SETPOINT_CHANGE_SOURCE.id),
            Some(setpoint_source::EXTERNAL)
        );
        assert_eq!(c.i16(SETPOINT_CHANGE_AMOUNT.id), Some(150));
        stamp_setpoint_change(&mut c, 800_000_000);
        assert_eq!(
            c.u64(SETPOINT_CHANGE_SOURCE_TIMESTAMP.id),
            Some(800_000_000)
        );
        // Setback writes are clamped into the bounds (SUCCESS either way).
        let g = c.write_guard.unwrap();
        let h = c.after_write.unwrap();
        let w = |c: &mut ClusterInstance<64>, id: AttributeId, v: u8| {
            let val = Value::Uint {
                width: 1,
                value: u64::from(v),
            };
            assert_eq!(g(&c.attributes, id, &val), ZclStatus::Success);
            c.set(id, &val);
            h(c, id);
            c.u8(id).unwrap()
        };
        assert_eq!(w(&mut c, OCCUPIED_SETBACK.id, 50), 30);
        assert_eq!(w(&mut c, OCCUPIED_SETBACK.id, 2), 5);
        assert_eq!(w(&mut c, OCCUPIED_SETBACK.id, 20), 20);
        assert_eq!(
            w(&mut c, UNOCCUPIED_SETBACK.id, SETBACK_UNUSED),
            SETBACK_UNUSED
        );
        // AC information guards.
        assert_eq!(
            g(&c.attributes, AC_TYPE.id, &Value::Enum8(5)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(&c.attributes, AC_LOUVER_POSITION.id, &Value::Enum8(0)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(
                &c.attributes,
                TEMPERATURE_SETPOINT_HOLD_DURATION.id,
                &Value::Uint {
                    width: 2,
                    value: 1441
                }
            ),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            g(
                &c.attributes,
                THERMOSTAT_PROGRAMMING_OPERATION_MODE.id,
                &Value::Bits { width: 1, bits: 8 }
            ),
            ZclStatus::InvalidValue
        );
        // Emergency heat: 2.0 °C below the 21.5 °C setpoint with a delta
        // of 1.5 °C.
        c.set(SYSTEM_MODE.id, &Value::Enum8(system_mode::HEAT));
        c.set_u8(EMERGENCY_HEAT_DELTA.id, 15);
        set_local_temperature(&mut c, Some(1950));
        assert_eq!(
            c.u8(THERMOSTAT_RUNNING_MODE.id),
            Some(system_mode::EMERGENCY_HEATING)
        );
        set_local_temperature(&mut c, Some(2100));
        assert_eq!(c.u8(THERMOSTAT_RUNNING_MODE.id), Some(system_mode::HEAT));
        // The relay log: three samples, read back newest first with the
        // unread count, then the newest again.
        set_local_temperature(&mut c, Some(1950));
        record_relay_status(&mut c, 360, running_state::HEAT as u8, 45);
        record_relay_status(
            &mut c,
            420,
            running_state::HEAT as u8 | running_state::FAN as u8,
            0xff,
        );
        record_relay_status(&mut c, 480, 0, 50);
        assert_eq!(c.u16(THERMOSTAT_RUNNING_STATE.id), Some(0));
        let Outcome::RelayLog(p) = handle(&mut c, CMD_GET_RELAY_STATUS_LOG, &[]) else {
            panic!("no relay log response");
        };
        assert_eq!(
            p.as_slice(),
            &[0xe0, 0x01, 0, 0x9e, 0x07, 50, 0x66, 0x08, 2, 0]
        );
        let Outcome::RelayLog(p) = handle(&mut c, CMD_GET_RELAY_STATUS_LOG, &[]) else {
            panic!("no relay log response");
        };
        assert_eq!(p[0..2], [0xa4, 0x01]);
        assert_eq!(p[8..], [1, 0]);
        let Outcome::RelayLog(p) = handle(&mut c, CMD_GET_RELAY_STATUS_LOG, &[]) else {
            panic!("no relay log response");
        };
        assert_eq!(p[0..2], [0x68, 0x01]);
        assert_eq!(p[8..], [0, 0]);
        let Outcome::RelayLog(p) = handle(&mut c, CMD_GET_RELAY_STATUS_LOG, &[]) else {
            panic!("no relay log response");
        };
        assert_eq!(p[0..2], [0xe0, 0x01]);
        // Without the log the command is unsupported; with the schedule
        // both extensions coexist.
        let mut plain: ClusterInstance<36> = server(Capability::Heating).unwrap();
        assert_eq!(
            handle(&mut plain, CMD_GET_RELAY_STATUS_LOG, &[]),
            Outcome::Default(ZclStatus::UnsupportedClusterCommand)
        );
        enable_weekly_schedule(&mut c, 1, 12, 4).unwrap();
        assert!(c.def.received.contains(&CMD_GET_RELAY_STATUS_LOG));
        assert!(c.def.received.contains(&CMD_SET_WEEKLY_SCHEDULE));
        assert!(schedule(&c).is_some());
        assert_eq!(schedule(&c).unwrap().relay_log.len(), 3);
        // Schedule programming is off until Table 6-23 bit 0 is set.
        let monday = set_payload(
            day_of_week::MONDAY,
            schedule_mode::HEAT,
            &[(360, Some(2300), None)],
        );
        assert_eq!(
            handle(&mut c, CMD_SET_WEEKLY_SCHEDULE, &monday),
            Outcome::Scheduled
        );
        let now = Instant::from_millis(0);
        let monday_0700 = 2 * 86_400 + 7 * 3_600;
        assert_eq!(tick(&mut c, now, monday_0700), None);
        c.set(
            THERMOSTAT_PROGRAMMING_OPERATION_MODE.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(programming_mode::SCHEDULE),
            },
        );
        assert_eq!(tick(&mut c, now, monday_0700), Some((Some(2300), None)));
        assert_eq!(
            c.u8(SETPOINT_CHANGE_SOURCE.id),
            Some(setpoint_source::SCHEDULE)
        );
    }
}
