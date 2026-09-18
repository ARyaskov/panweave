//! Hand-written definitions of the general clusters needed by the core
//! device types (ZCL8 chapter 3). Generated cluster definitions for the
//! full library live in `panweave-device-library`.

use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, CommandId};

pub mod alarms;
pub mod appliance;
pub mod color_control;
pub mod commissioning;
pub mod configuration;
pub mod diagnostics;
pub mod direct_configuration;
pub mod door_lock;
pub mod electrical_measurement;
pub mod groups;
pub mod hvac;
pub mod ias_ace;
pub mod ias_wd;
pub mod ias_zone;
pub mod io;
pub mod keep_alive;
pub mod level;
pub mod measurement;
pub mod meter_identification;
pub mod on_off;
pub mod ota;
pub mod partition;
pub mod poll_control;
pub mod power_configuration;
pub mod power_profile;
pub mod rssi_location;
pub mod scenes;
pub mod time;
pub mod touchlink;
pub mod window_covering;

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Basic cluster (ZCL8 §3.2), revision 3.
pub mod basic {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0000);
    /// `ZCLVersion`.
    pub const ZCL_VERSION: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(1), Access::RO);
    /// `ApplicationVersion`.
    pub const APPLICATION_VERSION: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(1), Access::RO);
    /// `StackVersion`.
    pub const STACK_VERSION: AttributeDef =
        AttributeDef::new(0x0002, DataType::Uint(1), Access::RO);
    /// `HWVersion`.
    pub const HW_VERSION: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(1), Access::RO);
    /// `ManufacturerName`.
    pub const MANUFACTURER_NAME: AttributeDef =
        AttributeDef::new(0x0004, DataType::CharString, Access::RO);
    /// `ModelIdentifier`.
    pub const MODEL_IDENTIFIER: AttributeDef =
        AttributeDef::new(0x0005, DataType::CharString, Access::RO);
    /// `DateCode`.
    pub const DATE_CODE: AttributeDef = AttributeDef::new(0x0006, DataType::CharString, Access::RO);
    /// `PowerSource`.
    pub const POWER_SOURCE: AttributeDef = AttributeDef::new(0x0007, DataType::Enum8, Access::RO);
    /// `LocationDescription`.
    pub const LOCATION_DESCRIPTION: AttributeDef =
        AttributeDef::new(0x0010, DataType::CharString, Access::RW);
    /// `PhysicalEnvironment`.
    pub const PHYSICAL_ENVIRONMENT: AttributeDef =
        AttributeDef::new(0x0011, DataType::Enum8, Access::RW);
    /// `DeviceEnabled`.
    pub const DEVICE_ENABLED: AttributeDef = AttributeDef::new(0x0012, DataType::Bool, Access::RW);
    /// `SWBuildID`.
    pub const SW_BUILD_ID: AttributeDef =
        AttributeDef::new(0x4000, DataType::CharString, Access::RO);

    /// Reset to Factory Defaults command (received).
    pub const CMD_RESET_TO_FACTORY_DEFAULTS: CommandId = CommandId(0x00);

    /// `ZCLVersion` value for ZCL8.
    pub const ZCL_VERSION_VALUE: u8 = 8;

    /// Power source enumeration values (Table 3-8).
    pub mod power_source {
        /// Unknown.
        pub const UNKNOWN: u8 = 0x00;
        /// Mains (single phase).
        pub const MAINS_SINGLE_PHASE: u8 = 0x01;
        /// Mains (3 phase).
        pub const MAINS_THREE_PHASE: u8 = 0x02;
        /// Battery.
        pub const BATTERY: u8 = 0x03;
        /// DC source.
        pub const DC_SOURCE: u8 = 0x04;
        /// Emergency mains constantly powered.
        pub const EMERGENCY_MAINS_CONSTANT: u8 = 0x05;
        /// Emergency mains and transfer switch.
        pub const EMERGENCY_MAINS_TRANSFER: u8 = 0x06;
    }

    /// Cluster definition.
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 3,
        received: &[CMD_RESET_TO_FACTORY_DEFAULTS],
        generated: &[],
    };

    /// Builds a server instance with the mandatory attributes
    /// (`ZCLVersion`, `PowerSource`) and the given manufacturer / model
    /// strings.
    pub fn server<const A: usize>(
        power_source: u8,
        manufacturer: &[u8],
        model: &[u8],
    ) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(
            ZCL_VERSION,
            &Value::Uint {
                width: 1,
                value: u64::from(ZCL_VERSION_VALUE),
            },
        )?;
        c.add_attribute(POWER_SOURCE, &Value::Enum8(power_source))?;
        c.add_attribute(
            MANUFACTURER_NAME,
            &Value::String {
                ty: DataType::CharString,
                bytes: Some(manufacturer),
            },
        )?;
        c.add_attribute(
            MODEL_IDENTIFIER,
            &Value::String {
                ty: DataType::CharString,
                bytes: Some(model),
            },
        )?;
        Ok(c)
    }
}

/// Identify cluster (ZCL8 §3.5), revision 2.
pub mod identify {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0003);
    /// `IdentifyTime` (seconds remaining).
    pub const IDENTIFY_TIME: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(2), Access::RW);

    /// Identify command (received).
    pub const CMD_IDENTIFY: CommandId = CommandId(0x00);
    /// Identify Query command (received).
    pub const CMD_IDENTIFY_QUERY: CommandId = CommandId(0x01);
    /// Trigger Effect command (received).
    pub const CMD_TRIGGER_EFFECT: CommandId = CommandId(0x40);
    /// Identify Query Response command (generated).
    pub const CMD_IDENTIFY_QUERY_RESPONSE: CommandId = CommandId(0x00);

    /// Cluster definition.
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 2,
        received: &[CMD_IDENTIFY, CMD_IDENTIFY_QUERY, CMD_TRIGGER_EFFECT],
        generated: &[CMD_IDENTIFY_QUERY_RESPONSE],
    };

    /// Builds a server instance.
    pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(IDENTIFY_TIME, &Value::Uint { width: 2, value: 0 })?;
        Ok(c)
    }

    /// Builds a client instance (no attributes; receives Identify Query
    /// Responses, §3.5.3).
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF.mirrored(), Role::Client)
    }

    /// Remaining identification time of a server instance.
    pub fn identify_time<const A: usize>(c: &ClusterInstance<A>) -> u16 {
        match c.attributes.value(IDENTIFY_TIME.id) {
            Some(Value::Uint { value, .. }) => u16::try_from(value).unwrap_or(u16::MAX),
            _ => 0,
        }
    }

    /// Sets `IdentifyTime` and (re)arms the one-second countdown
    /// (§3.5.2.2.1). Returns whether the value changed.
    pub fn set_identify_time<const A: usize>(
        c: &mut ClusterInstance<A>,
        seconds: u16,
        now: Instant,
    ) -> bool {
        let changed = c
            .attributes
            .set(
                IDENTIFY_TIME.id,
                &Value::Uint {
                    width: 2,
                    value: u64::from(seconds),
                },
            )
            .unwrap_or(false);
        c.tick = (seconds > 0).then(|| now + Duration::from_secs(1));
        changed
    }

    /// Advances the countdown: decrements `IdentifyTime` once per elapsed
    /// second. Returns the new value when it changed.
    pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<u16> {
        let due = c.tick?;
        if !now.has_reached(due) {
            return None;
        }
        let remaining = identify_time(c).saturating_sub(1);
        set_identify_time(c, remaining, due);
        if remaining > 0 && c.tick.is_some_and(|t| now.has_reached(t)) {
            // Late poll: catch up without skipping the update.
            c.tick = Some(now + Duration::from_secs(1));
        }
        Some(remaining)
    }

    /// Result of a received Identify server command.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Outcome {
        /// Unicast an Identify Query Response with this timeout
        /// (§3.5.2.4.1).
        QueryResponse(u16),
        /// `IdentifyTime` was set by an Identify command; a Default
        /// Response applies.
        Set(u16),
        /// Trigger Effect: execute the effect (identifier, variant).
        Effect(u8, u8),
        /// Not identifying: an Identify Query takes no further action.
        Silent,
        /// Malformed or unsupported command.
        Default(ZclStatus),
    }

    /// Processes a cluster-specific command received by the server
    /// (§3.5.2.3).
    pub fn handle<const A: usize>(
        c: &mut ClusterInstance<A>,
        command: CommandId,
        payload: &[u8],
        now: Instant,
    ) -> Outcome {
        match command {
            CMD_IDENTIFY => match payload {
                [lo, hi, ..] => {
                    let t = u16::from_le_bytes([*lo, *hi]);
                    set_identify_time(c, t, now);
                    Outcome::Set(t)
                }
                _ => Outcome::Default(ZclStatus::MalformedCommand),
            },
            CMD_IDENTIFY_QUERY => {
                let t = identify_time(c);
                if t > 0 {
                    Outcome::QueryResponse(t)
                } else {
                    Outcome::Silent
                }
            }
            CMD_TRIGGER_EFFECT => match payload {
                [effect, variant, ..] => Outcome::Effect(*effect, *variant),
                _ => Outcome::Default(ZclStatus::MalformedCommand),
            },
            _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
        }
    }
}
