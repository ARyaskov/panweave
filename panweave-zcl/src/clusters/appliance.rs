//! Appliance Management clusters (ZCL8 Chapter 15): EN50523 Appliance
//! Control (§15.2), Appliance Identification (§15.3), Appliance Events
//! and Alerts (§15.4) and Appliance Statistics (§15.5).
//!
//! The servers keep their state in the cluster instance (the signal
//! state, the current alerts, the log queue); the layer answers Signal
//! State, Get Alerts, Log Request and Log Queue Request from it and
//! hands the control commands to the application.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// EN50523 Appliance Control (§15.2).
pub mod control {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x001b);

    /// `StartTime` (uint16, Table 15-4 encoding, reportable).
    pub const START_TIME: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(2), Access::RO_REPORT);
    /// `FinishTime` (uint16, Table 15-4 encoding, reportable).
    pub const FINISH_TIME: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(2), Access::RO_REPORT);
    /// `RemainingTime` (uint16, relative, 0 outside RUNNING, optional).
    pub const REMAINING_TIME: AttributeDef =
        AttributeDef::new(0x0002, DataType::Uint(2), Access::RO_REPORT);

    /// Execution of a Command (client → server).
    pub const CMD_EXECUTION_OF_A_COMMAND: CommandId = CommandId(0x00);
    /// Signal State.
    pub const CMD_SIGNAL_STATE: CommandId = CommandId(0x01);
    /// Write Functions.
    pub const CMD_WRITE_FUNCTIONS: CommandId = CommandId(0x02);
    /// Overload Pause Resume.
    pub const CMD_OVERLOAD_PAUSE_RESUME: CommandId = CommandId(0x03);
    /// Overload Pause.
    pub const CMD_OVERLOAD_PAUSE: CommandId = CommandId(0x04);
    /// Overload Warning.
    pub const CMD_OVERLOAD_WARNING: CommandId = CommandId(0x05);
    /// Signal State Response (server → client).
    pub const CMD_SIGNAL_STATE_RESPONSE: CommandId = CommandId(0x00);
    /// Signal State Notification.
    pub const CMD_SIGNAL_STATE_NOTIFICATION: CommandId = CommandId(0x01);

    /// Cluster definition.
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 1,
        received: &[
            CMD_EXECUTION_OF_A_COMMAND,
            CMD_SIGNAL_STATE,
            CMD_WRITE_FUNCTIONS,
            CMD_OVERLOAD_PAUSE_RESUME,
            CMD_OVERLOAD_PAUSE,
            CMD_OVERLOAD_WARNING,
        ],
        generated: &[CMD_SIGNAL_STATE_RESPONSE, CMD_SIGNAL_STATE_NOTIFICATION],
    };

    /// Command Identification values (Table 15-6).
    pub mod command_id {
        /// Start the appliance cycle.
        pub const START: u8 = 0x01;
        /// Stop the appliance cycle.
        pub const STOP: u8 = 0x02;
        /// Pause the appliance cycle.
        pub const PAUSE: u8 = 0x03;
        /// Start superfreezing.
        pub const START_SUPERFREEZING: u8 = 0x04;
        /// Stop superfreezing.
        pub const STOP_SUPERFREEZING: u8 = 0x05;
        /// Start supercooling.
        pub const START_SUPERCOOLING: u8 = 0x06;
        /// Stop supercooling.
        pub const STOP_SUPERCOOLING: u8 = 0x07;
        /// Disable gas.
        pub const DISABLE_GAS: u8 = 0x08;
        /// Enable gas.
        pub const ENABLE_GAS: u8 = 0x09;
        /// First manufacturer-specific value.
        pub const MANUFACTURER_SPECIFIC: u8 = 0x80;
    }

    /// Appliance Status values (Table 15-9).
    pub mod status {
        /// Off.
        pub const OFF: u8 = 0x01;
        /// Stand-by.
        pub const STAND_BY: u8 = 0x02;
        /// Programmed.
        pub const PROGRAMMED: u8 = 0x03;
        /// Programmed, waiting to start.
        pub const PROGRAMMED_WAITING_TO_START: u8 = 0x04;
        /// Running.
        pub const RUNNING: u8 = 0x05;
        /// Pause.
        pub const PAUSE: u8 = 0x06;
        /// End programmed.
        pub const END_PROGRAMMED: u8 = 0x07;
        /// Failure.
        pub const FAILURE: u8 = 0x08;
        /// Programme interrupted.
        pub const PROGRAMME_INTERRUPTED: u8 = 0x09;
        /// Idle.
        pub const IDLE: u8 = 0x0a;
        /// Rinse hold.
        pub const RINSE_HOLD: u8 = 0x0b;
        /// Service.
        pub const SERVICE: u8 = 0x0c;
        /// Superfreezing.
        pub const SUPERFREEZING: u8 = 0x0d;
        /// Supercooling.
        pub const SUPERCOOLING: u8 = 0x0e;
        /// Superheating.
        pub const SUPERHEATING: u8 = 0x0f;
        /// First manufacturer-specific value.
        pub const MANUFACTURER_SPECIFIC: u8 = 0x80;
    }

    /// Remote Enable Flags (Table 15-10, bits 0..3).
    pub mod remote_enable {
        /// Disabled.
        pub const DISABLED: u8 = 0x0;
        /// Enabled remote and energy control.
        pub const ENABLED_REMOTE_AND_ENERGY_CONTROL: u8 = 0x1;
        /// Temporarily locked / disabled.
        pub const TEMPORARILY_LOCKED: u8 = 0x7;
        /// Enabled remote control.
        pub const ENABLED_REMOTE_CONTROL: u8 = 0xf;
    }

    /// Device Status 2 structure (Table 15-10, bits 4..7).
    pub mod status2_structure {
        /// Proprietary.
        pub const PROPRIETARY: u8 = 0x0;
        /// IRIS symptom code (three digits).
        pub const IRIS_SYMPTOM_CODE: u8 = 0x2;
    }

    /// Overload Warning events (Table 15-7).
    pub mod warning_event {
        /// Overall power above the "available power" level.
        pub const ABOVE_AVAILABLE_POWER: u8 = 0x00;
        /// Overall power above the "power threshold" level.
        pub const ABOVE_POWER_THRESHOLD: u8 = 0x01;
        /// Overall power back below the "available power" level.
        pub const BELOW_AVAILABLE_POWER: u8 = 0x02;
        /// Overall power back below the "power threshold" level.
        pub const BELOW_POWER_THRESHOLD: u8 = 0x03;
        /// Overall power would exceed "available power" if the
        /// appliance started.
        pub const WOULD_EXCEED_AVAILABLE_POWER: u8 = 0x04;
    }

    /// A time in the Table 15-4 encoding of `StartTime` / `FinishTime`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct ApplianceTime {
        /// Hours: 0–255 relative, 0–23 absolute.
        pub hours: u8,
        /// Minutes 0–59.
        pub minutes: u8,
        /// Absolute (time of day) rather than relative.
        pub absolute: bool,
    }

    impl ApplianceTime {
        /// The attribute value.
        pub const fn to_raw(self) -> u16 {
            ((self.hours as u16) << 8)
                | ((self.absolute as u16) << 6)
                | (self.minutes as u16 & 0x3f)
        }

        /// From the attribute value (`None` for a reserved encoding or
        /// minutes above 59).
        pub const fn from_raw(raw: u16) -> Option<Self> {
            let minutes = (raw & 0x3f) as u8;
            if minutes > 59 || raw & 0x80 != 0 {
                return None;
            }
            Some(ApplianceTime {
                hours: (raw >> 8) as u8,
                minutes,
                absolute: raw & 0x40 != 0,
            })
        }
    }

    /// The Signal State Response / Notification payload (Figure 15-6).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct SignalState {
        /// Appliance Status (Table 15-9).
        pub status: u8,
        /// Remote Enable Flags (4 bits, Table 15-10).
        pub remote_enable: u8,
        /// Device Status 2 structure (4 bits, Table 15-10).
        pub status2_structure: u8,
        /// Appliance Status 2 (24 bits) when provided.
        pub status2: Option<u32>,
    }

    impl Default for SignalState {
        fn default() -> Self {
            SignalState {
                status: status::OFF,
                remote_enable: remote_enable::DISABLED,
                status2_structure: status2_structure::PROPRIETARY,
                status2: None,
            }
        }
    }

    impl SignalState {
        /// Parses the payload.
        pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
            let mut r = Reader::new(payload);
            let status = r.u8()?;
            let flags = r.u8()?;
            let status2 = if r.is_empty() {
                None
            } else {
                Some(r.u24_le()?)
            };
            Ok(SignalState {
                status,
                remote_enable: flags & 0x0f,
                status2_structure: flags >> 4,
                status2,
            })
        }

        /// Encodes the payload.
        pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
            let mut w = Writer::new(out);
            w.u8(self.status)?;
            w.u8((self.remote_enable & 0x0f) | (self.status2_structure << 4))?;
            if let Some(s) = self.status2 {
                w.u24_le(s & 0x00ff_ffff)?;
            }
            Ok(w.position())
        }
    }

    /// One Write Functions record (Figure 15-4).
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub struct WriteFunction<'a> {
        /// Function (attribute) identifier.
        pub id: AttributeId,
        /// The value.
        pub value: Value<'a>,
    }

    /// Parses the records of a Write Functions command into `out`;
    /// fails on a malformed record or when `out` is full.
    pub fn parse_write_functions<'a, const N: usize>(
        payload: &'a [u8],
        out: &mut Vec<WriteFunction<'a>, N>,
    ) -> Result<(), CodecError> {
        let mut r = Reader::new(payload);
        while !r.is_empty() {
            let id = AttributeId(r.u16_le()?);
            let raw = r.u8()?;
            let ty = DataType::from_id(raw);
            if matches!(ty, DataType::Reserved(_)) {
                return Err(CodecError::InvalidField {
                    field: "function data type",
                    value: u32::from(raw),
                });
            }
            let value = Value::decode(&mut r, ty)?;
            out.push(WriteFunction { id, value })
                .map_err(|_| CodecError::Unrepresentable { field: "function" })?;
        }
        Ok(())
    }

    /// Encodes Write Functions records.
    pub fn encode_write_functions(
        records: &[WriteFunction<'_>],
        out: &mut [u8],
    ) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        for rec in records {
            w.u16_le(rec.id.0)?;
            w.u8(rec.value.data_type().id())?;
            rec.value.encode(&mut w)?;
        }
        Ok(w.position())
    }

    /// Server state: the signal state reported on request.
    #[derive(Clone, Debug, Default)]
    pub struct State {
        /// Current signal state.
        pub signal: SignalState,
    }

    /// Builds a server with `StartTime` / `FinishTime` (and
    /// `RemainingTime` when `remaining`) at 0, status OFF.
    pub fn server<const A: usize>(remaining: bool) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        let zero = Value::Uint { width: 2, value: 0 };
        c.add_attribute(START_TIME, &zero)?;
        c.add_attribute(FINISH_TIME, &zero)?;
        if remaining {
            c.add_attribute(REMAINING_TIME, &zero)?;
        }
        c.state = ClusterState::ApplianceControl(State::default());
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF, Role::Client)
    }

    /// The server's signal state.
    pub fn signal_state<const A: usize>(c: &ClusterInstance<A>) -> Option<SignalState> {
        match &c.state {
            ClusterState::ApplianceControl(s) => Some(s.signal),
            _ => None,
        }
    }

    /// Sets the server's signal state; returns whether it changed.
    pub fn set_signal_state<const A: usize>(
        c: &mut ClusterInstance<A>,
        signal: SignalState,
    ) -> bool {
        match &mut c.state {
            ClusterState::ApplianceControl(s) => {
                let changed = s.signal != signal;
                s.signal = signal;
                changed
            }
            _ => {
                c.state = ClusterState::ApplianceControl(State { signal });
                true
            }
        }
    }

    /// An overload command (§15.2.4.4–§15.2.4.6).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Overload {
        /// Pause operations.
        Pause,
        /// Resume operations.
        Resume,
        /// Show or clear a warning (Table 15-7).
        Warning(u8),
    }

    /// Result of a received command.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Outcome {
        /// Execute this Command Identification (Table 15-6).
        Execute(u8),
        /// Reply with a Signal State Response carrying this state.
        Response(SignalState),
        /// Write Functions: the records are for the application.
        WriteFunctions,
        /// An overload command.
        Overload(Overload),
        /// Refused with this status.
        Default(ZclStatus),
    }

    /// Handles a received command (§15.2.4).
    pub fn handle<const A: usize>(
        c: &ClusterInstance<A>,
        cmd: CommandId,
        payload: &[u8],
    ) -> Outcome {
        match cmd {
            CMD_EXECUTION_OF_A_COMMAND => match payload.first() {
                Some(&id) if id != 0 => Outcome::Execute(id),
                _ => Outcome::Default(ZclStatus::MalformedCommand),
            },
            CMD_SIGNAL_STATE => Outcome::Response(signal_state(c).unwrap_or_default()),
            CMD_WRITE_FUNCTIONS => {
                let mut records: Vec<WriteFunction<'_>, 8> = Vec::new();
                match parse_write_functions(payload, &mut records) {
                    Ok(()) if !records.is_empty() => Outcome::WriteFunctions,
                    _ => Outcome::Default(ZclStatus::MalformedCommand),
                }
            }
            CMD_OVERLOAD_PAUSE_RESUME => Outcome::Overload(Overload::Resume),
            CMD_OVERLOAD_PAUSE => Outcome::Overload(Overload::Pause),
            CMD_OVERLOAD_WARNING => match payload.first() {
                Some(&e) if e <= warning_event::WOULD_EXCEED_AVAILABLE_POWER => {
                    Outcome::Overload(Overload::Warning(e))
                }
                _ => Outcome::Default(ZclStatus::MalformedCommand),
            },
            _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
        }
    }
}

/// EN50523 Appliance Identification (§15.3).
pub mod identification {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0b00);

    /// `BasicIdentification` (uint56, Table 15-13).
    pub const BASIC_IDENTIFICATION: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(7), Access::RO);
    /// `CompanyName` (string, ≤16).
    pub const COMPANY_NAME: AttributeDef =
        AttributeDef::new(0x0010, DataType::CharString, Access::RO);
    /// `CompanyId`.
    pub const COMPANY_ID: AttributeDef = AttributeDef::new(0x0011, DataType::Uint(2), Access::RO);
    /// `BrandName` (string, ≤16).
    pub const BRAND_NAME: AttributeDef =
        AttributeDef::new(0x0012, DataType::CharString, Access::RO);
    /// `BrandId`.
    pub const BRAND_ID: AttributeDef = AttributeDef::new(0x0013, DataType::Uint(2), Access::RO);
    /// `Model` (octstr, ≤16).
    pub const MODEL: AttributeDef = AttributeDef::new(0x0014, DataType::OctetString, Access::RO);
    /// `PartNumber` (octstr, ≤16).
    pub const PART_NUMBER: AttributeDef =
        AttributeDef::new(0x0015, DataType::OctetString, Access::RO);
    /// `ProductRevision` (octstr, ≤6).
    pub const PRODUCT_REVISION: AttributeDef =
        AttributeDef::new(0x0016, DataType::OctetString, Access::RO);
    /// `SoftwareRevision` (octstr, ≤6).
    pub const SOFTWARE_REVISION: AttributeDef =
        AttributeDef::new(0x0017, DataType::OctetString, Access::RO);
    /// `ProductTypeName` (octstr, 2 octets).
    pub const PRODUCT_TYPE_NAME: AttributeDef =
        AttributeDef::new(0x0018, DataType::OctetString, Access::RO);
    /// `ProductTypeId`.
    pub const PRODUCT_TYPE_ID: AttributeDef =
        AttributeDef::new(0x0019, DataType::Uint(2), Access::RO);
    /// `CECEDSpecificationVersion` (Table 15-16).
    pub const CECED_SPECIFICATION_VERSION: AttributeDef =
        AttributeDef::new(0x001a, DataType::Uint(1), Access::RO);

    /// Cluster definition.
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 1,
        received: &[],
        generated: &[],
    };

    /// Product Type IDs (Table 15-14).
    pub mod product_type {
        /// White goods (generic).
        pub const WHITE_GOODS: u16 = 0x0000;
        /// Dishwasher.
        pub const DISHWASHER: u16 = 0x5601;
        /// Tumble dryer.
        pub const TUMBLE_DRYER: u16 = 0x5602;
        /// Washer dryer.
        pub const WASHER_DRYER: u16 = 0x5603;
        /// Washing machine.
        pub const WASHING_MACHINE: u16 = 0x5604;
        /// Hobs.
        pub const HOBS: u16 = 0x5e03;
        /// Induction hobs.
        pub const INDUCTION_HOBS: u16 = 0x5e09;
        /// Oven.
        pub const OVEN: u16 = 0x5e01;
        /// Electrical oven.
        pub const ELECTRICAL_OVEN: u16 = 0x5e06;
        /// Refrigerator freezer.
        pub const REFRIGERATOR_FREEZER: u16 = 0x6601;
    }

    /// The fields of `BasicIdentification` (Table 15-13).
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct BasicIdentification {
        /// Company ID (bits 0–15).
        pub company: u16,
        /// Brand ID (bits 16–31).
        pub brand: u16,
        /// Product Type ID (bits 32–47).
        pub product_type: u16,
        /// CECED specification version (bits 48–55).
        pub spec_version: u8,
    }

    impl BasicIdentification {
        /// The 56-bit attribute value.
        pub const fn to_raw(self) -> u64 {
            self.company as u64
                | ((self.brand as u64) << 16)
                | ((self.product_type as u64) << 32)
                | ((self.spec_version as u64) << 48)
        }

        /// From the attribute value.
        // Every field is a masked bit range.
        #[allow(clippy::cast_possible_truncation)]
        pub const fn from_raw(raw: u64) -> Self {
            BasicIdentification {
                company: (raw & 0xffff) as u16,
                brand: ((raw >> 16) & 0xffff) as u16,
                product_type: ((raw >> 32) & 0xffff) as u16,
                spec_version: ((raw >> 48) & 0xff) as u8,
            }
        }
    }

    /// Builds a server with `BasicIdentification`; the extended set is
    /// added by the application.
    pub fn server<const A: usize>(
        basic: BasicIdentification,
    ) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(
            BASIC_IDENTIFICATION,
            &Value::Uint {
                width: 7,
                value: basic.to_raw(),
            },
        )?;
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF, Role::Client)
    }

    /// The server's `BasicIdentification`.
    pub fn basic<const A: usize>(c: &ClusterInstance<A>) -> Option<BasicIdentification> {
        c.u64(BASIC_IDENTIFICATION.id)
            .map(BasicIdentification::from_raw)
    }
}

/// EN50523 Appliance Events and Alerts (§15.4).
pub mod events_alerts {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0b02);

    /// Get Alerts (client → server).
    pub const CMD_GET_ALERTS: CommandId = CommandId(0x00);
    /// Get Alerts Response (server → client).
    pub const CMD_GET_ALERTS_RESPONSE: CommandId = CommandId(0x00);
    /// Alerts Notification.
    pub const CMD_ALERTS_NOTIFICATION: CommandId = CommandId(0x01);
    /// Event Notification.
    pub const CMD_EVENT_NOTIFICATION: CommandId = CommandId(0x02);

    /// Cluster definition.
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 1,
        received: &[CMD_GET_ALERTS],
        generated: &[
            CMD_GET_ALERTS_RESPONSE,
            CMD_ALERTS_NOTIFICATION,
            CMD_EVENT_NOTIFICATION,
        ],
    };

    /// The most alerts one command carries (4-bit count).
    pub const MAX_ALERTS: usize = 15;

    /// Alert categories (Table 15-20).
    pub mod category {
        /// Warning.
        pub const WARNING: u8 = 0x1;
        /// Danger.
        pub const DANGER: u8 = 0x2;
        /// Failure.
        pub const FAILURE: u8 = 0x3;
    }

    /// Event Identification values (Table 15-21).
    pub mod event {
        /// End of the working cycle.
        pub const END_OF_CYCLE: u8 = 0x01;
        /// Set temperature reached.
        pub const TEMPERATURE_REACHED: u8 = 0x04;
        /// End of the cooking process.
        pub const END_OF_COOKING: u8 = 0x05;
        /// Switching off.
        pub const SWITCHING_OFF: u8 = 0x06;
        /// Wrong data.
        pub const WRONG_DATA: u8 = 0xf7;
    }

    /// One alert structure (Table 15-20).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Alert {
        /// Alert ID: 1–63 standardized, 128–255 manufacturer-specific.
        pub id: u8,
        /// Category (Table 15-20).
        pub category: u8,
        /// Present (`true`) or recovered.
        pub present: bool,
        /// Manufacturer-specific bits 16–23.
        pub manufacturer: u8,
    }

    impl Alert {
        /// The 24-bit structure.
        pub const fn to_raw(self) -> u32 {
            self.id as u32
                | (((self.category & 0x0f) as u32) << 8)
                | ((self.present as u32) << 12)
                | ((self.manufacturer as u32) << 16)
        }

        /// From the 24-bit structure.
        // Every field is a masked bit range.
        #[allow(clippy::cast_possible_truncation)]
        pub const fn from_raw(raw: u32) -> Self {
            Alert {
                id: (raw & 0xff) as u8,
                category: ((raw >> 8) & 0x0f) as u8,
                present: (raw >> 12) & 0x03 == 1,
                manufacturer: ((raw >> 16) & 0xff) as u8,
            }
        }
    }

    /// The current alerts of a server (`ClusterState::ApplianceAlerts`).
    #[derive(Clone, Debug, Default)]
    pub struct Alerts {
        /// Present alerts.
        pub list: Vec<Alert, MAX_ALERTS>,
    }

    /// Encodes a Get Alerts Response / Alerts Notification payload
    /// (Figure 15-8: count with type UNSTRUCTURED, then the structures).
    pub fn encode_alerts(alerts: &[Alert], out: &mut [u8]) -> Result<usize, CodecError> {
        if alerts.len() > MAX_ALERTS {
            return Err(CodecError::Unrepresentable { field: "alerts" });
        }
        let mut w = Writer::new(out);
        w.u8(u8::try_from(alerts.len()).unwrap_or(u8::MAX))?;
        for a in alerts {
            w.u24_le(a.to_raw())?;
        }
        Ok(w.position())
    }

    /// Parses a Get Alerts Response / Alerts Notification payload; a
    /// reserved alert type is refused.
    pub fn parse_alerts(payload: &[u8]) -> Result<Vec<Alert, MAX_ALERTS>, CodecError> {
        let mut r = Reader::new(payload);
        let count = r.u8()?;
        if count >> 4 != 0 {
            return Err(CodecError::InvalidField {
                field: "alert type",
                value: u32::from(count >> 4),
            });
        }
        let mut out = Vec::new();
        for _ in 0..(count & 0x0f) {
            let _ = out.push(Alert::from_raw(r.u24_le()?));
        }
        Ok(out)
    }

    /// Encodes an Event Notification payload (Figure 15-10).
    pub fn encode_event(event: u8, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(0)?;
        w.u8(event)?;
        Ok(w.position())
    }

    /// Parses an Event Notification payload.
    pub fn parse_event(payload: &[u8]) -> Result<u8, CodecError> {
        let mut r = Reader::new(payload);
        let _header = r.u8()?;
        r.u8()
    }

    /// Builds a server with no alerts.
    pub fn server<const A: usize>() -> ClusterInstance<A> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.state = ClusterState::ApplianceAlerts(Alerts::default());
        c
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF, Role::Client)
    }

    /// The server's current alerts.
    pub fn alerts<const A: usize>(c: &ClusterInstance<A>) -> &[Alert] {
        match &c.state {
            ClusterState::ApplianceAlerts(a) => &a.list,
            _ => &[],
        }
    }

    /// Records an alert change: a present alert replaces (or adds) the
    /// entry with its id, a recovered one removes it. Fails when the
    /// list is full.
    pub fn record<const A: usize>(
        c: &mut ClusterInstance<A>,
        alert: Alert,
    ) -> Result<(), ZclStatus> {
        if !matches!(c.state, ClusterState::ApplianceAlerts(_)) {
            c.state = ClusterState::ApplianceAlerts(Alerts::default());
        }
        let ClusterState::ApplianceAlerts(a) = &mut c.state else {
            return Err(ZclStatus::Failure);
        };
        a.list.retain(|x| x.id != alert.id);
        if alert.present {
            a.list
                .push(alert)
                .map_err(|_| ZclStatus::InsufficientSpace)?;
        }
        Ok(())
    }

    /// Result of a received command.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Outcome {
        /// Reply with a Get Alerts Response of these bytes.
        Response(usize),
        /// Refused with this status.
        Default(ZclStatus),
    }

    /// Handles a received command; a response is written to `out`.
    pub fn handle<const A: usize>(
        c: &ClusterInstance<A>,
        cmd: CommandId,
        out: &mut [u8],
    ) -> Outcome {
        match cmd {
            CMD_GET_ALERTS => match encode_alerts(alerts(c), out) {
                Ok(n) => Outcome::Response(n),
                Err(_) => Outcome::Default(ZclStatus::Failure),
            },
            _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
        }
    }
}

/// Appliance Statistics (§15.5).
pub mod statistics {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0b03);

    /// `LogMaxSize` (uint32, default 60).
    pub const LOG_MAX_SIZE: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(4), Access::RO);
    /// `LogQueueMaxSize` (uint8, default 1).
    pub const LOG_QUEUE_MAX_SIZE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(1), Access::RO);

    /// Log Request (client → server).
    pub const CMD_LOG_REQUEST: CommandId = CommandId(0x00);
    /// Log Queue Request.
    pub const CMD_LOG_QUEUE_REQUEST: CommandId = CommandId(0x01);
    /// Log Notification (server → client).
    pub const CMD_LOG_NOTIFICATION: CommandId = CommandId(0x00);
    /// Log Response.
    pub const CMD_LOG_RESPONSE: CommandId = CommandId(0x01);
    /// Log Queue Response.
    pub const CMD_LOG_QUEUE_RESPONSE: CommandId = CommandId(0x02);
    /// Statistics Available.
    pub const CMD_STATISTICS_AVAILABLE: CommandId = CommandId(0x03);

    /// Cluster definition.
    pub const DEF: ClusterDef = ClusterDef {
        id: ID,
        revision: 1,
        received: &[CMD_LOG_REQUEST, CMD_LOG_QUEUE_REQUEST],
        generated: &[
            CMD_LOG_NOTIFICATION,
            CMD_LOG_RESPONSE,
            CMD_LOG_QUEUE_RESPONSE,
            CMD_STATISTICS_AVAILABLE,
        ],
    };

    /// The largest log payload carried without the Partition cluster
    /// (§15.5.2.1.1).
    pub const MAX_LOG: usize = 70;
    /// Logs kept in the queue.
    pub const QUEUE: usize = 8;
    /// The invalid UTC time stamp of a device without a clock.
    pub const NO_TIME: u32 = 0xffff_ffff;

    /// A log (Log Notification / Log Response payload, Figure 15-11).
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Log {
        /// UTC time stamp, [`NO_TIME`] without a clock.
        pub timestamp: u32,
        /// Log ID (consecutive).
        pub id: u32,
        /// Log payload.
        pub payload: Vec<u8, MAX_LOG>,
    }

    impl Log {
        /// Parses the payload.
        pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
            let mut r = Reader::new(payload);
            let timestamp = r.u32_le()?;
            let id = r.u32_le()?;
            let len = r.u32_le()? as usize;
            let bytes = r.bytes(len)?;
            Ok(Log {
                timestamp,
                id,
                payload: Vec::from_slice(bytes)
                    .map_err(|_| CodecError::Unrepresentable { field: "log" })?,
            })
        }

        /// Encodes the payload.
        pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
            let mut w = Writer::new(out);
            w.u32_le(self.timestamp)?;
            w.u32_le(self.id)?;
            w.u32_le(u32::try_from(self.payload.len()).unwrap_or(u32::MAX))?;
            w.bytes(&self.payload)?;
            Ok(w.position())
        }
    }

    /// Encodes a Log Queue Response / Statistics Available payload
    /// (Figure 15-12).
    pub fn encode_ids(ids: &[u32], out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(u8::try_from(ids.len()).map_err(|_| CodecError::Unrepresentable { field: "ids" })?)?;
        for id in ids {
            w.u32_le(*id)?;
        }
        Ok(w.position())
    }

    /// Parses a Log Queue Response / Statistics Available payload.
    pub fn parse_ids(payload: &[u8]) -> Result<Vec<u32, QUEUE>, CodecError> {
        let mut r = Reader::new(payload);
        let n = r.u8()?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(r.u32_le()?)
                .map_err(|_| CodecError::Unrepresentable { field: "ids" })?;
        }
        Ok(out)
    }

    /// The server's log queue (`ClusterState::ApplianceLogs`): the
    /// most recent logs, oldest first.
    #[derive(Clone, Debug, Default)]
    pub struct LogQueue {
        /// Stored logs.
        pub logs: Vec<Log, QUEUE>,
        /// The next Log ID.
        pub next_id: u32,
    }

    impl LogQueue {
        /// Stores a log payload under the next Log ID (the oldest log is
        /// dropped when the queue is full) and returns it.
        pub fn push(&mut self, timestamp: u32, payload: &[u8]) -> Result<&Log, ZclStatus> {
            let log = Log {
                timestamp,
                id: self.next_id,
                payload: Vec::from_slice(payload).map_err(|_| ZclStatus::InvalidValue)?,
            };
            if self.logs.is_full() {
                self.logs.remove(0);
            }
            self.logs.push(log).map_err(|_| ZclStatus::Failure)?;
            self.next_id = self.next_id.wrapping_add(1);
            self.logs.last().ok_or(ZclStatus::Failure)
        }

        /// The log with `id`.
        pub fn get(&self, id: u32) -> Option<&Log> {
            self.logs.iter().find(|l| l.id == id)
        }

        /// The stored Log IDs.
        pub fn ids(&self) -> Vec<u32, QUEUE> {
            self.logs.iter().map(|l| l.id).collect()
        }
    }

    /// Builds a server with `LogMaxSize` [`MAX_LOG`] and `LogQueueMaxSize`
    /// [`QUEUE`].
    pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_attribute(
            LOG_MAX_SIZE,
            &Value::Uint {
                width: 4,
                value: MAX_LOG as u64,
            },
        )?;
        c.add_attribute(
            LOG_QUEUE_MAX_SIZE,
            &Value::Uint {
                width: 1,
                value: QUEUE as u64,
            },
        )?;
        c.state = ClusterState::ApplianceLogs(LogQueue::default());
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        ClusterInstance::new(DEF, Role::Client)
    }

    /// The server's log queue.
    pub fn queue<const A: usize>(c: &ClusterInstance<A>) -> Option<&LogQueue> {
        match &c.state {
            ClusterState::ApplianceLogs(q) => Some(q),
            _ => None,
        }
    }

    /// The server's log queue, mutably (created when absent).
    pub fn queue_mut<const A: usize>(c: &mut ClusterInstance<A>) -> &mut LogQueue {
        if !matches!(c.state, ClusterState::ApplianceLogs(_)) {
            c.state = ClusterState::ApplianceLogs(LogQueue::default());
        }
        match &mut c.state {
            ClusterState::ApplianceLogs(q) => q,
            // Just set above.
            _ => unreachable!(),
        }
    }

    /// Result of a received command.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Outcome {
        /// Reply with a Log Response of these bytes.
        Log(usize),
        /// Reply with a Log Queue Response of these bytes.
        Ids(usize),
        /// Refused with this status (NOT_FOUND for an unknown Log ID).
        Default(ZclStatus),
    }

    /// Handles a received command; a response is written to `out`.
    pub fn handle<const A: usize>(
        c: &ClusterInstance<A>,
        cmd: CommandId,
        payload: &[u8],
        out: &mut [u8],
    ) -> Outcome {
        match cmd {
            CMD_LOG_REQUEST => {
                let Ok(id) = Reader::new(payload).u32_le() else {
                    return Outcome::Default(ZclStatus::MalformedCommand);
                };
                match queue(c).and_then(|q| q.get(id)) {
                    Some(log) => match log.encode(out) {
                        Ok(n) => Outcome::Log(n),
                        Err(_) => Outcome::Default(ZclStatus::Failure),
                    },
                    None => Outcome::Default(ZclStatus::NotFound),
                }
            }
            CMD_LOG_QUEUE_REQUEST => {
                let ids = queue(c).map(LogQueue::ids).unwrap_or_default();
                match encode_ids(&ids, out) {
                    Ok(n) => Outcome::Ids(n),
                    Err(_) => Outcome::Default(ZclStatus::Failure),
                }
            }
            _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_codecs_round_trip() {
        let t = control::ApplianceTime {
            hours: 18,
            minutes: 30,
            absolute: true,
        };
        assert_eq!(t.to_raw(), 0x125e);
        assert_eq!(control::ApplianceTime::from_raw(0x125e), Some(t));
        assert_eq!(control::ApplianceTime::from_raw(0x00bc), None);
        let s = control::SignalState {
            status: control::status::RUNNING,
            remote_enable: control::remote_enable::ENABLED_REMOTE_CONTROL,
            status2_structure: control::status2_structure::IRIS_SYMPTOM_CODE,
            status2: Some(0x01_0203),
        };
        let mut buf = [0u8; 8];
        let n = s.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x05, 0x2f, 0x03, 0x02, 0x01]);
        assert_eq!(control::SignalState::parse(&buf[..n]).unwrap(), s);
        let short = control::SignalState { status2: None, ..s };
        let n = short.encode(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(control::SignalState::parse(&buf[..n]).unwrap(), short);
        let recs = [
            control::WriteFunction {
                id: control::START_TIME.id,
                value: Value::Uint {
                    width: 2,
                    value: 0x125e,
                },
            },
            control::WriteFunction {
                id: control::FINISH_TIME.id,
                value: Value::Uint {
                    width: 2,
                    value: 0x1400,
                },
            },
        ];
        let mut buf = [0u8; 16];
        let n = control::encode_write_functions(&recs, &mut buf).unwrap();
        assert_eq!(&buf[..n], &[0, 0, 0x21, 0x5e, 0x12, 1, 0, 0x21, 0x00, 0x14]);
        let mut parsed: Vec<control::WriteFunction<'_>, 4> = Vec::new();
        control::parse_write_functions(&buf[..n], &mut parsed).unwrap();
        assert_eq!(parsed.as_slice(), &recs);
    }

    #[test]
    fn control_server_handles_commands() {
        let mut c: ClusterInstance<8> = control::server(true).unwrap();
        assert_eq!(
            control::handle(
                &c,
                control::CMD_EXECUTION_OF_A_COMMAND,
                &[control::command_id::START]
            ),
            control::Outcome::Execute(control::command_id::START)
        );
        assert_eq!(
            control::handle(&c, control::CMD_EXECUTION_OF_A_COMMAND, &[]),
            control::Outcome::Default(ZclStatus::MalformedCommand)
        );
        let s = control::SignalState {
            status: control::status::PAUSE,
            ..Default::default()
        };
        assert!(control::set_signal_state(&mut c, s));
        assert!(!control::set_signal_state(&mut c, s));
        assert_eq!(
            control::handle(&c, control::CMD_SIGNAL_STATE, &[]),
            control::Outcome::Response(s)
        );
        assert_eq!(
            control::handle(&c, control::CMD_OVERLOAD_WARNING, &[0x04]),
            control::Outcome::Overload(control::Overload::Warning(0x04))
        );
        assert_eq!(
            control::handle(&c, control::CMD_OVERLOAD_WARNING, &[0x05]),
            control::Outcome::Default(ZclStatus::MalformedCommand)
        );
        assert_eq!(
            control::handle(&c, control::CMD_OVERLOAD_PAUSE, &[]),
            control::Outcome::Overload(control::Overload::Pause)
        );
        assert_eq!(
            control::handle(&c, control::CMD_WRITE_FUNCTIONS, &[0, 0, 0x21, 0x5e, 0x12]),
            control::Outcome::WriteFunctions
        );
        assert_eq!(
            control::handle(&c, control::CMD_WRITE_FUNCTIONS, &[0, 0, 0x21, 0x5e]),
            control::Outcome::Default(ZclStatus::MalformedCommand)
        );
    }

    #[test]
    fn identification_packs_the_basic_fields() {
        let b = identification::BasicIdentification {
            company: 0x1234,
            brand: 0x5678,
            product_type: identification::product_type::WASHING_MACHINE,
            spec_version: 0x1a,
        };
        assert_eq!(b.to_raw(), 0x001a_5604_5678_1234);
        assert_eq!(identification::BasicIdentification::from_raw(b.to_raw()), b);
        let c: ClusterInstance<8> = identification::server(b).unwrap();
        assert_eq!(identification::basic(&c), Some(b));
    }

    #[test]
    fn alerts_are_recorded_and_answered() {
        let mut c: ClusterInstance<8> = events_alerts::server();
        let a = events_alerts::Alert {
            id: 5,
            category: events_alerts::category::FAILURE,
            present: true,
            manufacturer: 0xaa,
        };
        assert_eq!(a.to_raw(), 0x00aa_1305);
        assert_eq!(events_alerts::Alert::from_raw(0x00aa_1305), a);
        events_alerts::record(&mut c, a).unwrap();
        events_alerts::record(
            &mut c,
            events_alerts::Alert {
                id: 7,
                category: events_alerts::category::WARNING,
                present: true,
                manufacturer: 0,
            },
        )
        .unwrap();
        let mut out = [0u8; 48];
        let events_alerts::Outcome::Response(n) =
            events_alerts::handle(&c, events_alerts::CMD_GET_ALERTS, &mut out)
        else {
            panic!("no response");
        };
        assert_eq!(&out[..n], &[0x02, 0x05, 0x13, 0xaa, 0x07, 0x11, 0x00]);
        let parsed = events_alerts::parse_alerts(&out[..n]).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], a);
        // Recovery removes the alert.
        events_alerts::record(
            &mut c,
            events_alerts::Alert {
                present: false,
                ..a
            },
        )
        .unwrap();
        assert_eq!(events_alerts::alerts(&c).len(), 1);
        assert!(events_alerts::parse_alerts(&[0x11, 0, 0, 0]).is_err());
        let n = events_alerts::encode_event(events_alerts::event::END_OF_CYCLE, &mut out).unwrap();
        assert_eq!(&out[..n], &[0x00, 0x01]);
        assert_eq!(events_alerts::parse_event(&out[..n]).unwrap(), 0x01);
    }

    #[test]
    fn statistics_queue_serves_log_requests() {
        let mut c: ClusterInstance<8> = statistics::server().unwrap();
        assert_eq!(c.u64(statistics::LOG_MAX_SIZE.id), Some(70));
        for i in 0..10u8 {
            statistics::queue_mut(&mut c)
                .push(statistics::NO_TIME, &[i, i, i])
                .unwrap();
        }
        let q = statistics::queue(&c).unwrap();
        assert_eq!(q.ids().as_slice(), &[2, 3, 4, 5, 6, 7, 8, 9]);
        let mut out = [0u8; 96];
        let statistics::Outcome::Log(n) = statistics::handle(
            &c,
            statistics::CMD_LOG_REQUEST,
            &4u32.to_le_bytes(),
            &mut out,
        ) else {
            panic!("no log");
        };
        let log = statistics::Log::parse(&out[..n]).unwrap();
        assert_eq!(log.id, 4);
        assert_eq!(log.timestamp, statistics::NO_TIME);
        assert_eq!(log.payload.as_slice(), &[4, 4, 4]);
        assert_eq!(
            statistics::handle(
                &c,
                statistics::CMD_LOG_REQUEST,
                &1u32.to_le_bytes(),
                &mut out
            ),
            statistics::Outcome::Default(ZclStatus::NotFound)
        );
        let statistics::Outcome::Ids(n) =
            statistics::handle(&c, statistics::CMD_LOG_QUEUE_REQUEST, &[], &mut out)
        else {
            panic!("no ids");
        };
        assert_eq!(out[0], 8);
        assert_eq!(
            statistics::parse_ids(&out[..n]).unwrap().as_slice(),
            &[2, 3, 4, 5, 6, 7, 8, 9]
        );
    }
}
