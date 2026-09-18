//! A cluster instance: attribute table plus the server-side processing of
//! the global commands that manipulate attributes (ZCL8 §2.5.1–§2.5.10,
//! §2.5.13, §2.5.18–§2.5.23).

use panweave_codec::{Decode, Encode, Reader, Writer};
use panweave_types::time::Instant;
use panweave_types::{AttributeId, ClusterId, CommandId, ManufacturerCode};

use crate::attribute::{Access, AttributeDef, AttributeTable};
use crate::frame::{Header, ZclStatus};
use crate::global::{
    self, AttributeInfo, AttributeValue, ConfigureReportingStatus, DiscoverAttributes,
    DiscoverCommands, ReadAttributeStatus, ReadReportingConfig, ReadReportingConfigStatus, Records,
    ReportDirection, ReportingConfig, WriteAttributeStatus, WriteStructuredStatus, command,
};
use crate::structured::{self, Selector};
use crate::types::{DataType, Value};

/// Server or client side of a cluster.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Role {
    /// Server (holds the attributes, receives client-to-server commands).
    Server,
    /// Client.
    Client,
}

/// Static cluster description used when instantiating.
#[derive(Clone, Copy, Debug)]
pub struct ClusterDef {
    /// Cluster identifier.
    pub id: ClusterId,
    /// Revision reported in `ClusterRevision`.
    pub revision: u16,
    /// Cluster-specific commands this side receives (for Discover
    /// Commands Received), ascending.
    pub received: &'static [CommandId],
    /// Cluster-specific commands this side generates, ascending.
    pub generated: &'static [CommandId],
}

impl ClusterDef {
    /// The other side's view: a definition written for the server
    /// (received = client → server, generated = server → client)
    /// becomes the client's, so that Discover Commands Received /
    /// Generated answer for the instantiated role.
    pub const fn mirrored(self) -> Self {
        ClusterDef {
            id: self.id,
            revision: self.revision,
            received: self.generated,
            generated: self.received,
        }
    }
}

/// Outcome of processing a global command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GlobalOutcome {
    /// A response of the given command identifier was written.
    Response(CommandId),
    /// No response (Write Attributes No Response, Report Attributes,
    /// Default Response).
    None,
    /// Reply with a Default Response carrying this status.
    Default(ZclStatus),
}

/// Validates a write from the network to a cluster attribute beyond the
/// generic type / access checks (cluster-specific ranges and
/// relationships, e.g. Poll Control §3.16.4.1). Returns the status for
/// the Write Attributes Response record.
pub type WriteGuard<const A: usize> = fn(&AttributeTable<A>, AttributeId, &Value<'_>) -> ZclStatus;

/// Cluster-specific follow-up to a successful network write of the
/// attribute (derived attributes such as status flags are refreshed).
pub type AfterWrite<const A: usize> = fn(&mut ClusterInstance<A>, AttributeId);

/// Cluster-specific runtime state of the clusters executed by the
/// endpoint dispatcher.
#[derive(Clone, Debug, Default)]
// The Color Control engine is the largest state; every instance carries
// the enum, which is bounded and heap-free by design.
#[allow(clippy::large_enum_variant)]
pub enum ClusterState {
    /// No state.
    #[default]
    None,
    /// Level Control transition (§3.10).
    Level(crate::clusters::level::Transition),
    /// Poll Control server / client state (§3.16).
    PollControl(crate::clusters::poll_control::State),
    /// Time server clock (§3.12).
    Time(crate::clusters::time::Clock),
    /// Alarms server table (§3.11).
    Alarms(crate::clusters::alarms::Table),
    /// IAS Zone server state (§8.2).
    IasZone(crate::clusters::ias_zone::State),
    /// Color Control transition engine (§5.2).
    Color(crate::clusters::color_control::Engine),
    /// Door Lock server state: PIN users and timers (§7.3).
    DoorLock(crate::clusters::door_lock::State),
    /// IAS ACE server state: the zone table and panel status (§8.3).
    IasAce(crate::clusters::ias_ace::Panel),
    /// Commissioning server state: the saved startup sets (§13.2).
    Commissioning(crate::clusters::commissioning::State),
    /// Thermostat server state: the weekly setpoint schedule (§6.3).
    Thermostat(crate::clusters::hvac::thermostat::Schedule),
    /// Power Configuration mains server: the voltage dwell timer (§3.3).
    Mains(crate::clusters::power_configuration::MainsDwell),
    /// A threshold dwell timer (Device Temperature Configuration §3.4).
    Dwell(crate::clusters::configuration::Dwell),
    /// Appliance Control server state: the signal state (§15.2).
    ApplianceControl(crate::clusters::appliance::control::State),
    /// Appliance Events and Alerts server state: the current alerts
    /// (§15.4).
    ApplianceAlerts(crate::clusters::appliance::events_alerts::Alerts),
    /// Appliance Statistics server state: the log queue (§15.5).
    ApplianceLogs(crate::clusters::appliance::statistics::LogQueue),
    /// Power Profile server state: the profiles (§3.17).
    PowerProfile(crate::clusters::power_profile::Profiles),
    /// RSSI Location server state: repeated responses, ping blasts
    /// and collected RSSI responses (§3.13).
    RssiLocation(crate::clusters::rssi_location::State),
    /// Zigbee Direct Configuration server state: the security model of
    /// the network (ZD 1.1 §11.3.5.1).
    DirectConfiguration(crate::clusters::direct_configuration::State),
}

/// A cluster instance.
#[derive(Clone, Debug)]
pub struct ClusterInstance<const A: usize> {
    /// Definition.
    pub def: ClusterDef,
    /// Role.
    pub role: Role,
    /// Attributes.
    pub attributes: AttributeTable<A>,
    /// Cluster-specific periodic timer (e.g. the Identify countdown),
    /// serviced by the endpoint dispatcher.
    pub tick: Option<Instant>,
    /// Cluster-specific state.
    pub state: ClusterState,
    /// Cluster-specific validation of network writes.
    pub write_guard: Option<WriteGuard<A>>,
    /// Cluster-specific follow-up to network writes.
    pub after_write: Option<AfterWrite<A>>,
    /// Manufacturer code of a manufacturer-specific cluster (§2.3.3):
    /// frames must carry it in their header, and only such frames reach
    /// the instance.
    pub manufacturer: Option<ManufacturerCode>,
    /// A multi-frame report is in progress: the previous Report
    /// Attributes ended with `AttributeReportingStatus` = Pending
    /// (§2.3.4.5.2).
    report_pending: bool,
}

impl<const A: usize> ClusterInstance<A> {
    /// Creates the instance with the mandatory `ClusterRevision`
    /// attribute (§2.3.4.5.1).
    pub fn new(def: ClusterDef, role: Role) -> Self {
        let mut attributes = AttributeTable::new();
        let _ = attributes.add(
            AttributeDef::CLUSTER_REVISION,
            &Value::Uint {
                width: 2,
                value: u64::from(def.revision),
            },
        );
        ClusterInstance {
            def,
            role,
            attributes,
            tick: None,
            state: ClusterState::None,
            write_guard: None,
            after_write: None,
            manufacturer: None,
            report_pending: false,
        }
    }

    /// Marks the instance as the manufacturer-specific cluster of
    /// `code` (identifiers 0xfc00–0xffff, §2.3.3); frames without the
    /// manufacturer code, or with another one, are not carried out.
    #[must_use]
    pub fn manufacturer_specific(mut self, code: ManufacturerCode) -> Self {
        self.manufacturer = Some(code);
        self
    }

    /// Adds an attribute with its initial value.
    pub fn add_attribute(
        &mut self,
        def: AttributeDef,
        initial: &Value<'_>,
    ) -> Result<(), ZclStatus> {
        self.attributes.add(def, initial)
    }

    /// Adds an attribute with its initial value and a default reporting
    /// configuration (BDB 3.1 §6.5).
    pub fn add_reported_attribute(
        &mut self,
        def: AttributeDef,
        initial: &Value<'_>,
        reporting: crate::attribute::DefaultReporting,
    ) -> Result<(), ZclStatus> {
        self.attributes
            .add_reported(def, initial, reporting, Instant::from_millis(0))
    }

    /// Restores the factory defaults of every attribute and clears the
    /// transient state (§3.2.2.3.1).
    pub fn reset_to_defaults(&mut self, now: Instant) {
        self.attributes.reset_to_defaults(now);
        self.tick = None;
        self.state = match core::mem::take(&mut self.state) {
            ClusterState::Level(_) => {
                ClusterState::Level(crate::clusters::level::Transition::default())
            }
            ClusterState::PollControl(_) => {
                ClusterState::PollControl(crate::clusters::poll_control::State::default())
            }
            ClusterState::Time(k) => ClusterState::Time(crate::clusters::time::Clock {
                base: None,
                published: crate::clusters::time::INVALID,
                ..k
            }),
            ClusterState::Alarms(_) => {
                ClusterState::Alarms(crate::clusters::alarms::Table::default())
            }
            ClusterState::IasZone(z) => ClusterState::IasZone(crate::clusters::ias_zone::State {
                cie: None,
                cie_address: 0,
                enroll_request_due: false,
                notify_due: None,
                test_until: None,
                ..z
            }),
            ClusterState::Color(_) => {
                ClusterState::Color(crate::clusters::color_control::Engine::default())
            }
            ClusterState::DoorLock(d) => {
                // The PIN users are wiped, the slot count is kept.
                let mut users = heapless::Vec::new();
                for _ in 0..d.users.len() {
                    let _ = users.push(crate::clusters::door_lock::User::default());
                }
                ClusterState::DoorLock(crate::clusters::door_lock::State {
                    users,
                    ..crate::clusters::door_lock::State::default()
                })
            }
            ClusterState::IasAce(p) => {
                // The zone table and code are wiped; the panel is disarmed.
                ClusterState::IasAce(crate::clusters::ias_ace::Panel {
                    audible: p.audible,
                    ready: true,
                    ..crate::clusters::ias_ace::Panel::default()
                })
            }
            ClusterState::Commissioning(_) => {
                ClusterState::Commissioning(crate::clusters::commissioning::State::default())
            }
            ClusterState::Thermostat(s) => {
                // The transitions are wiped, the capacities kept.
                ClusterState::Thermostat(crate::clusters::hvac::thermostat::Schedule {
                    weekly: s.weekly,
                    daily: s.daily,
                    dirty: true,
                    ..crate::clusters::hvac::thermostat::Schedule::default()
                })
            }
            ClusterState::Mains(_) => {
                ClusterState::Mains(crate::clusters::power_configuration::MainsDwell::default())
            }
            ClusterState::Dwell(_) => {
                ClusterState::Dwell(crate::clusters::configuration::Dwell::default())
            }
            ClusterState::ApplianceControl(_) => {
                ClusterState::ApplianceControl(crate::clusters::appliance::control::State::default())
            }
            ClusterState::ApplianceAlerts(_) => ClusterState::ApplianceAlerts(
                crate::clusters::appliance::events_alerts::Alerts::default(),
            ),
            ClusterState::ApplianceLogs(_) => ClusterState::ApplianceLogs(
                crate::clusters::appliance::statistics::LogQueue::default(),
            ),
            ClusterState::DirectConfiguration(s) => ClusterState::DirectConfiguration(s),
            ClusterState::RssiLocation(s) => {
                // The identity is kept; pending work is dropped.
                ClusterState::RssiLocation(crate::clusters::rssi_location::State {
                    pending_responses: 0,
                    requester: None,
                    pending_pings: 0,
                    collected: heapless::Vec::new(),
                    report_at: None,
                    next_response: None,
                    next_ping: None,
                    next_report: None,
                    calculated_at: None,
                    ..s
                })
            }
            ClusterState::PowerProfile(p) => {
                // The profile slots are kept; forecasts, schedules and
                // constraints are wiped.
                let mut wiped = crate::clusters::power_profile::Profiles::default();
                for e in &p.entries {
                    let _ = wiped.entries.push(crate::clusters::power_profile::Entry {
                        phases: heapless::Vec::new(),
                        record: crate::clusters::power_profile::ProfileRecord {
                            energy_phase: crate::clusters::power_profile::NO_PHASE,
                            state: crate::clusters::power_profile::state::IDLE,
                            ..e.record
                        },
                        schedule: heapless::Vec::new(),
                        constraints: crate::clusters::power_profile::Constraints {
                            id: e.record.id,
                            start_after: 0,
                            stop_before: crate::clusters::power_profile::NO_STOP,
                        },
                    });
                }
                ClusterState::PowerProfile(wiped)
            }
            ClusterState::None => ClusterState::None,
        };
    }

    /// Unsigned value of a standard attribute (`None` when absent).
    pub fn u64(&self, id: AttributeId) -> Option<u64> {
        self.attributes.u64(id)
    }

    /// 8-bit unsigned value of a standard attribute.
    pub fn u8(&self, id: AttributeId) -> Option<u8> {
        self.u64(id).and_then(|v| u8::try_from(v).ok())
    }

    /// 16-bit unsigned value of a standard attribute.
    pub fn u16(&self, id: AttributeId) -> Option<u16> {
        self.u64(id).and_then(|v| u16::try_from(v).ok())
    }

    /// 16-bit signed value of a standard attribute.
    pub fn i16(&self, id: AttributeId) -> Option<i16> {
        self.attributes
            .value(id)
            .and_then(|v| v.as_i64())
            .and_then(|v| i16::try_from(v).ok())
    }

    /// Boolean value of a standard attribute (`false` when absent or
    /// invalid).
    pub fn bool(&self, id: AttributeId) -> bool {
        matches!(self.attributes.value(id), Some(Value::Bool(Some(true))))
    }

    /// Application-side write of a standard attribute; returns whether
    /// the value changed.
    pub fn set(&mut self, id: AttributeId, v: &Value<'_>) -> bool {
        self.attributes.set(id, v).unwrap_or(false)
    }

    /// Application-side write of an unsigned 8-bit attribute.
    pub fn set_u8(&mut self, id: AttributeId, value: u8) -> bool {
        self.set(
            id,
            &Value::Uint {
                width: 1,
                value: u64::from(value),
            },
        )
    }

    /// Application-side write of an unsigned 16-bit attribute.
    pub fn set_u16(&mut self, id: AttributeId, value: u16) -> bool {
        self.set(
            id,
            &Value::Uint {
                width: 2,
                value: u64::from(value),
            },
        )
    }

    /// Application-side write of a signed 16-bit attribute.
    pub fn set_i16(&mut self, id: AttributeId, value: i16) -> bool {
        self.set(
            id,
            &Value::Int {
                width: 2,
                value: i64::from(value),
            },
        )
    }

    /// Application-side write of a boolean attribute.
    pub fn set_bool(&mut self, id: AttributeId, value: bool) -> bool {
        self.set(id, &Value::Bool(Some(value)))
    }

    /// Processes a global command addressed to this instance; the
    /// response payload (if any) is written to `out`.
    pub fn handle_global(
        &mut self,
        header: &Header,
        payload: &[u8],
        out: &mut Writer<'_>,
        now: Instant,
    ) -> GlobalOutcome {
        // In a manufacturer-specific cluster every attribute is the
        // manufacturer's: the frame's code names the cluster, not a
        // manufacturer-specific attribute of a standard cluster.
        let manuf = if self.manufacturer.is_some() && header.manufacturer == self.manufacturer {
            None
        } else {
            header.manufacturer
        };
        match header.command {
            command::READ_ATTRIBUTES => {
                for id in global::AttributeIds(payload) {
                    let rec = match self.attributes.get(id, manuf) {
                        Some(a) if a.def.access.has(Access::READ) => ReadAttributeStatus {
                            id,
                            status: ZclStatus::Success,
                            value: Some(a.value()),
                        },
                        Some(a) => ReadAttributeStatus {
                            id,
                            status: if a.def.access.has(Access::SECRET) {
                                ZclStatus::NotAuthorized
                            } else {
                                ZclStatus::WriteOnly
                            },
                            value: None,
                        },
                        None => ReadAttributeStatus {
                            id,
                            status: ZclStatus::UnsupportedAttribute,
                            value: None,
                        },
                    };
                    if rec.encoded_len() > out.remaining() {
                        // INSUFFICIENT_SPACE record if that fits, else stop.
                        let short = ReadAttributeStatus {
                            id,
                            status: ZclStatus::InsufficientSpace,
                            value: None,
                        };
                        if short.encode(out).is_err() {
                            break;
                        }
                        break;
                    }
                    if rec.encode(out).is_err() {
                        break;
                    }
                }
                GlobalOutcome::Response(command::READ_ATTRIBUTES_RESPONSE)
            }
            command::WRITE_ATTRIBUTES
            | command::WRITE_ATTRIBUTES_UNDIVIDED
            | command::WRITE_ATTRIBUTES_NO_RESPONSE => {
                let undivided = header.command == command::WRITE_ATTRIBUTES_UNDIVIDED;
                let respond = header.command != command::WRITE_ATTRIBUTES_NO_RESPONSE;
                let mut any_error = false;
                // Undivided: validate everything first (§2.5.4).
                if undivided {
                    for rec in Records::<AttributeValue>::new(payload) {
                        let Ok(rec) = rec else {
                            return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                        };
                        if self.check_write(&rec, manuf).is_err() {
                            any_error = true;
                        }
                    }
                }
                let mut wrote_status = false;
                for rec in Records::<AttributeValue>::new(payload) {
                    let Ok(rec) = rec else {
                        return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                    };
                    let status = match self.check_write(&rec, manuf) {
                        Ok(()) if undivided && any_error => continue,
                        Ok(()) => {
                            let set = match self.attributes.get_mut(rec.id, manuf) {
                                Some(mut a) => a.set(&rec.value).map(|_| ()),
                                None => Err(ZclStatus::UnsupportedAttribute),
                            };
                            match set {
                                Ok(()) => {
                                    if let Some(hook) = self.after_write {
                                        hook(self, rec.id);
                                    }
                                    continue;
                                }
                                Err(s) => s,
                            }
                        }
                        Err(s) => s,
                    };
                    if respond {
                        let st = WriteAttributeStatus {
                            status,
                            id: Some(rec.id),
                        };
                        if st.encode(out).is_err() {
                            break;
                        }
                        wrote_status = true;
                    }
                }
                if !respond {
                    return GlobalOutcome::None;
                }
                if !wrote_status {
                    let _ = WriteAttributeStatus {
                        status: ZclStatus::Success,
                        id: None,
                    }
                    .encode(out);
                }
                GlobalOutcome::Response(command::WRITE_ATTRIBUTES_RESPONSE)
            }
            command::READ_ATTRIBUTES_STRUCTURED => {
                let mut r = Reader::new(payload);
                while !r.is_empty() {
                    let (Ok(id), Ok(selector)) = (r.u16_le(), Selector::decode(&mut r)) else {
                        return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                    };
                    let id = AttributeId(id);
                    let rec = match (self.attributes.get(id, manuf), selector) {
                        (None, _) => ReadAttributeStatus {
                            id,
                            status: ZclStatus::UnsupportedAttribute,
                            value: None,
                        },
                        (Some(a), _) if !a.def.access.has(Access::READ) => ReadAttributeStatus {
                            id,
                            status: if a.def.access.has(Access::SECRET) {
                                ZclStatus::NotAuthorized
                            } else {
                                ZclStatus::WriteOnly
                            },
                            value: None,
                        },
                        (Some(a), Ok(sel)) if sel.is_whole() => ReadAttributeStatus {
                            id,
                            status: ZclStatus::Success,
                            value: Some(a.value()),
                        },
                        (Some(a), Ok(sel)) => {
                            let element = match a.value() {
                                Value::Composite { ty, bytes }
                                    if matches!(ty, DataType::Array | DataType::Struct) =>
                                {
                                    structured::select(ty, bytes, &sel.indices)
                                }
                                _ => Err(ZclStatus::InvalidSelector),
                            };
                            match element {
                                Ok(structured::Element::Count(n)) => ReadAttributeStatus {
                                    id,
                                    status: ZclStatus::Success,
                                    value: Some(Value::Uint {
                                        width: 2,
                                        value: u64::from(n),
                                    }),
                                },
                                Ok(structured::Element::Value { ty, bytes }) => {
                                    match Value::decode(&mut Reader::new(bytes), ty) {
                                        Ok(v) => ReadAttributeStatus {
                                            id,
                                            status: ZclStatus::Success,
                                            value: Some(v),
                                        },
                                        Err(_) => ReadAttributeStatus {
                                            id,
                                            status: ZclStatus::InvalidSelector,
                                            value: None,
                                        },
                                    }
                                }
                                Err(status) => ReadAttributeStatus {
                                    id,
                                    status,
                                    value: None,
                                },
                            }
                        }
                        (Some(_), Err(status)) => ReadAttributeStatus {
                            id,
                            status,
                            value: None,
                        },
                    };
                    if rec.encoded_len() > out.remaining() {
                        let _ = ReadAttributeStatus {
                            id,
                            status: ZclStatus::InsufficientSpace,
                            value: None,
                        }
                        .encode(out);
                        break;
                    }
                    if rec.encode(out).is_err() {
                        break;
                    }
                }
                GlobalOutcome::Response(command::READ_ATTRIBUTES_RESPONSE)
            }
            command::WRITE_ATTRIBUTES_STRUCTURED => {
                let mut r = Reader::new(payload);
                let mut wrote_status = false;
                while !r.is_empty() {
                    let (Ok(id), Ok(selector)) = (r.u16_le(), Selector::decode(&mut r)) else {
                        return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                    };
                    let Ok(ty) = r.u8() else {
                        return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                    };
                    let Ok(value) = Value::decode(&mut r, DataType::from_id(ty)) else {
                        return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                    };
                    let id = AttributeId(id);
                    let (status, failed) = match selector {
                        Ok(sel) => match self.write_structured(id, &sel, &value, manuf) {
                            Ok(()) => continue,
                            Err(status) => (status, sel),
                        },
                        Err(status) => (status, Selector::WHOLE),
                    };
                    let st = WriteStructuredStatus {
                        status,
                        target: Some((id, failed)),
                    };
                    if st.encode(out).is_err() {
                        break;
                    }
                    wrote_status = true;
                }
                if !wrote_status {
                    let _ = WriteStructuredStatus {
                        status: ZclStatus::Success,
                        target: None,
                    }
                    .encode(out);
                }
                GlobalOutcome::Response(command::WRITE_ATTRIBUTES_STRUCTURED_RESPONSE)
            }
            command::CONFIGURE_REPORTING => {
                let mut wrote = false;
                for rec in Records::<ReportingConfig>::new(payload) {
                    let Ok(rec) = rec else {
                        return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                    };
                    let status = self.configure(&rec, manuf, now);
                    if !status.is_success() {
                        let st = ConfigureReportingStatus {
                            status,
                            target: Some((rec.direction(), rec.id())),
                        };
                        if st.encode(out).is_err() {
                            break;
                        }
                        wrote = true;
                    }
                }
                if !wrote {
                    let _ = ConfigureReportingStatus {
                        status: ZclStatus::Success,
                        target: None,
                    }
                    .encode(out);
                }
                GlobalOutcome::Response(command::CONFIGURE_REPORTING_RESPONSE)
            }
            command::READ_REPORTING_CONFIGURATION => {
                for rec in Records::<ReadReportingConfig>::new(payload) {
                    let Ok(rec) = rec else {
                        return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                    };
                    let st = self.read_reporting(rec, manuf);
                    if st.encode(out).is_err() {
                        break;
                    }
                }
                GlobalOutcome::Response(command::READ_REPORTING_CONFIGURATION_RESPONSE)
            }
            command::DISCOVER_ATTRIBUTES | command::DISCOVER_ATTRIBUTES_EXTENDED => {
                let Ok(req) = DiscoverAttributes::decode_exact(payload) else {
                    return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                };
                let extended = header.command == command::DISCOVER_ATTRIBUTES_EXTENDED;
                let complete_pos = out.position();
                let Ok(complete_slot) = out.reserve(1) else {
                    return GlobalOutcome::Default(ZclStatus::InsufficientSpace);
                };
                complete_slot[0] = 1;
                let mut count = 0u8;
                let complete = self.attributes.discover(req.start, manuf, |a| {
                    if count >= req.max {
                        return false;
                    }
                    let info = AttributeInfo {
                        id: a.def.id,
                        ty: a.def.ty,
                        access: extended.then_some(a.def.access.0 & 0x07),
                    };
                    if info.encode(out).is_err() {
                        return false;
                    }
                    count += 1;
                    true
                });
                if !complete && let Ok(slot) = out.patch(complete_pos, 1) {
                    slot[0] = 0;
                }
                GlobalOutcome::Response(if extended {
                    command::DISCOVER_ATTRIBUTES_EXTENDED_RESPONSE
                } else {
                    command::DISCOVER_ATTRIBUTES_RESPONSE
                })
            }
            command::DISCOVER_COMMANDS_RECEIVED | command::DISCOVER_COMMANDS_GENERATED => {
                let Ok(req) = DiscoverCommands::decode_exact(payload) else {
                    return GlobalOutcome::Default(ZclStatus::MalformedCommand);
                };
                let received = header.command == command::DISCOVER_COMMANDS_RECEIVED;
                let list = if received {
                    self.def.received
                } else {
                    self.def.generated
                };
                let complete_pos = out.position();
                let Ok(complete_slot) = out.reserve(1) else {
                    return GlobalOutcome::Default(ZclStatus::InsufficientSpace);
                };
                complete_slot[0] = 1;
                let mut complete = true;
                for (count, c) in list.iter().filter(|c| c.0 >= req.start.0).enumerate() {
                    if count >= usize::from(req.max) || out.u8(c.0).is_err() {
                        complete = false;
                        break;
                    }
                }
                if !complete && let Ok(slot) = out.patch(complete_pos, 1) {
                    slot[0] = 0;
                }
                GlobalOutcome::Response(if received {
                    command::DISCOVER_COMMANDS_RECEIVED_RESPONSE
                } else {
                    command::DISCOVER_COMMANDS_GENERATED_RESPONSE
                })
            }
            command::REPORT_ATTRIBUTES | command::DEFAULT_RESPONSE => GlobalOutcome::None,
            c if c.0 <= command::DISCOVER_ATTRIBUTES_EXTENDED_RESPONSE.0 => {
                // Responses arriving at a server side are informational.
                GlobalOutcome::None
            }
            _ => GlobalOutcome::Default(if manuf.is_some() {
                ZclStatus::UnsupportedManufacturerGeneralCommand
            } else {
                ZclStatus::UnsupportedGeneralCommand
            }),
        }
    }

    /// The write checks of §2.5.3.3 in order.
    fn check_write(
        &self,
        rec: &AttributeValue<'_>,
        manuf: Option<ManufacturerCode>,
    ) -> Result<(), ZclStatus> {
        let a = self
            .attributes
            .get(rec.id, manuf)
            .ok_or(ZclStatus::UnsupportedAttribute)?;
        if rec.value.data_type() != a.def.ty {
            return Err(ZclStatus::InvalidDataType);
        }
        if !a.def.access.has(Access::WRITE) {
            return Err(ZclStatus::ReadOnly);
        }
        if rec.value.encoded_len() > crate::attribute::MAX_ATTRIBUTE_BYTES {
            return Err(ZclStatus::InvalidValue);
        }
        if let Some(guard) = self.write_guard {
            let status = guard(&self.attributes, rec.id, &rec.value);
            if !status.is_success() {
                return Err(status);
            }
        }
        Ok(())
    }

    /// One Write Attributes Structured record (§2.5.16.3): a whole
    /// write follows the plain Write Attributes rules; an element write
    /// rebuilds the composite; set / bag add and remove per the
    /// indicator. Array lengths are read-only (no application fill).
    fn write_structured(
        &mut self,
        id: AttributeId,
        selector: &Selector,
        value: &Value<'_>,
        manuf: Option<ManufacturerCode>,
    ) -> Result<(), ZclStatus> {
        if selector.is_whole() && selector.op == structured::op::WRITE {
            let rec = AttributeValue { id, value: *value };
            self.check_write(&rec, manuf)?;
            self.attributes
                .get_mut(id, manuf)
                .ok_or(ZclStatus::UnsupportedAttribute)?
                .set(value)?;
            if let Some(hook) = self.after_write {
                hook(self, id);
            }
            return Ok(());
        }
        let a = self
            .attributes
            .get(id, manuf)
            .ok_or(ZclStatus::UnsupportedAttribute)?;
        let Value::Composite { ty, bytes } = a.value() else {
            return Err(ZclStatus::InvalidSelector);
        };
        let rebuilt = match selector.op {
            structured::op::WRITE => {
                structured::replace(ty, bytes, &selector.indices, value, None)?
            }
            structured::op::ADD | structured::op::REMOVE => structured::add_remove(
                ty,
                bytes,
                &selector.indices,
                value,
                selector.op == structured::op::ADD,
            )?,
            _ => return Err(ZclStatus::InvalidSelector),
        };
        if !a.def.access.has(Access::WRITE) {
            return Err(ZclStatus::ReadOnly);
        }
        let whole = Value::Composite {
            ty,
            bytes: &rebuilt,
        };
        if let Some(guard) = self.write_guard {
            let status = guard(&self.attributes, id, &whole);
            if !status.is_success() {
                return Err(status);
            }
        }
        self.attributes
            .get_mut(id, manuf)
            .ok_or(ZclStatus::UnsupportedAttribute)?
            .set(&whole)
            .map(|_| ())
    }

    /// Configure Reporting processing (§2.5.7.3).
    fn configure(
        &mut self,
        rec: &ReportingConfig<'_>,
        manuf: Option<ManufacturerCode>,
        now: Instant,
    ) -> ZclStatus {
        match *rec {
            ReportingConfig::Reported {
                id,
                ty,
                min,
                max,
                change,
            } => {
                let Some(mut a) = self.attributes.get_mut(id, manuf) else {
                    return ZclStatus::UnsupportedAttribute;
                };
                let def = a.def();
                if def.ty.is_composite() || !def.access.has(Access::REPORT) {
                    return ZclStatus::UnreportableAttribute;
                }
                if ty != def.ty {
                    return ZclStatus::InvalidDataType;
                }
                if max != 0 && max != 0xffff && max < min {
                    return ZclStatus::InvalidValue;
                }
                if max == 0 && min == 0xffff {
                    // Revert to the default configuration: reporting off.
                    a.configure_reporting(0, 0xffff, 0, now);
                    return ZclStatus::Success;
                }
                let change = match change {
                    Some(Value::Single(f)) => f64::from(f).to_bits(),
                    Some(Value::Double(f)) => f.to_bits(),
                    Some(Value::Semi(bits)) => f64::from(crate::types::semi_to_f32(bits)).to_bits(),
                    other => other.as_ref().and_then(Value::as_u64).unwrap_or(0),
                };
                a.configure_reporting(min, max, change, now);
                ZclStatus::Success
            }
            ReportingConfig::Received { id, timeout } => {
                let Some(mut a) = self.attributes.get_mut(id, manuf) else {
                    return ZclStatus::UnreportableAttribute;
                };
                a.set_report_timeout(timeout);
                ZclStatus::Success
            }
        }
    }

    fn read_reporting(
        &self,
        rec: ReadReportingConfig,
        manuf: Option<ManufacturerCode>,
    ) -> ReadReportingConfigStatus<'_> {
        let Some(a) = self.attributes.get(rec.id, manuf) else {
            return ReadReportingConfigStatus {
                status: ZclStatus::UnsupportedAttribute,
                config: placeholder(rec),
            };
        };
        if !a.def.access.has(Access::REPORT) {
            return ReadReportingConfigStatus {
                status: ZclStatus::UnreportableAttribute,
                config: placeholder(rec),
            };
        }
        match (rec.direction, a.reporting) {
            (ReportDirection::Reported, Some(r)) if r.active() => ReadReportingConfigStatus {
                status: ZclStatus::Success,
                config: ReportingConfig::Reported {
                    id: rec.id,
                    ty: a.def.ty,
                    min: r.min,
                    max: r.max,
                    change: a
                        .def
                        .ty
                        .is_analog()
                        .then(|| change_value(a.def.ty, r.change)),
                },
            },
            (ReportDirection::Reported, _) => ReadReportingConfigStatus {
                status: ZclStatus::Success,
                config: ReportingConfig::Reported {
                    id: rec.id,
                    ty: a.def.ty,
                    min: 0,
                    max: 0xffff,
                    change: a.def.ty.is_analog().then(|| change_value(a.def.ty, 0)),
                },
            },
            (ReportDirection::Received, r) => ReadReportingConfigStatus {
                status: ZclStatus::Success,
                config: ReportingConfig::Received {
                    id: rec.id,
                    timeout: r.map_or(0, |r| r.timeout),
                },
            },
        }
    }

    /// Appends Report Attributes records for every due attribute and
    /// marks them reported; returns the number of records written.
    pub fn collect_reports(&mut self, now: Instant, out: &mut Writer<'_>) -> usize {
        // Room for the AttributeReportingStatus record that closes a
        // frame of a multi-frame report (§2.3.4.5.2).
        const STATUS_LEN: usize = 4;
        let mut n = 0;
        for i in 0..self.attributes.len() {
            let a = self.attributes.at(i);
            if !a.report_due(now) {
                continue;
            }
            let rec = AttributeValue {
                id: a.def.id,
                value: a.value(),
            };
            if rec.encoded_len() + STATUS_LEN > out.remaining() {
                break;
            }
            if rec.encode(out).is_err() {
                break;
            }
            self.attributes.at_mut(i).mark_reported(now);
            n += 1;
        }
        if n == 0 {
            return 0;
        }
        let more = self.attributes.iter().any(|a| a.report_due(now));
        let status = if more {
            Some(0x00)
        } else if self.report_pending {
            Some(0x01)
        } else {
            None
        };
        if let Some(s) = status {
            let rec = AttributeValue {
                id: AttributeDef::ATTRIBUTE_REPORTING_STATUS.id,
                value: Value::Enum8(s),
            };
            if rec.encode(out).is_ok() {
                n += 1;
            }
        }
        self.report_pending = more;
        n
    }

    /// Earliest scheduled report.
    pub fn next_report(&self) -> Option<Instant> {
        self.attributes.next_report()
    }

    /// Decodes `bytes` as a value of `id`'s type (helper for tests and
    /// applications).
    pub fn decode_value<'a>(&self, id: AttributeId, bytes: &'a [u8]) -> Option<Value<'a>> {
        let ty = self.attributes.get(id, None)?.def.ty;
        let mut r = Reader::new(bytes);
        Value::decode(&mut r, ty).ok()
    }
}

fn placeholder(rec: ReadReportingConfig) -> ReportingConfig<'static> {
    match rec.direction {
        ReportDirection::Reported => ReportingConfig::Reported {
            id: rec.id,
            ty: DataType::NoData,
            min: 0,
            max: 0,
            change: None,
        },
        ReportDirection::Received => ReportingConfig::Received {
            id: rec.id,
            timeout: 0,
        },
    }
}

/// Encodes a reportable change magnitude as a value of the attribute's
/// type.
fn change_value(ty: DataType, change: u64) -> Value<'static> {
    match ty {
        DataType::Uint(w) => Value::Uint {
            width: w,
            value: change,
        },
        DataType::Int(w) => Value::Int {
            width: w,
            value: i64::try_from(change).unwrap_or(i64::MAX),
        },
        #[allow(clippy::cast_possible_truncation)]
        DataType::Single => Value::Single(f64::from_bits(change) as f32),
        DataType::Double => Value::Double(f64::from_bits(change)),
        #[allow(clippy::cast_possible_truncation)]
        DataType::Semi => Value::Semi(crate::types::f32_to_semi(f64::from_bits(change) as f32)),
        #[allow(clippy::cast_possible_truncation)]
        DataType::TimeOfDay | DataType::Date | DataType::UtcTime => Value::Time {
            ty,
            raw: change as u32,
        },
        _ => Value::NoData,
    }
}

#[cfg(test)]
mod reporting_status_tests {
    use panweave_codec::Writer;
    use panweave_types::time::Instant;
    use panweave_types::{AttributeId, ClusterId};

    use super::*;
    use crate::attribute::Access;
    use crate::types::DataType;

    #[test]
    fn a_client_discovers_the_commands_of_its_own_side() {
        use crate::frame::{Direction, Header};
        use crate::global::{DiscoverCommands, command};
        use panweave_codec::Encode;
        use panweave_types::{CommandId, TransactionSequence};

        let def = ClusterDef {
            id: ClusterId(0x0006),
            revision: 1,
            received: &[CommandId(0x00), CommandId(0x01), CommandId(0x02)],
            generated: &[CommandId(0x40)],
        };
        let mirrored = def.mirrored();
        assert_eq!(mirrored.received, def.generated);
        assert_eq!(mirrored.generated, def.received);
        let mut client: ClusterInstance<4> = ClusterInstance::new(mirrored, Role::Client);
        let mut req = [0u8; 2];
        let req_len = DiscoverCommands {
            start: CommandId(0),
            max: 8,
        }
        .encode_to_slice(&mut req)
        .unwrap();
        let req = &req[..req_len];
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        let header = Header::global(
            TransactionSequence(1),
            command::DISCOVER_COMMANDS_RECEIVED,
            Direction::ToClient,
        );
        let outcome = client.handle_global(&header, req, &mut w, Instant::ZERO);
        assert!(matches!(outcome, GlobalOutcome::Response(_)));
        let n = w.position();
        assert_eq!(&buf[..n], &[1, 0x40]);
        let mut w = Writer::new(&mut buf);
        let header = Header::global(
            TransactionSequence(2),
            command::DISCOVER_COMMANDS_GENERATED,
            Direction::ToClient,
        );
        let _ = client.handle_global(&header, req, &mut w, Instant::ZERO);
        let n = w.position();
        assert_eq!(&buf[..n], &[1, 0x00, 0x01, 0x02]);
    }

    #[test]
    fn multi_frame_reports_carry_attribute_reporting_status() {
        let def = ClusterDef {
            id: ClusterId(0x0402),
            revision: 1,
            received: &[],
            generated: &[],
        };
        let mut c: ClusterInstance<8> = ClusterInstance::new(def, Role::Server);
        let now = Instant::ZERO;
        for i in 0..4u16 {
            let id = AttributeId(i);
            c.add_attribute(
                AttributeDef::new(id.0, DataType::Uint(2), Access::RO),
                &Value::Uint {
                    width: 2,
                    value: 100 + u64::from(i),
                },
            )
            .unwrap();
            c.attributes
                .get_mut(id, None)
                .unwrap()
                .configure_reporting(0, 10, 0, now);
        }
        let later = now + panweave_types::time::Duration::from_secs(11);
        // Room for two 5-octet records plus the status record.
        let mut buf = [0u8; 14];
        let n = {
            let mut w = Writer::new(&mut buf);
            c.collect_reports(later, &mut w)
        };
        assert_eq!(n, 3, "two attributes and a Pending status");
        assert_eq!(&buf[10..14], &[0xFE, 0xFF, 0x30, 0x00]);
        // The rest, closed with Complete.
        let mut buf = [0u8; 32];
        let n = {
            let mut w = Writer::new(&mut buf);
            c.collect_reports(later, &mut w)
        };
        assert_eq!(n, 3);
        assert_eq!(&buf[10..14], &[0xFE, 0xFF, 0x30, 0x01]);
        // A single-frame report carries no status.
        let again = later + panweave_types::time::Duration::from_secs(11);
        let mut buf = [0u8; 64];
        let n = {
            let mut w = Writer::new(&mut buf);
            c.collect_reports(again, &mut w)
        };
        assert_eq!(n, 4);
        assert!(!buf[..20].windows(2).any(|w| w == [0xFE, 0xFF]));
    }
}
