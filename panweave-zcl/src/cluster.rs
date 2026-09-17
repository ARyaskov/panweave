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
    ReportDirection, ReportingConfig, WriteAttributeStatus, command,
};
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
        }
    }

    /// Adds an attribute with its initial value.
    pub fn add_attribute(
        &mut self,
        def: AttributeDef,
        initial: &Value<'_>,
    ) -> Result<(), ZclStatus> {
        self.attributes.add(def, initial)
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
        let manuf = header.manufacturer;
        match header.command {
            command::READ_ATTRIBUTES => {
                for id in global::AttributeIds(payload) {
                    let rec = match self.attributes.get(id, manuf) {
                        Some(a) if a.def.access.has(Access::READ) => ReadAttributeStatus {
                            id,
                            status: ZclStatus::Success,
                            value: Some(a.value()),
                        },
                        Some(_) => ReadAttributeStatus {
                            id,
                            status: ZclStatus::WriteOnly,
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
                        Ok(()) => match self.attributes.get_mut(rec.id, manuf) {
                            Some(a) => match a.set(&rec.value) {
                                Ok(_) => continue,
                                Err(s) => s,
                            },
                            None => ZclStatus::UnsupportedAttribute,
                        },
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
            command::READ_ATTRIBUTES_STRUCTURED | command::WRITE_ATTRIBUTES_STRUCTURED => {
                // No structured attributes are held by this store.
                GlobalOutcome::Default(ZclStatus::UnsupportedGeneralCommand)
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
        Ok(())
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
                let Some(a) = self.attributes.get_mut(id, manuf) else {
                    return ZclStatus::UnsupportedAttribute;
                };
                if a.def.ty.is_composite() || !a.def.access.has(Access::REPORT) {
                    return ZclStatus::UnreportableAttribute;
                }
                if ty != a.def.ty {
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
                let change = change.as_ref().and_then(Value::as_u64).unwrap_or(0);
                a.configure_reporting(min, max, change, now);
                ZclStatus::Success
            }
            ReportingConfig::Received { id, timeout } => {
                let Some(a) = self.attributes.get_mut(id, manuf) else {
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
        match (rec.direction, &a.reporting) {
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
                    timeout: r.as_ref().map_or(0, |r| r.timeout),
                },
            },
        }
    }

    /// Appends Report Attributes records for every due attribute and
    /// marks them reported; returns the number of records written.
    pub fn collect_reports(&mut self, now: Instant, out: &mut Writer<'_>) -> usize {
        let mut n = 0;
        for a in self.attributes.iter_mut() {
            if !a.report_due(now) {
                continue;
            }
            let rec = AttributeValue {
                id: a.def.id,
                value: a.value(),
            };
            if rec.encoded_len() > out.remaining() {
                break;
            }
            if rec.encode(out).is_err() {
                break;
            }
            a.mark_reported(now);
            n += 1;
        }
        n
    }

    /// Earliest scheduled report.
    pub fn next_report(&self) -> Option<Instant> {
        self.attributes
            .iter()
            .filter_map(crate::attribute::Attribute::next_report)
            .min_by_key(|t| t.as_millis())
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
        #[allow(clippy::cast_precision_loss)]
        DataType::Single => Value::Single(change as f32),
        #[allow(clippy::cast_precision_loss)]
        DataType::Double => Value::Double(change as f64),
        #[allow(clippy::cast_possible_truncation)]
        DataType::Semi => Value::Semi(change as u16),
        #[allow(clippy::cast_possible_truncation)]
        DataType::TimeOfDay | DataType::Date | DataType::UtcTime => Value::Time {
            ty,
            raw: change as u32,
        },
        _ => Value::NoData,
    }
}
