//! `device <ieee> fingerprint [--json]`: a device's identifying values,
//! each labelled with where it comes from, for compatibility reports
//! (docs/device-compatibility.md).
//!
//! Provenance labels:
//!
//! * **Observed on hardware** — reported by the device over the air and
//!   stored by the hub this CLI is attached to (the CLI only talks to hub
//!   firmware over a serial port, so the device is a real one);
//! * **Documented externally** — from the hub's compatibility profile,
//!   which cites public documentation (`panweave_hub::compat`);
//! * **Derived from protocol semantics** — computed by the hub from
//!   observed values (category, capabilities, a profile's correction);
//! * **Unknown** — not reported (yet): never filled in from elsewhere.
//!
//! Identity strings are self-reported by the device and authenticate
//! nothing.

use std::fmt::Write as _;

use panweave_hub::compat;
use panweave_hub::model::{Ieee, PowerSource};
use panweave_hub::protocol::DeviceInfo;

use crate::json;

/// Where a value comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Provenance {
    Observed,
    Documented,
    Derived,
    Unknown,
}

impl Provenance {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Provenance::Observed => "Observed on hardware",
            Provenance::Documented => "Documented externally",
            Provenance::Derived => "Derived from protocol semantics",
            Provenance::Unknown => "Unknown",
        }
    }
}

/// One labelled value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Field {
    pub name: &'static str,
    pub value: Option<String>,
    pub provenance: Provenance,
}

/// Bytes as text, control characters escaped so that identifiers such
/// as `lumi.flood.agl02<TAB>F<0x01>` stay exact and printable.
fn exact(bytes: &[u8]) -> String {
    let mut s = String::new();
    for c in String::from_utf8_lossy(bytes).chars() {
        match c {
            '\t' => s.push_str("\\t"),
            '\\' => s.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(s, "\\x{:02x}", u32::from(c));
            }
            c => s.push(c),
        }
    }
    s
}

fn observed(name: &'static str, value: Option<String>) -> Field {
    Field {
        name,
        provenance: if value.is_some() {
            Provenance::Observed
        } else {
            Provenance::Unknown
        },
        value,
    }
}

fn non_empty(bytes: &[u8]) -> Option<String> {
    (!bytes.is_empty()).then(|| exact(bytes))
}

/// The labelled fingerprint of a device.
pub(crate) fn fields(d: &DeviceInfo) -> Vec<Field> {
    let s = &d.summary;
    let profile = compat::lookup(&d.manufacturer, &s.model);
    let mut out = vec![
        observed("ieee", Some(Ieee(s.ieee).to_string())),
        observed("network_address", Some(format!("{:#06x}", s.short))),
        observed("manufacturer_name", non_empty(&d.manufacturer)),
        observed("model_identifier", non_empty(&s.model)),
        observed("sw_build_id", non_empty(&d.sw_build)),
        observed(
            "manufacturer_code",
            d.manufacturer_code.map(|m| format!("{m:#06x}")),
        ),
        observed("logical_type", d.logical_type.map(|t| t.name().into())),
        observed("rx_on_when_idle", d.rx_on_when_idle.map(|r| r.to_string())),
    ];
    let corrected = profile.is_some_and(|p| p.corrections.battery_despite_mac_mains_flag)
        && d.power_source == PowerSource::Battery;
    out.push(Field {
        name: "power_source",
        value: (d.power_source != PowerSource::Unknown).then(|| d.power_source.name().into()),
        provenance: if d.power_source == PowerSource::Unknown {
            Provenance::Unknown
        } else if corrected {
            // The profile overrides the device's MAC mains claim.
            Provenance::Derived
        } else {
            Provenance::Observed
        },
    });
    if d.endpoints.is_empty() {
        out.push(observed("endpoint", None));
    }
    for e in &d.endpoints {
        let list = |l: &[u16]| {
            l.iter()
                .map(|c| format!("{c:#06x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        out.push(observed(
            "endpoint",
            Some(format!(
                "{} profile {:#06x} device {:#06x} in [{}] out [{}]",
                e.endpoint,
                e.profile,
                e.device_id,
                list(&e.inputs),
                list(&e.outputs)
            )),
        ));
    }
    out.push(observed(
        "ias_zone_type",
        d.zone
            .and_then(|z| z.zone_type)
            .map(|t| format!("{t:#06x}")),
    ));
    out.push(Field {
        name: "category",
        value: Some(s.category.name().into()),
        provenance: Provenance::Derived,
    });
    out.push(Field {
        name: "capabilities",
        value: Some(s.capabilities.names().collect::<Vec<_>>().join(", ")),
        provenance: Provenance::Derived,
    });
    out.push(Field {
        name: "interview",
        value: Some(s.interview.name().into()),
        provenance: Provenance::Derived,
    });
    match profile {
        Some(p) => {
            for (name, value) in [
                ("profile", p.id),
                ("vendor", p.vendor),
                ("commercial_model", p.commercial_model),
                ("profile_verification", p.verification.name()),
                ("profile_evidence", p.evidence),
            ] {
                out.push(Field {
                    name,
                    value: Some(value.split_whitespace().collect::<Vec<_>>().join(" ")),
                    provenance: Provenance::Documented,
                });
            }
            if p.corrections.battery_despite_mac_mains_flag {
                out.push(Field {
                    name: "correction",
                    value: Some("battery powered despite the MAC mains flag".into()),
                    provenance: Provenance::Documented,
                });
            }
        }
        None => out.push(Field {
            name: "profile",
            value: None,
            provenance: Provenance::Unknown,
        }),
    }
    out
}

/// Prints the fingerprint as text or as one JSON object.
pub(crate) fn print(d: &DeviceInfo, as_json: bool) {
    let f = fields(d);
    if as_json {
        let items: Vec<String> = f
            .iter()
            .map(|x| {
                json::Obj::new()
                    .str("name", x.name)
                    .opt_str("value", x.value.as_deref())
                    .str("provenance", x.provenance.label())
                    .finish()
            })
            .collect();
        println!(
            "{}",
            json::Obj::new()
                .str("ieee", &Ieee(d.summary.ieee).to_string())
                .raw("fields", &json::array(&items))
                .str(
                    "note",
                    "identity strings are self-reported and authenticate nothing"
                )
                .finish()
        );
        return;
    }
    for x in &f {
        println!(
            "{:<21} {:<48} [{}]",
            x.name,
            x.value.as_deref().unwrap_or("-"),
            x.provenance.label()
        );
    }
    if f.iter()
        .any(|x| x.name == "profile" && x.provenance == Provenance::Unknown)
    {
        println!("no compatibility profile: generic, standards-based handling");
    }
    println!("identity strings are self-reported and authenticate nothing");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use panweave_hub::model::{
        Capabilities, DeviceCategory, DeviceState, InterviewStage, InterviewStatus,
    };
    use panweave_hub::protocol::{DeviceSummary, EndpointDescriptor};

    fn device(manufacturer: &[u8], model: &[u8], power: PowerSource) -> DeviceInfo {
        let mut d = DeviceInfo {
            summary: DeviceSummary {
                ieee: 0x54EF_4410_0000_0001,
                short: 0x1234,
                category: DeviceCategory::default(),
                capabilities: Capabilities::default(),
                interview: InterviewStatus::default(),
                present: true,
                last_seen_s: None,
                model: heapless::Vec::new(),
            },
            manufacturer: heapless::Vec::new(),
            sw_build: heapless::Vec::new(),
            manufacturer_code: None,
            logical_type: None,
            rx_on_when_idle: Some(false),
            power_source: power,
            interview_stage: InterviewStage::default(),
            endpoints: heapless::Vec::new(),
            zone: None,
            lqi: None,
            state: DeviceState::default(),
        };
        d.manufacturer.extend_from_slice(manufacturer).unwrap();
        d.summary.model.extend_from_slice(model).unwrap();
        d
    }

    fn get<'a>(f: &'a [Field], name: &str) -> &'a Field {
        f.iter().find(|x| x.name == name).unwrap()
    }

    #[test]
    fn values_are_labelled_by_where_they_come_from() {
        let mut d = device(b"LUMI", b"lumi.flood.agl02\tF\x01", PowerSource::Battery);
        let mut ep = EndpointDescriptor {
            endpoint: 1,
            profile: 0x0104,
            device_id: 0x0402,
            ..Default::default()
        };
        ep.inputs.extend_from_slice(&[0x0000, 0x0500]).unwrap();
        d.endpoints.push(ep).unwrap();
        let f = fields(&d);
        let model = get(&f, "model_identifier");
        assert_eq!(model.value.as_deref(), Some("lumi.flood.agl02\\tF\\x01"));
        assert_eq!(model.provenance, Provenance::Observed);
        // Not reported: unknown, never guessed.
        assert_eq!(get(&f, "sw_build_id").provenance, Provenance::Unknown);
        assert_eq!(get(&f, "manufacturer_code").value, None);
        assert_eq!(get(&f, "ias_zone_type").provenance, Provenance::Unknown);
        // The Aqara profile's correction makes the power source derived.
        assert_eq!(get(&f, "power_source").provenance, Provenance::Derived);
        assert_eq!(
            get(&f, "profile").value.as_deref(),
            Some("aqara-water-leak-t1")
        );
        assert_eq!(get(&f, "profile").provenance, Provenance::Documented);
        assert_eq!(
            get(&f, "profile_verification").value.as_deref(),
            Some("documented-externally")
        );
        assert_eq!(get(&f, "category").provenance, Provenance::Derived);
        assert!(
            get(&f, "endpoint")
                .value
                .as_deref()
                .unwrap()
                .contains("in [0x0000 0x0500]")
        );
    }

    #[test]
    fn an_unknown_device_has_no_profile_and_observed_power() {
        let f = fields(&device(b"Acme", b"X1", PowerSource::Mains));
        assert_eq!(get(&f, "profile").provenance, Provenance::Unknown);
        assert_eq!(get(&f, "power_source").provenance, Provenance::Observed);
        assert_eq!(get(&f, "endpoint").provenance, Provenance::Unknown);
        let f = fields(&device(b"", b"", PowerSource::Unknown));
        assert_eq!(get(&f, "manufacturer_name").provenance, Provenance::Unknown);
        assert_eq!(get(&f, "power_source").value, None);
    }
}
