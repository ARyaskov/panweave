//! ZCL helpers of the engine: request payloads, and the mapping of
//! attribute values onto the registry's device model.

use heapless::Vec;
use panweave_codec::Writer;
use panweave_zcl::Value;

use crate::model::{Flag, PowerSource};
use crate::protocol::{AttributeData, MAX_ATTRIBUTE, Text};
use crate::registry::{Device, cluster};

/// Basic attributes read by the interview, in two groups so that each
/// response fits the stack's 96-octet application frame even with long
/// strings.
pub(crate) const BASIC_GROUPS: [&[u16]; 2] = [&[0x0004, 0x0005], &[0x4000, 0x0007]];

/// IAS Zone attributes.
pub(crate) mod ias_attr {
    /// ZoneState.
    pub const ZONE_STATE: u16 = 0x0000;
    /// ZoneType.
    pub const ZONE_TYPE: u16 = 0x0001;
    /// ZoneStatus.
    pub const ZONE_STATUS: u16 = 0x0002;
    /// IAS_CIE_Address.
    pub const CIE_ADDRESS: u16 = 0x0010;
}

/// IAS Zone commands.
pub(crate) mod ias_cmd {
    /// Zone Status Change Notification (server → client).
    pub const STATUS_CHANGE: u8 = 0x00;
    /// Zone Enroll Request (server → client).
    pub const ENROLL_REQUEST: u8 = 0x01;
    /// Zone Enroll Response (client → server).
    pub const ENROLL_RESPONSE: u8 = 0x00;
}

/// Power Configuration attributes.
pub(crate) mod power_attr {
    /// BatteryVoltage (100 mV).
    pub const BATTERY_VOLTAGE: u16 = 0x0020;
    /// BatteryPercentageRemaining (half percent).
    pub const BATTERY_PERCENTAGE: u16 = 0x0021;
    /// BatteryAlarmState.
    pub const BATTERY_ALARM_STATE: u16 = 0x003e;
}

/// A Read Attributes payload.
pub(crate) fn read_payload(attributes: &[u16]) -> Vec<u8, 16> {
    let mut p = Vec::new();
    for a in attributes {
        let _ = p.extend_from_slice(&a.to_le_bytes());
    }
    p
}

/// A reporting configuration the interview installs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Report {
    pub attribute: u16,
    pub data_type: u8,
    pub min: u16,
    pub max: u16,
    /// Reportable change (analog types), little-endian in the type's
    /// width.
    pub change: Option<u32>,
}

/// The reporting the interview configures per cluster: state changes
/// promptly, batteries and measurements sparingly (every report wakes a
/// sleepy device's radio).
pub(crate) fn reports_of(cluster_id: u16) -> &'static [Report] {
    const ON_OFF: &[Report] = &[Report {
        attribute: 0x0000,
        data_type: 0x10,
        min: 0,
        max: 600,
        change: None,
    }];
    const LEVEL: &[Report] = &[Report {
        attribute: 0x0000,
        data_type: 0x20,
        min: 1,
        max: 600,
        change: Some(1),
    }];
    const POWER: &[Report] = &[
        Report {
            attribute: power_attr::BATTERY_PERCENTAGE,
            data_type: 0x20,
            min: 3600,
            max: 43_200,
            change: Some(2),
        },
        Report {
            attribute: power_attr::BATTERY_VOLTAGE,
            data_type: 0x20,
            min: 3600,
            max: 43_200,
            change: Some(1),
        },
    ];
    const TEMPERATURE: &[Report] = &[Report {
        attribute: 0x0000,
        data_type: 0x29,
        min: 30,
        max: 3600,
        change: Some(50),
    }];
    const HUMIDITY: &[Report] = &[Report {
        attribute: 0x0000,
        data_type: 0x21,
        min: 30,
        max: 3600,
        change: Some(100),
    }];
    const OCCUPANCY: &[Report] = &[Report {
        attribute: 0x0000,
        data_type: 0x18,
        min: 0,
        max: 3600,
        change: None,
    }];
    match cluster_id {
        cluster::ON_OFF => ON_OFF,
        cluster::LEVEL => LEVEL,
        cluster::POWER_CONFIGURATION => POWER,
        cluster::TEMPERATURE => TEMPERATURE,
        cluster::HUMIDITY => HUMIDITY,
        cluster::OCCUPANCY => OCCUPANCY,
        _ => &[],
    }
}

/// The attributes read for a device's current state per cluster.
pub(crate) fn state_attributes(cluster_id: u16) -> &'static [u16] {
    match cluster_id {
        cluster::ON_OFF | cluster::LEVEL | cluster::TEMPERATURE | cluster::HUMIDITY => &[0x0000],
        cluster::OCCUPANCY => &[0x0000],
        cluster::POWER_CONFIGURATION => &[
            power_attr::BATTERY_VOLTAGE,
            power_attr::BATTERY_PERCENTAGE,
            power_attr::BATTERY_ALARM_STATE,
        ],
        cluster::IAS_ZONE => &[ias_attr::ZONE_STATE, ias_attr::ZONE_STATUS],
        _ => &[],
    }
}

/// Clusters whose server state the hub tracks, in interview order.
pub(crate) const TRACKED: [u16; 7] = [
    cluster::ON_OFF,
    cluster::LEVEL,
    cluster::POWER_CONFIGURATION,
    cluster::TEMPERATURE,
    cluster::HUMIDITY,
    cluster::OCCUPANCY,
    cluster::IAS_ZONE,
];

/// A Configure Reporting payload for `reports`.
pub(crate) fn configure_payload(reports: &[Report]) -> Vec<u8, 48> {
    let mut p: Vec<u8, 48> = Vec::new();
    let _ = p.resize(48, 0);
    let mut w = Writer::new(&mut p);
    for r in reports {
        let width = analog_width(r.data_type);
        let ok = w.u8(0).is_ok()
            && w.u16_le(r.attribute).is_ok()
            && w.u8(r.data_type).is_ok()
            && w.u16_le(r.min).is_ok()
            && w.u16_le(r.max).is_ok();
        if !ok {
            break;
        }
        if let (Some(c), Some(width)) = (r.change, width) {
            let bytes = c.to_le_bytes();
            if w.bytes(bytes.get(..width).unwrap_or(&bytes)).is_err() {
                break;
            }
        }
    }
    let n = w.position();
    p.truncate(n);
    p
}

/// Width of an analog type's value (the reportable change field), or
/// `None` for discrete types (ZCL8 Table 2-11).
pub(crate) fn analog_width(data_type: u8) -> Option<usize> {
    match data_type {
        0x20..=0x23 => Some(usize::from(data_type - 0x1f)),
        0x28..=0x2b => Some(usize::from(data_type - 0x27)),
        0x38 => Some(2),
        0x39 => Some(4),
        _ => None,
    }
}

/// A value as protocol attribute data (long values are cut at
/// [`MAX_ATTRIBUTE`] octets).
pub(crate) fn attribute_data(v: &Value<'_>) -> AttributeData {
    let mut buf = [0u8; 128];
    let mut w = Writer::new(&mut buf);
    let n = if v.encode(&mut w).is_ok() {
        w.position()
    } else {
        0
    };
    let raw = buf.get(..n.min(MAX_ATTRIBUTE)).unwrap_or(&[]);
    AttributeData {
        data_type: v.data_type().id(),
        raw: Vec::from_slice(raw).unwrap_or_default(),
    }
}

/// What applying an attribute value did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Applied {
    /// The normalized state changed.
    State,
    /// Identity or interview data changed (the record is dirty).
    Identity,
    /// Nothing changed.
    Unchanged,
    /// An IAS `ZoneStatus`: interpreted by the caller.
    ZoneStatus(u16),
    /// The model does not cover the attribute.
    Unmapped,
}

fn text<const N: usize>(v: &Value<'_>) -> Option<Text<N>> {
    match v {
        Value::String { bytes: Some(b), .. } => {
            // Trailing NULs and spaces pad some devices' strings.
            let end = b
                .iter()
                .rposition(|c| *c != 0 && *c != b' ')
                .map_or(0, |i| i + 1);
            let b = b.get(..end).unwrap_or(&[]);
            Vec::from_slice(b.get(..N.min(b.len())).unwrap_or(&[])).ok()
        }
        _ => None,
    }
}

fn set<T: PartialEq>(slot: &mut T, v: T) -> bool {
    if *slot == v {
        false
    } else {
        *slot = v;
        true
    }
}

fn state(changed: bool) -> Applied {
    if changed {
        Applied::State
    } else {
        Applied::Unchanged
    }
}

fn identity(changed: bool) -> Applied {
    if changed {
        Applied::Identity
    } else {
        Applied::Unchanged
    }
}

/// Applies `attribute` = `v` of `cluster_id` to the device.
pub(crate) fn apply(d: &mut Device, cluster_id: u16, attribute: u16, v: &Value<'_>) -> Applied {
    match (cluster_id, attribute) {
        (cluster::BASIC, 0x0004) => match text(v) {
            Some(t) => identity(set(&mut d.manufacturer, t)),
            None => Applied::Unchanged,
        },
        (cluster::BASIC, 0x0005) => match text(v) {
            Some(t) => identity(set(&mut d.model, t)),
            None => Applied::Unchanged,
        },
        (cluster::BASIC, 0x4000) => match text(v) {
            Some(t) => identity(set(&mut d.sw_build, t)),
            None => Applied::Unchanged,
        },
        (cluster::BASIC, 0x0007) => match v.as_u64().and_then(|x| u8::try_from(x).ok()) {
            Some(p) => identity(set(&mut d.power_source, PowerSource::from_basic(p))),
            None => Applied::Unchanged,
        },
        (cluster::ON_OFF, 0x0000) => match v {
            Value::Bool(b) => state(set(&mut d.state.on, *b)),
            _ => Applied::Unchanged,
        },
        (cluster::LEVEL, 0x0000) => {
            let level = v
                .as_u64()
                .and_then(|x| u8::try_from(x).ok())
                .filter(|l| *l != 0xff);
            state(set(&mut d.state.level, level))
        }
        (cluster::POWER_CONFIGURATION, power_attr::BATTERY_VOLTAGE) => {
            let mv = v
                .as_u64()
                .filter(|x| *x != 0 && *x != 0xff)
                .and_then(|x| u16::try_from(x * 100).ok());
            state(set(&mut d.state.battery_mv, mv))
        }
        (cluster::POWER_CONFIGURATION, power_attr::BATTERY_PERCENTAGE) => {
            // Half-percent units, 0..=200; 0xFF means invalid and any other
            // value above 200 is out of range: neither is turned into a
            // percentage (none is derived from the voltage either).
            let pct = v
                .as_u64()
                .filter(|x| *x <= 200)
                .and_then(|x| u8::try_from(x.div_ceil(2)).ok());
            state(set(&mut d.state.battery_percent, pct))
        }
        (cluster::POWER_CONFIGURATION, power_attr::BATTERY_ALARM_STATE) => match v.as_u64() {
            // Bit 0: BatteryMinThreshold reached on battery source 1.
            Some(bits) => state(set(&mut d.state.battery_low, Flag::from_bit(bits & 1 != 0))),
            None => Applied::Unchanged,
        },
        (cluster::TEMPERATURE, 0x0000) => {
            let t = v
                .as_i64()
                .and_then(|x| i16::try_from(x).ok())
                .filter(|t| *t != i16::MIN);
            state(set(&mut d.state.temperature_centi, t))
        }
        (cluster::HUMIDITY, 0x0000) => {
            let h = v
                .as_u64()
                .and_then(|x| u16::try_from(x).ok())
                .filter(|h| *h != 0xffff);
            state(set(&mut d.state.humidity_centi, h))
        }
        (cluster::OCCUPANCY, 0x0000) => match v.as_u64() {
            Some(bits) => state(set(&mut d.state.motion, Flag::from_bit(bits & 1 != 0))),
            None => Applied::Unchanged,
        },
        (cluster::IAS_ZONE, ias_attr::ZONE_STATUS) => match v.as_u64() {
            Some(s) => Applied::ZoneStatus(u16::try_from(s).unwrap_or(0)),
            None => Applied::Unchanged,
        },
        (cluster::IAS_ZONE, ias_attr::ZONE_STATE) => {
            let enrolled = v.as_u64() == Some(1);
            match d.zone.as_mut() {
                Some(z) => identity(set(&mut z.enrolled, enrolled)),
                None => Applied::Unchanged,
            }
        }
        (cluster::IAS_ZONE, ias_attr::ZONE_TYPE) => {
            let t = v.as_u64().and_then(|x| u16::try_from(x).ok());
            match d.zone.as_mut() {
                Some(z) if t.is_some() => identity(set(&mut z.zone_type, t)),
                _ => Applied::Unchanged,
            }
        }
        (cluster::IAS_ZONE, ias_attr::CIE_ADDRESS) => {
            d.cie_address = v.as_u64();
            Applied::Unchanged
        }
        _ => Applied::Unmapped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_zcl::DataType;

    #[test]
    fn configure_payload_encodes_change_only_for_analog_types() {
        let p = configure_payload(reports_of(cluster::ON_OFF));
        assert_eq!(p.as_slice(), &[0, 0, 0, 0x10, 0, 0, 0x58, 0x02]);
        let p = configure_payload(reports_of(cluster::TEMPERATURE));
        assert_eq!(p.as_slice(), &[0, 0, 0, 0x29, 30, 0, 0x10, 0x0e, 50, 0]);
        assert_eq!(
            configure_payload(reports_of(cluster::POWER_CONFIGURATION)).len(),
            18
        );
        assert!(reports_of(cluster::IAS_ZONE).is_empty());
    }

    #[test]
    fn attribute_values_map_onto_the_state() {
        let mut d = Device::new(1, 2);
        assert_eq!(
            apply(&mut d, cluster::ON_OFF, 0, &Value::Bool(Some(true))),
            Applied::State
        );
        assert_eq!(
            apply(&mut d, cluster::ON_OFF, 0, &Value::Bool(Some(true))),
            Applied::Unchanged
        );
        assert_eq!(d.state.on, Some(true));
        let pct = Value::Uint {
            width: 1,
            value: 151,
        };
        apply(&mut d, cluster::POWER_CONFIGURATION, 0x21, &pct);
        assert_eq!(d.state.battery_percent, Some(76));
        let unknown = Value::Uint {
            width: 1,
            value: 0xff,
        };
        apply(&mut d, cluster::POWER_CONFIGURATION, 0x21, &unknown);
        assert_eq!(d.state.battery_percent, None);
        for (raw, pct) in [
            (0, Some(0)),
            (1, Some(1)),
            (200, Some(100)),
            (201, None),
            (254, None),
        ] {
            let v = Value::Uint {
                width: 1,
                value: raw,
            };
            apply(&mut d, cluster::POWER_CONFIGURATION, 0x21, &v);
            assert_eq!(d.state.battery_percent, pct, "raw {raw}");
        }
        let volts = Value::Uint {
            width: 1,
            value: 30,
        };
        apply(&mut d, cluster::POWER_CONFIGURATION, 0x20, &volts);
        assert_eq!(d.state.battery_mv, Some(3000));
        let t = Value::Int {
            width: 2,
            value: -1250,
        };
        apply(&mut d, cluster::TEMPERATURE, 0, &t);
        assert_eq!(d.state.temperature_centi, Some(-1250));
        let name = Value::String {
            ty: DataType::CharString,
            bytes: Some(b"Model\0\0"),
        };
        assert_eq!(apply(&mut d, cluster::BASIC, 5, &name), Applied::Identity);
        assert_eq!(d.model.as_slice(), b"Model");
        let status = Value::Bits {
            width: 2,
            bits: 0x0001,
        };
        assert_eq!(
            apply(&mut d, cluster::IAS_ZONE, 2, &status),
            Applied::ZoneStatus(1)
        );
        assert_eq!(
            apply(
                &mut d,
                0x0b04,
                0x0505,
                &Value::Uint {
                    width: 2,
                    value: 230
                }
            ),
            Applied::Unmapped
        );
        let data = attribute_data(&name);
        assert_eq!(data.data_type, 0x42);
        assert_eq!(data.raw.as_slice(), b"\x07Model\0\0");
    }
}
