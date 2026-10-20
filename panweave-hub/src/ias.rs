//! IAS Zone status interpretation (ZCL8 §8.2).
//!
//! The meaning of `Alarm1` and `Alarm2` depends on the zone type (ZCL8
//! Table 8-5): for a Contact Switch `Alarm1` is the first portal being
//! open, for a Water Sensor `Alarm1` is water and `Alarm2` is not defined,
//! for a Motion Sensor `Alarm1` is intrusion and `Alarm2` presence. The
//! hub normalizes the primary condition of the zone types it knows and
//! leaves the others raw. `Tamper`, `Battery`, `Trouble` and `Battery
//! defect` mean the same for every zone type (Table 8-6). While the `Test`
//! bit is set the alarm bits report a test, not the environment, and are
//! not interpreted.
//!
//! A device whose firmware deviates from the table can be given an
//! [`AlarmOverride`] — only on evidence (a capture of its frames), never
//! by guessing from a product description. [`OVERRIDES`] is empty: no
//! deviation has been observed on hardware yet.

use crate::model::{ContactState, Flag, LeakState};
use crate::registry::zone_type;

/// `ZoneStatus` bits (ZCL8 Table 8-6).
pub mod status {
    /// Alarm1.
    pub const ALARM1: u16 = 1 << 0;
    /// Alarm2.
    pub const ALARM2: u16 = 1 << 1;
    /// Tamper.
    pub const TAMPER: u16 = 1 << 2;
    /// Battery low.
    pub const BATTERY: u16 = 1 << 3;
    /// Trouble / failure.
    pub const TROUBLE: u16 = 1 << 6;
    /// Test mode.
    pub const TEST: u16 = 1 << 8;
    /// Battery defect.
    pub const BATTERY_DEFECT: u16 = 1 << 9;
}

/// The condition a zone's alarm bits report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Primary {
    /// A contact: set = open.
    Contact,
    /// A water sensor: set = water.
    WaterLeak,
    /// A motion sensor: set = motion.
    Motion,
}

/// Which bits of `ZoneStatus` carry the primary condition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlarmMap {
    /// The condition.
    pub primary: Primary,
    /// The bits: the condition is present when any of them is set.
    pub mask: u16,
}

/// An evidence-based deviation of one device model from Table 8-5.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlarmOverride {
    /// Basic `ManufacturerName`, exactly.
    pub manufacturer: &'static [u8],
    /// Basic `ModelIdentifier`, exactly.
    pub model: &'static [u8],
    /// The map to use instead of the zone type's.
    pub map: AlarmMap,
}

/// Overrides confirmed on hardware. Empty until a device is captured
/// deviating from the standard.
pub const OVERRIDES: &[AlarmOverride] = &[];

/// The standard map of a zone type (ZCL8 Table 8-5), for the zone types
/// whose primary condition the hub normalizes.
pub const fn standard_map(zone_type: u16) -> Option<AlarmMap> {
    let primary = match zone_type {
        zone_type::CONTACT_SWITCH => Primary::Contact,
        zone_type::WATER_SENSOR => Primary::WaterLeak,
        zone_type::MOTION_SENSOR => Primary::Motion,
        _ => return None,
    };
    Some(AlarmMap {
        primary,
        mask: status::ALARM1,
    })
}

/// The map for a device: an override matching its manufacturer and
/// model in `overrides`, else the standard map of its zone type.
pub fn alarm_map(
    zone_type: Option<u16>,
    manufacturer: &[u8],
    model: &[u8],
    overrides: &[AlarmOverride],
) -> Option<AlarmMap> {
    overrides
        .iter()
        .find(|o| o.manufacturer == manufacturer && o.model == model)
        .map(|o| o.map)
        .or_else(|| zone_type.and_then(standard_map))
}

/// What a `ZoneStatus` says. `None` fields carry no information (a zone
/// type without that condition, or the test mode).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ZoneReading {
    /// Contact state.
    pub contact: Option<ContactState>,
    /// Water state.
    pub water_leak: Option<LeakState>,
    /// Motion.
    pub motion: Option<Flag>,
    /// Tamper.
    pub tamper: Flag,
    /// Low battery.
    pub battery_low: Flag,
    /// Trouble, or a battery defect.
    pub trouble: Flag,
    /// The zone is in test mode.
    pub test: bool,
}

/// Interprets `status` with `map`.
pub fn interpret(map: Option<AlarmMap>, status: u16) -> ZoneReading {
    let test = status & status::TEST != 0;
    let mut reading = ZoneReading {
        contact: None,
        water_leak: None,
        motion: None,
        tamper: Flag::from_bit(status & status::TAMPER != 0),
        battery_low: Flag::from_bit(status & status::BATTERY != 0),
        trouble: Flag::from_bit(status & (status::TROUBLE | status::BATTERY_DEFECT) != 0),
        test,
    };
    if let Some(m) = map
        && !test
    {
        let set = status & m.mask != 0;
        match m.primary {
            Primary::Contact => {
                reading.contact = Some(if set {
                    ContactState::Open
                } else {
                    ContactState::Closed
                });
            }
            Primary::WaterLeak => {
                reading.water_leak = Some(if set { LeakState::Leak } else { LeakState::Dry });
            }
            Primary::Motion => reading.motion = Some(Flag::from_bit(set)),
        }
    }
    reading
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alarm_bits_mean_what_the_zone_type_says() {
        let water = standard_map(zone_type::WATER_SENSOR);
        let r = interpret(water, status::ALARM1);
        assert_eq!(r.water_leak, Some(LeakState::Leak));
        assert_eq!(r.contact, None);
        // Alarm2 is not defined for a water sensor: no water.
        let r = interpret(water, status::ALARM2);
        assert_eq!(r.water_leak, Some(LeakState::Dry));

        let contact = standard_map(zone_type::CONTACT_SWITCH);
        assert_eq!(
            interpret(contact, status::ALARM1).contact,
            Some(ContactState::Open)
        );
        assert_eq!(interpret(contact, 0).contact, Some(ContactState::Closed));
        assert_eq!(interpret(contact, 0).water_leak, None);

        // A fire sensor's alarm is not normalized.
        let fire = standard_map(0x0028);
        assert_eq!(fire, None);
        let r = interpret(fire, status::ALARM1 | status::TAMPER);
        assert_eq!((r.contact, r.water_leak, r.motion), (None, None, None));
        assert_eq!(r.tamper, Flag::Set);
    }

    #[test]
    fn generic_bits_and_test_mode() {
        let contact = standard_map(zone_type::CONTACT_SWITCH);
        let r = interpret(contact, status::BATTERY | status::BATTERY_DEFECT);
        assert_eq!(r.battery_low, Flag::Set);
        assert_eq!(r.trouble, Flag::Set);
        assert_eq!(r.tamper, Flag::Clear);
        let r = interpret(contact, status::TEST | status::ALARM1);
        assert!(r.test);
        assert_eq!(r.contact, None, "a test alarm is not a door opening");
    }

    #[test]
    fn overrides_need_an_exact_match() {
        const QUIRK: AlarmOverride = AlarmOverride {
            manufacturer: b"Example",
            model: b"leak-1",
            map: AlarmMap {
                primary: Primary::WaterLeak,
                mask: status::ALARM2,
            },
        };
        let m = alarm_map(
            Some(zone_type::WATER_SENSOR),
            b"Example",
            b"leak-1",
            &[QUIRK],
        );
        assert_eq!(
            interpret(m, status::ALARM2).water_leak,
            Some(LeakState::Leak)
        );
        let m = alarm_map(
            Some(zone_type::WATER_SENSOR),
            b"Example",
            b"leak-2",
            &[QUIRK],
        );
        assert_eq!(m, standard_map(zone_type::WATER_SENSOR));
        assert!(OVERRIDES.is_empty());
    }
}
