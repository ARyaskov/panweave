//! Smart Energy device descriptions (SE 1.4a §5.12, Table 5-13, §6):
//! the device identifiers of profile 0x0109 with the clusters each
//! device must or may carry (Tables 6-1 and 6-3 – 6-10). Clusters not
//! listed as mandatory or optional for a device are prohibited on its
//! endpoint (§6.3.x.1), except manufacturer-specific ones (§6.1.2).

use panweave_types::{ClusterId, DeviceId};

use crate::cluster as c;

/// Range Extender (generic).
pub const RANGE_EXTENDER: DeviceId = DeviceId(0x0008);
/// Energy Service Interface.
pub const ENERGY_SERVICE_INTERFACE: DeviceId = DeviceId(0x0500);
/// Metering Device.
pub const METERING_DEVICE: DeviceId = DeviceId(0x0501);
/// In-Home Display.
pub const IN_HOME_DISPLAY: DeviceId = DeviceId(0x0502);
/// Programmable Communicating Thermostat.
pub const PCT: DeviceId = DeviceId(0x0503);
/// Load Control Device.
pub const LOAD_CONTROL_DEVICE: DeviceId = DeviceId(0x0504);
/// Smart Appliance.
pub const SMART_APPLIANCE: DeviceId = DeviceId(0x0505);
/// Prepayment Terminal.
pub const PREPAYMENT_TERMINAL: DeviceId = DeviceId(0x0506);
/// Physical Device.
pub const PHYSICAL_DEVICE: DeviceId = DeviceId(0x0507);
/// Remote Communications Device.
pub const REMOTE_COMMUNICATIONS_DEVICE: DeviceId = DeviceId(0x0508);

/// Which side of a cluster.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Side {
    /// Server (input) cluster.
    Server,
    /// Client (output) cluster.
    Client,
}

/// A Smart Energy device description.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Device {
    /// Device identifier (Table 5-13).
    pub id: DeviceId,
    /// Name.
    pub name: &'static str,
    /// Defining section.
    pub section: &'static str,
    /// Mandatory server clusters beyond the common ones.
    pub servers: &'static [ClusterId],
    /// Mandatory client clusters beyond the common ones.
    pub clients: &'static [ClusterId],
    /// Optional server clusters.
    pub optional_servers: &'static [ClusterId],
    /// Optional client clusters.
    pub optional_clients: &'static [ClusterId],
    /// The device must carry at least one of its optional client
    /// clusters (In-Home Display, §6.3.3.1) or at least one Tunneling
    /// side (Remote Communications Device, §6.3.10.1).
    pub at_least_one_optional: bool,
}

/// Clusters common to all devices (Table 6-1).
pub mod common {
    use super::c;
    use panweave_types::ClusterId;

    /// Mandatory server clusters of every device.
    pub const SERVERS: &[ClusterId] = &[c::BASIC, c::KEY_ESTABLISHMENT];
    /// Mandatory client clusters of every device.
    pub const CLIENTS: &[ClusterId] = &[c::KEY_ESTABLISHMENT];
    /// Optional server clusters of every device.
    pub const OPTIONAL_SERVERS: &[ClusterId] = &[
        c::POWER_CONFIGURATION,
        c::COMMISSIONING,
        c::IDENTIFY,
        c::EVENTS,
        c::OTA_UPGRADE,
        c::KEEP_ALIVE,
    ];
    /// Optional client clusters of every device.
    pub const OPTIONAL_CLIENTS: &[ClusterId] = &[c::COMMISSIONING, c::OTA_UPGRADE, c::KEEP_ALIVE];
}

/// The devices of the profile, ascending by identifier.
pub const DEVICES: &[Device] = &[
    Device {
        id: RANGE_EXTENDER,
        name: "Range Extender",
        section: "§6.3.6",
        servers: &[],
        clients: &[],
        optional_servers: &[],
        optional_clients: &[],
        at_least_one_optional: false,
    },
    Device {
        id: ENERGY_SERVICE_INTERFACE,
        name: "Energy Service Interface",
        section: "§6.3.1",
        servers: &[
            c::MESSAGING,
            c::PRICE,
            c::DEMAND_RESPONSE_LOAD_CONTROL,
            c::TIME,
        ],
        clients: &[],
        optional_servers: &[
            c::CALENDAR,
            c::METERING,
            c::PREPAYMENT,
            c::DEVICE_MANAGEMENT,
            c::ALARMS,
            c::MDU_PAIRING,
            c::TUNNELING,
            c::SUB_GHZ,
        ],
        optional_clients: &[
            c::PRICE,
            c::METERING,
            c::PREPAYMENT,
            c::TIME,
            c::DEVICE_MANAGEMENT,
            c::EVENTS,
            c::MDU_PAIRING,
            c::ENERGY_MANAGEMENT,
            c::TUNNELING,
            c::SUB_GHZ,
        ],
        at_least_one_optional: false,
    },
    Device {
        id: METERING_DEVICE,
        name: "Metering Device",
        section: "§6.3.2",
        servers: &[c::METERING],
        clients: &[],
        optional_servers: &[c::PREPAYMENT, c::ALARMS, c::TUNNELING],
        optional_clients: &[
            c::TIME,
            c::PRICE,
            c::CALENDAR,
            c::MESSAGING,
            c::DEVICE_MANAGEMENT,
            c::MDU_PAIRING,
            c::SUB_GHZ,
            c::TUNNELING,
        ],
        at_least_one_optional: false,
    },
    Device {
        id: IN_HOME_DISPLAY,
        name: "In-Home Display",
        section: "§6.3.3",
        servers: &[],
        clients: &[],
        optional_servers: &[c::ALARMS, c::TUNNELING],
        optional_clients: &[
            c::DEMAND_RESPONSE_LOAD_CONTROL,
            c::TIME,
            c::PREPAYMENT,
            c::PRICE,
            c::CALENDAR,
            c::METERING,
            c::MESSAGING,
            c::DEVICE_MANAGEMENT,
            c::MDU_PAIRING,
            c::ENERGY_MANAGEMENT,
            c::EVENTS,
            c::SUB_GHZ,
            c::TUNNELING,
        ],
        at_least_one_optional: true,
    },
    Device {
        id: PCT,
        name: "Programmable Communicating Thermostat",
        section: "§6.3.4",
        servers: &[],
        clients: &[c::DEMAND_RESPONSE_LOAD_CONTROL, c::TIME],
        optional_servers: &[c::ENERGY_MANAGEMENT, c::ALARMS, c::TUNNELING],
        optional_clients: &[
            c::PREPAYMENT,
            c::PRICE,
            c::CALENDAR,
            c::METERING,
            c::MESSAGING,
            c::DEVICE_MANAGEMENT,
            c::MDU_PAIRING,
            c::SUB_GHZ,
            c::TUNNELING,
        ],
        at_least_one_optional: false,
    },
    Device {
        id: LOAD_CONTROL_DEVICE,
        name: "Load Control Device",
        section: "§6.3.5",
        servers: &[],
        clients: &[c::DEMAND_RESPONSE_LOAD_CONTROL, c::TIME],
        optional_servers: &[c::ENERGY_MANAGEMENT, c::ALARMS, c::TUNNELING],
        optional_clients: &[
            c::PRICE,
            c::CALENDAR,
            c::DEVICE_MANAGEMENT,
            c::MDU_PAIRING,
            c::SUB_GHZ,
            c::TUNNELING,
        ],
        at_least_one_optional: false,
    },
    Device {
        id: SMART_APPLIANCE,
        name: "Smart Appliance",
        section: "§6.3.7",
        servers: &[],
        clients: &[c::PRICE, c::TIME],
        optional_servers: &[c::ENERGY_MANAGEMENT, c::ALARMS, c::TUNNELING],
        optional_clients: &[
            c::DEMAND_RESPONSE_LOAD_CONTROL,
            c::MESSAGING,
            c::CALENDAR,
            c::DEVICE_MANAGEMENT,
            c::MDU_PAIRING,
            c::SUB_GHZ,
            c::TUNNELING,
        ],
        at_least_one_optional: false,
    },
    Device {
        id: PREPAYMENT_TERMINAL,
        name: "Prepayment Terminal",
        section: "§6.3.8",
        servers: &[c::PREPAYMENT],
        clients: &[c::PRICE, c::TIME, c::PREPAYMENT],
        optional_servers: &[c::ALARMS, c::TUNNELING],
        optional_clients: &[
            c::DEMAND_RESPONSE_LOAD_CONTROL,
            c::CALENDAR,
            c::METERING,
            c::MESSAGING,
            c::DEVICE_MANAGEMENT,
            c::MDU_PAIRING,
            c::ENERGY_MANAGEMENT,
            c::SUB_GHZ,
            c::TUNNELING,
        ],
        at_least_one_optional: false,
    },
    Device {
        id: PHYSICAL_DEVICE,
        name: "Physical Device",
        section: "§6.3.9",
        servers: &[],
        clients: &[],
        optional_servers: &[],
        optional_clients: &[],
        at_least_one_optional: false,
    },
    Device {
        id: REMOTE_COMMUNICATIONS_DEVICE,
        name: "Remote Communications Device",
        section: "§6.3.10",
        servers: &[],
        clients: &[],
        optional_servers: &[c::TUNNELING, c::TIME, c::SUB_GHZ],
        optional_clients: &[c::TUNNELING],
        at_least_one_optional: true,
    },
];

/// A conformance problem of an endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Problem {
    /// A mandatory cluster is missing.
    Missing(ClusterId, Side),
    /// A cluster the device neither mandates nor allows.
    Prohibited(ClusterId, Side),
    /// None of the required optional clusters is present.
    NoOptional,
}

impl Device {
    /// Looks a device up by identifier.
    pub fn lookup(id: DeviceId) -> Option<&'static Device> {
        DEVICES
            .binary_search_by_key(&id.0, |d| d.id.0)
            .ok()
            .and_then(|i| DEVICES.get(i))
    }

    /// Whether `cluster` may appear on the `side` of this device: a
    /// common, mandatory or optional cluster, or a manufacturer-specific
    /// one (0xFC00 and above).
    pub fn allows(&self, cluster: ClusterId, side: Side) -> bool {
        if cluster.0 >= 0xFC00 {
            return true;
        }
        let (mandatory, optional, cm, co) = match side {
            Side::Server => (
                self.servers,
                self.optional_servers,
                common::SERVERS,
                common::OPTIONAL_SERVERS,
            ),
            Side::Client => (
                self.clients,
                self.optional_clients,
                common::CLIENTS,
                common::OPTIONAL_CLIENTS,
            ),
        };
        mandatory.contains(&cluster)
            || optional.contains(&cluster)
            || cm.contains(&cluster)
            || co.contains(&cluster)
    }

    /// Checks an endpoint's cluster lists against the device
    /// description; writes the problems found to `out` and returns their
    /// number (which may exceed `out.len()`).
    pub fn check(
        &self,
        servers: &[ClusterId],
        clients: &[ClusterId],
        out: &mut [Problem],
    ) -> usize {
        let mut n = 0;
        let mut push = |p: Problem| {
            if let Some(slot) = out.get_mut(n) {
                *slot = p;
            }
            n += 1;
        };
        for c in common::SERVERS.iter().chain(self.servers) {
            if !servers.contains(c) {
                push(Problem::Missing(*c, Side::Server));
            }
        }
        for c in common::CLIENTS.iter().chain(self.clients) {
            if !clients.contains(c) {
                push(Problem::Missing(*c, Side::Client));
            }
        }
        for c in servers {
            if !self.allows(*c, Side::Server) {
                push(Problem::Prohibited(*c, Side::Server));
            }
        }
        for c in clients {
            if !self.allows(*c, Side::Client) {
                push(Problem::Prohibited(*c, Side::Client));
            }
        }
        if self.at_least_one_optional
            && !self.optional_clients.iter().any(|c| clients.contains(c))
            && !self.optional_servers.iter().any(|c| servers.contains(c))
        {
            push(Problem::NoOptional);
        }
        n
    }

    /// True when the endpoint conforms to the device description.
    pub fn conforms(&self, servers: &[ClusterId], clients: &[ClusterId]) -> bool {
        self.check(servers, clients, &mut []) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_table_and_checks() {
        assert!(DEVICES.windows(2).all(|w| w[0].id.0 < w[1].id.0));
        let ihd = Device::lookup(IN_HOME_DISPLAY).unwrap();
        let mut out = [Problem::NoOptional; 4];
        // Missing Key Establishment and no optional client.
        let n = ihd.check(&[c::BASIC], &[], &mut out);
        assert_eq!(n, 3);
        assert_eq!(out[0], Problem::Missing(c::KEY_ESTABLISHMENT, Side::Server));
        assert_eq!(out[1], Problem::Missing(c::KEY_ESTABLISHMENT, Side::Client));
        assert_eq!(out[2], Problem::NoOptional);
        assert!(ihd.conforms(
            &[c::BASIC, c::KEY_ESTABLISHMENT, c::IDENTIFY],
            &[
                c::KEY_ESTABLISHMENT,
                c::PRICE,
                c::MESSAGING,
                ClusterId(0xFC01)
            ]
        ));
        // A Price server is prohibited on an IHD.
        let n = ihd.check(
            &[c::BASIC, c::KEY_ESTABLISHMENT, c::PRICE],
            &[c::KEY_ESTABLISHMENT, c::PRICE],
            &mut out,
        );
        assert_eq!(n, 1);
        assert_eq!(out[0], Problem::Prohibited(c::PRICE, Side::Server));
        let esi = Device::lookup(ENERGY_SERVICE_INTERFACE).unwrap();
        assert!(esi.conforms(
            &[
                c::BASIC,
                c::KEY_ESTABLISHMENT,
                c::MESSAGING,
                c::PRICE,
                c::DEMAND_RESPONSE_LOAD_CONTROL,
                c::TIME,
                c::METERING
            ],
            &[c::KEY_ESTABLISHMENT]
        ));
        assert!(!esi.conforms(&[c::BASIC, c::KEY_ESTABLISHMENT], &[c::KEY_ESTABLISHMENT]));
        assert!(Device::lookup(DeviceId(0x0100)).is_none());
    }
}
