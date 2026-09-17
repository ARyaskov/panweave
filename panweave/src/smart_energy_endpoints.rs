//! Ready-made Smart Energy endpoints (SE 1.4a Table 5-13, §6.3): each
//! builder assembles the common clusters of Table 6-1 (Basic and Key
//! Establishment server, Key Establishment client), the device's
//! mandatory clusters and any optional ones the caller asks for, on the
//! Smart Energy profile. Profile clusters come from
//! `panweave_smart_energy::endpoints`, general ones from
//! [`crate::endpoints`]; the result is checked against the device's
//! cluster rules before it is returned.

use heapless::Vec;
use panweave_smart_energy::cluster as c;
use panweave_smart_energy::devices::{self, Device, common};
use panweave_smart_energy::endpoints as se;
use panweave_types::{ClusterId, DeviceId, Endpoint, ProfileId};
use panweave_zcl::ClusterInstance;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

use crate::endpoints::{self, Built};

/// Why an endpoint could not be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuildError {
    /// Not a Smart Energy device identifier.
    UnknownDevice,
    /// A requested cluster is not allowed on the device (Table 6-3 …
    /// 6-10), or the device's at-least-one rule is unmet.
    NotConforming,
    /// A mandatory or requested cluster cannot be instantiated.
    Unimplemented(ClusterId),
    /// Too many clusters for the endpoint or descriptor.
    Full,
}

fn server_instance(id: ClusterId) -> Result<ClusterInstance<24>, BuildError> {
    if let Some(r) = se::server(id) {
        return r.map_err(|_| BuildError::Full);
    }
    endpoints::server(id).ok_or(BuildError::Unimplemented(id))
}

fn client_instance(id: ClusterId) -> Result<ClusterInstance<24>, BuildError> {
    if let Some(r) = se::client(id) {
        return r.map_err(|_| BuildError::Full);
    }
    endpoints::client(id).ok_or(BuildError::Unimplemented(id))
}

/// Builds a Smart Energy device endpoint: the common clusters, the
/// device's mandatory clusters and `optional_servers` /
/// `optional_clients` (which must be optional clusters of the device or
/// of Table 6-1).
pub fn device(
    endpoint: Endpoint,
    id: DeviceId,
    optional_servers: &[ClusterId],
    optional_clients: &[ClusterId],
) -> Result<Built, BuildError> {
    let dt = Device::lookup(id).ok_or(BuildError::UnknownDevice)?;
    let mut servers: Vec<ClusterId, 16> = Vec::new();
    let mut clients: Vec<ClusterId, 16> = Vec::new();
    let mut ep = EndpointInstance::new(endpoint, ProfileId::SMART_ENERGY);
    for c in common::SERVERS
        .iter()
        .chain(dt.servers)
        .chain(optional_servers)
    {
        if servers.contains(c) {
            continue;
        }
        servers.push(*c).map_err(|_| BuildError::Full)?;
        if *c == c::BASIC {
            // Added by the stack from its configuration.
            continue;
        }
        ep.add_instance(server_instance(*c)?)
            .map_err(|_| BuildError::Full)?;
    }
    for c in common::CLIENTS
        .iter()
        .chain(dt.clients)
        .chain(optional_clients)
    {
        if clients.contains(c) {
            continue;
        }
        clients.push(*c).map_err(|_| BuildError::Full)?;
        ep.add_instance(client_instance(*c)?)
            .map_err(|_| BuildError::Full)?;
    }
    if !dt.conforms(&servers, &clients) {
        return Err(BuildError::NotConforming);
    }
    let desc = SimpleDescriptor::new(endpoint, ProfileId::SMART_ENERGY, id, 1, &servers, &clients)
        .ok_or(BuildError::Full)?;
    Ok((desc, ep))
}

/// Energy Service Interface (0x0500, §6.3.1): Messaging, Price, DRLC
/// and Time servers plus the common clusters.
pub fn energy_service_interface(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::ENERGY_SERVICE_INTERFACE, &[], &[])
}

/// Metering Device (0x0501, §6.3.2): the Metering server.
pub fn metering_device(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::METERING_DEVICE, &[], &[])
}

/// In-Home Display (0x0502, §6.3.3) with the given client clusters (at
/// least one of Price, DRLC, Metering, Messaging … is required).
pub fn in_home_display(endpoint: Endpoint, clients: &[ClusterId]) -> Result<Built, BuildError> {
    device(endpoint, devices::IN_HOME_DISPLAY, &[], clients)
}

/// Programmable Communicating Thermostat (0x0503, §6.3.4).
pub fn programmable_communicating_thermostat(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::PCT, &[], &[])
}

/// Load Control Device (0x0504, §6.3.5).
pub fn load_control_device(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::LOAD_CONTROL_DEVICE, &[], &[])
}

/// Range Extender (0x0008, §6.3.6): the common clusters only.
pub fn range_extender(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::RANGE_EXTENDER, &[], &[])
}

/// Smart Appliance (0x0505, §6.3.7).
pub fn smart_appliance(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::SMART_APPLIANCE, &[], &[])
}

/// Prepayment Terminal (0x0506, §6.3.8).
pub fn prepayment_terminal(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::PREPAYMENT_TERMINAL, &[], &[])
}

/// Physical Device (0x0507, §6.3.9): the common clusters of a physical
/// device hosting other logical devices.
pub fn physical_device(endpoint: Endpoint) -> Result<Built, BuildError> {
    device(endpoint, devices::PHYSICAL_DEVICE, &[], &[])
}

/// Remote Communications Device (0x0508, §6.3.10) with a Tunneling
/// server, client or both.
pub fn remote_communications_device(
    endpoint: Endpoint,
    tunneling_server: bool,
    tunneling_client: bool,
) -> Result<Built, BuildError> {
    let t = [c::TUNNELING];
    device(
        endpoint,
        devices::REMOTE_COMMUNICATIONS_DEVICE,
        if tunneling_server { &t } else { &[] },
        if tunneling_client { &t } else { &[] },
    )
}
