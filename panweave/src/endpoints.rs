//! Ready-made endpoints for the device types whose mandatory clusters
//! are implemented by `panweave-zcl`. Each builder returns the simple
//! descriptor and the cluster instances; the Basic cluster is added by
//! the stack from its configuration when absent.
//!
//! Device types needing clusters this version does not implement (for
//! example the Color Control server of a Color Dimmable Light, DTL §23)
//! are reported by [`unsupported_clusters`] rather than silently
//! declared.

use heapless::Vec;
use panweave_device_library::DeviceType;
use panweave_types::{ClusterId, DeviceId, Endpoint, ProfileId};
use panweave_zcl::clusters::{groups, identify, keep_alive, level, on_off, poll_control, scenes};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::{ClusterDef, ClusterInstance, Role};
use panweave_zdo::descriptor::SimpleDescriptor;

/// An endpoint definition: descriptor plus cluster instances.
pub type Built = (SimpleDescriptor, EndpointInstance<8, 16>);

/// Clusters this crate can instantiate (server side).
const IMPLEMENTED_SERVERS: &[ClusterId] = &[
    ClusterId(0x0000),
    identify::ID,
    groups::ID,
    scenes::ID,
    on_off::ID,
    level::ID,
    poll_control::ID,
    keep_alive::ID,
];
/// Clusters this crate can instantiate (client side).
const IMPLEMENTED_CLIENTS: &[ClusterId] = &[
    identify::ID,
    groups::ID,
    scenes::ID,
    on_off::ID,
    level::ID,
    poll_control::ID,
    keep_alive::ID,
];

/// Mandatory clusters of `device` that cannot be instantiated yet
/// (server clusters first).
pub fn unsupported_clusters(device: &DeviceType) -> Vec<ClusterId, 16> {
    let mut out = Vec::new();
    for c in device.servers {
        if !IMPLEMENTED_SERVERS.contains(c) {
            let _ = out.push(*c);
        }
    }
    for c in device.clients {
        if !IMPLEMENTED_CLIENTS.contains(c) {
            let _ = out.push(*c);
        }
    }
    out
}

/// A server instance of `id` with its defaults, when implemented.
pub fn server(id: ClusterId) -> Option<ClusterInstance<16>> {
    match id {
        identify::ID => identify::server().ok(),
        groups::ID => groups::server().ok(),
        scenes::ID => scenes::server().ok(),
        on_off::ID => on_off::server().ok(),
        level::ID => level::server(1, 254).ok(),
        // Battery protection: check-ins at least every 30 s, long polls
        // of at least 1 s, fast polling for at most 2 minutes.
        poll_control::ID => poll_control::server(120, 4, 480).ok(),
        keep_alive::ID => keep_alive::server(
            keep_alive::DEFAULT_BASE_MINUTES,
            keep_alive::DEFAULT_JITTER_SECONDS,
        )
        .ok(),
        _ => None,
    }
}

/// A client instance of `id`, when implemented.
pub fn client(id: ClusterId) -> Option<ClusterInstance<16>> {
    match id {
        identify::ID => Some(identify::client()),
        groups::ID => Some(groups::client()),
        scenes::ID => Some(scenes::client()),
        on_off::ID => Some(on_off::client()),
        level::ID => Some(level::client()),
        // Check-ins are answered without requesting fast polling; the
        // application changes the policy through the cluster state.
        poll_control::ID => Some(poll_control::client(false, 0)),
        keep_alive::ID => Some(keep_alive::client()),
        _ => None,
    }
}

/// Builds an endpoint for a library device type from its mandatory
/// clusters plus `extra_servers` / `extra_clients`. Clusters without an
/// implementation are declared in the descriptor only when listed in
/// `declare_unimplemented` (they then answer `UNSUPPORTED_CLUSTER`).
/// Fails when the device type is unknown or the lists overflow.
pub fn device(
    endpoint: Endpoint,
    device: DeviceId,
    extra_servers: &[ClusterId],
    extra_clients: &[ClusterId],
    declare_unimplemented: bool,
) -> Option<Built> {
    let dt = DeviceType::lookup(device)?;
    let mut servers: Vec<ClusterId, 16> = Vec::new();
    let mut clients: Vec<ClusterId, 16> = Vec::new();
    let mut ep = EndpointInstance::new(endpoint, ProfileId::HOME_AUTOMATION);
    for c in dt.servers.iter().chain(extra_servers) {
        if servers.contains(c) {
            continue;
        }
        if *c == ClusterId(0x0000) {
            // Basic: added by the stack.
            servers.push(*c).ok()?;
            continue;
        }
        match server(*c) {
            Some(inst) => {
                ep.add_instance(inst).ok()?;
                servers.push(*c).ok()?;
            }
            None if declare_unimplemented => servers.push(*c).ok()?,
            None => {}
        }
    }
    for c in dt.clients.iter().chain(extra_clients) {
        if clients.contains(c) {
            continue;
        }
        match client(*c) {
            Some(inst) => {
                ep.add_instance(inst).ok()?;
                clients.push(*c).ok()?;
            }
            None if declare_unimplemented => clients.push(*c).ok()?,
            None => {}
        }
    }
    let desc = SimpleDescriptor::new(
        endpoint,
        ProfileId::HOME_AUTOMATION,
        device,
        1,
        &servers,
        &clients,
    )?;
    Some((desc, ep))
}

/// On/Off Light (device 0x0100, DTL §21): Identify, Groups, Scenes and
/// On/Off servers.
pub fn on_off_light(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0100), &[], &[], false)
}

/// Dimmable Light (device 0x0101, DTL §22): the On/Off Light plus the
/// Level Control server.
pub fn dimmable_light(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0101), &[], &[], false)
}

/// On/Off Light Switch (device 0x0103, DTL §24): Identify server, Identify
/// and On/Off clients.
pub fn on_off_light_switch(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0103), &[], &[], false)
}

/// Dimmer Switch (device 0x0104, DTL §25): Identify server; Identify,
/// On/Off and Level Control clients.
pub fn dimmer_switch(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0104), &[], &[], false)
}

/// The Trust Center's utility endpoint (BDB 3.1 §6.4): Keep-Alive server
/// and Poll Control client on a Configuration Tool (device 0x0005, DTL
/// §8) endpoint.
pub fn trust_center_utility(endpoint: Endpoint) -> Option<Built> {
    device(
        endpoint,
        DeviceId(0x0005),
        &[keep_alive::ID],
        &[poll_control::ID],
        false,
    )
}

/// A sleepy end device's utility clusters: adds the Poll Control server
/// to an endpoint built here.
pub fn with_poll_control((desc, mut ep): Built) -> Option<Built> {
    ep.add_instance(server(poll_control::ID)?).ok()?;
    let mut servers = desc.input_clusters.clone();
    servers.push(poll_control::ID).ok()?;
    let desc = SimpleDescriptor::new(
        desc.endpoint,
        desc.profile,
        desc.device,
        desc.device_version,
        &servers,
        &desc.output_clusters,
    )?;
    Some((desc, ep))
}

/// On/Off Switch (device 0x0000, DTL §4).
pub fn on_off_switch(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0000), &[], &[], false)
}

/// Definition of a cluster instance for custom endpoints.
pub fn custom_cluster(def: ClusterDef, role: Role) -> ClusterInstance<16> {
    ClusterInstance::new(def, role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn light_and_switch_endpoints() {
        let (d, ep) = on_off_light(Endpoint(1)).unwrap();
        assert_eq!(d.device, DeviceId(0x0100));
        assert!(d.has_input(on_off::ID));
        assert!(d.has_input(groups::ID));
        assert!(d.has_input(scenes::ID));
        assert!(ep.cluster(on_off::ID, Role::Server).is_some());
        assert!(ep.cluster(scenes::ID, Role::Server).is_some());
        let (d, ep) = on_off_light_switch(Endpoint(2)).unwrap();
        assert!(d.has_output(on_off::ID));
        assert!(ep.cluster(on_off::ID, Role::Client).is_some());
        assert!(ep.cluster(identify::ID, Role::Client).is_some());
        let light = DeviceType::lookup(DeviceId(0x0100)).unwrap();
        assert!(unsupported_clusters(light).is_empty());
        let color = DeviceType::lookup(DeviceId(0x0102)).unwrap();
        assert_eq!(unsupported_clusters(color).as_slice(), &[ClusterId(0x0300)]);
        let (d, ep) = dimmable_light(Endpoint(3)).unwrap();
        assert!(d.has_input(level::ID));
        assert!(ep.cluster(level::ID, Role::Server).is_some());
        let (d, ep) = with_poll_control(dimmer_switch(Endpoint(4)).unwrap()).unwrap();
        assert!(d.has_output(level::ID));
        assert!(d.has_input(poll_control::ID));
        assert!(ep.cluster(poll_control::ID, Role::Server).is_some());
        let (d, ep) = trust_center_utility(Endpoint(5)).unwrap();
        assert!(d.has_input(keep_alive::ID));
        assert!(d.has_output(poll_control::ID));
        assert!(ep.cluster(keep_alive::ID, Role::Server).is_some());
        assert!(device(Endpoint(1), DeviceId(0xEEEE), &[], &[], false).is_none());
    }
}
