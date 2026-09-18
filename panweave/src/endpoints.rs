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
use panweave_device_library::{DeviceType, Side};
use panweave_types::{AttributeId, ClusterId, CommandId, DeviceId, Endpoint, ProfileId};
use panweave_zcl::clusters::configuration::{
    ballast, barrier_control, dehumidification, device_temperature, pump, shade,
    switch_configuration, thermostat_ui,
};
use panweave_zcl::clusters::hvac::{fan_control, thermostat};
use panweave_zcl::clusters::measurement::{
    flow, illuminance, illuminance_level, occupancy, pressure, temperature, water_content,
};
use panweave_zcl::clusters::{
    alarms, color_control, diagnostics, ias_zone, power_configuration, time,
};
use panweave_zcl::clusters::{
    commissioning, door_lock, electrical_measurement, ias_ace, ias_wd, window_covering,
};
use panweave_zcl::clusters::{groups, identify, keep_alive, level, on_off, poll_control, scenes};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::requirements::requirements;
use panweave_zcl::{ClusterDef, ClusterInstance, Role};
use panweave_zdo::descriptor::SimpleDescriptor;

/// An endpoint definition: descriptor plus cluster instances.
pub type Built = (SimpleDescriptor, EndpointInstance<12, 36>);

/// Clusters this crate can instantiate (server side).
const IMPLEMENTED_SERVERS: &[ClusterId] = &[
    ClusterId(0x0000),
    identify::ID,
    groups::ID,
    scenes::ID,
    on_off::ID,
    level::ID,
    level::PWM_ID,
    poll_control::ID,
    keep_alive::ID,
    illuminance::ID,
    temperature::ID,
    occupancy::ID,
    color_control::ID,
    diagnostics::ID,
    alarms::ID,
    time::ID,
    power_configuration::ID,
    ias_zone::ID,
    thermostat::ID,
    fan_control::ID,
    window_covering::ID,
    door_lock::ID,
    ias_ace::ID,
    ias_wd::ID,
    electrical_measurement::ID,
    commissioning::ID,
    device_temperature::ID,
    switch_configuration::ID,
    ballast::ID,
    pump::ID,
    dehumidification::ID,
    thermostat_ui::ID,
    shade::ID,
    barrier_control::ID,
    illuminance_level::ID,
    pressure::ID,
    flow::ID,
    water_content::RELATIVE_HUMIDITY,
];
/// Clusters this crate can instantiate (client side).
const IMPLEMENTED_CLIENTS: &[ClusterId] = &[
    identify::ID,
    groups::ID,
    scenes::ID,
    on_off::ID,
    level::ID,
    level::PWM_ID,
    poll_control::ID,
    keep_alive::ID,
    illuminance::ID,
    temperature::ID,
    occupancy::ID,
    color_control::ID,
    diagnostics::ID,
    alarms::ID,
    time::ID,
    power_configuration::ID,
    ias_zone::ID,
    thermostat::ID,
    fan_control::ID,
    window_covering::ID,
    door_lock::ID,
    ias_ace::ID,
    ias_wd::ID,
    electrical_measurement::ID,
    commissioning::ID,
    device_temperature::ID,
    switch_configuration::ID,
    ballast::ID,
    pump::ID,
    dehumidification::ID,
    thermostat_ui::ID,
    shade::ID,
    barrier_control::ID,
    illuminance_level::ID,
    pressure::ID,
    flow::ID,
    water_content::RELATIVE_HUMIDITY,
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
pub fn server(id: ClusterId) -> Option<ClusterInstance<36>> {
    match id {
        identify::ID => identify::server().ok(),
        groups::ID => groups::server().ok(),
        scenes::ID => scenes::server().ok(),
        on_off::ID => on_off::server().ok(),
        // Level Control for Lighting: 1…254 (§3.19).
        level::ID => level::lighting_server(1, 254).ok(),
        level::PWM_ID => level::pwm_server(0, 100, 0, 0).ok(),
        // Battery protection: check-ins at least every 30 s, long polls
        // of at least 1 s, fast polling for at most 2 minutes.
        poll_control::ID => poll_control::server(120, 4, 480).ok(),
        keep_alive::ID => keep_alive::server(
            keep_alive::DEFAULT_BASE_MINUTES,
            keep_alive::DEFAULT_JITTER_SECONDS,
        )
        .ok(),
        // Sensors: the full range of the value format until the product
        // narrows it; readings start unknown.
        illuminance::ID => illuminance::server(1, 0xfffe).ok(),
        temperature::ID => temperature::server(-27315, 32767).ok(),
        occupancy::ID => occupancy::server(occupancy::sensor_bits::PIR).ok(),
        // A full-colour lamp: hue / saturation, enhanced hue, colour
        // loop, XY and colour temperature over 2000 K – 6500 K.
        color_control::ID => color_control::server(
            color_control::capability::HUE_SATURATION
                | color_control::capability::ENHANCED_HUE
                | color_control::capability::COLOR_LOOP
                | color_control::capability::XY
                | color_control::capability::COLOR_TEMPERATURE,
            (153, 500),
        )
        .ok(),
        diagnostics::ID => diagnostics::server().ok(),
        alarms::ID => alarms::server().ok(),
        // Not a master clock (the network may set it), with the zone
        // attributes.
        time::ID => time::server(0, true).ok(),
        power_configuration::ID => power_configuration::battery_server(30).ok(),
        // A contact switch enrolling on the CIE's request.
        ias_zone::ID => ias_zone::server(
            ias_zone::zone_type::CONTACT_SWITCH,
            0,
            ias_zone::EnrollMode::AutoRequest,
            None,
        )
        .ok(),
        thermostat::ID => {
            // A dual thermostat with the weekly schedule extension:
            // weeks start on Monday, four transitions a day.
            let mut c = thermostat::server(thermostat::Capability::HeatingAndCooling).ok()?;
            thermostat::enable_weekly_schedule(&mut c, 1, 28, 4).ok()?;
            Some(c)
        }
        fan_control::ID => fan_control::server(fan_control::sequence::LOW_MED_HIGH_AUTO).ok(),
        window_covering::ID => window_covering::server(
            window_covering::covering_type::ROLLERSHADE,
            window_covering::Control::ClosedLoop {
                open: 0,
                closed: u16::MAX,
                encoder: false,
            },
            window_covering::Control::Unsupported,
        )
        .ok(),
        door_lock::ID => door_lock::server(door_lock::lock_type::DEAD_BOLT, 4, true).ok(),
        ias_ace::ID => Some(ias_ace::server(None)),
        ias_wd::ID => ias_wd::server(ias_wd::DEFAULT_MAX_DURATION).ok(),
        electrical_measurement::ID => {
            electrical_measurement::server(electrical_measurement::Capability::AC).ok()
        }
        commissioning::ID => commissioning::server(&commissioning::StartupSet::default()).ok(),
        // Internal temperature with the alarm thresholds (an Alarms
        // server accompanies it on devices that list one).
        device_temperature::ID => device_temperature::server(true).ok(),
        switch_configuration::ID => {
            switch_configuration::server(switch_configuration::switch_type::TOGGLE).ok()
        }
        // A single-lamp ballast dimming over its whole range.
        ballast::ID => ballast::server(1, 254, 1).ok(),
        pump::ID => pump::server(
            pump::Limits {
                max_pressure: 1000,
                max_speed: 3000,
                max_flow: 500,
            },
            0x3fff,
        )
        .ok(),
        dehumidification::ID => dehumidification::server().ok(),
        thermostat_ui::ID => thermostat_ui::server().ok(),
        shade::ID => shade::server(1000, 1).ok(),
        // A barrier that reports intermediate positions, 30 s of travel.
        barrier_control::ID => barrier_control::server(true, 300, 300).ok(),
        illuminance_level::ID => illuminance_level::server(0).ok(),
        pressure::ID => pressure::server(-32767, 32767).ok(),
        flow::ID => flow::server(0, 0xfffe).ok(),
        water_content::RELATIVE_HUMIDITY => water_content::server(
            water_content::RELATIVE_HUMIDITY,
            0,
            water_content::MAX_PERCENT,
        )
        .ok(),
        _ => None,
    }
}

/// A client instance of `id`, when implemented.
pub fn client(id: ClusterId) -> Option<ClusterInstance<36>> {
    match id {
        identify::ID => Some(identify::client()),
        groups::ID => Some(groups::client()),
        scenes::ID => Some(scenes::client()),
        on_off::ID => Some(on_off::client()),
        level::ID => Some(level::client()),
        level::PWM_ID => Some(ClusterInstance::new(level::PWM_DEF, Role::Client)),
        // Check-ins are answered without requesting fast polling; the
        // application changes the policy through the cluster state.
        poll_control::ID => Some(poll_control::client(false, 0)),
        keep_alive::ID => Some(keep_alive::client()),
        illuminance::ID => Some(illuminance::client()),
        temperature::ID => Some(temperature::client()),
        occupancy::ID => Some(occupancy::client()),
        color_control::ID => Some(color_control::client()),
        diagnostics::ID => Some(diagnostics::client()),
        alarms::ID => Some(alarms::client()),
        time::ID => Some(time::client()),
        power_configuration::ID => Some(power_configuration::client()),
        ias_zone::ID => Some(ias_zone::client()),
        thermostat::ID => Some(thermostat::client()),
        fan_control::ID => Some(fan_control::client()),
        window_covering::ID => Some(window_covering::client()),
        door_lock::ID => Some(door_lock::client()),
        ias_ace::ID => Some(ias_ace::client()),
        ias_wd::ID => Some(ias_wd::client()),
        electrical_measurement::ID => Some(electrical_measurement::client()),
        commissioning::ID => Some(commissioning::client()),
        device_temperature::ID => Some(device_temperature::client()),
        switch_configuration::ID => Some(switch_configuration::client()),
        ballast::ID => Some(ballast::client()),
        pump::ID => Some(pump::client()),
        dehumidification::ID => Some(dehumidification::client()),
        thermostat_ui::ID => Some(thermostat_ui::client()),
        shade::ID => Some(shade::client()),
        barrier_control::ID => Some(barrier_control::client()),
        illuminance_level::ID => Some(illuminance_level::client()),
        pressure::ID => Some(pressure::client()),
        flow::ID => Some(flow::client()),
        water_content::RELATIVE_HUMIDITY => {
            Some(water_content::client(water_content::RELATIVE_HUMIDITY))
        }
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

/// Color Dimmable Light (device 0x0102, DTL §23): the Dimmable Light plus
/// the Color Control server.
pub fn color_dimmable_light(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0102), &[], &[], false)
}

/// IAS Control and Indication Equipment (device 0x0400): the IAS ACE
/// server (no arm code) with IAS Zone and IAS WD clients.
pub fn ias_cie(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0400), &[], &[], false)
}

/// IAS Warning Device (device 0x0403): IAS Zone and IAS WD servers.
pub fn ias_warning_device(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0403), &[], &[], false)
}

/// Door Lock (device 0x000a): Identify, Groups, Scenes and a dead-bolt
/// Door Lock server with four PIN users.
pub fn door_lock_device(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x000a), &[], &[], false)
}

/// Window Covering (device 0x0202): Identify, Groups, Scenes and a
/// closed-loop rollershade server.
pub fn window_covering_device(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0202), &[], &[], false)
}

/// Thermostat (device 0x0301): Identify and Thermostat servers, the
/// latter with the weekly setpoint schedule.
pub fn thermostat_device(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0301), &[], &[], false)
}

/// Dimmable Ballast (device 0x0109): Power Configuration, Device
/// Temperature Configuration, Identify, Groups, Scenes, On/Off, Level
/// Control and Ballast Configuration servers.
pub fn dimmable_ballast(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0109), &[], &[], false)
}

/// On/Off Sensor (device 0x0850): the pump-controller sensor with
/// Pump Configuration, Illuminance Level Sensing and Pressure
/// Measurement servers beside the On/Off group.
pub fn on_off_sensor(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0850), &[], &[], false)
}

/// Light Sensor (device 0x0106): Identify and Illuminance Measurement
/// servers, Identify client.
pub fn light_sensor(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0106), &[], &[], false)
}

/// Occupancy Sensor (device 0x0107): Identify and Occupancy Sensing
/// servers, Identify client.
pub fn occupancy_sensor(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0107), &[], &[], false)
}

/// Temperature Sensor (device 0x0302): Identify and Temperature
/// Measurement servers, Identify client.
pub fn temperature_sensor(endpoint: Endpoint) -> Option<Built> {
    device(endpoint, DeviceId(0x0302), &[], &[], false)
}

/// Why an endpoint composition does not meet its device type's or its
/// clusters' requirements (DTL §2.3, ZCL "M/O" columns).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Deficiency {
    /// The descriptor's device identifier is not in the Device Type
    /// Library; only the clusters' requirements were checked.
    UnknownDeviceType(DeviceId),
    /// A mandatory cluster of the device type is not in the descriptor.
    MissingCluster {
        /// Cluster.
        cluster: ClusterId,
        /// Side.
        side: Side,
    },
    /// The descriptor declares a cluster the endpoint has no instance of
    /// (it would answer `UNSUPPORTED_CLUSTER`).
    NoInstance {
        /// Cluster.
        cluster: ClusterId,
        /// Side.
        side: Side,
    },
    /// A server instance lacks a mandatory attribute.
    MissingAttribute {
        /// Cluster.
        cluster: ClusterId,
        /// Attribute.
        attribute: AttributeId,
    },
    /// An instance does not receive a mandatory cluster-specific command.
    MissingCommand {
        /// Cluster.
        cluster: ClusterId,
        /// Side.
        side: Side,
        /// Command.
        command: CommandId,
    },
}

/// Deficiencies reported by [`validate`].
pub type Deficiencies = Vec<Deficiency, 32>;

/// Validates an endpoint composition: the descriptor's cluster lists
/// against the device type's mandatory clusters, and every declared
/// cluster against its instance's mandatory attributes and received
/// commands ([`panweave_zcl::requirements`]). The Basic server is exempt
/// from the instance check (the stack adds it). Clusters without known
/// requirements only need an instance. At most 32 deficiencies are kept.
pub fn validate(desc: &SimpleDescriptor, ep: &EndpointInstance<12, 36>) -> Deficiencies {
    let mut out = Deficiencies::new();
    match DeviceType::lookup(desc.device) {
        Some(dt) => {
            let mut missing = [(ClusterId(0), Side::Server); 32];
            let n = dt.missing(&desc.input_clusters, &desc.output_clusters, &mut missing);
            for (cluster, side) in missing.iter().take(n) {
                let _ = out.push(Deficiency::MissingCluster {
                    cluster: *cluster,
                    side: *side,
                });
            }
        }
        None => {
            let _ = out.push(Deficiency::UnknownDeviceType(desc.device));
        }
    }
    for cluster in &desc.input_clusters {
        let Some(inst) = ep.cluster(*cluster, Role::Server) else {
            if *cluster != ClusterId(0x0000) {
                let _ = out.push(Deficiency::NoInstance {
                    cluster: *cluster,
                    side: Side::Server,
                });
            }
            continue;
        };
        let Some(req) = requirements(*cluster) else {
            continue;
        };
        for attribute in req.server_attributes {
            if inst.attributes.get(*attribute, None).is_none() {
                let _ = out.push(Deficiency::MissingAttribute {
                    cluster: *cluster,
                    attribute: *attribute,
                });
            }
        }
        check_commands(&mut out, *cluster, Side::Server, inst, req.server_commands);
    }
    for cluster in &desc.output_clusters {
        let Some(inst) = ep.cluster(*cluster, Role::Client) else {
            let _ = out.push(Deficiency::NoInstance {
                cluster: *cluster,
                side: Side::Client,
            });
            continue;
        };
        if let Some(req) = requirements(*cluster) {
            check_commands(&mut out, *cluster, Side::Client, inst, req.client_commands);
        }
    }
    out
}

fn check_commands(
    out: &mut Deficiencies,
    cluster: ClusterId,
    side: Side,
    inst: &ClusterInstance<36>,
    required: &[CommandId],
) {
    for command in required {
        if !inst.def.received.contains(command) {
            let _ = out.push(Deficiency::MissingCommand {
                cluster,
                side,
                command: *command,
            });
        }
    }
}

/// Definition of a cluster instance for custom endpoints.
pub fn custom_cluster(def: ClusterDef, role: Role) -> ClusterInstance<36> {
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
        assert!(unsupported_clusters(color).is_empty());
        let (d, ep) = color_dimmable_light(Endpoint(4)).unwrap();
        assert!(d.has_input(color_control::ID) && d.has_input(level::ID));
        assert!(ep.cluster(color_control::ID, Role::Server).is_some());
        type Builder = fn(Endpoint) -> Option<Built>;
        let sensors: [(Builder, u16, ClusterId); 10] = [
            (dimmable_ballast, 0x0109, ballast::ID),
            (on_off_sensor, 0x0850, pump::ID),
            (light_sensor, 0x0106, illuminance::ID),
            (occupancy_sensor, 0x0107, occupancy::ID),
            (temperature_sensor, 0x0302, temperature::ID),
            (thermostat_device, 0x0301, thermostat::ID),
            (window_covering_device, 0x0202, window_covering::ID),
            (door_lock_device, 0x000a, door_lock::ID),
            (ias_cie, 0x0400, ias_ace::ID),
            (ias_warning_device, 0x0403, ias_wd::ID),
        ];
        for (build, id, cluster) in sensors {
            let (d, ep) = build(Endpoint(5)).unwrap();
            assert_eq!(d.device, DeviceId(id));
            assert!(d.has_input(cluster));
            assert!(ep.cluster(cluster, Role::Server).is_some());
            assert!(unsupported_clusters(DeviceType::lookup(DeviceId(id)).unwrap()).is_empty());
        }
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

    #[test]
    fn every_buildable_device_type_validates() {
        for dt in &panweave_device_library::DEVICES {
            if !unsupported_clusters(dt).is_empty() {
                continue;
            }
            let (d, ep) = device(Endpoint(1), dt.id, &[], &[], false).unwrap();
            let found = validate(&d, &ep);
            assert!(found.is_empty(), "{} ({:?}): {:?}", dt.name, dt.id, found);
        }
    }

    #[test]
    fn validation_reports_deficiencies() {
        // A light whose descriptor forgot Groups and whose On/Off server
        // lost its OnOff attribute and Toggle command.
        let (mut d, mut ep) = on_off_light(Endpoint(1)).unwrap();
        d.input_clusters.retain(|c| *c != groups::ID);
        ep.clusters.retain(|c| c.def.id != on_off::ID);
        let def = ClusterDef {
            received: &[CommandId(0x00), CommandId(0x01)],
            ..on_off::DEF
        };
        ep.add_instance(ClusterInstance::new(def, Role::Server))
            .unwrap();
        let found = validate(&d, &ep);
        assert!(found.contains(&Deficiency::MissingCluster {
            cluster: groups::ID,
            side: Side::Server
        }));
        assert!(found.contains(&Deficiency::MissingAttribute {
            cluster: on_off::ID,
            attribute: on_off::ON_OFF.id
        }));
        assert!(found.contains(&Deficiency::MissingCommand {
            cluster: on_off::ID,
            side: Side::Server,
            command: CommandId(0x02)
        }));
        assert_eq!(found.len(), 3);
        // A declared cluster without an instance, and a client lacking a
        // mandatory response.
        let (mut d, mut ep) = on_off_light_switch(Endpoint(2)).unwrap();
        d.input_clusters.push(level::ID).unwrap();
        let inst = ep.cluster_mut(identify::ID, Role::Client).unwrap();
        inst.def = ClusterDef {
            received: &[],
            ..inst.def
        };
        let found = validate(&d, &ep);
        assert!(found.contains(&Deficiency::NoInstance {
            cluster: level::ID,
            side: Side::Server
        }));
        assert!(found.contains(&Deficiency::MissingCommand {
            cluster: identify::ID,
            side: Side::Client,
            command: CommandId(0x00)
        }));
        assert_eq!(found.len(), 2);
        // An unknown device type: clusters are still checked.
        let (mut d, ep) = on_off_light(Endpoint(3)).unwrap();
        d.device = DeviceId(0xEEEE);
        assert_eq!(
            validate(&d, &ep).as_slice(),
            &[Deficiency::UnknownDeviceType(DeviceId(0xEEEE))]
        );
    }
}
