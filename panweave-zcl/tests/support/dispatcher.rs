//! Shared stateful dispatcher harness for property tests and libFuzzer.
//!
//! The first byte selects a server; subsequent records contain control,
//! length (zero means 256), and frame bytes. A selected server shares its
//! endpoint with Groups, On/Off and Level Control where distinct, keeping
//! cross-cluster operations reachable without allocating every server.

use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::GroupTable;
use panweave_types::capacity::Cap;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, Endpoint, ExtendedAddress, GroupAddress, ProfileId, ShortAddress};
use panweave_zcl::cluster::ClusterInstance;
use panweave_zcl::clusters::appliance::{control, events_alerts, statistics};
use panweave_zcl::clusters::configuration::barrier_control;
use panweave_zcl::clusters::hvac::thermostat;
use panweave_zcl::clusters::{
    alarms, basic, color_control, commissioning, direct_configuration, door_lock, groups, ias_ace,
    ias_wd, ias_zone, identify, level, on_off, poll_control, power_profile, rssi_location, scenes,
    time, window_covering,
};
use panweave_zcl::layer::{EndpointInstance, Zcl, ZclEvent};

/// Servers whose command or timer semantics execute inside the dispatcher.
pub const CLUSTERS: [ClusterId; 24] = [
    basic::ID,
    identify::ID,
    groups::ID,
    scenes::ID,
    on_off::ID,
    level::ID,
    poll_control::ID,
    color_control::ID,
    thermostat::ID,
    window_covering::ID,
    door_lock::ID,
    alarms::ID,
    time::ID,
    ias_zone::ID,
    ias_ace::ID,
    ias_wd::ID,
    commissioning::ID,
    barrier_control::ID,
    control::ID,
    power_profile::ID,
    rssi_location::ID,
    direct_configuration::ID,
    events_alerts::ID,
    statistics::ID,
];

fn server(index: usize) -> ClusterInstance<64> {
    match index {
        0 => basic::server(1, b"test", b"test").unwrap(),
        1 => identify::server().unwrap(),
        2 => groups::server().unwrap(),
        3 => scenes::server().unwrap(),
        4 => on_off::server().unwrap(),
        5 => level::server(1, 254).unwrap(),
        6 => poll_control::server(2, 4, 480).unwrap(),
        7 => color_control::server(0x1f, (153, 500)).unwrap(),
        8 => {
            let mut cluster =
                thermostat::server(thermostat::Capability::HeatingAndCooling).unwrap();
            thermostat::enable_weekly_schedule(&mut cluster, 0, 28, 10).unwrap();
            cluster
        }
        9 => window_covering::server(
            window_covering::covering_type::ROLLERSHADE,
            window_covering::Control::ClosedLoop {
                open: 0,
                closed: 100,
                encoder: true,
            },
            window_covering::Control::OpenLoop,
        )
        .unwrap(),
        10 => door_lock::server(0, 4, true).unwrap(),
        11 => alarms::server().unwrap(),
        12 => time::server(0, true).unwrap(),
        13 => ias_zone::server(
            ias_zone::zone_type::CONTACT_SWITCH,
            1,
            ias_zone::EnrollMode::TripToPair,
            Some(2),
        )
        .unwrap(),
        14 => ias_ace::server(None),
        15 => ias_wd::server(300).unwrap(),
        16 => commissioning::server(&commissioning::StartupSet::default()).unwrap(),
        17 => barrier_control::server(true, 100, 100).unwrap(),
        18 => control::server(true).unwrap(),
        19 => power_profile::server(1, true, true).unwrap(),
        20 => rssi_location::server(ExtendedAddress(1), 0).unwrap(),
        21 => direct_configuration::server(true, 30, true).unwrap(),
        22 => events_alerts::server(),
        _ => statistics::server().unwrap(),
    }
}

/// Drives one server and related clusters, returning its id, processed
/// frame count, largest frame length and accepted schedule count so
/// regression tests can verify that long commands reach execution.
pub fn drive(data: &[u8]) -> (ClusterId, usize, usize, usize) {
    let (selector, mut remaining) = data
        .split_first()
        .map_or((0, &[][..]), |(s, rest)| (*s, rest));
    let index = usize::from(selector) % CLUSTERS.len();
    let selected = server(index);
    let selected_id = selected.def.id;
    let mut zcl: Zcl<1, 4, 64> = Zcl::new();
    let mut endpoint = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    endpoint.add_instance(selected).unwrap();
    for companion in [groups::ID, on_off::ID, level::ID] {
        if companion != selected_id {
            let instance = match companion {
                groups::ID => groups::server().unwrap(),
                on_off::ID => on_off::server().unwrap(),
                _ => level::server(1, 254).unwrap(),
            };
            endpoint.add_instance(instance).unwrap();
        }
    }
    zcl.add_endpoint(endpoint).unwrap();
    let mut group_table = GroupTable::<Cap<4>>::new();
    group_table.add(GroupAddress(1), Endpoint(1)).unwrap();
    let mut now = Instant::from_millis(1000);
    zcl.poll_timers(now);
    let mut frames = 0;
    let mut max_length = 0;
    let mut schedules = 0;
    while let Some((&control, tail)) = remaining.split_first() {
        let Some((&length, bytes)) = tail.split_first() else {
            break;
        };
        let wanted = if length == 0 {
            256
        } else {
            usize::from(length)
        };
        let length = wanted.min(bytes.len());
        let frame = &bytes[..length];
        remaining = &bytes[length..];
        let cluster = match control & 0x03 {
            0 | 1 => selected_id,
            2 => on_off::ID,
            _ => level::ID,
        };
        let delivery = match (control >> 2) & 0x03 {
            0 => Delivery::Endpoint(Endpoint(1)),
            1 => Delivery::Group(GroupAddress(1)),
            2 => Delivery::AllEndpoints,
            _ => Delivery::Endpoint(Endpoint(7)),
        };
        let indication = DataIndication {
            src: ShortAddress(if control & 0x40 != 0 { 0 } else { 0x1234 }),
            src_endpoint: Endpoint(5),
            src_ieee: Some(ExtendedAddress(1)),
            delivery,
            profile: ProfileId::HOME_AUTOMATION,
            cluster,
            asdu: frame,
            security: if control & 0x10 != 0 {
                SecurityStatus::LinkKey
            } else {
                SecurityStatus::NwkKey
            },
            lqi: 200,
            relayed: None,
            counter: 0,
            nwk_broadcast: control & 0x20 != 0,
        };
        let _ = zcl.on_data(&indication, &mut group_table);
        frames += 1;
        max_length = max_length.max(length);
        while zcl.next_action().is_some() {}
        while let Some(event) = zcl.next_event() {
            if matches!(event, ZclEvent::WeeklyScheduleChanged { .. }) {
                schedules += 1;
            }
        }
        now += Duration::from_millis(u64::from(control >> 6) * 100 + 1);
        zcl.poll_timers(now);
        let _ = zcl.next_deadline();
    }
    for _ in 0..64 {
        now += Duration::from_millis(250);
        zcl.poll_timers(now);
        while zcl.next_action().is_some() {}
        while zcl.next_event().is_some() {}
    }
    (selected_id, frames, max_length, schedules)
}
