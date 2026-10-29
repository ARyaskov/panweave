//! Lite sensors (the `SleepySensor` stack profile) commissioned and
//! interviewed by the full Panweave hub (`FullStack` coordinator) in the
//! same binary, over the simulator's medium. These say nothing about
//! commercial hubs or certification.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::model::{
    Capabilities, ContactState, DeviceCategory, InterviewStatus, LeakState, LogicalType,
    PowerSource,
};
use panweave_hub::protocol::{Event, Request, Response, SensorEvent};
use panweave_lite::sensor::{Inputs, SensorKind};
use panweave_lite::{Delivery, LiteEvent, SENSOR_ENDPOINT};
use panweave_storage::{Key, Kind};
use panweave_types::time::Duration;
use panweave_zcl::Role;
use panweave_zcl::clusters::ias_zone;

fn device(
    sim: &mut panweave_sim::Simulator,
    c: usize,
    ieee: u64,
) -> panweave_hub::protocol::DeviceInfo {
    match request(sim, c, &Request::GetDevice { ieee }) {
        Response::Device(d) => d,
        r => panic!("{r:?}"),
    }
}

fn sensor_events(events: &[Event], ieee: u64) -> Vec<SensorEvent> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Sensor { ieee: i, event } if *i == ieee => Some(*event),
            _ => None,
        })
        .collect()
}

#[test]
fn water_leak_sensor_joins_is_interviewed_enrolled_and_reports() {
    let (mut sim, c) = hub_network();
    let d = join_hub(
        &mut sim,
        c,
        "leak",
        sensor_config(LEAK, SensorKind::WaterLeak, b"lite-leak"),
    );
    let info = device(&mut sim, c, LEAK);
    // Interview: descriptors and Basic (the 'static strings).
    assert_eq!(
        info.summary.interview,
        InterviewStatus::Complete,
        "{info:?}"
    );
    assert_eq!(info.summary.category, DeviceCategory::WaterLeakSensor);
    assert_eq!(info.summary.model.as_slice(), b"lite-leak");
    assert_eq!(info.manufacturer.as_slice(), b"Lite Sim");
    assert_eq!(info.logical_type, Some(LogicalType::EndDevice));
    assert_eq!(info.rx_on_when_idle, Some(false));
    assert_eq!(info.power_source, PowerSource::Battery);
    assert_eq!(info.endpoints.len(), 1);
    assert_eq!(info.endpoints[0].device_id, 0x0402);
    assert!(info.endpoints[0].inputs.contains(&0x0500));
    assert!(info.summary.capabilities.contains(
        Capabilities::IAS_ZONE | Capabilities::WATER_LEAK | Capabilities::POWER_CONFIGURATION
    ));
    // Enrolment, and the enrolment record persisted.
    assert!(info.zone.unwrap().enrolled);
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        lite(x, d)
            .events
            .iter()
            .any(|e| matches!(e, LiteEvent::Enrolled { .. }))
    }));
    assert!(
        lite(&sim, d)
            .store
            .has(Key::with_id(Kind::Application, 0x0500))
    );
    assert_eq!(info.state.water_leak, LeakState::Dry);
    take_hub_events(&mut sim, c);

    // Water: notified at once (no waiting for a routine report) and
    // acknowledged.
    set_inputs(&mut sim, d, wet());
    wait_hub(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::WaterLeakDetected,
                ..
            }
        )
    });
    wait_confirmed(&mut sim, d, 30);
    // Dry again.
    set_inputs(&mut sim, d, dry());
    wait_hub(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::WaterLeakCleared,
                ..
            }
        )
    });
    wait_confirmed(&mut sim, d, 30);
    // Tamper and low battery bits are interpreted by the hub.
    set_inputs(
        &mut sim,
        d,
        Inputs {
            alarm: false,
            tamper: true,
            low_battery: true,
        },
    );
    wait_hub(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::TamperDetected,
                ..
            }
        )
    });
    wait_hub(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::BatteryLow,
                ..
            }
        )
    });
    let events = take_hub_events(&mut sim, c);
    let leaks = sensor_events(&events, LEAK);
    assert_eq!(
        leaks
            .iter()
            .filter(|e| **e == SensorEvent::WaterLeakDetected)
            .count(),
        1,
        "{events:?}"
    );
}

#[test]
fn contact_sensor_reports_open_and_closed() {
    let (mut sim, c) = hub_network();
    let mut cfg = sensor_config(DOOR, SensorKind::Contact, b"lite-door");
    cfg.sensor.poll_control = false;
    let d = join_hub(&mut sim, c, "door", cfg);
    let info = device(&mut sim, c, DOOR);
    assert_eq!(info.summary.category, DeviceCategory::ContactSensor);
    assert!(info.summary.capabilities.contains(Capabilities::CONTACT));
    assert!(info.zone.unwrap().enrolled, "{info:?}");
    assert_eq!(info.state.contact, ContactState::Closed);
    take_hub_events(&mut sim, c);
    set_inputs(&mut sim, d, wet());
    wait_hub(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                ieee: DOOR,
                event: SensorEvent::ContactOpened
            }
        )
    });
    set_inputs(&mut sim, d, dry());
    wait_hub(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                ieee: DOOR,
                event: SensorEvent::ContactClosed
            }
        )
    });
    wait_confirmed(&mut sim, d, 30);
    assert_eq!(
        device(&mut sim, c, DOOR).state.contact,
        ContactState::Closed
    );
}

#[test]
fn an_alarm_raised_while_the_hub_is_unreachable_is_delivered_before_its_clear() {
    let (mut sim, c) = hub_network();
    let d = join_hub(
        &mut sim,
        c,
        "leak",
        sensor_config(LEAK, SensorKind::WaterLeak, b"lite-leak"),
    );
    wait_confirmed(&mut sim, d, 30);
    take_hub_events(&mut sim, c);
    let radio = sim.device_radio(d);
    let hub_radio = sim.node_radio(c);
    sim.medium.block(radio, hub_radio);
    // Water, then dry, while the link is down.
    set_inputs(&mut sim, d, wet());
    sim.run_for(Duration::from_secs(3));
    set_inputs(&mut sim, d, dry());
    sim.run_for(Duration::from_secs(5));
    assert!(matches!(
        lite(&sim, d).dev.delivery(),
        Delivery::Pending { .. }
    ));
    // The undelivered alarm is held: the published status still says
    // water; it is not turned into "dry" by the failure.
    let srv = lite(&sim, d)
        .dev
        .stack
        .zcl
        .cluster(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
        .unwrap();
    assert_eq!(
        ias_zone::status(srv) & ias_zone::zone_status::ALARM1,
        ias_zone::zone_status::ALARM1
    );
    assert!(
        lite(&sim, d)
            .events
            .iter()
            .any(|e| matches!(e, LiteEvent::Delivery(Delivery::Pending { .. })))
    );
    // The link returns (possibly through a rejoin): first the leak,
    // then the clear.
    sim.medium.unblock(radio, hub_radio);
    assert!(
        sim.run_until(Duration::from_secs(120), |x| {
            let ev = sensor_events(hub_events(x, c), LEAK);
            ev.contains(&SensorEvent::WaterLeakDetected)
                && ev.contains(&SensorEvent::WaterLeakCleared)
        }),
        "hub: {:?} lite: {:?}",
        hub_events(&sim, c),
        lite(&sim, d).events
    );
    let ev = sensor_events(hub_events(&sim, c), LEAK);
    let detected = ev
        .iter()
        .position(|e| *e == SensorEvent::WaterLeakDetected)
        .unwrap();
    let cleared = ev
        .iter()
        .position(|e| *e == SensorEvent::WaterLeakCleared)
        .unwrap();
    assert!(detected < cleared, "{ev:?}");
    wait_confirmed(&mut sim, d, 60);
}

#[test]
fn enrolment_and_network_survive_a_power_cycle() {
    let (mut sim, c) = hub_network();
    let d = join_hub(
        &mut sim,
        c,
        "leak",
        sensor_config(LEAK, SensorKind::WaterLeak, b"lite-leak"),
    );
    wait_confirmed(&mut sim, d, 30);
    take_hub_events(&mut sim, c);
    // Power loss: RAM gone.
    lite_mut(&mut sim, d).powered = false;
    sim.run_for(Duration::from_secs(2));
    let now = sim.clock.now();
    // Restart with water present: the device restores its network and
    // enrolment, rejoins, and reports to the same CIE without a new
    // enrolment.
    lite_mut(&mut sim, d).power_cycle(wet(), now);
    sim.settle();
    assert!(
        sim.run_until(Duration::from_secs(120), |x| sensor_events(
            hub_events(x, c),
            LEAK
        )
        .contains(&SensorEvent::WaterLeakDetected)),
        "hub: {:?} lite: {:?}",
        hub_events(&sim, c),
        lite(&sim, d).events
    );
    let srv = lite(&sim, d)
        .dev
        .stack
        .zcl
        .cluster(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
        .unwrap();
    assert!(ias_zone::is_enrolled(srv));
    assert!(
        lite(&sim, d)
            .events
            .iter()
            .any(|e| matches!(e, LiteEvent::Joined { rejoin: true, .. })),
        "{:?}",
        lite(&sim, d).events
    );
    wait_confirmed(&mut sim, d, 30);
}
