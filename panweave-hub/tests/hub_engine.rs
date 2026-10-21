//! Engine behaviour driven by injected stack events: address changes,
//! rejoins, registry and queue overflow, persistence, removal and the
//! permit-join window.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::model::{InterviewStatus, LeakState};
use panweave_hub::protocol::{ErrorCode, Event, Request, Response, SensorEvent};
use panweave_hub::registry::{MAX_DEVICES, zone_type};
use panweave_runtime::StackEvent;
use panweave_sim::Simulator;
use panweave_storage::{Key, Kind, Storage};
use panweave_types::time::Duration;
use panweave_types::{ExtendedAddress, MacCapability, ShortAddress};
use panweave_zcl::clusters::ias_zone::EnrollMode;

/// A hub on a formed network whose Trust Center does not require the
/// link-key exchange: these tests inject stack events for devices that do
/// not exist on the simulated radio (no key-pair entry, so a requiring
/// Trust Center would rightly refuse them). Authorization itself is
/// covered by `trust_center_policy.rs` in panweave-runtime and
/// `hub_security.rs` here.
fn engine_network() -> (Simulator, usize) {
    let (mut sim, c) = network();
    sim.stack(c).config.trust_center_policy.require_key_exchange = false;
    (sim, c)
}

/// Delivers `event` to the hub as if the stack had raised it.
fn inject(sim: &mut Simulator, c: usize, event: StackEvent) {
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    panweave_sim::App::on_event(app, stack, &event);
}

fn announce(ieee: u64, short: u16) -> StackEvent {
    StackEvent::DeviceAnnounce {
        ieee: ExtendedAddress(ieee),
        short: ShortAddress(short),
        capability: MacCapability::SLEEPY_END_DEVICE,
    }
}

fn joined_events(events: &[Event]) -> Vec<(u64, u16, bool)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::DeviceJoined {
                ieee,
                short,
                rejoin,
            } => Some((*ieee, *short, *rejoin)),
            _ => None,
        })
        .collect()
}

#[test]
fn nwk_address_changes_follow_the_ieee_address() {
    let (mut sim, c) = engine_network();
    inject(&mut sim, c, announce(0x1111, 0x1001));
    sim.run_for(Duration::from_secs(40));
    take_hub_events(&mut sim, c);
    // The same device announces itself at a new address (a rejoin after
    // an address conflict): same registry entry, new address.
    inject(&mut sim, c, announce(0x1111, 0x2002));
    let events = take_hub_events(&mut sim, c);
    assert_eq!(joined_events(&events), vec![(0x1111, 0x2002, true)]);
    let Response::DeviceList(l) = request(&mut sim, c, &Request::ListDevices { start: 0 }) else {
        panic!()
    };
    assert_eq!(l.total, 1);
    assert_eq!(l.devices[0].short, 0x2002);
    // Another device takes the old address: the first keeps its new one.
    inject(&mut sim, c, announce(0x2222, 0x1001));
    let Response::Device(d) = request(&mut sim, c, &Request::GetDevice { ieee: 0x1111 }) else {
        panic!()
    };
    assert_eq!(d.summary.short, 0x2002);
}

#[test]
fn a_device_that_left_is_unknown_until_it_rejoins() {
    let (mut sim, c) = engine_network();
    let s = join(
        &mut sim,
        c,
        "leak",
        zone_sensor(
            LEAK,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"leak",
        ),
        LEAK,
    );
    take_hub_events(&mut sim, c);
    inject(
        &mut sim,
        c,
        StackEvent::DeviceLeft {
            ieee: ExtendedAddress(LEAK),
            rejoin: false,
        },
    );
    let events = take_hub_events(&mut sim, c);
    assert!(events.contains(&Event::DeviceLeft { ieee: LEAK }));
    assert!(events.contains(&Event::Sensor {
        ieee: LEAK,
        event: SensorEvent::WaterLeakStateUnknown
    }));
    let Response::Device(d) = request(&mut sim, c, &Request::GetDevice { ieee: LEAK }) else {
        panic!()
    };
    assert!(!d.summary.present);
    assert_eq!(d.state.water_leak, LeakState::Unknown);
    // Commands to a device that left are refused, not queued.
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::ReadAttribute {
                ieee: LEAK,
                endpoint: 1,
                cluster: 0x0500,
                attribute: 2
            }
        ),
        Response::Error(ErrorCode::Unreachable)
    );
    // It comes back: a rejoin of a known device, its interview kept.
    sim.run_for(Duration::from_secs(40));
    let short = sim.stack_ref(s).short_address().0;
    inject(&mut sim, c, announce(LEAK, short));
    let events = take_hub_events(&mut sim, c);
    assert_eq!(joined_events(&events), vec![(LEAK, short, true)]);
    let Response::Device(d) = request(&mut sim, c, &Request::GetDevice { ieee: LEAK }) else {
        panic!()
    };
    assert!(d.summary.present);
    assert!(d.summary.interview.is_finished());
    // Its state is read again as soon as it is heard.
    wait_event(&mut sim, c, 60, |e| {
        matches!(
            e,
            Event::Sensor {
                ieee: LEAK,
                event: SensorEvent::WaterLeakCleared
            }
        )
    });
}

#[test]
fn registry_overflow_keeps_the_known_devices() {
    let (mut sim, c) = engine_network();
    for i in 0..MAX_DEVICES as u64 {
        inject(
            &mut sim,
            c,
            announce(0x1000 + i, 0x0100 + u16::try_from(i).unwrap()),
        );
    }
    take_hub_events(&mut sim, c);
    inject(&mut sim, c, announce(0x9999, 0x7777));
    let events = take_hub_events(&mut sim, c);
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::HubError {
                error: ErrorCode::RegistryFull,
                ..
            }
        )),
        "{events:?}"
    );
    assert!(joined_events(&events).is_empty());
    let Response::Diagnostics(d) = request(&mut sim, c, &Request::GetDiagnostics) else {
        panic!()
    };
    assert_eq!(usize::from(d.devices), MAX_DEVICES);
    assert_eq!(d.registry_full, 1);
    // Removing one (registry only) makes room.
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RemoveDevice {
                ieee: 0x1000,
                leave: false
            }
        ),
        Response::Done
    );
    inject(&mut sim, c, announce(0x9999, 0x7777));
    let events = take_hub_events(&mut sim, c);
    assert_eq!(joined_events(&events), vec![(0x9999, 0x7777, false)]);
}

#[test]
fn a_full_event_queue_reports_how_many_events_were_lost() {
    let (mut sim, c) = engine_network();
    take_hub_events(&mut sim, c);
    // Feed the hub directly, without draining its queue.
    {
        let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        for i in 0..40u64 {
            app.hub.on_stack_event(
                stack,
                &announce(0x5000 + i, 0x0200 + u16::try_from(i).unwrap()),
            );
        }
        assert!(app.hub.counters.events_dropped > 0);
        let dropped = app.hub.counters.events_dropped;
        let mut seen = Vec::new();
        while let Some(e) = app.hub.next_event() {
            seen.push(e);
        }
        let reported: u32 = seen
            .iter()
            .filter_map(|e| match e {
                Event::EventsDropped { count } => Some(u32::from(*count)),
                _ => None,
            })
            .sum();
        assert_eq!(reported, dropped, "every loss is reported: {seen:?}");
    }
}

#[test]
fn the_registry_survives_a_restart_and_bad_records_are_skipped() {
    let (mut sim, c) = engine_network();
    join(
        &mut sim,
        c,
        "leak",
        zone_sensor(
            LEAK,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"leak",
        ),
        LEAK,
    );
    inject(&mut sim, c, announce(0x7777, 0x4444));
    let mut storage = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.flush();
        app.hub.storage().clone()
    };
    // The second device's record is of a format this firmware does not
    // know (written by a newer one): skipped, left in place.
    let key = Key::with_id(Kind::Application, 0x7777);
    let mut buf = [0u8; 512];
    let n = storage.load(key, &mut buf).unwrap().unwrap();
    buf[0] = 99;
    storage.store(key, &buf[..n]).unwrap();
    let mut app = HubApp::new(storage);
    assert_eq!(app.hub.restore().unwrap(), 1);
    assert!(app.hub.registry().get(LEAK).is_some());
    assert!(app.hub.registry().get(0x7777).is_none());
    assert_eq!(
        app.hub.registry().get(LEAK).unwrap().interview.status,
        InterviewStatus::Complete
    );
    assert!(app.hub.next_event().is_some_and(|e| matches!(
        e,
        Event::HubError {
            error: ErrorCode::StorageFailure,
            detail: 1
        }
    )));
    let mut probe = [0u8; 512];
    assert!(
        app.hub
            .storage()
            .clone()
            .load(key, &mut probe)
            .unwrap()
            .is_some()
    );
}

#[test]
fn removal_from_the_registry_and_from_the_network() {
    let (mut sim, c) = engine_network();
    let b = join(&mut sim, c, "bulb", bulb(), BULB);
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RemoveDevice {
                ieee: 0x4242,
                leave: true
            }
        ),
        Response::Error(ErrorCode::UnknownDevice)
    );
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RemoveDevice {
                ieee: BULB,
                leave: true
            }
        ),
        Response::Done
    );
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(b)
            .iter()
            .any(|e| matches!(e, StackEvent::Left { .. }))
    }));
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    assert!(app.hub.registry().get(BULB).is_none());
    app.hub.flush();
    let mut probe = [0u8; 512];
    assert!(
        app.hub
            .storage()
            .clone()
            .load(Key::with_id(Kind::Application, BULB), &mut probe)
            .unwrap()
            .is_none()
    );
}

#[test]
fn the_permit_join_window_is_bounded_and_closes_the_trust_center() {
    let (mut sim, c) = engine_network();
    assert!(sim.stack(c).config.trust_center_policy.allow_joins);
    assert_eq!(
        request(&mut sim, c, &Request::PermitJoin { seconds: 0 }),
        Response::Error(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        request(&mut sim, c, &Request::PermitJoin { seconds: 255 }),
        Response::Error(ErrorCode::InvalidArgument)
    );
    assert_eq!(request(&mut sim, c, &Request::CloseNetwork), Response::Done);
    assert!(!sim.stack(c).config.trust_center_policy.allow_joins);
    assert_eq!(
        request(&mut sim, c, &Request::PermitJoin { seconds: 20 }),
        Response::Done
    );
    let Response::NetworkStatus(s) = request(&mut sim, c, &Request::GetNetworkStatus) else {
        panic!()
    };
    assert_eq!(s.permit_join_s, 20);
    take_hub_events(&mut sim, c);
    sim.run_for(Duration::from_secs(21));
    assert!(hub_events(&sim, c).contains(&Event::PermitJoinChanged { seconds: 0 }));
    // New devices are still admitted for the grace period, then not.
    assert!(sim.stack(c).config.trust_center_policy.allow_joins);
    sim.run_for(Duration::from_secs(31));
    assert!(!sim.stack(c).config.trust_center_policy.allow_joins);
}

#[test]
fn a_reset_sensor_that_rejoins_is_enrolled_again() {
    use panweave_types::Endpoint;
    use panweave_zcl::clusters::ias_zone;
    use panweave_zcl::{Role, Value};
    let (mut sim, c) = engine_network();
    let s = join(
        &mut sim,
        c,
        "leak",
        zone_sensor(
            LEAK,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"leak",
        ),
        LEAK,
    );
    // The sensor forgets its CIE and enrolment (a factory reset).
    {
        let cl = sim
            .stack(s)
            .zcl
            .cluster_mut(Endpoint(1), ias_zone::ID, Role::Server)
            .unwrap();
        cl.set(ias_zone::ZONE_STATE.id, &Value::Enum8(0));
        cl.set(ias_zone::IAS_CIE_ADDRESS.id, &Value::Eui64(0));
    }
    sim.run_for(Duration::from_secs(40));
    take_hub_events(&mut sim, c);
    let short = sim.stack_ref(s).short_address().0;
    inject(&mut sim, c, announce(LEAK, short));
    // The state read after the rejoin shows the zone unenrolled: the hub
    // enrols it again.
    wait_event(&mut sim, c, 120, |e| {
        matches!(e, Event::DeviceInterviewCompleted { ieee: LEAK, .. })
    });
    let srv = sim
        .stack(s)
        .zcl
        .cluster(Endpoint(1), ias_zone::ID, Role::Server)
        .unwrap();
    assert!(ias_zone::is_enrolled(srv));
    assert_eq!(ias_zone::cie_address(srv).map(|a| a.0), Some(HUB));
}
