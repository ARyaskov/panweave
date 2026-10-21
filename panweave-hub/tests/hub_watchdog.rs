//! The watchdog supervisor (`panweave_hub::supervisor`) fed from the real
//! stack, in virtual time: healthy networks — idle, sleepy, busy with
//! diagnostics, capture, flash writes, a vanished host — never lead to a
//! reset decision. (The ESP32-C6 hardware watchdog itself is not part of
//! this test; see docs/esp32c6-hardware-testing.md.)

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::protocol::{Request, Response};
use panweave_hub::registry::zone_type;
use panweave_hub::supervisor::{Health, HealthSupervisor, Observation, Supervision};
use panweave_sim::Simulator;
use panweave_types::time::Duration;
use panweave_zcl::clusters::ias_zone::EnrollMode;

/// What the firmware would observe of the coordinator after a loop turn
/// (the simulator has no radio driver: completed transmissions are the
/// MAC's, faults none).
fn observe(sim: &mut Simulator, c: usize) -> Observation {
    let s = sim.stack(c);
    let mac = s.mac.stats;
    let now = s.now();
    Observation {
        now_ms: now.as_millis(),
        tx_completed: mac.tx_ucast.wrapping_add(mac.tx_bcast),
        tx_unacknowledged: mac.tx_ucast_fail,
        tx_faults: 0,
        rx_frames: mac.rx_ucast.wrapping_add(mac.rx_bcast),
        queue_full: mac
            .queue_limit_reached
            .wrapping_add(s.nwk.stats.pending_full),
        stack_overdue: s
            .next_deadline()
            .is_some_and(|d| d.as_millis() < now.as_millis()),
    }
}

/// Runs `secs` of virtual time in 100 ms loop turns; returns every
/// decision other than Feed.
fn supervise(
    sim: &mut Simulator,
    c: usize,
    sup: &mut HealthSupervisor,
    secs: u64,
    mut each: impl FnMut(&mut Simulator, u64),
) -> Vec<Supervision> {
    let mut out = Vec::new();
    for i in 0..secs * 10 {
        sim.step(Duration::from_millis(100));
        each(sim, i);
        let o = observe(sim, c);
        let s = sup.observe(o);
        if s != Supervision::Feed {
            out.push(s);
        }
    }
    out
}

fn supervisor(sim: &mut Simulator, c: usize) -> HealthSupervisor {
    HealthSupervisor::new(sim.stack(c).now().as_millis(), false)
}

#[test]
fn an_empty_network_idles_for_an_hour_without_a_reset() {
    let (mut sim, c) = network();
    let mut sup = supervisor(&mut sim, c);
    let out = supervise(&mut sim, c, &mut sup, 3600, |_, _| {});
    assert!(out.is_empty(), "{out:?}");
    let now = sim.stack(c).now().as_millis();
    assert!(matches!(
        sup.health(now),
        Health::HealthyIdle | Health::HealthyActive
    ));
}

#[test]
fn only_sleepy_sensors_for_an_hour() {
    let (mut sim, c) = network();
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
    join(
        &mut sim,
        c,
        "contact",
        zone_sensor(
            CONTACT,
            zone_type::CONTACT_SWITCH,
            EnrollMode::AutoRequest,
            b"contact",
        ),
        CONTACT,
    );
    let mut sup = supervisor(&mut sim, c);
    assert!(supervise(&mut sim, c, &mut sup, 3600, |_, _| {}).is_empty());
}

#[test]
fn diagnostics_flash_writes_and_a_vanished_host_stay_healthy() {
    let (mut sim, c) = network();
    let b = join(&mut sim, c, "bulb", bulb(), BULB);
    let mut sup = supervisor(&mut sim, c);
    let out = supervise(&mut sim, c, &mut sup, 600, |sim, i| {
        // Diagnostic streaming: the host reads the trace constantly.
        let _ = request(
            sim,
            c,
            &Request::ReadTrace {
                from: 0,
                max: 12,
                ieee: None,
            },
        );
        // Registry writes: the bulb changes address-relevant state now
        // and then (interview restarts are persisted).
        if i % 600 == 0 {
            assert_eq!(
                request(sim, c, &Request::InterviewDevice { ieee: BULB }),
                Response::Done
            );
        }
        // The bulb is switched locally every minute.
        if i % 600 == 300 {
            let _ = sim
                .stack(b)
                .zcl
                .set_on_off(panweave_types::Endpoint(1), i % 1200 == 300);
        }
    });
    assert!(out.is_empty(), "{out:?}");
    // The host vanishes: nobody reads the events for ten minutes.
    let out = supervise(&mut sim, c, &mut sup, 600, |_, _| {});
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn an_unreachable_device_times_out_its_transactions_without_a_stall() {
    let (mut sim, c) = network();
    let b = join(&mut sim, c, "bulb", bulb(), BULB);
    sim.isolate(b);
    let mut sup = supervisor(&mut sim, c);
    let out = supervise(&mut sim, c, &mut sup, 600, |sim, i| {
        if i % 300 == 0 {
            let _ = request(
                sim,
                c,
                &Request::Light {
                    ieee: BULB,
                    endpoint: 0,
                    command: panweave_hub::protocol::LightCommand::Toggle,
                },
            );
        }
    });
    // Missing acknowledgements: degraded at most, never a stall.
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn a_supervisor_reset_is_reported_once_by_the_next_boot() {
    use panweave_hub::diag::code;
    use panweave_hub::supervisor::StallCause;
    let (mut sim, c) = network();
    join(&mut sim, c, "bulb", bulb(), BULB);
    let storage = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.flush();
        assert!(app.hub.record_stall_reset(StallCause::RadioDriver));
        app.hub.storage().clone()
    };
    let previous = |hub: &panweave_hub::Hub<HubStore>| {
        let mut from = 0;
        let mut found = Vec::new();
        loop {
            let p = hub.read_trace(from, None, 12);
            if p.records.is_empty() {
                return found;
            }
            found.extend(
                p.records
                    .iter()
                    .filter(|r| r.code == code::PREVIOUS_STALL_RESET)
                    .copied(),
            );
            from = p.next;
        }
    };
    let mut rebooted = HubApp::new(storage);
    // The registry is intact: the record is not a device.
    assert_eq!(rebooted.hub.restore().unwrap(), 1);
    let found = previous(&rebooted.hub);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].status, Some(StallCause::RadioDriver.code()));
    // Reported once: the record is erased.
    let storage = rebooted.hub.storage().clone();
    let mut again = HubApp::new(storage);
    assert_eq!(again.hub.restore().unwrap(), 1);
    assert!(previous(&again.hub).is_empty());
}
