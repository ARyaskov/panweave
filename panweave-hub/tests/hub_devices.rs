//! The hub with three battery IAS sensors whose Basic identities emulate
//! the v0.3.0 target devices — Aqara WL-S02D (`LUMI` /
//! `lumi.flood.agl02`), Sber SBDV-00030 (`_TYZB01_epni2jgy` / `TS0203`)
//! and Yandex YNDX-00527 (`YNDX-00527`).
//!
//! **Synthetic fixtures**: only the identity strings come from the
//! devices' public documentation (see `panweave_hub::compat`); everything
//! else is the simulator's standard IAS sensor. These tests prove the
//! hub's generic paths and profile matching, not compatibility with the
//! real products (docs/device-compatibility.md).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::compat;
use panweave_hub::model::{ContactState, Flag, LeakState, PowerSource};
use panweave_hub::protocol::{DeviceInfo, Event, Request, Response, SensorEvent};
use panweave_hub::registry::zone_type;
use panweave_runtime::JoinMode;
use panweave_sim::Simulator;
use panweave_types::Endpoint;
use panweave_types::time::Duration;
use panweave_zcl::clusters::ias_zone::EnrollMode;

const AQARA: u64 = 0x54EF_4410_0000_0001;
const SBER: u64 = 0xA4C1_3800_0000_0002;
const YANDEX: u64 = 0x0C43_1400_0000_0003;

const ALARM1: u16 = 1 << 0;
const TAMPER: u16 = 1 << 2;

fn device(sim: &mut Simulator, c: usize, ieee: u64) -> DeviceInfo {
    match request(sim, c, &Request::GetDevice { ieee }) {
        Response::Device(d) => d,
        r => panic!("{r:?}"),
    }
}

fn set_zone(sim: &mut Simulator, node: usize, status: u16) {
    sim.stack(node)
        .zcl
        .set_zone_status(Endpoint(1), status)
        .unwrap();
}

fn sensor_events(sim: &Simulator, c: usize, ieee: u64) -> Vec<SensorEvent> {
    hub_events(sim, c)
        .iter()
        .filter_map(|e| match e {
            Event::Sensor { ieee: i, event } if *i == ieee => Some(*event),
            _ => None,
        })
        .collect()
}

struct Three {
    sim: Simulator,
    c: usize,
    aqara: usize,
    sber: usize,
    yandex: usize,
}

fn three() -> Three {
    let (mut sim, c) = network();
    let aqara = join(
        &mut sim,
        c,
        "aqara",
        zone_sensor_as(
            AQARA,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"LUMI",
            b"lumi.flood.agl02",
        ),
        AQARA,
    );
    let sber = join(
        &mut sim,
        c,
        "sber",
        zone_sensor_as(
            SBER,
            zone_type::CONTACT_SWITCH,
            EnrollMode::AutoRequest,
            b"_TYZB01_epni2jgy",
            b"TS0203",
        ),
        SBER,
    );
    let yandex = join(
        &mut sim,
        c,
        "yandex",
        zone_sensor_as(
            YANDEX,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"Yandex",
            b"YNDX-00527",
        ),
        YANDEX,
    );
    take_hub_events(&mut sim, c);
    Three {
        sim,
        c,
        aqara,
        sber,
        yandex,
    }
}

#[test]
fn the_three_identities_are_recognized_and_interviewed() {
    let mut t = three();
    for (ieee, profile) in [
        (AQARA, "aqara-water-leak-t1"),
        (SBER, "sber-opening-sensor"),
        (YANDEX, "yandex-water-leak-00527"),
    ] {
        let d = device(&mut t.sim, t.c, ieee);
        let p = compat::lookup(&d.manufacturer, &d.summary.model).unwrap();
        assert_eq!(p.id, profile);
        assert_eq!(d.power_source, PowerSource::Battery, "{profile}");
        assert!(d.zone.unwrap().enrolled, "{profile}");
        // The interview read the current ZoneStatus (0): the state is the
        // device's own answer, of the right kind only.
        if ieee == SBER {
            assert_eq!(d.state.contact, ContactState::Closed);
            assert_eq!(d.state.water_leak, LeakState::Unknown);
        } else {
            assert_eq!(d.state.water_leak, LeakState::Dry, "{profile}");
            assert_eq!(d.state.contact, ContactState::Unknown, "{profile}");
        }
    }
}

#[test]
fn events_in_close_succession_are_all_delivered_once() {
    let mut t = three();
    set_zone(&mut t.sim, t.aqara, ALARM1);
    set_zone(&mut t.sim, t.sber, ALARM1 | TAMPER);
    set_zone(&mut t.sim, t.yandex, ALARM1);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, AQARA).contains(&SensorEvent::WaterLeakDetected)
            && sensor_events(x, t.c, SBER).contains(&SensorEvent::ContactOpened)
            && sensor_events(x, t.c, YANDEX).contains(&SensorEvent::WaterLeakDetected)
    }));
    assert!(sensor_events(&t.sim, t.c, SBER).contains(&SensorEvent::TamperDetected));
    let sber = device(&mut t.sim, t.c, SBER);
    assert_eq!(sber.state.tamper, Flag::Set);
    assert_eq!(sber.state.zone_status, Some(ALARM1 | TAMPER), "raw kept");
    // A repeated notification of the same status is not a new event.
    set_zone(&mut t.sim, t.aqara, ALARM1);
    t.sim.run_for(Duration::from_secs(10));
    let leaks = sensor_events(&t.sim, t.c, AQARA)
        .iter()
        .filter(|e| **e == SensorEvent::WaterLeakDetected)
        .count();
    assert_eq!(leaks, 1);
    // Dry and closed.
    set_zone(&mut t.sim, t.aqara, 0);
    set_zone(&mut t.sim, t.sber, 0);
    set_zone(&mut t.sim, t.yandex, 0);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, AQARA).contains(&SensorEvent::WaterLeakCleared)
            && sensor_events(x, t.c, SBER).contains(&SensorEvent::ContactClosed)
            && sensor_events(x, t.c, YANDEX).contains(&SensorEvent::WaterLeakCleared)
    }));
}

#[test]
fn a_silent_sensor_a_rejoin_and_a_removal_leave_the_others_working() {
    let mut t = three();
    // Aqara stops answering; the others carry on.
    t.sim.isolate(t.aqara);
    set_zone(&mut t.sim, t.yandex, ALARM1);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, YANDEX).contains(&SensorEvent::WaterLeakDetected)
    }));
    // Sber rejoins (secured): same registry entry, still working.
    t.sim.stack(t.sber).join(JoinMode::SecuredRejoin).unwrap();
    // (Same address: the hub's registry entry simply stays.)
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        x.events(t.sber)
            .iter()
            .any(|e| matches!(e, panweave_runtime::StackEvent::Joined { rejoin: true, .. }))
    }));
    set_zone(&mut t.sim, t.sber, ALARM1);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, SBER).contains(&SensorEvent::ContactOpened)
    }));
    // Yandex is removed (and leaves); Sber still reports.
    assert_eq!(
        request(
            &mut t.sim,
            t.c,
            &Request::RemoveDevice {
                ieee: YANDEX,
                leave: true
            }
        ),
        Response::Done
    );
    t.sim.run_for(Duration::from_secs(10));
    take_hub_events(&mut t.sim, t.c);
    set_zone(&mut t.sim, t.sber, 0);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, SBER).contains(&SensorEvent::ContactClosed)
    }));
    let Response::DeviceList(l) = request(&mut t.sim, t.c, &Request::ListDevices { start: 0 })
    else {
        panic!()
    };
    assert_eq!(l.total, 2);
}

#[test]
fn a_hub_restart_restores_the_registry_with_unknown_states() {
    let mut t = three();
    set_zone(&mut t.sim, t.yandex, ALARM1);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, YANDEX).contains(&SensorEvent::WaterLeakDetected)
    }));
    let storage = {
        let (_, app) = t.sim.stack_and_app::<HubApp>(t.c).unwrap();
        app.hub.flush();
        app.hub.storage().clone()
    };
    let mut rebooted = HubApp::new(storage);
    assert_eq!(rebooted.hub.restore().unwrap(), 3);
    t.sim.node_mut(t.c).app = Box::new(rebooted);
    // A stale "wet" is never shown as current, nor turned into "dry".
    let y = device(&mut t.sim, t.c, YANDEX);
    assert_eq!(y.state.water_leak, LeakState::Unknown);
    assert_eq!(
        compat::lookup(&y.manufacturer, &y.summary.model).map(|p| p.id),
        Some("yandex-water-leak-00527")
    );
    // The next notification reaches the restored registry.
    set_zone(&mut t.sim, t.yandex, 0);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, YANDEX).contains(&SensorEvent::WaterLeakCleared)
    }));
}

#[test]
fn unauthorized_sources_cannot_raise_alarms() {
    let mut t = three();
    // The Trust Center forgets the Aqara sensor's key (it was never
    // admitted, as far as it is concerned): its alarm has no effect.
    t.sim
        .stack(t.c)
        .aps
        .security
        .remove(panweave_types::ExtendedAddress(AQARA));
    set_zone(&mut t.sim, t.aqara, ALARM1);
    t.sim.run_for(Duration::from_secs(20));
    assert!(sensor_events(&t.sim, t.c, AQARA).is_empty());
    assert_eq!(
        device(&mut t.sim, t.c, AQARA).state.water_leak,
        LeakState::Dry,
        "unchanged: still the last state an authorized frame gave"
    );
    assert!(t.sim.stack(t.c).denied_frames().unknown >= 1);
    // An authorized sensor's alarm is delivered.
    set_zone(&mut t.sim, t.yandex, ALARM1);
    assert!(t.sim.run_until(Duration::from_secs(60), |x| {
        sensor_events(x, t.c, YANDEX).contains(&SensorEvent::WaterLeakDetected)
    }));
}

/// Three sleepy sensors pair `stagger` apart and all must finish their
/// key exchange and interview. The coordinator's four NWK pending slots
/// fill with frames held for the sleepy children, so some frames are
/// refused locally; the APS layer must defer them, not lose them
/// (before v0.3.0 the Trust Center's key-exchange replies were dropped
/// and the sensors were removed when their key exchange timed out).
fn sleepy_sensors_pair_together(stagger: Duration) {
    let (mut sim, c) = network();
    let ids = [AQARA, SBER, YANDEX];
    for (ieee, zt, mf, model) in [
        (
            AQARA,
            zone_type::WATER_SENSOR,
            &b"LUMI"[..],
            &b"lumi.flood.agl02"[..],
        ),
        (
            SBER,
            zone_type::CONTACT_SWITCH,
            b"_TYZB01_epni2jgy",
            b"TS0203",
        ),
        (YANDEX, zone_type::WATER_SENSOR, b"Yandex", b"YNDX-00527"),
    ] {
        // 'static data for the stack configuration.
        let mf: &'static [u8] = Box::leak(mf.to_vec().into_boxed_slice());
        let model: &'static [u8] = Box::leak(model.to_vec().into_boxed_slice());
        let d = sim.add_stack(
            "sensor",
            zone_sensor_as(ieee, zt, EnrollMode::AutoRequest, mf, model),
            Box::new(panweave_sim::OnOffApp::default()),
        );
        sim.stack(d).join(JoinMode::Association).unwrap();
        sim.run_for(stagger);
    }
    assert!(
        sim.run_until(Duration::from_secs(600), |x| {
            ids.iter().all(|i| {
                hub_events(x, c).iter().any(|e| {
                    matches!(e, Event::DeviceInterviewCompleted { ieee, partial: false, .. } if ieee == i)
                })
            })
        }),
        "{:?}",
        hub_events(&sim, c)
    );
    // Nobody was removed for a failed key exchange.
    assert!(
        !hub_events(&sim, c)
            .iter()
            .any(|e| matches!(e, Event::DeviceLeft { .. })),
        "{:?}",
        hub_events(&sim, c)
    );
    let nwk = sim.stack(c).nwk.stats;
    let aps = sim.stack(c).aps.stats;
    eprintln!(
        "stagger {stagger:?}: NWK pending full {} (high water {}), APS deferrals {}",
        nwk.pending_full, nwk.pending_high_water, aps.deferrals
    );
    assert!(nwk.pending_high_water as usize <= panweave_nwk::layer::PENDING_TX);
    // Every local refusal was absorbed by a deferral.
    assert!(aps.deferrals >= nwk.pending_full.min(1));
}

#[test]
fn three_sleepy_sensors_joining_at_once_all_complete_their_interviews() {
    sleepy_sensors_pair_together(Duration::from_millis(0));
}

#[test]
fn three_sleepy_sensors_paired_seconds_apart_all_complete_their_interviews() {
    sleepy_sensors_pair_together(Duration::from_secs(3));
}
