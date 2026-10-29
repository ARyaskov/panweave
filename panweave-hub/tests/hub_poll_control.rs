//! Poll Control on the hub: the interview binds Poll Control, a Check-in
//! while the hub has work for a sleepy device asks it to fast poll, and
//! Fast Poll Stop sends it back to long polling once the work is done.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::diag::{DiagRecord, Severity, code};
use panweave_hub::protocol::{Event, Request, Response};
use panweave_hub::registry::zone_type;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
};
use panweave_zcl::Value;
use panweave_zcl::clusters::ias_zone::{self, EnrollMode};
use panweave_zcl::clusters::{identify, poll_control, power_configuration};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const POLLED: u64 = 0x00AA_0000_0000_0020;
const PLAIN: u64 = 0x00AA_0000_0000_0021;

/// Long poll of both sensors: frames for them wait up to this long.
const LONG_POLL_S: u64 = 30;

/// A contact sensor polling every 30 s; with `poll_control`, a Poll
/// Control server checking in every 10 s.
fn sensor(ieee: u64, model: &'static [u8], poll_control: bool) -> SimStack {
    let mut cfg = StackConfig::new(LogicalDeviceType::EndDevice, ExtendedAddress(ieee));
    cfg.sleepy = true;
    cfg.poll_interval = Duration::from_secs(LONG_POLL_S);
    cfg.manufacturer_name = b"Sim Devices";
    cfg.model = model;
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(ieee),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(power_configuration::battery_server(30).unwrap())
        .unwrap();
    ep.add_instance(
        ias_zone::server(
            zone_type::CONTACT_SWITCH,
            0x1234,
            EnrollMode::AutoRequest,
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let mut clusters = vec![
        ClusterId(0),
        power_configuration::ID,
        identify::ID,
        ias_zone::ID,
    ];
    if poll_control {
        let mut c = poll_control::server(0, 0, 0).unwrap();
        // Quarter seconds: check in every 10 s, long poll 30 s.
        c.set(
            poll_control::CHECK_IN_INTERVAL.id,
            &Value::Uint {
                width: 4,
                value: 40,
            },
        );
        c.set(
            poll_control::LONG_POLL_INTERVAL.id,
            &Value::Uint {
                width: 4,
                value: LONG_POLL_S * 4,
            },
        );
        ep.add_instance(c).unwrap();
        clusters.push(poll_control::ID);
    }
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0402),
        0,
        &clusters,
        &[],
    )
    .unwrap();
    s.add_endpoint(desc, ep).unwrap();
    s
}

fn everything(sim: &mut Simulator, c: usize) {
    let r = request(
        sim,
        c,
        &Request::SetTraceConfiguration {
            min_severity: Severity::Debug.code(),
            categories: u32::MAX,
        },
    );
    assert!(matches!(r, Response::TraceConfiguration(_)), "{r:?}");
}

fn trace(sim: &mut Simulator, c: usize, ieee: u64) -> Vec<DiagRecord> {
    trace_of(sim, c, Some(ieee))
}

fn trace_of(sim: &mut Simulator, c: usize, ieee: Option<u64>) -> Vec<DiagRecord> {
    let mut out = Vec::new();
    let mut from = 0;
    loop {
        let Response::TracePage(p) = request(
            sim,
            c,
            &Request::ReadTrace {
                from,
                max: 12,
                ieee,
            },
        ) else {
            panic!()
        };
        if p.records.is_empty() {
            return out;
        }
        out.extend(p.records.iter().copied());
        from = p.next;
    }
}

/// The newest trace record's sequence number.
fn last_seq(sim: &mut Simulator, c: usize) -> u32 {
    trace_of(sim, c, None).last().map_or(0, |r| r.seq)
}

/// Seconds from the join until the hub finished the interview.
fn interview_time(sim: &mut Simulator, c: usize, stack: SimStack, ieee: u64) -> u64 {
    let d = sim.add_stack("sensor", stack, Box::new(OnOffApp::default()));
    let start = sim.stack(c).now();
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(1800), |x| hub_events(x, c).iter().any(
            |e| matches!(e, Event::DeviceInterviewCompleted { ieee: i, .. } if *i == ieee)
        )),
        "no interview of {ieee:#x}"
    );
    sim.stack(c)
        .now()
        .saturating_duration_since(start)
        .as_millis()
        / 1000
}

/// Seconds a requested re-interview of an idle device takes.
fn reinterview_time(sim: &mut Simulator, c: usize, ieee: u64) -> u64 {
    take_hub_events(sim, c);
    let start = sim.stack(c).now();
    assert_eq!(
        request(sim, c, &Request::InterviewDevice { ieee }),
        Response::Done
    );
    assert!(
        sim.run_until(Duration::from_secs(1800), |x| hub_events(x, c).iter().any(
            |e| matches!(e, Event::DeviceInterviewCompleted { ieee: i, .. } if *i == ieee)
        )),
        "no re-interview of {ieee:#x}"
    );
    sim.stack(c)
        .now()
        .saturating_duration_since(start)
        .as_millis()
        / 1000
}

#[test]
fn check_ins_speed_up_a_sleepy_device_and_fast_polling_is_stopped() {
    let (mut sim, c) = network();
    everything(&mut sim, c);
    interview_time(&mut sim, c, sensor(POLLED, b"polled", true), POLLED);
    interview_time(&mut sim, c, sensor(PLAIN, b"plain", false), PLAIN);
    // Idle: both are back to long polling.
    sim.run_for(Duration::from_secs(120));
    let mark = last_seq(&mut sim, c);

    let polled = reinterview_time(&mut sim, c, POLLED);
    let plain = reinterview_time(&mut sim, c, PLAIN);
    // Requests wait for the device's next poll: a long poll without Poll
    // Control (frames held together go out in one burst); with it, the
    // Check-in the binding brings to the hub, answered with fast polling.
    // Measured: 5 s and 26 s. The simulated device also polls quickly
    // after every frame it receives, so the gain here comes mostly from
    // the Check-in; the fast-poll request itself is checked in the trace
    // below.
    assert!(
        polled < LONG_POLL_S / 2 && polled * 3 < plain,
        "with Poll Control {polled} s, without {plain} s"
    );

    let t: Vec<DiagRecord> = trace(&mut sim, c, POLLED)
        .into_iter()
        .filter(|r| r.seq > mark)
        .collect();
    let fast = t
        .iter()
        .position(|r| r.code == code::POLL_CHECK_IN && r.status == Some(1))
        .unwrap_or_else(|| panic!("no fast-poll request: {t:x?}"));
    let completed = t
        .iter()
        .position(|r| r.code == code::INTERVIEW_COMPLETED)
        .unwrap();
    let stop = t
        .iter()
        .position(|r| r.code == code::FAST_POLL_STOP)
        .unwrap_or_else(|| panic!("no Fast Poll Stop: {t:x?}"));
    assert!(fast < completed && completed < stop, "{t:x?}");

    // Idle afterwards: Check-ins are answered without fast polling.
    let before = last_seq(&mut sim, c);
    sim.run_for(Duration::from_secs(60));
    let t = trace(&mut sim, c, POLLED);
    let later: Vec<&DiagRecord> = t
        .iter()
        .filter(|r| r.seq > before && r.code == code::POLL_CHECK_IN)
        .collect();
    assert!(!later.is_empty(), "no Check-in in a minute: {t:x?}");
    assert!(later.iter().all(|r| r.status == Some(0)), "{later:x?}");
}

#[test]
fn a_host_command_to_a_sleepy_device_is_answered_at_the_next_check_in() {
    let (mut sim, c) = network();
    everything(&mut sim, c);
    interview_time(&mut sim, c, sensor(POLLED, b"polled", true), POLLED);
    sim.run_for(Duration::from_secs(60));
    take_hub_events(&mut sim, c);

    let Response::Accepted { command } = request(
        &mut sim,
        c,
        &Request::ReadAttribute {
            ieee: POLLED,
            endpoint: 1,
            cluster: 0x0000,
            attribute: 0x0004,
        },
    ) else {
        panic!()
    };
    let start = sim.stack(c).now();
    wait_event(
        &mut sim,
        c,
        120,
        |e| matches!(e, Event::CommandCompleted { command: x, .. } if *x == command),
    );
    let took = sim
        .stack(c)
        .now()
        .saturating_duration_since(start)
        .as_millis();
    // Within a Check-in interval plus the fast-poll exchange, not a long
    // poll.
    assert!(took < LONG_POLL_S * 1000, "{took} ms");
}
