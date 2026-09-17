//! Utility clusters at the runtime level: a sleepy end device's Poll
//! Control server driving its MAC poll rate from a bound client's
//! check-in responses, and a router's Trust Center keep-alive (ZCL8
//! §3.18.4) detecting a vanished Trust Center.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{identify, keep_alive, on_off, poll_control};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const SED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0004);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64, sleepy: bool) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.sleepy = sleepy;
    cfg.trust_center_policy.allow_joins = true;
    cfg.poll_interval = Duration::from_millis(3000);
    cfg.fast_polls = 2;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut servers = heapless::Vec::<ClusterId, 8>::new();
    let mut clients = heapless::Vec::<ClusterId, 8>::new();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    let _ = servers.push(ClusterId(0));
    let _ = servers.push(identify::ID);
    ep.add_instance(identify::server().unwrap()).unwrap();
    match role {
        LogicalDeviceType::Coordinator => {
            // Trust Center utility endpoint: Keep-Alive server (1 minute
            // base, no jitter) and a Poll Control client asking for 10 s
            // of fast polling at every check-in.
            let _ = servers.push(keep_alive::ID);
            ep.add_instance(keep_alive::server(1, 0).unwrap()).unwrap();
            let _ = clients.push(poll_control::ID);
            ep.add_instance(poll_control::client(true, 40)).unwrap();
        }
        LogicalDeviceType::EndDevice => {
            let _ = servers.push(on_off::ID);
            ep.add_instance(on_off::server().unwrap()).unwrap();
            let _ = servers.push(poll_control::ID);
            let mut pc = poll_control::server(2, 4, 480).unwrap();
            // Check in every 20 s.
            pc.set(
                poll_control::CHECK_IN_INTERVAL.id,
                &panweave_zcl::Value::Uint {
                    width: 4,
                    value: 80,
                },
            );
            ep.add_instance(pc).unwrap();
        }
        LogicalDeviceType::Router => {
            let _ = servers.push(on_off::ID);
            ep.add_instance(on_off::server().unwrap()).unwrap();
        }
    }
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0005),
        1,
        &servers,
        &clients,
    )
    .unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

fn joined(events: &[StackEvent]) -> Option<ShortAddress> {
    events.iter().find_map(|e| match e {
        StackEvent::Joined { short, .. } => Some(*short),
        _ => None,
    })
}

fn form(sim: &mut Simulator, c: usize) {
    sim.stack(c)
        .form_network_with_key(NETWORK_KEY.clone())
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
}

/// MAC data requests (polls) sent by node `i` in `(from, to)`.
fn polls_between(sim: &Simulator, i: usize, from: Instant, to: Instant) -> usize {
    sim.trace
        .iter()
        .filter(|t| {
            t.node == i && t.at.as_millis() >= from.as_millis() && t.at.as_millis() < to.as_millis()
        })
        .filter(|t| panweave_pcap::summarize(&t.frame).starts_with("MAC cmd"))
        .count()
}

#[test]
fn poll_control_check_in_puts_the_sleepy_device_into_fast_poll_mode() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41, false),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "sed",
        node(LogicalDeviceType::EndDevice, SED_IEEE, 43, true),
        Box::new(OnOffApp::default()),
    );
    form(&mut sim, c);
    sim.stack(s).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(s)).is_some()));
    // Bind the SED's Poll Control server to the coordinator (BDB §6.4 /
    // ZCL8 §3.16.3): check-ins go to the client.
    sim.stack(s)
        .aps
        .bindings
        .bind(BindingEntry {
            src_endpoint: Endpoint(1),
            cluster: poll_control::ID,
            destination: BindingDestination::Unicast {
                address: COORD_IEEE,
                endpoint: Endpoint(1),
            },
        })
        .unwrap();
    sim.run_for(Duration::from_secs(5));
    sim.take_events(c);
    sim.trace_enabled = true;
    // The next check-in reaches the coordinator's client, which asks for
    // fast polling.
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c).iter().any(|e| {
            matches!(
                e,
                StackEvent::CheckIn {
                    endpoint: Endpoint(1),
                    ..
                }
            )
        })
    }));
    let check_in = sim.clock.now();
    sim.run_for(Duration::from_secs(8));
    let fast = polls_between(&sim, s, check_in, sim.clock.now());
    // 8 s of fast polling at ShortPollInterval (0.5 s) versus 3 s long
    // polls: well over a dozen polls.
    assert!(fast >= 12, "fast polling: {fast} polls in 8 s");
    // After the 10 s fast poll timeout the long interval is back until
    // the next check-in (20 s after the previous one).
    sim.run_for(Duration::from_secs(3));
    let t0 = sim.clock.now();
    sim.run_for(Duration::from_secs(8));
    let slow = polls_between(&sim, s, t0, sim.clock.now());
    assert!((2..=3).contains(&slow), "long polling: {slow} polls in 8 s");
    assert!(sim.stack(s).is_operating());
}

#[test]
fn router_keep_alive_detects_a_vanished_trust_center() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41, false),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 42, false),
        Box::new(OnOffApp::default()),
    );
    form(&mut sim, c);
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r)).is_some()));
    // Default pacing until the first read (10 min base + up to 5 min
    // jitter), then the Trust Center's 1 minute base: 20 minutes cover
    // several keep-alive reads without any failure.
    sim.run_for(Duration::from_secs(20 * 60));
    assert!(
        !sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::TrustCenterLost)),
        "{:?}",
        sim.events(r)
    );
    assert!(
        !sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclResponse(f) if f.origin.cluster == keep_alive::ID)),
        "keep-alive responses are consumed by the stack"
    );
    // The Trust Center disappears: three failed reads (1 min apart, 10 s
    // timeout each) and the router reports it.
    sim.isolate(c);
    let gone = sim.clock.now();
    assert!(sim.run_until(Duration::from_secs(6 * 60), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::TrustCenterLost))
    }));
    let elapsed = sim.clock.now().saturating_duration_since(gone);
    assert!(
        elapsed.as_secs() >= 2 * 60,
        "three attempts are needed, took {} s",
        elapsed.as_secs()
    );
}

/// BDB 3.1 §7.3.3: a Trust Center without a Keep-Alive server is
/// polled with Node_Desc_req; three unanswered polls mean it is lost.
#[test]
fn router_falls_back_to_node_descriptor_polling() {
    let mut sim = Simulator::new();
    // A bare coordinator: no Keep-Alive server on any endpoint.
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, COORD_IEEE);
    cfg.trust_center_policy.allow_joins = true;
    let mut coord = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(51),
        MemoryStorage::new(),
    );
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0005),
        1,
        &[ClusterId(0)],
        &[],
    )
    .unwrap();
    coord
        .add_endpoint(
            desc,
            EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION),
        )
        .unwrap();
    let c = sim.add_stack("coord", coord, Box::new(OnOffApp::default()));
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 52, false),
        Box::new(OnOffApp::default()),
    );
    form(&mut sim, c);
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r)).is_some()));
    sim.run_for(Duration::from_secs(5));
    sim.take_events(r);
    // Node descriptor polls at the default pacing keep the link alive.
    sim.run_for(Duration::from_secs(40 * 60));
    assert!(
        !sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::TrustCenterLost))
    );
    assert!(
        !sim.events(r).iter().any(|e| matches!(e, StackEvent::Zdp(d)
            if d.cluster == panweave_zdo::cluster::response_of(panweave_zdo::cluster::NODE_DESC_REQ))),
        "keep-alive descriptors are consumed by the stack"
    );
    sim.isolate(c);
    assert!(sim.run_until(Duration::from_secs(60 * 60), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::TrustCenterLost))
    }));
}

/// A node without utility clusters (no Poll Control, no Keep-Alive).
fn bare(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.sleepy = role == LogicalDeviceType::EndDevice;
    cfg.trust_center_policy.allow_joins = true;
    cfg.poll_interval = Duration::from_millis(3000);
    cfg.fast_polls = 2;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0005),
        1,
        &[ClusterId(0)],
        &[],
    )
    .unwrap();
    n.add_endpoint(
        desc,
        EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION),
    )
    .unwrap();
    n
}

/// BDB 3.1 §6.6: the application switches a sleepy end device between
/// its slow and fast poll rates.
#[test]
fn application_selects_the_fast_poll_rate() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        bare(LogicalDeviceType::Coordinator, COORD_IEEE, 61),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "sed",
        bare(LogicalDeviceType::EndDevice, SED_IEEE, 62),
        Box::new(OnOffApp::default()),
    );
    form(&mut sim, c);
    sim.stack(s).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(s)).is_some()));
    sim.run_for(Duration::from_secs(20));
    sim.trace_enabled = true;
    // Slow rate: 3 s polls.
    let t0 = sim.clock.now();
    sim.run_for(Duration::from_secs(9));
    let slow = polls_between(&sim, s, t0, sim.clock.now());
    assert!((2..=4).contains(&slow), "slow: {slow}");
    // Fast rate on request (fast_poll_interval default 0.5 s).
    sim.stack(s).set_fast_polling(true);
    let t1 = sim.clock.now();
    sim.run_for(Duration::from_secs(9));
    let fast = polls_between(&sim, s, t1, sim.clock.now());
    assert!(fast >= 12, "fast: {fast}");
    sim.stack(s).set_fast_polling(false);
    sim.run_for(Duration::from_secs(3));
    let t2 = sim.clock.now();
    sim.run_for(Duration::from_secs(9));
    let slow_again = polls_between(&sim, s, t2, sim.clock.now());
    assert!((2..=4).contains(&slow_again), "slow again: {slow_again}");
}
