//! The Trust Center's application-frame boundary
//! (`panweave_runtime::authorization`): an application frame reaches the
//! application only from an authorized originator. Every test checks the
//! side effect, not only the counters — a refused Toggle must not switch
//! the Trust Center's On/Off server, a refused report must not reach the
//! application.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{Authorization, JoinMode, StackConfig, StackEvent};
use panweave_security::material::LinkKeyKind;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, CommandId, DeviceId, Endpoint, ExtendedAddress, GroupAddress, Key128,
    LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::frame::Header;
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::{Direction, Role};
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: Key128 = Key128::from_bytes([0x61; 16]);
const TC: ExtendedAddress = ExtendedAddress(0x00C2_0000_0000_0001);
const ROUTER: ExtendedAddress = ExtendedAddress(0x00C2_0000_0000_0002);
const CHILD: ExtendedAddress = ExtendedAddress(0x00C2_0000_0000_0003);
/// A synthetic, non-production pre-shared key.
const PRESHARED: Key128 = Key128::from_bytes([0xA7; 16]);
const GROUP: GroupAddress = GroupAddress(0x4321);

/// The Trust Center, with an On/Off server (commands have a visible
/// effect) and client (reports reach the application).
fn tc_stack() -> SimStack {
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, TC);
    cfg.trust_center_policy.allow_joins = true;
    cfg.trust_center_policy.dlk_enabled = false;
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(1),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    ep.add_instance(on_off::client()).unwrap();
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[ClusterId(0), identify::ID, on_off::ID],
        &[on_off::ID],
    )
    .unwrap();
    s.add_endpoint(desc, ep).unwrap();
    s
}

fn network() -> (Simulator, usize) {
    let mut sim = Simulator::new();
    let c = sim.add_stack("tc", tc_stack(), Box::new(OnOffApp::default()));
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(240).unwrap();
    (sim, c)
}

fn device(ieee: ExtendedAddress, role: LogicalDeviceType, preshared: bool, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    if preshared {
        cfg.preconfigured_link_key = (TC, PRESHARED, LinkKeyKind::Unique);
    }
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    )
}

fn authorized(sim: &Simulator, c: usize, ieee: ExtendedAddress) -> bool {
    sim.events(c)
        .iter()
        .any(|e| matches!(e, StackEvent::DeviceAuthorized { ieee: i, .. } if *i == ieee))
}

fn pending(sim: &Simulator, c: usize, ieee: ExtendedAddress) -> bool {
    sim.events(c)
        .iter()
        .any(|e| matches!(e, StackEvent::KeyExchangePending { ieee: i, .. } if *i == ieee))
}

/// A standard (key-exchanging) router, authorized.
fn join_router(sim: &mut Simulator, c: usize) -> usize {
    let r = sim.add_stack(
        "router",
        device(ROUTER, LogicalDeviceType::Router, false, 2),
        Box::new(OnOffApp::default()),
    );
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| authorized(x, c, ROUTER)));
    sim.run_for(Duration::from_secs(3));
    r
}

/// An end device that can only hear `router` (its parent).
fn join_child(sim: &mut Simulator, c: usize, preshared: bool) -> usize {
    if preshared {
        sim.stack(c)
            .install_link_key(CHILD, PRESHARED, LinkKeyKind::Unique, true);
    }
    let d = sim.add_stack(
        "child",
        device(CHILD, LogicalDeviceType::EndDevice, preshared, 3),
        Box::new(OnOffApp::default()),
    );
    sim.block(c, d);
    // The router joined after the first permit-join broadcast: open
    // again so that it accepts the child.
    sim.stack(c).permit_join_network(240).unwrap();
    sim.run_for(Duration::from_secs(1));
    sim.stack(d).join(JoinMode::Association).unwrap();
    d
}

fn tc_is_on(sim: &mut Simulator, c: usize) -> bool {
    let cl = sim
        .stack(c)
        .zcl
        .cluster_mut(Endpoint(1), on_off::ID, Role::Server)
        .unwrap();
    on_off::is_on(cl)
}

/// `d` sends a ZCL On/Off Toggle to `dst`.
fn toggle(sim: &mut Simulator, d: usize, dst: Destination) {
    let seq = sim.stack(d).zcl.next_seq();
    let header = Header::cluster_specific(seq, CommandId(0x02), Direction::ToServer);
    sim.stack(d)
        .zcl_send(
            dst,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            &header,
            &[],
        )
        .unwrap();
    sim.run_for(Duration::from_secs(3));
}

/// `d` reports On/Off = true to the Trust Center.
fn report(sim: &mut Simulator, d: usize) {
    let seq = sim.stack(d).zcl.next_seq();
    let header = Header::global(seq, CommandId(0x0a), Direction::ToClient);
    sim.stack(d)
        .zcl_send(
            to_tc(),
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            &header,
            &[0x00, 0x00, 0x10, 0x01],
        )
        .unwrap();
    sim.run_for(Duration::from_secs(3));
}

fn to_tc() -> Destination {
    Destination::Short {
        address: ShortAddress::COORDINATOR,
        endpoint: Endpoint(1),
    }
}

fn reports(sim: &Simulator, c: usize) -> usize {
    sim.events(c)
        .iter()
        .filter(|e| matches!(e, StackEvent::ZclReport(f) if f.origin.cluster == on_off::ID))
        .count()
}

#[test]
fn an_authorized_device_reports_and_commands() {
    let (mut sim, c) = network();
    let r = join_router(&mut sim, c);
    assert!(!tc_is_on(&mut sim, c));
    toggle(&mut sim, r, to_tc());
    assert!(tc_is_on(&mut sim, c), "the command took effect");
    report(&mut sim, r);
    assert_eq!(reports(&sim, c), 1);
    assert_eq!(sim.stack(c).unauthorized_frames_dropped(), 0);
}

#[test]
fn a_source_without_key_pair_entry_is_refused() {
    let (mut sim, c) = network();
    let r = join_router(&mut sim, c);
    // The device holds the network key but the Trust Center no longer
    // knows it (as if it had never been admitted).
    sim.stack(c).aps.security.remove(ROUTER);
    assert_eq!(
        sim.stack(c).device_authorization(ROUTER),
        Authorization::Unknown
    );
    toggle(&mut sim, r, to_tc());
    report(&mut sim, r);
    assert!(!tc_is_on(&mut sim, c), "no side effect");
    assert_eq!(reports(&sim, c), 0);
    assert_eq!(sim.stack(c).denied_frames().unknown, 2);
}

#[test]
fn an_unresolved_originator_is_held_until_resolved() {
    let (mut sim, c) = network();
    join_router(&mut sim, c);
    let d = join_child(&mut sim, c, false);
    assert!(sim.run_until(Duration::from_secs(60), |x| authorized(x, c, CHILD)));
    sim.run_for(Duration::from_secs(5));
    // The Trust Center forgets where the child is (as after a restart):
    // the child's next frame cannot be attributed at once.
    let short = sim.stack(d).short_address();
    sim.stack(c).nwk.address_map.remove_short(short);
    toggle(&mut sim, d, to_tc());
    sim.run_for(Duration::from_secs(5));
    // IEEE_addr_req resolved it: the frame was delivered, late.
    assert!(tc_is_on(&mut sim, c));
    assert_eq!(sim.stack(c).held_application_frames(), 0);
    assert_eq!(sim.stack(c).unauthorized_frames_dropped(), 0);
}

#[test]
fn an_originator_that_cannot_be_resolved_is_refused() {
    let (mut sim, c) = network();
    join_router(&mut sim, c);
    // A sleepy child: it answers the resolution only at its next poll.
    let mut cfg = StackConfig::new(LogicalDeviceType::EndDevice, CHILD);
    cfg.sleepy = true;
    cfg.poll_interval = Duration::from_millis(1000);
    let d = sim.add_stack(
        "child",
        SimStack::new(
            cfg,
            MacServiceConfig::default(),
            TestRng::seed(3),
            MemoryStorage::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    sim.block(c, d);
    sim.stack(c).permit_join_network(240).unwrap();
    sim.run_for(Duration::from_secs(1));
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| authorized(x, c, CHILD)));
    sim.run_for(Duration::from_secs(10));
    // From now on it polls every two minutes.
    sim.stack(d).config.poll_interval = Duration::from_secs(120);
    sim.stack(d).config.fast_polls = 0;
    sim.run_for(Duration::from_secs(3));
    let short = sim.stack(d).short_address();
    sim.stack(c).nwk.address_map.remove_short(short);
    toggle(&mut sim, d, to_tc());
    assert_eq!(sim.stack(c).held_application_frames(), 1);
    sim.run_for(Duration::from_secs(15));
    assert!(!tc_is_on(&mut sim, c), "never executed");
    assert_eq!(sim.stack(c).held_application_frames(), 0);
    assert_eq!(sim.stack(c).denied_frames().unresolved, 1);
}

#[test]
fn a_pending_child_behind_a_router_is_refused_and_an_authorized_one_admitted() {
    let (mut sim, c) = network();
    let r = join_router(&mut sim, c);
    let d = join_child(&mut sim, c, true);
    assert!(sim.run_until(Duration::from_secs(30), |x| pending(x, c, CHILD)));
    sim.run_for(Duration::from_secs(2));
    // Relayed by an authorized router: the originator decides.
    toggle(&mut sim, d, to_tc());
    report(&mut sim, d);
    assert!(!tc_is_on(&mut sim, c));
    assert_eq!(reports(&sim, c), 0);
    assert!(sim.stack(c).denied_frames().pending >= 1);
    // The router itself is fine.
    toggle(&mut sim, r, to_tc());
    assert!(tc_is_on(&mut sim, c));
}

#[test]
fn exempt_admitted_devices_pass_and_withdrawn_ones_do_not() {
    let (mut sim, c) = network();
    join_router(&mut sim, c);
    sim.stack(c)
        .grant_commissioning_exemption(CHILD, Duration::from_secs(60))
        .unwrap();
    let d = join_child(&mut sim, c, true);
    assert!(sim.run_until(Duration::from_secs(60), |x| authorized(x, c, CHILD)));
    assert_eq!(
        sim.stack(c).device_authorization(CHILD),
        Authorization::Exempt
    );
    assert!(
        sim.stack(c).commissioning_exemption(CHILD).is_none(),
        "consumed"
    );
    sim.run_for(Duration::from_secs(3));
    toggle(&mut sim, d, to_tc());
    assert!(tc_is_on(&mut sim, c));
    // Withdrawn: the device has an entry but never exchanged its key.
    sim.stack(c)
        .set_key_exchange_exemption(CHILD, false)
        .unwrap();
    assert_eq!(
        sim.stack(c).device_authorization(CHILD),
        Authorization::KeyExchangeIncomplete
    );
    toggle(&mut sim, d, to_tc());
    assert!(tc_is_on(&mut sim, c), "the second toggle had no effect");
    assert_eq!(sim.stack(c).denied_frames().incomplete, 1);
}

#[test]
fn an_expired_exemption_grants_nothing() {
    let (mut sim, c) = network();
    join_router(&mut sim, c);
    sim.stack(c)
        .grant_commissioning_exemption(CHILD, Duration::from_secs(5))
        .unwrap();
    sim.run_for(Duration::from_secs(10));
    assert!(sim.stack(c).commissioning_exemption(CHILD).is_none());
    assert_eq!(sim.stack(c).commissioning_exemptions(), (0, 1));
    join_child(&mut sim, c, true);
    assert!(sim.run_until(Duration::from_secs(30), |x| pending(x, c, CHILD)));
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::KeyExchangeTimedOut { ieee } if *ieee == CHILD))
    }));
    assert!(!authorized(&sim, c, CHILD));
}

#[test]
fn group_and_broadcast_frames_are_decided_on_their_originator() {
    let (mut sim, c) = network();
    let r = join_router(&mut sim, c);
    sim.stack(c).aps.groups.add(GROUP, Endpoint(1)).unwrap();
    toggle(&mut sim, r, Destination::Group(GROUP));
    assert!(
        tc_is_on(&mut sim, c),
        "group frame from an authorized device"
    );
    toggle(
        &mut sim,
        r,
        Destination::Short {
            address: ShortAddress(0xFFFD),
            endpoint: Endpoint(0xFF),
        },
    );
    assert!(!tc_is_on(&mut sim, c), "broadcast toggled it back");
    sim.stack(c).aps.security.remove(ROUTER);
    toggle(&mut sim, r, Destination::Group(GROUP));
    toggle(
        &mut sim,
        r,
        Destination::Short {
            address: ShortAddress(0xFFFD),
            endpoint: Endpoint(0xFF),
        },
    );
    assert!(!tc_is_on(&mut sim, c), "neither had an effect");
    assert_eq!(sim.stack(c).denied_frames().unknown, 2);
}

#[test]
fn a_removed_device_is_refused_even_if_it_keeps_talking() {
    let (mut sim, c) = network();
    let r = join_router(&mut sim, c);
    // The removal reaches the stack but not the device (it ignores it).
    sim.block(c, r);
    sim.stack(c).remove_node(ROUTER, None).unwrap();
    sim.run_for(Duration::from_secs(2));
    assert!(sim.stack(c).aps.security.entry(ROUTER).is_none());
    sim.unblock(c, r);
    toggle(&mut sim, r, to_tc());
    assert!(!tc_is_on(&mut sim, c));
    assert!(sim.stack(c).denied_frames().unknown >= 1);
}

#[test]
fn bootstrap_traffic_still_works_and_garbage_is_harmless() {
    let (mut sim, c) = network();
    // ZDO, key exchange and secured rejoin of a standard device.
    let r = join_router(&mut sim, c);
    sim.take_events(c);
    sim.stack(r).join(JoinMode::SecuredRejoin).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| authorized(x, c, ROUTER)));
    // Malformed and unsecured frames change nothing.
    for f in [
        vec![0x41, 0x88],
        vec![
            0x41, 0x88, 0x01, 0x34, 0x12, 0x00, 0x00, 0x01, 0x00, 0x08, 0x02, 0xff,
        ],
        vec![
            0x41, 0x88, 0x02, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00,
        ],
    ] {
        sim.inject(&f);
    }
    sim.run_for(Duration::from_secs(2));
    assert!(!tc_is_on(&mut sim, c));
    toggle(&mut sim, r, to_tc());
    assert!(tc_is_on(&mut sim, c), "the network is unharmed");
}
