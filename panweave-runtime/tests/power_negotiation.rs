//! Power negotiation (R23.2 §3.6.11, §3.4.13): routers broadcast Link
//! Power Delta notifications and lower each other's transmit power in
//! the MAC Power Control Information Table (Annex D.11.2.3); a sleepy
//! end device learns from the End Device Timeout Response that its
//! parent negotiates, sends a Request, polls for the Response and only
//! then adjusts; a router without support neither sends nor adjusts.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_nwk::command::LinkPowerDeltaType;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const PLAIN_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const SED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0004);

/// The simulator delivers every frame at −40 dBm; with `Popt` = −65 dBm
/// every device asks its neighbors for −25 dB, so the default maximum
/// of +8 dBm becomes −17 dBm.
const EXPECTED_POWER: i8 = -17;

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64, power: bool) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.sleepy = role == LogicalDeviceType::EndDevice;
    cfg.trust_center_policy.allow_joins = true;
    cfg.poll_interval = Duration::from_millis(1500);
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    n.nwk.config.power_control = power;
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[],
        &[],
    )
    .unwrap();
    n.add_endpoint(
        desc,
        panweave_zcl::layer::EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION),
    )
    .unwrap();
    n
}

fn joined(events: &[StackEvent]) -> Option<ShortAddress> {
    events.iter().find_map(|e| match e {
        StackEvent::Joined { short, .. } => Some(*short),
        _ => None,
    })
}

fn power_delta(
    events: &[StackEvent],
    kind: LinkPowerDeltaType,
) -> Option<(ShortAddress, Option<i8>)> {
    events.iter().find_map(|e| match e {
        StackEvent::LinkPowerDelta {
            src,
            kind: k,
            delta_db,
        } if *k == kind => Some((*src, *delta_db)),
        _ => None,
    })
}

#[test]
fn neighbors_negotiate_transmit_power_through_link_power_delta() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1, true),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 2, true),
        Box::new(OnOffApp::default()),
    );
    let p = sim.add_stack(
        "plain",
        node(LogicalDeviceType::Router, PLAIN_IEEE, 3, false),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "sed",
        node(LogicalDeviceType::EndDevice, SED_IEEE, 4, true),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    // The end device only hears the coordinator, its parent.
    sim.block(s, r);
    sim.block(s, p);
    for n in [r, p, s] {
        sim.stack(n).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(n)).is_some()));
    }
    let router_short = joined(sim.events(r)).unwrap();
    let plain_short = joined(sim.events(p)).unwrap();
    let sed_short = joined(sim.events(s)).unwrap();
    for n in [c, r, p, s] {
        sim.take_events(n);
    }
    // Joining starts at full power: nothing negotiated yet.
    assert!(sim.stack(r).mac.power_table().is_empty());

    // Routers: the coordinator's notification lowers the router's power
    // towards it and vice versa (§3.4.13.7 step 3).
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        power_delta(x.events(r), LinkPowerDeltaType::Notification).is_some()
            && power_delta(x.events(c), LinkPowerDeltaType::Notification).is_some()
    }));
    let (src, delta) = power_delta(sim.events(r), LinkPowerDeltaType::Notification).unwrap();
    assert_eq!(src, ShortAddress::COORDINATOR);
    assert_eq!(delta, Some(-25));
    let e = sim
        .stack(r)
        .mac
        .power_table()
        .get(Some(ShortAddress::COORDINATOR), None)
        .expect("router holds the coordinator link");
    assert_eq!(e.tx_power_dbm, EXPECTED_POWER);
    assert_eq!(e.extended, COORD_IEEE);
    assert_eq!(e.last_rssi_dbm, -40);
    assert!(e.nwk_negotiated);
    let e = sim
        .stack(c)
        .mac
        .power_table()
        .get(Some(router_short), None)
        .expect("coordinator holds the router link");
    assert_eq!(e.tx_power_dbm, EXPECTED_POWER);
    assert_eq!(e.extended, ROUTER_IEEE);

    // The router without support ignores the notifications and sends
    // none, so nobody negotiates with it.
    assert!(sim.stack(p).mac.power_table().is_empty());
    assert!(
        sim.events(p)
            .iter()
            .all(|e| !matches!(e, StackEvent::LinkPowerDelta { .. }))
    );
    assert!(
        sim.stack(c)
            .mac
            .power_table()
            .get(Some(plain_short), None)
            .is_none()
    );

    // The sleepy end device: the parent advertised power negotiation in
    // the End Device Timeout Response, the Request goes out and the
    // Response, polled for, adjusts the link (§3.6.11.2, §3.4.13.7).
    assert!(sim.stack(s).nwk.nib.parent_information.power_negotiation());
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        power_delta(x.events(s), LinkPowerDeltaType::Response).is_some()
    }));
    assert_eq!(
        power_delta(sim.events(s), LinkPowerDeltaType::Response),
        Some((ShortAddress::COORDINATOR, Some(-25)))
    );
    assert_eq!(
        sim.stack(s)
            .mac
            .power_table()
            .get(Some(ShortAddress::COORDINATOR), None)
            .map(|e| e.tx_power_dbm),
        Some(EXPECTED_POWER)
    );
    assert_eq!(
        power_delta(sim.events(c), LinkPowerDeltaType::Request),
        Some((sed_short, Some(-25)))
    );
    assert_eq!(
        sim.stack(c)
            .mac
            .power_table()
            .get(Some(sed_short), Some(SED_IEEE))
            .map(|e| e.tx_power_dbm),
        Some(EXPECTED_POWER)
    );
    // Only the Response counts for a sleepy device: no Notification was
    // applied on its side.
    assert!(power_delta(sim.events(s), LinkPowerDeltaType::Notification).is_none());
}
