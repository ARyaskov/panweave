//! Address conflict detection and resolution end to end (R23.2
//! §3.6.1.10): two routers end up with the same network address; the
//! coordinator sees the second IEEE address behind it, broadcasts a
//! Network Status (address conflict), and both routers pick fresh
//! addresses, announce them and stay reachable.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
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
const R1_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const R2_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
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

fn changed(events: &[StackEvent]) -> Option<ShortAddress> {
    events.iter().find_map(|e| match e {
        StackEvent::AddressChanged { short } => Some(*short),
        _ => None,
    })
}

#[test]
fn duplicate_addresses_are_detected_and_reassigned() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1),
        Box::new(OnOffApp::default()),
    );
    let r1 = sim.add_stack(
        "r1",
        node(LogicalDeviceType::Router, R1_IEEE, 2),
        Box::new(OnOffApp::default()),
    );
    let r2 = sim.add_stack(
        "r2",
        node(LogicalDeviceType::Router, R2_IEEE, 3),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    for n in [r1, r2] {
        sim.stack(n).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(n)).is_some()));
    }
    let a1 = joined(sim.events(r1)).unwrap();
    let a2 = joined(sim.events(r2)).unwrap();
    assert_ne!(a1, a2);
    sim.run_for(Duration::from_secs(5));
    for n in [c, r1, r2] {
        sim.take_events(n);
    }

    // r2 silently adopts r1's address (a stochastic allocation elsewhere
    // in the network could produce this). Its next Link Status carries
    // its IEEE address behind r1's short address.
    sim.stack(r2).nwk.nib.network_address = a1;
    sim.stack(r2).mac.set_short_address(a1);
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        changed(x.events(r1)).is_some() && changed(x.events(r2)).is_some()
    }));
    let n1 = changed(sim.events(r1)).unwrap();
    let n2 = changed(sim.events(r2)).unwrap();
    assert_ne!(n1, n2);
    assert_ne!(n1, a1);
    assert_ne!(n2, a1);
    assert_eq!(sim.stack(r1).nwk.nib.network_address, n1);
    assert_eq!(sim.stack(r2).nwk.nib.network_address, n2);
    // The coordinator learns the new addresses from the announcements.
    sim.run_for(Duration::from_secs(5));
    assert_eq!(sim.stack(c).nwk.address_map.short_for(R1_IEEE), Some(n1));
    assert_eq!(sim.stack(c).nwk.address_map.short_for(R2_IEEE), Some(n2));
}
