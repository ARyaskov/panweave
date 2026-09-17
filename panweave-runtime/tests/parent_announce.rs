//! Parent_annce after a reboot (R23.2 §2.4.3.1.12, §2.4.4.2.12): an
//! end device that moved from the coordinator to a router while the
//! coordinator was down is announced by the rebooted coordinator; the
//! router claims it and the coordinator drops the stale child entry.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, Restored, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId};
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const ED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);

fn node(
    role: LogicalDeviceType,
    ieee: ExtendedAddress,
    seed: u64,
    storage: MemoryStorage<64, 128>,
) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        storage,
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

fn joined(events: &[StackEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, StackEvent::Joined { .. }))
}

#[test]
fn rebooted_parent_announces_children_and_drops_the_claimed_one() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(
            LogicalDeviceType::Coordinator,
            COORD_IEEE,
            1,
            MemoryStorage::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(
            LogicalDeviceType::Router,
            ROUTER_IEEE,
            2,
            MemoryStorage::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    let e = sim.add_stack(
        "ed",
        node(
            LogicalDeviceType::EndDevice,
            ED_IEEE,
            3,
            MemoryStorage::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r))));
    // The end device joins the coordinator (the router is out of reach).
    sim.block(e, r);
    sim.stack(e).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(e))));
    sim.run_for(Duration::from_secs(5));
    assert!(sim.stack(c).nwk.neighbors.by_extended(ED_IEEE).is_some());

    // The coordinator goes down; the end device rejoins through the
    // router, which becomes its parent.
    let storage = sim.stack(c).storage.clone();
    sim.isolate(c);
    sim.unblock(e, r);
    sim.take_events(e);
    sim.stack(e).join(JoinMode::SecuredRejoin).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(e))));
    assert!(sim.stack(r).nwk.neighbors.by_extended(ED_IEEE).is_some());

    // The coordinator reboots with its stale child, announces it after
    // apsParentAnnounceBaseTimer + jitter, and the router's claim makes
    // it forget the child.
    let mut fresh = node(LogicalDeviceType::Coordinator, COORD_IEEE, 4, storage);
    assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
    assert!(fresh.nwk.neighbors.by_extended(ED_IEEE).is_some());
    fresh.poll(sim.clock.now());
    fresh.resume().unwrap();
    let c2 = sim.add_stack("coord2", fresh, Box::new(OnOffApp::default()));
    sim.block(c, c2);
    assert!(sim.run_until(Duration::from_secs(40), |x| {
        x.events(c2)
            .iter()
            .any(|e| matches!(e, StackEvent::ChildClaimed { ieee, .. } if *ieee == ED_IEEE))
    }));
    assert!(sim.stack(c2).nwk.neighbors.by_extended(ED_IEEE).is_none());
    assert!(sim.stack(r).nwk.neighbors.by_extended(ED_IEEE).is_some());
}
