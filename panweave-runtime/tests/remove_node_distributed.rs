//! Removing a node from a distributed network (BDB 3.1 §13.5): any
//! router sends the node a Mgmt_Leave_req and it leaves.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_security::material::LinkKeyKind;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{DeviceId, Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ProfileId};
use panweave_zdo::descriptor::SimpleDescriptor;

const A_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const B_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
/// The distributed security global link key (BDB 3.1 §6.2.4).
const DISTRIBUTED_KEY: Key128 = Key128::from_bytes([
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
]);

fn router(ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(LogicalDeviceType::Router, ieee);
    cfg.distributed = true;
    cfg.trust_center_policy.allow_joins = true;
    cfg.preconfigured_link_key = (
        ExtendedAddress::BROADCAST,
        DISTRIBUTED_KEY,
        LinkKeyKind::Global,
    );
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

#[test]
fn any_router_removes_a_node_with_mgmt_leave() {
    let mut sim = Simulator::new();
    let a = sim.add_stack("a", router(A_IEEE, 1), Box::new(OnOffApp::default()));
    let b = sim.add_stack("b", router(B_IEEE, 2), Box::new(OnOffApp::default()));
    sim.stack(a)
        .form_network_with_key(Key128::from_bytes([0x5A; 16]))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(a)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    assert!(sim.stack(a).aps.aib.is_distributed());
    sim.stack(a).permit_join_network(254).unwrap();
    sim.stack(b).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| {
            x.events(b)
                .iter()
                .any(|e| matches!(e, StackEvent::Joined { .. }))
        }),
        "b {:?} / a {:?} / a keys {:?} / a aps {:?}",
        sim.events(b),
        sim.events(a),
        sim.stack_ref(a).aps.security.keys(),
        sim.stack_ref(a).aps.stats
    );
    sim.run_for(Duration::from_secs(5));
    sim.take_events(a);
    sim.take_events(b);

    sim.stack(a).remove_node(B_IEEE, None).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(b)
            .iter()
            .any(|e| matches!(e, StackEvent::Left { rejoin: false }))
    }));
    assert!(!sim.stack(b).is_operating());
}
