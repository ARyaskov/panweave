//! The On-Network TCLK Update procedure (BDB 3.1 §10.2.4): after a
//! join with the global link key the node asks the Trust Center for
//! its node descriptor; an R23 Trust Center answers with a Selected
//! Key Negotiation Method TLV and, lacking a secret for the device,
//! the symmetric Request Key / Verify Key exchange follows; a Trust
//! Center announcing a stack revision below 21 ends the procedure
//! without a key update.

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
use panweave_types::{
    DeviceId, Endpoint, ExtendedAddress, KeyAttributes, LogicalDeviceType, ProfileId,
};
use panweave_zdo::descriptor::ServerMask;
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);

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

fn formed(sim: &mut Simulator) -> (usize, usize) {
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 2),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    (c, r)
}

fn joined(events: &[StackEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, StackEvent::Joined { .. }))
}

#[test]
fn r23_trust_center_leads_to_the_symmetric_exchange() {
    let mut sim = Simulator::new();
    let (c, r) = formed(&mut sim);
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r))));
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    }));
    // The descriptor came from a revision-23 Trust Center: the key is a
    // unique verified one now.
    let e = sim.stack(r).aps.security.entry(COORD_IEEE).unwrap();
    assert_eq!(e.kind, LinkKeyKind::Unique);
    assert_eq!(e.attributes, KeyAttributes::VerifiedKey);
    assert!(
        sim.events(r)
            .iter()
            .all(|e| !matches!(e, StackEvent::LinkKeyUpdateSkipped { .. }))
    );
    let _ = c;
}

#[test]
fn pre_r21_trust_center_keeps_the_global_key() {
    let mut sim = Simulator::new();
    let (c, r) = formed(&mut sim);
    // The coordinator advertises a revision-20 stack.
    let servers = sim.stack(c).zdo.node.server_mask.0 & 0x01FF;
    sim.stack(c).zdo.node.server_mask = ServerMask(servers | (20 << 9));
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r))));
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdateSkipped { revision } if *revision == 20))
    }));
    sim.run_for(Duration::from_secs(10));
    assert!(
        sim.events(r)
            .iter()
            .all(|e| !matches!(e, StackEvent::LinkKeyUpdated))
    );
    assert_eq!(
        sim.stack(r).aps.security.entry(COORD_IEEE).unwrap().kind,
        LinkKeyKind::Global
    );
}
