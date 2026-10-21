//! The Trust Center's join milestones (`panweave_runtime::join_trace`):
//! their order for a successful join, and where a refused join stops.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::join_trace::{JoinStage, decision};
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{ExtendedAddress, LogicalDeviceType};

const KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x71; 16]);
const TC: ExtendedAddress = ExtendedAddress(0x00AB_0000_0000_0001);
const DEV: ExtendedAddress = ExtendedAddress(0x00AB_0000_0000_0002);

fn stack(role: LogicalDeviceType, ieee: ExtendedAddress, allow_joins: bool) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = allow_joins;
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(ieee.0),
        MemoryStorage::new(),
    )
}

fn stages(sim: &mut Simulator, c: usize) -> Vec<(JoinStage, u8)> {
    let mut out = Vec::new();
    while let Some(r) = sim.stack(c).next_join_record() {
        assert_eq!(r.device, DEV);
        out.push((r.stage, r.detail));
    }
    out
}

fn network(allow_joins: bool) -> (Simulator, usize, usize) {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "tc",
        stack(LogicalDeviceType::Coordinator, TC, allow_joins),
        Box::new(OnOffApp::default()),
    );
    let d = sim.add_stack(
        "dev",
        stack(LogicalDeviceType::EndDevice, DEV, false),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(60).unwrap();
    sim.stack(d).join(JoinMode::Association).unwrap();
    (sim, c, d)
}

#[test]
fn a_successful_join_is_traced_in_order() {
    let (mut sim, c, d) = network(true);
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(d)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    }));
    sim.run_for(Duration::from_secs(2));
    let mut got = stages(&mut sim, c);
    // A Panweave joiner uses R23 Network Commissioning towards an R23
    // parent; only MAC association (R21/R22 devices) produces an
    // AssociationRequest record.
    if got
        .first()
        .is_some_and(|(s, _)| *s == JoinStage::AssociationRequest)
    {
        got.remove(0);
    }
    let order: Vec<JoinStage> = got.iter().map(|(s, _)| *s).collect();
    let expect = [
        JoinStage::ChildJoined,
        JoinStage::Decision,
        JoinStage::KeyTransportSent,
        JoinStage::KeyDelivered,
        JoinStage::KeyExchangePending,
        JoinStage::TclkRequested,
        JoinStage::TclkVerified,
        JoinStage::Authorized,
    ];
    assert_eq!(order, expect, "{got:?}");
    assert_eq!(got[0].1, 1, "an unsecured join");
    assert_eq!(got[1].1, decision::TRANSPORT_NETWORK_KEY);
    assert_eq!(got[5].1, 1, "the link key request was granted");
    assert_eq!(
        got[7].1, 0,
        "authorized by the key exchange, not an exemption"
    );
    assert_eq!(sim.stack(c).join_trace_dropped, 0);
}

#[test]
fn a_join_refused_by_policy_stops_at_the_decision() {
    let (mut sim, c, _d) = network(false);
    sim.run_for(Duration::from_secs(20));
    let mut got = stages(&mut sim, c);
    got.retain(|(s, _)| *s != JoinStage::AssociationRequest);
    assert!(got.len() >= 2, "{got:?}");
    assert_eq!(got[0].0, JoinStage::ChildJoined);
    assert_eq!(got[1], (JoinStage::Decision, decision::IGNORE));
    assert!(
        !got.iter().any(|(s, _)| *s == JoinStage::KeyTransportSent),
        "no key for a refused device: {got:?}"
    );
}

#[test]
fn a_mac_association_request_is_traced() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "tc",
        stack(LogicalDeviceType::Coordinator, TC, true),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(60).unwrap();
    sim.run_for(Duration::from_secs(1));
    while sim.stack(c).next_join_record().is_some() {}
    // An R21-style joiner: MAC Association Request, command frame,
    // acknowledgement requested, short destination (the coordinator),
    // extended source on the broadcast PAN.
    let pan = sim.stack(c).pan_id().0.to_le_bytes();
    let mut f = vec![0x23, 0xC8, 0x42, pan[0], pan[1], 0x00, 0x00, 0xFF, 0xFF];
    f.extend_from_slice(&DEV.0.to_le_bytes());
    f.extend_from_slice(&[0x01, 0x80]);
    sim.inject(&f);
    sim.run_for(Duration::from_millis(500));
    let first = sim.stack(c).next_join_record().expect("a record");
    assert_eq!(first.stage, JoinStage::AssociationRequest);
    assert_eq!(first.device, DEV);
    assert_eq!(first.detail, 0x80, "the capability octet");
    assert_eq!(first.short, None);
}
