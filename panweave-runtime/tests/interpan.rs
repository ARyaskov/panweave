//! The inter-PAN data service (R23.2 Annex G): an application frame
//! broadcast across PANs reaches every device on the channel, a unicast
//! one its target only, and a frame secured with a shared link key is
//! unprotected by the receiver.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::interpan::InterPanDelivery;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::interpan::{InterPanIndication, InterPanTarget};
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{ClusterId, ExtendedAddress, LogicalDeviceType, PanId, ProfileId};

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const LONER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const PROFILE: ProfileId = ProfileId(0x0104);
const CLUSTER: ClusterId = ClusterId(0x1000);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    )
}

fn inter_pan(events: &[StackEvent]) -> Option<InterPanIndication> {
    events.iter().find_map(|e| match e {
        StackEvent::InterPanData(i) => Some(i.clone()),
        _ => None,
    })
}

#[test]
fn inter_pan_frames_cross_networks_and_may_be_secured() {
    let mut sim = Simulator::new();
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
    // A device on no network at all still hears inter-PAN broadcasts.
    let l = sim.add_stack(
        "loner",
        node(LogicalDeviceType::Router, LONER_IEEE, 3),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    }));
    sim.run_for(Duration::from_secs(3));
    for n in [c, r, l] {
        sim.take_events(n);
    }
    // Broadcast: everyone on the channel gets it, unsecured.
    sim.stack(r)
        .inter_pan_request(
            InterPanTarget::Broadcast,
            PanId::BROADCAST,
            PROFILE,
            CLUSTER,
            &[0x11, 0x22, 0x33],
            false,
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        inter_pan(x.events(c)).is_some() && inter_pan(x.events(l)).is_some()
    }));
    let got = inter_pan(sim.events(l)).unwrap();
    assert_eq!(got.src, ROUTER_IEEE);
    assert_eq!(got.src_pan, sim.stack(r).pan_id());
    assert_eq!(got.dst_pan, PanId::BROADCAST);
    assert_eq!(got.delivery, InterPanDelivery::Broadcast);
    assert_eq!(got.profile, PROFILE);
    assert_eq!(got.cluster, CLUSTER);
    assert_eq!(got.asdu.as_slice(), &[0x11, 0x22, 0x33]);
    assert!(!got.secured);
    assert!(inter_pan(sim.events(r)).is_none());
    for n in [c, r, l] {
        sim.take_events(n);
    }
    // Secured unicast to the router: the shared Trust Center link key
    // protects it; the loner neither receives nor could unprotect it.
    sim.stack(c)
        .inter_pan_request(
            InterPanTarget::Device(ROUTER_IEEE),
            PanId::BROADCAST,
            PROFILE,
            CLUSTER,
            b"secret",
            true,
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |x| inter_pan(x.events(r)).is_some()));
    let got = inter_pan(sim.events(r)).unwrap();
    assert_eq!(got.src, COORD_IEEE);
    assert_eq!(got.delivery, InterPanDelivery::Unicast);
    assert_eq!(got.asdu.as_slice(), b"secret");
    assert!(got.secured);
    assert!(inter_pan(sim.events(l)).is_none());
    // Securing needs a device target with a shared key.
    assert!(
        sim.stack(c)
            .inter_pan_request(
                InterPanTarget::Broadcast,
                PanId::BROADCAST,
                PROFILE,
                CLUSTER,
                b"x",
                true
            )
            .is_err()
    );
    assert!(
        sim.stack(c)
            .inter_pan_request(
                InterPanTarget::Device(LONER_IEEE),
                PanId::BROADCAST,
                PROFILE,
                CLUSTER,
                b"x",
                true
            )
            .is_err()
    );
    // A group delivery is broadcast on the air with the group address.
    sim.take_events(r);
    sim.stack(c)
        .inter_pan_request(
            InterPanTarget::Group(panweave_types::GroupAddress(0x0102)),
            PanId::BROADCAST,
            PROFILE,
            CLUSTER,
            &[9],
            false,
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |x| inter_pan(x.events(r)).is_some()));
    assert_eq!(
        inter_pan(sim.events(r)).unwrap().delivery,
        InterPanDelivery::Group(panweave_types::GroupAddress(0x0102))
    );
}
