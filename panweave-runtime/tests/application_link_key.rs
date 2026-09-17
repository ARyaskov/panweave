//! Application link keys brokered by the Trust Center (R23.2 §4.7.3.9,
//! BDB 3.1 §7.4): two routers with verified Trust Center link keys; one
//! requests a key for the other, the Trust Center transports the same
//! key to both, and an APS-secured read between them succeeds. A pair
//! outside the `applicationKeyRequestList` is refused under the
//! ListedOnly policy, and a device without a verified key gets nothing.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::layer::{Destination, TxOptions};
use panweave_codec::Writer;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_security::trust_center::AppKeyRequestPolicy;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::basic;
use panweave_zcl::frame::{Direction, Header};
use panweave_zcl::global::command;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const A_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const B_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const EP: Endpoint = Endpoint(1);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(basic::server(0x01, b"Panweave", b"Test").unwrap())
        .unwrap();
    let servers: &[ClusterId] = &[basic::ID];
    let desc = SimpleDescriptor::new(
        EP,
        ProfileId::HOME_AUTOMATION,
        panweave_types::DeviceId(0x0100),
        1,
        servers,
        &[],
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

fn app_key(events: &[StackEvent]) -> Option<(ExtendedAddress, bool)> {
    events.iter().find_map(|e| match e {
        StackEvent::ApplicationLinkKey { partner, initiator } => Some((*partner, *initiator)),
        _ => None,
    })
}

fn secured_read(stack: &mut SimStack, dst: ShortAddress) {
    let seq = stack.zcl.next_seq();
    let header = Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer);
    let mut payload = [0u8; 2];
    let mut w = Writer::new(&mut payload);
    panweave_zcl::global::write_attribute_ids(&mut w, &[basic::ZCL_VERSION.id]).unwrap();
    stack
        .zcl
        .send(
            Destination::Short {
                address: dst,
                endpoint: EP,
            },
            ProfileId::HOME_AUTOMATION,
            basic::ID,
            EP,
            &header,
            &payload,
            TxOptions {
                security: true,
                ..TxOptions::ACKED
            },
        )
        .unwrap();
}

fn secured_read_answered(events: &[StackEvent]) -> bool {
    events.iter().any(|e| match e {
        StackEvent::ZclResponse(f) => {
            f.origin.cluster == basic::ID
                && f.origin.header.command == command::READ_ATTRIBUTES_RESPONSE
                && f.origin.aps_secured
        }
        _ => false,
    })
}

/// Forms the network, joins A and B, and waits for their Trust Center
/// link keys to be verified.
fn network(policy: AppKeyRequestPolicy) -> (Simulator, usize, usize, usize) {
    let mut sim = Simulator::new();
    let mut coord = node(LogicalDeviceType::Coordinator, COORD_IEEE, 1);
    coord.config.trust_center_policy.app_key_requests = policy;
    let c = sim.add_stack("coord", coord, Box::new(OnOffApp::default()));
    let a = sim.add_stack(
        "a",
        node(LogicalDeviceType::Router, A_IEEE, 2),
        Box::new(OnOffApp::default()),
    );
    let b = sim.add_stack(
        "b",
        node(LogicalDeviceType::Router, B_IEEE, 3),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    for n in [a, b] {
        sim.stack(n).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(n)).is_some()));
        assert!(sim.run_until(Duration::from_secs(30), |x| {
            x.events(n)
                .iter()
                .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
        }));
    }
    // The routers become neighbours through the Link Status exchange.
    sim.run_for(Duration::from_secs(40));
    for n in [c, a, b] {
        sim.take_events(n);
    }
    (sim, c, a, b)
}

#[test]
fn trust_center_brokers_an_application_link_key() {
    let (mut sim, _c, a, b) = network(AppKeyRequestPolicy::Any);
    let b_short = sim.stack(b).short_address();
    sim.stack(a).request_application_link_key(B_IEEE).unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        app_key(x.events(a)).is_some() && app_key(x.events(b)).is_some()
    }));
    assert_eq!(app_key(sim.events(a)), Some((B_IEEE, true)));
    assert_eq!(app_key(sim.events(b)), Some((A_IEEE, false)));
    // The key is the same on both sides: an APS-secured read from A
    // to B is answered, secured.
    secured_read(sim.stack(a), b_short);
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        secured_read_answered(x.events(a))
    }));
}

#[test]
fn listed_only_policy_refuses_unlisted_pairs() {
    let (mut sim, c, a, b) = network(AppKeyRequestPolicy::ListedOnly);
    sim.stack(a).request_application_link_key(B_IEEE).unwrap();
    sim.run_for(Duration::from_secs(10));
    assert!(app_key(sim.events(a)).is_none());
    assert!(app_key(sim.events(b)).is_none());
    // Listing the pair (in either order) allows it.
    sim.stack(c)
        .application_key_request_list
        .push((B_IEEE, A_IEEE))
        .unwrap();
    sim.stack(a).request_application_link_key(B_IEEE).unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        app_key(x.events(a)).is_some() && app_key(x.events(b)).is_some()
    }));
    // An unknown partner gets nothing.
    sim.take_events(a);
    sim.stack(a)
        .request_application_link_key(ExtendedAddress(0x00AA_0000_0000_0099))
        .unwrap();
    sim.run_for(Duration::from_secs(10));
    assert!(app_key(sim.events(a)).is_none());
}
