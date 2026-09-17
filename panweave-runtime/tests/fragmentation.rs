//! Fragmentation discovery and caching (R23.2 §2.2.8.4.5.1): an ASDU too
//! long for one APS-secured frame makes the sender ask for the peer's
//! Node Descriptor first, cache its fragmentation parameters and then
//! send the fragmented message; a peer known not to reassemble gets
//! nothing and the application is told.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::layer::{Destination, TxOptions};
use panweave_codec::{Encode, Writer};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::fragment_cache::FragmentationEntry;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::basic;
use panweave_zcl::frame::{Direction, Header};
use panweave_zcl::global::{AttributeValue, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::{DataType, Value};
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
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

/// An APS-secured Write Attributes of a 70-octet location string: 77
/// octets of ZCL, beyond one secured APS frame.
fn long_secured_write(stack: &mut SimStack, dst: ShortAddress) {
    let seq = stack.zcl.next_seq();
    let header = Header::global(seq, command::WRITE_ATTRIBUTES, Direction::ToServer);
    let location = [b'x'; 70];
    let mut payload = [0u8; 80];
    let mut w = Writer::new(&mut payload);
    AttributeValue {
        id: basic::LOCATION_DESCRIPTION.id,
        value: Value::String {
            ty: DataType::CharString,
            bytes: Some(&location),
        },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
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
            &payload[..n],
            TxOptions {
                security: true,
                ..TxOptions::ACKED
            },
        )
        .unwrap();
    stack.flush();
}

fn write_answered(events: &[StackEvent]) -> bool {
    events.iter().any(|e| match e {
        StackEvent::ZclResponse(f) => {
            f.origin.cluster == basic::ID
                && f.origin.header.command == command::WRITE_ATTRIBUTES_RESPONSE
        }
        _ => false,
    })
}

#[test]
fn fragmented_messages_wait_for_the_peer_parameters() {
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
    sim.run_for(Duration::from_secs(5));
    sim.take_events(c);
    let router_short = sim.stack(r).short_address();
    assert!(sim.stack(c).fragmentation_entry(router_short).is_none());
    // The write is held, the router's Node Descriptor fetched, the
    // parameters cached, then the fragmented message goes out and is
    // answered.
    long_secured_write(sim.stack(c), router_short);
    assert!(sim.run_until(Duration::from_secs(30), |x| write_answered(x.events(c))));
    let entry = sim.stack(c).fragmentation_entry(router_short).unwrap();
    assert!(entry.supported);
    assert!(usize::from(entry.max_incoming) >= 77);
    assert!(sim.stack(r).aps.stats.reassembled >= 1);
    // No Node_Desc_rsp reached the application: the discovery consumed it.
    assert!(!sim.events(c).iter().any(|e| matches!(
        e,
        StackEvent::Zdp(d) if d.cluster == panweave_zdo::zdp::cluster::response_of(panweave_zdo::zdp::cluster::NODE_DESC_REQ)
    )));
    // Cached: the next one goes straight out.
    sim.take_events(c);
    let reassembled = sim.stack(r).aps.stats.reassembled;
    long_secured_write(sim.stack(c), router_short);
    assert!(sim.run_until(Duration::from_secs(30), |x| write_answered(x.events(c))));
    assert_eq!(sim.stack(r).aps.stats.reassembled, reassembled + 1);
    // A peer that does not reassemble, or takes less, is refused.
    sim.take_events(c);
    sim.stack(c).cache_fragmentation(FragmentationEntry {
        addr: router_short,
        supported: true,
        max_incoming: 40,
    });
    long_secured_write(sim.stack(c), router_short);
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(c).iter().any(|e| {
            matches!(
                e,
                StackEvent::FragmentationRefused { dst, cluster, len }
                    if *dst == router_short && *cluster == basic::ID && *len == 77
            )
        })
    }));
    assert!(!write_answered(sim.events(c)));
    // A short, unsecured message never needs the cache.
    sim.take_events(c);
    let seq = sim.stack(c).zcl.next_seq();
    let header = Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer);
    let mut payload = [0u8; 2];
    let mut w = Writer::new(&mut payload);
    panweave_zcl::global::write_attribute_ids(&mut w, &[basic::ZCL_VERSION.id]).unwrap();
    sim.stack(c)
        .zcl
        .send(
            Destination::Short {
                address: router_short,
                endpoint: EP,
            },
            ProfileId::HOME_AUTOMATION,
            basic::ID,
            EP,
            &header,
            &payload,
            TxOptions::ACKED,
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(c).iter().any(|e| matches!(
            e,
            StackEvent::ZclResponse(f) if f.origin.header.command == command::READ_ATTRIBUTES_RESPONSE
        ))
    }));
}
