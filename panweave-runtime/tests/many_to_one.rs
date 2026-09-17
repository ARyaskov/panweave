//! Many-to-one routing and source routing end to end (R23.2 §3.6.4.5.1,
//! §3.6.4.5.5, §3.6.4.3): a concentrator without a route cache
//! advertises itself, a router two hops away sends a Route Record ahead
//! of its data, the concentrator stores the relay list and answers with
//! a source routed frame that the intermediate router relays.

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
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::basic;
use panweave_zcl::frame::{Direction, Header};
use panweave_zcl::global::command;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const R1_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const R2_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
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
        DeviceId(0x0100),
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

fn read_basic(stack: &mut SimStack, dst: ShortAddress) {
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
            TxOptions::ACKED,
        )
        .unwrap();
}

fn answered(events: &[StackEvent]) -> bool {
    events.iter().any(|e| match e {
        StackEvent::ZclResponse(f) => {
            f.origin.cluster == basic::ID
                && f.origin.header.command == command::READ_ATTRIBUTES_RESPONSE
        }
        _ => false,
    })
}

#[test]
fn concentrator_learns_routes_from_route_records_and_source_routes_back() {
    let mut sim = Simulator::new();
    let mut coord = node(LogicalDeviceType::Coordinator, COORD_IEEE, 1);
    coord.nwk.config.concentrator = true;
    let c = sim.add_stack("coord", coord, Box::new(OnOffApp::default()));
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
    // r2 only hears r1: coord — r1 — r2.
    sim.block(c, r2);
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.stack(r1).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r1)).is_some()));
    sim.stack(r1).permit_join_network(254).unwrap();
    sim.stack(r2).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r2)).is_some()));
    let r1_short = joined(sim.events(r1)).unwrap();
    let r2_short = joined(sim.events(r2)).unwrap();
    // Link Status makes the routers neighbours.
    sim.run_for(Duration::from_secs(40));
    for n in [c, r1, r2] {
        sim.take_events(n);
    }

    // The concentrator advertises itself without a route cache: the
    // routers install a many-to-one route and owe a Route Record.
    sim.stack(c).nwk.route_discovery(None, None, true).unwrap();
    sim.run_for(Duration::from_secs(10));
    let route = sim
        .stack(r2)
        .nwk
        .routes
        .get(ShortAddress::COORDINATOR)
        .copied()
        .expect("r2 has a route to the concentrator");
    assert!(route.many_to_one);
    assert!(route.route_record_required);
    assert_eq!(route.next_hop, r1_short);
    assert!(sim.stack(c).nwk.source_routes.get(r2_short).is_none());

    // r2's data is preceded by a Route Record; the concentrator stores
    // the relay list and answers source routed through r1.
    read_basic(sim.stack(r2), ShortAddress::COORDINATOR);
    assert!(sim.run_until(Duration::from_secs(20), |x| answered(x.events(r2))));
    let sr = sim
        .stack(c)
        .nwk
        .source_routes
        .get(r2_short)
        .expect("route record stored");
    assert_eq!(sr.relays.as_slice(), &[r1_short]);
    assert!(
        !sim.stack(r2)
            .nwk
            .routes
            .get(ShortAddress::COORDINATOR)
            .unwrap()
            .route_record_required
    );
    // The concentrator's own frames ride the source route rather than
    // the routing table entry it acquired while r2 joined.
    let usage_before = sim
        .stack(c)
        .nwk
        .routes
        .get(r2_short)
        .map_or(0, |r| r.total_usage);
    sim.take_events(c);
    read_basic(sim.stack(c), r2_short);
    assert!(sim.run_until(Duration::from_secs(20), |x| answered(x.events(c))));
    assert_eq!(
        sim.stack(c)
            .nwk
            .routes
            .get(r2_short)
            .map_or(0, |r| r.total_usage),
        usage_before
    );
}
