//! Table 5-12 enforcement end to end: an In-Home Display joined to an
//! ESI Trust Center reads the Price cluster without APS security and is
//! refused with a Default Response FAILURE under the network key, reads
//! it APS-secured and is answered, and reads the Basic cluster
//! unsecured and is answered (SE 1.4a §5.4.6).

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
use panweave_smart_energy::clusters::price;
use panweave_smart_energy::{PROFILE_ID, devices, endpoints as se, zcl_link_key_policy};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress,
};
use panweave_zcl::clusters::basic;
use panweave_zcl::frame::{Direction, Header, ZclStatus};
use panweave_zcl::global::command;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const TC_IEEE: ExtendedAddress = ExtendedAddress(1);
const IHD_IEEE: ExtendedAddress = ExtendedAddress(2);
const EP: Endpoint = Endpoint(10);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, PROFILE_ID);
    ep.add_instance(basic::server(0x01, b"Panweave", b"SE").unwrap())
        .unwrap();
    let (device, servers, clients): (_, &[ClusterId], &[ClusterId]) =
        if role == LogicalDeviceType::Coordinator {
            ep.add_instance(se::server(price::ID).unwrap().unwrap())
                .unwrap();
            (
                devices::ENERGY_SERVICE_INTERFACE,
                &[basic::ID, price::ID],
                &[],
            )
        } else {
            ep.add_instance(se::client(price::ID).unwrap().unwrap())
                .unwrap();
            (devices::IN_HOME_DISPLAY, &[basic::ID], &[price::ID])
        };
    let desc = SimpleDescriptor::new(EP, PROFILE_ID, device, 1, servers, clients).unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n.zcl.set_link_key_policy(Some(zcl_link_key_policy));
    n
}

fn read(stack: &mut SimStack, cluster: ClusterId, secured: bool) -> u8 {
    let seq = stack.zcl.next_seq();
    let header = Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer);
    let mut payload = [0u8; 2];
    let mut w = Writer::new(&mut payload);
    panweave_zcl::global::write_attribute_ids(&mut w, &[panweave_types::AttributeId(0x0000)])
        .unwrap();
    stack
        .zcl
        .send(
            Destination::Short {
                address: ShortAddress::COORDINATOR,
                endpoint: EP,
            },
            PROFILE_ID,
            cluster,
            EP,
            &header,
            &payload,
            TxOptions {
                security: secured,
                ..TxOptions::ACKED
            },
        )
        .unwrap();
    seq.0
}

/// The (command, status, aps_secured) of the reply to `seq`.
fn reply(
    events: &[StackEvent],
    cluster: ClusterId,
    seq: u8,
) -> Option<(u8, Option<ZclStatus>, bool)> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclResponse(f)
            if f.origin.cluster == cluster && f.origin.header.seq.0 == seq =>
        {
            let cmd = f.origin.header.command.0;
            let status = if cmd == command::DEFAULT_RESPONSE.0 {
                f.payload.get(1).map(|s| ZclStatus::from_raw(*s))
            } else {
                None
            };
            Some((cmd, status, f.origin.aps_secured))
        }
        _ => None,
    })
}

#[test]
fn unsecured_frames_of_link_key_clusters_are_refused_with_failure() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "esi",
        node(LogicalDeviceType::Coordinator, TC_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "ihd",
        node(LogicalDeviceType::Router, IHD_IEEE, 42),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    }));
    sim.run_for(Duration::from_secs(5));

    // Price without the link key: Default Response FAILURE, network
    // key only.
    let seq = read(sim.stack(r), price::ID, false);
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reply(x.events(r), price::ID, seq).is_some()
    }));
    assert_eq!(
        reply(sim.events(r), price::ID, seq),
        Some((command::DEFAULT_RESPONSE.0, Some(ZclStatus::Failure), false))
    );
    // Basic without the link key: answered.
    let seq = read(sim.stack(r), basic::ID, false);
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reply(x.events(r), basic::ID, seq).is_some()
    }));
    assert_eq!(
        reply(sim.events(r), basic::ID, seq),
        Some((command::READ_ATTRIBUTES_RESPONSE.0, None, false))
    );
    // Price with the link key: answered, and the answer is secured too.
    let seq = read(sim.stack(r), price::ID, true);
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reply(x.events(r), price::ID, seq).is_some()
    }));
    assert_eq!(
        reply(sim.events(r), price::ID, seq),
        Some((command::READ_ATTRIBUTES_RESPONSE.0, None, true))
    );
}
