//! Trust Center swap-out (R23.2 §4.7.4.1.2): a router joins the first
//! Trust Center and negotiates a unique link key; the Trust Center is
//! backed up (hashed keys only) and disappears; a replacement with a
//! different EUI64 restores the backup and forms a new network (new PAN
//! ID and network key, same extended PAN ID); the router's Trust Center
//! rejoin lands on it, the network key arrives under the hashed link
//! key, the swap-out is reported, the link key is renewed and an
//! APS-secured read to the new Trust Center succeeds.

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
    ClusterId, Endpoint, ExtendedAddress, Key128, KeyAttributes, LogicalDeviceType, ProfileId,
    ShortAddress,
};
use panweave_zcl::clusters::basic;
use panweave_zcl::frame::{Direction, Header};
use panweave_zcl::global::command;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const TC1_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const TC2_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0009);
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

fn joined(events: &[StackEvent]) -> Option<(ShortAddress, bool)> {
    events.iter().find_map(|e| match e {
        StackEvent::Joined { short, rejoin, .. } => Some((*short, *rejoin)),
        _ => None,
    })
}

fn secured_read(stack: &mut SimStack) {
    let seq = stack.zcl.next_seq();
    let header = Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer);
    let mut payload = [0u8; 2];
    let mut w = Writer::new(&mut payload);
    panweave_zcl::global::write_attribute_ids(&mut w, &[basic::ZCL_VERSION.id]).unwrap();
    stack
        .zcl
        .send(
            Destination::Short {
                address: ShortAddress::COORDINATOR,
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

#[test]
fn replacement_trust_center_takes_over_from_a_hashed_backup() {
    let mut sim = Simulator::new();
    let c1 = sim.add_stack(
        "tc1",
        node(LogicalDeviceType::Coordinator, TC1_IEEE, 1),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 2),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c1)
        .form_network_with_key(Key128::from_bytes([0x5A; 16]))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c1)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    let old_pan = sim.stack(c1).nwk.nib.pan_id;
    let epid = sim.stack(c1).nwk.nib.extended_pan_id;
    sim.stack(c1).permit_join_network(254).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r)).is_some()));
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    }));
    sim.run_for(Duration::from_secs(5));
    let router_key = sim
        .stack(r)
        .aps
        .security
        .entry(TC1_IEEE)
        .unwrap()
        .key
        .clone();

    // Backup: the router's entry carries the hash, never the key.
    let backup = sim.stack(c1).trust_center_backup::<8>().unwrap();
    assert_eq!(backup.extended_pan_id, epid);
    let entry = backup
        .entries
        .iter()
        .find(|e| e.device == ROUTER_IEEE)
        .expect("router backed up");
    assert_ne!(entry.swap_out_key, router_key);
    assert_eq!(
        entry.swap_out_key,
        sim.stack(r).aps.security.swap_out_key(TC1_IEEE).unwrap(),
        "both sides derive the same swap-out key"
    );
    assert!(sim.stack(r).trust_center_backup::<8>().is_none());

    // The old Trust Center vanishes; the replacement restores the
    // backup and forms a new network on the same extended PAN ID.
    sim.isolate(c1);
    let mut tc2 = node(LogicalDeviceType::Coordinator, TC2_IEEE, 3);
    assert_eq!(tc2.restore_trust_center_backup(&backup), 1);
    let c2 = sim.add_stack("tc2", tc2, Box::new(OnOffApp::default()));
    sim.stack(c2)
        .form_network_with_key(Key128::from_bytes([0xC3; 16]))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c2)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    assert_eq!(sim.stack(c2).nwk.nib.extended_pan_id, epid);
    assert_ne!(sim.stack(c2).nwk.nib.pan_id, old_pan);
    // The restored entry keeps its attributes and holds the hashed key.
    let restored = sim.stack(c2).aps.security.entry(ROUTER_IEEE).unwrap();
    assert_eq!(restored.attributes, KeyAttributes::VerifiedKey);
    assert_eq!(restored.key, entry.swap_out_key);
    sim.run_for(Duration::from_secs(40));
    sim.take_events(r);

    // The router's Trust Center rejoin (what the application does after
    // the keep-alive fails) lands on the new Trust Center.
    sim.stack(r).join(JoinMode::TrustCenterRejoin).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| {
            x.events(r)
                .iter()
                .any(|e| matches!(e, StackEvent::TrustCenterSwapped { .. }))
        }),
        "{:?}",
        sim.events(r)
    );
    assert!(sim.events(r).iter().any(|e| matches!(
        e,
        StackEvent::TrustCenterSwapped { old, new } if *old == TC1_IEEE && *new == TC2_IEEE
    )));
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            joined(x.events(r)).is_some_and(|(_, rejoin)| rejoin)
        }),
        "{:?}",
        sim.events(r)
    );
    assert_eq!(sim.stack(r).aps.aib.trust_center_address, TC2_IEEE);
    assert!(sim.stack(r).aps.security.entry(TC1_IEEE).is_none());
    // Step 8: the link key is renewed (the router asked for a new one).
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    }));
    let renewed = &sim.stack(r).aps.security.entry(TC2_IEEE).unwrap().key;
    assert_ne!(*renewed, entry.swap_out_key);
    // And APS-secured messaging with the new Trust Center works.
    sim.take_events(r);
    secured_read(sim.stack(r));
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        secured_read_answered(x.events(r))
    }));
}
