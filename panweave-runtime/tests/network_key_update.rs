//! Trust Center network key update (R23.2 §4.6.3.4): the new key is
//! broadcast as the alternate key, a Switch Key follows after the
//! broadcast delivery time, every device (a router and a sleepy end
//! device included) reports the switch with the retired sequence
//! number, and secured traffic continues under the new key.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    DeviceId, Endpoint, ExtendedAddress, Key128, KeySequenceNumber, LogicalDeviceType, ProfileId,
    ShortAddress,
};
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const SED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.sleepy = role == LogicalDeviceType::EndDevice;
    cfg.trust_center_policy.allow_joins = true;
    cfg.poll_interval = Duration::from_millis(1500);
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

fn joined(events: &[StackEvent]) -> Option<ShortAddress> {
    events.iter().find_map(|e| match e {
        StackEvent::Joined { short, .. } => Some(*short),
        _ => None,
    })
}

fn switched(events: &[StackEvent]) -> Option<(Option<KeySequenceNumber>, KeySequenceNumber)> {
    events.iter().find_map(|e| match e {
        StackEvent::NetworkKeySwitched { previous, sequence } => Some((*previous, *sequence)),
        _ => None,
    })
}

#[test]
fn trust_center_rotates_the_network_key() {
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
    let s = sim.add_stack(
        "sed",
        node(LogicalDeviceType::EndDevice, SED_IEEE, 3),
        Box::new(OnOffApp::default()),
    );
    let old_key = Key128::from_bytes([0x5A; 16]);
    sim.stack(c).form_network_with_key(old_key.clone()).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.block(s, r);
    for n in [r, s] {
        sim.stack(n).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(n)).is_some()));
    }
    sim.run_for(Duration::from_secs(5));
    for n in [c, r, s] {
        sim.take_events(n);
    }
    let old_seq = sim.stack(c).nwk.security.keys.active().unwrap().sequence;

    // Not the Trust Center: refused.
    assert!(
        sim.stack(r)
            .update_network_key(Key128::from_bytes([1; 16]))
            .is_err()
    );
    let new_key = Key128::from_bytes([0xC3; 16]);
    let new_seq = sim.stack(c).update_network_key(new_key.clone()).unwrap();
    assert_eq!(new_seq.0, old_seq.0.wrapping_add(1));
    // A second update while one is pending is refused.
    assert!(
        sim.stack(c)
            .update_network_key(Key128::from_bytes([2; 16]))
            .is_err()
    );

    assert!(
        sim.run_until(Duration::from_secs(60), |x| {
            [c, r, s].iter().all(|n| switched(x.events(*n)).is_some())
        }),
        "s {:?} / s keys {:?}",
        sim.events(s),
        sim.stack_ref(s).nwk.security.keys
    );
    for n in [c, r, s] {
        assert_eq!(switched(sim.events(n)), Some((Some(old_seq), new_seq)));
        let keys = &sim.stack(n).nwk.security.keys;
        assert_eq!(keys.active().unwrap().sequence, new_seq);
        assert_eq!(keys.active().unwrap().key, new_key);
        // The retired key stays in its slot until the next update.
        assert_eq!(keys.get(old_seq).map(|k| &k.key), Some(&old_key));
    }

    // Traffic under the new key: the router's Link Status keeps the
    // coordinator's neighbour entry fresh and a further update works.
    sim.take_events(c);
    let third = sim
        .stack(c)
        .update_network_key(Key128::from_bytes([0x11; 16]))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        [c, r, s].iter().all(|n| {
            x.events(*n)
                .iter()
                .any(|e| matches!(e, StackEvent::NetworkKeySwitched { sequence, .. } if *sequence == third))
        })
    }));
    assert!(sim.stack(r).nwk.security.keys.get(old_seq).is_none());
}

fn rotate_to_seven_sleepy_children(through_router: bool, occupy_slots: bool) {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1),
        Box::new(OnOffApp::default()),
    );
    let old_key = Key128::from_bytes([0x4D; 16]);
    sim.stack(c).form_network_with_key(old_key.clone()).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| x.stack_ref(c).is_operating()));
    sim.stack(c).permit_join_network(254).unwrap();
    let parent = if through_router {
        let r = sim.add_stack(
            "router",
            node(LogicalDeviceType::Router, ROUTER_IEEE, 2),
            Box::new(OnOffApp::default()),
        );
        sim.stack(r).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| x.stack_ref(r).is_operating()));
        // A router must finish its Trust Center key exchange before it
        // forwards the joins of other devices.
        assert!(
            sim.run_until(Duration::from_secs(30), |x| x
                .events(r)
                .iter()
                .any(|event| { matches!(event, StackEvent::LinkKeyUpdated) })),
            "router key exchange did not complete: {:?}",
            sim.events(r),
        );
        r
    } else {
        c
    };
    sim.stack(parent).permit_join(254).unwrap();
    let mut children = Vec::new();
    for i in 0..7u64 {
        let ieee = ExtendedAddress(SED_IEEE.0 + i);
        let s = sim.add_stack(
            "sed",
            node(LogicalDeviceType::EndDevice, ieee, i + 3),
            Box::new(OnOffApp::default()),
        );
        if through_router {
            sim.block(c, s);
        }
        sim.stack(s).join(JoinMode::Association).unwrap();
        assert!(
            sim.run_until(Duration::from_secs(60), |x| joined(x.events(s)).is_some()),
            "sleepy child {i} did not join: child {:?}; parent {:?}; coordinator {:?}",
            sim.events(s),
            sim.events(parent),
            sim.events(c),
        );
        // Network-key receipt precedes full Trust Center authorization.
        // Finish each exchange before admitting the next child.
        assert!(
            sim.run_until(Duration::from_secs(30), |x| x.events(c).iter().any(|event| {
                matches!(event, StackEvent::DeviceAuthorized { ieee: authorized, .. } if *authorized == ieee)
            })),
            "sleepy child {i} was not authorized: child {:?}; coordinator {:?}",
            sim.events(s),
            sim.events(c),
        );
        let short = sim.stack_ref(s).nwk.nib.network_address;
        children.push((s, ieee, short));
        // Completed route discoveries retain their entries for the
        // protocol's discovery interval. Commission this network without
        // exhausting the unrelated four-entry discovery tables.
        sim.run_for(panweave_nwk::nib::constants::ROUTE_DISCOVERY_TIME);
    }
    sim.run_for(Duration::from_secs(5));
    assert_eq!(
        sim.stack_ref(parent)
            .nwk
            .neighbors
            .end_device_children()
            .count(),
        7
    );
    let old_seq = sim
        .stack_ref(c)
        .nwk
        .security
        .keys
        .active()
        .unwrap()
        .sequence;
    for n in std::iter::once(c)
        .chain(std::iter::once(parent))
        .chain(children.iter().map(|(s, _, _)| *s))
    {
        sim.take_events(n);
    }

    if occupy_slots {
        // These requests remain pending until the sleeping recipients poll.
        for (_, _, short) in children.iter().take(panweave_aps::layer::PENDING_TX) {
            sim.stack(parent)
                .zdp_request(
                    *short,
                    panweave_zdo::cluster::NODE_DESC_REQ,
                    &panweave_zdo::zdp::NodeDescReq {
                        addr: *short,
                        tlvs: &[],
                    },
                )
                .unwrap();
        }
        let (_, ieee, short) = children[6];
        assert_eq!(
            sim.stack(parent)
                .aps
                .relay_network_key_to_child(ieee, short, &old_key, old_seq, COORD_IEEE),
            Err(panweave_aps::layer::ApsError::Busy),
            "the precondition must exercise APS backpressure",
        );
    }

    let key = Key128::from_bytes([0xB8; 16]);
    let sequence = sim.stack(c).update_network_key(key.clone()).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(90), |x| children.iter().all(
            |(s, _, _)| {
                x.stack_ref(*s)
                    .nwk
                    .security
                    .keys
                    .active()
                    .is_some_and(|active| active.sequence == sequence && active.key == key)
            }
        )),
        "not every sleepy child received the new key"
    );
    assert!(
        !sim.events(parent)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkKeyRelayFailed { .. }))
    );

    // Each child must answer real, NWK-secured traffic after the switch.
    for (s, _, short) in children {
        sim.take_events(c);
        let seq = sim
            .stack(c)
            .zdp_request(
                short,
                panweave_zdo::cluster::NODE_DESC_REQ,
                &panweave_zdo::zdp::NodeDescReq {
                    addr: short,
                    tlvs: &[],
                },
            )
            .unwrap();
        assert!(sim.run_until(Duration::from_secs(30), |x| x.events(c).iter().any(|e| {
            matches!(e, StackEvent::Zdp(data) if data.src == short && data.seq == seq && data.cluster == panweave_zdo::cluster::response_of(panweave_zdo::cluster::NODE_DESC_REQ))
        })), "child {s} did not communicate after rotation");
    }
}

#[test]
fn coordinator_rotates_key_for_more_sleepy_children_than_aps_slots() {
    rotate_to_seven_sleepy_children(false, false);
}

#[test]
fn router_retries_key_relays_after_occupied_aps_slots_complete() {
    rotate_to_seven_sleepy_children(true, true);
}
