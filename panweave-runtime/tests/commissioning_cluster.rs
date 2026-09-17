//! The Commissioning cluster at the runtime level (ZCL8 §13.2): a
//! router seeds its startup set from the network it joined, the tool
//! (coordinator) cannot read the keys back (NOT_AUTHORIZED), writes the
//! network key and a silent-join StartupControl, saves the set under an
//! index (stored in non-volatile memory and restored by a rebooted
//! stack), and sends Restart Device; after the delay the router leaves,
//! re-adopts the network from the set and is reachable again.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_codec::{Encode, Writer};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::{Key, Kind, MemoryStorage, Storage};
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, CommandId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
    TransactionSequence,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::commissioning::{self as cs, StartupSet};
use panweave_zcl::clusters::identify;
use panweave_zcl::frame::{Direction, ZclStatus};
use panweave_zcl::global::{AttributeValue, ReadAttributeStatus, Records, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::Value;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0007);
const EP: Endpoint = Endpoint(1);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    node_with(role, ieee, seed, MemoryStorage::new())
}

fn node_with(
    role: LogicalDeviceType,
    ieee: ExtendedAddress,
    seed: u64,
    storage: MemoryStorage<64, 128>,
) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        storage,
    );
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    let (servers, clients): (&[ClusterId], &[ClusterId]) = match role {
        LogicalDeviceType::Router => {
            ep.add_instance(cs::server(&StartupSet::default()).unwrap())
                .unwrap();
            (&[ClusterId(0), identify::ID, cs::ID], &[identify::ID])
        }
        _ => {
            ep.add_instance(cs::client()).unwrap();
            (&[ClusterId(0), identify::ID], &[identify::ID, cs::ID])
        }
    };
    let desc = SimpleDescriptor::new(
        EP,
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0005),
        1,
        servers,
        clients,
    )
    .unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

fn reply(events: &[StackEvent], seq: TransactionSequence, cmd: CommandId) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclCommand(f) | StackEvent::ZclResponse(f)
            if f.origin.header.seq == seq
                && f.origin.cluster == cs::ID
                && f.origin.header.command == cmd =>
        {
            Some(f.payload.to_vec())
        }
        _ => None,
    })
}

#[test]
fn tool_writes_the_startup_set_and_restarts_the_router_into_a_silent_join() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "tool",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 42),
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
    sim.run_for(Duration::from_secs(3));
    assert!(sim.stack(r).seed_startup_set(EP));
    let seeded = sim.stack(r).startup_set(EP).unwrap();
    assert_eq!(seeded.startup_control, cs::startup_control::SILENT_JOIN);
    assert_eq!(seeded.extended_pan_id, sim.stack(c).extended_pan_id().0);
    assert_eq!(seeded.trust_center_address, COORD_IEEE.0);
    let original_short = sim.stack(r).short_address();
    sim.take_events(c);
    let dst = Destination::Short {
        address: original_short,
        endpoint: EP,
    };

    // Reading the keys is refused; the other attributes read fine.
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    panweave_zcl::global::write_attribute_ids(
        &mut w,
        &[cs::NETWORK_KEY.id, cs::STARTUP_CONTROL.id],
    )
    .unwrap();
    let n = w.position();
    let seq = sim
        .stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            cs::ID,
            EP,
            command::READ_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reply(x.events(c), seq, command::READ_ATTRIBUTES_RESPONSE).is_some()
    }));
    let p = reply(sim.events(c), seq, command::READ_ATTRIBUTES_RESPONSE).unwrap();
    let recs: Vec<ReadAttributeStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(recs[0].status, ZclStatus::NotAuthorized);
    assert_eq!(
        recs[1].value,
        Some(Value::Enum8(cs::startup_control::SILENT_JOIN))
    );
    sim.take_events(c);

    // The tool writes the network key and saves the set under index 1.
    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: cs::NETWORK_KEY.id,
        value: Value::Key128(*NETWORK_KEY.as_bytes()),
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    sim.stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            cs::ID,
            EP,
            command::WRITE_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    sim.run_for(Duration::from_secs(3));
    assert_eq!(
        sim.stack(r).startup_set(EP).unwrap().network_key,
        NETWORK_KEY
    );
    let n = cs::encode_index(0, 1, &mut buf).unwrap();
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            cs::ID,
            EP,
            cs::CMD_SAVE_STARTUP_PARAMETERS,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reply(x.events(c), seq, cs::CMD_SAVE_STARTUP_PARAMETERS_RESPONSE) == Some(vec![0])
    }));
    // The saved set is in non-volatile storage (§13.2.2.3.2) and a
    // rebooted stack with the same storage gets it back.
    assert!(
        sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::StartupSetsChanged { endpoint: EP }))
    );
    let mut rec = [0u8; 256];
    let stored = sim
        .stack(r)
        .storage
        .load(Key::with_id(Kind::StartupSets, u64::from(EP.0)), &mut rec)
        .unwrap()
        .unwrap();
    assert_eq!(stored, 1 + 1 + StartupSet::ENCODED_LEN);
    let mut rebooted = node_with(
        LogicalDeviceType::Router,
        ROUTER_IEEE,
        43,
        sim.stack(r).storage.clone(),
    );
    rebooted.restore().unwrap();
    let saved = cs::saved(rebooted.zcl.cluster(EP, cs::ID, Role::Server).unwrap());
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].0, 1);
    assert_eq!(saved[0].1.network_key, NETWORK_KEY);
    assert_eq!(saved[0].1.startup_control, cs::startup_control::SILENT_JOIN);
    sim.take_events(c);
    sim.take_events(r);

    // Restart Device with a 2 s delay and jitter: the router answers
    // SUCCESS, tells its application and, once the delay has elapsed,
    // applies the set itself: leave, then silent re-adoption.
    let restart_sent = sim.clock.now();
    let n = cs::encode_restart(cs::restart_options::IMMEDIATE, 2, 5, &mut buf).unwrap();
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            cs::ID,
            EP,
            cs::CMD_RESTART_DEVICE,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reply(x.events(c), seq, cs::CMD_RESTART_DEVICE_RESPONSE) == Some(vec![0])
            && x.events(r).iter().any(|e| {
                matches!(
                    e,
                    StackEvent::Restart {
                        endpoint: EP,
                        install: true,
                        immediate: true,
                        delay: 2,
                        jitter: 5
                    }
                )
            })
    }));
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::Left { .. }))
    }));
    // Not before the delay, not later than the delay plus 5 × 80 ms of
    // jitter (plus the leave itself).
    let left_at = sim.clock.now();
    let elapsed = left_at.as_millis() - restart_sent.as_millis();
    assert!((2_000..=4_000).contains(&elapsed), "{elapsed} ms");
    sim.run_for(Duration::from_secs(2));
    assert!(!sim.stack(r).is_idle());
    assert_eq!(sim.stack(r).short_address(), original_short);
    assert_eq!(
        sim.stack(r).extended_pan_id(),
        sim.stack(c).extended_pan_id()
    );
    // A silently joined router becomes routable once the Link Status
    // exchange has made it a neighbour again (R23.2 §3.6.4.4).
    sim.run_for(Duration::from_secs(40));
    sim.take_events(c);

    // Reachable again on the same address with the same key.
    let mut w = Writer::new(&mut buf);
    panweave_zcl::global::write_attribute_ids(&mut w, &[cs::STARTUP_CONTROL.id]).unwrap();
    let n = w.position();
    let seq = sim
        .stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            cs::ID,
            EP,
            command::READ_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(
        sim.run_until(Duration::from_secs(15), |x| {
            reply(x.events(c), seq, command::READ_ATTRIBUTES_RESPONSE).is_some()
        }),
        "{:?}",
        sim.events(c)
    );
    let _ = sim.stack(r).zcl.cluster(EP, cs::ID, Role::Server).unwrap();
}
