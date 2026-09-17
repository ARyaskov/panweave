//! Persistence and warm start: devices rebooted from their persisted
//! storage keep their network parameters, addresses and keys, continue
//! their outgoing frame counters and resume operation without a fresh
//! join (R23.2 §3.6.9, §2.2.8.1, §4.4.12.1, §3.6.10.8; BDB 3.1 §7.1).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, Restored, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::{Key, Kind, MemoryStorage, Storage};
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, Key128, KeyAttributes, LogicalDeviceType,
    ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::frame::Direction;
use panweave_zcl::global::command;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: Key128 = Key128::from_bytes([0x33; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00BB_0000_0000_0001);
const ED_IEEE: ExtendedAddress = ExtendedAddress(0x00BB_0000_0000_0002);

fn lamp_endpoint() -> (SimpleDescriptor, EndpointInstance<8, 24>) {
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[ClusterId(0x0000), identify::ID, on_off::ID],
        &[on_off::ID],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    (desc, ep)
}

fn build(
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
    let (d, e) = lamp_endpoint();
    n.add_endpoint(d, e).unwrap();
    n
}

/// Sends an On command from node `from` to `to` and waits for the
/// Default Response.
fn toggle_on(sim: &mut Simulator, from: usize, to: ShortAddress) -> bool {
    let seq = sim
        .stack(from)
        .zcl
        .send_command(
            Destination::Short {
                address: to,
                endpoint: Endpoint(1),
            },
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            on_off::CMD_ON,
            Direction::ToServer,
            None,
            &[],
        )
        .unwrap();
    sim.stack(from).flush();
    sim.run_until(Duration::from_secs(15), |x| {
        x.events(from).iter().any(|e| matches!(
            e,
            StackEvent::ZclResponse(f) if f.origin.header.seq == seq && f.origin.header.command == command::DEFAULT_RESPONSE
        ))
    })
}

fn joined(sim: &Simulator, i: usize, rejoin: bool) -> bool {
    sim.events(i)
        .iter()
        .any(|e| matches!(e, StackEvent::Joined { rejoin: r, .. } if *r == rejoin))
}

fn nwk_counter(sim: &mut Simulator, i: usize) -> u32 {
    sim.stack(i).nwk.security.keys.outgoing.peek()
}

fn load(storage: &mut MemoryStorage<64, 128>, key: Key) -> Option<Vec<u8>> {
    let mut buf = [0u8; 128];
    storage
        .load(key, &mut buf)
        .unwrap()
        .map(|n| buf[..n].to_vec())
}

#[test]
fn end_device_and_coordinator_survive_reboots() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        build(
            LogicalDeviceType::Coordinator,
            COORD_IEEE,
            1,
            MemoryStorage::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    let d = sim.add_stack(
        "ed",
        build(
            LogicalDeviceType::EndDevice,
            ED_IEEE,
            2,
            MemoryStorage::new(),
        ),
        Box::new(OnOffApp::default()),
    );

    // A factory-new device has nothing to restore.
    assert_eq!(sim.stack(d).restore().unwrap(), Restored::FactoryNew);

    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join(180).unwrap();
    sim.stack(c).flush();
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| {
            joined(x, d, false)
                && x.events(d)
                    .iter()
                    .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
        }),
        "join incomplete: {:?}",
        sim.events(d)
    );
    let ed_short = sim.stack(d).short_address();
    let pan = sim.stack(c).pan_id();
    let epid = sim.stack(c).nwk.nib.extended_pan_id;
    assert!(toggle_on(&mut sim, c, ed_short));
    sim.run_for(Duration::from_secs(5));

    // Everything the specification lists as persistent is in storage.
    for k in [
        Kind::Nib,
        Kind::NetworkKeys,
        Kind::NwkFrameCounter,
        Kind::Aib,
        Kind::Children,
    ] {
        assert!(
            load(&mut sim.stack(c).storage, Key::single(k)).is_some(),
            "coordinator lacks {k:?}"
        );
    }
    assert!(
        load(
            &mut sim.stack(c).storage,
            Key::with_id(Kind::LinkKey, ED_IEEE.0)
        )
        .is_some()
    );
    assert!(
        load(
            &mut sim.stack(d).storage,
            Key::with_id(Kind::LinkKey, COORD_IEEE.0)
        )
        .is_some()
    );
    // Keys are stored in storage records only — never in the trace.
    let children = load(&mut sim.stack(c).storage, Key::single(Kind::Children)).unwrap();
    assert_eq!(children.len(), 1 + 16, "one end-device child persisted");

    // --- End device reboot -------------------------------------------
    let ed_counter_before = nwk_counter(&mut sim, d);
    let ed_storage = sim.stack(d).storage.clone();
    sim.isolate(d);
    let mut fresh = build(LogicalDeviceType::EndDevice, ED_IEEE, 3, ed_storage);
    assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
    assert_eq!(fresh.short_address(), ed_short);
    assert_eq!(fresh.pan_id(), pan);
    assert_eq!(fresh.nwk.nib.extended_pan_id, epid);
    assert_eq!(fresh.aps.aib.trust_center_address, COORD_IEEE);
    let tclk = fresh.aps.security.entry(COORD_IEEE).unwrap();
    assert_eq!(tclk.attributes, KeyAttributes::VerifiedKey);
    // The restored counter continues past the persisted reservation and
    // is never below what was already used.
    assert!(
        fresh.nwk.security.keys.outgoing.peek() >= ed_counter_before,
        "counter rolled back: {} < {ed_counter_before}",
        fresh.nwk.security.keys.outgoing.peek()
    );
    fresh.poll(sim.clock.now());
    fresh.resume().unwrap();
    let d2 = sim.add_stack("ed2", fresh, Box::new(OnOffApp::default()));
    sim.block(d, d2);
    assert!(
        sim.run_until(Duration::from_secs(60), |x| joined(x, d2, true)),
        "secured rejoin failed: {:?}",
        sim.events(d2)
    );
    assert_eq!(sim.stack(d2).short_address(), ed_short);
    // The parent accepts the rebooted child's frames (fresh counters are
    // above the ones it saw) and application traffic works both ways.
    sim.take_events(c);
    assert!(toggle_on(&mut sim, c, ed_short), "{:?}", sim.events(c));
    assert!(toggle_on(&mut sim, d2, ShortAddress::COORDINATOR));

    // --- Coordinator reboot ------------------------------------------
    let c_storage = sim.stack(c).storage.clone();
    sim.isolate(c);
    let mut fresh = build(LogicalDeviceType::Coordinator, COORD_IEEE, 4, c_storage);
    assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
    assert_eq!(fresh.short_address(), ShortAddress::COORDINATOR);
    assert_eq!(fresh.pan_id(), pan);
    assert!(fresh.nwk.security.has_key());
    // The child is back in the neighbor table with a full timeout period
    // (§3.6.10.8) and its verified link key.
    let child = fresh.nwk.neighbors.by_extended(ED_IEEE).unwrap();
    assert_eq!(child.short, ed_short);
    assert_eq!(child.timeout_counter_secs, child.device_timeout_secs);
    assert_eq!(
        fresh.aps.security.entry(ED_IEEE).unwrap().attributes,
        KeyAttributes::VerifiedKey
    );
    fresh.poll(sim.clock.now());
    fresh.resume().unwrap();
    let c2 = sim.add_stack("coord2", fresh, Box::new(OnOffApp::default()));
    // The old instance is gone for good: not even its last broadcast
    // retries reach the rebooted one.
    sim.block(c, c2);
    sim.run_for(Duration::from_secs(5));
    assert!(sim.stack(c2).is_operating());
    // Traffic in both directions with the rebooted coordinator.
    assert!(toggle_on(&mut sim, c2, ed_short), "{:?}", sim.events(c2));
    assert!(toggle_on(&mut sim, d2, ShortAddress::COORDINATOR));
}

#[test]
fn factory_reset_erases_network_state() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        build(
            LogicalDeviceType::Coordinator,
            COORD_IEEE,
            1,
            MemoryStorage::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    assert!(!sim.stack(c).storage.is_empty());
    sim.stack(c).erase_persisted().unwrap();
    assert!(sim.stack(c).storage.is_empty());
    let storage = sim.stack(c).storage.clone();
    let mut fresh = build(LogicalDeviceType::Coordinator, COORD_IEEE, 5, storage);
    assert_eq!(fresh.restore().unwrap(), Restored::FactoryNew);
    assert!(fresh.resume().is_err());
}
