//! Touchlink at the runtime level (BDB 3.1 §12): a factory new end
//! device scans, discovers a factory new router, asks it to identify,
//! and starts a distributed network through it (Network Start Request
//! with the certification-key transport). The router forms the network
//! with the assigned parameters, the initiator rejoins it, and ZCL
//! traffic flows between them. Then a second router is touchlinked onto
//! the running network by the (now non-factory-new) end device.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_codec::Writer;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::touchlink::{TouchlinkConfig, TouchlinkEvent};
use panweave_runtime::{StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{identify, touchlink};
use panweave_zcl::frame::Direction;
use panweave_zcl::global::{self, ReadAttributeStatus, Records, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::{Role, Value};
use panweave_zdo::descriptor::SimpleDescriptor;

const REMOTE_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0011);
const LAMP_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0012);
const LAMP2_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0013);
const EP: Endpoint = Endpoint(1);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let cfg = StackConfig::new(role, ieee);
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    let (servers, clients, device): (&[ClusterId], &[ClusterId], DeviceId) = match role {
        LogicalDeviceType::EndDevice => {
            ep.add_instance(touchlink::client()).unwrap();
            (
                &[ClusterId(0), identify::ID],
                &[identify::ID, touchlink::ID],
                DeviceId(0x0820),
            )
        }
        _ => {
            ep.add_instance(touchlink::server()).unwrap();
            (
                &[ClusterId(0), identify::ID, touchlink::ID],
                &[identify::ID],
                DeviceId(0x0100),
            )
        }
    };
    let desc =
        SimpleDescriptor::new(EP, ProfileId::HOME_AUTOMATION, device, 1, servers, clients).unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n.enable_touchlink(TouchlinkConfig::CERTIFICATION);
    n
}

fn discovered(events: &[StackEvent]) -> bool {
    events.iter().any(|e| {
        matches!(
            e,
            StackEvent::Touchlink(TouchlinkEvent::Discovered { count }) if *count > 0
        )
    })
}

fn touchlink(events: &[StackEvent], f: impl Fn(&TouchlinkEvent) -> bool) -> bool {
    events
        .iter()
        .any(|e| matches!(e, StackEvent::Touchlink(t) if f(t)))
}

fn read_identify_time(sim: &mut Simulator, from: usize, to: usize) -> Option<u16> {
    let dst = Destination::Short {
        address: sim.stack(to).short_address(),
        endpoint: EP,
    };
    let mut buf = [0u8; 4];
    let mut w = Writer::new(&mut buf);
    global::write_attribute_ids(&mut w, &[identify::IDENTIFY_TIME.id]).unwrap();
    let n = w.position();
    let seq = sim
        .stack(from)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            identify::ID,
            EP,
            command::READ_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(from).flush();
    let found = sim.run_until(Duration::from_secs(20), |x| {
        x.events(from).iter().any(|e| {
            matches!(
                e,
                StackEvent::ZclResponse(f)
                    if f.origin.header.seq == seq
                        && f.origin.header.command == command::READ_ATTRIBUTES_RESPONSE
            )
        })
    });
    if !found {
        return None;
    }
    let payload = sim.events(from).iter().find_map(|e| match e {
        StackEvent::ZclResponse(f) if f.origin.header.seq == seq => Some(f.payload.clone()),
        _ => None,
    })?;
    let recs: Vec<ReadAttributeStatus> = Records::new(&payload).map(Result::unwrap).collect();
    match recs.first()?.value {
        Some(Value::Uint { value, .. }) => u16::try_from(value).ok(),
        _ => None,
    }
}

#[test]
fn factory_new_remote_starts_a_network_through_a_lamp_and_adds_another() {
    let mut sim = Simulator::new();
    let remote = sim.add_stack(
        "remote",
        node(LogicalDeviceType::EndDevice, REMOTE_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let lamp = sim.add_stack(
        "lamp",
        node(LogicalDeviceType::Router, LAMP_IEEE, 42),
        Box::new(OnOffApp::default()),
    );
    let lamp2 = sim.add_stack(
        "lamp2",
        node(LogicalDeviceType::Router, LAMP2_IEEE, 43),
        Box::new(OnOffApp::default()),
    );
    // Keep the second lamp out of the first exchange.
    sim.isolate(lamp2);

    // Discovery: five scans on channel 11 then the rest of the primary set.
    sim.stack(remote).touchlink_start(false, false).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| discovered(x.events(remote))),
        "{:?} / lamp {:?}",
        sim.events(remote),
        sim.events(lamp)
    );
    let c = sim.stack(remote).touchlink_candidates()[0];
    assert_eq!(c.ieee, LAMP_IEEE);
    assert!(c.response.touchlink.factory_new);
    assert!(c.response.zigbee.is_router());
    assert_eq!(c.response.key_bitmask & (1 << 15), 1 << 15);
    assert!(touchlink(sim.events(lamp), |t| matches!(
        t,
        TouchlinkEvent::Scanned { initiator } if *initiator == REMOTE_IEEE
    )));

    // Identify the lamp for 2 s.
    sim.stack(remote).touchlink_identify(&c, 2).unwrap();
    sim.run_for(Duration::from_millis(500));
    let t = sim
        .stack(lamp)
        .zcl
        .cluster(EP, identify::ID, Role::Server)
        .unwrap()
        .u16(identify::IDENTIFY_TIME.id)
        .unwrap();
    assert!(t > 0 && t <= 2, "identify time {t}");

    // Select: the lamp starts a distributed network, the remote rejoins.
    sim.take_events(remote);
    sim.take_events(lamp);
    sim.stack(remote).touchlink_select(&c).unwrap();
    let ok = sim.run_until(Duration::from_secs(60), |x| {
        touchlink(x.events(remote), |t| {
            matches!(t, TouchlinkEvent::Success { .. })
        }) && x
            .events(remote)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    });
    assert!(
        ok,
        "remote {:?}\nlamp {:?}",
        sim.events(remote),
        sim.events(lamp)
    );
    assert!(touchlink(sim.events(lamp), |t| matches!(
        t,
        TouchlinkEvent::Started { initiator } if *initiator == REMOTE_IEEE
    )));
    assert!(
        sim.events(lamp)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    );
    assert_eq!(sim.stack(remote).short_address(), ShortAddress(0x0001));
    assert_eq!(sim.stack(lamp).short_address(), ShortAddress(0x0002));
    assert_eq!(
        sim.stack(remote).extended_pan_id(),
        sim.stack(lamp).extended_pan_id()
    );
    assert_eq!(
        sim.stack(lamp).trust_center_address(),
        ExtendedAddress::BROADCAST,
        "a distributed network"
    );
    sim.run_for(Duration::from_secs(3));
    sim.take_events(remote);
    // The remote can talk to the lamp over the new network.
    assert_eq!(read_identify_time(&mut sim, remote, lamp), Some(0));

    // A second lamp is touchlinked onto the running network.
    sim.unblock(remote, lamp2);
    sim.take_events(remote);
    sim.stack(remote).touchlink_start(false, false).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| discovered(x.events(remote))),
        "{:?}",
        sim.events(remote)
    );
    let c2 = sim
        .stack(remote)
        .touchlink_candidates()
        .iter()
        .find(|c| c.ieee == LAMP2_IEEE)
        .copied()
        .unwrap();
    sim.take_events(remote);
    sim.take_events(lamp2);
    sim.stack(remote).touchlink_select(&c2).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            touchlink(x.events(remote), |t| {
                matches!(t, TouchlinkEvent::Success { .. })
            })
        }),
        "remote {:?}\nlamp2 {:?}",
        sim.events(remote),
        sim.events(lamp2)
    );
    assert!(touchlink(sim.events(lamp2), |t| matches!(
        t,
        TouchlinkEvent::Joined { initiator } if *initiator == REMOTE_IEEE
    )));
    sim.unblock(lamp, lamp2);
    // The lamps become neighbours through the Link Status exchange.
    sim.run_for(Duration::from_secs(40));
    assert_eq!(sim.stack(lamp2).short_address(), ShortAddress(0x0003));
    assert_eq!(
        sim.stack(lamp2).extended_pan_id(),
        sim.stack(lamp).extended_pan_id()
    );
    sim.take_events(remote);
    assert_eq!(read_identify_time(&mut sim, remote, lamp2), Some(0));

    // Reset lamp2 to factory new (BDB 3.1 §13.2): the remote scans with
    // the reset option, selects lamp2, the Reset To Factory New Request
    // makes it leave and clear its persistent data, keeping only the
    // outgoing NWK frame counter.
    sim.block(remote, lamp);
    let counter_before = sim.stack(lamp2).nwk.security.keys.outgoing.peek();
    sim.take_events(remote);
    sim.take_events(lamp2);
    sim.stack(remote).touchlink_start(false, true).unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| discovered(x.events(remote))));
    let c3 = *sim
        .stack(remote)
        .touchlink_candidates()
        .iter()
        .find(|c| c.ieee == LAMP2_IEEE)
        .expect("lamp2 discovered");
    assert!(!c3.response.touchlink.factory_new);
    sim.stack(remote).touchlink_select(&c3).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(lamp2)
            .iter()
            .any(|e| matches!(e, StackEvent::FactoryReset))
    }));
    assert!(touchlink(sim.events(remote), |t| matches!(
        t,
        TouchlinkEvent::ResetSent
    )));
    assert!(!sim.stack(lamp2).nwk.nib.joined);
    assert_eq!(sim.stack(lamp2).storage.len(), 1);
    assert!(sim.stack(lamp2).nwk.security.keys.outgoing.peek() >= counter_before);
}
