//! Enhanced beaconing (R23.2 Annex D.11.1): a joiner discovers the
//! network with Enhanced Beacon Requests carrying the EB Filter IE;
//! only a router with enhanced beaconing answers, with an Enhanced
//! Beacon whose TX Power IE seeds both Power Control Information Tables
//! (D.11.2.4.2); a rejoin uses the Rejoin IE and is answered only by
//! routers on the same extended PAN ID; the IEEE joining list filters
//! joining requests (D.11.1.2).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::{JoiningPolicy, MacServiceConfig};
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const PLAIN_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const JOINER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const OTHER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0004);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64, enhanced: bool) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig {
            enhanced_beacons: enhanced,
            ..MacServiceConfig::default()
        },
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    n.nwk.config.enhanced_beacon_requests = enhanced;
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

fn joined(events: &[StackEvent]) -> Option<(ShortAddress, bool)> {
    events.iter().find_map(|e| match e {
        StackEvent::Joined { short, rejoin, .. } => Some((*short, *rejoin)),
        _ => None,
    })
}

fn formed(sim: &mut Simulator, c: usize) {
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
}

#[test]
fn joins_and_rejoins_through_enhanced_beacons() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1, true),
        Box::new(OnOffApp::default()),
    );
    let p = sim.add_stack(
        "plain",
        node(LogicalDeviceType::Router, PLAIN_IEEE, 2, false),
        Box::new(OnOffApp::default()),
    );
    let j = sim.add_stack(
        "joiner",
        node(LogicalDeviceType::Router, JOINER_IEEE, 3, true),
        Box::new(OnOffApp::default()),
    );
    formed(&mut sim, c);
    // The plain router joins with ordinary beacons and permits joining.
    sim.stack(p).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(p)).is_some()));
    sim.stack(p).permit_join_network(254).unwrap();
    sim.run_for(Duration::from_secs(2));

    // The joiner sends Enhanced Beacon Requests: the plain router never
    // answers them, so the coordinator is the only candidate.
    sim.stack(j).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(j)).is_some()));
    let (joiner_short, rejoin) = joined(sim.events(j)).unwrap();
    assert!(!rejoin);
    assert_eq!(
        sim.stack(j).nwk.nib.parent_address,
        ShortAddress::COORDINATOR
    );
    // The TX Power IE of the Enhanced Beacon set the link's power on
    // the joiner (D.11.2.4.2: -65 dBm optimum, 48 dB path loss from +8
    // dBm heard at -40 dBm) and the coordinator seeded its own entry
    // from the request; the join confirmed both links.
    let e = sim
        .stack(j)
        .mac
        .power_table()
        .get(Some(ShortAddress::COORDINATOR), Some(COORD_IEEE))
        .expect("joiner holds the coordinator link");
    assert_eq!(e.tx_power_dbm, -17);
    assert!(e.nwk_negotiated);
    let e = sim
        .stack(c)
        .mac
        .power_table()
        .get(None, Some(JOINER_IEEE))
        .expect("coordinator holds the joiner link");
    assert_eq!(e.tx_power_dbm, -17);
    assert!(e.nwk_negotiated);
    assert_eq!(e.short, joiner_short);
    assert!(sim.stack(p).mac.power_table().is_empty());

    // Rejoin: the Rejoin IE names the extended PAN ID; a coordinator of
    // another network with enhanced beaconing does not answer it.
    let o = sim.add_stack(
        "other",
        node(LogicalDeviceType::Coordinator, OTHER_IEEE, 4, true),
        Box::new(OnOffApp::default()),
    );
    formed(&mut sim, o);
    sim.take_events(j);
    sim.stack(j).join(JoinMode::SecuredRejoin).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(j)).is_some()));
    let (short, rejoin) = joined(sim.events(j)).unwrap();
    assert!(rejoin);
    assert_eq!(short, joiner_short);
    assert_eq!(
        sim.stack_ref(j).nwk.nib.extended_pan_id,
        sim.stack_ref(c).nwk.nib.extended_pan_id
    );
    assert_eq!(
        sim.stack_ref(j).nwk.nib.pan_id,
        sim.stack_ref(c).nwk.nib.pan_id
    );
}

#[test]
fn joining_list_filters_enhanced_beacon_requests() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1, true),
        Box::new(OnOffApp::default()),
    );
    let j = sim.add_stack(
        "joiner",
        node(LogicalDeviceType::Router, JOINER_IEEE, 3, true),
        Box::new(OnOffApp::default()),
    );
    formed(&mut sim, c);
    // Not on the list: no Enhanced Beacon, no join.
    sim.stack(c).mac.pib.joining_policy = JoiningPolicy::IeeeListJoin;
    sim.stack(j).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(j)
            .iter()
            .any(|e| matches!(e, StackEvent::JoinFailed(_)))
    }));
    assert!(joined(sim.events(j)).is_none());
    // Listed: answered.
    sim.stack(c)
        .mac
        .pib
        .joining_ieee_list
        .push(JOINER_IEEE)
        .unwrap();
    sim.take_events(j);
    sim.stack(j).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(j)).is_some()));
}
