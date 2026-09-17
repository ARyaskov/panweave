//! BDB 3.1 commissioning over the simulator: network formation on the
//! primary channel list (§8.1), off-network steering with the secondary
//! channel fallback and the post-join commissioning window (§9.8),
//! on-network steering (§9.7), finding & binding as target and initiator
//! with unicast and group bindings (§11), and the rejoin procedure (§10).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_aps::tables::BindingDestination;
use panweave_bdb::{Config as BdbConfig, Failure, Outcome};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{StackConfig, StackEvent};
use panweave_sim::{BdbApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    AttributeId, Channel, ChannelMask, DeviceId, Endpoint, ExtendedAddress, GroupAddress,
    LogicalDeviceType, ProfileId,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::{basic, groups, identify, on_off};
use panweave_zcl::frame::Direction;
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::Value;
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD: ExtendedAddress = ExtendedAddress(0x00CC_0000_0000_0001);
const LAMP: ExtendedAddress = ExtendedAddress(0x00CC_0000_0000_0002);
const SWITCH: ExtendedAddress = ExtendedAddress(0x00CC_0000_0000_0003);

fn basic_server() -> panweave_zcl::ClusterInstance<36> {
    basic::server(
        basic::power_source::MAINS_SINGLE_PHASE,
        b"Panweave",
        b"Test",
    )
    .unwrap()
}

/// On/Off light: Identify, Groups and On/Off servers.
fn lamp_endpoint() -> (SimpleDescriptor, EndpointInstance<8, 36>) {
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[basic::ID, identify::ID, groups::ID, on_off::ID],
        &[],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(basic_server()).unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(groups::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    (desc, ep)
}

/// On/Off switch: Identify server + client, Groups client, On/Off client.
fn switch_endpoint() -> (SimpleDescriptor, EndpointInstance<8, 36>) {
    let desc = SimpleDescriptor::new(
        Endpoint(2),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0103),
        1,
        &[basic::ID, identify::ID],
        &[identify::ID, groups::ID, on_off::ID],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(2), ProfileId::HOME_AUTOMATION);
    ep.add_instance(basic_server()).unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(identify::client()).unwrap();
    ep.add_instance(groups::client()).unwrap();
    ep.add_instance(panweave_zcl::ClusterInstance::new(
        on_off::DEF,
        Role::Client,
    ))
    .unwrap();
    (desc, ep)
}

fn stack(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64, lamp: bool) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let (d, e) = if lamp {
        lamp_endpoint()
    } else {
        switch_endpoint()
    };
    s.add_endpoint(d, e).unwrap();
    s
}

fn outcomes(sim: &Simulator, i: usize) -> &[Outcome] {
    &sim.app::<BdbApp>(i).unwrap().outcomes
}

/// Runs `f` with the node's stack and its BDB machine.
fn with_bdb<T>(
    sim: &mut Simulator,
    i: usize,
    f: impl FnOnce(&mut SimStack, &mut BdbApp) -> T,
) -> T {
    let (stack, app) = sim.stack_and_app::<BdbApp>(i).unwrap();
    f(stack, app)
}

fn wait_outcome(sim: &mut Simulator, i: usize, timeout: Duration) -> Outcome {
    let before = outcomes(sim, i).len();
    assert!(
        sim.run_until(timeout, |s| outcomes(s, i).len() > before),
        "no outcome for node {i} within {timeout:?}"
    );
    *outcomes(sim, i).last().unwrap()
}

fn lamp_on(sim: &Simulator, i: usize) -> bool {
    matches!(
        sim.node(i)
            .stack
            .zcl
            .cluster(Endpoint(1), on_off::ID, Role::Server)
            .and_then(|c| c.attributes.value(AttributeId(0))),
        Some(Value::Bool(Some(true)))
    )
}

#[test]
fn bdb_formation_steering_finding_binding_and_rejoin() {
    let mut sim = Simulator::new();
    let bdb = BdbConfig::DEFAULT_2_4GHZ;

    // --- Formation on the primary channel list (§8.1) -----------------
    let c = sim.add_stack(
        "coord",
        stack(LogicalDeviceType::Coordinator, COORD, 1, false),
        Box::new(BdbApp::new(bdb)),
    );
    with_bdb(&mut sim, c, |stack, app| {
        app.bdb.form_network(stack).unwrap();
    });
    assert_eq!(
        wait_outcome(&mut sim, c, Duration::from_secs(30)),
        Outcome::Formation(Ok(()))
    );
    let channel = sim.stack(c).nwk.nib.channel;
    assert!(ChannelMask::BDB_PRIMARY.contains(channel), "{channel:?}");
    assert!(sim.app::<BdbApp>(c).unwrap().bdb.is_on_network());
    // A second formation is refused.
    with_bdb(&mut sim, c, |stack, app| {
        assert_eq!(app.bdb.form_network(stack), Err(Failure::AlreadyOnNetwork));
        // On-network steering opens the network (§9.7).
        app.bdb.steer_on_network(stack).unwrap();
    });
    sim.run_for(Duration::from_secs(1));

    // --- Lamp (router) steers; its primary list holds no network, so
    //     the secondary list is used (§9.8 steps 10–11) -----------------
    let mut lamp_cfg = bdb;
    lamp_cfg.primary_channels = ChannelMask::EMPTY.with(Channel::new(26).unwrap());
    lamp_cfg.secondary_channels = ChannelMask::ALL_2_4GHZ;
    lamp_cfg.same_network_retries = 1;
    let l = sim.add_stack(
        "lamp",
        stack(LogicalDeviceType::Router, LAMP, 2, true),
        Box::new(BdbApp::new(lamp_cfg)),
    );
    with_bdb(&mut sim, l, |stack, app| {
        app.bdb.steer(stack).unwrap();
    });
    assert_eq!(
        wait_outcome(&mut sim, l, Duration::from_secs(120)),
        Outcome::Steering(Ok(())),
        "{:?}",
        sim.events(l)
    );
    assert_eq!(sim.stack(l).nwk.nib.channel, channel);
    assert!(
        sim.events(l)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    );
    // Step 13: the joined router opened its own permit-join flag.
    assert!(sim.stack(l).nwk.is_permitting_joins());

    // --- Switch (end device) steers with the defaults ------------------
    let s = sim.add_stack(
        "switch",
        stack(LogicalDeviceType::EndDevice, SWITCH, 3, false),
        Box::new(BdbApp::new(bdb)),
    );
    with_bdb(&mut sim, s, |stack, app| {
        app.bdb.steer(stack).unwrap();
    });
    assert_eq!(
        wait_outcome(&mut sim, s, Duration::from_secs(120)),
        Outcome::Steering(Ok(())),
        "{:?}",
        sim.events(s)
    );
    sim.run_for(Duration::from_secs(2));

    // --- Finding & binding: lamp target, switch initiator (§11) ---------
    with_bdb(&mut sim, l, |stack, app| {
        app.bdb.find_and_bind_target(stack, Endpoint(1)).unwrap();
    });
    assert_eq!(
        identify::identify_time(
            sim.stack(l)
                .zcl
                .cluster(Endpoint(1), identify::ID, Role::Server)
                .unwrap()
        ),
        180
    );
    with_bdb(&mut sim, s, |stack, app| {
        app.bdb
            .find_and_bind_initiator(stack, Endpoint(2), None, &[])
            .unwrap();
    });
    assert_eq!(
        wait_outcome(&mut sim, s, Duration::from_secs(30)),
        Outcome::FindingBindingInitiator {
            endpoint: Endpoint(2),
            bindings: 1,
            result: Ok(()),
        },
        "{:?}",
        sim.events(s)
    );
    let binding = sim.stack(s).aps.bindings.iter().next().copied().unwrap();
    assert_eq!(binding.src_endpoint, Endpoint(2));
    assert_eq!(binding.cluster, on_off::ID);
    assert_eq!(
        binding.destination,
        BindingDestination::Unicast {
            address: LAMP,
            endpoint: Endpoint(1)
        }
    );
    // The binding works: On through the bound destination lights the lamp.
    assert!(!lamp_on(&sim, l));
    sim.stack(s)
        .zcl
        .send_command(
            Destination::Bound,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(2),
            on_off::CMD_ON,
            Direction::ToServer,
            None,
            &[],
        )
        .unwrap();
    sim.stack(s).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        matches!(
            x.node(l)
                .stack
                .zcl
                .cluster(Endpoint(1), on_off::ID, Role::Server)
                .and_then(|c| c.attributes.value(AttributeId(0))),
            Some(Value::Bool(Some(true)))
        )
    }));

    // --- Group binding: Add Group reaches the lamp (§11.2 step 9) ------
    let group = GroupAddress(0x0042);
    with_bdb(&mut sim, s, |stack, app| {
        app.bdb
            .find_and_bind_initiator(stack, Endpoint(2), Some(group), &[on_off::ID])
            .unwrap();
    });
    assert_eq!(
        wait_outcome(&mut sim, s, Duration::from_secs(30)),
        Outcome::FindingBindingInitiator {
            endpoint: Endpoint(2),
            bindings: 1,
            result: Ok(()),
        }
    );
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.node(l).stack.aps.groups.contains(group, Endpoint(1))
    }));
    assert!(
        sim.stack(s)
            .aps
            .bindings
            .iter()
            .any(|b| b.destination == BindingDestination::Group(group))
    );
    // A group-addressed Off reaches the lamp through its new membership.
    sim.stack(s)
        .zcl
        .send_command(
            Destination::Group(group),
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(2),
            on_off::CMD_OFF,
            Direction::ToServer,
            None,
            &[],
        )
        .unwrap();
    sim.stack(s).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        matches!(
            x.node(l)
                .stack
                .zcl
                .cluster(Endpoint(1), on_off::ID, Role::Server)
                .and_then(|c| c.attributes.value(AttributeId(0))),
            Some(Value::Bool(Some(false)))
        )
    }));

    // --- No identifying target: the initiator reports it ---------------
    {
        let node = sim.node_mut(l);
        node.stack.zcl.set_identify_time(Endpoint(1), 0).unwrap();
        node.stack.flush();
    }
    assert_eq!(
        wait_outcome(&mut sim, l, Duration::from_secs(5)),
        Outcome::FindingBindingTarget {
            endpoint: Endpoint(1)
        }
    );
    with_bdb(&mut sim, s, |stack, app| {
        app.bdb
            .find_and_bind_initiator(stack, Endpoint(2), None, &[])
            .unwrap();
    });
    assert_eq!(
        wait_outcome(&mut sim, s, Duration::from_secs(30)),
        Outcome::FindingBindingInitiator {
            endpoint: Endpoint(2),
            bindings: 0,
            result: Err(Failure::NoIdentifyQueryResponse),
        }
    );

    // --- Rejoin procedure (§10.1): secured rejoin on the current channel
    let switch_short = sim.stack(s).short_address();
    with_bdb(&mut sim, s, |stack, app| {
        app.bdb.rejoin(stack, false).unwrap();
    });
    assert_eq!(
        wait_outcome(&mut sim, s, Duration::from_secs(60)),
        Outcome::Rejoin(Ok(())),
        "{:?}",
        sim.events(s)
    );
    assert_eq!(sim.stack(s).short_address(), switch_short);
}
