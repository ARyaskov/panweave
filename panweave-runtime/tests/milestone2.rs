//! Milestone 2: a router joins the coordinator, a sleepy end device joins
//! through the router (network key tunnelled by the Trust Center), data
//! is routed coordinator ↔ router ↔ sleepy end device with MAC polling,
//! attribute reports flow to the coordinator, and after the router fails
//! the sleepy end device rejoins the coordinator directly.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: panweave_types::ExtendedAddress =
    panweave_types::ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: panweave_types::ExtendedAddress =
    panweave_types::ExtendedAddress(0x00AA_0000_0000_0003);
const SED_IEEE: panweave_types::ExtendedAddress =
    panweave_types::ExtendedAddress(0x00AA_0000_0000_0004);

fn on_off_state(sim: &mut Simulator, i: usize) -> bool {
    matches!(
        sim.stack(i)
            .zcl
            .cluster(Endpoint(1), on_off::ID, Role::Server)
            .and_then(|c| c.attributes.value(AttributeId(0))),
        Some(Value::Bool(Some(true)))
    )
}

use panweave_aps::Destination;
use panweave_aps::tables::BindingDestination;
use panweave_codec::{Decode, Encode};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    AttributeId, ClusterId, DeviceId, Endpoint, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::frame::Direction;
use panweave_zcl::global::{AttributeValue, Records, ReportingConfig, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::{DataType, Value};
use panweave_zcl::{ClusterDef, Role};
use panweave_zdo::descriptor::SimpleDescriptor;
use panweave_zdo::zdp::{BindReq, StatusRsp, ZdpStatus, cluster};

fn node(
    role: LogicalDeviceType,
    ieee: panweave_types::ExtendedAddress,
    seed: u64,
    sleepy: bool,
) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.sleepy = sleepy;
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
        DeviceId(if sleepy { 0x0100 } else { 0x0005 }),
        1,
        &[ClusterId(0), identify::ID, on_off::ID],
        &[on_off::ID],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    ep.add_cluster(
        ClusterDef {
            id: on_off::ID,
            revision: 2,
            received: &[],
            generated: &[],
        },
        Role::Client,
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

#[test]
fn router_and_sleepy_end_device_with_router_failure() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "node",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 11, false),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "node",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 12, false),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "node",
        node(LogicalDeviceType::EndDevice, SED_IEEE, 13, true),
        Box::new(OnOffApp::default()),
    );
    // The sleepy end device only hears the router.
    sim.block(c, s);

    // --- Coordinator forms, router joins ---------------------------------
    sim.stack(c)
        .form_network_with_key(NETWORK_KEY.clone())
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| joined(x.events(r)).is_some()),
        "router did not join: {:?}",
        sim.events(r)
    );
    let router_short = joined(sim.events(r)).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
    }));
    assert!(sim.stack(r).nwk.nib.router_started);
    // The router received the network-wide permit joining request.
    sim.stack(c).permit_join_network(180).unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |s| {
        s.node(r).stack.nwk.is_permitting_joins()
    }));
    sim.take_events(c);
    sim.take_events(r);

    // --- Sleepy end device joins through the router ---------------------
    sim.stack(s).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(90), |x| joined(x.events(s)).is_some()),
        "sleepy end device did not join: {:?} / router {:?} / coord {:?}",
        sim.events(s),
        sim.events(r),
        sim.events(c)
    );
    let sed_short = joined(sim.events(s)).unwrap();
    assert_eq!(sim.stack(s).nwk.nib.parent_address, router_short);
    // The Trust Center tunnelled the key through the router and learned
    // the device from Update Device; the router now lists an authenticated
    // child.
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            x.events(c).iter().any(
                |e| matches!(e, StackEvent::DeviceAuthorized { ieee, .. } if *ieee == SED_IEEE),
            ) && x
                .events(s)
                .iter()
                .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
        }),
        "coord {:?} / sed {:?}",
        sim.events(c),
        sim.events(s)
    );
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::DeviceAnnounce { ieee, .. } if *ieee == SED_IEEE))
    }));
    sim.take_events(c);
    sim.take_events(s);

    // --- Multi-hop: coordinator binds the SED's On/Off to itself ------------
    sim.stack(c)
        .zdp_request(
            sed_short,
            cluster::BIND_REQ,
            &BindReq {
                src: SED_IEEE,
                src_endpoint: Endpoint(1),
                cluster: on_off::ID,
                destination: BindingDestination::Unicast {
                    address: COORD_IEEE,
                    endpoint: Endpoint(1),
                },
            },
        )
        .unwrap();
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            x.events(c)
                .iter()
                .any(|e| matches!(e, StackEvent::Zdp(z) if z.cluster == ClusterId(0x8021)))
        }),
        "no bind response: {:?}",
        sim.events(c)
    );
    let rsp = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::Zdp(z) if z.cluster == ClusterId(0x8021) => Some(z.data.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        StatusRsp::decode_exact(&rsp).unwrap().status,
        ZdpStatus::Success
    );
    // Configure reporting on the SED (through the router).
    let cfg = ReportingConfig::Reported {
        id: AttributeId(0),
        ty: DataType::Bool,
        min: 0,
        max: 10,
        change: None,
    };
    let mut cbuf = [0u8; 16];
    let n = cfg.encode_to_slice(&mut cbuf).unwrap();
    let dst = Destination::Short {
        address: sed_short,
        endpoint: Endpoint(1),
    };
    let seq = sim
        .stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            command::CONFIGURE_REPORTING,
            Direction::ToServer,
            None,
            &cbuf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            x.events(c).iter().any(|e| {
                matches!(
                    e,
                    StackEvent::ZclResponse(f) if f.origin.header.seq == seq
                )
            })
        }),
        "no configure reporting response: {:?}",
        sim.events(c)
    );
    sim.take_events(c);
    // Toggle the lamp: the change report travels SED → router → coordinator.
    sim.stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            on_off::CMD_ON,
            Direction::ToServer,
            None,
            &[],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            x.events(c)
                .iter()
                .any(|e| matches!(e, StackEvent::ZclReport(_)))
        }),
        "no report: {:?}",
        sim.events(c)
    );
    let rep = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::ZclReport(f) => Some(f.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(rep.origin.src, sed_short);
    let recs: Vec<AttributeValue> = Records::new(&rep.payload).map(Result::unwrap).collect();
    assert_eq!(recs[0].value, Value::Bool(Some(true)));
    assert!(on_off_state(&mut sim, s));
    sim.take_events(c);
    // Periodic reports keep arriving through the router.
    assert!(sim.run_until(Duration::from_secs(25), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclReport(_)))
    }));
    sim.take_events(c);
    sim.take_events(s);

    // --- Router failure: the sleepy end device rejoins the coordinator ----
    sim.isolate(r);
    sim.unblock(c, s);
    assert!(
        sim.run_until(Duration::from_secs(300), |x| {
            x.events(s)
                .iter()
                .any(|e| matches!(e, StackEvent::Joined { rejoin: true, .. }))
        }),
        "no rejoin: sed {:?}",
        sim.events(s)
    );
    assert_eq!(
        sim.stack(s).nwk.nib.parent_address,
        ShortAddress::COORDINATOR
    );
    assert_eq!(
        sim.stack(s).short_address(),
        sed_short,
        "address kept on rejoin"
    );
    // Reports resume directly to the coordinator.
    sim.take_events(c);
    assert!(
        sim.run_until(Duration::from_secs(40), |x| {
            x.events(c)
                .iter()
                .any(|e| matches!(e, StackEvent::ZclReport(f) if f.origin.src == sed_short))
        }),
        "no report after rejoin: {:?}",
        sim.events(c)
    );
    assert_eq!(sim.stack(c).dropped_events, 0);
    assert_eq!(sim.stack(s).dropped_events, 0);
}

/// The Trust Center removes a device it is not the parent of: APS Remove
/// Device to the router, NWK Leave to the child, Update Device (Device
/// Left) back to the Trust Center (R23.2 §4.6.3.6).
#[test]
fn trust_center_removes_a_device_through_its_parent() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 21, false),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 22, false),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "sed",
        node(LogicalDeviceType::EndDevice, SED_IEEE, 23, true),
        Box::new(OnOffApp::default()),
    );
    sim.block(c, s);
    sim.stack(c)
        .form_network_with_key(NETWORK_KEY.clone())
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r)).is_some()));
    sim.run_for(Duration::from_secs(2));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(s).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(s)).is_some()));
    sim.run_for(Duration::from_secs(5));
    sim.take_events(c);
    sim.take_events(r);
    sim.take_events(s);

    // Unknown parent: refused; via the router: the device leaves.
    assert!(sim.stack(c).remove_device(SED_IEEE, None).is_err());
    sim.stack(c)
        .remove_device(SED_IEEE, Some(ROUTER_IEEE))
        .unwrap();
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            x.events(s)
                .iter()
                .any(|e| matches!(e, StackEvent::Left { rejoin: false }))
        }),
        "sed: {:?}\nrouter: {:?}",
        sim.events(s),
        sim.events(r)
    );
    assert!(!sim.stack(s).is_operating());
    // The router reported the departure and the Trust Center learnt it.
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::DeviceLeft { ieee, rejoin: false } if *ieee == SED_IEEE))
    }), "coord: {:?}", sim.events(c));
    assert!(sim.events(r).iter().any(|e| matches!(
        e,
        StackEvent::DeviceLeft { ieee, .. } if *ieee == SED_IEEE
    )));
    assert!(sim.stack(r).nwk.neighbors.by_extended(SED_IEEE).is_none());
}
