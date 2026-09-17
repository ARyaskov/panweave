//! A window covering router driven by a coordinator (ZCL8 §7.4): motion
//! is refused while `Mode` keeps the maintenance bit, a network write of
//! `Mode` releases it (and mirrors the reversal bit into `ConfigStatus`),
//! Go To Lift Percentage reaches the application as a command, and the
//! position it reports back is delivered to the bound client through
//! the default reporting of `CurrentPositionLiftPercentage`.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_codec::{Decode, Encode, Reader, Writer};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
    TransactionSequence,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::window_covering::{self as wc, Command, Control};
use panweave_zcl::clusters::{groups, identify, scenes};
use panweave_zcl::frame::{Direction, ZclStatus};
use panweave_zcl::global::{AttributeValue, DefaultResponse, Records, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::Value;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
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
    ep.add_instance(identify::server().unwrap()).unwrap();
    let (servers, clients, device): (&[ClusterId], &[ClusterId], DeviceId) = match role {
        LogicalDeviceType::Router => {
            ep.add_instance(groups::server().unwrap()).unwrap();
            ep.add_instance(scenes::server().unwrap()).unwrap();
            ep.add_instance(
                wc::server(
                    wc::covering_type::ROLLERSHADE,
                    Control::ClosedLoop {
                        open: 0,
                        closed: 200,
                        encoder: true,
                    },
                    Control::Unsupported,
                )
                .unwrap(),
            )
            .unwrap();
            (
                &[ClusterId(0), identify::ID, groups::ID, scenes::ID, wc::ID],
                &[identify::ID],
                DeviceId(0x0202),
            )
        }
        _ => {
            ep.add_instance(wc::client()).unwrap();
            (
                &[ClusterId(0), identify::ID],
                &[identify::ID, wc::ID],
                DeviceId(0x0203),
            )
        }
    };
    let desc =
        SimpleDescriptor::new(EP, ProfileId::HOME_AUTOMATION, device, 1, servers, clients).unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

fn default_response(events: &[StackEvent], seq: TransactionSequence) -> Option<ZclStatus> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclResponse(f)
            if f.origin.header.seq == seq
                && f.origin.header.command == command::DEFAULT_RESPONSE =>
        {
            DefaultResponse::decode(&mut Reader::new(&f.payload))
                .ok()
                .map(|d| d.status)
        }
        _ => None,
    })
}

fn reported_lift(events: &[StackEvent]) -> Option<u8> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclReport(f) if f.origin.cluster == wc::ID => Records::new(&f.payload)
            .map(|r: Result<AttributeValue, _>| r.unwrap())
            .find_map(|r| {
                (r.id == wc::CURRENT_POSITION_LIFT_PERCENTAGE.id)
                    .then(|| r.value.as_u64().and_then(|v| u8::try_from(v).ok()))
                    .flatten()
            }),
        _ => None,
    })
}

#[test]
fn go_to_lift_percentage_reaches_the_application_and_the_position_is_reported() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "shade",
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
    sim.stack(r)
        .aps
        .bindings
        .bind(BindingEntry {
            src_endpoint: EP,
            cluster: wc::ID,
            destination: BindingDestination::Unicast {
                address: COORD_IEEE,
                endpoint: EP,
            },
        })
        .unwrap();
    sim.run_for(Duration::from_secs(3));
    sim.take_events(c);
    sim.take_events(r);
    let dst = Destination::Short {
        address: sim.stack(r).short_address(),
        endpoint: EP,
    };

    // Fresh out of the box the Mode default keeps maintenance on: FAILURE.
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            wc::ID,
            EP,
            wc::CMD_GO_TO_LIFT_PERCENTAGE,
            Direction::ToServer,
            None,
            &[40],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        default_response(x.events(c), seq).is_some()
    }));
    assert_eq!(
        default_response(sim.events(c), seq),
        Some(ZclStatus::Failure)
    );
    assert!(
        !sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::WindowCovering { .. }))
    );
    sim.take_events(c);

    // The installer writes Mode = reversed, normal operation.
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: wc::MODE.id,
        value: Value::Bits {
            width: 1,
            bits: u64::from(wc::mode::REVERSED),
        },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    sim.stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            wc::ID,
            EP,
            command::WRITE_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    sim.run_for(Duration::from_secs(5));
    {
        let cl = sim.stack(r).zcl.cluster(EP, wc::ID, Role::Server).unwrap();
        assert!(!wc::in_maintenance(cl));
        let status = cl
            .attributes
            .value(wc::CONFIG_STATUS.id)
            .unwrap()
            .as_u64()
            .unwrap();
        assert_ne!(status & u64::from(wc::config_status::REVERSED), 0);
    }

    // Now the command is accepted and handed to the application.
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            wc::ID,
            EP,
            wc::CMD_GO_TO_LIFT_PERCENTAGE,
            Direction::ToServer,
            None,
            &[40],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(r).iter().any(|e| {
            matches!(
                e,
                StackEvent::WindowCovering {
                    endpoint: EP,
                    command: Command::LiftPercentage(40)
                }
            )
        })
    }));
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        default_response(x.events(c), seq) == Some(ZclStatus::Success)
    }));
    sim.take_events(c);

    // The motor arrives at 80 cm of 200: 40 %, reported to the client.
    {
        let cl = sim
            .stack(r)
            .zcl
            .cluster_mut(EP, wc::ID, Role::Server)
            .unwrap();
        assert!(wc::set_lift(cl, 80));
        assert_eq!(cl.u16(wc::NUMBER_OF_ACTUATIONS_LIFT.id), Some(1));
    }
    assert!(
        sim.run_until(Duration::from_secs(30), |x| reported_lift(x.events(c))
            .is_some()),
        "{:?}",
        sim.events(c)
    );
    assert_eq!(reported_lift(sim.events(c)), Some(40));
    sim.take_events(c);

    // A lift value beyond the installed closed limit is INVALID_VALUE.
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            wc::ID,
            EP,
            wc::CMD_GO_TO_LIFT_VALUE,
            Direction::ToServer,
            None,
            &[0xc9, 0x00],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        default_response(x.events(c), seq).is_some()
    }));
    assert_eq!(
        default_response(sim.events(c), seq),
        Some(ZclStatus::InvalidValue)
    );
    // Tilt is not supported by a rollershade.
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            wc::ID,
            EP,
            wc::CMD_GO_TO_TILT_PERCENTAGE,
            Direction::ToServer,
            None,
            &[10],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        default_response(x.events(c), seq).is_some()
    }));
    assert_eq!(
        default_response(sim.events(c), seq),
        Some(ZclStatus::UnsupportedClusterCommand)
    );
    sim.take_events(c);
    sim.take_events(r);

    // Store the 40 % position in a scene, move on, recall it: the
    // application is told to go back to 40 % over the transition time.
    for (cmd, payload) in [
        (groups::CMD_ADD_GROUP, &[0x01, 0x00, 0x00][..]),
        (scenes::CMD_STORE_SCENE, &[0x01, 0x00, 0x07][..]),
    ] {
        let cluster = if cmd == groups::CMD_ADD_GROUP {
            groups::ID
        } else {
            scenes::ID
        };
        sim.stack(c)
            .zcl
            .send_command(
                dst,
                ProfileId::HOME_AUTOMATION,
                cluster,
                EP,
                cmd,
                Direction::ToServer,
                None,
                payload,
            )
            .unwrap();
        sim.stack(c).flush();
        sim.run_for(Duration::from_secs(3));
    }
    {
        let cl = sim
            .stack(r)
            .zcl
            .cluster_mut(EP, wc::ID, Role::Server)
            .unwrap();
        assert!(wc::set_lift(cl, 200));
    }
    sim.run_for(Duration::from_secs(3));
    sim.take_events(r);
    sim.stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            scenes::ID,
            EP,
            scenes::CMD_RECALL_SCENE,
            Direction::ToServer,
            None,
            &[0x01, 0x00, 0x07, 0x14, 0x00],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| {
            x.events(r).iter().any(|e| {
                matches!(
                    e,
                    StackEvent::WindowCovering {
                        endpoint: EP,
                        command: Command::Scene {
                            lift: Some(40),
                            tilt: None,
                            tenths: 20
                        }
                    }
                )
            })
        }),
        "{:?}",
        sim.events(r)
    );
}
