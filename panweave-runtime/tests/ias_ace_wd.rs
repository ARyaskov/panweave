//! A security system at the runtime level (ZCL8 §8.3, §8.4): a CIE
//! coordinator running the IAS ACE server, a keypad router (ACE
//! client) and a warning device router (IAS Zone + IAS WD servers). The
//! keypad arms the panel with the code, the CIE sends Start Warning to
//! the siren (which reports it to its application and stops after the
//! duration), and an enrolled zone's status change is relayed by the
//! CIE to the bound keypad as Zone Status Changed.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_codec::{Encode, Writer};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, CommandId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::ias_ace::{self as ace, Request};
use panweave_zcl::clusters::{ias_wd, ias_zone, identify};
use panweave_zcl::frame::Direction;
use panweave_zcl::global::{AttributeValue, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::Value;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const CIE_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const KEYPAD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0005);
const SIREN_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0006);
const EP: Endpoint = Endpoint(1);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Cie,
    Keypad,
    Siren,
}

fn node(kind: Kind, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let role = if kind == Kind::Cie {
        LogicalDeviceType::Coordinator
    } else {
        LogicalDeviceType::Router
    };
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
    let (servers, clients, device): (&[ClusterId], &[ClusterId], DeviceId) = match kind {
        Kind::Cie => {
            ep.add_instance(ace::server(Some(ace::Code::new(b"4321").unwrap())))
                .unwrap();
            ep.add_instance(ias_zone::client()).unwrap();
            ep.add_instance(ias_wd::client()).unwrap();
            (
                &[ClusterId(0), identify::ID, ace::ID],
                &[identify::ID, ias_zone::ID, ias_wd::ID],
                DeviceId(0x0400),
            )
        }
        Kind::Keypad => {
            ep.add_instance(ace::client()).unwrap();
            (
                &[ClusterId(0), identify::ID],
                &[identify::ID, ace::ID],
                DeviceId(0x0401),
            )
        }
        Kind::Siren => {
            ep.add_instance(
                ias_zone::server(
                    ias_zone::zone_type::STANDARD_WARNING_DEVICE,
                    0x1234,
                    ias_zone::EnrollMode::AutoRequest,
                    None,
                )
                .unwrap(),
            )
            .unwrap();
            ep.add_instance(ias_wd::server(60).unwrap()).unwrap();
            (
                &[ClusterId(0), identify::ID, ias_zone::ID, ias_wd::ID],
                &[identify::ID],
                DeviceId(0x0403),
            )
        }
    };
    let desc =
        SimpleDescriptor::new(EP, ProfileId::HOME_AUTOMATION, device, 1, servers, clients).unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

fn ace_frame(events: &[StackEvent], cmd: CommandId) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclCommand(f) | StackEvent::ZclResponse(f)
            if f.origin.cluster == ace::ID && f.origin.header.command == cmd =>
        {
            Some(f.payload.to_vec())
        }
        _ => None,
    })
}

fn zone_frame(events: &[StackEvent], cmd: CommandId) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclCommand(f)
            if f.origin.cluster == ias_zone::ID && f.origin.header.command == cmd =>
        {
            Some(f.payload.to_vec())
        }
        _ => None,
    })
}

#[test]
fn keypad_arms_the_cie_which_warns_the_siren_and_relays_zone_status() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "cie",
        node(Kind::Cie, CIE_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let k = sim.add_stack(
        "keypad",
        node(Kind::Keypad, KEYPAD_IEEE, 42),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "siren",
        node(Kind::Siren, SIREN_IEEE, 43),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    for n in [k, s] {
        sim.stack(n).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| {
            x.events(n)
                .iter()
                .any(|e| matches!(e, StackEvent::Joined { .. }))
        }));
    }
    // The CIE's ACE server is bound to the keypad.
    sim.stack(c)
        .aps
        .bindings
        .bind(BindingEntry {
            src_endpoint: EP,
            cluster: ace::ID,
            destination: BindingDestination::Unicast {
                address: KEYPAD_IEEE,
                endpoint: EP,
            },
        })
        .unwrap();
    sim.run_for(Duration::from_secs(3));
    let cie = Destination::Short {
        address: sim.stack(c).short_address(),
        endpoint: EP,
    };
    let siren = Destination::Short {
        address: sim.stack(s).short_address(),
        endpoint: EP,
    };
    sim.take_events(c);
    sim.take_events(k);
    sim.take_events(s);

    // Enrol the siren's zone as zone 7 (Auto-Enroll-Request).
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: ias_zone::IAS_CIE_ADDRESS.id,
        value: Value::Eui64(CIE_IEEE.0),
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    sim.stack(c)
        .zcl
        .send_global(
            siren,
            ProfileId::HOME_AUTOMATION,
            ias_zone::ID,
            EP,
            command::WRITE_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        zone_frame(x.events(c), ias_zone::CMD_ZONE_ENROLL_REQUEST).is_some()
    }));
    sim.stack(c)
        .zcl
        .send_command(
            siren,
            ProfileId::HOME_AUTOMATION,
            ias_zone::ID,
            EP,
            ias_zone::CMD_ZONE_ENROLL_RESPONSE,
            Direction::ToServer,
            None,
            &ias_zone::enroll_response(ias_zone::enroll_code::SUCCESS, 7),
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(s)
            .iter()
            .any(|e| matches!(e, StackEvent::ZoneEnrolled { zone_id: 7, .. }))
    }));
    {
        let panel = sim
            .stack(c)
            .zcl
            .cluster_mut(EP, ace::ID, Role::Server)
            .unwrap();
        ace::add_zone(
            panel,
            ace::Zone {
                id: 7,
                zone_type: ias_zone::zone_type::STANDARD_WARNING_DEVICE,
                address: SIREN_IEEE.0,
                status: 0,
                bypassed: false,
                bypass_allowed: true,
                label: heapless::Vec::from_slice(b"siren").unwrap(),
            },
        )
        .unwrap();
    }
    sim.take_events(c);
    sim.take_events(k);

    // The keypad arms all zones with the code.
    let n = ace::encode_arm(ace::arm_mode::ALL, b"4321", 0xff, &mut buf).unwrap();
    sim.stack(k)
        .zcl
        .send_command(
            cie,
            ProfileId::HOME_AUTOMATION,
            ace::ID,
            EP,
            ace::CMD_ARM,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(k).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        ace_frame(x.events(k), ace::CMD_ARM_RESPONSE).is_some()
    }));
    assert_eq!(
        ace_frame(sim.events(k), ace::CMD_ARM_RESPONSE).unwrap(),
        vec![ace::arm_notification::ALL_ZONES_ARMED]
    );
    assert!(sim.events(c).iter().any(|e| matches!(
        e,
        StackEvent::Ace {
            endpoint: EP,
            request: Request::Arm {
                mode: ace::arm_mode::ALL,
                zone_id: 0xff
            }
        }
    )));
    sim.take_events(k);
    // The keypad asks for the panel status.
    sim.stack(k)
        .zcl
        .send_command(
            cie,
            ProfileId::HOME_AUTOMATION,
            ace::ID,
            EP,
            ace::CMD_GET_PANEL_STATUS,
            Direction::ToServer,
            None,
            &[],
        )
        .unwrap();
    sim.stack(k).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        ace_frame(x.events(k), ace::CMD_GET_PANEL_STATUS_RESPONSE).is_some()
    }));
    let p = ace::PanelStatus::parse(
        &ace_frame(sim.events(k), ace::CMD_GET_PANEL_STATUS_RESPONSE).unwrap(),
    )
    .unwrap();
    assert_eq!(p.status, ace::panel_status::ARMED_AWAY);
    sim.take_events(k);

    // The CIE starts a 5 s burglar warning on the siren.
    let warning = ias_wd::Warning {
        mode: ias_wd::warning_mode::BURGLAR,
        strobe: true,
        siren_level: ias_wd::level::HIGH,
        duration: 5,
        strobe_duty_cycle: 50,
        strobe_level: ias_wd::level::HIGH,
    };
    let n = warning.encode(&mut buf).unwrap();
    sim.stack(c)
        .zcl
        .send_command(
            siren,
            ProfileId::HOME_AUTOMATION,
            ias_wd::ID,
            EP,
            ias_wd::CMD_START_WARNING,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(3), |x| {
        x.events(s).iter().any(|e| {
            matches!(
                e,
                StackEvent::Warning {
                    endpoint: EP,
                    warning: Some(w)
                } if *w == warning
            )
        })
    }));
    assert!(
        sim.stack(s)
            .zcl
            .cluster(EP, ias_wd::ID, Role::Server)
            .is_some_and(ias_wd::is_warning)
    );
    sim.take_events(s);
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(s).iter().any(|e| {
            matches!(
                e,
                StackEvent::Warning {
                    endpoint: EP,
                    warning: None
                }
            )
        })
    }));

    // The siren's zone trips: the CIE relays it to the keypad.
    sim.take_events(k);
    assert!(
        sim.stack(s)
            .zcl
            .set_zone_status(EP, ias_zone::zone_status::ALARM1)
            .unwrap()
    );
    sim.stack(s).flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| {
            ace_frame(x.events(k), ace::CMD_ZONE_STATUS_CHANGED).is_some()
        }),
        "{:?}",
        sim.events(k)
    );
    let changed = ace_frame(sim.events(k), ace::CMD_ZONE_STATUS_CHANGED).unwrap();
    let z = ace::ZoneStatusChanged::parse(&changed).unwrap();
    assert_eq!(
        (z.zone_id, z.status, z.label),
        (7, ias_zone::zone_status::ALARM1, &b"siren"[..])
    );
    // The CIE goes into alarm and tells the keypad.
    sim.take_events(k);
    sim.stack(c)
        .zcl
        .ace_set_panel_status(
            EP,
            ace::panel_status::IN_ALARM,
            0,
            ace::alarm_status::BURGLAR,
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        ace_frame(x.events(k), ace::CMD_PANEL_STATUS_CHANGED).is_some()
    }));
    let p =
        ace::PanelStatus::parse(&ace_frame(sim.events(k), ace::CMD_PANEL_STATUS_CHANGED).unwrap())
            .unwrap();
    assert_eq!(
        (p.status, p.alarm),
        (ace::panel_status::IN_ALARM, ace::alarm_status::BURGLAR)
    );
}
