//! General clusters at the runtime level: a router's Alarms server
//! notifying a bound coordinator of a Power Configuration battery alarm
//! (ZCL8 §3.3, §3.11) with a time stamp from its Time server, the alarm
//! log read back with Get Alarm, a Reset Alarm reaching the application,
//! and the Time server set over the network (§3.12). The Diagnostics
//! server outgrows `small-tables`.
#![cfg(not(feature = "small-tables"))]
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
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::{
    alarms, diagnostics, ias_zone, identify, power_configuration as power, time,
};
use panweave_zcl::frame::Direction;
use panweave_zcl::global::{AttributeValue, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::{DataType, Value};
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
    let (servers, clients): (&[ClusterId], &[ClusterId]) = match role {
        LogicalDeviceType::Router => {
            ep.add_instance(power::battery_server(30).unwrap()).unwrap();
            ep.add_instance(alarms::server().unwrap()).unwrap();
            // Not a master clock: the network may set it.
            ep.add_instance(time::server(0, false).unwrap()).unwrap();
            ep.add_instance(
                ias_zone::server(
                    ias_zone::zone_type::CONTACT_SWITCH,
                    0x1234,
                    ias_zone::EnrollMode::AutoRequest,
                    None,
                )
                .unwrap(),
            )
            .unwrap();
            ep.add_instance(diagnostics::server().unwrap()).unwrap();
            (
                &[
                    ClusterId(0),
                    identify::ID,
                    power::ID,
                    alarms::ID,
                    time::ID,
                    ias_zone::ID,
                    diagnostics::ID,
                ],
                &[identify::ID],
            )
        }
        _ => {
            ep.add_instance(alarms::client()).unwrap();
            ep.add_instance(time::client()).unwrap();
            ep.add_instance(ias_zone::client()).unwrap();
            (
                &[ClusterId(0), identify::ID],
                &[identify::ID, alarms::ID, time::ID, ias_zone::ID],
            )
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

fn alarm_received(events: &[StackEvent]) -> Option<alarms::Alarm> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclCommand(f)
            if f.origin.cluster == alarms::ID && f.origin.header.command == alarms::CMD_ALARM =>
        {
            alarms::Alarm::parse(&f.payload)
        }
        _ => None,
    })
}

#[test]
fn battery_alarm_reaches_the_bound_client_with_a_time_stamp() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
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
    sim.stack(r)
        .aps
        .bindings
        .bind(BindingEntry {
            src_endpoint: EP,
            cluster: alarms::ID,
            destination: BindingDestination::Unicast {
                address: COORD_IEEE,
                endpoint: EP,
            },
        })
        .unwrap();
    sim.run_for(Duration::from_secs(3));
    sim.take_events(c);

    // The coordinator sets the router's clock over the air.
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: time::TIME.id,
        value: Value::Time {
            ty: DataType::UtcTime,
            raw: 800_000_000,
        },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let dst = Destination::Short {
        address: sim.stack(r).short_address(),
        endpoint: EP,
    };
    sim.stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            time::ID,
            EP,
            command::WRITE_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| {
            x.events(r).iter().any(|e| {
                matches!(
                    e,
                    StackEvent::TimeSet {
                        endpoint: EP,
                        utc: 800_000_000
                    }
                )
            })
        }),
        "{:?}",
        sim.events(r)
    );
    sim.run_for(Duration::from_secs(5));
    let t = sim.stack(r).zcl.time(EP).unwrap();
    assert!((800_000_005..=800_000_007).contains(&t), "{t}");

    // A battery reading below the minimum threshold raises alarm 0x10.
    {
        let cl = sim
            .stack(r)
            .zcl
            .cluster_mut(EP, power::ID, Role::Server)
            .unwrap();
        cl.set_u8(power::BATTERY_VOLTAGE_MIN_THRESHOLD.id, 20);
        cl.set(
            power::BATTERY_ALARM_MASK.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(power::battery_alarm::MIN_THRESHOLD),
            },
        );
        let raised = power::set_battery(cl, Some(19), Some(10));
        assert_eq!(raised.as_slice(), &[(0x10, 1)]);
    }
    sim.stack(r).zcl.raise_alarm(EP, power::ID, 0x10).unwrap();
    sim.stack(r).flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| alarm_received(x.events(c))
            .is_some()),
        "{:?}",
        sim.events(c)
    );
    assert_eq!(
        alarm_received(sim.events(c)),
        Some(alarms::Alarm {
            code: 0x10,
            cluster: power::ID
        })
    );
    sim.take_events(c);
    // Get Alarm returns the logged entry with its time stamp, then the
    // log is empty (NOT_FOUND).
    for expect_entry in [true, false] {
        let seq = sim
            .stack(c)
            .zcl
            .send_command(
                dst,
                ProfileId::HOME_AUTOMATION,
                alarms::ID,
                EP,
                alarms::CMD_GET_ALARM,
                Direction::ToServer,
                None,
                &[],
            )
            .unwrap();
        sim.stack(c).flush();
        assert!(sim.run_until(Duration::from_secs(10), |x| {
            x.events(c).iter().any(|e| {
                matches!(
                    e,
                    StackEvent::ZclCommand(f)
                        if f.origin.header.seq == seq
                            && f.origin.header.command == alarms::CMD_GET_ALARM_RESPONSE
                )
            })
        }));
        let rsp = sim
            .events(c)
            .iter()
            .find_map(|e| match e {
                StackEvent::ZclCommand(f) if f.origin.header.seq == seq => Some(f.payload.clone()),
                _ => None,
            })
            .unwrap();
        let entry = alarms::parse_get_alarm_response(&rsp).unwrap();
        if expect_entry {
            let e = entry.unwrap();
            assert_eq!((e.code, e.cluster), (0x10, power::ID));
            assert!((800_000_005..=800_000_010).contains(&e.time), "{}", e.time);
        } else {
            assert_eq!(entry, None);
        }
        sim.take_events(c);
    }
    // Reset Alarm reaches the router's application.
    sim.stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            alarms::ID,
            EP,
            alarms::CMD_RESET_ALARM,
            Direction::ToServer,
            None,
            &[0x10, 0x01, 0x00],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(r).iter().any(|e| {
            matches!(
                e,
                StackEvent::AlarmReset {
                    endpoint: EP,
                    alarm: Some((0x10, ClusterId(0x0001)))
                }
            )
        })
    }));
    let _ = ShortAddress::COORDINATOR;
}

fn zone_command(events: &[StackEvent], cmd: panweave_types::CommandId) -> Option<Vec<u8>> {
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
fn ias_zone_auto_enroll_request_and_status_notification() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "cie",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "zone",
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
    sim.take_events(c);
    // A status change before the CIE is configured is not reported.
    assert!(
        sim.stack(r)
            .zcl
            .set_zone_status(EP, ias_zone::zone_status::ALARM1)
            .unwrap()
    );
    sim.run_for(Duration::from_secs(3));
    assert!(zone_command(sim.events(c), ias_zone::CMD_ZONE_STATUS_CHANGE_NOTIFICATION).is_none());
    // The CIE writes its address: the zone reports the pending status
    // and asks for enrolment (Auto-Enroll-Request).
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: ias_zone::IAS_CIE_ADDRESS.id,
        value: Value::Eui64(COORD_IEEE.0),
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let dst = Destination::Short {
        address: sim.stack(r).short_address(),
        endpoint: EP,
    };
    sim.stack(c)
        .zcl
        .send_global(
            dst,
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
    assert!(
        sim.run_until(Duration::from_secs(10), |x| {
            zone_command(x.events(c), ias_zone::CMD_ZONE_ENROLL_REQUEST).is_some()
        }),
        "{:?}",
        sim.events(c)
    );
    let req = ias_zone::EnrollRequest::parse(
        &zone_command(sim.events(c), ias_zone::CMD_ZONE_ENROLL_REQUEST).unwrap(),
    )
    .unwrap();
    assert_eq!(req.zone_type, ias_zone::zone_type::CONTACT_SWITCH);
    assert_eq!(req.manufacturer_code, 0x1234);
    let note = ias_zone::StatusChange::parse(
        &zone_command(sim.events(c), ias_zone::CMD_ZONE_STATUS_CHANGE_NOTIFICATION).unwrap(),
    )
    .unwrap();
    assert_eq!(note.zone_status, ias_zone::zone_status::ALARM1);
    assert_eq!(note.zone_id, ias_zone::ZONE_ID_NONE);
    assert!(note.delay >= 12, "delay {} quarter seconds", note.delay);
    sim.take_events(c);
    // The CIE enrols the zone as zone 3.
    sim.stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            ias_zone::ID,
            EP,
            ias_zone::CMD_ZONE_ENROLL_RESPONSE,
            Direction::ToServer,
            None,
            &ias_zone::enroll_response(ias_zone::enroll_code::SUCCESS, 3),
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(r).iter().any(|e| {
            matches!(
                e,
                StackEvent::ZoneEnrolled {
                    endpoint: EP,
                    zone_id: 3
                }
            )
        })
    }));
    // A restore is notified promptly with the zone identifier.
    assert!(sim.stack(r).zcl.set_zone_status(EP, 0).unwrap());
    sim.stack(r).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        zone_command(x.events(c), ias_zone::CMD_ZONE_STATUS_CHANGE_NOTIFICATION).is_some()
    }));
    let note = ias_zone::StatusChange::parse(
        &zone_command(sim.events(c), ias_zone::CMD_ZONE_STATUS_CHANGE_NOTIFICATION).unwrap(),
    )
    .unwrap();
    assert_eq!((note.zone_status, note.zone_id), (0, 3));
    assert!(note.delay <= 4, "delay {}", note.delay);
    // The Diagnostics server reflects the traffic so far.
    assert!(sim.stack(r).refresh_diagnostics(EP));
    let d = sim
        .stack(r)
        .zcl
        .cluster(EP, diagnostics::ID, Role::Server)
        .unwrap();
    assert!(d.u64(diagnostics::MAC_TX_UCAST.id).unwrap() > 0);
    assert!(d.u64(diagnostics::MAC_RX_UCAST.id).unwrap() > 0);
    assert!(d.u64(diagnostics::MAC_RX_BCAST.id).unwrap() > 0);
    assert!(d.u16(diagnostics::APS_RX_UCAST.id).unwrap() > 0);
    assert!(d.u16(diagnostics::APS_TX_UCAST_SUCCESS.id).unwrap() > 0);
    assert!(d.u16(diagnostics::NEIGHBOR_ADDED.id).unwrap() > 0);
    assert_eq!(d.u16(diagnostics::JOIN_INDICATION.id), Some(0));
    assert_eq!(d.u16(diagnostics::APS_FC_FAILURE.id), Some(0));
    assert_eq!(
        d.u16(diagnostics::PHY_TO_MAC_QUEUE_LIMIT_REACHED.id),
        Some(0)
    );
    assert_eq!(d.u8(diagnostics::LAST_MESSAGE_LQI.id), Some(200));
    assert_eq!(d.u16(diagnostics::NWK_DECRYPT_FAILURES.id), Some(0));
    assert!(!sim.stack(r).refresh_diagnostics(Endpoint(9)));
}
