//! Appliance Management clusters through the endpoint dispatcher (ZCL8
//! Chapter 15): Signal State answered from the server state, control
//! commands handed to the application, alerts / events / logs notified
//! to the bound clients and served on request.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use panweave_aps::Destination;
use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::GroupTable;
use panweave_codec::{Decode, Encode};
use panweave_types::time::Instant;
use panweave_types::{ClusterId, CommandId, Endpoint, ProfileId, ShortAddress};
use panweave_zcl::clusters::appliance::{control, events_alerts, identification, statistics};
use panweave_zcl::clusters::{basic, identify};
use panweave_zcl::frame::{Direction, Frame, FrameType, Header, ZclStatus};
use panweave_zcl::global::{DefaultResponse, command};
use panweave_zcl::layer::{EndpointInstance, Zcl, ZclAction, ZclEvent, ZclIndication};

const CLIENT: ShortAddress = ShortAddress(0x1234);
const EP: Endpoint = Endpoint(1);
const T0: Instant = Instant::from_millis(1000);

type Node = Zcl<2, 12, 36>;

fn washing_machine() -> Node {
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(
        basic::server(basic::power_source::MAINS_SINGLE_PHASE, b"Panweave", b"WM").unwrap(),
    )
    .unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(control::server(true).unwrap()).unwrap();
    ep.add_instance(
        identification::server(identification::BasicIdentification {
            company: 1,
            brand: 2,
            product_type: identification::product_type::WASHING_MACHINE,
            spec_version: 0x1a,
        })
        .unwrap(),
    )
    .unwrap();
    ep.add_instance(events_alerts::server()).unwrap();
    ep.add_instance(statistics::server().unwrap()).unwrap();
    zcl.add_endpoint(ep).unwrap();
    zcl.poll_timers(T0);
    zcl
}

fn ind<'a>(cluster: ClusterId, asdu: &'a [u8]) -> DataIndication<'a> {
    DataIndication {
        src: CLIENT,
        src_endpoint: Endpoint(5),
        src_ieee: None,
        delivery: Delivery::Endpoint(EP),
        profile: ProfileId::HOME_AUTOMATION,
        cluster,
        asdu,
        security: SecurityStatus::NwkKey,
        lqi: 200,
        relayed: None,
        counter: 0,
        nwk_broadcast: false,
    }
}

fn frame(header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = Frame {
        header: *header,
        payload,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    buf[..n].to_vec()
}

/// Sends a cluster-specific command to the server; returns the first
/// reply and whether the command was handed over as an indication.
fn command(
    zcl: &mut Node,
    cluster: ClusterId,
    cmd: CommandId,
    payload: &[u8],
) -> (Option<(Header, Vec<u8>)>, bool) {
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(0x21),
        cmd,
        Direction::ToServer,
    );
    let bytes = frame(&header, payload);
    let mut groups = GroupTable::<4>::new();
    while zcl.next_action().is_some() {}
    let handed = matches!(
        zcl.on_data(&ind(cluster, &bytes), &mut groups),
        Some(ZclIndication::Command { .. })
    );
    let reply = match zcl.next_action() {
        Some(ZclAction::Send { frame, .. }) => {
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            Some((h, frame[n..].to_vec()))
        }
        None => None,
    };
    (reply, handed)
}

fn default_status(reply: Option<(Header, Vec<u8>)>) -> ZclStatus {
    let (h, p) = reply.expect("a reply");
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    DefaultResponse::decode_exact(&p).unwrap().status
}

fn bound_send(zcl: &mut Node, cluster: ClusterId) -> (Header, Vec<u8>) {
    match zcl.next_action() {
        Some(ZclAction::Send {
            destination,
            cluster: c,
            frame,
            ..
        }) => {
            assert_eq!(destination, Destination::Bound);
            assert_eq!(c, cluster);
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            assert_eq!(h.control.frame_type, FrameType::ClusterSpecific);
            assert_eq!(h.control.direction, Direction::ToClient);
            (h, frame[n..].to_vec())
        }
        None => panic!("nothing sent"),
    }
}

#[test]
fn appliance_control_is_executed_by_the_application() {
    let mut zcl = washing_machine();
    // Signal State: answered from the (initial) state.
    let (reply, handed) = command(&mut zcl, control::ID, control::CMD_SIGNAL_STATE, &[]);
    assert!(!handed);
    let (h, p) = reply.unwrap();
    assert_eq!(h.command, control::CMD_SIGNAL_STATE_RESPONSE);
    assert_eq!(
        control::SignalState::parse(&p).unwrap(),
        control::SignalState::default()
    );
    // Execution of a Command: the application is told, then reports
    // the new state, which is notified to the bound clients.
    let (reply, _) = command(
        &mut zcl,
        control::ID,
        control::CMD_EXECUTION_OF_A_COMMAND,
        &[control::command_id::START],
    );
    assert_eq!(default_status(reply), ZclStatus::Success);
    assert!(matches!(
        zcl.next_event(),
        Some(ZclEvent::ApplianceCommand {
            endpoint: EP,
            command: control::command_id::START
        })
    ));
    let running = control::SignalState {
        status: control::status::RUNNING,
        remote_enable: control::remote_enable::ENABLED_REMOTE_CONTROL,
        ..Default::default()
    };
    assert!(zcl.appliance_signal_state(EP, running).unwrap());
    let (h, p) = bound_send(&mut zcl, control::ID);
    assert_eq!(h.command, control::CMD_SIGNAL_STATE_NOTIFICATION);
    assert_eq!(control::SignalState::parse(&p).unwrap(), running);
    assert!(!zcl.appliance_signal_state(EP, running).unwrap());
    assert!(zcl.next_action().is_none());
    // Overload commands become events; Write Functions is handed over.
    let (reply, _) = command(&mut zcl, control::ID, control::CMD_OVERLOAD_PAUSE, &[]);
    assert_eq!(default_status(reply), ZclStatus::Success);
    assert!(matches!(
        zcl.next_event(),
        Some(ZclEvent::ApplianceOverload {
            overload: control::Overload::Pause,
            ..
        })
    ));
    let (reply, handed) = command(
        &mut zcl,
        control::ID,
        control::CMD_WRITE_FUNCTIONS,
        &[0x00, 0x00, 0x21, 0x5e, 0x12],
    );
    assert!(reply.is_none());
    assert!(handed);
    let (reply, handed) = command(&mut zcl, control::ID, control::CMD_OVERLOAD_WARNING, &[9]);
    assert!(!handed);
    assert_eq!(default_status(reply), ZclStatus::MalformedCommand);
}

#[test]
fn alerts_events_and_logs_are_notified_and_served() {
    let mut zcl = washing_machine();
    let alert = events_alerts::Alert {
        id: 3,
        category: events_alerts::category::WARNING,
        present: true,
        manufacturer: 0,
    };
    zcl.appliance_alert(EP, alert).unwrap();
    let (h, p) = bound_send(&mut zcl, events_alerts::ID);
    assert_eq!(h.command, events_alerts::CMD_ALERTS_NOTIFICATION);
    assert_eq!(
        events_alerts::parse_alerts(&p).unwrap().as_slice(),
        &[alert]
    );
    let (reply, _) = command(
        &mut zcl,
        events_alerts::ID,
        events_alerts::CMD_GET_ALERTS,
        &[],
    );
    let (h, p) = reply.unwrap();
    assert_eq!(h.command, events_alerts::CMD_GET_ALERTS_RESPONSE);
    assert_eq!(
        events_alerts::parse_alerts(&p).unwrap().as_slice(),
        &[alert]
    );
    zcl.appliance_event(EP, events_alerts::event::END_OF_CYCLE)
        .unwrap();
    let (h, p) = bound_send(&mut zcl, events_alerts::ID);
    assert_eq!(h.command, events_alerts::CMD_EVENT_NOTIFICATION);
    assert_eq!(
        events_alerts::parse_event(&p).unwrap(),
        events_alerts::event::END_OF_CYCLE
    );
    // Logs: notified when stored, listed and retrieved on request.
    assert_eq!(zcl.appliance_log(EP, b"cycle 1").unwrap(), 0);
    let (h, p) = bound_send(&mut zcl, statistics::ID);
    assert_eq!(h.command, statistics::CMD_LOG_NOTIFICATION);
    let log = statistics::Log::parse(&p).unwrap();
    assert_eq!((log.id, log.timestamp), (0, statistics::NO_TIME));
    assert_eq!(log.payload.as_slice(), b"cycle 1");
    assert_eq!(zcl.appliance_log(EP, b"cycle 2").unwrap(), 1);
    zcl.appliance_statistics_available(EP).unwrap();
    while zcl.next_action().is_some() {}
    let (reply, _) = command(
        &mut zcl,
        statistics::ID,
        statistics::CMD_LOG_QUEUE_REQUEST,
        &[],
    );
    let (h, p) = reply.unwrap();
    assert_eq!(h.command, statistics::CMD_LOG_QUEUE_RESPONSE);
    assert_eq!(statistics::parse_ids(&p).unwrap().as_slice(), &[0, 1]);
    let (reply, _) = command(
        &mut zcl,
        statistics::ID,
        statistics::CMD_LOG_REQUEST,
        &1u32.to_le_bytes(),
    );
    let (h, p) = reply.unwrap();
    assert_eq!(h.command, statistics::CMD_LOG_RESPONSE);
    assert_eq!(
        statistics::Log::parse(&p).unwrap().payload.as_slice(),
        b"cycle 2"
    );
    let (reply, _) = command(
        &mut zcl,
        statistics::ID,
        statistics::CMD_LOG_REQUEST,
        &7u32.to_le_bytes(),
    );
    assert_eq!(default_status(reply), ZclStatus::NotFound);
    // Identification is attribute-only.
    let c = zcl
        .cluster(EP, identification::ID, panweave_zcl::Role::Server)
        .unwrap();
    assert_eq!(
        identification::basic(c).unwrap().product_type,
        identification::product_type::WASHING_MACHINE
    );
}
