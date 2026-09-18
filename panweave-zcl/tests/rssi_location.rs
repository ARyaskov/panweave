//! RSSI Location through the endpoint dispatcher (ZCL8 §3.13): location
//! and configuration requests answered, repeated responses and ping
//! blasts driven by the timer, RSSI responses collected into a report,
//! anchor announcements and recalculation requests handed over.

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
use panweave_types::time::{Duration, Instant};
use panweave_types::{CommandId, Endpoint, ExtendedAddress, ProfileId, ShortAddress};
use panweave_zcl::clusters::rssi_location as rssi;
use panweave_zcl::clusters::{basic, identify};
use panweave_zcl::frame::{Direction, Frame, Header, ZclStatus};
use panweave_zcl::global::{DefaultResponse, command};
use panweave_zcl::layer::{EndpointInstance, Zcl, ZclAction, ZclEvent};

const CLIENT: ShortAddress = ShortAddress(0x1234);
const EP: Endpoint = Endpoint(1);
const OWN: ExtendedAddress = ExtendedAddress(0x00aa_bbcc_ddee_ff01);
const T0: Instant = Instant::from_millis(1000);

type Node = Zcl<2, 12, 36>;

fn node() -> Node {
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(
        basic::server(basic::power_source::MAINS_SINGLE_PHASE, b"Panweave", b"Tag").unwrap(),
    )
    .unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(rssi::server(OWN, rssi::method::CENTRALIZED).unwrap())
        .unwrap();
    zcl.add_endpoint(ep).unwrap();
    zcl.poll_timers(T0);
    zcl
}

fn ind<'a>(asdu: &'a [u8]) -> DataIndication<'a> {
    DataIndication {
        src: CLIENT,
        src_endpoint: Endpoint(5),
        src_ieee: None,
        delivery: Delivery::Endpoint(EP),
        profile: ProfileId::HOME_AUTOMATION,
        cluster: rssi::ID,
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

fn command(zcl: &mut Node, cmd: CommandId, payload: &[u8]) -> Option<(Header, Vec<u8>)> {
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(0x21),
        cmd,
        Direction::ToServer,
    );
    let bytes = frame(&header, payload);
    let mut groups = GroupTable::<4>::new();
    while zcl.next_action().is_some() {}
    let out = zcl.on_data(&ind(&bytes), &mut groups);
    assert!(out.is_none(), "executed by the layer");
    match zcl.next_action()? {
        ZclAction::Send { frame, .. } => {
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            Some((h, frame[n..].to_vec()))
        }
    }
}

fn default_status(reply: Option<(Header, Vec<u8>)>) -> ZclStatus {
    let (h, p) = reply.expect("a reply");
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    DefaultResponse::decode_exact(&p).unwrap().status
}

fn sent(zcl: &mut Node) -> (Header, Vec<u8>, Destination) {
    match zcl.next_action() {
        Some(ZclAction::Send {
            destination,
            cluster,
            frame,
            ..
        }) => {
            assert_eq!(cluster, rssi::ID);
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            (h, frame[n..].to_vec(), destination)
        }
        None => panic!("nothing sent"),
    }
}

#[test]
fn location_requests_are_answered_and_repeated() {
    let mut zcl = node();
    let mut buf = [0u8; 32];
    // Nothing known yet: a unicast request for another device is NOT_FOUND.
    let g = rssi::GetLocationData {
        absolute_only: false,
        recalculate: false,
        broadcast_indicator: false,
        broadcast_response: false,
        compact_response: false,
        number_responses: 1,
        target: Some(ExtendedAddress(7)),
    };
    let n = g.encode(&mut buf).unwrap();
    let (h, p) = command(&mut zcl, rssi::CMD_GET_LOCATION_DATA, &buf[..n]).unwrap();
    assert_eq!(h.command, rssi::CMD_LOCATION_DATA_RESPONSE);
    assert_eq!(
        rssi::parse_location_response(&p).unwrap(),
        (ZclStatus::NotFound, None)
    );
    // The application measured a location; a request with recalculate
    // and three responses answers at once and asks for a recalculation.
    zcl.rssi_location_measured(EP, (10, 20, Some(30)), 75, 3)
        .unwrap();
    let g = rssi::GetLocationData {
        recalculate: true,
        compact_response: true,
        number_responses: 3,
        target: Some(OWN),
        ..g
    };
    let n = g.encode(&mut buf).unwrap();
    let (h, p) = command(&mut zcl, rssi::CMD_GET_LOCATION_DATA, &buf[..n]).unwrap();
    assert_eq!(h.command, rssi::CMD_LOCATION_DATA_RESPONSE);
    let (status, Some(l)) = rssi::parse_location_response(&p).unwrap() else {
        panic!("no location");
    };
    assert_eq!(status, ZclStatus::Success);
    assert_eq!(
        (l.coordinate1, l.coordinate2, l.coordinate3),
        (10, 20, Some(30))
    );
    assert_eq!(l.calculated.unwrap().quality, 75);
    assert!(matches!(
        zcl.next_event(),
        Some(ZclEvent::LocationRecalculate { endpoint: EP })
    ));
    // ReportingPeriod is 0: the follow-ups come one second apart as
    // compact notifications unicast to the requester.
    zcl.poll_timers(T0 + Duration::from_secs(1));
    let (h, p, d) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_COMPACT_LOCATION_DATA_NOTIFICATION);
    assert_eq!(
        d,
        Destination::Short {
            address: CLIENT,
            endpoint: Endpoint(5)
        }
    );
    assert_eq!(rssi::LocationData::parse(&p, true).unwrap().coordinate1, 10);
    assert!(zcl.next_action().is_none());
    zcl.poll_timers(T0 + Duration::from_secs(2));
    let (h, _, _) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_COMPACT_LOCATION_DATA_NOTIFICATION);
    zcl.poll_timers(T0 + Duration::from_secs(3));
    assert!(zcl.next_action().is_none());
    // Set Absolute Location fixes the location; Set Device Configuration
    // is then refused, Get Device Configuration answered.
    let a = rssi::AbsoluteLocation {
        coordinate1: 100,
        coordinate2: 200,
        coordinate3: 300,
        power: -4000,
        path_loss_exponent: 250,
    };
    let n = a.encode(&mut buf).unwrap();
    assert_eq!(
        default_status(command(
            &mut zcl,
            rssi::CMD_SET_ABSOLUTE_LOCATION,
            &buf[..n]
        )),
        ZclStatus::Success
    );
    let cfg = rssi::DeviceConfiguration {
        power: -4000,
        path_loss_exponent: 250,
        calculation_period: 100,
        number_rssi_measurements: 2,
        reporting_period: 0,
    };
    let n = cfg.encode(&mut buf).unwrap();
    assert_eq!(
        default_status(command(
            &mut zcl,
            rssi::CMD_SET_DEVICE_CONFIGURATION,
            &buf[..n]
        )),
        ZclStatus::Failure
    );
    let n = rssi::encode_address(OWN, &mut buf).unwrap();
    let (h, p) = command(&mut zcl, rssi::CMD_GET_DEVICE_CONFIGURATION, &buf[..n]).unwrap();
    assert_eq!(h.command, rssi::CMD_DEVICE_CONFIGURATION_RESPONSE);
    let (status, Some(c)) = rssi::parse_configuration_response(&p).unwrap() else {
        panic!("no configuration");
    };
    assert_eq!(status, ZclStatus::Success);
    assert_eq!((c.power, c.path_loss_exponent), (-4000, 250));
    // An absolute location answers absolute-only broadcasts with the
    // full response (no calculation fields).
    let g = rssi::GetLocationData {
        absolute_only: true,
        recalculate: false,
        broadcast_indicator: true,
        number_responses: 1,
        target: None,
        ..g
    };
    let n = g.encode(&mut buf).unwrap();
    let (h, p) = command(&mut zcl, rssi::CMD_GET_LOCATION_DATA, &buf[..n]).unwrap();
    assert_eq!(h.command, rssi::CMD_LOCATION_DATA_RESPONSE);
    let (_, Some(l)) = rssi::parse_location_response(&p).unwrap() else {
        panic!("no location");
    };
    assert!(l.location_type.absolute && l.calculated.is_none());
    assert_eq!(l.coordinate3, Some(300));
}

#[test]
fn pings_rssi_reports_and_anchors() {
    let mut zcl = node();
    let mut buf = [0u8; 32];
    // Send Pings: two RSSI Pings 100 ms apart, broadcast.
    let p = rssi::SendPings {
        target: OWN,
        number_rssi_measurements: 2,
        calculation_period: 100,
    };
    let n = p.encode(&mut buf).unwrap();
    assert_eq!(
        default_status(command(&mut zcl, rssi::CMD_SEND_PINGS, &buf[..n])),
        ZclStatus::Success
    );
    zcl.poll_timers(T0);
    let (h, p, d) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_RSSI_PING);
    assert_eq!(p, [0x00]);
    assert_eq!(
        d,
        Destination::Short {
            address: ShortAddress::BROADCAST_RX_ON,
            endpoint: Endpoint::BROADCAST
        }
    );
    assert!(zcl.next_action().is_none());
    zcl.poll_timers(T0 + Duration::from_millis(100));
    let (h, _, _) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_RSSI_PING);
    zcl.poll_timers(T0 + Duration::from_millis(200));
    assert!(zcl.next_action().is_none());
    // An RSSI Request goes out; the neighbours' RSSI Responses are
    // collected and reported to the bound central device after
    // CalculationPeriod.
    zcl.rssi_request(EP).unwrap();
    let (h, p, _) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_RSSI_REQUEST);
    assert!(p.is_empty());
    let info = rssi::NeighborInfo {
        neighbor: ExtendedAddress(2),
        x: 1,
        y: 2,
        z: 3,
        rssi: -61,
        measurements: 2,
    };
    let n = info.encode(&mut buf).unwrap();
    let t = T0 + Duration::from_secs(5);
    zcl.poll_timers(t);
    assert_eq!(
        default_status(command(&mut zcl, rssi::CMD_RSSI_RESPONSE, &buf[..n])),
        ZclStatus::Success
    );
    zcl.poll_timers(t + Duration::from_millis(100));
    let (h, p, d) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_REPORT_RSSI_MEASUREMENTS);
    assert_eq!(d, Destination::Bound);
    let report = rssi::RssiReport::parse(&p).unwrap();
    assert_eq!(report.measuring, OWN);
    assert_eq!(report.neighbors.as_slice(), &[info]);
    // Request Own Location goes to the central device; an anchor's
    // announcement reaches the application.
    zcl.rssi_request_own_location(EP).unwrap();
    let (h, p, d) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_REQUEST_OWN_LOCATION);
    assert_eq!(d, Destination::Bound);
    assert_eq!(rssi::parse_address(&p).unwrap(), OWN);
    let a = rssi::AnchorNodeAnnounce {
        anchor: ExtendedAddress(3),
        x: 5,
        y: 6,
        z: rssi::UNKNOWN,
    };
    let n = a.encode(&mut buf).unwrap();
    assert_eq!(
        default_status(command(&mut zcl, rssi::CMD_ANCHOR_NODE_ANNOUNCE, &buf[..n])),
        ZclStatus::Success
    );
    assert!(matches!(
        zcl.next_event(),
        Some(ZclEvent::AnchorNode { endpoint: EP, announce }) if announce == a
    ));
    // A periodic notification runs at ReportingPeriod.
    let cfg = rssi::DeviceConfiguration {
        power: -4000,
        path_loss_exponent: 250,
        calculation_period: 100,
        number_rssi_measurements: 2,
        reporting_period: 30,
    };
    let n = cfg.encode(&mut buf).unwrap();
    let t2 = T0 + Duration::from_secs(60);
    zcl.poll_timers(t2);
    assert_eq!(
        default_status(command(
            &mut zcl,
            rssi::CMD_SET_DEVICE_CONFIGURATION,
            &buf[..n]
        )),
        ZclStatus::Success
    );
    assert_eq!(zcl.next_deadline(), Some(t2 + Duration::from_secs(30)));
    zcl.poll_timers(t2 + Duration::from_secs(30));
    let (h, _, d) = sent(&mut zcl);
    assert_eq!(h.command, rssi::CMD_LOCATION_DATA_NOTIFICATION);
    assert_eq!(d, Destination::Bound);
}
