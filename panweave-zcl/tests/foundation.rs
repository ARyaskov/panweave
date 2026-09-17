//! ZCL foundation behaviour: global commands against a server endpoint,
//! Default Responses, cluster-specific dispatch and attribute reporting.

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
use panweave_codec::{Decode, Encode, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId, CommandId, Endpoint, ProfileId, ShortAddress};
use panweave_zcl::clusters::{basic, identify, on_off};
use panweave_zcl::frame::{Direction, Frame, FrameType, Header, ZclStatus};
use panweave_zcl::global::{
    self, AttributeValue, ConfigureReportingStatus, DefaultResponse, DiscoverAttributes,
    DiscoverAttributesResponse, ReadAttributeStatus, Records, ReportingConfig,
    WriteAttributeStatus, command,
};
use panweave_zcl::layer::{EndpointInstance, Zcl, ZclAction, ZclEvent, ZclIndication};
use panweave_zcl::types::DataType;
use panweave_zcl::{Role, Value as V};

const CLIENT: ShortAddress = ShortAddress(0x1234);
const SERVER_EP: Endpoint = Endpoint(1);

type Node = Zcl<2, 4, 8>;

fn server() -> Node {
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(SERVER_EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(
        basic::server(
            basic::power_source::MAINS_SINGLE_PHASE,
            b"Panweave",
            b"Lamp",
        )
        .unwrap(),
    )
    .unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    // An application-executed cluster (Temperature Measurement server).
    ep.add_cluster(
        panweave_zcl::ClusterDef {
            id: ClusterId(0x0402),
            revision: 1,
            received: &[],
            generated: &[],
        },
        Role::Server,
    )
    .unwrap();
    zcl.add_endpoint(ep).unwrap();
    zcl.poll_timers(Instant::from_millis(1000));
    zcl
}

fn ind<'a>(cluster: ClusterId, asdu: &'a [u8], broadcast: bool) -> DataIndication<'a> {
    DataIndication {
        src: CLIENT,
        src_endpoint: Endpoint(5),
        src_ieee: None,
        delivery: Delivery::Endpoint(SERVER_EP),
        profile: ProfileId::HOME_AUTOMATION,
        cluster,
        asdu,
        security: SecurityStatus::NwkKey,
        lqi: 200,
        relayed: None,
        counter: 0,
        nwk_broadcast: broadcast,
    }
}

fn frame(header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 96];
    let n = Frame {
        header: *header,
        payload,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    buf[..n].to_vec()
}

/// Sends a global command and returns the (header, payload) of the reply.
fn exchange(
    zcl: &mut Node,
    cluster: ClusterId,
    cmd: CommandId,
    payload: &[u8],
) -> Option<(Header, Vec<u8>, Destination)> {
    let header = Header::global(
        panweave_types::TransactionSequence(0x33),
        cmd,
        Direction::ToServer,
    );
    let bytes = frame(&header, payload);
    let out = zcl.on_data(&ind(cluster, &bytes, false), &mut GroupTable::<4>::new());
    assert!(out.is_none(), "global commands are handled internally");
    match zcl.next_action()? {
        ZclAction::Send {
            destination,
            cluster: c,
            frame,
            src_endpoint,
            ..
        } => {
            assert_eq!(c, cluster);
            assert_eq!(src_endpoint, SERVER_EP);
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            Some((h, frame[n..].to_vec(), destination))
        }
    }
}

#[test]
fn read_write_and_discover_attributes() {
    let mut zcl = server();
    // Read OnOff, ClusterRevision and an unknown attribute.
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    global::write_attribute_ids(
        &mut w,
        &[AttributeId(0), AttributeId(0xFFFD), AttributeId(0x0042)],
    )
    .unwrap();
    let n = w.position();
    let (h, p, dst) = exchange(&mut zcl, on_off::ID, command::READ_ATTRIBUTES, &buf[..n]).unwrap();
    assert_eq!(h.command, command::READ_ATTRIBUTES_RESPONSE);
    assert_eq!(h.control.direction, Direction::ToClient);
    assert!(h.control.disable_default_response);
    assert_eq!(h.seq.0, 0x33);
    assert!(
        matches!(dst, Destination::Short { address, endpoint } if address == CLIENT && endpoint == Endpoint(5))
    );
    let recs: Vec<ReadAttributeStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0].value, Some(V::Bool(Some(false))));
    assert_eq!(recs[1].value, Some(V::Uint { width: 2, value: 2 }));
    assert_eq!(recs[2].status, ZclStatus::UnsupportedAttribute);

    // Write: OnOff is read-only, IdentifyTime is writable, wrong type.
    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: AttributeId(0),
        value: V::Bool(Some(true)),
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let (h, p, _) = exchange(&mut zcl, on_off::ID, command::WRITE_ATTRIBUTES, &buf[..n]).unwrap();
    assert_eq!(h.command, command::WRITE_ATTRIBUTES_RESPONSE);
    let st: Vec<WriteAttributeStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(
        st,
        vec![WriteAttributeStatus {
            status: ZclStatus::ReadOnly,
            id: Some(AttributeId(0))
        }]
    );

    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: AttributeId(0),
        value: V::Uint {
            width: 2,
            value: 30,
        },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let (_, p, _) = exchange(&mut zcl, identify::ID, command::WRITE_ATTRIBUTES, &buf[..n]).unwrap();
    assert_eq!(p, vec![0x00], "single SUCCESS record without identifier");
    assert_eq!(
        zcl.cluster(SERVER_EP, identify::ID, Role::Server)
            .unwrap()
            .attributes
            .value(AttributeId(0)),
        Some(V::Uint {
            width: 2,
            value: 30
        })
    );
    let mut w = Writer::new(&mut buf);
    AttributeValue {
        id: AttributeId(0),
        value: V::Uint { width: 1, value: 3 },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.position();
    let (_, p, _) = exchange(&mut zcl, identify::ID, command::WRITE_ATTRIBUTES, &buf[..n]).unwrap();
    assert_eq!(p[0], ZclStatus::InvalidDataType.raw());

    // Discover attributes of Basic starting at 0x0004, max 2.
    let req = DiscoverAttributes {
        start: AttributeId(0x0004),
        max: 2,
    };
    let n = req.encode_to_slice(&mut buf).unwrap();
    let (h, p, _) = exchange(&mut zcl, basic::ID, command::DISCOVER_ATTRIBUTES, &buf[..n]).unwrap();
    assert_eq!(h.command, command::DISCOVER_ATTRIBUTES_RESPONSE);
    let rsp = DiscoverAttributesResponse::parse(&p, false).unwrap();
    assert!(!rsp.complete);
    let infos: Vec<_> = rsp.iter().collect();
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0].id, AttributeId(0x0004));
    assert_eq!(infos[0].ty, DataType::CharString);
    assert_eq!(infos[1].id, AttributeId(0x0005));
    let req = DiscoverAttributes {
        start: AttributeId(0x0006),
        max: 10,
    };
    let n = req.encode_to_slice(&mut buf).unwrap();
    let (_, p, _) = exchange(
        &mut zcl,
        basic::ID,
        command::DISCOVER_ATTRIBUTES_EXTENDED,
        &buf[..n],
    )
    .unwrap();
    let rsp = DiscoverAttributesResponse::parse(&p, true).unwrap();
    assert!(rsp.complete);
    let infos: Vec<_> = rsp.iter().collect();
    assert_eq!(infos.last().unwrap().id, AttributeId(0xFFFD));
    assert_eq!(infos[0].access, Some(0x01));
}

#[test]
fn default_responses_and_cluster_specific_commands() {
    let mut zcl = server();
    // Unknown cluster: Default Response UNSUPPORTED_CLUSTER.
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(7),
        CommandId(1),
        Direction::ToServer,
    );
    let bytes = frame(&header, &[]);
    assert!(
        zcl.on_data(
            &ind(ClusterId(0x0500), &bytes, false),
            &mut GroupTable::<4>::new()
        )
        .is_none()
    );
    let ZclAction::Send {
        frame: f, cluster, ..
    } = zcl.next_action().unwrap();
    assert_eq!(cluster, ClusterId(0x0500));
    let (h, n) = Header::decode_prefix(&f).unwrap();
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    assert_eq!(h.control.frame_type, FrameType::Global);
    let dr = DefaultResponse::decode_exact(&f[n..]).unwrap();
    assert_eq!(
        dr,
        DefaultResponse {
            command: CommandId(1),
            status: ZclStatus::UnsupportedCluster
        }
    );
    // Same via broadcast: silence.
    assert!(
        zcl.on_data(
            &ind(ClusterId(0x0500), &bytes, true),
            &mut GroupTable::<4>::new()
        )
        .is_none()
    );
    assert!(zcl.next_action().is_none());

    // On command: executed by the layer, reported as an event and
    // answered with a Default Response.
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(8),
        on_off::CMD_ON,
        Direction::ToServer,
    );
    let bytes = frame(&header, &[]);
    let out = zcl.on_data(&ind(on_off::ID, &bytes, false), &mut GroupTable::<4>::new());
    assert!(out.is_none(), "On/Off is executed by the layer");
    let c = zcl.cluster(SERVER_EP, on_off::ID, Role::Server).unwrap();
    assert!(on_off::is_on(c));
    assert_eq!(
        zcl.next_event(),
        Some(ZclEvent::OnOff {
            endpoint: SERVER_EP,
            on: true
        })
    );
    let ZclAction::Send { frame: f, .. } = zcl.next_action().unwrap();
    let (h, n) = Header::decode_prefix(&f).unwrap();
    assert_eq!(h.seq.0, 8);
    assert_eq!(
        DefaultResponse::decode_exact(&f[n..]).unwrap().command,
        on_off::CMD_ON
    );
    // With Disable Default Response set and success: nothing.
    let header = header.disable_default_response(true);
    let bytes = frame(&header, &[]);
    assert!(
        zcl.on_data(&ind(on_off::ID, &bytes, false), &mut GroupTable::<4>::new())
            .is_none()
    );
    assert!(zcl.next_action().is_none());
    assert!(zcl.next_event().is_none(), "no change, no event");
    // A cluster-specific command for a cluster the layer does not
    // execute reaches the application.
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(10),
        CommandId(0x00),
        Direction::ToServer,
    )
    .disable_default_response(true);
    let bytes = frame(&header, &[1, 2]);
    let Some(ZclIndication::Command { origin, payload }) = zcl.on_data(
        &ind(ClusterId(0x0402), &bytes, false),
        &mut GroupTable::<4>::new(),
    ) else {
        panic!("expected command");
    };
    assert_eq!(payload, &[1, 2]);
    assert_eq!(origin.endpoint, SERVER_EP);
    zcl.default_response(&origin, ZclStatus::Success).unwrap();
    assert!(zcl.next_action().is_none());
    zcl.default_response(&origin, ZclStatus::InvalidField)
        .unwrap();
    assert!(zcl.next_action().is_some(), "errors are always reported");

    // Unsupported global command → UNSUP_GENERAL_COMMAND.
    let header = Header::global(
        panweave_types::TransactionSequence(9),
        CommandId(0x7f),
        Direction::ToServer,
    );
    let bytes = frame(&header, &[]);
    assert!(
        zcl.on_data(&ind(on_off::ID, &bytes, false), &mut GroupTable::<4>::new())
            .is_none()
    );
    let ZclAction::Send { frame: f, .. } = zcl.next_action().unwrap();
    let (_, n) = Header::decode_prefix(&f).unwrap();
    assert_eq!(
        DefaultResponse::decode_exact(&f[n..]).unwrap().status,
        ZclStatus::UnsupportedGeneralCommand
    );
}

#[test]
fn reporting_configuration_and_reports() {
    let mut zcl = server();
    let mut buf = [0u8; 32];
    // Configure OnOff: min 1 s, max 60 s.
    let cfg = ReportingConfig::Reported {
        id: AttributeId(0),
        ty: DataType::Bool,
        min: 1,
        max: 60,
        change: None,
    };
    let n = cfg.encode_to_slice(&mut buf).unwrap();
    let (h, p, _) = exchange(
        &mut zcl,
        on_off::ID,
        command::CONFIGURE_REPORTING,
        &buf[..n],
    )
    .unwrap();
    assert_eq!(h.command, command::CONFIGURE_REPORTING_RESPONSE);
    let st: Vec<ConfigureReportingStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(
        st,
        vec![ConfigureReportingStatus {
            status: ZclStatus::Success,
            target: None
        }]
    );
    // Unreportable (ClusterRevision) and wrong type.
    let bad = ReportingConfig::Reported {
        id: AttributeId(0xFFFD),
        ty: DataType::Uint(2),
        min: 0,
        max: 0,
        change: Some(V::Uint { width: 2, value: 1 }),
    };
    let n = bad.encode_to_slice(&mut buf).unwrap();
    let (_, p, _) = exchange(
        &mut zcl,
        on_off::ID,
        command::CONFIGURE_REPORTING,
        &buf[..n],
    )
    .unwrap();
    let st: Vec<ConfigureReportingStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(st[0].status, ZclStatus::UnreportableAttribute);
    let bad = ReportingConfig::Reported {
        id: AttributeId(0),
        ty: DataType::Uint(1),
        min: 0,
        max: 0,
        change: Some(V::Uint { width: 1, value: 1 }),
    };
    let n = bad.encode_to_slice(&mut buf).unwrap();
    let (_, p, _) = exchange(
        &mut zcl,
        on_off::ID,
        command::CONFIGURE_REPORTING,
        &buf[..n],
    )
    .unwrap();
    assert_eq!(p[0], ZclStatus::InvalidDataType.raw());

    // Read back the configuration.
    let rr = global::ReadReportingConfig {
        direction: global::ReportDirection::Reported,
        id: AttributeId(0),
    };
    let n = rr.encode_to_slice(&mut buf).unwrap();
    let (h, p, _) = exchange(
        &mut zcl,
        on_off::ID,
        command::READ_REPORTING_CONFIGURATION,
        &buf[..n],
    )
    .unwrap();
    assert_eq!(h.command, command::READ_REPORTING_CONFIGURATION_RESPONSE);
    let st = global::ReadReportingConfigStatus::decode_exact(&p).unwrap();
    assert_eq!(st.status, ZclStatus::Success);
    assert_eq!(
        st.config,
        ReportingConfig::Reported {
            id: AttributeId(0),
            ty: DataType::Bool,
            min: 1,
            max: 60,
            change: None
        }
    );

    // No report yet; a change reports after the minimum interval.
    zcl.poll_timers(Instant::from_millis(1500));
    assert!(zcl.next_action().is_none());
    zcl.set_on_off(SERVER_EP, true).unwrap();
    let _ = zcl.next_event();
    zcl.poll_timers(Instant::from_millis(1900));
    assert!(zcl.next_action().is_none(), "minimum interval");
    zcl.poll_timers(Instant::from_millis(2000));
    let ZclAction::Send {
        destination,
        frame: f,
        cluster,
        ..
    } = zcl.next_action().expect("report");
    assert_eq!(destination, Destination::Bound);
    assert_eq!(cluster, on_off::ID);
    let (h, n) = Header::decode_prefix(&f).unwrap();
    assert_eq!(h.command, command::REPORT_ATTRIBUTES);
    assert_eq!(h.control.direction, Direction::ToClient);
    let recs: Vec<AttributeValue> = Records::new(&f[n..]).map(Result::unwrap).collect();
    assert_eq!(
        recs,
        vec![AttributeValue {
            id: AttributeId(0),
            value: V::Bool(Some(true))
        }]
    );
    // Periodic report at the maximum interval.
    assert_eq!(zcl.next_deadline(), Some(Instant::from_millis(62_000)));
    zcl.poll_timers(Instant::from_millis(61_999));
    assert!(zcl.next_action().is_none());
    zcl.poll_timers(Instant::from_millis(62_000));
    assert!(zcl.next_action().is_some());

    // Reports arriving at a client instance are handed to the app.
    let mut client = Node::new();
    let mut ep = EndpointInstance::new(Endpoint(5), ProfileId::HOME_AUTOMATION);
    ep.add_cluster(on_off::DEF, Role::Client).unwrap();
    client.add_endpoint(ep).unwrap();
    let mut rep = DataIndication {
        ..ind(on_off::ID, &f, false)
    };
    rep.delivery = Delivery::Endpoint(Endpoint(5));
    let out = client.on_data(&rep, &mut GroupTable::<4>::new());
    assert!(matches!(out, Some(ZclIndication::Report { .. })));
    assert!(
        client.next_action().is_none(),
        "reports with DDR set need no Default Response"
    );

    let _ = Duration::from_secs(0);
}

#[test]
fn group_delivery_targets_member_endpoints_only() {
    let mut zcl = server();
    let mut ep2 = EndpointInstance::new(Endpoint(2), ProfileId::HOME_AUTOMATION);
    ep2.add_instance(on_off::server().unwrap()).unwrap();
    zcl.add_endpoint(ep2).unwrap();
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(1),
        on_off::CMD_ON,
        Direction::ToServer,
    );
    let bytes = frame(&header, &[]);
    let mut i = ind(on_off::ID, &bytes, true);
    i.delivery = Delivery::Group(panweave_types::GroupAddress(1));
    let mut groups = GroupTable::<4>::new();
    groups
        .add(panweave_types::GroupAddress(1), Endpoint(2))
        .unwrap();
    let out = zcl.on_data(&i, &mut groups);
    assert!(out.is_none(), "On/Off is executed by the layer");
    assert_eq!(
        zcl.next_event(),
        Some(ZclEvent::OnOff {
            endpoint: Endpoint(2),
            on: true
        })
    );
    assert!(zcl.next_event().is_none(), "endpoint 1 is not a member");
    assert!(
        !on_off::is_on(zcl.cluster(SERVER_EP, on_off::ID, Role::Server).unwrap()),
        "endpoint 1 untouched"
    );
    assert!(
        zcl.next_action().is_none(),
        "no Default Response to a groupcast"
    );
}

#[test]
fn identify_server_countdown_and_query() {
    let mut zcl = server();
    let now = Instant::from_millis(1000);
    let cs = |seq: u8, cmd: CommandId| {
        Header::cluster_specific(
            panweave_types::TransactionSequence(seq),
            cmd,
            Direction::ToServer,
        )
    };
    // Not identifying: a broadcast Identify Query is silently ignored.
    let q = frame(&cs(1, identify::CMD_IDENTIFY_QUERY), &[]);
    assert!(
        zcl.on_data(&ind(identify::ID, &q, true), &mut GroupTable::<4>::new())
            .is_none()
    );
    assert!(zcl.next_action().is_none());
    assert!(zcl.next_event().is_none());

    // Identify(3 s): attribute set, Default Response, event.
    let id = frame(&cs(2, identify::CMD_IDENTIFY), &3u16.to_le_bytes());
    assert!(
        zcl.on_data(&ind(identify::ID, &id, false), &mut GroupTable::<4>::new())
            .is_none()
    );
    assert_eq!(
        zcl.next_event(),
        Some(ZclEvent::Identify {
            endpoint: SERVER_EP,
            seconds: 3
        })
    );
    let Some(ZclAction::Send { frame: f, .. }) = zcl.next_action() else {
        panic!("default response expected");
    };
    let (h, n) = Header::decode_prefix(&f).unwrap();
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    assert_eq!(
        DefaultResponse::decode_exact(&f[n..]).unwrap().status,
        ZclStatus::Success
    );
    assert_eq!(
        identify::identify_time(zcl.cluster(SERVER_EP, identify::ID, Role::Server).unwrap()),
        3
    );
    assert_eq!(zcl.next_deadline(), Some(now + Duration::from_secs(1)));

    // Identify Query while identifying → unicast Identify Query Response
    // with the remaining time.
    assert!(
        zcl.on_data(&ind(identify::ID, &q, true), &mut GroupTable::<4>::new())
            .is_none()
    );
    let Some(ZclAction::Send {
        destination,
        frame: f,
        ..
    }) = zcl.next_action()
    else {
        panic!("query response expected");
    };
    assert_eq!(
        destination,
        Destination::Short {
            address: CLIENT,
            endpoint: Endpoint(5)
        }
    );
    let (h, n) = Header::decode_prefix(&f).unwrap();
    assert_eq!(h.control.frame_type, FrameType::ClusterSpecific);
    assert_eq!(h.control.direction, Direction::ToClient);
    assert_eq!(h.command, identify::CMD_IDENTIFY_QUERY_RESPONSE);
    assert_eq!(&f[n..], &3u16.to_le_bytes());

    // Countdown: one decrement per second, event at each step, stops at 0.
    zcl.poll_timers(now + Duration::from_millis(1000));
    assert_eq!(
        zcl.next_event(),
        Some(ZclEvent::Identify {
            endpoint: SERVER_EP,
            seconds: 2
        })
    );
    zcl.poll_timers(now + Duration::from_millis(2000));
    zcl.poll_timers(now + Duration::from_millis(3000));
    assert_eq!(
        zcl.next_event(),
        Some(ZclEvent::Identify {
            endpoint: SERVER_EP,
            seconds: 1
        })
    );
    assert_eq!(
        zcl.next_event(),
        Some(ZclEvent::Identify {
            endpoint: SERVER_EP,
            seconds: 0
        })
    );
    // Only the OnOff default report (5 min after construction) remains.
    assert_eq!(zcl.next_deadline(), Some(Instant::from_millis(300_000)));
    assert!(
        zcl.on_data(&ind(identify::ID, &q, true), &mut GroupTable::<4>::new())
            .is_none()
    );
    assert!(zcl.next_action().is_none());

    // Trigger Effect is surfaced to the application.
    let te = frame(&cs(3, identify::CMD_TRIGGER_EFFECT), &[0x01, 0x00]);
    assert!(
        zcl.on_data(&ind(identify::ID, &te, false), &mut GroupTable::<4>::new())
            .is_none()
    );
    assert_eq!(
        zcl.next_event(),
        Some(ZclEvent::TriggerEffect {
            endpoint: SERVER_EP,
            effect: 1,
            variant: 0
        })
    );
}

/// Sends `header` to `cluster` and returns the Default Response status,
/// or the response header when a real response came back.
fn reply(zcl: &mut Node, cluster: ClusterId, header: &Header, payload: &[u8]) -> (Header, Vec<u8>) {
    let bytes = frame(header, payload);
    let _ = zcl.on_data(&ind(cluster, &bytes, false), &mut GroupTable::<4>::new());
    let ZclAction::Send { frame, .. } = zcl.next_action().expect("a reply");
    let (h, n) = Header::decode_prefix(&frame).unwrap();
    (h, frame[n..].to_vec())
}

#[test]
fn manufacturer_specific_clusters_need_their_code() {
    use panweave_types::ManufacturerCode;
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(SERVER_EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(
        basic::server(
            basic::power_source::MAINS_SINGLE_PHASE,
            b"Panweave",
            b"Lamp",
        )
        .unwrap(),
    )
    .unwrap();
    zcl.add_endpoint(ep).unwrap();
    let ms = ClusterId(0xfc01);
    let code = ManufacturerCode(0x1234);
    // A manufacturer-specific cluster with one attribute.
    let mut c: panweave_zcl::ClusterInstance<8> = panweave_zcl::ClusterInstance::new(
        panweave_zcl::ClusterDef {
            id: ms,
            revision: 1,
            received: &[CommandId(0)],
            generated: &[],
        },
        Role::Server,
    )
    .manufacturer_specific(code);
    c.add_attribute(
        panweave_zcl::AttributeDef::new(0x0000, DataType::Uint(1), panweave_zcl::Access::RO),
        &V::Uint { width: 1, value: 7 },
    )
    .unwrap();
    zcl.endpoint_mut(SERVER_EP)
        .unwrap()
        .add_instance(c)
        .unwrap();
    let seq = panweave_types::TransactionSequence(9);
    let mut ids = [0u8; 2];
    let mut w = Writer::new(&mut ids);
    global::write_attribute_ids(&mut w, &[AttributeId(0)]).unwrap();
    // Without the manufacturer code the cluster is not there.
    let (h, p) = reply(
        &mut zcl,
        ms,
        &Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer),
        &ids,
    );
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    assert_eq!(
        DefaultResponse::decode_exact(&p).unwrap().status,
        ZclStatus::UnsupportedCluster
    );
    // Another manufacturer's code is not recognised.
    let (h, p) = reply(
        &mut zcl,
        ms,
        &Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer)
            .with_manufacturer(ManufacturerCode(0x4321)),
        &ids,
    );
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    assert_eq!(
        DefaultResponse::decode_exact(&p).unwrap().status,
        ZclStatus::UnsupportedManufacturerGeneralCommand
    );
    let (h, p) = reply(
        &mut zcl,
        ms,
        &Header::cluster_specific(seq, CommandId(0), Direction::ToServer)
            .with_manufacturer(ManufacturerCode(0x4321)),
        &[],
    );
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    assert_eq!(
        DefaultResponse::decode_exact(&p).unwrap().status,
        ZclStatus::UnsupportedManufacturerClusterCommand
    );
    // The right code reads the attribute (the response echoes the code).
    let (h, p) = reply(
        &mut zcl,
        ms,
        &Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer).with_manufacturer(code),
        &ids,
    );
    assert_eq!(h.command, command::READ_ATTRIBUTES_RESPONSE);
    assert_eq!(h.manufacturer, Some(code));
    let recs: Vec<ReadAttributeStatus> = Records::new(&p).map(Result::unwrap).collect();
    assert_eq!(recs[0].value, Some(V::Uint { width: 1, value: 7 }));
    // Standard clusters keep ignoring the code as before.
    let (h, _) = reply(
        &mut zcl,
        basic::ID,
        &Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer),
        &ids,
    );
    assert_eq!(h.command, command::READ_ATTRIBUTES_RESPONSE);
}
