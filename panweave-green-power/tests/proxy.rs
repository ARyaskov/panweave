//! The Basic Proxy end to end at the crate level: pairings, tunnelling
//! of unsecured and secured GPDFs with the right destinations, aliases
//! and delays, duplicate and freshness filtering, commissioning mode and
//! the Proxy Table Request.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::{Decode, Encode};
use panweave_green_power::cluster::{
    self, CommissioningNotification, CommunicationMode, GppGpdLink, Notification, Pairing,
    ProxyCommissioningMode, ProxyTableRequest, ProxyTableResponse, Response, SinkAddress,
    TableStatus,
};
use panweave_green_power::command;
use panweave_green_power::gpdf::{GpdId, Gpdf, SecurityLevel, mac_header};
use panweave_green_power::proxy::{
    Alias, DMIN_UNIDIRECTIONAL, DUPLICATE_TIMEOUT, Destination, Outgoing, PairingError, Proxy,
    ProxyConfig, ProxyEvent,
};
use panweave_green_power::proxy_table::{ProxyEntry, derived_alias};
use panweave_green_power::security::KeyType;
use panweave_mac::frame::{Frame as MacFrame, MacAddress};
use panweave_security::cipher::SoftwareAes;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ExtendedAddress, Key128, ShortAddress};

const PROXY_SHORT: ShortAddress = ShortAddress(0x1234);
const PROXY_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0010);
const SINK_SHORT: ShortAddress = ShortAddress(0x0000);
const SINK_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const GPD: GpdId = GpdId::SrcId(0x8765_4321);
const KEY: Key128 = Key128::from_bytes([
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
]);
/// §A.1.5.4.2.1 (after the PHY length octet).
const LEVEL2: [u8; 22] = [
    0x01, 0x08, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x8C, 0x10, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00,
    0x00, 0x20, 0xCF, 0x78, 0x7E, 0x72,
];
const T0: Instant = Instant::from_millis(10_000);
const LINK: GppGpdLink = GppGpdLink(0xC0);

type Basic = Proxy<4>;

fn proxy() -> Basic {
    let mut p = Basic::new(ProxyConfig::new(PROXY_SHORT, PROXY_IEEE));
    p.poll(T0);
    p
}

fn unsecured_gpdf(buf: &mut [u8; 40], seq: u8, src_id: u32, command: u8, payload: &[u8]) -> usize {
    let mut body = [0u8; 32];
    body[0] = 0x0C;
    body[1..5].copy_from_slice(&src_id.to_le_bytes());
    body[5] = command;
    body[6..6 + payload.len()].copy_from_slice(payload);
    MacFrame {
        header: mac_header(
            seq,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body[..6 + payload.len()],
    }
    .encode_to_slice(buf)
    .unwrap()
}

fn feed(p: &mut Basic, frame: &[u8]) {
    let mac = MacFrame::decode_exact(frame).unwrap();
    let g = Gpdf::decode(&mac).unwrap();
    p.on_gpdf::<SoftwareAes>(&g, LINK);
}

fn drain(p: &mut Basic) -> Vec<Outgoing> {
    let mut v = Vec::new();
    while let Some(o) = p.next_outgoing() {
        v.push(o);
    }
    v
}

fn events(p: &mut Basic) -> Vec<ProxyEvent> {
    let mut v = Vec::new();
    while let Some(e) = p.next_event() {
        v.push(e);
    }
    v
}

fn pairing(mode: CommunicationMode, sink: SinkAddress) -> Pairing {
    Pairing {
        gpd: GPD,
        add_sink: true,
        remove_gpd: false,
        mode,
        gpd_fixed: false,
        sequence_number_capable: false,
        security_level_raw: 0,
        key_type: KeyType::None,
        sink: Some(sink),
        device_id: Some(0x02),
        frame_counter: None,
        key: None,
        assigned_alias: None,
        groupcast_radius: None,
    }
}

#[test]
fn unsecured_gpdf_is_tunnelled_to_every_paired_sink() {
    let mut p = proxy();
    // Nothing is forwarded for an unknown GPD.
    let mut buf = [0u8; 40];
    let n = unsecured_gpdf(&mut buf, 1, 0x8765_4321, command::TOGGLE, &[]);
    feed(&mut p, &buf[..n]);
    assert!(drain(&mut p).is_empty());
    // Pair: derived groupcast and lightweight unicast.
    p.on_pairing(
        &pairing(
            CommunicationMode::DerivedGroupcast,
            SinkAddress::Group(0x4321),
        ),
        false,
    );
    p.on_pairing(
        &pairing(
            CommunicationMode::LightweightUnicast,
            SinkAddress::Unicast(SINK_IEEE, SINK_SHORT),
        ),
        false,
    );
    assert_eq!(
        events(&mut p),
        vec![ProxyEvent::TableChanged, ProxyEvent::TableChanged]
    );
    let e = p.table.find(&GPD).unwrap();
    assert!(e.derived_group);
    assert_eq!(e.lightweight_sinks.as_slice(), &[(SINK_IEEE, SINK_SHORT)]);
    // The same frame again (new sequence number) is tunnelled twice.
    let n = unsecured_gpdf(&mut buf, 2, 0x8765_4321, command::TOGGLE, &[]);
    feed(&mut p, &buf[..n]);
    let out = drain(&mut p);
    assert_eq!(out.len(), 2);
    let unicast = out
        .iter()
        .find(|o| o.destination == Destination::Unicast(SINK_SHORT))
        .expect("lightweight unicast");
    assert_eq!(unicast.alias, None);
    assert_eq!(unicast.not_before, T0 + DMIN_UNIDIRECTIONAL);
    assert_eq!(unicast.command, cluster::client_cmd::NOTIFICATION);
    let group = out
        .iter()
        .find(|o| o.destination == Destination::Group(0x4321))
        .expect("derived groupcast");
    assert_eq!(
        group.alias,
        Some(Alias {
            address: derived_alias(&GPD),
            sequence: 2
        })
    );
    let nt = Notification::decode_exact(&unicast.payload).unwrap();
    assert_eq!(nt.gpd, GPD);
    assert_eq!(nt.command_id, command::TOGGLE);
    assert_eq!(nt.frame_counter, 2, "MAC sequence for unprotected frames");
    assert_eq!(nt.security_level, SecurityLevel::None);
    assert!(nt.also_unicast && nt.also_derived_group && !nt.also_commissioned_group);
    assert!(nt.tx_queue_full && !nt.bidirectional);
    assert_eq!(nt.proxy, Some((PROXY_SHORT, LINK)));
    assert!(p.table.find(&GPD).unwrap().in_range);
    // A duplicate within gpDuplicateTimeout is dropped; after it, it is a
    // new frame.
    feed(&mut p, &buf[..n]);
    assert!(drain(&mut p).is_empty());
    p.poll(T0 + DUPLICATE_TIMEOUT);
    feed(&mut p, &buf[..n]);
    assert_eq!(drain(&mut p).len(), 2);
    // Removing the unicast sink leaves the group; removing the group
    // empties and deletes the entry.
    let mut rm = pairing(
        CommunicationMode::LightweightUnicast,
        SinkAddress::Unicast(SINK_IEEE, SINK_SHORT),
    );
    rm.add_sink = false;
    rm.device_id = None;
    p.on_pairing(&rm, false);
    assert!(p.table.find(&GPD).unwrap().lightweight_sinks.is_empty());
    let mut rm = pairing(
        CommunicationMode::DerivedGroupcast,
        SinkAddress::Group(0x4321),
    );
    rm.add_sink = false;
    rm.device_id = None;
    p.on_pairing(&rm, false);
    assert!(p.table.find(&GPD).is_none());
    // A unicast pairing for an unsupported mode is refused.
    p.on_pairing(
        &pairing(
            CommunicationMode::FullUnicast,
            SinkAddress::Unicast(SINK_IEEE, SINK_SHORT),
        ),
        true,
    );
    assert_eq!(
        events(&mut p).last(),
        Some(&ProxyEvent::PairingRejected(PairingError::InvalidField))
    );
}

#[test]
fn secured_gpdf_needs_matching_security_and_freshness() {
    let mut p = proxy();
    let mut pr = pairing(
        CommunicationMode::CommissionedGroupcast,
        SinkAddress::Group(0x0042),
    );
    pr.security_level_raw = SecurityLevel::Mic.raw();
    pr.key_type = KeyType::GroupKey;
    pr.key = Some(KEY.clone());
    pr.frame_counter = Some(1);
    pr.assigned_alias = Some(ShortAddress(0x0100));
    pr.groupcast_radius = Some(3);
    p.on_pairing(&pr, true);
    assert!(
        events(&mut p)
            .iter()
            .all(|e| *e == ProxyEvent::TableChanged)
    );
    // The §A.1.5.4.2 frame (counter 2) is verified and forwarded to the
    // commissioned group with its alias and sequence − 9.
    feed(&mut p, &LEVEL2);
    let out = drain(&mut p);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].destination, Destination::Group(0x0042));
    assert_eq!(
        out[0].alias,
        Some(Alias {
            address: ShortAddress(0x0100),
            sequence: 2u8.wrapping_sub(9)
        })
    );
    assert_eq!(out[0].radius, 3);
    let n = Notification::decode_exact(&out[0].payload).unwrap();
    assert_eq!(n.security_level, SecurityLevel::Mic);
    assert_eq!(n.key_type, KeyType::GroupKey);
    assert_eq!(n.frame_counter, 2);
    // The vector's "0x20 (OFF)" is the Table 54 On command.
    assert_eq!(n.command_id, command::ON);
    assert!(n.also_commissioned_group && !n.also_unicast && !n.also_derived_group);
    assert_eq!(p.table.find(&GPD).unwrap().frame_counter, 2);
    // Replayed later: not fresh any more (counter 2 ≤ stored 2).
    p.poll(T0 + Duration::from_secs(5));
    feed(&mut p, &LEVEL2);
    assert!(drain(&mut p).is_empty());
    // A tampered MIC fails; nothing is forwarded in operational mode.
    let mut bad = LEVEL2;
    bad[13] = 0x03; // counter 3, MIC no longer valid
    feed(&mut p, &bad);
    assert!(drain(&mut p).is_empty());
    assert_eq!(p.table.find(&GPD).unwrap().frame_counter, 2);
    // An unprotected frame from a GPD paired with security is dropped.
    let mut buf = [0u8; 40];
    let n = unsecured_gpdf(&mut buf, 9, 0x8765_4321, command::TOGGLE, &[]);
    feed(&mut p, &buf[..n]);
    assert!(drain(&mut p).is_empty());
}

#[test]
fn commissioning_mode_forwards_commissioning_frames() {
    let mut p = proxy();
    // Out of commissioning mode a Commissioning GPDF from an unknown GPD
    // is dropped.
    let mut buf = [0u8; 40];
    let n = unsecured_gpdf(
        &mut buf,
        20,
        0x0000_0042,
        command::COMMISSIONING,
        &[0x02, 0x80, 0x00],
    );
    feed(&mut p, &buf[..n]);
    assert!(drain(&mut p).is_empty());
    // Enter commissioning mode (broadcast notifications, 60 s window,
    // exit on first pairing).
    p.on_commissioning_mode(
        &ProxyCommissioningMode {
            enter: true,
            exit_on_first_pairing: true,
            exit_on_command: false,
            unicast: false,
            window_secs: Some(60),
            channel: None,
        },
        SINK_SHORT,
    );
    assert_eq!(
        events(&mut p),
        vec![ProxyEvent::CommissioningMode(Some(
            T0 + Duration::from_secs(60)
        ))]
    );
    assert!(
        p.next_deadline()
            .is_some_and(|t| t.as_millis() <= (T0 + Duration::from_secs(60)).as_millis())
    );
    let n = unsecured_gpdf(
        &mut buf,
        21,
        0x0000_0042,
        command::COMMISSIONING,
        &[0x02, 0x80, 0x00],
    );
    feed(&mut p, &buf[..n]);
    let out = drain(&mut p);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].destination, Destination::Broadcast);
    assert_eq!(
        out[0].command,
        cluster::client_cmd::COMMISSIONING_NOTIFICATION
    );
    assert_eq!(
        out[0].alias,
        Some(Alias {
            address: derived_alias(&GpdId::SrcId(0x42)),
            sequence: 21u8.wrapping_sub(12)
        })
    );
    let c = CommissioningNotification::decode_exact(&out[0].payload).unwrap();
    assert_eq!(c.gpd, GpdId::SrcId(0x42));
    assert_eq!(c.command_id, command::COMMISSIONING);
    assert_eq!(c.payload, &[0x02, 0x80, 0x00]);
    assert!(!c.security_failed && c.mic.is_none());
    assert_eq!(c.frame_counter, 21);
    // A Channel Request (Maintenance frame) is forwarded with RxAfterTx
    // and GPD ID 0.
    let body = [0x0D, command::CHANNEL_REQUEST, 0x85];
    let n = MacFrame {
        header: mac_header(
            22,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    feed(&mut p, &buf[..n]);
    let out = drain(&mut p);
    assert_eq!(out.len(), 1);
    let c = CommissioningNotification::decode_exact(&out[0].payload).unwrap();
    assert_eq!(c.gpd, GpdId::SrcId(0));
    assert!(c.rx_after_tx);
    assert_eq!(c.command_id, command::CHANNEL_REQUEST);
    assert_eq!(c.payload, &[0x85]);
    // A protected Commissioning GPDF with an individual key the proxy
    // cannot know is forwarded with SecurityProcessingFailed and the MIC.
    let mut protected = LEVEL2;
    protected[8] = 0x30; // level 0b10, individual key
    protected[17] = command::COMMISSIONING;
    feed(&mut p, &protected);
    let out = drain(&mut p);
    assert_eq!(out.len(), 1);
    let c = CommissioningNotification::decode_exact(&out[0].payload).unwrap();
    assert!(c.security_failed);
    assert_eq!(c.key_type, KeyType::Individual);
    assert_eq!(c.security_level, SecurityLevel::Mic);
    assert_eq!(c.mic, Some([0xCF, 0x78, 0x7E, 0x72]));
    assert_eq!(c.frame_counter, 2);
    // The first GP Pairing ends commissioning mode.
    p.on_pairing(
        &pairing(
            CommunicationMode::DerivedGroupcast,
            SinkAddress::Group(0x4321),
        ),
        false,
    );
    assert!(!p.in_commissioning_mode());
    assert!(events(&mut p).contains(&ProxyEvent::CommissioningMode(None)));
    // Unicast commissioning notifications go to the originator without
    // alias; the window expires by itself.
    p.on_commissioning_mode(
        &ProxyCommissioningMode {
            enter: true,
            exit_on_first_pairing: false,
            exit_on_command: true,
            unicast: true,
            window_secs: None,
            channel: None,
        },
        ShortAddress(0x2222),
    );
    let n = unsecured_gpdf(
        &mut buf,
        30,
        0x0000_0043,
        command::COMMISSIONING,
        &[0x02, 0x80, 0x00],
    );
    feed(&mut p, &buf[..n]);
    let out = drain(&mut p);
    assert_eq!(
        out[0].destination,
        Destination::Unicast(ShortAddress(0x2222))
    );
    assert_eq!(out[0].alias, None);
    p.poll(T0 + Duration::from_secs(180));
    assert!(!p.in_commissioning_mode());
}

#[test]
fn proxy_table_request_by_index_and_by_gpd() {
    let mut p = proxy();
    p.on_pairing(
        &pairing(
            CommunicationMode::DerivedGroupcast,
            SinkAddress::Group(0x4321),
        ),
        false,
    );
    let other = GpdId::Ieee {
        address: ExtendedAddress(0x00AA_BBCC_DDEE_FF11),
        endpoint: 1,
    };
    let mut pr = pairing(
        CommunicationMode::LightweightUnicast,
        SinkAddress::Unicast(SINK_IEEE, SINK_SHORT),
    );
    pr.gpd = other;
    p.on_pairing(&pr, false);
    assert_eq!(p.table.len(), 2);
    // By index 0: both entries fit.
    p.on_proxy_table_request(&ProxyTableRequest::ByIndex(0), SINK_SHORT, true);
    let out = drain(&mut p);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].destination, Destination::Unicast(SINK_SHORT));
    let r = ProxyTableResponse::decode_exact(&out[0].payload).unwrap();
    assert_eq!(r.status, TableStatus::Success);
    assert_eq!((r.total, r.start_index, r.count), (2, 0, 2));
    let mut reader = panweave_codec::Reader::new(r.entries);
    let e0 = ProxyEntry::decode(&mut reader).unwrap();
    let e1 = ProxyEntry::decode(&mut reader).unwrap();
    assert_eq!(e0.gpd, GPD);
    assert_eq!(e1.gpd, other);
    assert!(reader.is_empty());
    // By GPD: one entry, start index 0xff.
    p.on_proxy_table_request(&ProxyTableRequest::ByGpd(other), SINK_SHORT, true);
    let out = drain(&mut p);
    let r = ProxyTableResponse::decode_exact(&out[0].payload).unwrap();
    assert_eq!(
        (r.status, r.total, r.start_index, r.count),
        (TableStatus::Success, 2, 0xff, 1)
    );
    // Unknown GPD, broadcast request: silence; unicast: NOT_FOUND.
    p.on_proxy_table_request(
        &ProxyTableRequest::ByGpd(GpdId::SrcId(7)),
        SINK_SHORT,
        false,
    );
    assert!(drain(&mut p).is_empty());
    p.on_proxy_table_request(&ProxyTableRequest::ByIndex(5), SINK_SHORT, true);
    let out = drain(&mut p);
    let r = ProxyTableResponse::decode_exact(&out[0].payload).unwrap();
    assert_eq!(
        (r.status, r.total, r.start_index, r.count),
        (TableStatus::NotFound, 2, 5, 0)
    );
    // RemoveGPD with endpoint 0xff clears every entry of the IEEE device.
    let mut rm = pr;
    rm.add_sink = false;
    rm.remove_gpd = true;
    rm.sink = None;
    rm.device_id = None;
    rm.gpd = GpdId::Ieee {
        address: ExtendedAddress(0x00AA_BBCC_DDEE_FF11),
        endpoint: 0xff,
    };
    p.on_pairing(&rm, false);
    assert_eq!(p.table.len(), 1);
}

#[test]
fn gp_response_appoints_the_selected_sender() {
    let mut p = proxy();
    p.on_commissioning_mode(
        &ProxyCommissioningMode {
            enter: true,
            exit_on_first_pairing: false,
            exit_on_command: true,
            unicast: true,
            window_secs: Some(60),
            channel: None,
        },
        SINK_SHORT,
    );
    let _ = (drain(&mut p), events(&mut p));
    // Another proxy is appointed: nothing is queued here.
    let reply = [0x50, 0x62, 0x1A];
    let other = Response {
        gpd: GPD,
        endpoint_match: false,
        selected_sender: ShortAddress(0x2222),
        tx_channel: 15,
        command_id: command::COMMISSIONING_REPLY,
        payload: Some(&reply),
    };
    p.on_response(&other);
    assert!(!p.is_first_to_forward());
    let mut buf = [0u8; 40];
    let mut body = [0u8; 8];
    body[0] = 0x8C;
    body[1] = 0x40; // ApplicationID 0, RxAfterTx
    body[2..6].copy_from_slice(&0x8765_4321u32.to_le_bytes());
    body[6] = command::COMMISSIONING;
    body[7] = 0x02;
    let n = MacFrame {
        header: mac_header(
            30,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body[..8],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    feed(&mut p, &buf[..n]);
    assert!(p.next_gpdf().is_none());
    // The commissioning frame is still tunnelled (with RxAfterTx).
    let out = drain(&mut p);
    assert_eq!(out.len(), 1);
    assert!(
        CommissioningNotification::decode_exact(&out[0].payload)
            .unwrap()
            .rx_after_tx
    );
    // This proxy is appointed: the Commissioning Reply GPDF goes out
    // gpTxOffset after the GPD's next frame with RxAfterTx, on the
    // channel named by the sink.
    p.on_response(&Response {
        selected_sender: PROXY_SHORT,
        ..other
    });
    assert!(p.is_first_to_forward());
    assert!(p.next_gpdf().is_none(), "nothing until the receive window");
    body[7] = 0x03;
    let n = MacFrame {
        header: mac_header(
            31,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body[..8],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    p.poll(T0 + Duration::from_secs(1));
    feed(&mut p, &buf[..n]);
    let tx = p.next_gpdf().unwrap();
    assert_eq!(tx.not_before, T0 + Duration::from_millis(1020));
    assert_eq!(tx.channel, Some(15));
    assert_eq!(tx.dst, MacAddress::Short(ShortAddress(0xffff)));
    assert_eq!(&tx.frame[..2], &[0x8C, 0x80]);
    assert_eq!(&tx.frame[2..6], &0x8765_4321u32.to_le_bytes());
    assert_eq!(tx.frame[6], command::COMMISSIONING_REPLY);
    assert_eq!(&tx.frame[7..], &reply);
    // One transmission per entry: a further window sends nothing.
    body[7] = 0x04;
    let n = MacFrame {
        header: mac_header(
            32,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body[..8],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    feed(&mut p, &buf[..n]);
    assert!(p.next_gpdf().is_none());
    // A Channel Configuration for the Maintenance GPD answers a Channel
    // Request with a receive window (Auto-Commissioning clear).
    p.on_response(&Response {
        gpd: GpdId::SrcId(0),
        endpoint_match: false,
        selected_sender: PROXY_SHORT,
        tx_channel: 20,
        command_id: command::CHANNEL_CONFIGURATION,
        payload: Some(&[0x14]),
    });
    let n = MacFrame {
        header: mac_header(
            33,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &[0x4D, command::CHANNEL_REQUEST, 0x94],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    feed(&mut p, &buf[..n]);
    assert!(
        p.next_gpdf().is_none(),
        "no window after Auto-Commissioning"
    );
    let n = MacFrame {
        header: mac_header(
            34,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &[0x0D, command::CHANNEL_REQUEST, 0x94],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    feed(&mut p, &buf[..n]);
    let tx = p.next_gpdf().unwrap();
    assert_eq!(tx.channel, Some(20));
    assert_eq!(
        tx.frame.as_slice(),
        &[0x0D, command::CHANNEL_CONFIGURATION, 0x14]
    );
    // Leaving commissioning mode drops the queue.
    p.on_response(&Response {
        selected_sender: PROXY_SHORT,
        ..other
    });
    p.on_commissioning_mode(
        &ProxyCommissioningMode {
            enter: false,
            exit_on_first_pairing: false,
            exit_on_command: false,
            unicast: false,
            window_secs: None,
            channel: None,
        },
        SINK_SHORT,
    );
    assert!(!p.is_first_to_forward());
}
