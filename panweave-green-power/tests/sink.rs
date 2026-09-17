//! The Basic Combo sink end to end at the crate level: unidirectional and
//! bidirectional commissioning (directly and through a proxy), the keys
//! it accepts and hands out, the GP Pairing / GP Response / Channel
//! Configuration it generates, operation with freshness and duplicate
//! filtering, decommissioning and the Sink Table Request.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::{Decode, Encode, Writer};
use panweave_green_power::cluster::{
    self, CommissioningNotification, CommunicationMode, GppGpdLink, Notification, Pairing,
    ProxyCommissioningMode, Response, SinkAddress, SinkTableRequest, SinkTableResponse,
    TableStatus,
};
use panweave_green_power::command;
use panweave_green_power::commissioning::{
    ChannelConfiguration, Commissioning, CommissioningReply, KeyField, SecurityCapabilities,
};
use panweave_green_power::gpdf::{
    ExtendedFrameControl, FrameType, GpdId, Gpdf, NwkFrameControl, SecurityLevel, mac_header,
    write_header,
};
use panweave_green_power::proxy::Destination;
use panweave_green_power::security::{self, Direction, KeyType};
use panweave_green_power::sink::{GpdfTx, Refusal, Sink, SinkConfig, SinkEvent, SinkFrame};
use panweave_mac::frame::{Frame as MacFrame, MacAddress};
use panweave_security::cipher::SoftwareAes;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ExtendedAddress, Key128, PanId, ShortAddress};

const SINK_SHORT: ShortAddress = ShortAddress(0x0000);
const SINK_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const PROXY: ShortAddress = ShortAddress(0x1234);
const GPD: GpdId = GpdId::SrcId(0x8765_4321);
const NWK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const OOB_KEY: Key128 = Key128::from_bytes([
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
]);
const T0: Instant = Instant::from_millis(10_000);
const LINK: GppGpdLink = GppGpdLink(0xC0);
const CHANNEL: u8 = 15;

type Combo = Sink<SoftwareAes, 4>;

fn sink() -> Combo {
    let mut cfg = SinkConfig::new(SINK_SHORT, SINK_IEEE, PanId(0x1A62), CHANNEL);
    cfg.nwk_key = Some(NWK_KEY.clone());
    let mut s = Combo::new(cfg);
    s.poll(T0);
    s
}

fn ext(level: SecurityLevel, individual: bool, rx_after_tx: bool) -> ExtendedFrameControl {
    ExtendedFrameControl {
        application_id: panweave_green_power::gpdf::ApplicationId::SrcId,
        security_level: level,
        individual_key: individual,
        rx_after_tx,
        from_proxy: false,
    }
}

/// A Data GPDF from the GPD, protected with `key` when given.
fn data_gpdf(
    seq: u8,
    e: ExtendedFrameControl,
    auto: bool,
    counter: Option<u32>,
    app: &[u8],
    key: Option<&Key128>,
) -> Vec<u8> {
    let fc = NwkFrameControl {
        frame_type: FrameType::Data,
        auto_commissioning: auto,
        extension: true,
    };
    let mut hdr = [0u8; 16];
    let mut w = Writer::new(&mut hdr);
    write_header(&mut w, fc, Some(e), Some(&GPD), counter).unwrap();
    let hl = w.position();
    let mut payload = app.to_vec();
    let mic = key.map(|k| {
        security::protect::<SoftwareAes>(
            k,
            e.security_level,
            &GPD,
            counter.unwrap(),
            Direction::FromGpd,
            &hdr[..hl],
            &mut payload,
        )
        .unwrap()
    });
    let mut body = hdr[..hl].to_vec();
    body.extend(&payload);
    if let Some(m) = mic {
        body.extend(&m);
    }
    let mut buf = [0u8; 96];
    let n = MacFrame {
        header: mac_header(
            seq,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    buf[..n].to_vec()
}

fn feed(s: &mut Combo, frame: &[u8]) {
    let mac = MacFrame::decode_exact(frame).unwrap();
    let g = Gpdf::decode(&mac).unwrap();
    s.on_gpdf(&g, LINK);
}

fn frames(s: &mut Combo) -> Vec<SinkFrame> {
    let mut v = Vec::new();
    while let Some(f) = s.next_frame() {
        v.push(f);
    }
    v
}

fn gpdfs(s: &mut Combo) -> Vec<GpdfTx> {
    let mut v = Vec::new();
    while let Some(f) = s.next_gpdf() {
        v.push(f);
    }
    v
}

fn events(s: &mut Combo) -> Vec<SinkEvent> {
    let mut v = Vec::new();
    while let Some(e) = s.next_event() {
        v.push(e);
    }
    v
}

fn commissioning_body(c: &Commissioning<'_>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = c.encode_to_slice(&mut buf).unwrap();
    let mut v = vec![command::COMMISSIONING];
    v.extend(&buf[..n]);
    v
}

fn commands(evs: &[SinkEvent]) -> Vec<u8> {
    evs.iter()
        .filter_map(|e| match e {
            SinkEvent::Command(c) => Some(c.command_id),
            _ => None,
        })
        .collect()
}

#[test]
fn unidirectional_commissioning_with_a_protected_oob_key() {
    let mut s = sink();
    let until = s
        .enter_commissioning_mode(true, Some(Duration::from_secs(60)))
        .unwrap();
    assert_eq!(until, T0 + Duration::from_secs(60));
    assert_eq!(events(&mut s), [SinkEvent::CommissioningMode(Some(until))]);
    let out = frames(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].destination, Destination::Broadcast);
    assert_eq!(
        out[0].command,
        cluster::server_cmd::PROXY_COMMISSIONING_MODE
    );
    let m = ProxyCommissioningMode::decode_exact(&out[0].payload).unwrap();
    assert!(m.enter && m.unicast && m.exit_on_first_pairing);
    assert_eq!(m.window_secs, Some(60));
    // A GPD without security is refused by the default gpsSecurityLevel;
    // one with security but no link-key protection too.
    let plain = Commissioning {
        device_id: 0x02,
        sequence_number_capable: true,
        rx_on_capable: false,
        pan_id_request: false,
        key_request: false,
        fixed_location: false,
        security: None,
        key: None,
        outgoing_counter: None,
        application: None,
    };
    feed(
        &mut s,
        &data_gpdf(
            1,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &commissioning_body(&plain),
            None,
        ),
    );
    assert_eq!(
        events(&mut s),
        [SinkEvent::Refused {
            gpd: GPD,
            reason: Refusal::SecurityLevel
        }]
    );
    let (protected, mic) = security::protect_gpd_key::<SoftwareAes>(
        &Key128::WELL_KNOWN_GLOBAL_TCLK,
        &GPD,
        Direction::FromGpd,
        0,
        &OOB_KEY,
    )
    .unwrap();
    let mut secured = Commissioning {
        security: Some(SecurityCapabilities {
            level: 0b10,
            key_type: KeyType::Individual,
            key_encryption: false,
        }),
        key: Some(KeyField {
            bytes: *OOB_KEY.as_bytes().first_chunk::<16>().unwrap(),
            mic: None,
        }),
        outgoing_counter: Some(0x10),
        ..plain
    };
    feed(
        &mut s,
        &data_gpdf(
            2,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &commissioning_body(&secured),
            None,
        ),
    );
    assert_eq!(
        events(&mut s),
        [SinkEvent::Refused {
            gpd: GPD,
            reason: Refusal::LinkKeyProtection
        }]
    );
    // The certifiable GPD: level 0b10, OOB key protected with the
    // gpLinkKey.
    secured.security.as_mut().unwrap().key_encryption = true;
    secured.key = Some(KeyField {
        bytes: protected,
        mic: Some(mic),
    });
    feed(
        &mut s,
        &data_gpdf(
            3,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &commissioning_body(&secured),
            None,
        ),
    );
    let evs = events(&mut s);
    assert_eq!(
        evs,
        [
            SinkEvent::TableChanged,
            SinkEvent::Paired {
                gpd: GPD,
                device_id: 0x02,
                mode: CommunicationMode::DerivedGroupcast,
                alias: ShortAddress(0x4321),
                group: Some(0x4321),
                announce: true,
            },
            SinkEvent::CommissioningMode(None),
        ]
    );
    let out = frames(&mut s);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].command, cluster::server_cmd::PAIRING);
    let p = Pairing::decode_exact(&out[0].payload).unwrap();
    assert!(p.add_sink && !p.remove_gpd);
    assert_eq!(p.mode, CommunicationMode::DerivedGroupcast);
    assert_eq!(p.sink, Some(SinkAddress::Group(0x4321)));
    assert_eq!(p.security_level(), Some(SecurityLevel::Mic));
    assert_eq!(p.key_type, KeyType::Individual);
    assert_eq!(p.key, Some(OOB_KEY.clone()));
    assert_eq!(p.frame_counter, Some(0x10));
    assert_eq!(p.device_id, Some(0x02));
    assert!(p.sequence_number_capable);
    assert_eq!(
        out[1].command,
        cluster::server_cmd::PROXY_COMMISSIONING_MODE
    );
    assert!(
        !ProxyCommissioningMode::decode_exact(&out[1].payload)
            .unwrap()
            .enter
    );
    assert!(!s.in_commissioning_mode());
    let e = s.table.find(&GPD).unwrap();
    assert_eq!(e.security.as_ref().unwrap().key, Some(OOB_KEY.clone()));
    assert_eq!(e.frame_counter, 0x10);
    // Operation: a Toggle protected with the OOB key and a fresh counter
    // is delivered once; replays, stale counters, unprotected frames and
    // frames under another key are dropped.
    let toggle = |seq: u8, counter: u32, key: &Key128| {
        data_gpdf(
            seq,
            ext(SecurityLevel::Mic, true, false),
            false,
            Some(counter),
            &[command::TOGGLE],
            Some(key),
        )
    };
    feed(&mut s, &toggle(4, 0x11, &OOB_KEY));
    let evs = events(&mut s);
    assert_eq!(commands(&evs), [command::TOGGLE]);
    assert!(evs.contains(&SinkEvent::TableChanged));
    assert_eq!(s.table.find(&GPD).unwrap().frame_counter, 0x11);
    feed(&mut s, &toggle(4, 0x11, &OOB_KEY));
    assert!(events(&mut s).is_empty());
    s.poll(T0 + Duration::from_secs(5));
    feed(&mut s, &toggle(5, 0x11, &OOB_KEY));
    assert!(events(&mut s).is_empty());
    feed(&mut s, &toggle(6, 0x12, &NWK_KEY));
    assert!(events(&mut s).is_empty());
    feed(
        &mut s,
        &data_gpdf(
            7,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &[command::TOGGLE],
            None,
        ),
    );
    assert!(events(&mut s).is_empty());
    // A commissioning attempt in operational mode changes nothing.
    feed(
        &mut s,
        &data_gpdf(
            8,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &commissioning_body(&secured),
            None,
        ),
    );
    assert!(events(&mut s).is_empty() && frames(&mut s).is_empty());
    // Decommissioning, protected as agreed, removes the pairing and
    // tells the proxies.
    feed(
        &mut s,
        &data_gpdf(
            9,
            ext(SecurityLevel::Mic, true, false),
            false,
            Some(0x13),
            &[command::DECOMMISSIONING],
            Some(&OOB_KEY),
        ),
    );
    assert_eq!(
        events(&mut s),
        [
            SinkEvent::TableChanged,
            SinkEvent::Decommissioned {
                gpd: GPD,
                group: Some(0x4321)
            }
        ]
    );
    let out = frames(&mut s);
    assert_eq!(out.len(), 1);
    let p = Pairing::decode_exact(&out[0].payload).unwrap();
    assert!(p.remove_gpd && !p.add_sink);
    assert!(s.table.is_empty());
}

#[test]
fn bidirectional_commissioning_hands_out_the_derived_group_key() {
    let mut s = sink();
    s.enter_commissioning_mode(false, None).unwrap();
    assert!(frames(&mut s).is_empty(), "proxies not involved");
    let _ = events(&mut s);
    let asking = Commissioning {
        device_id: 0x07,
        sequence_number_capable: false,
        rx_on_capable: true,
        pan_id_request: true,
        key_request: true,
        fixed_location: false,
        security: Some(SecurityCapabilities {
            level: 0b10,
            key_type: KeyType::None,
            key_encryption: true,
        }),
        key: None,
        outgoing_counter: Some(5),
        application: None,
    };
    feed(
        &mut s,
        &data_gpdf(
            1,
            ext(SecurityLevel::None, false, true),
            false,
            None,
            &commissioning_body(&asking),
            None,
        ),
    );
    assert!(events(&mut s).is_empty(), "no pairing before Success");
    assert!(s.table.is_empty());
    // The Commissioning Reply goes out gpTxOffset later, unprotected,
    // from the sink to the GPD, carrying the PAN ID and the NWK-key
    // derived group key under the gpLinkKey.
    let tx = gpdfs(&mut s);
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].not_before, T0 + Duration::from_millis(20));
    assert_eq!(tx[0].dst, MacAddress::Short(ShortAddress(0xffff)));
    let f = &tx[0].frame;
    assert_eq!(f[0], 0x8C);
    assert_eq!(f[1], 0x80, "ApplicationID 0, level 0, direction to GPD");
    assert_eq!(&f[2..6], &0x8765_4321u32.to_le_bytes());
    assert_eq!(f[6], command::COMMISSIONING_REPLY);
    let reply = CommissioningReply::decode_exact(&f[7..]).unwrap();
    assert_eq!(reply.pan_id, Some(PanId(0x1A62)));
    assert_eq!(reply.security_level, 0b10);
    assert_eq!(reply.key_type, KeyType::NwkDerivedGroupKey);
    assert_eq!(reply.frame_counter, Some(5));
    let kf = reply.key.unwrap();
    let derived = security::derive_group_key::<SoftwareAes>(&NWK_KEY);
    let recovered = security::unprotect_gpd_key::<SoftwareAes>(
        &Key128::WELL_KNOWN_GLOBAL_TCLK,
        &GPD,
        Direction::ToGpd,
        5,
        &kf.bytes,
        &kf.mic.unwrap(),
    )
    .unwrap();
    assert_eq!(recovered, derived);
    // A Success that is not fresher than the outgoing counter fails.
    let success = |seq: u8, counter: u32| {
        data_gpdf(
            seq,
            ext(SecurityLevel::Mic, false, false),
            false,
            Some(counter),
            &[command::SUCCESS],
            Some(&derived),
        )
    };
    feed(&mut s, &success(2, 5));
    assert_eq!(
        events(&mut s),
        [SinkEvent::Refused {
            gpd: GPD,
            reason: Refusal::SuccessSecurity
        }]
    );
    feed(&mut s, &success(3, 6));
    let evs = events(&mut s);
    assert!(matches!(
        evs[1],
        SinkEvent::Paired {
            gpd: GPD,
            device_id: 0x07,
            announce: true,
            ..
        }
    ));
    let out = frames(&mut s);
    let p = Pairing::decode_exact(&out[0].payload).unwrap();
    assert_eq!(p.key_type, KeyType::NwkDerivedGroupKey);
    assert_eq!(p.key, Some(derived.clone()));
    assert_eq!(p.frame_counter, Some(6));
    let e = s.table.find(&GPD).unwrap();
    assert!(e.rx_on_capable);
    assert_eq!(e.frame_counter, 6);
    // In operation the GPD uses the delivered key.
    feed(
        &mut s,
        &data_gpdf(
            4,
            ext(SecurityLevel::Mic, false, false),
            false,
            Some(7),
            &[command::ON],
            Some(&derived),
        ),
    );
    assert_eq!(commands(&events(&mut s)), [command::ON]);
}

#[test]
fn multi_hop_commissioning_through_a_proxy() {
    let mut s = sink();
    s.enter_commissioning_mode(true, None).unwrap();
    let _ = (frames(&mut s), events(&mut s));
    // A Channel Request forwarded by the proxy: the proxy becomes the
    // SelectedSender of the Channel Configuration on the GPD's next
    // channel.
    let n = CommissioningNotification {
        gpd: GpdId::SrcId(0),
        rx_after_tx: true,
        security_level: SecurityLevel::None,
        key_type: KeyType::None,
        security_failed: false,
        bidirectional: false,
        frame_counter: 3,
        command_id: command::CHANNEL_REQUEST,
        payload: &[0x94],
        proxy: Some((PROXY, LINK)),
        mic: None,
    };
    s.on_commissioning_notification(&n, PROXY);
    let out = frames(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].command, cluster::server_cmd::RESPONSE);
    let r = Response::decode_exact(&out[0].payload).unwrap();
    assert_eq!(r.gpd, GpdId::SrcId(0));
    assert_eq!(r.selected_sender, PROXY);
    assert_eq!(r.tx_channel, 15);
    assert_eq!(r.command_id, command::CHANNEL_CONFIGURATION);
    assert_eq!(
        ChannelConfiguration::decode_exact(r.payload.unwrap()).unwrap(),
        ChannelConfiguration {
            channel: CHANNEL,
            basic: true
        }
    );
    // The Commissioning command with a key request: GP Response carries
    // the Commissioning Reply for the proxy to deliver.
    let asking = Commissioning {
        device_id: 0x02,
        sequence_number_capable: true,
        rx_on_capable: false,
        pan_id_request: false,
        key_request: true,
        fixed_location: false,
        security: Some(SecurityCapabilities {
            level: 0b10,
            key_type: KeyType::None,
            key_encryption: true,
        }),
        key: None,
        outgoing_counter: Some(7),
        application: None,
    };
    let body = commissioning_body(&asking);
    let n = CommissioningNotification {
        gpd: GPD,
        rx_after_tx: true,
        security_level: SecurityLevel::None,
        key_type: KeyType::None,
        security_failed: false,
        bidirectional: false,
        frame_counter: 7,
        command_id: command::COMMISSIONING,
        payload: &body[1..],
        proxy: Some((PROXY, LINK)),
        mic: None,
    };
    s.on_commissioning_notification(&n, PROXY);
    let out = frames(&mut s);
    assert_eq!(out.len(), 1);
    let r = Response::decode_exact(&out[0].payload).unwrap();
    assert_eq!(r.gpd, GPD);
    assert_eq!(r.selected_sender, PROXY);
    assert_eq!(r.command_id, command::COMMISSIONING_REPLY);
    let reply = CommissioningReply::decode_exact(r.payload.unwrap()).unwrap();
    assert_eq!(reply.pan_id, None);
    assert_eq!(reply.key_type, KeyType::NwkDerivedGroupKey);
    assert!(reply.key.unwrap().mic.is_some());
    assert!(
        gpdfs(&mut s).is_empty(),
        "the proxy transmits, not the sink"
    );
    // The Success comes back tunnelled with SecurityProcessingFailed:
    // the proxy has no key for the GPD; the sink checks it itself.
    let derived = security::derive_group_key::<SoftwareAes>(&NWK_KEY);
    let header = [0x8C, 0x10, 0x21, 0x43, 0x65, 0x87, 8, 0, 0, 0];
    let mut payload = [command::SUCCESS];
    let mic = security::protect::<SoftwareAes>(
        &derived,
        SecurityLevel::Mic,
        &GPD,
        8,
        Direction::FromGpd,
        &header,
        &mut payload,
    )
    .unwrap();
    let n = CommissioningNotification {
        gpd: GPD,
        rx_after_tx: false,
        security_level: SecurityLevel::Mic,
        key_type: KeyType::None,
        security_failed: true,
        bidirectional: false,
        frame_counter: 8,
        command_id: command::SUCCESS,
        payload: &[],
        proxy: Some((PROXY, LINK)),
        mic: Some(mic),
    };
    s.on_commissioning_notification(&n, PROXY);
    let evs = events(&mut s);
    assert!(
        evs.iter()
            .any(|e| matches!(e, SinkEvent::Paired { gpd: GPD, .. })),
        "{evs:?}"
    );
    assert!(evs.contains(&SinkEvent::CommissioningMode(None)));
    let out = frames(&mut s);
    assert_eq!(out[0].command, cluster::server_cmd::PAIRING);
    assert_eq!(s.table.find(&GPD).unwrap().frame_counter, 8);
    // Operation through GP Notifications: delivered once when received
    // in the pairing's mode; a unicast one in the wrong mode triggers
    // the corrective GP Pairings instead.
    let toggle = Notification {
        gpd: GPD,
        also_unicast: false,
        also_derived_group: true,
        also_commissioned_group: false,
        security_level: SecurityLevel::Mic,
        key_type: KeyType::NwkDerivedGroupKey,
        rx_after_tx: false,
        tx_queue_full: true,
        bidirectional: false,
        frame_counter: 9,
        command_id: command::TOGGLE,
        payload: &[],
        proxy: Some((PROXY, LINK)),
    };
    s.on_notification(&toggle, PROXY, false);
    s.on_notification(&toggle, ShortAddress(0x2222), false);
    assert_eq!(commands(&events(&mut s)), [command::TOGGLE]);
    let wrong = Notification {
        frame_counter: 10,
        ..toggle
    };
    s.on_notification(&wrong, PROXY, true);
    assert!(commands(&events(&mut s)).is_empty());
    let out = frames(&mut s);
    assert_eq!(out.len(), 2);
    let add = Pairing::decode_exact(&out[0].payload).unwrap();
    let remove = Pairing::decode_exact(&out[1].payload).unwrap();
    assert!(add.add_sink && add.mode == CommunicationMode::DerivedGroupcast);
    assert!(!remove.add_sink && remove.mode == CommunicationMode::LightweightUnicast);
    assert_eq!(
        remove.sink,
        Some(SinkAddress::Unicast(SINK_IEEE, SINK_SHORT))
    );
}

#[test]
fn direct_channel_request_and_sink_table_request() {
    let mut s = sink();
    // Nothing answers a Channel Request outside commissioning mode.
    let mut buf = [0u8; 40];
    let n = MacFrame {
        header: mac_header(3, MacAddress::Short(ShortAddress(0xffff)), MacAddress::None),
        payload: &[0x0D, command::CHANNEL_REQUEST, 0x94],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    feed(&mut s, &buf[..n]);
    assert!(gpdfs(&mut s).is_empty());
    s.enter_commissioning_mode(false, None).unwrap();
    feed(&mut s, &buf[..n]);
    let tx = gpdfs(&mut s);
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].not_before, T0 + Duration::from_millis(20));
    assert_eq!(
        tx[0].frame.as_slice(),
        &[0x0D, command::CHANNEL_CONFIGURATION, 0x14]
    );
    // A Channel Request with Auto-Commissioning (no receive window) is
    // not answered.
    let n = MacFrame {
        header: mac_header(4, MacAddress::Short(ShortAddress(0xffff)), MacAddress::None),
        payload: &[0x4D, command::CHANNEL_REQUEST, 0x94],
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    feed(&mut s, &buf[..n]);
    assert!(gpdfs(&mut s).is_empty());
    // Sink Table Request on an empty table: NOT_FOUND only in unicast.
    s.on_sink_table_request(&SinkTableRequest::ByIndex(0), PROXY, false);
    assert!(frames(&mut s).is_empty());
    s.on_sink_table_request(&SinkTableRequest::ByIndex(0), PROXY, true);
    let out = frames(&mut s);
    assert_eq!(out[0].destination, Destination::Unicast(PROXY));
    assert_eq!(out[0].command, cluster::server_cmd::SINK_TABLE_RESPONSE);
    let r = SinkTableResponse::decode_exact(&out[0].payload).unwrap();
    assert_eq!(r.status, TableStatus::NotFound);
    assert_eq!((r.total, r.start_index, r.count), (0, 0, 0));
    // With an unsecured pairing (policy relaxed) the entry comes back.
    s.config.security_level.minimum = 0;
    s.config.security_level.link_key_protection = false;
    let plain = Commissioning {
        device_id: 0x02,
        sequence_number_capable: true,
        rx_on_capable: false,
        pan_id_request: false,
        key_request: false,
        fixed_location: true,
        security: None,
        key: None,
        outgoing_counter: None,
        application: None,
    };
    feed(
        &mut s,
        &data_gpdf(
            5,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &commissioning_body(&plain),
            None,
        ),
    );
    assert!(
        events(&mut s)
            .iter()
            .any(|e| matches!(e, SinkEvent::Paired { .. }))
    );
    let _ = frames(&mut s);
    s.on_sink_table_request(&SinkTableRequest::ByGpd(GPD), PROXY, true);
    let out = frames(&mut s);
    let r = SinkTableResponse::decode_exact(&out[0].payload).unwrap();
    assert_eq!(r.status, TableStatus::Success);
    assert_eq!((r.total, r.start_index, r.count), (1, 0xff, 1));
    let e = panweave_green_power::sink_table::SinkEntry::decode(&mut panweave_codec::Reader::new(
        r.entries,
    ))
    .unwrap();
    assert_eq!(e.gpd, GPD);
    assert!(e.fixed_location && e.sequence_number_capable);
    assert_eq!(
        e.frame_counter, 5,
        "MAC sequence number of the pairing frame"
    );
    // An unprotected Toggle from the unsecured pairing is delivered.
    feed(
        &mut s,
        &data_gpdf(
            6,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &[command::TOGGLE],
            None,
        ),
    );
    assert_eq!(commands(&events(&mut s)), [command::TOGGLE]);
}

#[test]
fn pairing_configuration_manages_the_sink_table() {
    use panweave_green_power::cluster::{
        ConfigurationAction, PairedEndpoints, PairingConfiguration,
    };
    use panweave_green_power::proxy_table::{ALIAS_DERIVED, SecurityOptions};
    use panweave_green_power::sink::ConfigurationError;
    use panweave_green_power::sink_table::SinkEntry;
    let mut s = sink();
    let secured = |gpd: GpdId, mode: CommunicationMode| {
        let mut e = SinkEntry::new(gpd, mode, 0x02);
        e.sequence_number_capable = true;
        e.security = Some(SecurityOptions {
            level: SecurityLevel::Mic,
            key_type: KeyType::Individual,
            key: Some(OOB_KEY.clone()),
        });
        e.frame_counter = 5;
        e
    };
    let cfg = |action, send_pairing, entry: SinkEntry, endpoints| PairingConfiguration {
        action,
        send_pairing,
        entry,
        paired_endpoints: endpoints,
        application_info: None,
        reports: None,
    };
    // A commissioning tool adds a lightweight unicast pairing with two
    // local endpoints: the entry is stored, the endpoints reported, the
    // GP Pairing sent, no Device_annce for lightweight unicast.
    let c = cfg(
        ConfigurationAction::Extend,
        true,
        secured(GPD, CommunicationMode::LightweightUnicast),
        PairedEndpoints::List(&[1, 2]),
    );
    assert_eq!(s.on_pairing_configuration(&c, true), Ok(()));
    let evs = events(&mut s);
    assert!(evs.contains(&SinkEvent::TableChanged));
    assert!(evs.iter().any(|e| matches!(
        e,
        SinkEvent::LocalEndpoints { gpd: GPD, endpoints: Some(l) } if l.as_slice() == [1, 2]
    )));
    assert!(evs.iter().any(|e| matches!(
        e,
        SinkEvent::Paired {
            gpd: GPD,
            mode: CommunicationMode::LightweightUnicast,
            announce: false,
            group: None,
            ..
        }
    )));
    let out = frames(&mut s);
    assert_eq!(out.len(), 1);
    let p = Pairing::decode_exact(&out[0].payload).unwrap();
    assert!(p.add_sink);
    assert_eq!(p.sink, Some(SinkAddress::Unicast(SINK_IEEE, SINK_SHORT)));
    assert_eq!(p.key, Some(OOB_KEY.clone()));
    // Extending with another communication mode is refused; the
    // existing pairing stays.
    let other = cfg(
        ConfigurationAction::Extend,
        false,
        secured(GPD, CommunicationMode::DerivedGroupcast),
        PairedEndpoints::All,
    );
    assert_eq!(
        s.on_pairing_configuration(&other, true),
        Err(ConfigurationError::Failure)
    );
    assert_eq!(
        s.table.find(&GPD).unwrap().mode,
        CommunicationMode::LightweightUnicast
    );
    // A pre-commissioned group pairing for a second GPD: the sink joins
    // the group and announces the alias.
    let other_gpd = GpdId::SrcId(0x0000_0055);
    let mut e = secured(other_gpd, CommunicationMode::CommissionedGroupcast);
    e.groups.push((0x0010, ALIAS_DERIVED)).unwrap();
    let c = cfg(
        ConfigurationAction::Extend,
        true,
        e,
        PairedEndpoints::Derived,
    );
    assert_eq!(s.on_pairing_configuration(&c, true), Ok(()));
    let evs = events(&mut s);
    assert!(evs.iter().any(|e| matches!(
        e,
        SinkEvent::Paired {
            gpd,
            group: Some(0x0010),
            announce: true,
            ..
        } if *gpd == other_gpd
    )));
    assert!(evs.iter().any(|e| matches!(
        e,
        SinkEvent::LocalEndpoints {
            endpoints: None,
            ..
        }
    )));
    let _ = frames(&mut s);
    // Removing that group pairing empties the entry.
    let mut e = SinkEntry::new(other_gpd, CommunicationMode::CommissionedGroupcast, 0);
    e.groups.push((0x0010, ALIAS_DERIVED)).unwrap();
    let c = cfg(
        ConfigurationAction::RemovePairing,
        true,
        e,
        PairedEndpoints::None,
    );
    assert_eq!(s.on_pairing_configuration(&c, true), Ok(()));
    assert!(s.table.find(&other_gpd).is_none());
    assert!(events(&mut s).iter().any(|e| matches!(
        e,
        SinkEvent::Decommissioned {
            group: Some(0x0010),
            ..
        }
    )));
    let out = frames(&mut s);
    let p = Pairing::decode_exact(&out[0].payload).unwrap();
    assert!(!p.add_sink && !p.remove_gpd);
    assert_eq!(p.sink, Some(SinkAddress::Group(0x0010)));
    // Below the security policy, and an unsupported action.
    let plain = cfg(
        ConfigurationAction::Extend,
        false,
        SinkEntry::new(GpdId::SrcId(0x66), CommunicationMode::FullUnicast, 0),
        PairedEndpoints::All,
    );
    assert_eq!(
        s.on_pairing_configuration(&plain, true),
        Err(ConfigurationError::Failure)
    );
    let desc = PairingConfiguration {
        action: ConfigurationAction::ApplicationDescription,
        reports: Some((1, 1, &[])),
        ..plain.clone()
    };
    assert_eq!(
        s.on_pairing_configuration(&desc, true),
        Err(ConfigurationError::Unsupported)
    );
    // Remove GPD sends the RemoveGPD pairing; a second time: NOT_FOUND.
    let c = cfg(
        ConfigurationAction::RemoveGpd,
        true,
        SinkEntry::new(GPD, CommunicationMode::FullUnicast, 0),
        PairedEndpoints::None,
    );
    assert_eq!(s.on_pairing_configuration(&c, true), Ok(()));
    assert!(s.table.is_empty());
    let out = frames(&mut s);
    assert!(Pairing::decode_exact(&out[0].payload).unwrap().remove_gpd);
    assert_eq!(
        s.on_pairing_configuration(&c, true),
        Err(ConfigurationError::NotFound)
    );
    // No action with Send GP Pairing for an unknown GPD sends nothing.
    let c = cfg(
        ConfigurationAction::NoAction,
        true,
        SinkEntry::new(GPD, CommunicationMode::FullUnicast, 0),
        PairedEndpoints::None,
    );
    assert_eq!(s.on_pairing_configuration(&c, true), Ok(()));
    assert!(frames(&mut s).is_empty());
}

#[test]
fn multi_sensor_commissioning_waits_for_the_application_description() {
    use panweave_green_power::commissioning::ApplicationInfo;
    use panweave_green_power::description::{
        ApplicationDescription, AttributeRecord, CompactReport, DataPoint, ReportDescriptor,
        ReportedAttribute,
    };
    use panweave_types::ClusterId;
    let mut s = sink();
    s.enter_commissioning_mode(false, None).unwrap();
    let _ = events(&mut s);
    // The Commissioning command announces an Application Description.
    let (protected, mic) = security::protect_gpd_key::<SoftwareAes>(
        &Key128::WELL_KNOWN_GLOBAL_TCLK,
        &GPD,
        Direction::FromGpd,
        0,
        &OOB_KEY,
    )
    .unwrap();
    let c = Commissioning {
        device_id: 0x30,
        sequence_number_capable: true,
        rx_on_capable: false,
        pan_id_request: false,
        key_request: false,
        fixed_location: true,
        security: Some(SecurityCapabilities {
            level: 0b10,
            key_type: KeyType::Individual,
            key_encryption: true,
        }),
        key: Some(KeyField {
            bytes: protected,
            mic: Some(mic),
        }),
        outgoing_counter: Some(0x10),
        application: Some(ApplicationInfo {
            manufacturer_id: None,
            model_id: None,
            commands: None,
            clusters: None,
            switch: None,
            description_follows: true,
        }),
    };
    feed(
        &mut s,
        &data_gpdf(
            1,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &commissioning_body(&c),
            None,
        ),
    );
    assert!(
        events(&mut s).is_empty(),
        "no pairing before the description"
    );
    assert!(s.table.is_empty());
    // The description: report 0 = Temperature Measurement MeasuredValue
    // (int16) at offset 0.
    let mut records = [0u8; 16];
    let mut rw = Writer::new(&mut records);
    AttributeRecord::write(&mut rw, 0x0000, 0x29, Some(0), None).unwrap();
    let rn = rw.position();
    let mut points = [0u8; 24];
    let mut pw = Writer::new(&mut points);
    DataPoint::write(&mut pw, ClusterId(0x0402), true, None, 1, &records[..rn]).unwrap();
    let pn = pw.position();
    let mut desc = [0u8; 40];
    let mut dw = Writer::new(&mut desc);
    ReportDescriptor::write(&mut dw, 0, Some(60), &points[..pn]).unwrap();
    let dn = dw.position();
    let d = ApplicationDescription {
        total_reports: 1,
        reports: 1,
        descriptors: &desc[..dn],
    };
    let mut body = vec![command::APPLICATION_DESCRIPTION];
    let mut dbuf = [0u8; 48];
    let n = d.encode_to_slice(&mut dbuf).unwrap();
    body.extend(&dbuf[..n]);
    feed(
        &mut s,
        &data_gpdf(
            2,
            ext(SecurityLevel::None, false, false),
            false,
            None,
            &body,
            None,
        ),
    );
    let evs = events(&mut s);
    assert!(evs.iter().any(|e| matches!(
        e,
        SinkEvent::Paired {
            gpd: GPD,
            device_id: 0x30,
            ..
        }
    )));
    assert_eq!(s.table.find(&GPD).unwrap().frame_counter, 0x10);
    assert!(s.descriptions.get(&GPD).unwrap().is_complete());
    let _ = frames(&mut s);
    // A Compact Attribute Reporting in operation carries 21.50 °C.
    feed(
        &mut s,
        &data_gpdf(
            3,
            ext(SecurityLevel::Mic, true, false),
            false,
            Some(0x11),
            &[0xA8, 0x00, 0x66, 0x08],
            Some(&OOB_KEY),
        ),
    );
    let evs = events(&mut s);
    let cmd = evs
        .iter()
        .find_map(|e| match e {
            SinkEvent::Command(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(cmd.command_id, 0xA8);
    let report = CompactReport::parse(&cmd.payload).unwrap();
    let desc = s.descriptions.get(&GPD).unwrap();
    let attrs: Vec<ReportedAttribute<'_>> = report
        .attributes(&desc.report(report.report_id).unwrap())
        .collect();
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].cluster, ClusterId(0x0402));
    assert_eq!(attrs[0].value, &[0x66, 0x08]);
}
