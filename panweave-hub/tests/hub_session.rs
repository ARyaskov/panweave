//! A host session over a byte stream: framing errors, oversized frames,
//! version and access checks, and backpressure.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::protocol::frame::{FrameDecoder, MAX_WIRE};
use panweave_hub::protocol::{ErrorCode, Event, Message, Request, Response};
use panweave_hub::{Access, Session};
use panweave_runtime::StackEvent;
use panweave_types::{ExtendedAddress, MacCapability, ShortAddress};

fn frame(id: u16, request: Request) -> Vec<u8> {
    let mut wire = [0u8; MAX_WIRE];
    let n = Message::Request { id, request }
        .encode_frame(&mut wire)
        .unwrap();
    wire[..n].to_vec()
}

/// Everything the session transmitted, decoded.
fn sent<const TX: usize>(s: &mut Session<TX>) -> Vec<Message> {
    let mut dec = FrameDecoder::new();
    let mut out = Vec::new();
    s.transmit(|b| {
        if let Some(Ok(body)) = dec.push(b) {
            out.push(Message::decode(body).unwrap());
        }
        true
    });
    out
}

fn responses(messages: &[Message]) -> Vec<(u16, Response)> {
    messages
        .iter()
        .filter_map(|m| match m {
            Message::Response { id, response } => Some((*id, response.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn radio_diagnostics_with_driver_stats_survives_usb_sized_chunks() {
    use panweave_hub::protocol::RadioDriverStats;
    let (mut sim, c) = network();
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let driver = RadioDriverStats {
        tx_attempts: u32::MAX,
        tx_acked: u32::MAX,
        tx_no_ack: u32::MAX,
        tx_cca_failures: u32::MAX,
        tx_faults: u32::MAX,
        rx_frames: u32::MAX,
        rx_malformed: u32::MAX,
        config_errors: u32::MAX,
        config_flushes: u32::MAX,
        last_rssi: Some(-128),
        last_lqi: Some(255),
    };
    for driver in [None, Some(driver)] {
        app.hub.platform.driver = driver;
        app.hub.platform.tx_power_dbm = Some(10);
        let expected = app.hub.handle(stack, &Request::GetRadioDiagnostics);
        let mut body = [0; panweave_hub::protocol::frame::MAX_BODY];
        let n = Message::Response {
            id: 42,
            response: expected.clone(),
        }
        .encode(&mut body)
        .unwrap();
        assert!(
            n <= 123,
            "fully populated radio diagnostics fits comfortably in MAX_BODY=512"
        );
        for chunk in [1, 63, 64, 65, 256] {
            let mut session: Session = Session::new(Access::Admin);
            for bytes in frame(42, Request::GetRadioDiagnostics).chunks(chunk) {
                session.receive(bytes, &mut app.hub, stack);
            }
            let mut decoder = FrameDecoder::new();
            let mut received = Vec::new();
            while session.tx_len() > 0 {
                let mut sent = 0;
                session.transmit(|b| {
                    if sent == chunk {
                        return false;
                    }
                    sent += 1;
                    if let Some(result) = decoder.push(b) {
                        received.push(Message::decode(result.unwrap()).unwrap());
                    }
                    true
                });
            }
            assert_eq!(
                received,
                vec![Message::Response {
                    id: 42,
                    response: expected.clone()
                }]
            );
            assert_eq!(session.stats.responses_dropped, 0);
            assert_eq!(session.stats.oversize, 0);
            assert_eq!(session.stats.malformed, 0);
        }
    }
}

#[test]
fn usb_short_packets_release_exact_endpoint_sized_radio_responses() {
    use panweave_hub::protocol::RadioDriverStats;
    // A USB host may withhold full endpoint packets until a short packet
    // terminates the transfer. A full FIFO auto-flushes and is busy until
    // the next turn; flushing it while busy does not send a trailing ZLP.
    #[derive(Default)]
    struct Endpoint {
        fifo: Vec<u8>,
        buffered: Vec<u8>,
        delivered: Vec<u8>,
        busy: bool,
    }
    impl Endpoint {
        fn write(&mut self, b: u8) -> bool {
            if self.busy {
                return false;
            }
            self.fifo.push(b);
            if self.fifo.len() == 64 {
                self.buffered.append(&mut self.fifo);
                self.busy = true;
            }
            true
        }
        fn flush(&mut self) {
            if !self.busy {
                self.buffered.append(&mut self.fifo);
                self.delivered.append(&mut self.buffered);
                self.busy = true;
            }
        }
        fn tick(&mut self) {
            self.busy = false;
        }
    }
    let (mut sim, c) = network();
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.platform.driver = Some(RadioDriverStats {
        last_rssi: Some(-30),
        last_lqi: Some(255),
        ..RadioDriverStats::default()
    });
    app.hub.platform.tx_power_dbm = Some(10);
    for corrected in [false, true] {
        let mut session: Session = Session::new(Access::Admin);
        session.receive(
            &frame(42, Request::GetRadioDiagnostics),
            &mut app.hub,
            stack,
        );
        let expected = Message::Response {
            id: 42,
            response: app.hub.handle(stack, &Request::GetRadioDiagnostics),
        };
        let mut bytes = [0; MAX_WIRE];
        let n = expected.encode_frame(&mut bytes).unwrap();
        assert_eq!(
            n, 128,
            "radio response lands exactly on endpoint boundaries"
        );
        let mut endpoint = Endpoint::default();
        while session.tx_len() > 0 {
            let sent = if corrected {
                panweave_hub::esp32c6::transmit_usb_chunk(&mut session, |b| endpoint.write(b))
            } else {
                session.transmit(|b| endpoint.write(b))
            };
            assert!(sent > 0);
            endpoint.flush();
            endpoint.tick();
        }
        if corrected {
            assert_eq!(endpoint.delivered, bytes[..n]);
            assert_eq!(
                panweave_hub::esp32c6::transmit_usb_chunk(&mut session, |_| {
                    panic!("empty queue must not write or keep the link busy")
                }),
                0
            );
            let mut decoder = FrameDecoder::new();
            let messages: Vec<_> = endpoint
                .delivered
                .into_iter()
                .filter_map(|b| {
                    decoder
                        .push(b)
                        .map(|r| Message::decode(r.unwrap()).unwrap())
                })
                .collect();
            assert_eq!(messages, vec![expected]);
        } else {
            assert!(
                endpoint.delivered.is_empty(),
                "legacy sender can finish its queue with no host-visible response"
            );
            assert_eq!(endpoint.buffered, bytes[..n]);
        }
    }

    let mut session: Session = Session::new(Access::Admin);
    session.receive(
        &frame(42, Request::GetRadioDiagnostics),
        &mut app.hub,
        stack,
    );
    let expected = Message::Response {
        id: 42,
        response: app.hub.handle(stack, &Request::GetRadioDiagnostics),
    };
    let mut wire = [0; MAX_WIRE];
    let n = expected.encode_frame(&mut wire).unwrap();
    let mut received = Vec::new();
    assert_eq!(
        panweave_hub::esp32c6::transmit_usb_chunk(&mut session, |_| false),
        0
    );
    assert_eq!(
        session.tx_len(),
        n,
        "a full FIFO must not consume queued output"
    );
    let mut accepted = 0;
    let sent = panweave_hub::esp32c6::transmit_usb_chunk(&mut session, |b| {
        if accepted == 7 {
            return false;
        }
        accepted += 1;
        received.push(b);
        true
    });
    assert_eq!(sent, 7);
    assert_eq!(session.tx_len(), n - 7);
    while session.tx_len() > 0 {
        let sent = panweave_hub::esp32c6::transmit_usb_chunk(&mut session, |b| {
            received.push(b);
            true
        });
        assert!((1..=63).contains(&sent));
    }
    assert_eq!(
        received,
        wire[..n],
        "FIFO backpressure must not lose or duplicate a byte"
    );
}

#[test]
fn corrupted_and_oversized_frames_are_dropped_and_the_stream_recovers() {
    let (mut sim, c) = network();
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let mut s: Session = Session::new(Access::Admin);
    // Text noise (a boot message), a frame with a flipped bit, an
    // endless frame, then a good request.
    let mut bad = frame(1, Request::GetHubInfo);
    bad[4] ^= 0x20;
    let mut stream = b"ESP-ROM:esp32c6\r\n".to_vec();
    stream.extend_from_slice(&bad);
    stream.push(0);
    stream.extend(std::iter::repeat_n(0x55u8, 3 * MAX_WIRE));
    stream.push(0);
    stream.extend_from_slice(&frame(2, Request::GetHubInfo));
    let handled = s.receive(&stream, &mut app.hub, stack);
    assert_eq!(handled, 1);
    assert_eq!(s.stats.corrupt, 2, "the noise and the damaged frame");
    assert_eq!(s.stats.oversize, 1);
    let r = responses(&sent(&mut s));
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0, 2);
    let Response::HubInfo(info) = &r[0].1 else {
        panic!("{r:?}")
    };
    assert_eq!(info.ieee, HUB);
    assert_eq!(info.protocol_version, 1);
    // The counters are reported.
    s.receive(&frame(3, Request::GetDiagnostics), &mut app.hub, stack);
    let r = responses(&sent(&mut s));
    let Response::Diagnostics(d) = &r[0].1 else {
        panic!()
    };
    assert_eq!(
        (d.frames_corrupt, d.frames_oversize, d.frames_rx),
        (2, 1, 2)
    );
}

#[test]
fn malformed_unknown_and_foreign_version_requests_get_errors() {
    let (mut sim, c) = network();
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let mut s: Session = Session::new(Access::Admin);
    let mut wire = [0u8; MAX_WIRE];
    // Version 2 request id 7.
    let n = panweave_hub::protocol::frame::encode(&[2, 1, 7, 0, 0x01], &mut wire).unwrap();
    s.receive(&wire[..n], &mut app.hub, stack);
    // Unknown request tag 0x60, id 8.
    let n = panweave_hub::protocol::frame::encode(&[1, 1, 8, 0, 0x60], &mut wire).unwrap();
    s.receive(&wire[..n], &mut app.hub, stack);
    // A truncated GetDevice, id 9.
    let n = panweave_hub::protocol::frame::encode(&[1, 1, 9, 0, 0x06, 1, 2], &mut wire).unwrap();
    s.receive(&wire[..n], &mut app.hub, stack);
    // Trailing bytes after GetHubInfo, id 10.
    let n = panweave_hub::protocol::frame::encode(&[1, 1, 10, 0, 0x01, 0], &mut wire).unwrap();
    s.receive(&wire[..n], &mut app.hub, stack);
    let r = responses(&sent(&mut s));
    assert_eq!(
        r,
        vec![
            (7, Response::Error(ErrorCode::UnsupportedVersion)),
            (8, Response::Error(ErrorCode::UnknownRequest)),
            (9, Response::Error(ErrorCode::Malformed)),
            (10, Response::Error(ErrorCode::Malformed)),
        ]
    );
    assert_eq!(s.stats.malformed, 4);
}

#[test]
fn a_monitor_session_cannot_change_anything() {
    let (mut sim, c) = network();
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let mut s: Session = Session::new(Access::Monitor);
    let mut stream = frame(1, Request::PermitJoin { seconds: 60 });
    stream.extend(frame(
        2,
        Request::Light {
            ieee: BULB,
            endpoint: 0,
            command: panweave_hub::protocol::LightCommand::TurnOn,
        },
    ));
    stream.extend(frame(
        3,
        Request::RemoveDevice {
            ieee: BULB,
            leave: true,
        },
    ));
    stream.extend(frame(4, Request::GetNetworkStatus));
    s.receive(&stream, &mut app.hub, stack);
    let r = responses(&sent(&mut s));
    assert_eq!(r[0], (1, Response::Error(ErrorCode::Unauthorized)));
    assert_eq!(r[1], (2, Response::Error(ErrorCode::Unauthorized)));
    assert_eq!(r[2], (3, Response::Error(ErrorCode::Unauthorized)));
    assert!(matches!(r[3], (4, Response::NetworkStatus(_))));
    assert_eq!(s.stats.unauthorized, 3);
    // A Control session may act on devices but not on the network.
    let mut s: Session = Session::new(Access::Control);
    s.receive(&frame(5, Request::CloseNetwork), &mut app.hub, stack);
    assert_eq!(
        responses(&sent(&mut s)),
        vec![(5, Response::Error(ErrorCode::Unauthorized))]
    );
}

#[test]
fn a_host_that_stops_reading_loses_events_but_not_responses() {
    let (mut sim, c) = network();
    // The announces below are injected for devices the Trust Center never
    // keyed: with the key exchange required they would (rightly) be
    // ignored, and produce no events to fill the queue.
    sim.stack(c).config.trust_center_policy.require_key_exchange = false;
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    while app.hub.next_event().is_some() {}
    // A small transmit queue that nobody drains.
    let mut s: Session<1024> = Session::new(Access::Admin);
    for i in 0..80u64 {
        app.hub.on_stack_event(
            stack,
            &StackEvent::DeviceAnnounce {
                ieee: ExtendedAddress(0x6000 + i),
                short: ShortAddress(0x0300 + u16::try_from(i).unwrap()),
                capability: MacCapability::SLEEPY_END_DEVICE,
            },
        );
        s.pump_events(&mut app.hub);
    }
    assert!(s.tx_len() <= 1024);
    assert!(app.hub.counters.events_dropped > 0);
    // The request still gets its answer.
    s.receive(&frame(42, Request::GetHubInfo), &mut app.hub, stack);
    assert_eq!(s.stats.responses_dropped, 0);
    let messages = sent(&mut s);
    assert!(matches!(
        responses(&messages).last(),
        Some((42, Response::HubInfo(_)))
    ));
    // Once the host reads again, the loss is reported.
    let mut later = Vec::new();
    for _ in 0..10 {
        s.pump_events(&mut app.hub);
        later.extend(sent(&mut s));
    }
    assert!(later.iter().any(|m| matches!(
        m,
        Message::Event {
            event: Event::EventsDropped { .. },
            ..
        }
    )));
    // Event sequence numbers are consecutive across the whole stream.
    let seqs: Vec<u16> = messages
        .iter()
        .chain(&later)
        .filter_map(|m| match m {
            Message::Event { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert!(seqs.windows(2).all(|w| w[1] == w[0].wrapping_add(1)));
    // A disconnected host: the queue is dropped at once.
    s.receive(&frame(43, Request::GetHubInfo), &mut app.hub, stack);
    s.discard_tx();
    assert_eq!(s.tx_len(), 0);
    assert!(s.stats.discarded > 0);
}
