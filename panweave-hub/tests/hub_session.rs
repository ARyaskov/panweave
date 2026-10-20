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
