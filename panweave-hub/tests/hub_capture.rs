//! Radio capture in the hub engine (`radio-capture` feature): bounded,
//! Admin-only, time-limited, sanitized by default, and never exporting
//! key material in its default modes. Synthetic, non-production secrets
//! are planted in frames of every kind and searched for in what the hub
//! hands the host and in the PCAP file built from it.
//!
//! Run with `cargo test -p panweave-hub --features radio-capture` (the
//! quality gate does).

#![cfg(feature = "radio-capture")]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::capture::{CaptureMode, CapturedFrame, flags, kept_len};
use panweave_hub::diag::code;
use panweave_hub::protocol::{CapturePage, ErrorCode, Request, Response};
use panweave_types::time::Duration;

/// A synthetic secret (never a real key).
const SECRET: [u8; 16] = [
    0x5E, 0xC2, 0xE7, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
];

fn contains_secret(data: &[u8]) -> bool {
    data.windows(SECRET.len()).any(|w| w == SECRET)
}

/// MAC data frame header, PAN ID compression, short addresses.
const MAC: [u8; 9] = [0x41, 0x88, 0x01, 0x34, 0x12, 0x00, 0x00, 0x01, 0x00];

fn nwk_header(fc: u16) -> Vec<u8> {
    let mut n = fc.to_le_bytes().to_vec();
    n.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x1e, 0x42]);
    n
}

fn aux_header() -> Vec<u8> {
    let mut a = vec![0x28, 0x10, 0x00, 0x00, 0x00];
    a.extend_from_slice(&0x00aa_bbcc_ddee_ff00u64.to_le_bytes());
    a.push(0x00);
    a
}

/// Frames of every kind, each carrying the secret where a key could be.
fn secret_frames() -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    // 1. An APS Transport Key in an NWK-unsecured data frame.
    let mut f = MAC.to_vec();
    f.extend(nwk_header(0x0008));
    f.extend_from_slice(&[0x21, 0x07, 0x05, 0x01]);
    f.extend_from_slice(&SECRET);
    out.push(("unsecured key transport", f));
    // 2. NWK-secured (a TCLK transport is indistinguishable from any).
    let mut f = MAC.to_vec();
    f.extend(nwk_header(0x0208));
    f.extend(aux_header());
    f.extend_from_slice(&SECRET);
    out.push(("nwk secured", f));
    // 3. NWK-unsecured, APS-secured payload.
    let mut f = MAC.to_vec();
    f.extend(nwk_header(0x0008));
    f.extend_from_slice(&[0x61, 0x01, 0x00, 0x00, 0x00, 0x00]);
    f.extend_from_slice(&SECRET);
    out.push(("aps secured", f));
    // 4. Tunnel / key-management NWK command (unsecured).
    let mut f = MAC.to_vec();
    f.extend(nwk_header(0x0009));
    f.push(0x0e);
    f.extend_from_slice(&SECRET);
    out.push(("unsecured nwk command", f));
    // 5. Unexpected security-control combinations: security bit with a
    //    key identifier other than the network key.
    let mut f = MAC.to_vec();
    f.extend(nwk_header(0x0208));
    f.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04]);
    f.extend_from_slice(&SECRET);
    out.push(("odd security control", f));
    // 6. Malformed security header (cut short).
    let mut f = MAC.to_vec();
    f.extend(nwk_header(0x0208));
    f.extend_from_slice(&[0x28]);
    f.extend_from_slice(&SECRET[..8]);
    f.extend_from_slice(&SECRET[8..]);
    out.push(("malformed security header", f));
    // 7. Truncated NWK header.
    let mut f = MAC.to_vec();
    f.extend_from_slice(&[0x08, 0x02]);
    f.extend_from_slice(&SECRET);
    out.push(("truncated", f));
    // 8. Green Power / unknown protocol version.
    let mut f = MAC.to_vec();
    f.extend_from_slice(&[0x8c, 0x30]);
    f.extend_from_slice(&SECRET);
    out.push(("green power", f));
    // 9. Unknown NWK command identifier, secured MAC.
    let mut f = MAC.to_vec();
    f[0] |= 0x08;
    f.extend(nwk_header(0x0009));
    f.push(0xfe);
    f.extend_from_slice(&SECRET);
    out.push(("mac security", f));
    // 10. Oversized.
    let mut f = MAC.to_vec();
    f.extend(nwk_header(0x0008));
    while f.len() < 200 {
        f.extend_from_slice(&SECRET);
    }
    out.push(("oversized", f));
    out
}

fn start(sim: &mut panweave_sim::Simulator, c: usize, seconds: u16, mode: CaptureMode) -> Response {
    request(sim, c, &Request::StartCapture { seconds, mode })
}

fn read(sim: &mut panweave_sim::Simulator, c: usize) -> CapturePage {
    match request(sim, c, &Request::ReadCapture { max: 3 }) {
        Response::CapturePage(p) => p,
        r => panic!("{r:?}"),
    }
}

fn drain(sim: &mut panweave_sim::Simulator, c: usize) -> Vec<CapturedFrame> {
    let mut out = Vec::new();
    loop {
        let p = read(sim, c);
        if p.frames.is_empty() {
            return out;
        }
        out.extend(p.frames.iter().cloned());
    }
}

fn offer(sim: &mut panweave_sim::Simulator, c: usize, frames: &[(&str, Vec<u8>)]) {
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    for (_, f) in frames {
        app.hub
            .capture_frame(0, 15, f, flags::RX, Some(-50), Some(200));
    }
}

/// The PCAP file the CLI writes from captured frames.
fn pcap(frames: &[CapturedFrame]) -> Vec<u8> {
    let mut w = panweave_pcap::PcapWriter::new(Vec::new()).unwrap();
    for f in frames {
        w.write_truncated(
            u64::from(f.at_ms) * 1000,
            &f.data,
            usize::from(f.original_len),
        )
        .unwrap();
    }
    w.finish().unwrap()
}

#[test]
fn default_modes_never_export_planted_secrets() {
    let frames = secret_frames();
    for mode in [CaptureMode::Sanitized, CaptureMode::Metadata] {
        let (mut sim, c) = network();
        assert_eq!(start(&mut sim, c, 60, mode), Response::Done);
        for chunk in frames.chunks(4) {
            offer(&mut sim, c, chunk);
            let got = drain(&mut sim, c);
            assert_eq!(got.len(), chunk.len());
            for ((name, original), f) in chunk.iter().zip(&got) {
                assert!(!contains_secret(&f.data), "{mode:?} {name}: {:x?}", f.data);
                assert_eq!(
                    usize::from(f.original_len),
                    original.len().min(255),
                    "{name}"
                );
                assert_ne!(f.flags & flags::REDACTED, 0, "{name} must say it was cut");
                // Useful metadata survives: the MAC header at least.
                if *name != "truncated" || mode == CaptureMode::Metadata {
                    assert!(f.data.len() >= MAC.len().min(original.len()), "{name}");
                }
                assert_eq!((f.rssi, f.lqi), (Some(-50), Some(200)));
            }
            let file = pcap(&got);
            assert!(!contains_secret(&file), "{mode:?} pcap");
        }
    }
}

#[test]
fn raw_mode_is_explicit_and_does_export_payloads() {
    let (mut sim, c) = network();
    assert_eq!(start(&mut sim, c, 60, CaptureMode::Raw), Response::Done);
    let frames = secret_frames();
    offer(&mut sim, c, &frames[..1]);
    let got = drain(&mut sim, c);
    assert!(contains_secret(&got[0].data), "raw is raw");
    assert_eq!(got[0].flags & flags::REDACTED, 0);
    // Starting a raw capture is recorded as a warning.
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let p = app.hub.read_trace(0, None, 12);
    let mut from = p.first_available;
    let mut found = None;
    loop {
        let p = app.hub.read_trace(from, None, 12);
        if p.records.is_empty() {
            break;
        }
        if let Some(r) = p.records.iter().find(|r| r.code == code::CAPTURE_STARTED) {
            found = Some(*r);
        }
        from = p.next;
    }
    let r = found.unwrap();
    assert_eq!(r.status, Some(CaptureMode::Raw.code()));
    assert_eq!(r.severity, panweave_hub::diag::Severity::Warning);
}

#[test]
fn a_real_join_under_sanitized_capture_keeps_only_headers() {
    let (mut sim, c) = network();
    sim.trace_enabled = true;
    assert_eq!(
        start(&mut sim, c, 600, CaptureMode::Sanitized),
        Response::Done
    );
    join(&mut sim, c, "bulb", bulb(), BULB);
    // Feed the hub every frame that crossed the simulated air, as the
    // firmware's radio boundary would (the simulator plays the radio).
    let air: Vec<Vec<u8>> = sim.trace.iter().map(|t| t.frame.clone()).collect();
    assert!(air.len() > 20);
    let mut kept = Vec::new();
    for chunk in air.chunks(8) {
        {
            let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
            for f in chunk {
                app.hub.capture_frame(0, 11, f, 0, None, None);
            }
        }
        kept.extend(drain(&mut sim, c));
    }
    assert_eq!(kept.len(), air.len());
    let mut payload_bytes_dropped = 0usize;
    for (f, original) in kept.iter().zip(&air) {
        assert_eq!(f.data.len(), kept_len(original, CaptureMode::Sanitized));
        assert_eq!(
            f.data.as_slice(),
            &original[..f.data.len()],
            "a prefix, never altered"
        );
        payload_bytes_dropped += original.len() - f.data.len();
    }
    assert!(payload_bytes_dropped > 0);
    // The network key never appears, in clear, in the export.
    let file = pcap(&kept);
    assert!(!file.windows(16).any(|w| w == NETWORK_KEY.as_bytes()));
}

#[test]
fn capture_is_bounded_time_limited_and_restartable() {
    let (mut sim, c) = network();
    // Nothing is copied while no capture runs.
    offer(&mut sim, c, &secret_frames()[..1]);
    assert_eq!(read(&mut sim, c).queued, 0);
    assert_eq!(
        start(&mut sim, c, 0, CaptureMode::Sanitized),
        Response::Error(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        start(&mut sim, c, 3601, CaptureMode::Sanitized),
        Response::Error(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        start(&mut sim, c, 2, CaptureMode::Sanitized),
        Response::Done
    );
    // Overflow: the excess is counted, the radio never waits.
    {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        for i in 0..40u8 {
            app.hub
                .capture_frame(u64::from(i), 11, &[0x02, 0x00, i], 0, None, None);
        }
    }
    let p = read(&mut sim, c);
    assert!(p.active);
    assert_eq!(p.mode, CaptureMode::Sanitized);
    assert_eq!(p.dropped, 40 - 16);
    // Interrupted (the host vanished): the capture ends by itself.
    sim.run_for(Duration::from_secs(3));
    let p = read(&mut sim, c);
    assert!(!p.active);
    // A restart starts afresh; stop is idempotent.
    assert_eq!(start(&mut sim, c, 5, CaptureMode::Metadata), Response::Done);
    let p = read(&mut sim, c);
    assert!(p.active && p.mode == CaptureMode::Metadata && p.dropped == 0);
    assert_eq!(request(&mut sim, c, &Request::StopCapture), Response::Done);
    assert_eq!(request(&mut sim, c, &Request::StopCapture), Response::Done);
    assert!(!read(&mut sim, c).active);
}

/// Simulated milliseconds from opening the network until the bulb's
/// interview completes, with or without full diagnostics.
fn interview_time(diagnostics: bool) -> u64 {
    let (mut sim, c) = network();
    if diagnostics {
        assert!(matches!(
            request(
                &mut sim,
                c,
                &Request::SetTraceConfiguration {
                    min_severity: 0,
                    categories: panweave_hub::diag::ALL_CATEGORIES,
                }
            ),
            Response::TraceConfiguration(_)
        ));
        assert_eq!(
            start(&mut sim, c, 3600, CaptureMode::Sanitized),
            Response::Done
        );
        sim.trace_enabled = true;
    }
    let started = sim.stack(c).now().as_millis();
    let d = sim.add_stack("bulb", bulb(), Box::new(panweave_sim::OnOffApp::default()));
    sim.stack(d)
        .join(panweave_runtime::JoinMode::Association)
        .unwrap();
    let mut fed = 0;
    loop {
        sim.step(Duration::from_millis(50));
        if diagnostics {
            // Every frame on the air goes through the capture, as on
            // the target; the host drains it now and then.
            let frames: Vec<Vec<u8>> = sim.trace[fed..].iter().map(|t| t.frame.clone()).collect();
            fed = sim.trace.len();
            let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
            for f in &frames {
                app.hub.capture_frame(0, 11, f, 0, None, None);
            }
            let _ = read(&mut sim, c);
        }
        if hub_events(&sim, c).iter().any(
            |e| matches!(e, panweave_hub::protocol::Event::DeviceInterviewCompleted { ieee, .. } if *ieee == BULB),
        ) {
            return sim.stack(c).now().as_millis() - started;
        }
        assert!(sim.stack(c).now().as_millis() - started < 300_000);
    }
}

#[test]
fn full_diagnostics_do_not_change_protocol_timing() {
    // Deterministic simulation: same seeds, same radio; the trace at its
    // most verbose and a capture of every frame must not delay a single
    // protocol step. (CPU cost on the target is measured by the loop
    // timing metrics, not here.)
    assert_eq!(interview_time(true), interview_time(false));
}
