//! `capture …`: bounded radio frame capture to a pcap file.
//!
//! The hub keeps a small frame buffer (16 frames) that the host drains
//! while the capture runs; the CLI writes what it drains to a classic pcap
//! file (`LINKTYPE_IEEE802_15_4_NOFCS`, 230) that Wireshark opens, and
//! optionally a JSONL file with each frame's direction, RSSI/LQI and
//! flags. Frames the host could not drain in time are counted by the hub
//! and reported at the end, never silently lost.
//!
//! The hub sanitizes frames before they leave it (`--mode sanitized`, the
//! default: headers only, no payload that could carry a key; `metadata`:
//! MAC headers only). A cut frame is written as a PCAP record whose
//! captured length is shorter than its original length, so Wireshark
//! shows it as cut. `--mode raw` exports whole frames, including network
//! key transports protected only by the well-known link key; it needs
//! `--allow-raw` as well.

use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use panweave_hub::capture::{CaptureMode, CapturedFrame, flags};
use panweave_hub::protocol::{CapturePage, ErrorCode, MAX_CAPTURE_PAGE, Request, Response};
use panweave_pcap::PcapWriter;

use crate::diagcmd::{unsupported, unwrap_ms};
use crate::json::Obj;
use crate::{Hub, STOP, error_text, number};

fn read(hub: &mut Hub) -> Result<CapturePage, String> {
    let max = u8::try_from(MAX_CAPTURE_PAGE).unwrap_or(1);
    match hub.call(Request::ReadCapture { max })? {
        Response::CapturePage(p) => Ok(p),
        r if unsupported(&r) => {
            Err("the hub firmware does not support capture (needs firmware 0.2.1 or later)".into())
        }
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

fn start(hub: &mut Hub, seconds: u16, mode: CaptureMode) -> Result<(), String> {
    match hub.call(Request::StartCapture { seconds, mode })? {
        Response::Done => Ok(()),
        Response::Error(ErrorCode::NotSupported) => Err(
            "this firmware was built without radio capture (the `capture` feature of the ESP32-C6 crate)"
                .into(),
        ),
        r if unsupported(&r) => {
            Err("the hub firmware does not support capture (needs firmware 0.2.1 or later)".into())
        }
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

fn stop(hub: &mut Hub) -> Result<(), String> {
    match hub.call(Request::StopCapture)? {
        Response::Done => Ok(()),
        r if unsupported(&r) => Err("the hub firmware does not support capture".into()),
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

/// One frame as a metadata JSONL line.
pub(crate) fn frame_json(f: &CapturedFrame, uptime_ms: u64) -> String {
    Obj::new()
        .int("seq", f.seq.into())
        .int("uptime_ms", unwrap_ms(uptime_ms, f.at_ms).into())
        .str(
            "direction",
            if f.flags & flags::RX != 0 { "rx" } else { "tx" },
        )
        .int("channel", f.channel.into())
        .int("captured_length", i128::try_from(f.data.len()).unwrap_or(0))
        .int("original_length", f.original_len.into())
        .opt("rssi_dbm", f.rssi.map(Into::into))
        .opt("lqi", f.lqi.map(Into::into))
        .bool("acked", f.flags & flags::ACKED != 0)
        .bool("no_ack", f.flags & flags::NO_ACK != 0)
        .bool("tx_fault", f.flags & flags::TX_FAULT != 0)
        .bool("redacted", f.flags & flags::REDACTED != 0)
        .str("summary", &panweave_pcap::summarize(&f.data))
        .finish()
}

/// Drains the hub's capture into `pcap` (and `meta`) until it stops, the
/// deadline passes or Ctrl+C. Returns (frames written, dropped by the hub).
fn drain(
    hub: &mut Hub,
    pcap: &mut PcapWriter<BufWriter<File>>,
    mut meta: Option<&mut BufWriter<File>>,
    deadline: Instant,
) -> Result<(u64, u32), String> {
    let mut written = 0;
    let mut last_seq: Option<u32> = None;
    let mut gaps = 0u32;
    let mut dropped;
    loop {
        let page = read(hub)?;
        dropped = page.dropped;
        for f in &page.frames {
            if let Some(prev) = last_seq {
                gaps += f.seq.wrapping_sub(prev).saturating_sub(1);
            }
            last_seq = Some(f.seq);
            let at = unwrap_ms(page.uptime_ms, f.at_ms);
            pcap.write_truncated(at * 1000, &f.data, usize::from(f.original_len))
                .map_err(|e| format!("writing pcap: {e}"))?;
            if let Some(m) = meta.as_deref_mut() {
                writeln!(m, "{}", frame_json(f, page.uptime_ms))
                    .map_err(|e| format!("writing metadata: {e}"))?;
            }
            written += 1;
        }
        let stopping = STOP.load(Ordering::SeqCst) || Instant::now() >= deadline;
        if !page.active && page.queued == 0 && page.frames.is_empty() {
            break;
        }
        if stopping && page.frames.is_empty() {
            break;
        }
        if page.frames.len() < MAX_CAPTURE_PAGE {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Ok((written, dropped.max(gaps)))
}

fn flag<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| *a == name)
        .and_then(|i| args.get(i + 1).copied())
}

/// The capture mode asked for: `sanitized` unless `--mode` says
/// otherwise; `raw` only together with `--allow-raw`.
pub(crate) fn mode(args: &[&str]) -> Result<CaptureMode, String> {
    if args.contains(&"--no-redact") {
        return Err("--no-redact was replaced by `--mode raw --allow-raw`".into());
    }
    let mode = match flag(args, "--mode") {
        Some(m) => CaptureMode::parse(m)
            .ok_or_else(|| format!("unknown capture mode {m} (metadata, sanitized, raw)"))?,
        None => CaptureMode::Sanitized,
    };
    if mode == CaptureMode::Raw && !args.contains(&"--allow-raw") {
        return Err(
            "raw capture exports whole frames, including network keys sent to joining devices under the well-known link key; add --allow-raw to confirm"
                .into(),
        );
    }
    Ok(mode)
}

/// `capture start|stop|export …`.
pub(crate) fn run(hub: &mut Hub, args: &[&str]) -> Result<(), String> {
    match args {
        ["stop", ..] => {
            stop(hub)?;
            println!("capture stopped");
            Ok(())
        }
        ["start", rest @ ..] => {
            let seconds = flag(rest, "--seconds").map_or(Ok(60), number)?;
            let mode = mode(rest)?;
            start(hub, seconds, mode)?;
            println!(
                "{} capture started for {seconds} s (the hub holds only a few frames: run `capture export` to keep them)",
                mode.name()
            );
            Ok(())
        }
        ["export", rest @ ..] => {
            let path = flag(rest, "--output").ok_or("export needs --output FILE.pcap")?;
            let seconds: u16 = flag(rest, "--seconds").map_or(Ok(60), number)?;
            let mode = mode(rest)?;
            let mut pcap = PcapWriter::new(BufWriter::new(
                File::create(path).map_err(|e| format!("{path}: {e}"))?,
            ))
            .map_err(|e| format!("{path}: {e}"))?;
            let mut meta = match flag(rest, "--metadata") {
                Some(m) => Some(BufWriter::new(
                    File::create(m).map_err(|e| format!("{m}: {e}"))?,
                )),
                None => None,
            };
            if mode == CaptureMode::Raw {
                eprintln!(
                    "warning: raw capture: whole frames are written, including network key transports to joining devices; do not share the file"
                );
            }
            start(hub, seconds, mode)?;
            eprintln!("capturing for {seconds} s (Ctrl+C to stop early) …");
            let result = drain(
                hub,
                &mut pcap,
                meta.as_mut(),
                Instant::now() + Duration::from_secs(seconds.into()),
            );
            // Stop the hub's capture whatever happened on this side.
            let stopped = stop(hub);
            let (written, dropped) = result?;
            stopped?;
            pcap.finish().map_err(|e| format!("{path}: {e}"))?;
            if let Some(mut m) = meta {
                m.flush().map_err(|e| e.to_string())?;
            }
            println!("{written} frame(s) written to {path}");
            if dropped > 0 {
                println!(
                    "{dropped} frame(s) were dropped by the hub (its buffer was full): the capture is incomplete"
                );
            }
            Ok(())
        }
        _ => Err(crate::USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_hub::capture::CaptureBuffer;

    /// A synthetic, non-production secret.
    const SECRET: [u8; 16] = [0x5E; 16];

    /// What the hub hands the CLI for an unsecured key transport carrying
    /// `SECRET`, captured in `mode`.
    fn captured(mode: CaptureMode) -> CapturedFrame {
        let mut f = vec![0x41, 0x88, 0x01, 0x34, 0x12, 0x00, 0x00, 0x01, 0x00];
        f.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x1e, 0x42]);
        f.extend_from_slice(&[0x21, 0x07, 0x05, 0x01]);
        f.extend_from_slice(&SECRET);
        let mut buf: CaptureBuffer<1> = CaptureBuffer::new();
        buf.start(10_000, mode);
        buf.offer(1500, 15, &f, flags::RX, Some(-60), Some(200));
        let mut out: heapless::Vec<CapturedFrame, 1> = heapless::Vec::new();
        buf.take(1, &mut out);
        out.pop().unwrap_or_else(|| unreachable!())
    }

    fn hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut s, x| {
            use std::fmt::Write as _;
            let _ = write!(s, "{x:02x}");
            s
        })
    }

    #[test]
    fn exports_of_a_sanitized_capture_hold_no_secret() {
        let f = captured(CaptureMode::Sanitized);
        let j = frame_json(&f, 2000);
        assert!(
            j.starts_with(r#"{"seq":0,"uptime_ms":1500,"direction":"rx","channel":15"#),
            "{j}"
        );
        assert!(
            j.contains(r#""captured_length":17,"original_length":37"#),
            "{j}"
        );
        assert!(j.contains(r#""redacted":true"#), "{j}");
        assert!(!j.to_lowercase().contains(&hex(&SECRET[..4])), "{j}");
        let mut w = PcapWriter::new(Vec::new()).unwrap_or_else(|_| unreachable!());
        w.write_truncated(1_500_000, &f.data, usize::from(f.original_len))
            .unwrap_or_else(|_| unreachable!());
        let file = w.finish().unwrap_or_else(|_| unreachable!());
        assert!(!file.windows(16).any(|x| x == SECRET));
        assert_eq!(&file[32..36], &17u32.to_le_bytes());
        assert_eq!(&file[36..40], &37u32.to_le_bytes());
        // Raw, by contrast, is the frame as sent.
        assert!(
            captured(CaptureMode::Raw)
                .data
                .windows(16)
                .any(|x| x == SECRET)
        );
    }

    #[test]
    fn raw_mode_needs_an_explicit_acknowledgement() {
        assert_eq!(mode(&[]), Ok(CaptureMode::Sanitized));
        assert_eq!(mode(&["--mode", "metadata"]), Ok(CaptureMode::Metadata));
        assert!(mode(&["--mode", "raw"]).is_err());
        assert_eq!(
            mode(&["--mode", "raw", "--allow-raw"]),
            Ok(CaptureMode::Raw)
        );
        assert!(mode(&["--no-redact"]).is_err());
        assert!(mode(&["--mode", "everything"]).is_err());
    }
}
