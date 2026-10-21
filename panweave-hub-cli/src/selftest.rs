//! `self-test`: the hardware smoke test of a hub on its USB port.
//!
//! Every test reads state or makes a change it undoes; none erases flash,
//! forms a new network or factory-resets the hub. Two tests change more
//! and only run when asked: `--allow-reboot` resets the chip through the
//! USB Serial/JTAG reset line and checks that the network and registry come
//! back unchanged, and `--join-test` opens the network for joining and
//! waits for a device the operator puts in pairing mode.

use std::time::{Duration, Instant};

use panweave_hub::diag::{Severity, code};
use panweave_hub::model::Ieee;
use panweave_hub::protocol::frame::MAX_WIRE;
use panweave_hub::protocol::{
    ErrorCode, Event, Message, NetworkRestore, NetworkState, Request, ResetKind, Response,
};

use crate::diagcmd::{self, unsupported};
use crate::json::{Obj, array};
use crate::{Hub, error_text, text};

/// A test's outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        }
    }
}

/// One test's result.
pub(crate) struct Outcome {
    pub(crate) number: u8,
    pub(crate) name: &'static str,
    pub(crate) status: Status,
    pub(crate) detail: String,
    pub(crate) duration: Duration,
}

/// What the smoke test may do.
pub(crate) struct Options {
    pub(crate) allow_reboot: bool,
    pub(crate) join_test: bool,
    pub(crate) join_seconds: u8,
}

type Check = Result<(Status, String), String>;

fn pass(detail: impl Into<String>) -> Check {
    Ok((Status::Pass, detail.into()))
}

fn fail(detail: impl Into<String>) -> Check {
    Ok((Status::Fail, detail.into()))
}

fn skip(detail: impl Into<String>) -> Check {
    Ok((Status::Skip, detail.into()))
}

const OLD: &str = "firmware without diagnostics (before 0.2.1)";

fn protocol(hub: &mut Hub) -> Check {
    match hub.call(Request::GetHubInfo)? {
        Response::HubInfo(h) if h.protocol_version == 1 => pass(format!(
            "protocol v1, firmware {}, hub {}",
            text(&h.firmware),
            Ieee(h.ieee)
        )),
        Response::HubInfo(h) => fail(format!("protocol v{}", h.protocol_version)),
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn boot(hub: &mut Hub) -> Check {
    match hub.call(Request::GetBootReport)? {
        Response::BootReport(b) => {
            let missing: Vec<&str> = [
                ("reset reason", b.reset.is_none()),
                ("cpu clock", b.cpu_mhz.is_none()),
                ("radio channel", b.radio_channel.is_none()),
                ("network", b.network.is_none()),
            ]
            .iter()
            .filter(|(_, m)| *m)
            .map(|(n, _)| *n)
            .collect();
            if b.chip.is_empty() || !b.usb_ready {
                fail("boot report incomplete")
            } else if missing.is_empty() {
                pass(format!(
                    "{} build {}, booted in {} ms",
                    text(&b.chip),
                    text(&b.build),
                    b.boot_ms.map_or_else(|| "?".into(), |m| m.to_string())
                ))
            } else {
                pass(format!("unavailable: {}", missing.join(", ")))
            }
        }
        r if unsupported(&r) => skip(OLD),
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn reset(hub: &mut Hub) -> Check {
    match hub.call(Request::GetBootReport)? {
        Response::BootReport(b) => match (b.reset, b.reset_raw) {
            (Some(ResetKind::WatchdogReset), raw) => fail(format!(
                "the last reset was a watchdog reset ({}): the firmware hung or a loop turn overran",
                raw.map_or("?", panweave_hub::esp32c6::reset_reason_name)
            )),
            (Some(k), raw) => pass(format!(
                "{} ({})",
                k.name(),
                raw.map_or("?", panweave_hub::esp32c6::reset_reason_name)
            )),
            (None, _) => skip("reset reason unavailable"),
        },
        r if unsupported(&r) => skip(OLD),
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn partitions(hub: &mut Hub) -> Check {
    match hub.call(Request::GetBootReport)? {
        Response::BootReport(b) => {
            if !b.partition_table_read {
                return fail("the partition table could not be read");
            }
            if !b.findings.is_empty() {
                let codes: Vec<String> = b.findings.iter().map(|f| f.code.to_string()).collect();
                return fail(format!(
                    "partition findings {} (`diagnostics system`)",
                    codes.join(", ")
                ));
            }
            match b.hubdata {
                Some((o, s)) => pass(format!(
                    "{} partitions, registry area {o:#x} + {s:#x}",
                    b.partitions.len()
                )),
                None => fail("no hubdata partition: the registry is RAM only"),
            }
        }
        r if unsupported(&r) => skip(OLD),
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn storage(hub: &mut Hub) -> Check {
    match hub.call(Request::GetStorageDiagnostics)? {
        Response::StorageDiagnostics(d) => {
            let mut problems = Vec::new();
            for (name, s) in [("stack", d.stack_store), ("registry", d.hub_store)] {
                match s {
                    Some(s) if s.io_errors > 0 => {
                        problems.push(format!("{name} store: {} I/O errors", s.io_errors));
                    }
                    Some(s) if s.corrupt_records > 0 => {
                        problems.push(format!(
                            "{name} store: {} corrupt records skipped",
                            s.corrupt_records
                        ));
                    }
                    Some(_) => {}
                    None => problems.push(format!("{name} store unavailable")),
                }
            }
            if d.registry_errors > 0 {
                problems.push(format!("{} registry write errors", d.registry_errors));
            }
            if problems.is_empty() {
                pass(format!(
                    "registry persistent with {} device(s)",
                    d.registry_devices
                ))
            } else {
                fail(problems.join("; "))
            }
        }
        r if unsupported(&r) => skip(OLD),
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn network(hub: &mut Hub) -> Check {
    let status = match hub.call(Request::GetNetworkStatus)? {
        Response::NetworkStatus(s) => s,
        r => return fail(format!("unexpected response {r:?}")),
    };
    if status.state != NetworkState::Up {
        return fail(format!("network {}", status.state.name()));
    }
    let restore = match hub.call(Request::GetBootReport)? {
        Response::BootReport(b) => b.network,
        _ => None,
    };
    if let Some(r) = restore.filter(|r| r.refused_to_form()) {
        return fail(format!("network at boot: {}", r.name()));
    }
    let mut total = None;
    if let Response::DeviceList(l) = hub.call(Request::ListDevices { start: 0 })? {
        total = Some(l.total);
    }
    if total.is_some_and(|t| t != status.devices) {
        return fail("the registry and the network status disagree on the device count");
    }
    pass(format!(
        "PAN {:#06x} channel {}, {} device(s){}",
        status.network.pan_id,
        status.network.channel,
        status.devices,
        restore.map_or_else(String::new, |r| format!(", {}", r.name()))
    ))
}

fn radio(hub: &mut Hub) -> Check {
    match hub.call(Request::GetRadioDiagnostics)? {
        Response::RadioDiagnostics(d) => {
            let Some(s) = d.driver else {
                return skip("driver counters unavailable");
            };
            if s.config_errors > 0 || s.tx_faults > 0 {
                fail(format!(
                    "{} configuration errors, {} transmit faults",
                    s.config_errors, s.tx_faults
                ))
            } else {
                pass(format!(
                    "channel {}, tx {} (acked {}), rx {}",
                    d.channel.map_or_else(|| "?".into(), |c| c.to_string()),
                    s.tx_attempts,
                    s.tx_acked,
                    s.rx_frames
                ))
            }
        }
        r if unsupported(&r) => skip(OLD),
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn runtime(hub: &mut Hub) -> Check {
    let d = match diagcmd::get_runtime(hub) {
        Ok(d) => d,
        Err(_) => return skip(OLD),
    };
    if d.watchdog_s.is_none() {
        return fail("the watchdog is not armed");
    }
    match d.loop_max_us {
        Some(us) if us > 500_000 => fail(format!("a loop turn took {us} µs")),
        Some(us) => pass(format!(
            "longest loop turn {us} µs, {} overrun(s), watchdog {} s",
            d.loop_overruns.unwrap_or(0),
            d.watchdog_s.unwrap_or(0)
        )),
        None => skip("loop timing unavailable"),
    }
}

fn trace(hub: &mut Hub) -> Check {
    let (records, _, lost) = match diagcmd::read_all(hub, None) {
        Ok(r) => r,
        Err(_) => return skip(OLD),
    };
    let serious: Vec<&str> = records
        .iter()
        .filter(|r| r.severity >= Severity::Error)
        .map(|r| panweave_hub::diag::code_name(r.code))
        .collect();
    let booted = records.iter().any(|r| r.code == code::BOOT_COMPLETED);
    let detail = format!(
        "{} record(s), {lost} dropped{}",
        records.len(),
        if booted {
            ""
        } else {
            ", boot record no longer stored"
        }
    );
    if serious.is_empty() {
        pass(detail)
    } else {
        fail(format!("{detail}; errors: {}", serious.join(", ")))
    }
}

fn trace_config(hub: &mut Hub) -> Check {
    let c = match hub.call(Request::GetTraceConfiguration)? {
        Response::TraceConfiguration(c) => c,
        r if unsupported(&r) => return skip(OLD),
        r => return fail(format!("unexpected response {r:?}")),
    };
    // Write the configuration back unchanged: proves Admin access and the
    // request path without changing what the hub keeps.
    match hub.call(Request::SetTraceConfiguration {
        min_severity: c.min_severity.code(),
        categories: c.categories,
    })? {
        Response::TraceConfiguration(n)
            if n.min_severity == c.min_severity && n.categories == c.categories =>
        {
            // An invalid level must be refused.
            match hub.call(Request::SetTraceConfiguration {
                min_severity: 0xee,
                categories: c.categories,
            })? {
                Response::Error(ErrorCode::InvalidArgument) => pass(format!(
                    "keeps {} and above, invalid levels refused",
                    c.min_severity.name()
                )),
                r => fail(format!("an invalid level was not refused: {r:?}")),
            }
        }
        Response::Error(ErrorCode::Unauthorized) => fail("the USB session is not Admin"),
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn capture(hub: &mut Hub) -> Check {
    match hub.call(Request::StartCapture {
        seconds: 2,
        mode: panweave_hub::capture::CaptureMode::Sanitized,
    })? {
        Response::Done => {}
        Response::Error(ErrorCode::NotSupported) => {
            return skip("firmware built without the capture feature");
        }
        r if unsupported(&r) => return skip(OLD),
        r => return fail(format!("unexpected response {r:?}")),
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut frames = 0;
    let mut active = true;
    while Instant::now() < deadline && active {
        match hub.call(Request::ReadCapture { max: 3 })? {
            Response::CapturePage(p) => {
                frames += p.frames.len();
                active = p.active;
            }
            r => return fail(format!("unexpected response {r:?}")),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = hub.call(Request::StopCapture)?;
    if active {
        fail("the capture did not stop at its deadline")
    } else {
        pass(format!("{frames} frame(s) in 2 s, stopped on time"))
    }
}

fn usb(hub: &mut Hub) -> Check {
    // Line noise, a frame with a wrong CRC and an over-long frame: the hub
    // must drop them and keep answering.
    let mut junk = vec![0x00, 0x13, 0x37, 0x00];
    junk.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 0x01, 0xde, 0xad, 0x00]);
    junk.extend(std::iter::repeat_n(0x42u8, MAX_WIRE + 16));
    junk.push(0x00);
    hub.send_raw(&junk)?;
    std::thread::sleep(Duration::from_millis(100));
    match hub.call(Request::GetHubInfo)? {
        Response::HubInfo(_) => {
            let rejected = match diagcmd::get_runtime(hub) {
                Ok(d) => format!(", {} output discard(s) so far", d.usb_discards),
                Err(_) => String::new(),
            };
            pass(format!("corrupt and oversize frames ignored{rejected}"))
        }
        r => fail(format!("unexpected response {r:?}")),
    }
}

fn reboot(hub: &mut Hub, o: &Options) -> Check {
    if !o.allow_reboot {
        return skip("needs --allow-reboot (resets the chip)");
    }
    let before = match hub.call(Request::GetNetworkStatus)? {
        Response::NetworkStatus(s) => s,
        r => return fail(format!("unexpected response {r:?}")),
    };
    hub.reset_and_reconnect()?;
    let after = match hub.call(Request::GetNetworkStatus)? {
        Response::NetworkStatus(s) => s,
        r => return fail(format!("unexpected response {r:?}")),
    };
    let restore = match hub.call(Request::GetBootReport)? {
        Response::BootReport(b) => b.network,
        _ => None,
    };
    if after.network != before.network {
        return fail("the hub came back on a different network");
    }
    if after.devices != before.devices {
        return fail(format!(
            "{} device(s) before the reset, {} after",
            before.devices, after.devices
        ));
    }
    if restore.is_some_and(|r| r != NetworkRestore::Restored) {
        return fail(format!(
            "network at boot: {}",
            restore.map_or("?", NetworkRestore::name)
        ));
    }
    pass(format!(
        "network and {} device(s) restored after a reset",
        after.devices
    ))
}

fn join(hub: &mut Hub, o: &Options) -> Check {
    if !o.join_test {
        return skip("needs --join-test (opens the network for joining)");
    }
    let seconds = o.join_seconds;
    match hub.call(Request::PermitJoin { seconds })? {
        Response::Done => {}
        Response::Error(e) => return fail(error_text(e)),
        r => return fail(format!("unexpected response {r:?}")),
    }
    eprintln!("network open for {seconds} s: put a device in pairing mode now");
    let deadline = Instant::now() + Duration::from_secs(seconds.into());
    let mut joined = None;
    let mut interviewed = false;
    while Instant::now() < deadline && !interviewed {
        if let Ok(Message::Event { event, .. }) = hub.rx.recv_timeout(Duration::from_millis(500)) {
            match event {
                Event::DeviceJoined { ieee, .. } if joined.is_none() => {
                    eprintln!("{} joined, interviewing …", Ieee(ieee));
                    joined = Some(ieee);
                }
                Event::DeviceInterviewCompleted { ieee, .. } if Some(ieee) == joined => {
                    interviewed = true;
                }
                _ => {}
            }
        }
    }
    let _ = hub.call(Request::CloseNetwork)?;
    match (joined, interviewed) {
        (Some(i), true) => pass(format!("{} joined and was interviewed", Ieee(i))),
        (Some(i), false) => fail(format!(
            "{} joined but its interview did not finish (`diagnostics interview {}`)",
            Ieee(i),
            Ieee(i)
        )),
        (None, _) => fail("no device joined (`diagnostics watch --category trust-center`)"),
    }
}

/// Runs the smoke test; `connect` failures are test 1.
pub(crate) fn run(hub: &mut Hub, port: &str, o: &Options) -> Vec<Outcome> {
    let mut out = vec![Outcome {
        number: 1,
        name: "usb-port",
        status: Status::Pass,
        detail: format!("{port} open"),
        duration: Duration::ZERO,
    }];
    type Test = fn(&mut Hub, &Options) -> Check;
    let tests: [(&str, Test); 14] = [
        ("protocol", |h, _| protocol(h)),
        ("boot-report", |h, _| boot(h)),
        ("reset-reason", |h, _| reset(h)),
        ("partitions", |h, _| partitions(h)),
        ("storage", |h, _| storage(h)),
        ("network", |h, _| network(h)),
        ("radio", |h, _| radio(h)),
        ("runtime", |h, _| runtime(h)),
        ("trace", |h, _| trace(h)),
        ("admin-access", |h, _| trace_config(h)),
        ("capture", |h, _| capture(h)),
        ("usb-robustness", |h, _| usb(h)),
        ("reboot-persistence", reboot),
        ("join", join),
    ];
    for (i, (name, test)) in tests.iter().enumerate() {
        if crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let started = Instant::now();
        let (status, detail) = match test(hub, o) {
            Ok(r) => r,
            Err(e) => (Status::Fail, e),
        };
        out.push(Outcome {
            number: u8::try_from(i + 2).unwrap_or(u8::MAX),
            name,
            status,
            detail,
            duration: started.elapsed(),
        });
    }
    out
}

/// The results as a JSON report.
pub(crate) fn report_json(results: &[Outcome]) -> String {
    let items: Vec<String> = results
        .iter()
        .map(|r| {
            Obj::new()
                .int("number", r.number.into())
                .str("name", r.name)
                .str("status", r.status.name())
                .str("detail", &r.detail)
                .int(
                    "duration_ms",
                    i128::try_from(r.duration.as_millis()).unwrap_or(0),
                )
                .finish()
        })
        .collect();
    let count = |s| results.iter().filter(|r| r.status == s).count();
    Obj::new()
        .str(
            "tool",
            concat!("panweave-hub-cli ", env!("CARGO_PKG_VERSION")),
        )
        .int("passed", i128::try_from(count(Status::Pass)).unwrap_or(0))
        .int("failed", i128::try_from(count(Status::Fail)).unwrap_or(0))
        .int("skipped", i128::try_from(count(Status::Skip)).unwrap_or(0))
        .raw("tests", &array(&items))
        .finish()
}

/// Prints the results; true when none failed.
pub(crate) fn print(results: &[Outcome], as_json: bool) -> bool {
    if as_json {
        println!("{}", report_json(results));
    } else {
        for r in results {
            println!(
                "{:>2}. {:<19} {}  {}",
                r.number,
                r.name,
                r.status.name(),
                r.detail
            );
        }
    }
    !results.iter().any(|r| r.status == Status::Fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_counts_outcomes() {
        let r = [
            Outcome {
                number: 1,
                name: "usb-port",
                status: Status::Pass,
                detail: "COM5 open".into(),
                duration: Duration::from_millis(3),
            },
            Outcome {
                number: 14,
                name: "reboot-persistence",
                status: Status::Skip,
                detail: "needs --allow-reboot".into(),
                duration: Duration::ZERO,
            },
        ];
        let j = report_json(&r);
        assert!(j.contains(r#""passed":1,"failed":0,"skipped":1"#), "{j}");
        assert!(j.contains(r#""status":"SKIP""#), "{j}");
    }
}
