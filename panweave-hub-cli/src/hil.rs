//! `hil …`: operator-driven hardware-in-the-loop checks of one real device
//! (a light, a contact sensor, a water leak sensor, or one of the v0.3.0
//! target products), with a reproducible JSON report.
//!
//! Target scenarios (`aqara-leak`, `sber-contact`, `yandex-leak`) also
//! check that the device matches its compatibility profile, record its
//! fingerprint with provenance, its battery report, and that it keeps
//! reporting after a battery power cycle. Nothing is destructive: no
//! factory reset, no network change. A run's overall result is PASS only
//! when every step passed with the operator present; a run with skipped
//! steps is INCOMPLETE. A PASS report is the evidence a profile needs
//! before its verification status may be changed (by a reviewed code
//! change, never by this tool).
//!
//! The workflow is vendor neutral: it only uses what the hub's interview
//! and normalized state report, and asks the operator to act on the device
//! and to confirm what only a person can see (a lamp turning on). Each
//! step is PASS, FAIL or SKIP; the report carries the hub's identity and
//! the device's trace records during the run.

use std::io::{BufRead, Write as _};
use std::time::{Duration, Instant};

use panweave_hub::compat;
use panweave_hub::model::{ContactState, Ieee, LeakState};
use panweave_hub::protocol::{
    CommandStage, DeviceInfo, Event, LightCommand, Message, Request, Response,
};

use crate::json::{Obj, array};
use crate::selftest::Status;
use crate::{Hub, error_text, text};
use crate::{diagcmd, fingerprint, securitycmd};

struct Step {
    name: String,
    status: Status,
    detail: String,
    duration: Duration,
}

/// What a run may ask of the operator.
pub(crate) struct Options {
    /// Never prompt: steps that need the operator's eyes are skipped.
    pub(crate) unattended: bool,
    /// How long to wait for each physical action.
    pub(crate) wait: Duration,
}

fn ask(o: &Options, question: &str) -> Option<bool> {
    if o.unattended {
        return None;
    }
    eprint!("{question} [y/n] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    match line.trim() {
        "y" | "Y" | "yes" => Some(true),
        "n" | "N" | "no" => Some(false),
        _ => None,
    }
}

fn tell(o: &Options, what: &str) -> bool {
    if o.unattended {
        return false;
    }
    eprintln!(">>> {what}");
    true
}

fn command(hub: &mut Hub, request: Request) -> Result<(CommandStage, Duration), String> {
    let started = Instant::now();
    match hub.call(request)? {
        Response::Accepted { command } => match hub.outcome(command, Duration::from_secs(30))? {
            Event::CommandCompleted { stage, .. } => Ok((stage, started.elapsed())),
            e => Err(format!("{e:?}")),
        },
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

/// Waits for the device's normalized state to satisfy `done`.
fn wait_state(
    hub: &mut Hub,
    target: u64,
    wait: Duration,
    done: &dyn Fn(&panweave_hub::model::DeviceState) -> bool,
) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < wait && !crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
        if let Ok(Message::Event {
            event: Event::DeviceStateChanged { ieee, state },
            ..
        }) = hub.rx.recv_timeout(Duration::from_millis(500))
            && ieee == target
            && done(&state)
        {
            return Some(started.elapsed());
        }
    }
    None
}

fn light_steps(hub: &mut Hub, target: u64, o: &Options, steps: &mut Vec<Step>) {
    for (name, cmd, question) in [
        ("turn-on", LightCommand::TurnOn, Some("Is the light ON?")),
        ("turn-off", LightCommand::TurnOff, Some("Is the light OFF?")),
        ("toggle", LightCommand::Toggle, None),
        (
            "brightness-50",
            LightCommand::SetBrightness {
                percent: 50,
                transition_ds: 0,
            },
            Some("Is the light on at about half brightness?"),
        ),
        ("turn-off-again", LightCommand::TurnOff, None),
    ] {
        let started = Instant::now();
        let (status, detail) = match command(
            hub,
            Request::Light {
                ieee: target,
                endpoint: 0,
                command: cmd,
            },
        ) {
            Ok((stage, took)) => {
                let confirmed = format!("{} in {} ms", stage.name(), took.as_millis());
                match question.map(|q| ask(o, q)) {
                    None => (Status::Pass, confirmed),
                    Some(Some(true)) => (Status::Pass, format!("{confirmed}, operator confirmed")),
                    Some(Some(false)) => {
                        (Status::Fail, format!("{confirmed}, operator saw no change"))
                    }
                    Some(None) => (Status::Pass, format!("{confirmed}, not visually confirmed")),
                }
            }
            Err(e) if e.contains("NotSupported") || e.contains("not-supported") => {
                (Status::Skip, e)
            }
            Err(e) => (Status::Fail, e),
        };
        steps.push(Step {
            name: name.into(),
            status,
            detail,
            duration: started.elapsed(),
        });
    }
}

fn sensor_step(
    hub: &mut Hub,
    target: u64,
    o: &Options,
    name: &str,
    instruction: &str,
    done: &dyn Fn(&panweave_hub::model::DeviceState) -> bool,
) -> Step {
    let started = Instant::now();
    let (status, detail) = if tell(o, instruction) {
        match wait_state(hub, target, o.wait, done) {
            Some(t) => (Status::Pass, format!("reported after {} ms", t.as_millis())),
            None => (
                Status::Fail,
                format!(
                    "no matching state change within {} s (`diagnostics device {}`)",
                    o.wait.as_secs(),
                    Ieee(target)
                ),
            ),
        }
    } else {
        (Status::Skip, "needs an operator".into())
    };
    Step {
        name: name.into(),
        status,
        detail,
        duration: started.elapsed(),
    }
}

fn identity_step(d: &DeviceInfo, want: &str) -> Step {
    let ok = d.summary.interview.is_finished();
    Step {
        name: "interviewed".into(),
        status: if ok { Status::Pass } else { Status::Fail },
        detail: format!(
            "{} {} ({}), category {}, wanted {want}, interview {}",
            text(&d.manufacturer),
            text(&d.summary.model),
            text(&d.sw_build),
            d.summary.category.name(),
            d.summary.interview.name()
        ),
        duration: Duration::ZERO,
    }
}

/// A v0.3.0 target product: its compatibility profile and sensor kind.
struct Target {
    profile: &'static str,
    leak: bool,
}

fn product(kind: &str) -> Option<Target> {
    match kind {
        "aqara-leak" => Some(Target {
            profile: "aqara-water-leak-t1",
            leak: true,
        }),
        "sber-contact" => Some(Target {
            profile: "sber-opening-sensor",
            leak: false,
        }),
        "yandex-leak" => Some(Target {
            profile: "yandex-water-leak-00527",
            leak: true,
        }),
        _ => None,
    }
}

fn step(name: &str, status: Status, detail: String) -> Step {
    Step {
        name: name.into(),
        status,
        detail,
        duration: Duration::ZERO,
    }
}

/// The device is the product the scenario is for.
fn profile_step(d: &DeviceInfo, want: &str) -> Step {
    let found = compat::lookup(&d.manufacturer, &d.summary.model).map(|p| p.id);
    let detail = format!(
        "{:?} / {:?} matches {}",
        text(&d.manufacturer),
        text(&d.summary.model),
        found.unwrap_or("no profile")
    );
    if found == Some(want) {
        step("profile", Status::Pass, detail)
    } else {
        step(
            "profile",
            Status::Fail,
            format!("{detail}, expected {want}"),
        )
    }
}

/// The identity was observed (not inferred).
fn fingerprint_step(d: &DeviceInfo) -> Step {
    let f = fingerprint::fields(d);
    let unknown: Vec<&str> = f
        .iter()
        .filter(|x| x.provenance == fingerprint::Provenance::Unknown)
        .map(|x| x.name)
        .collect();
    let identity = !d.manufacturer.is_empty() || !d.summary.model.is_empty();
    step(
        "fingerprint",
        if identity { Status::Pass } else { Status::Fail },
        if unknown.is_empty() {
            "every value observed or documented".into()
        } else {
            format!("not reported: {}", unknown.join(", "))
        },
    )
}

/// What the device reported about its battery (never inferred from the
/// voltage).
fn battery_step(hub: &mut Hub, target: u64) -> Step {
    let state = match hub.call(Request::GetDeviceState { ieee: target }) {
        Ok(Response::DeviceState { state, .. }) => state,
        Ok(r) => {
            return step(
                "battery",
                Status::Fail,
                format!("unexpected response: {r:?}"),
            );
        }
        Err(e) => return step("battery", Status::Fail, e),
    };
    let mut parts = Vec::new();
    if let Some(mv) = state.battery_mv {
        parts.push(format!("{mv} mV"));
    }
    if let Some(p) = state.battery_percent {
        parts.push(format!("{p} %"));
    }
    if parts.is_empty() {
        step(
            "battery",
            Status::Skip,
            "no battery value reported yet (a sleepy sensor reports on its own schedule)".into(),
        )
    } else {
        step(
            "battery",
            Status::Pass,
            format!("{}, battery low {:?}", parts.join(", "), state.battery_low),
        )
    }
}

/// The device is heard again after the operator power-cycles it.
fn power_cycle_step(hub: &mut Hub, target: u64, o: &Options) -> Step {
    let started = Instant::now();
    let last_seen = |hub: &mut Hub| match hub.call(Request::GetDevice { ieee: target }) {
        Ok(Response::Device(d)) => d.summary.last_seen_s,
        _ => None,
    };
    let before = last_seen(hub);
    if !tell(
        o,
        "Remove the sensor's battery for 10 s, then put it back (no reset button, no pairing).",
    ) {
        return step("power-cycle", Status::Skip, "needs an operator".into());
    }
    let limit = o.wait + Duration::from_secs(10);
    while started.elapsed() < limit && !crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(2));
        let now = last_seen(hub);
        if now.is_some() && now > before.map(|b| b.saturating_add(5)) {
            return Step {
                name: "power-cycle".into(),
                status: Status::Pass,
                detail: format!("heard again after {} ms", started.elapsed().as_millis()),
                duration: started.elapsed(),
            };
        }
    }
    Step {
        name: "power-cycle".into(),
        status: Status::Fail,
        detail: format!("not heard within {} s", limit.as_secs()),
        duration: started.elapsed(),
    }
}

fn sensor_pair(hub: &mut Hub, target: u64, o: &Options, leak: bool, suffix: &str) -> [Step; 2] {
    if leak {
        [
            sensor_step(
                hub,
                target,
                o,
                &format!("leak{suffix}"),
                "Put a drop of water across the sensor's probes (keep water away from the hub and any other electronics).",
                &|s| s.water_leak == LeakState::Leak,
            ),
            sensor_step(
                hub,
                target,
                o,
                &format!("dry{suffix}"),
                "Dry the probes completely.",
                &|s| s.water_leak == LeakState::Dry,
            ),
        ]
    } else {
        [
            sensor_step(
                hub,
                target,
                o,
                &format!("open{suffix}"),
                "Open the contact (separate the magnet).",
                &|s| s.contact == ContactState::Open,
            ),
            sensor_step(
                hub,
                target,
                o,
                &format!("close{suffix}"),
                "Close the contact.",
                &|s| s.contact == ContactState::Closed,
            ),
        ]
    }
}

/// The run's overall result: PASS only when every step passed.
fn result(steps: &[Step]) -> &'static str {
    if steps.iter().any(|s| s.status == Status::Fail) {
        "FAIL"
    } else if steps.iter().all(|s| s.status == Status::Pass) {
        "PASS"
    } else {
        "INCOMPLETE"
    }
}

/// The source tree's commit, when the tool runs inside a git checkout.
fn commit() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (out.status.success() && !s.is_empty()).then(|| s.to_owned())
}

/// The current UTC time as RFC 3339.
fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    utc(secs)
}

/// Seconds since the Unix epoch as an RFC 3339 UTC time.
fn utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Runs `hil <kind> <ieee>` and writes the report; true when no step failed.
pub(crate) fn run(
    hub: &mut Hub,
    kind: &str,
    target: u64,
    o: &Options,
    report: Option<&str>,
) -> Result<bool, String> {
    let device = match hub.call(Request::GetDevice { ieee: target })? {
        Response::Device(d) => d,
        Response::Error(e) => return Err(error_text(e)),
        r => return Err(format!("unexpected response: {r:?}")),
    };
    let first_seq = diagcmd::read_page(hub, 0, None).map_or(0, |p| p.next);
    let mut steps = vec![identity_step(&device, kind)];
    match kind {
        _ if product(kind).is_some() => {
            let (profile, leak) = product(kind).map_or(("", false), |t| (t.profile, t.leak));
            steps.push(profile_step(&device, profile));
            steps.push(fingerprint_step(&device));
            steps.extend(sensor_pair(hub, target, o, leak, ""));
            steps.push(battery_step(hub, target));
            steps.push(power_cycle_step(hub, target, o));
            steps.extend(sensor_pair(hub, target, o, leak, "-after-power-cycle"));
        }
        "light" => light_steps(hub, target, o, &mut steps),
        "contact" => {
            steps.push(sensor_step(
                hub,
                target,
                o,
                "open",
                "Open the contact (separate the magnet).",
                &|s| s.contact == ContactState::Open,
            ));
            steps.push(sensor_step(
                hub,
                target,
                o,
                "close",
                "Close the contact.",
                &|s| s.contact == ContactState::Closed,
            ));
        }
        "leak" => {
            steps.push(sensor_step(
                hub,
                target,
                o,
                "leak",
                "Wet the sensor's probes.",
                &|s| s.water_leak == LeakState::Leak,
            ));
            steps.push(sensor_step(
                hub,
                target,
                o,
                "dry",
                "Dry the probes completely.",
                &|s| s.water_leak == LeakState::Dry,
            ));
        }
        _ => {
            return Err(format!(
                "unknown device kind {kind} (light, contact, leak, aqara-leak, sber-contact, yandex-leak)"
            ));
        }
    }
    for s in &steps {
        println!("{:<26} {}  {}", s.name, s.status.name(), s.detail);
    }
    println!("result: {}", result(&steps));
    if let Some(path) = report {
        let hub_info = match hub.call(Request::GetHubInfo)? {
            Response::HubInfo(h) => Obj::new()
                .str("ieee", &Ieee(h.ieee).to_string())
                .str("firmware", &text(&h.firmware))
                .finish(),
            _ => "null".into(),
        };
        let build = match hub.call(Request::GetBootReport)? {
            Response::BootReport(b) => Some(text(&b.build)),
            _ => None,
        };
        let records: Vec<String> = match diagcmd::read_all(hub, Some(target)) {
            Ok((records, uptime, _)) => records
                .iter()
                .filter(|r| r.seq.wrapping_sub(first_seq) < u32::MAX / 2)
                .map(|r| diagcmd::record_json(r, uptime))
                .collect(),
            Err(_) => Vec::new(),
        };
        let step_json: Vec<String> = steps
            .iter()
            .map(|s| {
                Obj::new()
                    .str("name", &s.name)
                    .str("status", s.status.name())
                    .str("detail", &s.detail)
                    .int(
                        "duration_ms",
                        i128::try_from(s.duration.as_millis()).unwrap_or(0),
                    )
                    .finish()
            })
            .collect();
        let fingerprint: Vec<String> = fingerprint::fields(&device)
            .iter()
            .map(|x| {
                Obj::new()
                    .str("name", x.name)
                    .opt_str("value", x.value.as_deref())
                    .str("provenance", x.provenance.label())
                    .finish()
            })
            .collect();
        let profile = compat::lookup(&device.manufacturer, &device.summary.model);
        let runtime =
            diagcmd::get_runtime(hub).map_or_else(|_| "null".into(), |d| diagcmd::runtime_json(&d));
        let security = match hub.call(Request::GetSecurityStatus) {
            Ok(Response::SecurityStatus(s)) => securitycmd::status_json(&s),
            _ => "null".into(),
        };
        let json = Obj::new()
            .str(
                "tool",
                concat!("panweave-hub-cli ", env!("CARGO_PKG_VERSION")),
            )
            .str("kind", kind)
            .str("date", &now_utc())
            .opt_str("commit", commit().as_deref())
            .str("result", result(&steps))
            .raw("hub", &hub_info)
            .opt_str("build", build.as_deref())
            .opt_str("profile", profile.map(|p| p.id))
            .opt_str("commercial_model", profile.map(|p| p.commercial_model))
            .opt_str(
                "profile_verification",
                profile.map(|p| p.verification.name()),
            )
            .raw(
                "device",
                &Obj::new()
                    .str("ieee", &Ieee(target).to_string())
                    .str("manufacturer", &text(&device.manufacturer))
                    .str("model", &text(&device.summary.model))
                    .str("sw_build", &text(&device.sw_build))
                    .str("category", device.summary.category.name())
                    .str("power", device.power_source.name())
                    .raw("fingerprint", &array(&fingerprint))
                    .finish(),
            )
            .raw(
                "diagnostics",
                &Obj::new()
                    .raw("runtime", &runtime)
                    .raw("security", &security)
                    .finish(),
            )
            .bool("operator_present", !o.unattended)
            .raw("steps", &array(&step_json))
            .raw("trace", &array(&records))
            .finish();
        std::fs::write(path, json + "\n").map_err(|e| format!("{path}: {e}"))?;
        println!("report written to {path}");
    }
    Ok(!steps.iter().any(|s| s.status == Status::Fail))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_run_passes_only_when_every_step_passed() {
        let s = |st| step("x", st, String::new());
        assert_eq!(result(&[s(Status::Pass), s(Status::Pass)]), "PASS");
        assert_eq!(result(&[s(Status::Pass), s(Status::Skip)]), "INCOMPLETE");
        assert_eq!(result(&[s(Status::Skip), s(Status::Fail)]), "FAIL");
        assert_eq!(result(&[s(Status::Skip)]), "INCOMPLETE");
    }

    #[test]
    fn targets_name_existing_profiles() {
        for kind in ["aqara-leak", "sber-contact", "yandex-leak"] {
            let t = product(kind).unwrap();
            assert!(compat::PROFILES.iter().any(|p| p.id == t.profile), "{kind}");
        }
        assert!(
            product("sber-bulb").is_none(),
            "SBDV-00115 is not a Zigbee device"
        );
    }

    #[test]
    fn dates_are_rfc3339() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc(1_792_627_199), "2026-10-21T23:59:59Z");
    }
}
