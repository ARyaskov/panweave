//! `alerts …`: the experimental Zigbee → Wi-Fi → Zigbee notifications
//! (docs/esp32c6-wifi-alerts.md): status, configuration, a test message.
//!
//! Secrets (the Wi-Fi password, the bot token) are read from standard
//! input, never from the command line (shell history, process lists),
//! and never printed: the hub does not return them.

use std::io::BufRead;

use panweave_hub::protocol::alerts::{STAGES, auth, kinds};
use panweave_hub::protocol::{
    AlertConfigUpdate, AlertStage, AlertStatus, ErrorCode, Request, Response, ScanEntry, Text,
    WifiFailure, WifiScan,
};

use crate::diagcmd::unsupported;
use crate::json::{Obj, array};
use crate::{Hub, error_text, number};

const OLD_FIRMWARE: &str = "the hub firmware does not support Wi-Fi notifications (built without the `alerts` feature, or older than this CLI)";

fn kinds_names(k: u8) -> String {
    let mut v = Vec::new();
    for (bit, name) in [
        (kinds::LEAK, "leak"),
        (kinds::CONTACT, "contact"),
        (kinds::TAMPER, "tamper"),
        (kinds::BATTERY_LOW, "battery"),
    ] {
        if k & bit != 0 {
            v.push(name);
        }
    }
    if v.is_empty() {
        "none".into()
    } else {
        v.join(",")
    }
}

fn parse_kinds(s: &str) -> Result<u8, String> {
    let mut k = 0;
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        k |= match part {
            "leak" => kinds::LEAK,
            "contact" => kinds::CONTACT,
            "tamper" => kinds::TAMPER,
            "battery" => kinds::BATTERY_LOW,
            "none" => 0,
            "all" => kinds::ALL,
            p => {
                return Err(format!(
                    "unknown notification kind {p} (leak, contact, tamper, battery)"
                ));
            }
        };
    }
    Ok(k)
}

fn ms(v: Option<u32>) -> String {
    v.map_or_else(|| "-".into(), |v| format!("{v} ms"))
}

/// What a Wi-Fi disconnect reason code means (IEEE 802.11 reason codes;
/// 200 and above are the ESP-IDF driver's), for the codes a failed join
/// usually carries.
fn wifi_reason_name(code: u16) -> &'static str {
    match code {
        1 => "unspecified",
        2 => "authentication expired",
        3 => "deauthenticated: station leaving",
        4 => "disassociated: inactivity",
        5 => "access point full",
        8 => "disassociated: station leaving",
        13 => "invalid information element",
        14 => "MIC failure",
        15 => "4-way handshake timeout (wrong password?)",
        16 => "group key update timeout",
        17 => "information element differs in the handshake",
        18 => "invalid group cipher",
        19 => "invalid pairwise cipher",
        20 => "invalid AKMP",
        23 => "802.1X authentication failed",
        24 => "cipher suite rejected",
        29 => "bad cipher or AKM",
        39 => "timeout",
        200 => "beacon timeout",
        201 => "no access point found with this SSID",
        202 => "authentication failed (wrong password or security mode?)",
        203 => "association failed",
        204 => "handshake timeout (wrong password?)",
        205 => "connection failed",
        209 => "SA query timeout (PMF)",
        210 => "no access point with compatible security",
        211 => "no access point within the security threshold",
        212 => "no access point within the signal threshold",
        _ => "see IEEE 802.11 reason codes",
    }
}

/// `reason 201 (no access point found with this SSID), RSSI -71 dBm`.
fn wifi_failure_text(f: WifiFailure) -> String {
    format!(
        "reason {} ({}){}",
        f.reason,
        wifi_reason_name(f.reason),
        f.rssi
            .map(|r| format!(", RSSI {r} dBm"))
            .unwrap_or_default()
    )
}

/// `aa:bb:cc:dd:ee:ff` (or with `-`).
fn parse_mac(v: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = v.split([':', '-']).collect();
    let bad = || format!("BSSID {v:?}: expected six hex octets, aa:bb:cc:dd:ee:ff");
    if parts.len() != 6 {
        return Err(bad());
    }
    let mut m = [0u8; 6];
    for (o, p) in m.iter_mut().zip(parts) {
        if p.len() != 2 {
            return Err(bad());
        }
        *o = u8::from_str_radix(p, 16).map_err(|_| bad())?;
    }
    Ok(m)
}

fn mac_text(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An SSID for display (`(hidden)` when empty, lossy UTF-8).
fn ssid_text(ssid: &[u8]) -> String {
    if ssid.is_empty() {
        "(hidden)".into()
    } else {
        format!("\"{}\"", String::from_utf8_lossy(ssid))
    }
}

/// `"Neighbour" 02:11:22:33:44:55 ch 6, -48 dBm, WPA2`.
fn scan_entry_text(e: &ScanEntry) -> String {
    format!(
        "{} {} ch {}, {} dBm, {}",
        ssid_text(&e.ssid),
        mac_text(e.bssid),
        e.channel,
        e.rssi,
        auth::name(e.auth)
    )
}

fn scan_entry_json(e: &ScanEntry) -> String {
    Obj::new()
        .str("ssid", &String::from_utf8_lossy(&e.ssid))
        .str("bssid", &mac_text(e.bssid))
        .int("channel", e.channel.into())
        .int("rssi", e.rssi.into())
        .str("security", auth::name(e.auth))
        .finish()
}

fn scan_json(s: &WifiScan) -> String {
    let strongest: Vec<String> = s.strongest.iter().map(scan_entry_json).collect();
    let mut o = Obj::new()
        .int("scan_ms", s.scan_ms.into())
        .int("seen", s.seen.into());
    o = match &s.target {
        Some(t) => o.raw("target", &scan_entry_json(t)),
        None => o.raw("target", "null"),
    };
    o.raw("strongest", &array(&strongest)).finish()
}

/// Prints what a scan heard, with `indent` before each line.
fn print_scan(s: &WifiScan, ssid: &[u8], indent: &str) {
    println!(
        "{indent}scan: {} access point{} heard in {} ms",
        s.seen,
        if s.seen == 1 { "" } else { "s" },
        s.scan_ms
    );
    match &s.target {
        Some(t) => println!(
            "{indent}  {} heard: {}",
            ssid_text(ssid),
            scan_entry_text(t)
        ),
        None => println!(
            "{indent}  {} NOT heard (hidden: pin its BSSID to find it; 5 GHz only; out of range?)",
            ssid_text(ssid)
        ),
    }
    if s.seen == 0 {
        println!(
            "{indent}  nothing heard at all: suspect the radio after 802.15.4, not the network"
        );
    }
    for e in &s.strongest {
        println!("{indent}  {}", scan_entry_text(e));
    }
}

/// The last experiment's scan (`None`: none since boot).
fn get_scan(hub: &mut Hub) -> Result<Option<WifiScan>, String> {
    match hub.call(Request::GetWifiScan)? {
        Response::WifiScan(s) => Ok(s),
        r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
        Response::Error(ErrorCode::NotSupported) => Err(
            "this firmware cannot switch its radio (flash the experimental hub-wifi image)".into(),
        ),
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

/// `alerts scan`: what the last radio-switch experiment heard.
fn scan(hub: &mut Hub, as_json: bool) -> Result<(), String> {
    let ssid = get(hub)?.ssid;
    match get_scan(hub)? {
        Some(s) if as_json => println!("{}", scan_json(&s)),
        Some(s) => print_scan(&s, &ssid, ""),
        None if as_json => println!("null"),
        None => println!("no scan since boot: run `alerts probe`"),
    }
    Ok(())
}

pub(crate) fn status_json(s: &AlertStatus) -> String {
    let stages: Vec<String> = AlertStage::ALL
        .iter()
        .zip(s.stage_ms)
        .map(|(st, v)| {
            Obj::new()
                .str("stage", st.name())
                .opt("ms", v.map(Into::into))
                .finish()
        })
        .collect();
    Obj::new()
        .str("state", s.state.name())
        .bool("enabled", s.enabled)
        .str("ssid", &String::from_utf8_lossy(&s.ssid))
        .bool("password_set", s.password_set)
        .bool("token_set", s.token_set)
        .str("chat_id", &String::from_utf8_lossy(&s.chat_id))
        .str("notify", &kinds_names(s.kinds))
        .int("delay_ms", s.delay_ms.into())
        .int("budget_ms", s.budget_ms.into())
        .int("min_zigbee_ms", s.min_zigbee_ms.into())
        .int("boot_id", s.boot_id.into())
        .int("queue_depth", s.queue_depth.into())
        .int("queue_capacity", s.queue_capacity.into())
        .int("overflowed", s.overflowed.into())
        .opt("next_attempt_ms", s.next_attempt_ms.map(Into::into))
        .int("attempts", s.attempts.into())
        .int("successes", s.successes.into())
        .int("failures", s.failures.into())
        .int("ambiguous", s.ambiguous.into())
        .int("budget_overruns", s.budget_overruns.into())
        .int("restore_failures", s.restore_failures.into())
        .opt("last_downtime_ms", s.last_downtime_ms.map(Into::into))
        .opt("max_downtime_ms", s.max_downtime_ms.map(Into::into))
        .raw("stages", &array(&stages))
        .str("last_error", s.last_error.name())
        .opt_str("last_error_stage", s.last_error_stage.map(AlertStage::name))
        .opt("last_http_status", s.last_http_status.map(Into::into))
        .opt("last_message_id", s.last_message_id.map(Into::into))
        .int("probes", s.probes.into())
        .int("probes_associated", s.probes_associated.into())
        .opt("wifi_reason", s.wifi_failure.map(|f| f.reason.into()))
        .opt_str(
            "wifi_reason_name",
            s.wifi_failure.map(|f| wifi_reason_name(f.reason)),
        )
        .opt(
            "wifi_rssi",
            s.wifi_failure.and_then(|f| f.rssi).map(Into::into),
        )
        .opt_str("wifi_bssid", s.bssid.map(mac_text).as_deref())
        .opt("wifi_channel", s.channel.map(Into::into))
        .bool("wifi_wpa3_only", s.wpa3_only)
        .finish()
}

fn get(hub: &mut Hub) -> Result<AlertStatus, String> {
    match hub.call(Request::GetAlertStatus)? {
        Response::AlertStatus(s) => Ok(s),
        r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
        Response::Error(ErrorCode::NotSupported) => Err(OLD_FIRMWARE.into()),
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

fn status(hub: &mut Hub, as_json: bool) -> Result<(), String> {
    let s = get(hub)?;
    if as_json {
        println!("{}", status_json(&s));
        return Ok(());
    }
    println!("state             {}", s.state.name());
    println!(
        "wifi              ssid {:?}, password {}",
        String::from_utf8_lossy(&s.ssid),
        if s.password_set { "set" } else { "not set" }
    );
    println!(
        "wifi pin          {}, {}, {}",
        s.bssid
            .map_or("any BSSID".into(), |m| format!("BSSID {}", mac_text(m))),
        s.channel
            .map_or("all channels".into(), |c| format!("channel {c}")),
        if s.wpa3_only {
            "WPA3 only"
        } else {
            "WPA2 or better"
        }
    );
    println!(
        "telegram          chat {:?}, bot token {}",
        String::from_utf8_lossy(&s.chat_id),
        if s.token_set { "set" } else { "not set" }
    );
    println!("notify            {}", kinds_names(s.kinds));
    println!(
        "timing            check every {} ms (empty intervals stay in Zigbee), Zigbee downtime budget {} ms, at least {} ms of Zigbee between attempts",
        s.delay_ms, s.budget_ms, s.min_zigbee_ms
    );
    println!(
        "queue             {}/{} pending (boot {}), {} lost to a full queue",
        s.queue_depth, s.queue_capacity, s.boot_id, s.overflowed
    );
    if let Some(n) = s.next_attempt_ms {
        println!("next attempt      in {} s", n.div_ceil(1000));
    }
    println!(
        "attempts          {} ({} delivered, {} failed, {} ambiguous, {} over budget, {} restore failures)",
        s.attempts, s.successes, s.failures, s.ambiguous, s.budget_overruns, s.restore_failures
    );
    println!(
        "radio probes      {} ({} joined the access point)",
        s.probes, s.probes_associated
    );
    println!(
        "zigbee downtime   last {}, max {}",
        ms(s.last_downtime_ms),
        ms(s.max_downtime_ms)
    );
    if s.stage_ms.iter().any(Option::is_some) {
        let parts: Vec<String> = AlertStage::ALL
            .iter()
            .zip(s.stage_ms)
            .filter_map(|(st, v)| v.map(|v| format!("{} {v}", st.name())))
            .collect();
        println!("last stages (ms)  {}", parts.join(", "));
    }
    println!(
        "last error        {}{}{}",
        s.last_error.name(),
        s.last_error_stage
            .map(|st| format!(" at {}", st.name()))
            .unwrap_or_default(),
        s.last_http_status
            .map(|h| format!(" (HTTP {h})"))
            .unwrap_or_default()
    );
    if let Some(f) = s.wifi_failure {
        println!("wi-fi join        {}", wifi_failure_text(f));
    }
    if let Some(m) = s.last_message_id {
        println!("last delivered    message_id {m}");
    }
    debug_assert_eq!(s.stage_ms.len(), STAGES);
    Ok(())
}

fn text<const N: usize>(what: &str, v: &str) -> Result<Text<N>, String> {
    Text::from_slice(v.as_bytes()).map_err(|_| format!("{what} is longer than {N} octets"))
}

fn read_secret<const N: usize>(
    what: &str,
    lines: &mut impl Iterator<Item = std::io::Result<String>>,
) -> Result<Text<N>, String> {
    eprintln!("reading the {what} from standard input (one line)");
    let line = lines
        .next()
        .ok_or_else(|| format!("no {what} on standard input"))?
        .map_err(|e| format!("standard input: {e}"))?;
    let v = line.trim_end_matches(['\r', '\n']);
    if v.is_empty() {
        return Err(format!("empty {what}"));
    }
    text(what, v)
}

fn value<'a>(rest: &[&'a str], name: &str) -> Result<Option<&'a str>, String> {
    match rest.iter().position(|a| *a == name) {
        Some(i) => rest
            .get(i + 1)
            .copied()
            .map(Some)
            .ok_or_else(|| format!("{name} needs a value")),
        None => Ok(None),
    }
}

fn configure(hub: &mut Hub, rest: &[&str]) -> Result<(), String> {
    let mut u = AlertConfigUpdate::default();
    if rest.contains(&"--enable") {
        u.enabled = Some(true);
    }
    if rest.contains(&"--disable") {
        u.enabled = Some(false);
    }
    u.clear_secrets = rest.contains(&"--clear-secrets");
    if let Some(v) = value(rest, "--delay-ms")? {
        u.delay_ms = Some(number(v)?);
    }
    if let Some(v) = value(rest, "--interval-ms")? {
        if u.delay_ms.is_some() {
            return Err("use --interval-ms or its legacy alias --delay-ms, not both".into());
        }
        u.delay_ms = Some(number(v)?);
    }
    if let Some(v) = value(rest, "--budget-ms")? {
        u.budget_ms = Some(number(v)?);
    }
    if let Some(v) = value(rest, "--notify")? {
        u.kinds = Some(parse_kinds(v)?);
    }
    if let Some(v) = value(rest, "--wifi-ssid")? {
        u.ssid = Some(text("SSID", v)?);
    }
    if let Some(v) = value(rest, "--chat-id")? {
        u.chat_id = Some(text("chat id", v)?);
    }
    if let Some(v) = value(rest, "--wifi-bssid")? {
        u.bssid = Some(if v == "none" {
            None
        } else {
            Some(parse_mac(v)?)
        });
    }
    if let Some(v) = value(rest, "--wifi-channel")? {
        u.channel = Some(if v == "none" { None } else { Some(number(v)?) });
    }
    if rest.contains(&"--wifi-wpa3-only") {
        u.wpa3_only = Some(true);
    }
    if rest.contains(&"--wifi-allow-wpa2") {
        u.wpa3_only = Some(false);
    }
    for secret in ["--wifi-password", "--telegram-token"] {
        if rest.contains(&secret) {
            return Err(format!(
                "{secret} is not accepted on the command line; use {secret}-stdin"
            ));
        }
    }
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    if rest.contains(&"--wifi-password-stdin") {
        u.password = Some(read_secret("Wi-Fi password", &mut lines)?);
    }
    if rest.contains(&"--telegram-token-stdin") {
        u.token = Some(read_secret("Telegram bot token", &mut lines)?);
    }
    match hub.call(Request::SetAlertConfig(u))? {
        Response::Done => {
            println!("settings stored");
            Ok(())
        }
        Response::Error(ErrorCode::InvalidArgument) => Err(
            "refused: delay 1000-3600000 ms, budget 500-60000 ms, password at least 8 characters, token and chat id without spaces or quotes, channel 1-13, BSSID a unicast MAC address".into(),
        ),
        Response::Error(ErrorCode::StorageFailure) => {
            Err("the hub has no persistent storage: notifications need it".into())
        }
        r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
        Response::Error(ErrorCode::NotSupported) => Err(OLD_FIRMWARE.into()),
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

/// `alerts probe [--count N] [--interval S]`: the radio-switch
/// experiment, `count` times, one every `interval` seconds; prints each
/// run's downtime and stages, then the distribution.
fn probe(hub: &mut Hub, rest: &[&str], as_json: bool) -> Result<(), String> {
    let count: u32 = value(rest, "--count")?.map_or(Ok(1), number)?;
    let interval: u64 = value(rest, "--interval")?.map_or(Ok(60), number)?;
    if count == 0 || interval < 35 && count > 1 {
        return Err("--count at least 1; --interval at least 35 s between probes".into());
    }
    let mut downtimes = Vec::new();
    for i in 0..count {
        let before = get(hub)?;
        match hub.call(Request::RunRadioProbe)? {
            Response::Done => {}
            Response::Error(ErrorCode::InvalidArgument) => {
                return Err("set the Wi-Fi SSID (and password) first, or the radio failed to come back earlier (see `alerts status`)".into());
            }
            Response::Error(ErrorCode::NotSupported) => {
                return Err(
                    "this firmware cannot switch its radio (flash the experimental hub-wifi image)"
                        .into(),
                );
            }
            Response::Error(ErrorCode::Busy) => {
                return Err(
                    "less than 30 s since the last probe: Zigbee gets its time first".into(),
                );
            }
            r if unsupported(&r) => return Err(OLD_FIRMWARE.into()),
            Response::Error(e) => return Err(error_text(e)),
            r => return Err(format!("unexpected response: {r:?}")),
        }
        // The hub runs the probe at its next loop turn and does not
        // answer meanwhile: wait for the counter to move.
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(u64::from(before.budget_ms) + 15_000);
        let after = loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if let Ok(s) = get(hub)
                && s.probes > before.probes
            {
                break s;
            }
            if std::time::Instant::now() > deadline {
                return Err("the hub did not report the probe in time (`alerts status`, `diagnostics system`)".into());
            }
        };
        let joined = after.probes_associated > before.probes_associated;
        if let Some(d) = after.last_downtime_ms {
            downtimes.push(d);
        }
        // The scan of this run (the hub keeps the last one).
        let heard = get_scan(hub).ok().flatten();
        if as_json {
            println!(
                "{}",
                Obj::new()
                    .int("run", (i + 1).into())
                    .bool("joined", joined)
                    .raw("status", &status_json(&after))
                    .raw("scan", &heard.as_ref().map_or("null".into(), scan_json))
                    .finish()
            );
        } else {
            let stages: Vec<String> = AlertStage::ALL
                .iter()
                .zip(after.stage_ms)
                .filter_map(|(st, v)| v.map(|v| format!("{} {v}", st.name())))
                .collect();
            println!(
                "probe {}: {}, Zigbee down {}{} [{}]",
                i + 1,
                if joined {
                    "joined the access point".to_string()
                } else {
                    format!(
                        "failed ({}{}{})",
                        after.last_error.name(),
                        after
                            .last_error_stage
                            .map(|s| format!(" at {}", s.name()))
                            .unwrap_or_default(),
                        after
                            .wifi_failure
                            .map(|f| format!(": {}", wifi_failure_text(f)))
                            .unwrap_or_default()
                    )
                },
                ms(after.last_downtime_ms),
                if after.last_downtime_ms.is_some_and(|d| d > after.budget_ms) {
                    " (over budget)"
                } else {
                    ""
                },
                stages.join(", ")
            );
            if let Some(h) = &heard {
                print_scan(h, &after.ssid, "  ");
            }
        }
        if i + 1 < count {
            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
    }
    if !as_json && downtimes.len() > 1 {
        downtimes.sort_unstable();
        let pick = |q: f64| {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let i = ((downtimes.len() - 1) as f64 * q).round() as usize;
            downtimes[i.min(downtimes.len() - 1)]
        };
        println!(
            "downtime over {} probes: min {} ms, median {} ms, p95 {} ms, max {} ms",
            downtimes.len(),
            downtimes[0],
            pick(0.5),
            pick(0.95),
            downtimes[downtimes.len() - 1]
        );
    }
    Ok(())
}

/// `alerts [status] | alerts configure … | alerts test | alerts probe`.
pub(crate) fn run(hub: &mut Hub, args: &[&str], as_json: bool) -> Result<(), String> {
    match args {
        [] | ["status", ..] => status(hub, as_json),
        ["configure", rest @ ..] => configure(hub, rest),
        ["probe", rest @ ..] => probe(hub, rest, as_json),
        ["scan", ..] => scan(hub, as_json),
        ["test", ..] => match hub.call(Request::QueueTestAlert)? {
            Response::Done => {
                println!(
                    "test notification queued; it is sent with the next attempt (`alerts status` shows when)"
                );
                Ok(())
            }
            Response::Error(ErrorCode::InvalidArgument) => {
                Err("notifications are disabled: `alerts configure --enable` first".into())
            }
            r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
            Response::Error(ErrorCode::NotSupported) => Err(OLD_FIRMWARE.into()),
            Response::Error(e) => Err(error_text(e)),
            r => Err(format!("unexpected response: {r:?}")),
        },
        _ => Err(crate::USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_bssid_parses_with_colons_or_dashes_and_prints_back() {
        let m = [0x02, 0x1a, 0xb2, 0x33, 0x44, 0xff];
        assert_eq!(parse_mac("02:1a:B2:33:44:ff").unwrap(), m);
        assert_eq!(parse_mac("02-1a-b2-33-44-ff").unwrap(), m);
        assert_eq!(mac_text(m), "02:1a:b2:33:44:ff");
        for bad in [
            "02:1a:b2:33:44",
            "02:1a:b2:33:44:ff:00",
            "2:1a:b2:33:44:ff",
            "zz:1a:b2:33:44:ff",
        ] {
            assert!(parse_mac(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn notification_kinds_parse_and_print() {
        assert_eq!(
            parse_kinds("leak,contact").unwrap(),
            kinds::LEAK | kinds::CONTACT
        );
        assert_eq!(parse_kinds("all").unwrap(), kinds::ALL);
        assert_eq!(parse_kinds("none").unwrap(), 0);
        assert!(parse_kinds("door").is_err());
        assert_eq!(kinds_names(kinds::DEFAULT), "leak,contact");
        assert_eq!(kinds_names(0), "none");
    }

    #[test]
    fn the_status_json_has_no_secret_fields() {
        let s = AlertStatus {
            password_set: true,
            token_set: true,
            ..AlertStatus::default()
        };
        let j = status_json(&s);
        assert!(j.contains(r#""password_set":true"#) && j.contains(r#""token_set":true"#));
        assert!(!j.contains("\"password\"") && !j.contains("\"token\""));
        assert!(
            j.contains(r#""stages":[{"stage":"stop-zigbee","ms":null}"#),
            "{j}"
        );
    }
}
