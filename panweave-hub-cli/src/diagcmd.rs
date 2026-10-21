//! `diagnostics …`: the hub's boot report, counters and trace.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::Ordering;
use std::time::Duration;

use panweave_hub::diag::{
    ALL_CATEGORIES, Category, DiagRecord, Severity, code, code_name, ias_bits,
};
use panweave_hub::esp32c6;
use panweave_hub::model::{Ieee, InterviewStage};
use panweave_hub::partitions::Finding;
use panweave_hub::protocol::{
    BootReport, ErrorCode, MAX_TRACE_PAGE, QueueUsage, RadioDiagnostics, Request, Response,
    RuntimeDiagnostics, StorageDiagnostics, StoreUsage, TracePage,
};

use crate::json::{Obj, array, string};
use crate::{Hub, STOP, error_text, ieee, text};

/// A response that only an older firmware gives to a diagnostic request.
pub(crate) fn unsupported(r: &Response) -> bool {
    matches!(r, Response::Error(ErrorCode::UnknownRequest))
}

const OLD_FIRMWARE: &str =
    "the hub firmware does not support this request (diagnostics need firmware 0.2.1 or later)";

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "unavailable".into(), |v| v.to_string())
}

fn opt_i(v: Option<impl Into<i128>>) -> Option<i128> {
    v.map(Into::into)
}

/// Absolute milliseconds since boot of a record stamped `at_ms` (modulo
/// 2³²), read at `uptime_ms`.
pub(crate) fn unwrap_ms(uptime_ms: u64, at_ms: u32) -> u64 {
    let now32 = u32::try_from(uptime_ms & u64::from(u32::MAX)).unwrap_or(0);
    uptime_ms.saturating_sub(u64::from(now32.wrapping_sub(at_ms)))
}

fn finding_text(code: u8) -> &'static str {
    // Rebuild a finding of each kind to reuse its description.
    let f = match code {
        1 => Finding::Overlap(0, 0),
        2 => Finding::OverlapsTable(0),
        3 => Finding::OutOfFlash(0),
        4 => Finding::Misaligned(0),
        5 => Finding::AppMisaligned(0),
        6 => Finding::DuplicateLabel(0),
        7 => Finding::HubdataMissing,
        8 => Finding::HubdataNotData(0),
        9 => Finding::HubdataTooSmall(0),
        10 => Finding::NvsMoved,
        11 => Finding::NoApp,
        12 => Finding::ImageTooLarge(0, 0),
        _ => return "unknown finding",
    };
    f.describe()
}

fn system(hub: &mut Hub, as_json: bool) -> Result<(), String> {
    let r = hub.call(Request::GetBootReport)?;
    let b = match r {
        Response::BootReport(b) => b,
        r if unsupported(&r) => return Err(OLD_FIRMWARE.into()),
        Response::Error(e) => return Err(error_text(e)),
        r => return Err(format!("unexpected response: {r:?}")),
    };
    if as_json {
        println!("{}", boot_json(&b));
        return Ok(());
    }
    println!("chip          {}", text(&b.chip));
    println!(
        "revision      {}",
        b.chip_revision.map_or_else(
            || "unavailable".into(),
            |r| format!("v{}.{}", r / 100, r % 100)
        )
    );
    println!(
        "firmware      {} (build {})",
        text(&b.firmware),
        text(&b.build)
    );
    match (b.reset, b.reset_raw) {
        (Some(k), Some(raw)) => println!(
            "reset         {} ({:#04x}: {})",
            k.name(),
            raw,
            esp32c6::reset_reason_name(raw)
        ),
        (Some(k), None) => println!("reset         {}", k.name()),
        _ => println!("reset         unavailable"),
    }
    println!("cpu clock     {} MHz", opt(b.cpu_mhz));
    println!(
        "flash         {}",
        b.flash_size
            .map_or_else(|| "unavailable".into(), |s| format!("{} KiB", s / 1024))
    );
    println!("ieee          {}", Ieee(b.ieee));
    println!("radio channel {}", opt(b.radio_channel));
    println!(
        "network       {}",
        b.network.map_or("unavailable", |n| n.name())
    );
    println!(
        "registry      {} device(s), {}",
        opt(b.registry_devices),
        if b.registry_persistent {
            "persistent"
        } else {
            "RAM only"
        }
    );
    println!(
        "usb           {}",
        if b.usb_ready { "ready" } else { "not ready" }
    );
    println!(
        "watchdog      {}",
        b.watchdog_s
            .map_or_else(|| "off".into(), |s| format!("{s} s"))
    );
    println!("boot time     {} ms", opt(b.boot_ms));
    println!(
        "partitions    {}",
        if b.partition_table_read {
            "table read"
        } else {
            "table could not be read"
        }
    );
    for (i, p) in b.partitions.iter().enumerate() {
        println!(
            "  {i}: {:<10} type {:#04x} subtype {:#04x} offset {:#08x} size {:#08x}",
            text(&p.label),
            p.kind,
            p.subtype,
            p.offset,
            p.size
        );
    }
    match b.hubdata {
        Some((o, s)) => println!("registry area {o:#08x} + {s:#x}"),
        None => println!("registry area none (no usable hubdata partition)"),
    }
    for f in &b.findings {
        let part = if f.partition == 0xff {
            String::new()
        } else {
            format!(" (partition {})", f.partition)
        };
        println!("finding       {}{part}", finding_text(f.code));
    }
    Ok(())
}

pub(crate) fn boot_json(b: &BootReport) -> String {
    let parts: Vec<String> = b
        .partitions
        .iter()
        .map(|p| {
            Obj::new()
                .str("label", &text(&p.label))
                .int("type", p.kind.into())
                .int("subtype", p.subtype.into())
                .int("offset", p.offset.into())
                .int("size", p.size.into())
                .finish()
        })
        .collect();
    let findings: Vec<String> = b
        .findings
        .iter()
        .map(|f| {
            Obj::new()
                .int("code", f.code.into())
                .str("description", finding_text(f.code))
                .opt(
                    "partition",
                    (f.partition != 0xff).then_some(f.partition.into()),
                )
                .finish()
        })
        .collect();
    Obj::new()
        .str("chip", &text(&b.chip))
        .opt("chip_revision", opt_i(b.chip_revision))
        .str("firmware", &text(&b.firmware))
        .str("build", &text(&b.build))
        .opt_str("reset", b.reset.map(|r| r.name()))
        .opt("reset_raw", opt_i(b.reset_raw))
        .opt("cpu_mhz", opt_i(b.cpu_mhz))
        .opt("flash_size", opt_i(b.flash_size))
        .bool("partition_table_read", b.partition_table_read)
        .raw("partitions", &array(&parts))
        .raw("findings", &array(&findings))
        .opt("hubdata_offset", b.hubdata.map(|(o, _)| o.into()))
        .opt("hubdata_size", b.hubdata.map(|(_, s)| s.into()))
        .str("ieee", &Ieee(b.ieee).to_string())
        .opt("radio_channel", opt_i(b.radio_channel))
        .opt_str("network", b.network.map(|n| n.name()))
        .opt("registry_devices", opt_i(b.registry_devices))
        .bool("registry_persistent", b.registry_persistent)
        .bool("usb_ready", b.usb_ready)
        .opt("watchdog_s", opt_i(b.watchdog_s))
        .opt("boot_ms", opt_i(b.boot_ms))
        .finish()
}

pub(crate) fn radio_json(d: &RadioDiagnostics) -> String {
    let driver = d.driver.map_or_else(
        || "null".to_string(),
        |s| {
            Obj::new()
                .int("tx_attempts", s.tx_attempts.into())
                .int("tx_acked", s.tx_acked.into())
                .int("tx_no_ack_or_cca", s.tx_no_ack.into())
                .int("tx_cca_failures", s.tx_cca_failures.into())
                .int("tx_faults", s.tx_faults.into())
                .int("rx_frames", s.rx_frames.into())
                .int("rx_malformed", s.rx_malformed.into())
                .int("config_errors", s.config_errors.into())
                .int("config_flushes", s.config_flushes.into())
                .opt("last_rssi_dbm", opt_i(s.last_rssi))
                .opt("last_lqi", opt_i(s.last_lqi))
                .finish()
        },
    );
    Obj::new()
        .opt("channel", opt_i(d.channel))
        .opt("tx_power_dbm", opt_i(d.tx_power_dbm))
        .bool("energy_detection", d.energy_detection)
        .raw("driver", &driver)
        .int("mac_tx_ucast", d.mac_tx_ucast.into())
        .int("mac_tx_ucast_retry", d.mac_tx_ucast_retry.into())
        .int("mac_tx_ucast_fail", d.mac_tx_ucast_fail.into())
        .int("mac_rx_ucast", d.mac_rx_ucast.into())
        .int("mac_tx_bcast", d.mac_tx_bcast.into())
        .int("mac_rx_bcast", d.mac_rx_bcast.into())
        .int("mac_queue_full", d.mac_queue_full.into())
        .int("nwk_malformed", d.nwk_malformed.into())
        .int("nwk_security_failures", d.nwk_security_failures.into())
        .int("nwk_replays", d.nwk_replays.into())
        .int("nwk_no_route", d.nwk_no_route.into())
        .int("nwk_pending_full", d.nwk_pending_full.into())
        .int("nwk_pending_high_water", d.nwk_pending_high_water.into())
        .int("nwk_pending", d.nwk_pending.into())
        .int("nwk_pending_held", d.nwk_pending_held.into())
        .int("nwk_pending_capacity", d.nwk_pending_capacity.into())
        .int("aps_tx_success", d.aps_tx_success.into())
        .int("aps_retries", d.aps_retries.into())
        .int("aps_ack_failures", d.aps_ack_failures.into())
        .int("aps_security_dropped", d.aps_security_dropped.into())
        .int("aps_malformed", d.aps_malformed.into())
        .finish()
}

fn radio(hub: &mut Hub, as_json: bool) -> Result<(), String> {
    let d = match hub.call(Request::GetRadioDiagnostics)? {
        Response::RadioDiagnostics(d) => d,
        r if unsupported(&r) => return Err(OLD_FIRMWARE.into()),
        r => return Err(format!("unexpected response: {r:?}")),
    };
    if as_json {
        println!("{}", radio_json(&d));
        return Ok(());
    }
    println!("channel            {}", opt(d.channel));
    println!(
        "tx power           {}",
        d.tx_power_dbm
            .map_or_else(|| "unavailable".into(), |p| format!("{p} dBm"))
    );
    println!(
        "energy detection   {}",
        if d.energy_detection {
            "available"
        } else {
            "not provided by the driver"
        }
    );
    match d.driver {
        Some(s) => {
            println!("driver (radio adapter, observed):");
            println!("  tx attempts      {}", s.tx_attempts);
            println!("  tx acked         {}", s.tx_acked);
            println!(
                "  tx no ack / CCA  {} (the driver does not tell which)",
                s.tx_no_ack
            );
            println!(
                "  tx CCA failures  {} (frames sent without an ack request)",
                s.tx_cca_failures
            );
            println!("  tx faults        {}", s.tx_faults);
            println!("  rx frames        {}", s.rx_frames);
            println!("  rx malformed     {}", s.rx_malformed);
            println!("  config errors    {}", s.config_errors);
            println!("  config flushes   {}", s.config_flushes);
            println!(
                "  last rx          rssi {} dBm, lqi {}",
                opt(s.last_rssi),
                opt(s.last_lqi)
            );
            println!("  rx queue overflow unavailable (reported only in the driver's log)");
        }
        None => println!("driver             unavailable"),
    }
    println!("MAC service (software retries):");
    println!(
        "  unicast tx {} retries {} failed {} | rx {}",
        d.mac_tx_ucast, d.mac_tx_ucast_retry, d.mac_tx_ucast_fail, d.mac_rx_ucast
    );
    println!(
        "  broadcast tx {} rx {} | queue full {}",
        d.mac_tx_bcast, d.mac_rx_bcast, d.mac_queue_full
    );
    println!("NWK:");
    println!(
        "  malformed {} security failures {} replays {} no route {}",
        d.nwk_malformed, d.nwk_security_failures, d.nwk_replays, d.nwk_no_route
    );
    println!(
        "  pending unicasts {}/{} ({} held for sleepy children), most {}, refused when full {}",
        d.nwk_pending,
        d.nwk_pending_capacity,
        d.nwk_pending_held,
        d.nwk_pending_high_water,
        d.nwk_pending_full
    );
    println!("APS (end-to-end acknowledgements):");
    println!(
        "  acked {} retries {} unacknowledged {} security dropped {} malformed {}",
        d.aps_tx_success,
        d.aps_retries,
        d.aps_ack_failures,
        d.aps_security_dropped,
        d.aps_malformed
    );
    Ok(())
}

fn store_text(s: Option<StoreUsage>) -> String {
    s.map_or_else(
        || "unavailable".into(),
        |s| {
            format!(
                "{} of {} octets free, {} writes, {} compactions, {} corrupt records, {} I/O errors{}",
                s.free,
                s.capacity,
                s.writes,
                s.compactions,
                s.corrupt_records,
                s.io_errors,
                if s.formatted_at_open {
                    ", formatted at boot (was blank or unreadable)"
                } else {
                    ""
                }
            )
        },
    )
}

fn store_json(s: Option<StoreUsage>) -> String {
    s.map_or_else(
        || "null".into(),
        |s| {
            Obj::new()
                .int("capacity", s.capacity.into())
                .int("free", s.free.into())
                .int("writes", s.writes.into())
                .int("compactions", s.compactions.into())
                .int("corrupt_records", s.corrupt_records.into())
                .int("io_errors", s.io_errors.into())
                .bool("formatted_at_open", s.formatted_at_open)
                .finish()
        },
    )
}

pub(crate) fn storage_json(d: &StorageDiagnostics) -> String {
    Obj::new()
        .bool("registry_persistent", d.registry_persistent)
        .int("registry_devices", d.registry_devices.into())
        .int("registry_writes", d.registry_writes.into())
        .int("registry_errors", d.registry_errors.into())
        .int("registry_full_errors", d.registry_full_errors.into())
        .int("records_skipped", d.records_skipped.into())
        .opt("last_error", opt_i(d.last_error))
        .opt_str("network", d.network.map(|n| n.name()))
        .raw("stack_store", &store_json(d.stack_store))
        .raw("hub_store", &store_json(d.hub_store))
        .finish()
}

fn storage(hub: &mut Hub, as_json: bool) -> Result<(), String> {
    let d = match hub.call(Request::GetStorageDiagnostics)? {
        Response::StorageDiagnostics(d) => d,
        r if unsupported(&r) => return Err(OLD_FIRMWARE.into()),
        r => return Err(format!("unexpected response: {r:?}")),
    };
    if as_json {
        println!("{}", storage_json(&d));
        return Ok(());
    }
    println!(
        "network at boot   {}",
        d.network.map_or("unavailable", |n| n.name())
    );
    println!(
        "registry          {}, {} device(s)",
        if d.registry_persistent {
            "persistent"
        } else {
            "RAM only"
        },
        d.registry_devices
    );
    println!(
        "registry writes   {} (errors {}, of which full {}; records skipped at boot {})",
        d.registry_writes, d.registry_errors, d.registry_full_errors, d.records_skipped
    );
    println!(
        "last error        {}",
        d.last_error.map_or("none", |e| match e {
            0 => "storage full",
            1 => "flash I/O error",
            _ => "record larger than the buffer",
        })
    );
    println!("stack store       {}", store_text(d.stack_store));
    println!("registry store    {}", store_text(d.hub_store));
    Ok(())
}

fn queue_text(q: QueueUsage) -> String {
    format!("{}/{} (most {})", q.len, q.capacity, q.high_water)
}

fn queue_json(q: QueueUsage) -> String {
    Obj::new()
        .int("len", q.len.into())
        .int("capacity", q.capacity.into())
        .int("high_water", q.high_water.into())
        .finish()
}

pub(crate) fn runtime_json(d: &RuntimeDiagnostics) -> String {
    Obj::new()
        .int("uptime_ms", d.uptime_ms.into())
        .opt("loop_iterations", opt_i(d.loop_iterations))
        .opt("loop_max_us", opt_i(d.loop_max_us))
        .opt("loop_overruns", opt_i(d.loop_overruns))
        .opt("radio_step_max_us", opt_i(d.radio_step_max_us))
        .opt("watchdog_s", opt_i(d.watchdog_s))
        .raw("hub_events", &queue_json(d.hub_events))
        .raw("pending", &queue_json(d.pending))
        .raw("commands", &queue_json(d.commands))
        .raw("trace", &queue_json(d.trace))
        .raw("session_tx", &queue_json(d.session_tx))
        .raw("capture", &queue_json(d.capture))
        .int("hub_events_dropped", d.hub_events_dropped.into())
        .int("stack_events_dropped", d.stack_events_dropped.into())
        .int("trace_dropped", d.trace_dropped.into())
        .int("join_trace_dropped", d.join_trace_dropped.into())
        .int("capture_dropped", d.capture_dropped.into())
        .opt("usb_rx_bytes", opt_i(d.usb_rx_bytes))
        .opt("usb_tx_bytes", opt_i(d.usb_tx_bytes))
        .int("usb_discards", d.usb_discards.into())
        .int("devices", d.devices.into())
        .int("max_devices", d.max_devices.into())
        .int("interviews_active", d.interviews_active.into())
        .int("interviews_stalled", d.interviews_stalled.into())
        .raw(
            "target",
            &Obj::new()
                .opt("stack_size", opt_i(d.target.stack_size))
                .opt("stack_peak", opt_i(d.target.stack_peak))
                .opt("heap_size", opt_i(d.target.heap_size))
                .opt("heap_used", opt_i(d.target.heap_used))
                .opt("heap_peak", opt_i(d.target.heap_peak))
                .opt("loop_over_20ms", opt_i(d.target.loop_over_20ms))
                .opt("hub_poll_max_us", opt_i(d.target.hub_poll_max_us))
                .opt("radio_idle_ms", opt_i(d.target.radio_idle_ms))
                .opt("rx_bursts_cut", opt_i(d.target.rx_bursts_cut))
                .opt_str(
                    "health",
                    d.target
                        .health
                        .map(|h| panweave_hub::supervisor::Health::from_code(h).name()),
                )
                .opt("radio_recoveries", opt_i(d.target.radio_recoveries))
                .finish(),
        )
        .finish()
}

pub(crate) fn get_runtime(hub: &mut Hub) -> Result<RuntimeDiagnostics, String> {
    match hub.call(Request::GetRuntimeDiagnostics)? {
        Response::RuntimeDiagnostics(d) => Ok(d),
        r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

fn runtime(hub: &mut Hub, as_json: bool) -> Result<(), String> {
    let d = get_runtime(hub)?;
    if as_json {
        println!("{}", runtime_json(&d));
        return Ok(());
    }
    println!(
        "uptime            {}.{:03} s",
        d.uptime_ms / 1000,
        d.uptime_ms % 1000
    );
    println!("loop iterations   {}", opt(d.loop_iterations));
    println!(
        "longest loop turn {}",
        d.loop_max_us
            .map_or_else(|| "unavailable".into(), |v| format!("{v} µs"))
    );
    println!(
        "loop overruns     {} (turns over 50 ms)",
        opt(d.loop_overruns)
    );
    println!(
        "longest radio step {}",
        d.radio_step_max_us
            .map_or_else(|| "unavailable".into(), |v| format!("{v} µs"))
    );
    println!(
        "watchdog          {}",
        d.watchdog_s
            .map_or_else(|| "unavailable".into(), |s| format!("{s} s timeout"))
    );
    println!("hub events        {}", queue_text(d.hub_events));
    println!("zigbee pending    {}", queue_text(d.pending));
    println!("host commands     {}", queue_text(d.commands));
    println!("trace             {}", queue_text(d.trace));
    println!("usb tx queue      {} octets", queue_text(d.session_tx));
    println!("capture queue     {}", queue_text(d.capture));
    println!(
        "dropped           hub events {}, stack events {}, trace {}, join milestones {}, captured frames {}",
        d.hub_events_dropped,
        d.stack_events_dropped,
        d.trace_dropped,
        d.join_trace_dropped,
        d.capture_dropped
    );
    println!(
        "usb               rx {} octets, tx {} octets, output discarded {} time(s)",
        opt(d.usb_rx_bytes),
        opt(d.usb_tx_bytes),
        d.usb_discards
    );
    println!(
        "registry          {}/{} devices, {} interview(s) active, {} stalled",
        d.devices, d.max_devices, d.interviews_active, d.interviews_stalled
    );
    let t = &d.target;
    let octets = |v: Option<u32>| v.map_or_else(|| "unavailable".into(), |v| format!("{v} octets"));
    println!(
        "main stack        {} of {} at most (painted-stack watermark, a lower bound)",
        octets(t.stack_peak),
        octets(t.stack_size)
    );
    println!(
        "heap              {} used, {} at most, of {}",
        octets(t.heap_used),
        octets(t.heap_peak),
        octets(t.heap_size)
    );
    println!(
        "loop turns >20 ms {} (a polling sleepy child may miss its frame)",
        opt(t.loop_over_20ms)
    );
    println!(
        "longest hub poll  {}",
        t.hub_poll_max_us.map_or_else(
            || "unavailable".into(),
            |v| format!("{v} µs (registry flash writes included)")
        )
    );
    println!(
        "radio idle        {}",
        t.radio_idle_ms.map_or_else(
            || "unavailable".into(),
            |v| format!("{v} ms since the last completed transmission or reception")
        )
    );
    println!("rx bursts cut     {}", opt(t.rx_bursts_cut));
    println!(
        "health            {}",
        t.health.map_or("unavailable", |h| {
            panweave_hub::supervisor::Health::from_code(h).name()
        })
    );
    println!("radio recoveries  {}", opt(t.radio_recoveries));
    Ok(())
}

/// A human description of a record's code-specific fields.
pub(crate) fn detail(r: &DiagRecord) -> String {
    let mut s = String::new();
    match r.code {
        code::INTERVIEW_STARTED
        | code::INTERVIEW_REQUEST
        | code::INTERVIEW_ANSWER
        | code::INTERVIEW_TIMEOUT
        | code::INTERVIEW_STEP_SKIPPED
        | code::INTERVIEW_STALLED
        | code::INTERVIEW_RESUMED
        | code::INTERVIEW_COMPLETED
        | code::INTERVIEW_SEND_DEFERRED => {
            if let Some(a) = r.arg {
                let stage = InterviewStage::from_code(u8::try_from(a >> 8).unwrap_or(0));
                let _ = write!(s, " stage {} step {}", stage.name(), a & 0xff);
            }
            match (r.code, r.status) {
                (code::INTERVIEW_REQUEST | code::INTERVIEW_TIMEOUT, Some(n)) => {
                    let _ = write!(s, " attempt {n}");
                }
                (code::INTERVIEW_COMPLETED, Some(1)) => s.push_str(" (partial)"),
                (code::INTERVIEW_STEP_SKIPPED | code::INTERVIEW_STALLED, Some(0xff)) => {
                    s.push_str(" after timeouts");
                }
                (_, Some(st)) if st != 0 => {
                    let _ = write!(s, " status {st:#04x}");
                }
                _ => {}
            }
        }
        code::IAS_STATUS => {
            if let Some(a) = r.arg {
                let raw = a & 0xffff;
                let _ = write!(s, " zone status {raw:#06x}");
                if a & ias_bits::CONTACT_KNOWN != 0 {
                    s.push_str(if a & ias_bits::CONTACT_OPEN != 0 {
                        " contact=open"
                    } else {
                        " contact=closed"
                    });
                }
                if a & ias_bits::LEAK_KNOWN != 0 {
                    s.push_str(if a & ias_bits::LEAK != 0 {
                        " water=leak"
                    } else {
                        " water=dry"
                    });
                }
                if a & ias_bits::TEST_MODE != 0 {
                    s.push_str(" test-mode (alarms not interpreted)");
                }
                if a & ias_bits::TYPE_UNKNOWN != 0 {
                    s.push_str(" zone type unknown (alarms not interpreted)");
                }
                if a & ias_bits::OVERRIDE != 0 {
                    s.push_str(" manufacturer override applied");
                }
            }
        }
        code::JOIN_DECISION => {
            s.push_str(match r.status {
                Some(0) => " negotiate key",
                Some(1) => " transport network key",
                Some(2) => " allow (secured rejoin)",
                Some(3) => " ignore (refused by policy: network closed?)",
                Some(4) => " remove",
                _ => "",
            });
        }
        code::JOIN_CHILD_JOINED | code::JOIN_UPDATE_DEVICE => {
            s.push_str(match r.status {
                Some(0) => " secured rejoin",
                Some(1) => " unsecured join",
                Some(2) => " device left",
                Some(3) => " trust center rejoin",
                _ => "",
            });
        }
        code::JOIN_TCLK_REQUESTED => {
            s.push_str(if r.status == Some(1) {
                " granted"
            } else {
                " refused by policy"
            });
        }
        code::PARTITION_PROBLEM => {
            if let Some(f) = r.status {
                let _ = write!(s, " {}", finding_text(f));
            }
        }
        _ => {
            if let Some(st) = r.status {
                let _ = write!(s, " status {st:#04x}");
            }
            if let Some(a) = r.arg {
                let _ = write!(s, " arg {a}");
            }
        }
    }
    if matches!(
        r.code,
        code::JOIN_CHILD_JOINED
            | code::JOIN_UPDATE_DEVICE
            | code::JOIN_DECISION
            | code::JOIN_KEY_SENT
            | code::JOIN_KEY_DELIVERED
            | code::JOIN_KEY_FAILED
            | code::JOIN_TCLK_REQUESTED
            | code::JOIN_TCLK_VERIFIED
    ) && let Some(ms) = r.arg
    {
        let _ = write!(s, " (+{ms} ms)");
    }
    s
}

/// One record as a console line.
pub(crate) fn line(r: &DiagRecord, uptime_ms: u64) -> String {
    let t = unwrap_ms(uptime_ms, r.at_ms);
    let mut s = format!(
        "#{:<6} {:>6}.{:03} s {:<8} {:<13} {}",
        r.seq,
        t / 1000,
        t % 1000,
        r.severity.name(),
        r.category.name(),
        code_name(r.code)
    );
    if let Some(i) = r.ieee {
        let _ = write!(s, " {}", Ieee(i));
    }
    if let Some(a) = r.short {
        let _ = write!(s, " nwk {a:#06x}");
    }
    if let Some(e) = r.endpoint {
        let _ = write!(s, " ep {e}");
    }
    if let Some(c) = r.cluster {
        let _ = write!(s, " cluster {c:#06x}");
    }
    if let Some(t) = r.tsn {
        let _ = write!(s, " tsn {t}");
    }
    s.push_str(&detail(r));
    s
}

/// One record as a JSONL object (documented schema).
pub(crate) fn record_json(r: &DiagRecord, uptime_ms: u64) -> String {
    Obj::new()
        .int("seq", r.seq.into())
        .int("uptime_ms", unwrap_ms(uptime_ms, r.at_ms).into())
        .str("severity", r.severity.name())
        .str("category", r.category.name())
        .int("code", r.code.into())
        .str("code_name", code_name(r.code))
        .opt_str("ieee", r.ieee.map(|i| Ieee(i).to_string()).as_deref())
        .opt("nwk", opt_i(r.short))
        .opt("endpoint", opt_i(r.endpoint))
        .opt("cluster", opt_i(r.cluster))
        .opt("tsn", opt_i(r.tsn))
        .opt("status", opt_i(r.status))
        .opt("arg", opt_i(r.arg))
        .str("detail", detail(r).trim())
        .finish()
}

/// Reads one trace page.
pub(crate) fn read_page(hub: &mut Hub, from: u32, ieee: Option<u64>) -> Result<TracePage, String> {
    let max = u8::try_from(MAX_TRACE_PAGE).unwrap_or(1);
    match hub.call(Request::ReadTrace { from, max, ieee })? {
        Response::TracePage(p) => Ok(p),
        r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

/// Every stored record (optionally of one device), with the uptime of the
/// last page and the number of records known lost before the first one.
pub(crate) fn read_all(
    hub: &mut Hub,
    ieee: Option<u64>,
) -> Result<(Vec<DiagRecord>, u64, u32), String> {
    let mut out = Vec::new();
    let first = read_page(hub, 0, ieee)?;
    let mut from = first.first_available;
    let lost = first.dropped;
    let mut uptime;
    loop {
        let page = read_page(hub, from, ieee)?;
        uptime = page.uptime_ms;
        let empty = page.records.is_empty();
        out.extend(page.records.iter().copied());
        if empty || page.next == from {
            break;
        }
        from = page.next;
    }
    Ok((out, uptime, lost))
}

struct Filter {
    level: Severity,
    categories: u32,
}

fn parse_filter(args: &[&str]) -> Result<Filter, String> {
    let mut f = Filter {
        level: Severity::Trace,
        categories: ALL_CATEGORIES,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--level" => {
                let v = it.next().ok_or("--level needs a value")?;
                f.level = Severity::parse(v).ok_or_else(|| format!("unknown level {v}"))?;
            }
            "--category" => {
                let v = it.next().ok_or("--category needs a value")?;
                f.categories = parse_categories(v)?;
            }
            _ => {}
        }
    }
    Ok(f)
}

fn parse_categories(v: &str) -> Result<u32, String> {
    if v == "all" {
        return Ok(ALL_CATEGORIES);
    }
    let mut mask = 0;
    for name in v.split(',') {
        mask |= Category::parse(name.trim())
            .ok_or_else(|| format!("unknown category {name}"))?
            .bit();
    }
    Ok(mask)
}

fn watch(hub: &mut Hub, args: &[&str], as_json: bool) -> Result<(), String> {
    let f = parse_filter(args)?;
    if let Response::TraceConfiguration(c) = hub.call(Request::GetTraceConfiguration)?
        && c.min_severity > f.level
        && !as_json
    {
        eprintln!(
            "note: the hub keeps {} and above only; `diagnostics configure --level {}` to keep more",
            c.min_severity.name(),
            f.level.name()
        );
    }
    // Start from what is stored now, then follow.
    let first = read_page(hub, 0, None)?;
    let mut from = first.first_available;
    while !STOP.load(Ordering::SeqCst) {
        let page = read_page(hub, from, None)?;
        if page.first_available.wrapping_sub(from) < u32::MAX / 2 && page.first_available != from {
            let lost = page.first_available.wrapping_sub(from);
            if as_json {
                println!(
                    "{}",
                    Obj::new()
                        .str("gap", "records lost")
                        .int("count", lost.into())
                        .finish()
                );
            } else {
                println!("… {lost} record(s) lost (the trace was full)");
            }
        }
        for r in &page.records {
            if r.severity < f.level || f.categories & r.category.bit() == 0 {
                continue;
            }
            if as_json {
                println!("{}", record_json(r, page.uptime_ms));
            } else {
                println!("{}", line(r, page.uptime_ms));
            }
        }
        let advanced = page.next != from;
        from = page.next;
        if !advanced || page.records.len() < MAX_TRACE_PAGE {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    Ok(())
}

fn device(hub: &mut Hub, target: u64, interview_only: bool, as_json: bool) -> Result<(), String> {
    let (records, uptime, lost) = read_all(hub, Some(target))?;
    let wanted = |r: &DiagRecord| {
        !interview_only
            || matches!(
                r.category,
                Category::Interview
                    | Category::IasZone
                    | Category::Zcl
                    | Category::Zdo
                    | Category::TrustCenter
                    | Category::Commissioning
            )
    };
    if as_json {
        for r in records.iter().filter(|r| wanted(r)) {
            println!("{}", record_json(r, uptime));
        }
        return Ok(());
    }
    if lost > 0 {
        println!(
            "note: {lost} record(s) were dropped from the trace since boot: the timeline may be incomplete"
        );
    }
    if records.is_empty() {
        println!("no trace records for {}", Ieee(target));
    }
    for r in records.iter().filter(|r| wanted(r)) {
        println!("{}", line(r, uptime));
    }
    if interview_only {
        summarize_interview(&records);
    }
    Ok(())
}

/// Explains, from the trace, where an interview stands and why.
pub(crate) fn summarize_interview(records: &[DiagRecord]) {
    let count = |c: u16| records.iter().filter(|r| r.code == c).count();
    let last_stage = records
        .iter()
        .rev()
        .find(|r| r.category == Category::Interview && r.arg.is_some())
        .and_then(|r| r.arg)
        .map(|a| InterviewStage::from_code(u8::try_from(a >> 8).unwrap_or(0)));
    println!("--- summary");
    println!(
        "requests {}, answers {}, timeouts {}, steps skipped {}, stalls {}, resumptions {}",
        count(code::INTERVIEW_REQUEST),
        count(code::INTERVIEW_ANSWER),
        count(code::INTERVIEW_TIMEOUT),
        count(code::INTERVIEW_STEP_SKIPPED),
        count(code::INTERVIEW_STALLED),
        count(code::INTERVIEW_RESUMED),
    );
    if let Some(s) = last_stage {
        println!("last stage seen: {}", s.name());
    }
    for r in records
        .iter()
        .filter(|r| r.code == code::INTERVIEW_STEP_SKIPPED || r.code == code::INTERVIEW_STALLED)
    {
        println!("  {}{}", code_name(r.code), detail(r));
    }
    if count(code::INTERVIEW_REQUEST) > 0 && count(code::INTERVIEW_ANSWER) == 0 {
        println!(
            "the device never answered: a sleepy device that stopped polling, out of range, or not on this network"
        );
    }
    if count(code::IAS_NOT_ENROLLED) > 0 && count(code::IAS_ENROLL_CONFIRMED) == 0 {
        println!("IAS enrolment was not confirmed: the zone may not send notifications to the hub");
    }
    if count(code::INTERVIEW_COMPLETED) == 0 && count(code::INTERVIEW_STARTED) == 0 {
        println!(
            "no interview start in the trace (it may have been dropped, or happened before the trace was cleared)"
        );
    }
}

fn export(hub: &mut Hub, args: &[&str]) -> Result<(), String> {
    let path = args
        .iter()
        .position(|a| *a == "--output")
        .and_then(|i| args.get(i + 1))
        .ok_or("export needs --output FILE")?;
    let target = match args.iter().position(|a| *a == "--ieee") {
        Some(i) => Some(ieee(args.get(i + 1).ok_or("--ieee needs a value")?)?),
        None => None,
    };
    let (records, uptime, lost) = read_all(hub, target)?;
    let mut f = std::fs::File::create(path).map_err(|e| format!("{path}: {e}"))?;
    if lost > 0 {
        writeln!(
            f,
            "{}",
            Obj::new()
                .str("gap", "records dropped before export")
                .int("count", lost.into())
                .finish()
        )
        .map_err(|e| e.to_string())?;
    }
    for r in &records {
        writeln!(f, "{}", record_json(r, uptime)).map_err(|e| e.to_string())?;
    }
    println!("{} record(s) written to {path}", records.len());
    Ok(())
}

fn configure(hub: &mut Hub, args: &[&str], as_json: bool) -> Result<(), String> {
    let current = match hub.call(Request::GetTraceConfiguration)? {
        Response::TraceConfiguration(c) => c,
        r if unsupported(&r) => return Err(OLD_FIRMWARE.into()),
        r => return Err(format!("unexpected response: {r:?}")),
    };
    let mut level = current.min_severity;
    let mut categories = current.categories;
    let mut it = args.iter();
    let mut changed = false;
    while let Some(a) = it.next() {
        match *a {
            "--level" => {
                let v = it.next().ok_or("--level needs a value")?;
                level = Severity::parse(v).ok_or_else(|| format!("unknown level {v}"))?;
                changed = true;
            }
            "--category" => {
                categories = parse_categories(it.next().ok_or("--category needs a value")?)?;
                changed = true;
            }
            _ => {}
        }
    }
    let c = if changed {
        match hub.call(Request::SetTraceConfiguration {
            min_severity: level.code(),
            categories,
        })? {
            Response::TraceConfiguration(c) => c,
            Response::Error(e) => return Err(error_text(e)),
            r => return Err(format!("unexpected response: {r:?}")),
        }
    } else {
        current
    };
    let names: Vec<&str> = Category::ALL
        .iter()
        .filter(|cat| c.categories & cat.bit() != 0)
        .map(|cat| cat.name())
        .collect();
    if as_json {
        println!(
            "{}",
            Obj::new()
                .str("min_severity", c.min_severity.name())
                .raw(
                    "categories",
                    &array(&names.iter().map(|n| string(n)).collect::<Vec<_>>())
                )
                .int("capacity", c.capacity.into())
                .int("stored", c.stored.into())
                .int("dropped", c.dropped.into())
                .int("filtered", c.filtered.into())
                .finish()
        );
    } else {
        println!("keeps       {} and above", c.min_severity.name());
        println!("categories  {}", names.join(", "));
        println!(
            "stored      {}/{} (dropped {}, filtered {})",
            c.stored, c.capacity, c.dropped, c.filtered
        );
    }
    Ok(())
}

/// `diagnostics <sub> …`.
pub(crate) fn run(hub: &mut Hub, args: &[&str], as_json: bool) -> Result<(), String> {
    match args {
        ["system", ..] => system(hub, as_json),
        ["radio", ..] => radio(hub, as_json),
        ["storage", ..] => storage(hub, as_json),
        ["runtime", ..] => runtime(hub, as_json),
        ["trace", ..] => {
            let (records, uptime, lost) = read_all(hub, None)?;
            if lost > 0 && !as_json {
                println!("note: {lost} record(s) were dropped since boot");
            }
            for r in &records {
                if as_json {
                    println!("{}", record_json(r, uptime));
                } else {
                    println!("{}", line(r, uptime));
                }
            }
            Ok(())
        }
        ["watch", rest @ ..] => watch(hub, rest, as_json),
        ["device", id, ..] => device(hub, ieee(id)?, false, as_json),
        ["interview", id, ..] => device(hub, ieee(id)?, true, as_json),
        ["export", rest @ ..] => export(hub, rest),
        ["configure", rest @ ..] => configure(hub, rest, as_json),
        ["clear", ..] => match hub.call(Request::ClearTrace)? {
            Response::Done => {
                println!("trace cleared");
                Ok(())
            }
            r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
            Response::Error(e) => Err(error_text(e)),
            r => Err(format!("unexpected response: {r:?}")),
        },
        _ => Err(crate::USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_unwrap_across_the_32_bit_boundary() {
        assert_eq!(unwrap_ms(10_000, 9_000), 9_000);
        let uptime = (1u64 << 32) + 500;
        // Stamped 1000 ms before the wrap.
        assert_eq!(unwrap_ms(uptime, u32::MAX - 999), (1u64 << 32) - 1000);
        assert_eq!(unwrap_ms(uptime, 400), (1u64 << 32) + 400);
    }

    #[test]
    fn records_render_and_serialize_without_secrets() {
        let r = DiagRecord::new(
            Category::TrustCenter,
            Severity::Warning,
            code::JOIN_DECISION,
        )
        .ieee(0x0011_2233_4455_6677)
        .short(0x1234)
        .status(3)
        .arg(250);
        let l = line(&r, 1000);
        assert!(l.contains("join-decision"), "{l}");
        assert!(l.contains("ignore"), "{l}");
        assert!(l.contains("(+250 ms)"), "{l}");
        let j = record_json(&r, 1000);
        assert!(j.contains(r#""ieee":"00:11:22:33:44:55:66:77""#), "{j}");
        assert!(j.contains(r#""code_name":"join-decision""#), "{j}");
        let ias = DiagRecord::new(Category::IasZone, Severity::Info, code::IAS_STATUS).arg(
            panweave_hub::diag::zone_status_arg(0x0001, ias_bits::LEAK_KNOWN | ias_bits::LEAK),
        );
        assert!(line(&ias, 0).contains("water=leak"));
    }
}
