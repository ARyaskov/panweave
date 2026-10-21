//! Diagnostics of the hub against simulated devices: the trace of joins,
//! interviews and IAS zones, trace filtering and overflow, the diagnostic
//! requests' validation and access control, radio capture, and storage
//! failures reported instead of hidden.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::capture::CaptureMode;
use panweave_hub::diag::{
    ALL_CATEGORIES, Category, DiagRecord, Severity, code, ias_bits, zone_status_arg,
};
use panweave_hub::model::LeakState;
use panweave_hub::protocol::frame::{FrameDecoder, MAX_WIRE};
use panweave_hub::protocol::{
    ErrorCode, Event, Message, NetworkRestore, Request, Response, TracePage,
};
use panweave_hub::registry::zone_type;
use panweave_hub::{Access, Hub, HubConfig, Session};
use panweave_storage::{Key, Kind, Storage, StorageError};
use panweave_types::Endpoint;
use panweave_types::time::Duration;
use panweave_zcl::clusters::ias_zone::EnrollMode;

/// Every stored record (of `ieee`), oldest first, through the paginated
/// request.
fn trace(sim: &mut panweave_sim::Simulator, c: usize, ieee: Option<u64>) -> Vec<DiagRecord> {
    let mut out = Vec::new();
    let mut from = match request(
        sim,
        c,
        &Request::ReadTrace {
            from: 0,
            max: 1,
            ieee: None,
        },
    ) {
        Response::TracePage(p) => p.first_available,
        r => panic!("{r:?}"),
    };
    loop {
        let Response::TracePage(p) = request(
            sim,
            c,
            &Request::ReadTrace {
                from,
                max: 12,
                ieee,
            },
        ) else {
            panic!()
        };
        if p.records.is_empty() {
            return out;
        }
        out.extend(p.records.iter().copied());
        from = p.next;
    }
}

fn codes(records: &[DiagRecord]) -> Vec<u16> {
    records.iter().map(|r| r.code).collect()
}

fn position(records: &[DiagRecord], code: u16) -> usize {
    records
        .iter()
        .position(|r| r.code == code)
        .unwrap_or_else(|| panic!("no record {code:#06x} in {:x?}", codes(records)))
}

fn configure(sim: &mut panweave_sim::Simulator, c: usize, level: Severity, categories: u32) {
    let r = request(
        sim,
        c,
        &Request::SetTraceConfiguration {
            min_severity: level.code(),
            categories,
        },
    );
    assert!(matches!(r, Response::TraceConfiguration(_)), "{r:?}");
}

fn leak_sensor() -> panweave_sim::SimStack {
    zone_sensor(
        LEAK,
        zone_type::WATER_SENSOR,
        EnrollMode::AutoRequest,
        b"leak",
    )
}

#[test]
fn a_join_and_interview_leave_an_ordered_timeline() {
    let (mut sim, c) = network();
    configure(&mut sim, c, Severity::Debug, ALL_CATEGORIES);
    let s = join(&mut sim, c, "leak", leak_sensor(), LEAK);
    let t = trace(&mut sim, c, Some(LEAK));
    assert!(t.iter().all(|r| r.ieee == Some(LEAK)), "filtered by device");
    // Trust Center: the key went out and was delivered, before the hub
    // learnt of the device and interviewed it.
    let key_sent = position(&t, code::JOIN_KEY_SENT);
    let delivered = position(&t, code::JOIN_KEY_DELIVERED);
    let authorized = position(&t, code::DEVICE_AUTHORIZED);
    let started = position(&t, code::INTERVIEW_STARTED);
    let request_ = position(&t, code::INTERVIEW_REQUEST);
    let answer = position(&t, code::INTERVIEW_ANSWER);
    let enrolled = position(&t, code::IAS_ENROLL_CONFIRMED);
    let completed = position(&t, code::INTERVIEW_COMPLETED);
    assert!(key_sent < delivered, "{:x?}", codes(&t));
    assert!(authorized < started && started < request_ && request_ < answer);
    assert!(
        answer < enrolled && enrolled <= completed,
        "{:x?}",
        codes(&t)
    );
    assert_eq!(t[delivered].category, Category::TrustCenter);
    assert_eq!(t[completed].status, Some(0), "complete, not partial");
    // Requests carry what correlates them with a capture.
    let r = t[request_];
    assert!(r.tsn.is_some() && r.arg.is_some(), "{r:?}");
    // Records are in sequence order with monotonic timestamps.
    assert!(t.windows(2).all(|w| w[0].seq < w[1].seq));
    assert!(t.windows(2).all(|w| w[0].at_ms <= w[1].at_ms));

    // An alarm: the raw zone status and its interpretation, together.
    take_hub_events(&mut sim, c);
    sim.stack(s)
        .zcl
        .set_zone_status(Endpoint(1), 0x0001)
        .unwrap();
    wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::DeviceStateChanged { ieee: LEAK, state } if state.water_leak == LeakState::Leak),
    );
    let t = trace(&mut sim, c, Some(LEAK));
    let status = t.iter().rfind(|r| r.code == code::IAS_STATUS).unwrap();
    assert_eq!(
        status.arg,
        Some(zone_status_arg(
            0x0001,
            ias_bits::LEAK_KNOWN | ias_bits::LEAK
        ))
    );
    assert_eq!(status.category, Category::IasZone);
}

#[test]
fn an_unanswered_interview_records_its_timeouts_and_stall() {
    let (mut sim, c) = network();
    let b = join(&mut sim, c, "bulb", bulb(), BULB);
    configure(&mut sim, c, Severity::Debug, ALL_CATEGORIES);
    sim.isolate(b);
    assert_eq!(
        request(&mut sim, c, &Request::InterviewDevice { ieee: BULB }),
        Response::Done
    );
    wait_event(&mut sim, c, 600, |e| {
        matches!(e, Event::DeviceInterviewFailed { ieee: BULB, .. })
    });
    let t = trace(&mut sim, c, Some(BULB));
    let restarted = t
        .iter()
        .rposition(|r| r.code == code::INTERVIEW_STARTED)
        .unwrap();
    let after = &t[restarted..];
    let timeouts = after
        .iter()
        .filter(|r| r.code == code::INTERVIEW_TIMEOUT)
        .count();
    assert!(timeouts >= 2, "retried: {:x?}", codes(after));
    let stalled = after
        .iter()
        .find(|r| r.code == code::INTERVIEW_STALLED)
        .unwrap();
    assert!(stalled.severity >= Severity::Warning);
    // The stage and step it stalled at are recorded.
    assert!(stalled.arg.is_some());
    assert!(
        !after.iter().any(|r| r.code == code::INTERVIEW_ANSWER),
        "nothing answered"
    );
}

#[test]
fn filtering_happens_before_queueing_and_overflow_is_counted() {
    let (mut sim, c) = network();
    // Only errors of the IAS category: nothing of a join is kept …
    configure(&mut sim, c, Severity::Error, Category::IasZone.bit());
    let Response::TraceConfiguration(before) =
        request(&mut sim, c, &Request::GetTraceConfiguration)
    else {
        panic!()
    };
    join(&mut sim, c, "bulb", bulb(), BULB);
    let Response::TraceConfiguration(after) = request(&mut sim, c, &Request::GetTraceConfiguration)
    else {
        panic!()
    };
    assert_eq!(after.stored, before.stored, "filtered records take no room");
    assert!(after.filtered > before.filtered);
    assert_eq!(after.dropped, 0);

    // … while everything at Trace overflows the 128-record ring: the
    // oldest are dropped, counted, and a reader learns where it lost them.
    // Every configuration change is itself recorded.
    for _ in 0..200 {
        configure(&mut sim, c, Severity::Trace, ALL_CATEGORIES);
    }
    let Response::TracePage(p) = request(
        &mut sim,
        c,
        &Request::ReadTrace {
            from: 0,
            max: 12,
            ieee: None,
        },
    ) else {
        panic!()
    };
    let TracePage {
        first_available,
        dropped,
        ..
    } = p;
    assert!(dropped >= 72, "{dropped}");
    assert!(first_available > 0);
    let Response::TraceConfiguration(full) = request(&mut sim, c, &Request::GetTraceConfiguration)
    else {
        panic!()
    };
    assert_eq!(full.stored, full.capacity);
    assert_eq!(full.capacity, 128);
}

#[test]
fn critical_records_bypass_the_filter() {
    let (mut sim, c) = network();
    configure(&mut sim, c, Severity::Critical, 0);
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.set_network_restore(NetworkRestore::ReadFailed);
    app.hub.log(DiagRecord::new(
        Category::Watchdog,
        Severity::Info,
        code::WATCHDOG_ARMED,
    ));
    let t = trace(&mut sim, c, None);
    assert!(t.iter().any(|r| r.code == code::NETWORK_RESTORE_FAILED));
    assert!(!t.iter().any(|r| r.code == code::WATCHDOG_ARMED));
    let Response::StorageDiagnostics(d) = request(&mut sim, c, &Request::GetStorageDiagnostics)
    else {
        panic!()
    };
    assert_eq!(d.network, Some(NetworkRestore::ReadFailed));
}

#[test]
fn invalid_diagnostic_requests_are_refused() {
    let (mut sim, c) = network();
    for r in [
        Request::SetTraceConfiguration {
            min_severity: 9,
            categories: ALL_CATEGORIES,
        },
        Request::ReadTrace {
            from: 0,
            max: 0,
            ieee: None,
        },
        Request::ReadTrace {
            from: 0,
            max: 13,
            ieee: None,
        },
        Request::ReadCapture { max: 0 },
        Request::ReadCapture { max: 4 },
    ] {
        assert_eq!(
            request(&mut sim, c, &r),
            Response::Error(ErrorCode::InvalidArgument),
            "{r:?}"
        );
    }
    // Capture is off unless the firmware supports it.
    // Capture without the radio-capture feature: NotSupported.
    #[cfg(not(feature = "radio-capture"))]
    for r in [
        Request::StartCapture {
            seconds: 10,
            mode: CaptureMode::Sanitized,
        },
        Request::StopCapture,
        Request::ReadCapture { max: 3 },
    ] {
        assert_eq!(
            request(&mut sim, c, &r),
            Response::Error(ErrorCode::NotSupported),
            "{r:?}"
        );
    }
    // Every report answers, with "unavailable" where the platform said
    // nothing (no radio driver numbers in the simulator).
    let Response::RadioDiagnostics(radio) = request(&mut sim, c, &Request::GetRadioDiagnostics)
    else {
        panic!()
    };
    assert!(radio.driver.is_none());
    assert_eq!(radio.nwk_pending_capacity, 4);
    let Response::RuntimeDiagnostics(rt) = request(&mut sim, c, &Request::GetRuntimeDiagnostics)
    else {
        panic!()
    };
    assert!(rt.loop_max_us.is_none() && rt.watchdog_s.is_none());
    assert!(rt.hub_events.high_water >= 1);
    assert_eq!(rt.trace.capacity, 128);
    let Response::BootReport(b) = request(&mut sim, c, &Request::GetBootReport) else {
        panic!()
    };
    assert!(b.reset.is_none() && b.cpu_mhz.is_none(), "nothing invented");
}

fn sent(s: &mut Session) -> Vec<Response> {
    let mut dec = FrameDecoder::new();
    let mut out = Vec::new();
    s.transmit(|b| {
        if let Some(Ok(body)) = dec.push(b)
            && let Ok(Message::Response { response, .. }) = Message::decode(body)
        {
            out.push(response);
        }
        true
    });
    out
}

fn frame(id: u16, request: Request) -> Vec<u8> {
    let mut wire = [0u8; MAX_WIRE];
    let n = Message::Request { id, request }
        .encode_frame(&mut wire)
        .unwrap();
    wire[..n].to_vec()
}

#[test]
fn only_admin_sessions_change_the_trace_or_capture() {
    let (mut sim, c) = network();
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let mut monitor: Session = Session::new(Access::Monitor);
    for (id, r) in [
        (
            1,
            Request::SetTraceConfiguration {
                min_severity: 0,
                categories: ALL_CATEGORIES,
            },
        ),
        (2, Request::ClearTrace),
        (
            3,
            Request::StartCapture {
                seconds: 10,
                mode: CaptureMode::Raw,
            },
        ),
        (4, Request::ReadCapture { max: 3 }),
    ] {
        monitor.receive(&frame(id, r), &mut app.hub, stack);
    }
    // Reading is allowed.
    monitor.receive(
        &frame(
            5,
            Request::ReadTrace {
                from: 0,
                max: 12,
                ieee: None,
            },
        ),
        &mut app.hub,
        stack,
    );
    let r = sent(&mut monitor);
    assert_eq!(r.len(), 5);
    assert!(
        r[..4]
            .iter()
            .all(|r| *r == Response::Error(ErrorCode::Unauthorized)),
        "{r:?}"
    );
    let Response::TracePage(p) = &r[4] else {
        panic!("{r:?}")
    };
    // The refusals are themselves recorded, with the request's id.
    let refused: Vec<_> = p
        .records
        .iter()
        .filter(|r| r.code == code::USB_UNAUTHORIZED)
        .collect();
    assert_eq!(refused.len(), 4);
    assert_eq!(refused[0].arg, Some(1));
}

#[test]
fn registry_write_failures_are_reported_not_hidden() {
    let (mut sim, c) = network();
    {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.storage().fail_writes(Some(StorageError::Full));
    }
    join(&mut sim, c, "bulb", bulb(), BULB);
    {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.flush();
    }
    sim.run_for(Duration::from_secs(1));
    assert!(hub_events(&sim, c).iter().any(|e| matches!(
        e,
        Event::HubError {
            error: ErrorCode::StorageFailure,
            ..
        }
    )));
    let Response::StorageDiagnostics(d) = request(&mut sim, c, &Request::GetStorageDiagnostics)
    else {
        panic!()
    };
    assert!(
        d.registry_errors >= 1 && d.registry_full_errors >= 1,
        "{d:?}"
    );
    assert_eq!(d.last_error, Some(0), "full");
    let t = trace(&mut sim, c, None);
    let failed = t.iter().find(|r| r.code == code::STORE_FAILED).unwrap();
    assert_eq!(failed.severity, Severity::Error);
    // The device stays usable from RAM.
    assert!(matches!(
        request(&mut sim, c, &Request::GetDevice { ieee: BULB }),
        Response::Device(_)
    ));

    // An I/O error is told apart from a full store.
    {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.storage().fail_writes(Some(StorageError::Io));
    }
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RemoveDevice {
                ieee: BULB,
                leave: false
            }
        ),
        Response::Done
    );
    sim.run_for(Duration::from_secs(40));
    let Response::StorageDiagnostics(d) = request(&mut sim, c, &Request::GetStorageDiagnostics)
    else {
        panic!()
    };
    assert_eq!(d.last_error, Some(1), "I/O");
}

fn restored(storage: HubStore) -> (Hub<HubStore>, Result<usize, StorageError>) {
    let mut hub = Hub::new(
        HubConfig {
            firmware: "test",
            ..HubConfig::default()
        },
        storage,
    );
    let r = hub.restore();
    (hub, r)
}

fn records(hub: &Hub<HubStore>) -> Vec<DiagRecord> {
    let mut all = Vec::new();
    let mut from = 0;
    loop {
        let p = hub.read_trace(from, None, 12);
        if p.records.is_empty() {
            return all;
        }
        all.extend(p.records.iter().copied());
        from = p.next;
    }
}

#[test]
fn damaged_registry_storage_is_reported_at_restore() {
    let (mut sim, c) = network();
    join(&mut sim, c, "bulb", bulb(), BULB);
    join(&mut sim, c, "leak", leak_sensor(), LEAK);
    let storage = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.flush();
        app.hub.storage().clone()
    };
    let mut buf = [0u8; 512];

    // A record cut short (a torn write): skipped and reported; the other
    // device is restored.
    let mut s = storage.clone();
    let key = Key::with_id(Kind::Application, LEAK);
    let n = s.load(key, &mut buf).unwrap().unwrap();
    s.store(key, &buf[..n / 2]).unwrap();
    let (hub, r) = restored(s);
    assert_eq!(r, Ok(1));
    let t = records(&hub);
    let skipped = t.iter().find(|r| r.code == code::RECORD_SKIPPED).unwrap();
    assert_eq!(skipped.ieee, Some(LEAK));

    // A record missing from the index's list: the same.
    let mut s = storage.clone();
    s.erase(Key::with_id(Kind::Application, BULB)).unwrap();
    let (hub, r) = restored(s);
    assert_eq!(r, Ok(1));
    assert!(
        records(&hub)
            .iter()
            .any(|r| r.code == code::RECORD_SKIPPED && r.ieee == Some(BULB))
    );

    // A corrupt index: nothing restored, an error recorded, no panic.
    let mut s = storage.clone();
    let index = Key::with_id(Kind::Application, 0);
    if let Some(n) = s.load(index, &mut buf).unwrap() {
        buf[..n].fill(0xff);
        s.store(index, &buf[..n]).unwrap();
        let (hub, r) = restored(s);
        assert_eq!(r, Ok(0));
        assert!(records(&hub).iter().any(|r| r.code == code::INDEX_CORRUPT));
    }

    // Intact storage restores both, reporting how many.
    let (hub, r) = restored(storage);
    assert_eq!(r, Ok(2));
    let done = records(&hub)
        .into_iter()
        .find(|r| r.code == code::REGISTRY_RESTORED)
        .unwrap();
    assert_eq!(done.arg, Some(2));
}
