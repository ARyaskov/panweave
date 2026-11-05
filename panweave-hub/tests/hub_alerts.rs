//! Experimental Wi-Fi notifications through the hub, end to end in the
//! simulator: real joins, IAS reports and storage; the radio switch and
//! the network are **mocks** (no Wi-Fi exists here), and the Zigbee
//! outage an attempt causes is modelled by taking the hub off the air
//! for the attempt's downtime. These tests prove the queue, schedule,
//! acknowledgement and recovery logic — not that an ESP32-C6 can switch
//! its radio, which only hardware can show (examples/esp32c6-wifi-alerts/README.md).

#![cfg(feature = "alerts")]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use std::cell::Cell;
use std::fmt::Write as _;

use common::*;
use heapless::Vec as HVec;
use panweave_hub::PreparedAlert;
use panweave_hub::alert::attempt::{
    self, Clock, Deadline, NetError, Network, RadioSwitch, RadioSwitchError, Report,
};
use panweave_hub::alert::queue::EventId;
use panweave_hub::alert::uplink::{self, Uplink};
use panweave_hub::protocol::{
    AlertConfigUpdate, AlertDestination, AlertError, AlertStage, AlertState, AlertStatus,
    ErrorCode, Event, Request, Response, ScanEntry, SensorEvent, WifiFailure, WifiScan,
};
use panweave_hub::registry::zone_type;
use panweave_sim::Simulator;
use panweave_types::Endpoint;
use panweave_types::time::Duration;
use panweave_zcl::clusters::ias_zone::EnrollMode;

const ALARM1: u16 = 1;
const PASSWORD: &str = "wifi-secret-pw";
const TOKEN: &str = "123456:TOKENsecret_xyz";

fn text<const N: usize>(s: &str) -> HVec<u8, N> {
    HVec::from_slice(s.as_bytes()).unwrap()
}

fn configure(sim: &mut Simulator, c: usize, update: AlertConfigUpdate) {
    assert_eq!(
        request(sim, c, &Request::SetAlertConfig(update)),
        Response::Done
    );
}

fn enable(sim: &mut Simulator, c: usize) {
    configure(
        sim,
        c,
        AlertConfigUpdate {
            enabled: Some(true),
            ssid: Some(text("home")),
            password: Some(text(PASSWORD)),
            token: Some(text(TOKEN)),
            chat_id: Some(text("-1001234567890")),
            ..AlertConfigUpdate::default()
        },
    );
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.set_alert_radio_switching(true);
}

fn status(sim: &mut Simulator, c: usize) -> AlertStatus {
    match request(sim, c, &Request::GetAlertStatus) {
        Response::AlertStatus(s) => s,
        r => panic!("{r:?}"),
    }
}

fn set_zone(sim: &mut Simulator, node: usize, status: u16) {
    sim.stack(node)
        .zcl
        .set_zone_status(Endpoint(1), status)
        .unwrap();
}

fn saw(sim: &Simulator, c: usize, ieee: u64, e: SensorEvent) -> bool {
    hub_events(sim, c)
        .iter()
        .any(|x| matches!(x, Event::Sensor { ieee: i, event } if *i == ieee && *event == e))
}

fn due(sim: &mut Simulator, c: usize) -> bool {
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.poll(stack);
    app.hub.alert_due()
}

fn leak_sensor(sim: &mut Simulator, c: usize) -> usize {
    join(
        sim,
        c,
        "aqara",
        zone_sensor_as(
            LEAK,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"LUMI",
            b"lumi.flood.agl02",
        ),
        LEAK,
    )
}

fn contact_sensor(sim: &mut Simulator, c: usize) -> usize {
    join(
        sim,
        c,
        "sber",
        zone_sensor_as(
            CONTACT,
            zone_type::CONTACT_SWITCH,
            EnrollMode::AutoRequest,
            b"_TYZB01_nnv2dy5m",
            b"TS0203",
        ),
        CONTACT,
    )
}

// ---- mocks of the firmware side -------------------------------------

struct T {
    now: Cell<u64>,
}

struct TClock<'a>(&'a T);
impl Clock for TClock<'_> {
    fn now_ms(&mut self) -> u64 {
        self.0.now.get()
    }
}

struct Radio<'a> {
    t: &'a T,
    on: bool,
}
impl RadioSwitch for Radio<'_> {
    fn suspend_zigbee(&mut self) -> Result<(), RadioSwitchError> {
        self.t.now.set(self.t.now.get() + 3);
        self.on = false;
        Ok(())
    }
    fn resume_zigbee(&mut self) -> Result<(), RadioSwitchError> {
        self.t.now.set(self.t.now.get() + 8);
        self.on = true;
        Ok(())
    }
}

/// A network whose stages take `ms` each, failing at `fail`.
struct Net<'a> {
    t: &'a T,
    ms: u64,
    fail: Option<(AlertStage, NetError)>,
    response: &'static [u8],
    sent: Vec<u8>,
}

impl Net<'_> {
    fn stage(&mut self, s: AlertStage, d: Deadline) -> Result<(), NetError> {
        let now = self.t.now.get();
        if let Some((f, e)) = self.fail
            && f == s
        {
            self.t.now.set(now + self.ms);
            return Err(e);
        }
        if now + self.ms > d.network_end {
            self.t.now.set(d.network_end);
            return Err(NetError::Timeout);
        }
        self.t.now.set(now + self.ms);
        Ok(())
    }
}

impl Network for Net<'_> {
    fn wifi_start(&mut self, d: Deadline) -> Result<(), NetError> {
        self.stage(AlertStage::WifiStart, d)
    }
    fn associate(&mut self, d: Deadline) -> Result<(), NetError> {
        self.stage(AlertStage::Associate, d)
    }
    fn obtain_ip(&mut self, d: Deadline) -> Result<(), NetError> {
        self.stage(AlertStage::ObtainIp, d)
    }
    fn resolve(&mut self, _: &str, d: Deadline) -> Result<[u8; 4], NetError> {
        self.stage(AlertStage::Resolve, d)
            .map(|()| [149, 154, 167, 220])
    }
    fn connect(&mut self, _: [u8; 4], _: u16, d: Deadline) -> Result<(), NetError> {
        self.stage(AlertStage::Connect, d)
    }
    fn tls_handshake(&mut self, _: &str, d: Deadline) -> Result<(), NetError> {
        self.stage(AlertStage::Tls, d)
    }
    fn send(&mut self, r: &[u8], d: Deadline) -> Result<(), NetError> {
        self.sent = r.to_vec();
        self.stage(AlertStage::Request, d)
    }
    fn receive(&mut self, buf: &mut [u8], d: Deadline) -> Result<usize, NetError> {
        self.stage(AlertStage::Response, d)?;
        buf[..self.response.len()].copy_from_slice(self.response);
        Ok(self.response.len())
    }
    fn wifi_stop(&mut self) {
        self.t.now.set(self.t.now.get() + 15);
    }
}

fn ok(message_id: i64) -> &'static [u8] {
    Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"ok\":true,\"result\":{{\"message_id\":{message_id}}}}}"
        )
        .into_bytes()
        .into_boxed_slice(),
    )
}

/// Runs one attempt the way the firmware would, and applies its Zigbee
/// outage to the simulated hub. Returns the report and the text sent.
fn attempt(
    sim: &mut Simulator,
    c: usize,
    stage_ms: u64,
    fail: Option<(AlertStage, NetError)>,
    response: &'static [u8],
) -> (Report, String) {
    let mut request = [0u8; 2048];
    let (prepared, report, sent, resp) = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        let prepared = app.hub.prepare_alert(&mut request).unwrap();
        let t = T {
            now: Cell::new(1_000_000),
        };
        let mut radio = Radio { t: &t, on: true };
        let mut net = Net {
            t: &t,
            ms: stage_ms,
            fail,
            response,
            sent: Vec::new(),
        };
        let mut resp = [0u8; 1024];
        let report = attempt::run(
            &mut TClock(&t),
            &mut radio,
            &mut net,
            prepared.budget_ms,
            panweave_hub::alert::telegram::HOST,
            panweave_hub::alert::telegram::PORT,
            &request[..prepared.len],
            &mut resp,
        );
        assert!(radio.on, "Zigbee reception restored");
        panweave_hub::alert::telegram::wipe(&mut request);
        (prepared, report, net.sent, resp)
    };
    // The hub hears nothing while Wi-Fi has the radio.
    sim.isolate(c);
    sim.run_for(Duration::from_millis(u64::from(report.downtime_ms)));
    for j in 0..sim.node_count() {
        if j != c {
            sim.unblock(c, j);
        }
    }
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.poll(stack);
    app.hub.finish_alert(&prepared, &report, &resp);
    let body = String::from_utf8(sent).unwrap();
    let text = body
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, b)| b.to_owned());
    (report, text)
}

// ---- tests ----------------------------------------------------------

#[test]
fn the_mode_is_off_by_default_and_queues_nothing() {
    let (mut sim, c) = network();
    let leak = leak_sensor(&mut sim, c);
    let s = status(&mut sim, c);
    assert_eq!(s.state, AlertState::Disabled);
    assert!(!s.enabled && !s.password_set && !s.token_set);
    assert_eq!((s.delay_ms, s.budget_ms), (60_000, 2_000));
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakDetected
    )));
    let s = status(&mut sim, c);
    assert_eq!(
        (s.queue_depth, s.boot_id),
        (0, 0),
        "nothing opened, nothing written"
    );
    assert!(!due(&mut sim, c));
    assert_eq!(
        request(&mut sim, c, &Request::QueueTestAlert),
        Response::Error(ErrorCode::InvalidArgument)
    );
}

#[test]
fn a_leak_and_its_recovery_are_both_delivered_in_order_and_sensors_keep_reporting_after_the_outage()
{
    let (mut sim, c) = network();
    enable(&mut sim, c);
    let leak = leak_sensor(&mut sim, c);
    let contact = contact_sensor(&mut sim, c);
    let s = status(&mut sim, c);
    assert_eq!(s.state, AlertState::ZigbeeOperational);
    assert!(s.password_set && s.token_set);

    // The interview's first reading (unknown -> dry) is not news.
    assert!(saw(&sim, c, LEAK, SensorEvent::WaterLeakCleared));
    assert_eq!(status(&mut sim, c).queue_depth, 0);
    take_hub_events(&mut sim, c);
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakDetected
    )));
    let scheduled = status(&mut sim, c).next_attempt_ms.unwrap();
    let check_at = sim.clock.now().as_millis() + u64::from(scheduled);
    // The leak clears 10 s later, before any delivery.
    sim.run_for(Duration::from_secs(10));
    set_zone(&mut sim, leak, 0);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakCleared
    )));
    let s = status(&mut sim, c);
    assert_eq!(
        (s.queue_depth, s.state),
        (2, AlertState::WaitingForDelivery)
    );

    // Both transitions share the next minute boundary.
    while sim.clock.now().as_millis() + 1_000 < check_at {
        assert!(!due(&mut sim, c));
        sim.run_for(Duration::from_secs(1));
    }
    sim.run_for(Duration::from_millis(1_500));
    assert!(due(&mut sim, c));

    let (report, text) = attempt(&mut sim, c, 100, None, ok(4242));
    assert!(report.restored && !report.over_budget());
    let detected = text.find("Water leak detected.").unwrap();
    let cleared = text.find("Water leak cleared.").unwrap();
    assert!(detected < cleared, "{text}");
    assert!(text.contains("#1.0.") && text.contains("#1.1."), "{text}");
    assert!(text.contains("LUMI lumi.flood.agl02"));
    assert!(text.contains("no wall-clock time"));
    assert!(!text.contains(TOKEN) && !text.contains(PASSWORD));

    let s = status(&mut sim, c);
    assert_eq!(s.queue_depth, 0);
    assert_eq!((s.successes, s.failures), (1, 0));
    assert_eq!(s.last_message_id, Some(4242));
    assert_eq!(s.last_http_status, Some(200));
    assert_eq!(s.last_downtime_ms, Some(report.downtime_ms));
    // Every stage but the experiment's scan.
    for (stage, ms) in AlertStage::ALL.iter().zip(s.stage_ms) {
        assert_eq!(ms.is_some(), *stage != AlertStage::Scan, "{stage:?}");
    }
    assert_eq!(s.state, AlertState::ZigbeeOperational);

    // Already paired sensors keep reporting after Zigbee comes back.
    set_zone(&mut sim, contact, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        CONTACT,
        SensorEvent::ContactOpened
    )));
    let n = hub_events(&sim, c)
        .iter()
        .filter(|e| matches!(e, Event::Sensor { ieee, event: SensorEvent::WaterLeakDetected } if *ieee == LEAK))
        .count();
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        hub_events(x, c)
            .iter()
            .filter(|e| matches!(e, Event::Sensor { ieee, event: SensorEvent::WaterLeakDetected } if *ieee == LEAK))
            .count()
            > n
    }));
    // Both the contact opening and the new leak are queued by default.
    assert_eq!(status(&mut sim, c).queue_depth, 2);
}

#[test]
fn door_open_close_and_leak_are_batched_at_the_same_minute_check() {
    let (mut sim, c) = network();
    let contact = contact_sensor(&mut sim, c);
    let leak = leak_sensor(&mut sim, c);
    enable(&mut sim, c);
    take_hub_events(&mut sim, c);
    set_zone(&mut sim, contact, ALARM1);
    assert!(sim.run_until(Duration::from_secs(5), |x| saw(
        x,
        c,
        CONTACT,
        SensorEvent::ContactOpened
    )));
    let first_deadline =
        u64::from(status(&mut sim, c).next_attempt_ms.unwrap()) + sim.clock.now().as_millis();
    set_zone(&mut sim, contact, 0);
    assert!(sim.run_until(Duration::from_secs(5), |x| saw(
        x,
        c,
        CONTACT,
        SensorEvent::ContactClosed
    )));
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(5), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakDetected
    )));
    assert_eq!(status(&mut sim, c).queue_depth, 3);
    assert!(!due(&mut sim, c));
    assert_eq!(
        u64::from(status(&mut sim, c).next_attempt_ms.unwrap()) + sim.clock.now().as_millis(),
        first_deadline,
        "later events do not postpone the minute check"
    );
    while !due(&mut sim, c) {
        sim.run_for(Duration::from_millis(100));
    }
    let (_, body) = attempt(&mut sim, c, 50, None, ok(700));
    let opened = body.find("Contact opened.").unwrap();
    let closed = body.find("Contact closed.").unwrap();
    let wet = body.find("Water leak detected.").unwrap();
    assert!(opened < closed && closed < wet, "{body}");
    assert_eq!(status(&mut sim, c).queue_depth, 0);
    sim.run_for(Duration::from_secs(120));
    assert!(!due(&mut sim, c), "empty minutes must not start Wi-Fi");
    assert_eq!(status(&mut sim, c).successes, 1);
}

#[test]
fn network_failures_keep_the_events_and_back_off_with_zigbee_time_between_attempts() {
    let (mut sim, c) = network();
    let leak = leak_sensor(&mut sim, c);
    enable(&mut sim, c);
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakDetected
    )));
    sim.run_for(Duration::from_secs(61));
    assert!(due(&mut sim, c));
    let mut last_end = 0;
    for (stage, err) in [
        (AlertStage::Associate, NetError::Failed),
        (AlertStage::ObtainIp, NetError::Timeout),
        (AlertStage::Resolve, NetError::Failed),
        (AlertStage::Tls, NetError::Failed),
    ] {
        while !due(&mut sim, c) {
            sim.run_for(Duration::from_secs(1));
        }
        let start = sim.clock.now().as_millis();
        if last_end > 0 {
            assert!(start - last_end >= 30_000, "Zigbee time between attempts");
        }
        let (report, _) = attempt(&mut sim, c, 50, Some((stage, err)), ok(1));
        assert!(report.restored);
        last_end = sim.clock.now().as_millis();
        let s = status(&mut sim, c);
        assert_eq!(s.state, AlertState::RetryScheduled);
        // A stage that ran out of time is reported as such.
        let expected = if err == NetError::Timeout {
            AlertError::BudgetExhausted
        } else {
            AlertError::StageFailed
        };
        assert_eq!(s.last_error, expected);
        assert_eq!(s.last_error_stage, Some(stage));
        assert_eq!(s.queue_depth, 1, "kept after a failure at {stage:?}");
        assert!(s.next_attempt_ms.unwrap() >= 30_000);
    }
    assert_eq!(status(&mut sim, c).failures, 4);
    // Then it works.
    while !due(&mut sim, c) {
        sim.run_for(Duration::from_secs(5));
    }
    attempt(&mut sim, c, 50, None, ok(9));
    let s = status(&mut sim, c);
    assert_eq!((s.queue_depth, s.successes), (0, 1));
}

#[test]
fn the_budget_cancels_a_slow_attempt_and_zigbee_comes_back() {
    let (mut sim, c) = network();
    let leak = leak_sensor(&mut sim, c);
    enable(&mut sim, c);
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakDetected
    )));
    sim.run_for(Duration::from_secs(61));
    assert!(due(&mut sim, c));
    // Every stage takes 600 ms: the 2 s budget cannot be met.
    let (report, _) = attempt(&mut sim, c, 600, None, ok(1));
    assert!(report.restored);
    assert!(report.downtime_ms <= 2_000, "{}", report.downtime_ms);
    let s = status(&mut sim, c);
    assert_eq!(s.queue_depth, 1);
    assert!(matches!(
        s.last_error,
        AlertError::StageFailed | AlertError::BudgetExhausted
    ));
    // The sensor still reaches the hub after the cancelled attempt.
    set_zone(&mut sim, leak, 0);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakCleared
    )));
}

#[test]
fn an_ambiguous_attempt_marks_the_retry_as_a_possible_repeat() {
    let (mut sim, c) = network();
    let leak = leak_sensor(&mut sim, c);
    enable(&mut sim, c);
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakDetected
    )));
    sim.run_for(Duration::from_secs(61));
    assert!(due(&mut sim, c));
    let (_, first) = attempt(
        &mut sim,
        c,
        50,
        Some((AlertStage::Response, NetError::Timeout)),
        ok(1),
    );
    assert!(!first.contains("possible repeat"));
    let s = status(&mut sim, c);
    assert_eq!((s.ambiguous, s.last_error), (1, AlertError::Ambiguous));
    while !due(&mut sim, c) {
        sim.run_for(Duration::from_secs(5));
    }
    let (_, second) = attempt(&mut sim, c, 50, None, ok(2));
    assert!(second.contains("may repeat an earlier message"), "{second}");
    assert!(second.contains("#1.0.") && second.contains("[possible repeat]"));
}

#[test]
fn telegram_rate_limits_and_rejections_are_honoured() {
    let (mut sim, c) = network();
    enable(&mut sim, c);
    assert_eq!(
        request(&mut sim, c, &Request::QueueTestAlert),
        Response::Done
    );
    sim.run_for(Duration::from_secs(61));
    assert!(due(&mut sim, c));
    let limited: &'static [u8] = b"HTTP/1.1 429 Too Many Requests\r\n\r\n{\"ok\":false,\"error_code\":429,\"parameters\":{\"retry_after\":300}}";
    attempt(&mut sim, c, 50, None, limited);
    let s = status(&mut sim, c);
    assert_eq!(s.last_error, AlertError::RateLimited);
    assert_eq!(s.last_http_status, Some(429));
    assert!(s.next_attempt_ms.unwrap() >= 299_000);
    while !due(&mut sim, c) {
        sim.run_for(Duration::from_secs(10));
    }
    let forbidden: &'static [u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n{\"ok\":false,\"error_code\":403,\"description\":\"Forbidden: bot is not a member of the channel chat\"}";
    attempt(&mut sim, c, 50, None, forbidden);
    let s = status(&mut sim, c);
    assert_eq!(s.last_error, AlertError::Rejected);
    assert_eq!(s.queue_depth, 1, "kept until the bot can post");
}

#[test]
fn pending_events_and_the_acknowledgement_survive_a_hub_reboot() {
    let (mut sim, c) = network();
    let leak = leak_sensor(&mut sim, c);
    enable(&mut sim, c);
    set_zone(&mut sim, leak, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        LEAK,
        SensorEvent::WaterLeakDetected
    )));

    let reboot = |sim: &mut Simulator| {
        let storage = {
            let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
            app.hub.flush();
            app.hub.storage().clone()
        };
        let mut rebooted = HubApp::new(storage);
        rebooted.hub.restore().unwrap();
        rebooted.hub.set_alert_radio_switching(true);
        sim.node_mut(c).app = Box::new(rebooted);
    };
    // Power loss before any attempt.
    reboot(&mut sim);
    let s = status(&mut sim, c);
    assert_eq!((s.enabled, s.queue_depth, s.boot_id), (true, 1, 2));
    assert!(s.password_set && s.token_set, "settings persisted");
    // Due a delay after the boot.
    assert!(!due(&mut sim, c));
    sim.run_for(Duration::from_secs(61));
    assert!(due(&mut sim, c));
    let (_, text) = attempt(&mut sim, c, 50, None, ok(31337));
    assert!(
        text.contains("#1.0."),
        "the identifier from the first boot: {text}"
    );
    reboot(&mut sim);
    let s = status(&mut sim, c);
    assert_eq!(s.queue_depth, 0, "delivered events are not resent");
    assert_eq!(
        s.last_message_id,
        Some(31337),
        "the acknowledgement persisted"
    );
    assert_eq!(s.boot_id, 3);
}

#[test]
fn a_full_queue_counts_losses_and_reports_them_without_evicting_alarms() {
    let (mut sim, c) = network();
    enable(&mut sim, c);
    for _ in 0..20 {
        assert_eq!(
            request(&mut sim, c, &Request::QueueTestAlert),
            Response::Done
        );
    }
    let s = status(&mut sim, c);
    assert_eq!((s.queue_depth, s.queue_capacity, s.overflowed), (16, 16, 4));
    sim.run_for(Duration::from_secs(61));
    let (_, text) = attempt(&mut sim, c, 50, None, ok(5));
    assert!(
        text.contains("4 event(s) were not stored (queue full), #1.16 to #1.19."),
        "{text}"
    );
    assert!(text.contains("#1.0."), "the oldest event was kept");
    let s = status(&mut sim, c);
    assert_eq!(s.overflowed, 0, "reported, so cleared");
    assert!(
        s.queue_depth < 16 && s.queue_depth > 0,
        "the rest wait for the next message"
    );
}

#[test]
fn settings_are_validated_and_secrets_are_never_returned() {
    let (mut sim, c) = network();
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::SetAlertConfig(AlertConfigUpdate {
                budget_ms: Some(100),
                ..AlertConfigUpdate::default()
            })
        ),
        Response::Error(ErrorCode::InvalidArgument)
    );
    enable(&mut sim, c);
    let mut body = [0u8; 600];
    let n = panweave_hub::protocol::Message::Response {
        id: 1,
        response: Response::AlertStatus(status(&mut sim, c)),
    }
    .encode(&mut body)
    .unwrap();
    let wire = &body[..n];
    for secret in [PASSWORD, TOKEN] {
        assert!(!wire.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
    // Without radio switching in the firmware nothing is ever due.
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.set_alert_radio_switching(false);
    assert_eq!(status(&mut sim, c).state, AlertState::Unsupported);
}

/// A scan that heard two neighbours and not the configured network.
fn heard() -> WifiScan {
    let entry = |ssid: &[u8], channel, rssi| ScanEntry {
        ssid: HVec::from_slice(ssid).unwrap(),
        bssid: [0x02, 0x11, 0x22, 0x33, 0x44, channel],
        channel,
        rssi,
        auth: panweave_hub::protocol::alerts::auth::WPA2,
    };
    WifiScan {
        scan_ms: 310,
        seen: 2,
        target: None,
        strongest: HVec::from_slice(&[entry(b"Neighbour", 6, -48), entry(b"", 11, -80)]).unwrap(),
    }
}

#[test]
fn the_radio_probe_runs_once_per_request_and_sensors_report_afterwards() {
    let (mut sim, c) = network();
    let contact = contact_sensor(&mut sim, c);
    // Firmware without the experiment.
    assert_eq!(
        request(&mut sim, c, &Request::RunRadioProbe),
        Response::Error(ErrorCode::NotSupported)
    );
    assert_eq!(
        request(&mut sim, c, &Request::GetWifiScan),
        Response::Error(ErrorCode::NotSupported)
    );
    {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.set_radio_probe_supported(true);
    }
    // No access point configured yet.
    assert_eq!(
        request(&mut sim, c, &Request::RunRadioProbe),
        Response::Error(ErrorCode::InvalidArgument)
    );
    enable(&mut sim, c);
    assert_eq!(
        request(&mut sim, c, &Request::RunRadioProbe),
        Response::Done
    );
    let (report, sent) = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        assert!(app.hub.take_radio_probe());
        assert!(!app.hub.take_radio_probe(), "one probe per request");
        let t = T {
            now: Cell::new(5_000),
        };
        let mut radio = Radio { t: &t, on: true };
        let mut net = Net {
            t: &t,
            ms: 200,
            fail: None,
            response: ok(1),
            sent: Vec::new(),
        };
        let budget = app.hub.alert_probe_budget_ms();
        let report = attempt::run_probe(&mut TClock(&t), &mut radio, &mut net, budget);
        assert!(radio.on);
        app.hub.finish_probe(&report);
        (report, net.sent)
    };
    assert!(sent.is_empty(), "a probe sends nothing");
    sim.isolate(c);
    sim.run_for(Duration::from_millis(u64::from(report.downtime_ms)));
    for j in 0..sim.node_count() {
        if j != c {
            sim.unblock(c, j);
        }
    }
    let s = status(&mut sim, c);
    assert_eq!((s.probes, s.probes_associated), (1, 1));
    assert_eq!(s.last_downtime_ms, Some(report.downtime_ms));
    assert_eq!(s.stage_ms[AlertStage::Associate.index()], Some(200));
    assert_eq!(s.stage_ms[AlertStage::ObtainIp.index()], None);
    assert_eq!(s.queue_depth, 0, "the queue is not involved");
    // Not again before Zigbee had its mandatory period.
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.poll(stack);
    assert_eq!(
        request(&mut sim, c, &Request::RunRadioProbe),
        Response::Error(ErrorCode::Busy)
    );
    assert_eq!(s.wifi_failure, None, "joined: no failure reason");
    assert_eq!(
        request(&mut sim, c, &Request::GetWifiScan),
        Response::WifiScan(None),
        "nothing scanned yet"
    );
    sim.run_for(Duration::from_secs(31));
    assert_eq!(
        request(&mut sim, c, &Request::RunRadioProbe),
        Response::Done
    );
    // The access point is not found: the driver's reason and signal are
    // reported with the failed stage.
    {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        assert!(app.hub.take_radio_probe());
        let t = T {
            now: Cell::new(60_000),
        };
        let mut radio = Radio { t: &t, on: true };
        let mut net = Net {
            t: &t,
            ms: 200,
            fail: Some((AlertStage::Associate, NetError::Failed)),
            response: ok(1),
            sent: Vec::new(),
        };
        let report = attempt::run_probe(&mut TClock(&t), &mut radio, &mut net, 2_000);
        let failure = WifiFailure {
            reason: 201,
            rssi: None,
        };
        app.hub.note_wifi_failure(Some(failure));
        app.hub.note_wifi_scan(Some(heard()));
        app.hub.finish_probe(&report);
    }
    assert_eq!(
        request(&mut sim, c, &Request::GetWifiScan),
        Response::WifiScan(Some(heard()))
    );
    let s = status(&mut sim, c);
    assert_eq!((s.probes, s.probes_associated), (2, 1));
    assert_eq!(s.last_error_stage, Some(AlertStage::Associate));
    assert_eq!(
        s.wifi_failure,
        Some(WifiFailure {
            reason: 201,
            rssi: None
        })
    );
    set_zone(&mut sim, contact, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| saw(
        x,
        c,
        CONTACT,
        SensorEvent::ContactOpened
    )));
}

// ---- a server destination ------------------------------------------

/// A server-like uplink for the engine tests: the request lists the
/// event identifiers; the answer `all` acknowledges every event, a list
/// `boot.seq,…` only those.
struct ListUplink;

impl Uplink for ListUplink {
    fn build(
        &mut self,
        _ctx: &uplink::Context<'_>,
        pending: &[uplink::Pending<'_>],
        out: &mut [u8],
    ) -> Result<uplink::Built, uplink::BuildError> {
        let mut s = String::from("POST /r HTTP/1.1\r\n\r\n");
        for p in pending {
            let _ = write!(s, "{}.{},", p.event.id.boot, p.event.id.seq);
        }
        let b = s.as_bytes();
        out.get_mut(..b.len())
            .ok_or(uplink::BuildError::TooLong)?
            .copy_from_slice(b);
        Ok(uplink::Built {
            len: b.len(),
            events: pending.len(),
            overflow_reported: 0,
        })
    }

    fn parse(&mut self, response: &[u8]) -> (Option<u16>, uplink::Reply) {
        let mut scratch = [0u8; 256];
        let Some((status, body)) = uplink::http_body(response, &mut scratch) else {
            return (None, uplink::Reply::Malformed);
        };
        if status != 200 {
            return (Some(status), uplink::Reply::ServerError);
        }
        let body = core::str::from_utf8(body).unwrap();
        let acked = if body == "all" {
            uplink::Acked::All
        } else {
            uplink::Acked::Some(
                body.split(',')
                    .filter(|x| !x.is_empty())
                    .map(|x| {
                        let (b, s) = x.split_once('.').unwrap();
                        EventId {
                            boot: b.parse().unwrap(),
                            seq: s.parse().unwrap(),
                        }
                    })
                    .collect(),
            )
        };
        (
            Some(status),
            uplink::Reply::Delivered {
                acked,
                message_id: None,
            },
        )
    }

    fn accepts_heartbeat(&self) -> bool {
        true
    }
}

/// Runs the simulation second by second until an attempt is due.
fn wait_due(sim: &mut Simulator, c: usize, secs: u64) -> bool {
    for _ in 0..secs {
        if due(sim, c) {
            return true;
        }
        sim.run_for(Duration::from_secs(1));
    }
    due(sim, c)
}

fn http_ok(body: &str) -> &'static [u8] {
    Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
        .into_boxed_slice(),
    )
}

fn enable_server(sim: &mut Simulator, c: usize, heartbeat_s: u32) {
    configure(
        sim,
        c,
        AlertConfigUpdate {
            enabled: Some(true),
            ssid: Some(text("home")),
            password: Some(text(PASSWORD)),
            token: Some(text("hub-token_0123456789")),
            destination: Some(AlertDestination::Server),
            server_host: Some(text("hub.example.com")),
            server_port: Some(8443),
            heartbeat_s: Some(heartbeat_s),
            ..AlertConfigUpdate::default()
        },
    );
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.set_alert_radio_switching(true);
}

/// One attempt with [`ListUplink`]; returns the prepared request and
/// the request text.
fn server_attempt(
    sim: &mut Simulator,
    c: usize,
    fail: Option<(AlertStage, NetError)>,
    response: &'static [u8],
) -> (PreparedAlert, String) {
    let mut request = [0u8; 2048];
    let (prepared, report, sent, resp) = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        let prepared = app
            .hub
            .prepare_alert_with(&mut ListUplink, &mut request)
            .unwrap();
        let t = T {
            now: Cell::new(1_000_000),
        };
        let mut radio = Radio { t: &t, on: true };
        let mut net = Net {
            t: &t,
            ms: 100,
            fail,
            response,
            sent: Vec::new(),
        };
        let mut resp = [0u8; 1024];
        let report = attempt::run(
            &mut TClock(&t),
            &mut radio,
            &mut net,
            prepared.budget_ms,
            &prepared.host,
            prepared.port,
            &request[..prepared.len],
            &mut resp,
        );
        (prepared, report, net.sent, resp)
    };
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    app.hub.poll(stack);
    app.hub
        .finish_alert_with(&mut ListUplink, &prepared, &report, &resp);
    (prepared, String::from_utf8(sent).unwrap())
}

#[test]
fn a_server_destination_sends_heartbeats_when_nothing_is_queued() {
    let (mut sim, c) = network();
    enable_server(&mut sim, c, 120);
    let s = status(&mut sim, c);
    assert_eq!(s.state, AlertState::ZigbeeOperational);
    assert_eq!(s.destination, AlertDestination::Server);
    assert_eq!(
        (s.server_host.as_slice(), s.server_port, s.heartbeat_s),
        (b"hub.example.com".as_slice(), 8443, 120)
    );
    assert!(s.next_heartbeat_ms.is_some_and(|ms| ms <= 60_000));
    assert!(!due(&mut sim, c), "the first heartbeat waits one interval");

    sim.run_for(Duration::from_secs(61));
    assert!(due(&mut sim, c));
    let (prepared, sent) = server_attempt(&mut sim, c, None, http_ok("all"));
    assert!(prepared.heartbeat);
    assert_eq!(
        (prepared.host.as_str(), prepared.port),
        ("hub.example.com", 8443)
    );
    assert!(sent.ends_with("\r\n\r\n"), "no events: {sent:?}");
    let s = status(&mut sim, c);
    assert_eq!((s.successes, s.last_error), (1, AlertError::None));
    assert!(s.next_heartbeat_ms.is_some_and(|ms| ms > 110_000));
    assert!(!due(&mut sim, c));

    // A failed heartbeat is retried sooner than the interval, but not
    // before the mandatory Zigbee time.
    sim.run_for(Duration::from_secs(121));
    assert!(due(&mut sim, c));
    server_attempt(
        &mut sim,
        c,
        Some((AlertStage::Connect, NetError::Failed)),
        http_ok("all"),
    );
    let s = status(&mut sim, c);
    assert_eq!(s.failures, 1);
    assert!(
        s.next_heartbeat_ms
            .is_some_and(|ms| (29_000..=120_000).contains(&ms))
    );
    assert_eq!(s.queue_depth, 0);

    // Telegram never gets a heartbeat.
    configure(
        &mut sim,
        c,
        AlertConfigUpdate {
            destination: Some(AlertDestination::Telegram),
            chat_id: Some(text("-1001234567890")),
            ..AlertConfigUpdate::default()
        },
    );
    assert_eq!(status(&mut sim, c).next_heartbeat_ms, None);
    sim.run_for(Duration::from_secs(600));
    assert!(!due(&mut sim, c));
}

#[test]
fn a_server_acknowledging_some_events_keeps_the_others_queued() {
    let (mut sim, c) = network();
    enable_server(&mut sim, c, 0);
    let leak = leak_sensor(&mut sim, c);
    let contact = contact_sensor(&mut sim, c);
    take_hub_events(&mut sim, c);
    set_zone(&mut sim, leak, ALARM1);
    set_zone(&mut sim, contact, ALARM1);
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        saw(x, c, LEAK, SensorEvent::WaterLeakDetected)
            && saw(x, c, CONTACT, SensorEvent::ContactOpened)
    }));
    assert_eq!(status(&mut sim, c).queue_depth, 2);
    assert!(wait_due(&mut sim, c, 120));

    // The server takes only the first event.
    let boot = status(&mut sim, c).boot_id;
    let (prepared, sent) = server_attempt(&mut sim, c, None, http_ok(&format!("{boot}.0,")));
    assert!(!prepared.heartbeat);
    assert!(sent.contains(&format!("{boot}.0,")) && sent.contains(&format!("{boot}.1,")));
    let s = status(&mut sim, c);
    assert_eq!((s.queue_depth, s.successes), (1, 1));

    // The other is sent again, marked as possibly delivered, and taken.
    assert!(wait_due(&mut sim, c, 300));
    let (_, sent) = server_attempt(&mut sim, c, None, http_ok("all"));
    assert!(sent.contains(&format!("{boot}.1,")) && !sent.contains(&format!("{boot}.0,")));
    assert_eq!(status(&mut sim, c).queue_depth, 0);
}

#[test]
fn server_settings_travel_in_the_protocol_and_are_validated() {
    let (mut sim, c) = network();
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::SetAlertConfig(AlertConfigUpdate {
                server_host: Some(text("not a host")),
                ..AlertConfigUpdate::default()
            })
        ),
        Response::Error(ErrorCode::InvalidArgument)
    );
    enable_server(&mut sim, c, 900);
    let s = status(&mut sim, c);
    assert_eq!(
        s.state,
        AlertState::ZigbeeOperational,
        "complete without a chat"
    );
    assert!(s.token_set);
    assert_eq!(s.heartbeat_s, 900);
}
