//! The hub's side of the experimental Wi-Fi notifications
//! ([`crate::alert`]): sensor events are queued durably as they are
//! emitted; the firmware asks [`Hub::alert_due`], builds the request with
//! [`Hub::prepare_alert`], runs [`crate::alert::attempt::run`] with its
//! radio and network, and reports with [`Hub::finish_alert`].

use heapless::Vec;
use panweave_storage::Storage;

use crate::alert::attempt::{Outcome, Report};
use crate::alert::message::{self, Sensor};
use crate::alert::queue::{self, EventId, Queue};
use crate::alert::schedule::{MIN_ZIGBEE_MS, Schedule};
use crate::alert::{Config, telegram};
use crate::hub::Hub;
use crate::model::{ContactState, DeviceState, Flag, LeakState};
use crate::protocol::alerts::STAGES;
use crate::protocol::{
    AlertConfigUpdate, AlertError, AlertKind, AlertStage, AlertState, AlertStatus, ErrorCode,
    Request, Response,
};

/// The notification state the hub keeps.
#[derive(Debug, Default)]
pub(crate) struct AlertEngine {
    config: Config,
    queue: Option<Queue>,
    schedule: Schedule,
    status: AlertStatus,
    restore_failed: bool,
    supported: bool,
    loaded: bool,
    probe_supported: bool,
    probe_requested: bool,
    /// When the last probe ended (monotonic ms).
    probe_ended: Option<u64>,
    /// What the last probe's scan heard.
    scan: Option<crate::protocol::WifiScan>,
}

/// A request ready for an attempt.
#[derive(Clone, Debug)]
pub struct PreparedAlert {
    /// Length of the request in the caller's buffer (which holds the bot
    /// token: wipe it after the attempt, [`telegram::wipe`]).
    pub len: usize,
    /// The Zigbee downtime budget to run the attempt with.
    pub budget_ms: u32,
    ids: Vec<EventId, { queue::CAPACITY }>,
    overflow_reported: u32,
}

fn sensor_state(leak: LeakState, contact: ContactState) -> &'static str {
    match (leak, contact) {
        (LeakState::Leak, _) => "leak",
        (LeakState::Dry, _) => "dry",
        (_, ContactState::Open) => "open",
        (_, ContactState::Closed) => "closed",
        _ => "unknown",
    }
}

impl<HS: Storage> Hub<HS> {
    /// Loads the notification settings, and the queue when enabled. Part
    /// of [`Hub::restore`]; reads nothing else and writes only when the
    /// mode is enabled (one boot-counter write).
    pub(crate) fn restore_alerts(&mut self) {
        if !self.config.persistent {
            return;
        }
        self.alerts.config = Config::load(&mut self.storage);
        self.alerts.loaded = true;
        if self.alerts.config.enabled {
            self.open_alert_queue();
        }
    }

    fn open_alert_queue(&mut self) {
        if self.alerts.queue.is_none() {
            let q = Queue::open(&mut self.storage);
            let now = self.now.as_millis();
            self.alerts.schedule.on_boot(
                now,
                !q.is_empty(),
                u64::from(self.alerts.config.delay_ms),
            );
            self.alerts.queue = Some(q);
        }
    }

    /// Declares whether this firmware can hand the radio to Wi-Fi (it
    /// implements `alert::attempt::RadioSwitch` and `Network`). Without
    /// it events are still queued when the mode is enabled, but no
    /// attempt is ever due.
    pub fn set_alert_radio_switching(&mut self, supported: bool) {
        self.alerts.supported = supported;
    }

    /// Declares whether this firmware can run the radio-switch
    /// experiment ([`crate::alert::attempt::run_probe`]), independently
    /// of full delivery support.
    pub fn set_radio_probe_supported(&mut self, supported: bool) {
        self.alerts.probe_supported = supported;
    }

    /// Whether a host asked for a radio-switch experiment; clears the
    /// request. The firmware then runs `attempt::run_probe` with
    /// [`Hub::alert_probe_budget_ms`] and reports with
    /// [`Hub::finish_probe`].
    pub fn take_radio_probe(&mut self) -> bool {
        core::mem::take(&mut self.alerts.probe_requested)
    }

    /// The Zigbee downtime budget for a probe (the configured budget).
    pub fn alert_probe_budget_ms(&self) -> u32 {
        self.alerts.config.budget_ms
    }

    /// Records why the attempt being finished could not join the access
    /// point (`None`: it joined, or did not get that far). Call before
    /// [`Hub::finish_probe`] or [`Hub::finish_alert`]; the value stays in
    /// [`AlertStatus::wifi_failure`] until the next attempt reports.
    ///
    /// [`AlertStatus::wifi_failure`]: crate::protocol::AlertStatus::wifi_failure
    pub fn note_wifi_failure(&mut self, failure: Option<crate::protocol::WifiFailure>) {
        self.alerts.status.wifi_failure = failure;
    }

    /// Records what the probe being finished heard in its scan (`None`:
    /// it did not get to scan). Call before [`Hub::finish_probe`];
    /// answered to `GetWifiScan` until the next probe.
    pub fn note_wifi_scan(&mut self, scan: Option<crate::protocol::WifiScan>) {
        self.alerts.scan = scan;
    }

    /// Records a radio-switch experiment: stage durations, downtime,
    /// overruns, restoration. The queue is not touched.
    pub fn finish_probe(&mut self, report: &Report) {
        self.alerts.probe_ended = Some(self.now.as_millis());
        let st = &mut self.alerts.status;
        st.probes = st.probes.saturating_add(1);
        st.stage_ms = report.stage_ms;
        st.last_downtime_ms = Some(report.downtime_ms);
        st.max_downtime_ms = Some(st.max_downtime_ms.unwrap_or(0).max(report.downtime_ms));
        st.last_http_status = None;
        if report.over_budget() {
            st.budget_overruns = st.budget_overruns.saturating_add(1);
        }
        match report.outcome {
            Outcome::Response(_) => {
                st.probes_associated = st.probes_associated.saturating_add(1);
                st.last_error = AlertError::None;
                st.last_error_stage = None;
            }
            Outcome::Failed { stage, timed_out } => {
                st.last_error = if timed_out {
                    AlertError::BudgetExhausted
                } else {
                    AlertError::StageFailed
                };
                st.last_error_stage = Some(stage);
            }
            Outcome::Cancelled { stage } | Outcome::Ambiguous { stage } => {
                st.last_error = AlertError::BudgetExhausted;
                st.last_error_stage = Some(stage);
            }
            Outcome::SuspendFailed => {
                st.last_error = AlertError::StageFailed;
                st.last_error_stage = Some(AlertStage::StopZigbee);
            }
        }
        if !report.restored {
            st.restore_failures = st.restore_failures.saturating_add(1);
            st.last_error = AlertError::RadioRestore;
            st.last_error_stage = Some(AlertStage::RestoreZigbee);
            self.alerts.restore_failed = true;
        }
    }

    /// Queues the notifiable changes between two states of a sensor when
    /// the mode is enabled and the kind selected. A recovery is queued
    /// only after an alarm: the first reading of a sensor (unknown → dry,
    /// unknown → closed, after a pairing or a reboot) is not news.
    pub(crate) fn alert_state_change(
        &mut self,
        ieee: u64,
        before: &DeviceState,
        after: &DeviceState,
    ) {
        if !self.alerts.config.enabled {
            return;
        }
        let mut kinds: Vec<AlertKind, 4> = Vec::new();
        match (before.water_leak, after.water_leak) {
            (b, LeakState::Leak) if b != LeakState::Leak => {
                let _ = kinds.push(AlertKind::WaterLeak);
            }
            (LeakState::Leak, LeakState::Dry) => {
                let _ = kinds.push(AlertKind::WaterLeakCleared);
            }
            _ => {}
        }
        match (before.contact, after.contact) {
            (b, ContactState::Open) if b != ContactState::Open => {
                let _ = kinds.push(AlertKind::ContactOpened);
            }
            (ContactState::Open, ContactState::Closed) => {
                let _ = kinds.push(AlertKind::ContactClosed);
            }
            _ => {}
        }
        if before.tamper != Flag::Set && after.tamper == Flag::Set {
            let _ = kinds.push(AlertKind::Tamper);
        }
        if before.battery_low != Flag::Set && after.battery_low == Flag::Set {
            let _ = kinds.push(AlertKind::BatteryLow);
        }
        for kind in kinds {
            if self.alerts.config.kinds & kind.kind_bit() != 0 {
                self.queue_alert(kind, ieee, after.zone_status);
            }
        }
    }

    fn queue_alert(&mut self, kind: AlertKind, ieee: u64, zone_status: Option<u16>) {
        self.open_alert_queue();
        let now = self.now.as_millis();
        let delay = u64::from(self.alerts.config.delay_ms);
        let Some(q) = self.alerts.queue.as_mut() else {
            return;
        };
        let errors = q.storage_errors;
        if q.push(&mut self.storage, kind, ieee, zone_status, now)
            .is_ok()
        {
            self.alerts.schedule.on_event(now, delay);
        }
        if q.storage_errors != errors {
            self.alerts.status.last_error = AlertError::Storage;
        }
    }

    /// Whether an attempt should start now.
    pub fn alert_due(&self) -> bool {
        self.alerts.config.enabled
            && self.alerts.supported
            && !self.alerts.restore_failed
            && self.alerts.config.is_complete()
            && self.alerts.queue.as_ref().is_some_and(|q| !q.is_empty())
            && self.alerts.schedule.is_due(self.now.as_millis())
    }

    /// When the next attempt is due (monotonic ms), while one can run.
    pub(crate) fn alert_deadline(&self) -> Option<u64> {
        let a = &self.alerts;
        (a.config.enabled && a.supported && !a.restore_failed && a.config.is_complete())
            .then(|| a.schedule.due())
            .flatten()
            .filter(|_| a.queue.as_ref().is_some_and(|q| !q.is_empty()))
    }

    /// The Wi-Fi SSID and password the firmware's `Network` connects
    /// with (secret: never log them).
    pub fn alert_wifi_credentials(&self) -> (&[u8], &[u8]) {
        (&self.alerts.config.ssid, &self.alerts.config.password)
    }

    /// The access-point pin: BSSID, channel, WPA3-only.
    pub fn alert_wifi_pin(&self) -> (Option<[u8; 6]>, Option<u8>, bool) {
        let c = &self.alerts.config;
        (c.bssid, c.channel, c.wpa3_only)
    }

    /// Builds the `sendMessage` request for the pending events into
    /// `out` (which then holds the bot token).
    pub fn prepare_alert(&mut self, out: &mut [u8]) -> Option<PreparedAlert> {
        let q = self.alerts.queue.as_ref()?;
        let pending = q.pending();
        if pending.is_empty() {
            return None;
        }
        let registry = &self.registry;
        let mut names: Vec<(u64, heapless::String<72>), { queue::CAPACITY }> = Vec::new();
        for e in &pending {
            if let Some(d) = registry.get(e.ieee)
                && !names.iter().any(|(i, _)| *i == e.ieee)
            {
                let mut n = heapless::String::new();
                let m = core::str::from_utf8(&d.manufacturer).unwrap_or("");
                let mo = core::str::from_utf8(&d.model).unwrap_or("");
                let _ = core::fmt::Write::write_fmt(&mut n, format_args!("{m} {mo}"));
                let _ = names.push((e.ieee, n));
            }
        }
        let composed = message::compose(&pending, q.overflow(), |ieee| Sensor {
            name: names
                .iter()
                .find(|(i, _)| *i == ieee)
                .map_or("", |(_, n)| n.as_str().trim()),
            state: registry.get(ieee).map_or("unknown", |d| {
                sensor_state(d.state.water_leak, d.state.contact)
            }),
        });
        let len = match telegram::build_request(
            &self.alerts.config.token,
            &self.alerts.config.chat_id,
            &composed.text,
            out,
        ) {
            Ok(n) => n,
            Err(_) => {
                self.alerts.status.last_error = AlertError::Rejected;
                return None;
            }
        };
        self.alerts.status.attempts = self.alerts.status.attempts.saturating_add(1);
        Some(PreparedAlert {
            len,
            budget_ms: self.alerts.config.budget_ms,
            ids: pending.iter().take(composed.events).map(|e| e.id).collect(),
            overflow_reported: composed.overflow_reported,
        })
    }

    /// Records the outcome of an attempt run with `prepared`; `response`
    /// is the buffer the attempt received into.
    pub fn finish_alert(&mut self, prepared: &PreparedAlert, report: &Report, response: &[u8]) {
        let now = self.now.as_millis();
        let delay = u64::from(self.alerts.config.delay_ms);
        let st = &mut self.alerts.status;
        st.stage_ms = report.stage_ms;
        st.last_downtime_ms = Some(report.downtime_ms);
        st.max_downtime_ms = Some(st.max_downtime_ms.unwrap_or(0).max(report.downtime_ms));
        if report.over_budget() {
            st.budget_overruns = st.budget_overruns.saturating_add(1);
        }
        st.last_http_status = None;
        let mut retry_after = None;
        let (error, stage, ambiguous) = match report.outcome {
            Outcome::Response(n) => {
                let mut scratch = [0u8; 512];
                let (status, reply) =
                    telegram::parse_response(response.get(..n).unwrap_or(&[]), &mut scratch);
                st.last_http_status = status;
                match reply {
                    telegram::Reply::Delivered { message_id } => {
                        st.last_message_id = Some(message_id);
                        (AlertError::None, None, false)
                    }
                    telegram::Reply::RetryAfter { seconds, .. } => {
                        retry_after = Some(seconds);
                        (AlertError::RateLimited, Some(AlertStage::Response), false)
                    }
                    telegram::Reply::Rejected { .. } => {
                        (AlertError::Rejected, Some(AlertStage::Response), false)
                    }
                    telegram::Reply::ServerError { .. } => {
                        (AlertError::StageFailed, Some(AlertStage::Response), false)
                    }
                    telegram::Reply::Malformed => {
                        (AlertError::BadResponse, Some(AlertStage::Response), true)
                    }
                }
            }
            // The deadline expired inside the stage.
            Outcome::Failed {
                stage,
                timed_out: true,
            } => (AlertError::BudgetExhausted, Some(stage), false),
            Outcome::Failed { stage, .. } => (AlertError::StageFailed, Some(stage), false),
            Outcome::Cancelled { stage } => (AlertError::BudgetExhausted, Some(stage), false),
            Outcome::Ambiguous { stage } => (AlertError::Ambiguous, Some(stage), true),
            Outcome::SuspendFailed => {
                (AlertError::StageFailed, Some(AlertStage::StopZigbee), false)
            }
        };
        if ambiguous {
            st.ambiguous = st.ambiguous.saturating_add(1);
        }
        let delivered = error == AlertError::None;
        if delivered {
            st.successes = st.successes.saturating_add(1);
            st.last_error = AlertError::None;
            st.last_error_stage = None;
        } else {
            st.failures = st.failures.saturating_add(1);
            st.last_error = error;
            st.last_error_stage = stage;
        }
        if !report.restored {
            st.restore_failures = st.restore_failures.saturating_add(1);
            st.last_error = AlertError::RadioRestore;
            st.last_error_stage = Some(AlertStage::RestoreZigbee);
            self.alerts.restore_failed = true;
        }
        let Some(q) = self.alerts.queue.as_mut() else {
            return;
        };
        if delivered {
            let message_id = self.alerts.status.last_message_id.unwrap_or(0);
            q.acknowledge(
                &mut self.storage,
                message_id,
                &prepared.ids,
                prepared.overflow_reported,
            );
            let boot = q.boot();
            let oldest = q
                .pending()
                .iter()
                .map(|e| {
                    if e.id.boot == boot {
                        e.at_ms
                    } else {
                        now.saturating_sub(delay)
                    }
                })
                .min();
            self.alerts.schedule.on_success(now, oldest, delay);
        } else {
            q.note_attempt(&mut self.storage, &prepared.ids, ambiguous);
            self.alerts.schedule.on_failure(now, retry_after, delay);
        }
    }

    fn alert_state(&self) -> AlertState {
        let a = &self.alerts;
        if !a.config.enabled {
            AlertState::Disabled
        } else if a.restore_failed {
            AlertState::RadioRestoreFailed
        } else if !a.supported {
            AlertState::Unsupported
        } else if !a.config.is_complete() {
            AlertState::NotConfigured
        } else if a.queue.as_ref().is_none_or(Queue::is_empty) {
            AlertState::ZigbeeOperational
        } else if a.schedule.failures() > 0 {
            AlertState::RetryScheduled
        } else {
            AlertState::WaitingForDelivery
        }
    }

    /// The notification state, without secrets.
    pub fn alert_status(&self) -> AlertStatus {
        let a = &self.alerts;
        let c = &a.config;
        let mut s = a.status.clone();
        s.state = self.alert_state();
        s.enabled = c.enabled;
        s.ssid.clone_from(&c.ssid);
        s.password_set = !c.password.is_empty();
        s.bssid = c.bssid;
        s.channel = c.channel;
        s.wpa3_only = c.wpa3_only;
        s.token_set = !c.token.is_empty();
        s.chat_id.clone_from(&c.chat_id);
        s.kinds = c.kinds;
        s.delay_ms = c.delay_ms;
        s.budget_ms = c.budget_ms;
        #[allow(clippy::cast_possible_truncation)]
        {
            s.min_zigbee_ms = MIN_ZIGBEE_MS as u32;
            s.queue_capacity = queue::CAPACITY as u8;
        }
        if let Some(q) = &a.queue {
            s.boot_id = q.boot();
            s.queue_depth = u8::try_from(q.len()).unwrap_or(u8::MAX);
            s.overflowed = q.overflow().count;
            s.next_attempt_ms = a
                .schedule
                .remaining(self.now.as_millis())
                .filter(|_| !q.is_empty())
                .map(|r| u32::try_from(r).unwrap_or(u32::MAX));
            if s.last_message_id.is_none() {
                s.last_message_id = q.last_ack().map(|a| a.message_id);
            }
        }
        debug_assert_eq!(s.stage_ms.len(), STAGES);
        s
    }

    fn set_alert_config(&mut self, u: &AlertConfigUpdate) -> Result<(), ErrorCode> {
        if !self.config.persistent {
            // Events must never live only in RAM.
            return Err(ErrorCode::StorageFailure);
        }
        if !self.alerts.loaded {
            self.restore_alerts();
        }
        let mut c = self.alerts.config.clone();
        c.apply(u)?;
        c.store(&mut self.storage)?;
        self.alerts.config = c;
        if self.alerts.config.enabled {
            self.open_alert_queue();
            self.alerts.restore_failed = false;
            if u.delay_ms.is_some() || u.enabled == Some(true) {
                self.alerts.schedule.clear();
                if self.alerts.queue.as_ref().is_some_and(|q| !q.is_empty()) {
                    self.alerts
                        .schedule
                        .on_event(self.now.as_millis(), u64::from(self.alerts.config.delay_ms));
                }
            }
        }
        Ok(())
    }

    /// Answers the notification requests.
    pub(crate) fn handle_alerts(
        &mut self,
        request: &Request,
    ) -> Option<Result<Response, ErrorCode>> {
        Some(match request {
            Request::GetAlertStatus => Ok(Response::AlertStatus(self.alert_status())),
            Request::SetAlertConfig(u) => self.set_alert_config(u).map(|()| Response::Done),
            Request::GetWifiScan => {
                if self.alerts.probe_supported {
                    Ok(Response::WifiScan(self.alerts.scan.clone()))
                } else {
                    Err(ErrorCode::NotSupported)
                }
            }
            Request::RunRadioProbe => {
                if !self.alerts.probe_supported {
                    Err(ErrorCode::NotSupported)
                } else if self.alerts.config.ssid.is_empty() || self.alerts.restore_failed {
                    Err(ErrorCode::InvalidArgument)
                } else if self
                    .alerts
                    .probe_ended
                    .is_some_and(|t| self.now.as_millis() < t.saturating_add(MIN_ZIGBEE_MS))
                {
                    // Zigbee gets its mandatory period between outages.
                    Err(ErrorCode::Busy)
                } else {
                    self.alerts.probe_requested = true;
                    Ok(Response::Done)
                }
            }
            Request::QueueTestAlert => {
                if self.alerts.config.enabled {
                    self.queue_alert(AlertKind::Test, 0, None);
                    Ok(Response::Done)
                } else {
                    Err(ErrorCode::InvalidArgument)
                }
            }
            _ => return None,
        })
    }
}
