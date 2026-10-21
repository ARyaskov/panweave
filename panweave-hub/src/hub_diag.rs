//! The hub's diagnostics: the trace, the join timeline, frame capture,
//! and the diagnostic requests of the protocol.

use heapless::Vec;
use panweave_runtime::Stack;
use panweave_runtime::join_trace::{JoinRecord, JoinStage, decision};
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::CryptoRng;
use panweave_types::time::Instant;

#[cfg(feature = "radio-capture")]
use crate::capture::CaptureMode;
use crate::diag::{Category, DiagRecord, Severity, TraceConfig, code};
#[cfg(feature = "radio-capture")]
use crate::hub::CAPTURE_FRAMES;
use crate::hub::{DIAG_CAPACITY, EVENT_CAPACITY, Hub, MAX_COMMANDS, MAX_PENDING};
use crate::model::InterviewStatus;
use crate::protocol::{
    BootReport, ErrorCode, MAX_CAPTURE_PAGE, MAX_TRACE_PAGE, NetworkRestore, QueueUsage,
    RadioDiagnostics, Request, Response, RuntimeDiagnostics, StorageDiagnostics,
    TraceConfiguration, TracePage,
};
#[cfg(feature = "radio-capture")]
use crate::protocol::{CapturePage, MAX_CAPTURE_SECONDS};
use crate::registry::MAX_DEVICES;

fn ms32(t: Instant) -> u32 {
    u32::try_from(t.as_millis() & u64::from(u32::MAX)).unwrap_or(0)
}

fn sat16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

fn sat8(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

impl<HS: Storage> Hub<HS> {
    /// Records a diagnostic, stamped with the hub's clock. Filtered by the
    /// trace configuration before anything is stored.
    pub fn log(&mut self, record: DiagRecord) {
        let at = ms32(self.now);
        self.diag.record(record, at);
    }

    /// Whether a record of `category` / `severity` would be kept (to skip
    /// building costly records).
    pub fn trace_wants(&self, category: Category, severity: Severity) -> bool {
        self.diag.wants(category, severity)
    }

    /// The trace's configuration.
    pub fn trace_config(&self) -> TraceConfig {
        self.diag.config()
    }

    /// Records dropped from the trace.
    pub fn trace_dropped(&self) -> u32 {
        self.diag.dropped()
    }

    /// Sets the boot report the firmware assembled; fields the engine
    /// knows (registry, persistence) are completed when it is read.
    pub fn set_boot_report(&mut self, report: BootReport) {
        self.boot = report;
    }

    /// The boot report.
    pub fn boot_report(&self) -> &BootReport {
        &self.boot
    }

    /// Records what happened to the network at boot.
    pub fn set_network_restore(&mut self, outcome: NetworkRestore) {
        self.network_restore = Some(outcome);
        self.boot.network = Some(outcome);
        let (sev, c) = match outcome {
            NetworkRestore::Restored => (Severity::Info, code::NETWORK_RESTORED),
            NetworkRestore::Formed => (Severity::Info, code::NETWORK_FORMED),
            NetworkRestore::ReadFailed => (Severity::Critical, code::NETWORK_RESTORE_FAILED),
            NetworkRestore::CorruptNotFormed | NetworkRestore::StoredUnusable => {
                (Severity::Critical, code::NETWORK_NOT_FORMED)
            }
            NetworkRestore::NotAttempted => return,
        };
        self.log(DiagRecord::new(Category::Boot, sev, c).status(outcome.code()));
    }

    /// A page of the trace: up to `max` records (at most
    /// [`MAX_TRACE_PAGE`]) from sequence number `from`, optionally only
    /// those of device `ieee` (what [`Request::ReadTrace`] answers).
    pub fn read_trace(&self, from: u32, ieee: Option<u64>, max: usize) -> TracePage {
        let mut records: Vec<_, MAX_TRACE_PAGE> = Vec::new();
        let next = self.diag.read(from, ieee, max, &mut records);
        TracePage {
            uptime_ms: self.now.as_millis(),
            next,
            first_available: self.diag.first_seq(),
            dropped: self.diag.dropped(),
            records,
        }
    }

    /// Records, before the watchdog is let to reset the chip, why: the next
    /// boot reports it (`previous-stall-reset`). One small record in the
    /// registry storage, written only on a confirmed stall; returns
    /// whether it was written.
    pub fn record_stall_reset(&mut self, cause: crate::supervisor::StallCause) -> bool {
        if !self.config.persistent {
            return false;
        }
        let uptime = u32::try_from(self.now.as_millis() / 1000).unwrap_or(u32::MAX);
        let mut rec = [0u8; 6];
        rec[0] = 1;
        rec[1] = cause.code();
        rec[2..6].copy_from_slice(&uptime.to_le_bytes());
        self.storage
            .store(crate::persist::supervisor_key(), &rec)
            .is_ok()
    }

    /// Reports and erases the record of a supervisor-requested reset.
    pub(crate) fn take_previous_stall_reset(&mut self) {
        let mut buf = [0u8; 8];
        let Ok(Some(n)) = self
            .storage
            .load(crate::persist::supervisor_key(), &mut buf)
        else {
            return;
        };
        if n == 6 && buf[0] == 1 {
            let uptime = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
            self.log(
                DiagRecord::new(
                    Category::Watchdog,
                    Severity::Critical,
                    code::PREVIOUS_STALL_RESET,
                )
                .status(buf[1])
                .arg(uptime),
            );
        }
        let _ = self.storage.erase(crate::persist::supervisor_key());
    }

    /// Whether frames should be offered to [`Hub::capture_frame`]
    /// (always `false` without the `radio-capture` feature).
    pub fn capture_active(&self) -> bool {
        #[cfg(feature = "radio-capture")]
        return self.capture.is_active();
        #[cfg(not(feature = "radio-capture"))]
        false
    }

    /// Offers a radio frame to the capture (copied only while one runs).
    pub fn capture_frame(
        &mut self,
        now_ms: u64,
        channel: u8,
        frame: &[u8],
        flags: u8,
        rssi: Option<i8>,
        lqi: Option<u8>,
    ) {
        #[cfg(feature = "radio-capture")]
        self.capture.offer(now_ms, channel, frame, flags, rssi, lqi);
        #[cfg(not(feature = "radio-capture"))]
        let _ = (now_ms, channel, frame, flags, rssi, lqi);
    }

    /// Updates the high-water marks of the engine's queues.
    pub(crate) fn note_high_water(&mut self) {
        let now = [
            sat16(self.pending_events()),
            sat16(self.pending.len()),
            sat16(self.commands_len()),
        ];
        for (hw, n) in self.high_water.iter_mut().zip(now) {
            *hw = (*hw).max(n);
        }
    }

    /// Diagnostic housekeeping of a poll: join milestones, drops, the
    /// capture's time limit.
    pub(crate) fn poll_diagnostics<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
    ) {
        while let Some(r) = stack.next_join_record() {
            self.log_join(r);
        }
        let lost = stack.join_trace_dropped.wrapping_sub(self.join_drops_seen);
        if lost > 0 {
            self.join_drops_seen = stack.join_trace_dropped;
            self.log(
                DiagRecord::new(
                    Category::TrustCenter,
                    Severity::Warning,
                    code::JOIN_TRACE_LOST,
                )
                .arg(lost),
            );
        }
        let stack_drops = self.platform.stack_events_dropped;
        let new = stack_drops.wrapping_sub(self.stack_drops_seen);
        if new > 0 {
            self.stack_drops_seen = stack_drops;
            self.log(
                DiagRecord::new(
                    Category::Resources,
                    Severity::Warning,
                    code::STACK_EVENTS_DROPPED,
                )
                .arg(new),
            );
        }
        #[cfg(feature = "radio-capture")]
        if self.capture.poll(self.now.as_millis()) {
            self.log(
                DiagRecord::new(Category::System, Severity::Info, code::CAPTURE_STOPPED).status(1),
            );
        }
        self.note_high_water();
    }

    /// Logs a join milestone with the time since the device's previous
    /// one (`arg`, milliseconds; absent for the first one seen).
    fn log_join(&mut self, r: JoinRecord) {
        let ieee = r.device.0;
        let since = match self.join_last.iter_mut().find(|(d, _)| *d == ieee) {
            Some((_, t)) => {
                let d = r.at.saturating_duration_since(*t).as_millis();
                *t = r.at;
                Some(u32::try_from(d).unwrap_or(u32::MAX))
            }
            None => {
                if self.join_last.is_full() {
                    self.join_last.remove(0);
                }
                let _ = self.join_last.push((ieee, r.at));
                None
            }
        };
        let (c, severity) = match r.stage {
            JoinStage::AssociationRequest => (code::JOIN_ASSOCIATION_REQUEST, Severity::Info),
            JoinStage::ChildJoined => (code::JOIN_CHILD_JOINED, Severity::Info),
            JoinStage::UpdateDevice => (code::JOIN_UPDATE_DEVICE, Severity::Info),
            JoinStage::Decision if r.detail == decision::IGNORE || r.detail == decision::REMOVE => {
                (code::JOIN_DECISION, Severity::Warning)
            }
            JoinStage::Decision => (code::JOIN_DECISION, Severity::Info),
            JoinStage::KeyTransportSent => (code::JOIN_KEY_SENT, Severity::Info),
            JoinStage::KeyDelivered => (code::JOIN_KEY_DELIVERED, Severity::Info),
            JoinStage::KeyDeliveryFailed => (code::JOIN_KEY_FAILED, Severity::Error),
            JoinStage::TclkRequested if r.detail == 0 => {
                (code::JOIN_TCLK_REQUESTED, Severity::Warning)
            }
            JoinStage::TclkRequested => (code::JOIN_TCLK_REQUESTED, Severity::Info),
            JoinStage::TclkVerified => (code::JOIN_TCLK_VERIFIED, Severity::Info),
            JoinStage::KeyExchangePending => (code::JOIN_KEY_EXCHANGE_PENDING, Severity::Info),
            JoinStage::KeyExchangeTimedOut => (code::JOIN_KEY_EXCHANGE_TIMEOUT, Severity::Warning),
            JoinStage::Authorized if r.detail == 1 => (code::JOIN_AUTHORIZED, Severity::Warning),
            JoinStage::Authorized => (code::JOIN_AUTHORIZED, Severity::Info),
            JoinStage::ExemptionWithdrawn => (code::JOIN_EXEMPTION_WITHDRAWN, Severity::Warning),
        };
        let mut rec = DiagRecord::new(Category::TrustCenter, severity, c)
            .ieee(ieee)
            .status(r.detail);
        if let Some(s) = r.short {
            rec = rec.short(s.0);
        }
        if let Some(ms) = since {
            rec = rec.arg(ms);
        }
        let at = ms32(r.at);
        self.diag.record(rec, at);
    }

    fn queue(len: usize, capacity: usize, high_water: u16) -> QueueUsage {
        QueueUsage {
            len: sat16(len),
            capacity: sat16(capacity),
            high_water: high_water.max(sat16(len)),
        }
    }

    fn radio_diagnostics<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &Stack<C, R, S>,
    ) -> RadioDiagnostics {
        let mac = stack.mac.stats;
        let nwk = stack.nwk.stats;
        let aps = stack.aps.stats;
        let (pending, held) = stack.nwk.pending_tx();
        RadioDiagnostics {
            channel: stack.is_operating().then(|| stack.nwk.nib.channel.raw()),
            tx_power_dbm: self.platform.tx_power_dbm,
            energy_detection: self.platform.energy_detection,
            driver: self.platform.driver,
            mac_tx_ucast: mac.tx_ucast,
            mac_tx_ucast_retry: mac.tx_ucast_retry,
            mac_tx_ucast_fail: mac.tx_ucast_fail,
            mac_rx_ucast: mac.rx_ucast,
            mac_tx_bcast: mac.tx_bcast,
            mac_rx_bcast: mac.rx_bcast,
            mac_queue_full: mac.queue_limit_reached,
            nwk_malformed: nwk.malformed,
            nwk_security_failures: nwk.security_failures,
            nwk_replays: nwk.replays,
            nwk_no_route: nwk.no_route,
            nwk_pending_full: nwk.pending_full,
            nwk_pending_high_water: u8::try_from(nwk.pending_high_water).unwrap_or(u8::MAX),
            nwk_pending: sat8(pending),
            nwk_pending_held: sat8(held),
            nwk_pending_capacity: sat8(panweave_nwk::layer::PENDING_TX),
            aps_tx_success: aps.tx_ucast_success,
            aps_retries: aps.retries,
            aps_ack_failures: aps.ack_failures,
            aps_security_dropped: aps.security_dropped,
            aps_malformed: aps.malformed,
        }
    }

    fn storage_diagnostics(&self) -> StorageDiagnostics {
        StorageDiagnostics {
            registry_persistent: self.config.persistent,
            registry_devices: sat8(self.registry.len()),
            registry_writes: self.counters.storage_writes,
            registry_errors: self.counters.storage_errors,
            registry_full_errors: self.counters.storage_full,
            records_skipped: self.counters.records_skipped,
            last_error: self.counters.last_storage_error,
            network: self.network_restore,
            stack_store: self.platform.stack_store,
            hub_store: self.platform.hub_store,
        }
    }

    fn runtime_diagnostics<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &Stack<C, R, S>,
    ) -> RuntimeDiagnostics {
        let active = self.registry.iter().filter(|d| d.interview.busy).count();
        let stalled = self
            .registry
            .iter()
            .filter(|d| d.interview.status == InterviewStatus::Stalled)
            .count();
        RuntimeDiagnostics {
            uptime_ms: self.now.as_millis(),
            loop_iterations: self.platform.loop_iterations,
            loop_max_us: self.platform.loop_max_us,
            loop_overruns: self.platform.loop_overruns,
            radio_step_max_us: self.platform.radio_step_max_us,
            watchdog_s: self.platform.watchdog_s,
            hub_events: Self::queue(self.pending_events(), EVENT_CAPACITY, self.high_water[0]),
            pending: Self::queue(self.pending.len(), MAX_PENDING, self.high_water[1]),
            commands: Self::queue(self.commands_len(), MAX_COMMANDS, self.high_water[2]),
            trace: Self::queue(self.diag.len(), DIAG_CAPACITY, sat16(self.diag.len())),
            session_tx: QueueUsage::default(),
            #[cfg(feature = "radio-capture")]
            capture: Self::queue(self.capture.len(), CAPTURE_FRAMES, 0),
            #[cfg(not(feature = "radio-capture"))]
            capture: QueueUsage::default(),
            hub_events_dropped: self.counters.events_dropped,
            stack_events_dropped: self.platform.stack_events_dropped,
            trace_dropped: self.diag.dropped(),
            join_trace_dropped: stack.join_trace_dropped,
            #[cfg(feature = "radio-capture")]
            capture_dropped: self.capture.dropped(),
            #[cfg(not(feature = "radio-capture"))]
            capture_dropped: 0,
            usb_rx_bytes: self.platform.usb_rx_bytes,
            usb_tx_bytes: self.platform.usb_tx_bytes,
            usb_discards: 0,
            devices: sat8(self.registry.len()),
            max_devices: sat8(MAX_DEVICES),
            interviews_active: sat8(active),
            target: self.platform.target,
            interviews_stalled: sat8(stalled),
        }
    }

    fn trace_configuration(&self) -> TraceConfiguration {
        let c = self.diag.config();
        TraceConfiguration {
            min_severity: c.min_severity,
            categories: c.categories,
            capacity: sat16(DIAG_CAPACITY),
            stored: sat16(self.diag.len()),
            dropped: self.diag.dropped(),
            filtered: self.diag.filtered(),
        }
    }

    /// The diagnostic requests; `None` for the others.
    pub(crate) fn handle_diagnostics<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        request: &Request,
    ) -> Option<Result<Response, ErrorCode>> {
        Some(match request {
            Request::GetBootReport => {
                let mut b = self.boot.clone();
                b.ieee = stack.config.ieee.0;
                b.registry_persistent = self.config.persistent;
                b.network = self.network_restore;
                Ok(Response::BootReport(b))
            }
            Request::GetRadioDiagnostics => {
                Ok(Response::RadioDiagnostics(self.radio_diagnostics(stack)))
            }
            Request::GetStorageDiagnostics => {
                Ok(Response::StorageDiagnostics(self.storage_diagnostics()))
            }
            Request::GetRuntimeDiagnostics => Ok(Response::RuntimeDiagnostics(
                self.runtime_diagnostics(stack),
            )),
            Request::GetTraceConfiguration => {
                Ok(Response::TraceConfiguration(self.trace_configuration()))
            }
            Request::SetTraceConfiguration {
                min_severity,
                categories,
            } => match Severity::from_code(*min_severity) {
                None => Err(ErrorCode::InvalidArgument),
                Some(min_severity) => {
                    self.diag.configure(TraceConfig {
                        min_severity,
                        categories: *categories,
                    });
                    self.log(
                        DiagRecord::new(Category::System, Severity::Info, code::TRACE_CONFIGURED)
                            .status(min_severity.code())
                            .arg(*categories),
                    );
                    Ok(Response::TraceConfiguration(self.trace_configuration()))
                }
            },
            Request::ReadTrace { from, max, ieee } => {
                if *max == 0 || usize::from(*max) > MAX_TRACE_PAGE {
                    Err(ErrorCode::InvalidArgument)
                } else {
                    Ok(Response::TracePage(self.read_trace(
                        *from,
                        *ieee,
                        usize::from(*max),
                    )))
                }
            }
            Request::ClearTrace => {
                let n = self.diag.clear();
                self.log(
                    DiagRecord::new(Category::System, Severity::Info, code::TRACE_CLEARED)
                        .arg(u32::try_from(n).unwrap_or(u32::MAX)),
                );
                Ok(Response::Done)
            }
            Request::StartCapture { .. } | Request::StopCapture | Request::ReadCapture { .. } => {
                self.handle_capture(request)
            }
            _ => return None,
        })
    }
}

impl<HS: Storage> Hub<HS> {
    /// The capture requests of a firmware built without the
    /// `radio-capture` feature: `NotSupported` (arguments still
    /// validated), so one host build serves both firmware variants.
    #[cfg(not(feature = "radio-capture"))]
    // The same signature as the capture build's.
    #[allow(clippy::unused_self)]
    fn handle_capture(&mut self, request: &Request) -> Result<Response, ErrorCode> {
        match request {
            Request::ReadCapture { max } if *max == 0 || usize::from(*max) > MAX_CAPTURE_PAGE => {
                Err(ErrorCode::InvalidArgument)
            }
            _ => Err(ErrorCode::NotSupported),
        }
    }

    #[cfg(feature = "radio-capture")]
    fn handle_capture(&mut self, request: &Request) -> Result<Response, ErrorCode> {
        match request {
            Request::StartCapture { seconds, mode } => {
                if *seconds == 0 || *seconds > MAX_CAPTURE_SECONDS {
                    return Err(ErrorCode::InvalidArgument);
                }
                let until = self.now.as_millis() + u64::from(*seconds) * 1000;
                self.capture.start(until, *mode);
                let severity = if *mode == CaptureMode::Raw {
                    Severity::Warning
                } else {
                    Severity::Info
                };
                self.log(
                    DiagRecord::new(Category::System, severity, code::CAPTURE_STARTED)
                        .status(mode.code())
                        .arg(u32::from(*seconds)),
                );
                Ok(Response::Done)
            }
            Request::StopCapture => {
                if self.capture.is_active() {
                    self.capture.stop();
                    self.log(
                        DiagRecord::new(Category::System, Severity::Info, code::CAPTURE_STOPPED)
                            .status(0),
                    );
                }
                Ok(Response::Done)
            }
            Request::ReadCapture { max } => {
                if *max == 0 || usize::from(*max) > MAX_CAPTURE_PAGE {
                    return Err(ErrorCode::InvalidArgument);
                }
                let mut frames: Vec<_, MAX_CAPTURE_PAGE> = Vec::new();
                self.capture.take(usize::from(*max), &mut frames);
                let remaining = self
                    .capture
                    .until_ms()
                    .map_or(0, |t| t.saturating_sub(self.now.as_millis()).div_ceil(1000));
                Ok(Response::CapturePage(CapturePage {
                    active: self.capture.is_active(),
                    mode: self.capture.mode(),
                    remaining_s: u16::try_from(remaining).unwrap_or(u16::MAX),
                    dropped: self.capture.dropped(),
                    queued: sat16(self.capture.len()),
                    uptime_ms: self.now.as_millis(),
                    frames,
                }))
            }
            _ => Err(ErrorCode::UnknownRequest),
        }
    }
}
