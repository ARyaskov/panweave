//! Watchdog supervision from evidence, not from silence.
//!
//! The firmware feeds the hardware watchdog once per main-loop turn, so a
//! loop that stops turning (a deadlock, an endless busy-wait) is reset by
//! the hardware — that is the watchdog's job (**A. loop health**). This
//! module decides, on top of that, whether the loop is turning around a
//! system that no longer makes progress, using two kinds of evidence:
//!
//! * **B. protocol stack progress**: after the stack was polled, its
//!   earliest deadline must not stay in the past. A deadline that remains
//!   overdue for [`STACK_OVERDUE_MS`] means scheduled work is not being
//!   processed.
//! * **C. radio driver health**: a transmission the driver *refused or
//!   never completed* (a fault) is evidence against the driver; a
//!   transmission that completed without an acknowledgement, or failed
//!   CCA, is evidence *for* it (the radio did its job; the channel or the
//!   peer did not), and so is any received frame. [`FAULT_THRESHOLD`]
//!   faults in a row with no completed transmission or reception for
//!   [`RADIO_FAULT_MS`] is a suspected driver stall.
//!
//! Silence is not evidence: a coordinator with no devices, only sleepy
//! children, or simply nothing to say transmits little or nothing, and
//! is [`Health::HealthyIdle`] for as long as it likes. Missing ACKs, CCA
//! failures and full queues make the system [`Health::Degraded`] and are
//! reported, never escalated.
//!
//! A suspected stall first triggers one **non-destructive recovery**
//! ([`Supervision::Recover`]: the firmware re-applies the radio
//! configuration and restarts reception with the driver's documented
//! calls). Only when the stall persists for [`CONFIRM_MS`] after that is
//! it confirmed and the loop asked to stop feeding the watchdog
//! ([`Supervision::Escalate`]); the chip resets and resumes its network
//! from flash — nothing is erased or re-formed. To rule out reset loops,
//! escalation is disabled for a boot that followed a watchdog reset
//! ([`HealthSupervisor::new`]): such a boot reports the confirmed stall
//! (Critical) and keeps running degraded.

/// A stack deadline overdue this long after polling is a stall.
pub const STACK_OVERDUE_MS: u64 = 10_000;
/// Transmission faults in a row (no completed transmission or reception
/// in between) before the radio is suspected.
pub const FAULT_THRESHOLD: u32 = 5;
/// …and for at least this long.
pub const RADIO_FAULT_MS: u64 = 30_000;
/// A suspected stall that persists this long after the recovery attempt
/// is confirmed.
pub const CONFIRM_MS: u64 = 60_000;
/// Activity within this period makes the system active rather than idle.
pub const ACTIVE_WINDOW_MS: u64 = 60_000;

/// What one loop turn observed (cumulative counters since boot).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Observation {
    /// Milliseconds since boot.
    pub now_ms: u64,
    /// Transmissions the radio completed (acknowledged, not acknowledged
    /// or CCA failure): the radio did its job.
    pub tx_completed: u32,
    /// Transmissions without an acknowledgement or with a CCA failure.
    pub tx_unacknowledged: u32,
    /// Transmissions the driver refused or never completed.
    pub tx_faults: u32,
    /// Frames received.
    pub rx_frames: u32,
    /// Frames refused for lack of queue space (MAC queue full, NWK
    /// pending table full).
    pub queue_full: u32,
    /// The stack's earliest deadline is still in the past after the
    /// stack was polled this turn.
    pub stack_overdue: bool,
}

/// The supervisor's view of the system.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    /// Nothing to do, nothing wrong.
    HealthyIdle,
    /// Recent radio activity, nothing wrong.
    HealthyActive,
    /// Working, with unacknowledged transmissions or full queues
    /// recently: reported, not escalated.
    Degraded,
    /// Evidence of a stall; a recovery attempt was made.
    SuspectedStall,
    /// The stall persisted after recovery.
    ConfirmedStall,
}

impl Health {
    /// The wire / trace code.
    pub const fn code(self) -> u8 {
        match self {
            Health::HealthyIdle => 0,
            Health::HealthyActive => 1,
            Health::Degraded => 2,
            Health::SuspectedStall => 3,
            Health::ConfirmedStall => 4,
        }
    }

    /// The value of a code (unknown codes read as idle).
    pub const fn from_code(c: u8) -> Self {
        match c {
            1 => Health::HealthyActive,
            2 => Health::Degraded,
            3 => Health::SuspectedStall,
            4 => Health::ConfirmedStall,
            _ => Health::HealthyIdle,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            Health::HealthyIdle => "healthy-idle",
            Health::HealthyActive => "healthy-active",
            Health::Degraded => "degraded",
            Health::SuspectedStall => "suspected-stall",
            Health::ConfirmedStall => "confirmed-stall",
        }
    }
}

/// Why a stall is suspected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StallCause {
    /// The radio driver refuses or never completes transmissions.
    RadioDriver,
    /// The stack's scheduled work is not being processed.
    StackProgress,
}

impl StallCause {
    /// The trace code.
    pub const fn code(self) -> u8 {
        match self {
            StallCause::RadioDriver => 1,
            StallCause::StackProgress => 2,
        }
    }
}

/// What the loop should do this turn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Supervision {
    /// Feed the watchdog.
    Feed,
    /// A stall is suspected: record it, attempt the safe recovery, feed.
    Recover(StallCause),
    /// The stall is confirmed: record it, then stop feeding (once; later
    /// turns return [`Supervision::Withhold`]).
    Escalate(StallCause),
    /// Keep not feeding: the watchdog resets the chip.
    Withhold,
    /// The stall is confirmed but escalation is disabled for this boot:
    /// record it, keep feeding, stay degraded.
    ConfirmedNoEscalation(StallCause),
}

/// The health supervisor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HealthSupervisor {
    escalation_allowed: bool,
    last: Observation,
    last_radio_progress_ms: u64,
    last_activity_ms: Option<u64>,
    last_degraded_ms: Option<u64>,
    faults_since_progress: u32,
    first_fault_ms: Option<u64>,
    overdue_since_ms: Option<u64>,
    suspected: Option<(StallCause, u64)>,
    confirmed: bool,
    escalated: bool,
    recoveries: u32,
}

impl HealthSupervisor {
    /// A supervisor starting at `now_ms`. `after_watchdog_reset`: this boot
    /// followed a watchdog reset — a confirmed stall is then reported but
    /// never escalated again, so a persistent failure cannot become a
    /// reset loop.
    pub const fn new(now_ms: u64, after_watchdog_reset: bool) -> Self {
        HealthSupervisor {
            escalation_allowed: !after_watchdog_reset,
            last: Observation {
                now_ms,
                tx_completed: 0,
                tx_unacknowledged: 0,
                tx_faults: 0,
                rx_frames: 0,
                queue_full: 0,
                stack_overdue: false,
            },
            last_radio_progress_ms: now_ms,
            last_activity_ms: None,
            last_degraded_ms: None,
            faults_since_progress: 0,
            first_fault_ms: None,
            overdue_since_ms: None,
            suspected: None,
            confirmed: false,
            escalated: false,
            recoveries: 0,
        }
    }

    /// Whether a confirmed stall may still end in a reset this boot.
    pub const fn escalation_allowed(&self) -> bool {
        self.escalation_allowed
    }

    /// Recovery attempts made this boot.
    pub const fn recoveries(&self) -> u32 {
        self.recoveries
    }

    /// Milliseconds since the radio last completed a transmission or
    /// received a frame.
    pub const fn radio_idle_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_radio_progress_ms)
    }

    /// The current health at `now_ms`.
    pub fn health(&self, now_ms: u64) -> Health {
        if self.confirmed {
            return Health::ConfirmedStall;
        }
        if self.suspected.is_some() {
            return Health::SuspectedStall;
        }
        let recent =
            |t: Option<u64>| t.is_some_and(|t| now_ms.saturating_sub(t) < ACTIVE_WINDOW_MS);
        if recent(self.last_degraded_ms) {
            Health::Degraded
        } else if recent(self.last_activity_ms) {
            Health::HealthyActive
        } else {
            Health::HealthyIdle
        }
    }

    /// One loop turn.
    pub fn observe(&mut self, o: Observation) -> Supervision {
        let now = o.now_ms;
        let radio_progress =
            o.tx_completed != self.last.tx_completed || o.rx_frames != self.last.rx_frames;
        if radio_progress {
            self.last_radio_progress_ms = now;
            self.last_activity_ms = Some(now);
            self.faults_since_progress = 0;
            self.first_fault_ms = None;
        }
        let new_faults = o.tx_faults.wrapping_sub(self.last.tx_faults);
        if new_faults > 0 && !radio_progress {
            self.faults_since_progress = self.faults_since_progress.saturating_add(new_faults);
            self.first_fault_ms.get_or_insert(now);
            self.last_activity_ms = Some(now);
        }
        if o.tx_unacknowledged != self.last.tx_unacknowledged
            || o.queue_full != self.last.queue_full
        {
            self.last_degraded_ms = Some(now);
        }
        if o.stack_overdue {
            self.overdue_since_ms.get_or_insert(now);
        } else {
            self.overdue_since_ms = None;
        }
        self.last = o;

        let cause = if self.faults_since_progress >= FAULT_THRESHOLD
            && self
                .first_fault_ms
                .is_some_and(|t| now.saturating_sub(t) >= RADIO_FAULT_MS)
        {
            Some(StallCause::RadioDriver)
        } else if self
            .overdue_since_ms
            .is_some_and(|t| now.saturating_sub(t) >= STACK_OVERDUE_MS)
        {
            Some(StallCause::StackProgress)
        } else {
            None
        };
        let Some(cause) = cause else {
            // The evidence went away: recovered.
            // (Progress after an escalation, before the reset, feeds
            // again too.)
            self.suspected = None;
            self.confirmed = false;
            self.escalated = false;
            return Supervision::Feed;
        };
        match self.suspected {
            None => {
                self.suspected = Some((cause, now));
                self.recoveries = self.recoveries.saturating_add(1);
                Supervision::Recover(cause)
            }
            Some((_, since)) if now.saturating_sub(since) < CONFIRM_MS => Supervision::Feed,
            Some(_) if self.escalated => Supervision::Withhold,
            Some(_) if self.confirmed => Supervision::Feed,
            Some(_) => {
                self.confirmed = true;
                if self.escalation_allowed {
                    self.escalated = true;
                    Supervision::Escalate(cause)
                } else {
                    Supervision::ConfirmedNoEscalation(cause)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simulated radio and stack, advanced in virtual time.
    struct World {
        sup: HealthSupervisor,
        o: Observation,
    }

    impl World {
        fn new(after_reset: bool) -> Self {
            World {
                sup: HealthSupervisor::new(0, after_reset),
                o: Observation::default(),
            }
        }

        /// Runs `ms` of loop turns, 100 ms apart, applying `turn` before
        /// each observation; returns every non-Feed decision.
        fn run(&mut self, ms: u64, mut turn: impl FnMut(&mut Observation)) -> Vec<Supervision> {
            let mut out = Vec::new();
            let end = self.o.now_ms + ms;
            while self.o.now_ms < end {
                self.o.now_ms += 100;
                turn(&mut self.o);
                let s = self.sup.observe(self.o);
                if s != Supervision::Feed {
                    out.push(s);
                }
            }
            out
        }
    }

    const HOUR: u64 = 3_600_000;

    #[test]
    fn a_new_network_with_no_devices_idles_for_an_hour() {
        let mut w = World::new(false);
        // No transmission at all (not even Link Status) for an hour.
        assert!(w.run(HOUR, |_| {}).is_empty());
        assert_eq!(w.sup.health(w.o.now_ms), Health::HealthyIdle);
        assert_eq!(w.sup.radio_idle_ms(w.o.now_ms), HOUR);
    }

    #[test]
    fn sleepy_children_and_occasional_traffic_stay_healthy() {
        let mut w = World::new(false);
        let mut t = 0u64;
        // A sensor reports every 10 minutes; ten minutes without any
        // completed transmission in between.
        let out = w.run(HOUR, |o| {
            t += 100;
            if t.is_multiple_of(600_000) {
                o.rx_frames += 1;
                o.tx_completed += 1;
            }
        });
        assert!(out.is_empty());
        assert!(matches!(
            w.sup.health(w.o.now_ms),
            Health::HealthyActive | Health::HealthyIdle
        ));
    }

    #[test]
    fn missing_acks_cca_failures_and_full_queues_degrade_without_escalation() {
        let mut w = World::new(false);
        let out = w.run(HOUR, |o| {
            // Every transmission completes without an acknowledgement or
            // fails CCA (interference, an absent peer), queues overflow.
            o.tx_completed += 1;
            o.tx_unacknowledged += 1;
            o.queue_full += 1;
        });
        assert!(out.is_empty());
        assert_eq!(w.sup.health(w.o.now_ms), Health::Degraded);
    }

    #[test]
    fn a_few_faults_and_temporary_interference_recover_by_themselves() {
        let mut w = World::new(false);
        let mut n = 0;
        let out = w.run(600_000, |o| {
            n += 1;
            // A burst of faults, then the radio works again.
            if n % 1000 < 4 {
                o.tx_faults += 1;
            } else if n % 100 == 0 {
                o.tx_completed += 1;
            }
        });
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn a_driver_that_never_completes_is_recovered_then_escalated_once() {
        let mut w = World::new(false);
        let out = w.run(RADIO_FAULT_MS + CONFIRM_MS + 10_000, |o| o.tx_faults += 1);
        assert_eq!(out[0], Supervision::Recover(StallCause::RadioDriver));
        assert_eq!(out[1], Supervision::Escalate(StallCause::RadioDriver));
        assert!(out[2..].iter().all(|s| *s == Supervision::Withhold));
        assert_eq!(w.sup.health(w.o.now_ms), Health::ConfirmedStall);
        assert_eq!(w.sup.recoveries(), 1);
    }

    #[test]
    fn the_recovery_can_fix_the_radio() {
        let mut w = World::new(false);
        let out = w.run(RADIO_FAULT_MS + 1_000, |o| o.tx_faults += 1);
        assert_eq!(out, vec![Supervision::Recover(StallCause::RadioDriver)]);
        // After the recovery the radio completes transmissions again.
        let out = w.run(CONFIRM_MS * 2, |o| o.tx_completed += 1);
        assert!(out.is_empty());
        assert_eq!(w.sup.health(w.o.now_ms), Health::HealthyActive);
    }

    #[test]
    fn stack_work_that_stays_overdue_is_a_stall() {
        let mut w = World::new(false);
        // Overdue for less than the limit: a long flash write, fine.
        assert!(w.run(5_000, |o| o.stack_overdue = true).is_empty());
        assert!(w.run(1_000, |o| o.stack_overdue = false).is_empty());
        let out = w.run(STACK_OVERDUE_MS + CONFIRM_MS + 1_000, |o| {
            o.stack_overdue = true;
        });
        assert_eq!(out[0], Supervision::Recover(StallCause::StackProgress));
        assert_eq!(out[1], Supervision::Escalate(StallCause::StackProgress));
    }

    #[test]
    fn after_a_watchdog_reset_a_confirmed_stall_does_not_reset_again() {
        let mut w = World::new(true);
        assert!(!w.sup.escalation_allowed());
        let out = w.run(HOUR, |o| o.tx_faults += 1);
        assert_eq!(
            out,
            vec![
                Supervision::Recover(StallCause::RadioDriver),
                Supervision::ConfirmedNoEscalation(StallCause::RadioDriver),
            ],
            "reported once, never a Withhold: no reset loop"
        );
        assert_eq!(w.sup.health(w.o.now_ms), Health::ConfirmedStall);
    }

    #[test]
    fn receptions_count_as_radio_progress() {
        let mut w = World::new(false);
        // Transmissions fault but frames keep arriving: the receiver
        // works, the driver is not dead (escalating would not help).
        let out = w.run(600_000, |o| {
            o.tx_faults += 1;
            if o.now_ms.is_multiple_of(10_000) {
                o.rx_frames += 1;
            }
        });
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn health_codes_round_trip() {
        for c in 0..=4 {
            assert_eq!(Health::from_code(c).code(), c);
        }
    }
}
