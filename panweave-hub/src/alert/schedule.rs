//! When to attempt a delivery.
//!
//! * Pending events are delivered at the next periodic check (60 s by
//!   default, aligned to the monotonic clock). Empty intervals never
//!   start Wi-Fi. Later events cannot postpone an already scheduled check.
//! * After a failed attempt the next one waits for a bounded exponential
//!   backoff, Telegram's `retry_after` when it gave one, and in every
//!   case a mandatory period of Zigbee operation — whichever is latest.
//!   Back-to-back radio outages are impossible by construction.
//! * Leftover events and retries wait for a periodic check at or after
//!   the mandatory Zigbee period and any retry backoff.

/// Mandatory Zigbee operation between two attempts, milliseconds.
pub const MIN_ZIGBEE_MS: u64 = 30_000;
/// First retry backoff, milliseconds.
pub const BACKOFF_BASE_MS: u64 = 30_000;
/// Longest retry backoff, milliseconds.
pub const BACKOFF_MAX_MS: u64 = 15 * 60_000;
/// Longest `retry_after` honoured, milliseconds (a larger value is
/// clamped: a misbehaving answer cannot silence alarms for days).
pub const RETRY_AFTER_MAX_MS: u64 = 60 * 60_000;

fn at_or_after(now: u64, interval_ms: u64) -> u64 {
    let interval = interval_ms.max(1);
    let remainder = now % interval;
    if remainder == 0 {
        now
    } else {
        now.saturating_add(interval - remainder)
    }
}

fn next_check(now: u64, interval_ms: u64) -> u64 {
    let interval = interval_ms.max(1);
    now.saturating_add(interval - now % interval)
}

/// The delivery schedule.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Schedule {
    due: Option<u64>,
    not_before: u64,
    failures: u32,
}

impl Schedule {
    /// A new schedule: nothing due.
    pub const fn new() -> Self {
        Schedule {
            due: None,
            not_before: 0,
            failures: 0,
        }
    }

    /// When the next attempt is due (monotonic ms), if one is scheduled.
    pub const fn due(&self) -> Option<u64> {
        self.due
    }

    /// Consecutive failed attempts.
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    /// Whether an attempt is due at `now`.
    pub fn is_due(&self, now: u64) -> bool {
        self.due.is_some_and(|d| now >= d)
    }

    /// An event was queued: schedule the next check, never postponing it.
    pub fn on_event(&mut self, now: u64, interval_ms: u64) {
        if self.due.is_none() {
            self.due = Some(at_or_after(
                next_check(now, interval_ms).max(self.not_before),
                interval_ms,
            ));
        }
    }

    /// Events survived a reboot: send at the next check of the new clock.
    pub fn on_boot(&mut self, now: u64, pending: bool, interval_ms: u64) {
        self.due = pending.then(|| next_check(now, interval_ms));
    }

    /// The attempt that ended at `now` delivered. `oldest_pending` is the
    /// arrival of the oldest event still pending, if any. Its clock may
    /// belong to an earlier boot, so only its presence matters here.
    pub fn on_success(&mut self, now: u64, oldest_pending: Option<u64>, interval_ms: u64) {
        self.failures = 0;
        self.not_before = now.saturating_add(MIN_ZIGBEE_MS);
        self.due = oldest_pending.map(|_| {
            at_or_after(
                next_check(now, interval_ms).max(self.not_before),
                interval_ms,
            )
        });
    }

    /// The attempt that ended at `now` failed; `retry_after_s` is
    /// Telegram's answer to a rate limit.
    pub fn on_failure(&mut self, now: u64, retry_after_s: Option<u32>, interval_ms: u64) {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(16);
        let backoff = BACKOFF_BASE_MS
            .saturating_mul(1u64 << shift)
            .min(BACKOFF_MAX_MS);
        let retry_after =
            retry_after_s.map_or(0, |s| (u64::from(s) * 1000).min(RETRY_AFTER_MAX_MS));
        self.not_before = now.saturating_add(MIN_ZIGBEE_MS);
        self.due = Some(at_or_after(
            now.saturating_add(backoff)
                .max(now.saturating_add(retry_after))
                .max(self.not_before),
            interval_ms,
        ));
    }

    /// Nothing is pending any more (queue emptied by other means).
    pub fn clear(&mut self) {
        self.due = None;
    }

    /// Milliseconds until the next attempt.
    pub fn remaining(&self, now: u64) -> Option<u64> {
        self.due.map(|d| d.saturating_sub(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DELAY: u64 = 60_000;

    #[test]
    fn events_share_the_next_minute_check_without_postponement() {
        let mut s = Schedule::new();
        assert!(!s.is_due(0));
        s.on_event(1_000, DELAY);
        assert_eq!(s.due(), Some(60_000));
        // A new event every second for a minute.
        for t in (2_000..62_000).step_by(1_000) {
            s.on_event(t, DELAY);
            assert_eq!(s.due(), Some(60_000), "postponed at {t}");
        }
        assert!(!s.is_due(59_999));
        assert!(s.is_due(60_000));
    }

    #[test]
    fn failures_back_off_boundedly_and_always_leave_zigbee_time() {
        let mut s = Schedule::new();
        s.on_event(0, DELAY);
        let mut now = 60_000;
        let mut gaps = Vec::new();
        for _ in 0..12 {
            s.on_failure(now, None, DELAY);
            let due = s.due().unwrap();
            assert!(due >= now + MIN_ZIGBEE_MS);
            gaps.push(due - now);
            now = due;
        }
        assert_eq!(gaps[0], 60_000);
        assert_eq!(gaps[1], 60_000);
        assert_eq!(gaps[2], 120_000);
        assert!(gaps.iter().all(|g| *g <= BACKOFF_MAX_MS));
        assert_eq!(*gaps.last().unwrap(), BACKOFF_MAX_MS);
        assert_eq!(s.failures(), 12);
    }

    #[test]
    fn retry_after_is_honoured_clamped_and_never_shortens_the_zigbee_period() {
        let mut s = Schedule::new();
        s.on_failure(10_000, Some(120), DELAY);
        assert_eq!(s.due(), Some(180_000));
        // A tiny retry_after still leaves the mandatory Zigbee period.
        let mut s = Schedule::new();
        s.on_failure(10_000, Some(1), DELAY);
        assert_eq!(s.due(), Some(60_000));
        // An absurd one is clamped.
        let mut s = Schedule::new();
        s.on_failure(0, Some(u32::MAX), DELAY);
        assert_eq!(s.due(), Some(RETRY_AFTER_MAX_MS));
    }

    #[test]
    fn leftovers_wait_for_the_next_check_and_the_zigbee_period() {
        let mut s = Schedule::new();
        s.on_event(0, DELAY);
        s.on_failure(50_000, None, DELAY);
        assert_eq!(s.failures(), 1);
        // Delivered at 82 s; an event from 81 s remains.
        s.on_success(82_000, Some(81_000), DELAY);
        assert_eq!(s.failures(), 0);
        assert_eq!(s.due(), Some(120_000));
        // An event older than the delay is still held for the Zigbee period.
        s.on_success(200_000, Some(100_000), DELAY);
        assert_eq!(s.due(), Some(240_000));
        // A new event right after a success.
        s.on_success(300_000, None, DELAY);
        assert_eq!(s.due(), None);
        s.on_event(300_001, 1_000);
        assert_eq!(s.due(), Some(300_000 + MIN_ZIGBEE_MS));
    }

    #[test]
    fn events_from_a_previous_boot_are_due_at_the_next_check() {
        let mut s = Schedule::new();
        s.on_boot(500, true, DELAY);
        assert_eq!(s.due(), Some(60_000));
        s.on_boot(500, false, DELAY);
        assert_eq!(s.due(), None);
    }

    #[test]
    fn empty_minutes_never_start_wifi_and_late_events_use_the_imminent_check() {
        let mut s = Schedule::new();
        for now in [60_000, 120_000, 180_000] {
            assert!(!s.is_due(now));
        }
        s.on_event(239_999, DELAY);
        assert_eq!(s.due(), Some(240_000));
        s.on_success(241_000, None, DELAY);
        assert!(!s.is_due(300_000));
        s.on_event(300_000, DELAY);
        assert_eq!(s.due(), Some(360_000));
    }
}
