//! Smart Energy commissioning life-cycle (SE 1.4a §5.5.5): the joining,
//! service discovery, steady-state and rejoin-and-recovery rules as a
//! pure state machine. The application (or runtime) feeds it [`Event`]s
//! and performs the [`Action`]s it returns; time is the caller's and
//! random jitter is drawn through a closure so the schedule stays
//! testable.
//!
//! What is encoded:
//! * PAN auto-joining (§5.5.5.1): the scan schedule (at once, then once
//!   a minute for fifteen minutes ± 15 s, then hourly ± 30 min), joining
//!   only PANs that permit it with the install-code key, backing out of
//!   a PAN whose network key cannot be decrypted (at most three tries in
//!   succession on one PAN, never more than ten joins without a new
//!   scan), Key Establishment after the network key with at most ten
//!   failures in succession before a fifteen-minute pause and without
//!   leaving the PAN, and the leave rules of steps 7–8.
//! * Service discovery (§5.5.5.2): MDU Pairing first when supported,
//!   bindings to every matching ESI regardless of individual refusals,
//!   rediscovery every 3–24 hours, after recovery, and 60–600 s after a
//!   device announce.
//! * Steady state (§5.5.5.3): a failing keep-alive exchange leads to
//!   recovery after at most 24 hours of failures.
//! * Rejoin and recovery (§5.5.5.4): rejoin on the current channel
//!   (Trust Center rejoin, optionally a secure rejoin first, up to three
//!   rounds), then the other channels by extended PAN ID, back to the
//!   original channel between attempts, attempts at least daily and, after
//!   four failures, no faster than hourly ± 30 min; an APS-secured message
//!   from the Trust Center ends recovery.

use panweave_types::time::{Duration, Instant};

/// Retries of a join on the same PAN in succession (§5.5.5.1 step 4).
pub const SAME_PAN_JOIN_LIMIT: u8 = 3;
/// Joins without a fresh scan (§5.5.5.1 step 4).
pub const JOINS_BEFORE_RESCAN: u8 = 10;
/// Key Establishment failures in succession before a pause (step 6).
pub const KEY_ESTABLISHMENT_BURST: u8 = 10;
/// The pause after a burst of Key Establishment failures.
pub const KEY_ESTABLISHMENT_PAUSE: Duration = Duration::from_mins(15);
/// Shortest rediscovery period (§5.5.5.2 item 6a).
pub const REDISCOVERY_MIN: Duration = Duration::from_mins(3 * 60);
/// Longest rediscovery period.
pub const REDISCOVERY_MAX: Duration = Duration::from_mins(24 * 60);
/// Failing keep-alive exchanges lead to recovery within this time
/// (§5.5.5.3 item 3).
pub const STEADY_FAILURE_LIMIT: Duration = Duration::from_mins(24 * 60);
/// Rejoin rounds on one channel (§5.5.5.4 item 3).
pub const REJOIN_ROUNDS: u8 = 3;
/// Recovery attempts at least this often (§5.5.5.4 item 10).
pub const RECOVERY_PERIOD_MAX: Duration = Duration::from_mins(24 * 60);
/// Failed recovery attempts before slowing to hourly.
pub const RECOVERY_SLOW_AFTER: u8 = 4;
/// Time after a join without Key Establishment before a Trust Center
/// may remove the device (§5.5.5.5 item 6).
pub const TRUST_CENTER_REMOVAL_AFTER: Duration = Duration::from_mins(60);
/// Bindings an ESI supports at minimum: five devices on every cluster
/// (§5.5.5.5 item 2).
pub const ESI_MIN_DEVICES: usize = 5;

/// Auto-join scan schedule (§5.5.5.1 step 1): the delay before scan
/// number `attempt` (0 = the first). `random(n)` yields a value in
/// `0..n` used for the jitter.
pub fn scan_delay(attempt: u32, mut random: impl FnMut(u32) -> u32) -> Duration {
    if attempt == 0 {
        return Duration::from_millis(0);
    }
    if attempt <= 15 {
        // Once a minute for fifteen minutes, ± 15 s.
        let jitter = i64::from(random(30_001)) - 15_000;
        return Duration::from_millis((60_000 + jitter).max(0).unsigned_abs());
    }
    // Hourly, ± 30 minutes.
    let jitter = i64::from(random(3_600_001)) - 1_800_000;
    Duration::from_millis((3_600_000 + jitter).max(0).unsigned_abs())
}

/// Recovery attempt spacing (§5.5.5.4 item 10): `failures` completed
/// attempts so far. Before the fifth attempt the caller's own period
/// applies (bounded by [`RECOVERY_PERIOD_MAX`]); from then on hourly
/// ± 30 min.
pub fn recovery_delay(
    failures: u8,
    period: Duration,
    mut random: impl FnMut(u32) -> u32,
) -> Duration {
    if failures < RECOVERY_SLOW_AFTER {
        return Duration::from_millis(period.as_millis().min(RECOVERY_PERIOD_MAX.as_millis()));
    }
    let jitter = i64::from(random(3_600_001)) - 1_800_000;
    Duration::from_millis((3_600_000 + jitter).max(0).unsigned_abs())
}

/// Delay before rediscovering the services of a device that announced
/// itself (§5.5.5.2 item 6c): 60–600 s.
pub fn announce_rediscovery_delay(mut random: impl FnMut(u32) -> u32) -> Duration {
    Duration::from_millis(60_000 + u64::from(random(540_001)))
}

/// Where a leave instruction came from (§5.5.5.1 step 7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LeaveSource {
    /// An APS-encrypted APS Remove Device command.
    ApsRemoveDevice,
    /// A NWK Leave command from the device's parent.
    NwkLeaveFromParent,
    /// A NWK Leave command from any other device.
    NwkLeaveOther,
    /// The device's own user interface.
    User,
}

/// Whether a leave instruction is followed (§5.5.5.1 step 7; §5.5.5.5
/// item 6 for a child without an authorized key).
pub const fn follow_leave(source: LeaveSource, is_end_device: bool, key_authorized: bool) -> bool {
    match source {
        LeaveSource::ApsRemoveDevice | LeaveSource::User => true,
        LeaveSource::NwkLeaveFromParent => is_end_device || !key_authorized,
        LeaveSource::NwkLeaveOther => false,
    }
}

/// Whether a Trust Center may remove a device that joined at `joined`
/// and never completed Key Establishment (§5.5.5.5 item 6).
pub fn trust_center_may_remove(joined: Instant, now: Instant) -> bool {
    now.saturating_duration_since(joined).as_millis() > TRUST_CENTER_REMOVAL_AFTER.as_millis()
}

/// The life-cycle phases (§5.5.5.1–§5.5.5.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Phase {
    /// Un-commissioned, scanning and joining.
    AutoJoining,
    /// On the PAN with the network key, establishing the link key.
    KeyEstablishment,
    /// Discovering services and binding.
    ServiceDiscovery,
    /// Normal operation.
    Steady,
    /// Trying to get back in sync with the PAN.
    RejoinRecovery,
}

/// What happened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event {
    /// Auto-joining was initiated (power-up with startup control 2, or
    /// the user).
    Start,
    /// A scan finished: `joinable` PANs permit joining.
    ScanDone {
        /// PANs heard with the permit-joining bit set.
        joinable: u8,
    },
    /// The join succeeded and the network key was decrypted.
    JoinedWithKey,
    /// The join succeeded but the network key could not be decrypted
    /// (wrong PAN), or the join failed.
    JoinFailed,
    /// The Key Establishment server was found and CBKE finished.
    KeyEstablished,
    /// Key Establishment failed.
    KeyEstablishmentFailed,
    /// Service discovery and binding completed.
    DiscoveryDone,
    /// A periodic exchange with the Trust Center succeeded.
    KeepAliveOk,
    /// A periodic exchange with the Trust Center failed.
    KeepAliveFailed,
    /// A rejoin (secure or Trust Center) on the current channel
    /// succeeded.
    RejoinSucceeded,
    /// A rejoin on the current channel failed.
    RejoinFailed,
    /// The channel scan found the extended PAN on another channel.
    PanFoundOnOtherChannel,
    /// The channel scan found nothing.
    PanNotFound,
    /// An APS-secured message from the Trust Center under the current
    /// keys arrived.
    TrustCenterMessage,
    /// A leave instruction.
    Leave(LeaveSource),
}

/// What the application does next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Action {
    /// Scan the startup-set channels after `delay`.
    Scan {
        /// Delay before the scan.
        delay: Duration,
    },
    /// Join the next joinable PAN (or the same one again) with the
    /// install-code key.
    JoinNext,
    /// Find the Key Establishment server and run CBKE after `delay`.
    KeyEstablishment {
        /// Delay before starting.
        delay: Duration,
    },
    /// Discover services (MDU Pairing first when supported) and bind.
    DiscoverServices,
    /// Operate normally; the next rediscovery is due after `rediscover`.
    Steady {
        /// Rediscovery period.
        rediscover: Duration,
    },
    /// Keep operating; note the failure.
    Continue,
    /// Attempt a Trust Center rejoin (after an optional secure rejoin)
    /// on the current channel.
    Rejoin,
    /// Scan the other channels for the extended PAN ID.
    ScanForPan,
    /// Return to the original channel and wait `delay` before the next
    /// recovery attempt.
    WaitOnOriginalChannel {
        /// Delay before the next attempt.
        delay: Duration,
    },
    /// Leave: discard network settings and the link key, revert to the
    /// install code and await user input (or auto-join again).
    LeaveAndReset,
    /// Ignore the instruction.
    Ignore,
}

/// The commissioning state machine.
#[derive(Clone, Copy, Debug)]
pub struct Lifecycle {
    phase: Phase,
    scans: u32,
    joins_since_scan: u8,
    same_pan_joins: u8,
    ke_failures: u8,
    /// Keep-alive failures started here.
    failing_since: Option<Instant>,
    rejoin_rounds: u8,
    recovery_failures: u8,
    /// Whether the last recovery attempt already scanned other channels.
    scanned: bool,
    /// The caller's recovery period.
    recovery_period: Duration,
    /// The caller's rediscovery period.
    rediscovery: Duration,
    /// End devices follow a parent's NWK leave.
    is_end_device: bool,
}

impl Lifecycle {
    /// A device with the given rediscovery and recovery periods
    /// (clamped to the §5.5.5 bounds).
    pub const fn new(rediscovery: Duration, recovery_period: Duration) -> Self {
        let r = rediscovery.as_millis();
        let r = if r < REDISCOVERY_MIN.as_millis() {
            REDISCOVERY_MIN.as_millis()
        } else if r > REDISCOVERY_MAX.as_millis() {
            REDISCOVERY_MAX.as_millis()
        } else {
            r
        };
        let p = recovery_period.as_millis();
        let p = if p > RECOVERY_PERIOD_MAX.as_millis() {
            RECOVERY_PERIOD_MAX.as_millis()
        } else {
            p
        };
        Lifecycle {
            phase: Phase::AutoJoining,
            scans: 0,
            joins_since_scan: 0,
            same_pan_joins: 0,
            ke_failures: 0,
            failing_since: None,
            rejoin_rounds: 0,
            recovery_failures: 0,
            scanned: false,
            recovery_period: Duration::from_millis(p),
            rediscovery: Duration::from_millis(r),
            is_end_device: false,
        }
    }

    /// The current phase.
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Feeds an event at `now`; `random(n)` yields `0..n` for jitter.
    pub fn on_event(
        &mut self,
        event: Event,
        now: Instant,
        mut random: impl FnMut(u32) -> u32,
    ) -> Action {
        if let Event::Leave(source) = event {
            // Step 7: only an APS-secured Remove Device, the user, or a
            // parent's NWK leave to an end device (or an unauthenticated
            // child) is followed.
            let authorized = !matches!(self.phase, Phase::AutoJoining | Phase::KeyEstablishment);
            return if follow_leave(source, self.is_end_device, authorized) {
                let end_device = self.is_end_device;
                *self = Lifecycle::new(self.rediscovery, self.recovery_period);
                self.is_end_device = end_device;
                Action::LeaveAndReset
            } else {
                Action::Ignore
            };
        }
        match self.phase {
            Phase::AutoJoining => self.auto_joining(event, &mut random),
            Phase::KeyEstablishment => self.key_establishment(event),
            Phase::ServiceDiscovery => match event {
                Event::DiscoveryDone => {
                    self.phase = Phase::Steady;
                    self.failing_since = None;
                    Action::Steady {
                        rediscover: self.rediscovery,
                    }
                }
                _ => Action::Continue,
            },
            Phase::Steady => self.steady(event, now),
            Phase::RejoinRecovery => self.recovery(event, &mut random),
        }
    }

    fn auto_joining(&mut self, event: Event, random: &mut impl FnMut(u32) -> u32) -> Action {
        match event {
            Event::Start => {
                self.scans = 0;
                self.joins_since_scan = 0;
                self.same_pan_joins = 0;
                Action::Scan {
                    delay: Duration::from_millis(0),
                }
            }
            Event::ScanDone { joinable } => {
                self.joins_since_scan = 0;
                self.same_pan_joins = 0;
                if joinable == 0 {
                    self.scans = self.scans.saturating_add(1);
                    Action::Scan {
                        delay: scan_delay(self.scans, random),
                    }
                } else {
                    Action::JoinNext
                }
            }
            Event::JoinedWithKey => {
                self.phase = Phase::KeyEstablishment;
                self.ke_failures = 0;
                Action::KeyEstablishment {
                    delay: Duration::from_millis(0),
                }
            }
            Event::JoinFailed => {
                self.joins_since_scan = self.joins_since_scan.saturating_add(1);
                self.same_pan_joins = self.same_pan_joins.saturating_add(1);
                if self.joins_since_scan >= JOINS_BEFORE_RESCAN {
                    // Step 4: never more than ten joins without scanning.
                    self.scans = self.scans.saturating_add(1);
                    Action::Scan {
                        delay: scan_delay(self.scans, random),
                    }
                } else {
                    Action::JoinNext
                }
            }
            _ => Action::Continue,
        }
    }

    /// Whether the same PAN may be retried once more (at most three
    /// tries in succession, step 4).
    pub const fn may_retry_same_pan(&self) -> bool {
        self.same_pan_joins < SAME_PAN_JOIN_LIMIT
    }

    fn key_establishment(&mut self, event: Event) -> Action {
        match event {
            Event::KeyEstablished => {
                self.phase = Phase::ServiceDiscovery;
                self.ke_failures = 0;
                Action::DiscoverServices
            }
            Event::KeyEstablishmentFailed => {
                // Step 6: stay on the PAN; pause after ten failures.
                self.ke_failures = self.ke_failures.saturating_add(1);
                if self.ke_failures >= KEY_ESTABLISHMENT_BURST {
                    self.ke_failures = 0;
                    Action::KeyEstablishment {
                        delay: KEY_ESTABLISHMENT_PAUSE,
                    }
                } else {
                    Action::KeyEstablishment {
                        delay: Duration::from_millis(0),
                    }
                }
            }
            _ => Action::Continue,
        }
    }

    fn steady(&mut self, event: Event, now: Instant) -> Action {
        match event {
            Event::KeepAliveOk | Event::TrustCenterMessage => {
                self.failing_since = None;
                Action::Continue
            }
            Event::KeepAliveFailed => {
                let since = *self.failing_since.get_or_insert(now);
                if now.saturating_duration_since(since).as_millis()
                    >= STEADY_FAILURE_LIMIT.as_millis()
                {
                    self.enter_recovery()
                } else {
                    Action::Continue
                }
            }
            _ => Action::Continue,
        }
    }

    /// Enters rejoin and recovery at once (the implementation may do so
    /// before the 24-hour limit, §5.5.5.3 item 3).
    pub fn enter_recovery(&mut self) -> Action {
        self.phase = Phase::RejoinRecovery;
        self.rejoin_rounds = 0;
        self.scanned = false;
        self.failing_since = None;
        Action::Rejoin
    }

    fn recovery(&mut self, event: Event, random: &mut impl FnMut(u32) -> u32) -> Action {
        match event {
            Event::RejoinSucceeded | Event::TrustCenterMessage => {
                // Item 9 / §5.5.5.2 item 6b: back to steady state via a
                // fresh discovery.
                self.phase = Phase::ServiceDiscovery;
                self.recovery_failures = 0;
                Action::DiscoverServices
            }
            Event::RejoinFailed => {
                self.rejoin_rounds = self.rejoin_rounds.saturating_add(1);
                if self.rejoin_rounds < REJOIN_ROUNDS {
                    Action::Rejoin
                } else if !self.scanned {
                    self.scanned = true;
                    Action::ScanForPan
                } else {
                    // Rejoin on the found channel failed too: keep
                    // scanning the remaining channels (item 6).
                    Action::ScanForPan
                }
            }
            Event::PanFoundOnOtherChannel => {
                self.rejoin_rounds = 0;
                Action::Rejoin
            }
            Event::PanNotFound => {
                self.recovery_failures = self.recovery_failures.saturating_add(1);
                self.rejoin_rounds = 0;
                self.scanned = false;
                Action::WaitOnOriginalChannel {
                    delay: recovery_delay(self.recovery_failures, self.recovery_period, random),
                }
            }
            Event::Start => Action::Rejoin,
            _ => Action::Continue,
        }
    }
}

impl Lifecycle {
    /// Marks the device as an end device (a parent's NWK leave is then
    /// followed, step 7).
    pub const fn end_device(mut self) -> Self {
        self.is_end_device = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> Instant {
        Instant::from_millis(secs * 1000)
    }

    #[test]
    fn scan_schedule_follows_5_5_5_1() {
        assert_eq!(scan_delay(0, |_| 0).as_millis(), 0);
        assert_eq!(scan_delay(1, |_| 0).as_millis(), 45_000);
        assert_eq!(scan_delay(15, |n| n - 1).as_millis(), 75_000);
        assert_eq!(scan_delay(16, |_| 0).as_millis(), 1_800_000);
        assert_eq!(scan_delay(40, |n| n - 1).as_millis(), 5_400_000);
        assert_eq!(
            recovery_delay(0, Duration::from_mins(10), |_| 0).as_millis(),
            600_000
        );
        assert_eq!(
            recovery_delay(1, Duration::from_mins(48 * 60), |_| 0).as_millis(),
            RECOVERY_PERIOD_MAX.as_millis()
        );
        assert_eq!(
            recovery_delay(4, Duration::from_mins(10), |_| 1_800_000).as_millis(),
            3_600_000
        );
        assert_eq!(announce_rediscovery_delay(|_| 0).as_millis(), 60_000);
        assert_eq!(announce_rediscovery_delay(|n| n - 1).as_millis(), 600_000);
        assert!(follow_leave(LeaveSource::ApsRemoveDevice, false, true));
        assert!(!follow_leave(LeaveSource::NwkLeaveFromParent, false, true));
        assert!(follow_leave(LeaveSource::NwkLeaveFromParent, true, true));
        assert!(follow_leave(LeaveSource::NwkLeaveFromParent, false, false));
        assert!(!follow_leave(LeaveSource::NwkLeaveOther, true, false));
        assert!(!trust_center_may_remove(at(0), at(3600)));
        assert!(trust_center_may_remove(at(0), at(3601)));
    }

    #[test]
    fn joining_backs_out_and_paces_key_establishment() {
        let mut l = Lifecycle::new(Duration::from_mins(60), Duration::from_mins(60));
        // Rediscovery clamped to the three-hour minimum.
        assert_eq!(l.rediscovery, REDISCOVERY_MIN);
        let r = |_| 0u32;
        assert_eq!(
            l.on_event(Event::Start, at(0), r),
            Action::Scan {
                delay: Duration::from_millis(0)
            }
        );
        assert_eq!(
            l.on_event(Event::ScanDone { joinable: 0 }, at(1), r),
            Action::Scan {
                delay: Duration::from_millis(45_000)
            }
        );
        assert_eq!(
            l.on_event(Event::ScanDone { joinable: 2 }, at(50), r),
            Action::JoinNext
        );
        // Wrong PAN: back out and try the next; ten joins force a rescan.
        for i in 1..JOINS_BEFORE_RESCAN {
            assert_eq!(
                l.on_event(Event::JoinFailed, at(60), r),
                Action::JoinNext,
                "join {i}"
            );
            assert_eq!(l.may_retry_same_pan(), i < SAME_PAN_JOIN_LIMIT);
        }
        assert!(matches!(
            l.on_event(Event::JoinFailed, at(60), r),
            Action::Scan { .. }
        ));
        assert_eq!(
            l.on_event(Event::ScanDone { joinable: 1 }, at(120), r),
            Action::JoinNext
        );
        assert_eq!(
            l.on_event(Event::JoinedWithKey, at(130), r),
            Action::KeyEstablishment {
                delay: Duration::from_millis(0)
            }
        );
        assert_eq!(l.phase(), Phase::KeyEstablishment);
        // Nine failures retry at once, the tenth pauses fifteen minutes;
        // the device never leaves.
        for _ in 0..(KEY_ESTABLISHMENT_BURST - 1) {
            assert_eq!(
                l.on_event(Event::KeyEstablishmentFailed, at(140), r),
                Action::KeyEstablishment {
                    delay: Duration::from_millis(0)
                }
            );
        }
        assert_eq!(
            l.on_event(Event::KeyEstablishmentFailed, at(140), r),
            Action::KeyEstablishment {
                delay: KEY_ESTABLISHMENT_PAUSE
            }
        );
        assert_eq!(l.phase(), Phase::KeyEstablishment);
        // A NWK leave from a stranger is ignored; from the parent it is
        // followed while unauthenticated.
        assert_eq!(
            l.on_event(Event::Leave(LeaveSource::NwkLeaveOther), at(150), r),
            Action::Ignore
        );
        assert_eq!(
            l.on_event(Event::Leave(LeaveSource::NwkLeaveFromParent), at(150), r),
            Action::LeaveAndReset
        );
        assert_eq!(l.phase(), Phase::AutoJoining);
    }

    #[test]
    fn steady_state_recovers_and_returns() {
        let mut l = Lifecycle::new(Duration::from_mins(12 * 60), Duration::from_mins(60));
        let r = |_| 0u32;
        l.on_event(Event::Start, at(0), r);
        l.on_event(Event::ScanDone { joinable: 1 }, at(1), r);
        l.on_event(Event::JoinedWithKey, at(2), r);
        assert_eq!(
            l.on_event(Event::KeyEstablished, at(3), r),
            Action::DiscoverServices
        );
        assert_eq!(
            l.on_event(Event::DiscoveryDone, at(4), r),
            Action::Steady {
                rediscover: Duration::from_mins(12 * 60)
            }
        );
        // Once authenticated, a parent's NWK leave is ignored by a router.
        assert_eq!(
            l.on_event(Event::Leave(LeaveSource::NwkLeaveFromParent), at(5), r),
            Action::Ignore
        );
        // Keep-alive failures: recovery after 24 hours of them.
        assert_eq!(
            l.on_event(Event::KeepAliveFailed, at(10), r),
            Action::Continue
        );
        assert_eq!(l.on_event(Event::KeepAliveOk, at(20), r), Action::Continue);
        assert_eq!(
            l.on_event(Event::KeepAliveFailed, at(100), r),
            Action::Continue
        );
        assert_eq!(
            l.on_event(Event::KeepAliveFailed, at(100 + 86_399), r),
            Action::Continue
        );
        assert_eq!(
            l.on_event(Event::KeepAliveFailed, at(100 + 86_400), r),
            Action::Rejoin
        );
        assert_eq!(l.phase(), Phase::RejoinRecovery);
        // Three rejoin rounds on the channel, then a scan; nothing
        // found: wait on the original channel.
        assert_eq!(l.on_event(Event::RejoinFailed, at(200), r), Action::Rejoin);
        assert_eq!(l.on_event(Event::RejoinFailed, at(201), r), Action::Rejoin);
        assert_eq!(
            l.on_event(Event::RejoinFailed, at(202), r),
            Action::ScanForPan
        );
        assert_eq!(
            l.on_event(Event::PanNotFound, at(210), r),
            Action::WaitOnOriginalChannel {
                delay: Duration::from_mins(60)
            }
        );
        // Next attempt: found on another channel, rejoin there succeeds
        // → rediscovery, then steady.
        assert_eq!(l.on_event(Event::Start, at(4000), r), Action::Rejoin);
        for _ in 0..3 {
            l.on_event(Event::RejoinFailed, at(4001), r);
        }
        assert_eq!(
            l.on_event(Event::PanFoundOnOtherChannel, at(4010), r),
            Action::Rejoin
        );
        assert_eq!(
            l.on_event(Event::RejoinSucceeded, at(4011), r),
            Action::DiscoverServices
        );
        assert_eq!(l.phase(), Phase::ServiceDiscovery);
        l.on_event(Event::DiscoveryDone, at(4012), r);
        // Five failed recoveries slow the attempts to hourly.
        l.enter_recovery();
        for i in 0..RECOVERY_SLOW_AFTER {
            for _ in 0..3 {
                l.on_event(Event::RejoinFailed, at(5000), r);
            }
            let a = l.on_event(Event::PanNotFound, at(5000), |_| 1_800_000);
            let expected = if i + 1 < RECOVERY_SLOW_AFTER {
                Duration::from_mins(60)
            } else {
                Duration::from_millis(3_600_000)
            };
            assert_eq!(a, Action::WaitOnOriginalChannel { delay: expected });
            l.on_event(Event::Start, at(5001), r);
        }
        // An APS-secured Trust Center message ends recovery.
        assert_eq!(
            l.on_event(Event::TrustCenterMessage, at(6000), r),
            Action::DiscoverServices
        );
        // An APS Remove Device is always followed.
        assert_eq!(
            l.on_event(Event::Leave(LeaveSource::ApsRemoveDevice), at(6001), r),
            Action::LeaveAndReset
        );
    }
}
