//! Frame counter management.
//!
//! Outgoing counters (R23.2 §4.3.4) must never roll back, including across
//! power loss. [`OutgoingCounter`] implements a store-ahead reservation
//! window: the persisted value is an upper bound (`reserved_until`) that
//! the counter may use without further writes; on restart the counter
//! resumes *at* the persisted bound, never below. See
//! `docs/storage-model.md`.
//!
//! Incoming counters (§4.3.1.2 step 3 and 6) are tracked per sender in
//! [`IncomingCounters`]: a frame is fresh only if its counter is not below
//! the stored value, and the stored value becomes `received + 1`.

use heapless::Vec;
use panweave_types::{ExtendedAddress, FrameCounter};

/// Errors from outgoing counter allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CounterError {
    /// The counter reached `2^32 - 1`; the key must be replaced before any
    /// further frame is secured (§4.3.1.1 step 1).
    Exhausted,
    /// The reservation window is used up and a new reservation has not
    /// been committed yet. Transmission must wait (never reuse a value).
    ReservationRequired,
}

/// A pending reservation to persist. The caller commits it to storage and
/// then calls [`OutgoingCounter::commit_reservation`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reservation {
    /// The new upper bound (exclusive) to persist.
    pub reserved_until: u32,
}

/// Outgoing frame counter with store-ahead reservation.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OutgoingCounter {
    next: u32,
    reserved_until: u32,
    window: u32,
    margin: u32,
    /// A reservation handed out but not yet committed.
    in_flight: Option<u32>,
}

impl OutgoingCounter {
    /// Default reservation window.
    pub const DEFAULT_WINDOW: u32 = 1024;
    /// Default margin at which a new reservation is requested ahead of
    /// need.
    pub const DEFAULT_MARGIN: u32 = 64;
    /// Threshold above which a Switch Key resets the counter (§4.3.4).
    pub const SWITCH_RESET_THRESHOLD: u32 = 0x8000_0000;

    /// Restores a counter from the persisted bound. The first value
    /// handed out is `reserved_until` itself, so any value used before
    /// the last commit is never reused.
    pub const fn restore(reserved_until: u32) -> Self {
        OutgoingCounter {
            next: reserved_until,
            reserved_until,
            window: Self::DEFAULT_WINDOW,
            margin: Self::DEFAULT_MARGIN,
            in_flight: None,
        }
    }

    /// A fresh counter for a newly created key (no persisted state).
    pub const fn new() -> Self {
        Self::restore(0)
    }

    /// Sets the window and margin (margin is clamped below window).
    pub fn with_window(mut self, window: u32, margin: u32) -> Self {
        self.window = window.max(1);
        self.margin = margin.min(self.window.saturating_sub(1));
        self
    }

    /// The next value that would be handed out.
    #[inline]
    pub const fn peek(&self) -> u32 {
        self.next
    }

    /// The persisted (committed) upper bound.
    #[inline]
    pub const fn reserved_until(&self) -> u32 {
        self.reserved_until
    }

    /// True when a new reservation should be started now so that it is
    /// committed before the window runs out.
    #[inline]
    pub fn needs_reservation(&self) -> bool {
        self.in_flight.is_none()
            && self.next.saturating_add(self.margin) >= self.reserved_until
            && self.reserved_until != u32::MAX
    }

    /// Starts a reservation if one is needed; returns the value to persist.
    pub fn start_reservation(&mut self) -> Option<Reservation> {
        if !self.needs_reservation() {
            return None;
        }
        let target = self
            .next
            .saturating_add(self.window)
            .max(self.reserved_until);
        self.in_flight = Some(target);
        Some(Reservation {
            reserved_until: target,
        })
    }

    /// Records that `r` has been durably persisted.
    pub fn commit_reservation(&mut self, r: Reservation) {
        if self.in_flight == Some(r.reserved_until) {
            self.in_flight = None;
        }
        if r.reserved_until > self.reserved_until {
            self.reserved_until = r.reserved_until;
        }
    }

    /// Abandons an in-flight reservation (storage failure); a new one will
    /// be requested on the next check.
    pub fn abort_reservation(&mut self) {
        self.in_flight = None;
    }

    /// Allocates the next counter value.
    pub fn allocate(&mut self) -> Result<FrameCounter, CounterError> {
        if self.next == u32::MAX {
            return Err(CounterError::Exhausted);
        }
        if self.next >= self.reserved_until {
            return Err(CounterError::ReservationRequired);
        }
        let v = self.next;
        self.next += 1;
        Ok(FrameCounter(v))
    }

    /// Applies the Switch Key rule of §4.3.4: the counter is reset to zero
    /// only when it exceeds `0x8000_0000`. Returns true when a reset
    /// happened; the caller must then persist a fresh reservation before
    /// securing the next frame.
    pub fn on_key_switch(&mut self) -> bool {
        if self.next > Self::SWITCH_RESET_THRESHOLD {
            self.next = 0;
            self.reserved_until = 0;
            self.in_flight = None;
            true
        } else {
            false
        }
    }

    /// True when the counter is close to exhaustion and a network key
    /// update should be requested (`0x8000_0000` and above).
    #[inline]
    pub const fn near_exhaustion(&self) -> bool {
        self.next >= Self::SWITCH_RESET_THRESHOLD
    }
}

impl Default for OutgoingCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of an incoming freshness check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FreshnessError {
    /// The counter is below the stored value (replayed or stale frame).
    Replay,
    /// No slot is available for a new sender and `nwkAllFresh` requires
    /// tracking (§4.3.1.2 step 6).
    TableFull,
    /// The received counter is `2^32 - 1` (§4.3.1.2 step 1).
    Exhausted,
}

/// Per-sender incoming frame counters.
#[derive(Clone, Debug, Default)]
pub struct IncomingCounters<const N: usize> {
    entries: Vec<(ExtendedAddress, u32), N>,
}

impl<const N: usize> IncomingCounters<N> {
    /// Empty table.
    pub const fn new() -> Self {
        IncomingCounters {
            entries: Vec::new(),
        }
    }

    /// Checks `received` from `sender` and, if fresh, records
    /// `received + 1` as the next acceptable value.
    ///
    /// `all_fresh` corresponds to `nwkAllFresh`: when true, an untrackable
    /// sender is rejected; when false, frames from untracked senders are
    /// accepted without freshness protection.
    pub fn check_and_update(
        &mut self,
        sender: ExtendedAddress,
        received: FrameCounter,
        all_fresh: bool,
    ) -> Result<(), FreshnessError> {
        if received.0 == u32::MAX {
            return Err(FreshnessError::Exhausted);
        }
        if let Some(e) = self.entries.iter_mut().find(|e| e.0 == sender) {
            if received.0 < e.1 {
                return Err(FreshnessError::Replay);
            }
            e.1 = received.0 + 1;
            return Ok(());
        }
        if self.entries.push((sender, received.0 + 1)).is_err() && all_fresh {
            return Err(FreshnessError::TableFull);
        }
        Ok(())
    }

    /// Checks freshness without updating (for frames that are validated
    /// but not yet accepted).
    pub fn is_fresh(&self, sender: ExtendedAddress, received: FrameCounter) -> bool {
        received.0 != u32::MAX
            && self
                .entries
                .iter()
                .find(|e| e.0 == sender)
                .is_none_or(|e| received.0 >= e.1)
    }

    /// The stored next-acceptable counter for `sender`.
    pub fn get(&self, sender: ExtendedAddress) -> Option<u32> {
        self.entries.iter().find(|e| e.0 == sender).map(|e| e.1)
    }

    /// Sets the stored counter (e.g. from persisted state or a verified
    /// re-synchronisation).
    pub fn set(&mut self, sender: ExtendedAddress, next: u32) -> Result<(), FreshnessError> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.0 == sender) {
            e.1 = next;
            Ok(())
        } else {
            self.entries
                .push((sender, next))
                .map_err(|_| FreshnessError::TableFull)
        }
    }

    /// Forgets `sender` (device left the network).
    pub fn remove(&mut self, sender: ExtendedAddress) {
        self.entries.retain(|e| e.0 != sender);
    }

    /// Clears all counters (network key switch, §4.6.3.4).
    pub fn reset_all(&mut self) {
        self.entries.clear();
    }

    /// Number of tracked senders.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates the entries.
    pub fn iter(&self) -> impl Iterator<Item = (ExtendedAddress, u32)> + '_ {
        self.entries.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_counter_never_decreases_across_restart() {
        let mut c = OutgoingCounter::new();
        assert_eq!(c.allocate(), Err(CounterError::ReservationRequired));
        let r = c.start_reservation().unwrap();
        assert_eq!(r.reserved_until, OutgoingCounter::DEFAULT_WINDOW);
        c.commit_reservation(r);
        let mut last = 0;
        for _ in 0..100 {
            let v = c.allocate().unwrap().0;
            assert!(v >= last);
            last = v;
        }
        // "Power loss": restore from persisted bound → resumes at the bound.
        let restored = OutgoingCounter::restore(c.reserved_until());
        assert!(restored.peek() > last);
        assert_eq!(restored.peek(), OutgoingCounter::DEFAULT_WINDOW);
    }

    #[test]
    fn reservation_requested_ahead_of_need_and_window_is_hard_limit() {
        let mut c = OutgoingCounter::new().with_window(10, 3);
        let r = c.start_reservation().unwrap();
        c.commit_reservation(r);
        assert!(!c.needs_reservation());
        for _ in 0..7 {
            c.allocate().unwrap();
        }
        assert!(c.needs_reservation(), "margin reached");
        let r2 = c.start_reservation().unwrap();
        assert!(
            !c.needs_reservation(),
            "in-flight reservation suppresses duplicates"
        );
        for _ in 0..3 {
            c.allocate().unwrap();
        }
        assert_eq!(c.allocate(), Err(CounterError::ReservationRequired));
        c.commit_reservation(r2);
        assert_eq!(c.allocate().unwrap(), FrameCounter(10));
        // Abort path.
        c.abort_reservation();
        assert!(c.needs_reservation() || c.peek() + 3 < c.reserved_until());
    }

    #[test]
    fn exhaustion_and_switch_reset_rule() {
        let mut c = OutgoingCounter::restore(u32::MAX - 1);
        c.commit_reservation(Reservation {
            reserved_until: u32::MAX,
        });
        assert_eq!(c.allocate().unwrap(), FrameCounter(u32::MAX - 1));
        assert_eq!(c.allocate(), Err(CounterError::Exhausted));
        assert!(c.near_exhaustion());
        assert!(c.on_key_switch());
        assert_eq!(c.peek(), 0);
        let mut low = OutgoingCounter::restore(5);
        assert!(!low.on_key_switch(), "below threshold: counter preserved");
        assert_eq!(low.peek(), 5);
    }

    #[test]
    fn incoming_freshness() {
        let mut t = IncomingCounters::<2>::new();
        let a = ExtendedAddress(1);
        let b = ExtendedAddress(2);
        let c = ExtendedAddress(3);
        t.check_and_update(a, FrameCounter(10), true).unwrap();
        assert_eq!(t.get(a), Some(11));
        assert_eq!(
            t.check_and_update(a, FrameCounter(10), true),
            Err(FreshnessError::Replay)
        );
        assert_eq!(
            t.check_and_update(a, FrameCounter(9), true),
            Err(FreshnessError::Replay)
        );
        t.check_and_update(a, FrameCounter(11), true).unwrap();
        t.check_and_update(a, FrameCounter(100), true).unwrap();
        assert!(t.is_fresh(a, FrameCounter(101)));
        assert!(!t.is_fresh(a, FrameCounter(100)));
        t.check_and_update(b, FrameCounter(0), true).unwrap();
        assert_eq!(
            t.check_and_update(c, FrameCounter(0), true),
            Err(FreshnessError::TableFull)
        );
        assert_eq!(t.check_and_update(c, FrameCounter(0), false), Ok(()));
        assert_eq!(
            t.check_and_update(a, FrameCounter(u32::MAX), true),
            Err(FreshnessError::Exhausted)
        );
        t.remove(b);
        assert_eq!(t.len(), 1);
        t.reset_all();
        assert!(t.is_empty());
    }
}
