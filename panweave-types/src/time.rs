//! Monotonic time primitives.
//!
//! Protocol timers are expressed in milliseconds. An [`Instant`] is a
//! monotonic timestamp provided by the runtime clock (real or virtual);
//! a [`Duration`] is a span. Both are plain `u64` millisecond values so
//! that they are cheap to store in tables and trivially deterministic in
//! simulation.

use core::fmt;
use core::ops::{Add, AddAssign, Sub};

/// A span of time in milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Duration(u64);

impl Duration {
    /// Zero duration.
    pub const ZERO: Duration = Duration(0);
    /// The largest representable duration.
    pub const MAX: Duration = Duration(u64::MAX);

    /// Builds from milliseconds.
    #[inline]
    pub const fn from_millis(ms: u64) -> Duration {
        Duration(ms)
    }

    /// Builds from seconds (saturating).
    #[inline]
    pub const fn from_secs(s: u64) -> Duration {
        Duration(s.saturating_mul(1000))
    }

    /// Builds from minutes (saturating).
    #[inline]
    pub const fn from_mins(m: u64) -> Duration {
        Duration(m.saturating_mul(60_000))
    }

    /// Builds from IEEE 802.15.4 symbol periods on the 2.4 GHz PHY
    /// (16 µs per symbol), rounding up to whole milliseconds.
    #[inline]
    pub const fn from_symbols_2_4ghz(symbols: u64) -> Duration {
        // 16 µs per symbol → ms = symbols * 16 / 1000, rounded up.
        Duration(symbols.saturating_mul(16).saturating_add(999) / 1000)
    }

    /// Milliseconds.
    #[inline]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Whole seconds (truncating).
    #[inline]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    /// Saturating addition.
    #[inline]
    pub const fn saturating_add(self, rhs: Duration) -> Duration {
        Duration(self.0.saturating_add(rhs.0))
    }

    /// Saturating multiplication by an integer factor.
    #[inline]
    pub const fn saturating_mul(self, factor: u64) -> Duration {
        Duration(self.0.saturating_mul(factor))
    }

    /// Integer division.
    #[inline]
    pub const fn div(self, divisor: u64) -> Duration {
        match self.0.checked_div(divisor) {
            Some(v) => Duration(v),
            None => Duration::MAX,
        }
    }

    /// True for zero.
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl Add for Duration {
    type Output = Duration;
    fn add(self, rhs: Duration) -> Duration {
        self.saturating_add(rhs)
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        *self = self.saturating_add(rhs);
    }
}

impl fmt::Debug for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

crate::impl_defmt_via_debug!(Duration);

/// A monotonic timestamp in milliseconds since an arbitrary epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Instant(u64);

impl Instant {
    /// The epoch.
    pub const ZERO: Instant = Instant(0);
    /// The far future; useful as an "unscheduled" marker.
    pub const FAR_FUTURE: Instant = Instant(u64::MAX);

    /// Builds from milliseconds since the epoch.
    #[inline]
    pub const fn from_millis(ms: u64) -> Instant {
        Instant(ms)
    }

    /// Milliseconds since the epoch.
    #[inline]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Time elapsed since `earlier`, or zero when `earlier` is later.
    #[inline]
    pub const fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    /// Time until `later`, or zero when `later` has passed.
    #[inline]
    pub const fn saturating_duration_until(self, later: Instant) -> Duration {
        Duration(later.0.saturating_sub(self.0))
    }

    /// Saturating addition.
    #[inline]
    pub const fn saturating_add(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(d.0))
    }

    /// True when `self >= deadline`.
    #[inline]
    pub const fn has_reached(self, deadline: Instant) -> bool {
        self.0 >= deadline.0
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, rhs: Duration) -> Instant {
        self.saturating_add(rhs)
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = self.saturating_add(rhs);
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t+{}ms", self.0)
    }
}

crate::impl_defmt_via_debug!(Instant);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_conversions() {
        assert_eq!(Duration::from_secs(2).as_millis(), 2000);
        assert_eq!(Duration::from_mins(1).as_secs(), 60);
        // aBaseSuperframeDuration = 960 symbols = 15.36 ms → 16 ms rounded up.
        assert_eq!(Duration::from_symbols_2_4ghz(960).as_millis(), 16);
        assert_eq!(Duration::from_symbols_2_4ghz(0).as_millis(), 0);
        assert_eq!(
            Duration::MAX.saturating_add(Duration::from_secs(1)),
            Duration::MAX
        );
        assert_eq!(Duration::from_secs(10).div(0), Duration::MAX);
    }

    #[test]
    fn instant_arithmetic_saturates() {
        let a = Instant::from_millis(100);
        let b = a + Duration::from_millis(50);
        assert_eq!(b.as_millis(), 150);
        assert_eq!(b - a, Duration::from_millis(50));
        assert_eq!(a - b, Duration::ZERO);
        assert!(b.has_reached(a));
        assert!(!a.has_reached(b));
        assert_eq!(a.saturating_duration_until(b).as_millis(), 50);
    }
}
