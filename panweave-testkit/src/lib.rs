//! Test support: a virtual clock and a virtual 802.15.4 medium for
//! sans-I/O stacks.
//!
//! [`VirtualMedium`] models an ideal channel between radios: every frame
//! handed to [`VirtualMedium::transmit`] is delivered to every other
//! radio on the same channel that is listening, subject to optional link
//! blocking and loss injection. Acknowledgements are produced by the
//! receiving MAC (software ack), exactly as with a radio without
//! hardware acknowledgement support.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

use heapless::Vec;
use panweave_types::Channel;
use panweave_types::time::{Duration, Instant};

/// A virtual clock in milliseconds.
#[derive(Clone, Copy, Debug)]
pub struct VirtualClock {
    now: Instant,
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualClock {
    /// Starts at one second (so that "zero" never means "unset").
    pub const fn new() -> Self {
        VirtualClock {
            now: Instant::from_millis(1000),
        }
    }

    /// Starts at the given time.
    pub const fn at(now: Instant) -> Self {
        VirtualClock { now }
    }

    /// Current time.
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// Advances by `d`.
    pub fn advance(&mut self, d: Duration) {
        self.now = self.now.saturating_add(d);
    }

    /// Advances to `t` (never backwards).
    pub fn advance_to(&mut self, t: Instant) {
        if t.as_millis() > self.now.as_millis() {
            self.now = t;
        }
    }
}

/// Maximum PHY frame (without FCS).
pub const MAX_PHY_FRAME: usize = 125;

/// Maximum radios on a medium.
pub const MAX_RADIOS: usize = 16;

/// A frame in flight on the medium.
#[derive(Clone, Debug)]
pub struct AirFrame {
    /// Transmitting radio index.
    pub from: usize,
    /// Channel.
    pub channel: Channel,
    /// The frame bytes (no FCS).
    pub bytes: Vec<u8, MAX_PHY_FRAME>,
}

/// A radio attached to the medium.
#[derive(Clone, Copy, Debug)]
pub struct RadioState {
    /// Current channel.
    pub channel: Channel,
    /// Receiver enabled.
    pub listening: bool,
    /// Link quality reported for frames received by this radio.
    pub lqi: u8,
}

/// The virtual medium.
#[derive(Clone, Debug)]
pub struct VirtualMedium {
    radios: Vec<RadioState, MAX_RADIOS>,
    /// Blocked directed links (from, to).
    blocked: Vec<(usize, usize), 32>,
    /// Frames transmitted so far.
    pub frames_sent: u32,
    /// Frames dropped by loss injection.
    pub frames_dropped: u32,
    /// Drop the next `n` frames from radio `i`.
    drop_next: Vec<(usize, u32), MAX_RADIOS>,
}

impl Default for VirtualMedium {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualMedium {
    /// Empty medium.
    pub const fn new() -> Self {
        VirtualMedium {
            radios: Vec::new(),
            blocked: Vec::new(),
            frames_sent: 0,
            frames_dropped: 0,
            drop_next: Vec::new(),
        }
    }

    /// Adds a radio; returns its index.
    pub fn add_radio(&mut self) -> usize {
        let _ = self.radios.push(RadioState {
            channel: Channel::DEFAULT_2_4GHZ,
            listening: true,
            lqi: 200,
        });
        self.radios.len() - 1
    }

    /// Radio state.
    pub fn radio(&self, i: usize) -> Option<&RadioState> {
        self.radios.get(i)
    }

    /// Mutable radio state.
    pub fn radio_mut(&mut self, i: usize) -> Option<&mut RadioState> {
        self.radios.get_mut(i)
    }

    /// Sets the channel of radio `i`.
    pub fn set_channel(&mut self, i: usize, channel: Channel) {
        if let Some(r) = self.radios.get_mut(i) {
            r.channel = channel;
        }
    }

    /// Blocks frames from `a` to `b` and from `b` to `a`.
    pub fn block(&mut self, a: usize, b: usize) {
        let _ = self.blocked.push((a, b));
        let _ = self.blocked.push((b, a));
    }

    /// Restores the link between `a` and `b`.
    pub fn unblock(&mut self, a: usize, b: usize) {
        self.blocked
            .retain(|(x, y)| !((*x == a && *y == b) || (*x == b && *y == a)));
    }

    /// True when `from` can reach `to`.
    pub fn reachable(&self, from: usize, to: usize) -> bool {
        from != to
            && !self.blocked.contains(&(from, to))
            && matches!((self.radios.get(from), self.radios.get(to)), (Some(a), Some(b)) if a.channel == b.channel && b.listening)
    }

    /// Drops the next `n` frames transmitted by radio `i`.
    pub fn drop_next_from(&mut self, i: usize, n: u32) {
        if let Some(e) = self.drop_next.iter_mut().find(|(r, _)| *r == i) {
            e.1 = n;
        } else {
            let _ = self.drop_next.push((i, n));
        }
    }

    /// Transmits `bytes` from radio `from`; returns the indices of the
    /// radios that receive it (empty when dropped).
    pub fn transmit(
        &mut self,
        from: usize,
        bytes: &[u8],
    ) -> (Option<AirFrame>, Vec<usize, MAX_RADIOS>) {
        self.frames_sent = self.frames_sent.saturating_add(1);
        let mut targets = Vec::new();
        if let Some(e) = self
            .drop_next
            .iter_mut()
            .find(|(r, n)| *r == from && *n > 0)
        {
            e.1 -= 1;
            self.frames_dropped = self.frames_dropped.saturating_add(1);
            return (None, targets);
        }
        let Some(channel) = self.radios.get(from).map(|r| r.channel) else {
            return (None, targets);
        };
        let Ok(frame) = Vec::from_slice(bytes) else {
            return (None, targets);
        };
        for to in 0..self.radios.len() {
            if self.reachable(from, to) {
                let _ = targets.push(to);
            }
        }
        (
            Some(AirFrame {
                from,
                channel,
                bytes: frame,
            }),
            targets,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medium_delivery_and_blocking() {
        let mut m = VirtualMedium::new();
        let a = m.add_radio();
        let b = m.add_radio();
        let c = m.add_radio();
        let (f, t) = m.transmit(a, &[1, 2, 3]);
        assert!(f.is_some());
        assert_eq!(t.as_slice(), &[b, c]);
        m.block(a, c);
        let (_, t) = m.transmit(a, &[1]);
        assert_eq!(t.as_slice(), &[b]);
        m.set_channel(b, Channel::new_2_4ghz(15).unwrap());
        let (_, t) = m.transmit(a, &[1]);
        assert!(t.is_empty());
        m.unblock(a, c);
        m.drop_next_from(a, 1);
        let (f, t) = m.transmit(a, &[1]);
        assert!(f.is_none() && t.is_empty());
        let (_, t) = m.transmit(a, &[1]);
        assert_eq!(t.as_slice(), &[c]);
        assert_eq!(m.frames_dropped, 1);
        let mut clk = VirtualClock::new();
        clk.advance(Duration::from_millis(5));
        assert_eq!(clk.now(), Instant::from_millis(1005));
    }
}

/// A deterministic RNG that *claims* to be cryptographically secure so
/// that key-generating code paths can run in tests.
///
/// It wraps [`panweave_types::rng::DeterministicRng`]; the marker
/// implementation exists only for test determinism. Never use it in a
/// product build — the `CryptoRng` marker on the real RNG type is what
/// makes key generation trustworthy.
#[derive(Clone, Debug)]
pub struct TestRng(pub panweave_types::rng::DeterministicRng);

impl TestRng {
    /// Seeds the generator.
    pub fn seed(seed: u64) -> Self {
        TestRng(panweave_types::rng::DeterministicRng::seed(seed))
    }
}

impl panweave_types::Rng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}

impl panweave_types::CryptoRng for TestRng {}
