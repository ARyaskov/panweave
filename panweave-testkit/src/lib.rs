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

/// Configuration errors that would make the simulated topology invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediumError {
    /// Every radio slot is occupied.
    RadioCapacity,
    /// There is no room for both directions of another blocked link.
    LinkCapacity,
    /// A referenced radio does not exist.
    InvalidRadio,
}

impl core::fmt::Display for MediumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::RadioCapacity => "virtual medium radio capacity exceeded",
            Self::LinkCapacity => "virtual medium blocked-link capacity exceeded",
            Self::InvalidRadio => "virtual medium radio does not exist",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MediumError {}

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
    ///
    /// # Panics
    ///
    /// Panics when every radio slot is occupied. Use
    /// [`Self::try_add_radio`] for a recoverable configuration error.
    #[track_caller]
    pub fn add_radio(&mut self) -> usize {
        let index = self.radios.len();
        assert!(
            self.try_add_radio().is_ok(),
            "virtual medium radio capacity exceeded"
        );
        index
    }

    /// Adds a radio, or returns [`MediumError::RadioCapacity`] without
    /// changing the medium when every slot is occupied.
    pub fn try_add_radio(&mut self) -> Result<usize, MediumError> {
        let index = self.radios.len();
        self.radios
            .push(RadioState {
                channel: Channel::DEFAULT_2_4GHZ,
                listening: true,
                lqi: 200,
            })
            .map_err(|_| MediumError::RadioCapacity)?;
        Ok(index)
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
    /// Repeating the same block does not consume additional capacity.
    ///
    /// # Panics
    ///
    /// Panics for an unknown radio or insufficient blocked-link capacity.
    /// Use [`Self::try_block`] to handle these errors explicitly.
    #[track_caller]
    pub fn block(&mut self, a: usize, b: usize) {
        let result = self.try_block(a, b);
        assert!(result.is_ok(), "cannot block virtual link: {result:?}");
    }

    /// Atomically blocks both directions of a link. Unknown radios or
    /// insufficient capacity leave every existing link unchanged.
    /// Blocking an already blocked link, or a radio from itself, is a
    /// no-op.
    pub fn try_block(&mut self, a: usize, b: usize) -> Result<(), MediumError> {
        if self.radios.get(a).is_none() || self.radios.get(b).is_none() {
            return Err(MediumError::InvalidRadio);
        }
        if a == b {
            return Ok(());
        }
        let mut blocked = self.blocked.clone();
        for link in [(a, b), (b, a)] {
            if !blocked.contains(&link) {
                blocked.push(link).map_err(|_| MediumError::LinkCapacity)?;
            }
        }
        self.blocked = blocked;
        Ok(())
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
    ///
    /// # Panics
    ///
    /// Panics for an unknown radio. Use [`Self::try_drop_next_from`] for
    /// a recoverable configuration error.
    #[track_caller]
    pub fn drop_next_from(&mut self, i: usize, n: u32) {
        let result = self.try_drop_next_from(i, n);
        assert!(result.is_ok(), "cannot configure virtual loss: {result:?}");
    }

    /// Configures loss injection for an existing radio. Unknown radios
    /// do not occupy the bounded loss table.
    pub fn try_drop_next_from(&mut self, i: usize, n: u32) -> Result<(), MediumError> {
        if self.radios.get(i).is_none() {
            return Err(MediumError::InvalidRadio);
        }
        if let Some(e) = self.drop_next.iter_mut().find(|(r, _)| *r == i) {
            e.1 = n;
        } else {
            // One entry per valid radio fits exactly in MAX_RADIOS slots.
            self.drop_next
                .push((i, n))
                .map_err(|_| MediumError::RadioCapacity)?;
        }
        Ok(())
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

    #[test]
    fn seventeenth_radio_is_rejected_without_aliasing() {
        let mut medium = VirtualMedium::new();
        for index in 0..MAX_RADIOS {
            assert_eq!(medium.try_add_radio(), Ok(index));
        }
        assert_eq!(medium.try_add_radio(), Err(MediumError::RadioCapacity));
        medium.set_channel(MAX_RADIOS - 1, Channel::new_2_4ghz(20).unwrap());
        let (frame, targets) = medium.transmit(MAX_RADIOS - 1, &[1]);
        assert_eq!(frame.unwrap().channel.raw(), 20);
        assert!(targets.is_empty());
        assert!(medium.radio(MAX_RADIOS).is_none());
    }

    #[test]
    #[should_panic(expected = "virtual medium radio capacity exceeded")]
    fn adding_a_radio_past_capacity_fails_fast() {
        let mut medium = VirtualMedium::new();
        for _ in 0..=MAX_RADIOS {
            medium.add_radio();
        }
    }

    #[test]
    fn blocking_is_idempotent_and_capacity_failure_is_atomic() {
        let mut medium = VirtualMedium::new();
        for _ in 0..MAX_RADIOS {
            medium.add_radio();
        }
        for peer in 1..MAX_RADIOS {
            medium.try_block(0, peer).unwrap();
        }
        medium.try_block(1, 2).unwrap();
        for _ in 0..MAX_RADIOS {
            assert_eq!(medium.try_block(1, 2), Ok(()));
            assert_eq!(medium.try_block(2, 1), Ok(()));
        }
        assert_eq!(medium.try_block(2, 3), Err(MediumError::LinkCapacity));
        assert!(medium.reachable(2, 3));
        assert!(medium.reachable(3, 2));
        assert!(!medium.reachable(1, 2));
        assert!(!medium.reachable(2, 1));
        for peer in 1..MAX_RADIOS {
            assert!(!medium.reachable(0, peer));
            assert!(!medium.reachable(peer, 0));
        }
        medium.unblock(1, 2);
        assert_eq!(medium.try_block(2, 3), Ok(()));
        assert!(!medium.reachable(2, 3));
        assert!(!medium.reachable(3, 2));
    }

    #[test]
    fn invalid_loss_and_link_configuration_do_not_consume_capacity() {
        let mut medium = VirtualMedium::new();
        assert_eq!(medium.try_block(0, 1), Err(MediumError::InvalidRadio));
        for index in 0..MAX_RADIOS {
            assert_eq!(
                medium.try_drop_next_from(MAX_RADIOS + index, 1),
                Err(MediumError::InvalidRadio)
            );
            medium.add_radio();
            assert_eq!(medium.try_drop_next_from(index, 1), Ok(()));
        }
        for index in 0..MAX_RADIOS {
            let (frame, _) = medium.transmit(index, &[1]);
            assert!(frame.is_none());
        }
        assert_eq!(medium.frames_dropped, u32::try_from(MAX_RADIOS).unwrap());
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
