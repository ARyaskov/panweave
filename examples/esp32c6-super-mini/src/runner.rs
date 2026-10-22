//! The main loop: the sans-I/O stack driven by the radio and the clock.
//!
//! ```ignore
//! let board = Board::init();
//! let mut node = Router::new(board.ieee)
//!     .mac(Radio::mac_config())
//!     .build(board.rng, board.storage);
//! let mut runner = Runner::new(board.radio);
//! loop {
//!     let deadline = runner.step(&mut node);
//!     while let Some(event) = node.next_event() { /* the application */ }
//!     runner.idle(deadline);
//! }
//! ```
//!
//! [`Runner::step`] polls the stack at the current time, executes every
//! radio action it produces and feeds it every frame the radio holds,
//! until nothing moves; [`Runner::idle`] waits for the next deadline or
//! the next frame. The wait is a polled delay: the chip stays awake, as
//! a router or an rx-on end device must anyway. A sleepy end device
//! would put the radio and the CPU to sleep between polls instead
//! (`esp-hal-embassy` timers and `wfi`), which this crate does not do.

use esp_hal::delay::Delay;
use panweave::Node;
use panweave::mac::constants::MAX_MAC_FRAME_SIZE;
use panweave::mac::service::MacAction;
use panweave::security::cipher::BlockCipher;
use panweave::storage::Storage;
use panweave::types::CryptoRng;
use panweave::types::time::Instant;

use crate::radio::Radio;

/// A frame the runner moved between the stack and the radio, for an
/// observer (frame capture). Borrowed for the duration of the call: an
/// observer copies what it keeps.
pub enum Traffic<'a> {
    /// A frame handed to the radio (an attempt; `acked` says whether an
    /// acknowledgement came back when one was requested).
    Tx {
        /// The MAC frame without FCS.
        frame: &'a [u8],
        /// An acknowledgement was requested.
        ack_requested: bool,
        /// One came back.
        acked: bool,
        /// The driver reported a fault (no outcome, or refused).
        fault: bool,
    },
    /// A frame the radio received (it passed the address filter).
    Rx {
        /// The MAC frame without FCS.
        frame: &'a [u8],
        /// RSSI, dBm.
        rssi: i8,
        /// LQI.
        lqi: u8,
    },
}

/// The stack's clock: milliseconds since boot from the system timer.
pub fn now() -> Instant {
    Instant::from_millis(
        esp_hal::time::Instant::now()
            .duration_since_epoch()
            .as_millis(),
    )
}

/// Drives a `Node` on the radio.
pub struct Runner {
    /// The radio.
    pub radio: Radio,
    rx: [u8; MAX_MAC_FRAME_SIZE],
    delay: Delay,
    /// Frames received, transmitted.
    pub rx_frames: u32,
    /// Frames transmitted.
    pub tx_frames: u32,
    /// Longest [`Runner::step`], µs (radio and stack processing, no
    /// waiting).
    pub step_max_us: u32,
    /// Steps that stopped after [`MAX_RX_PER_STEP`] received frames to
    /// let the rest of the loop (USB, watchdog) run.
    pub rx_bursts_cut: u32,
}

/// Received frames one [`Runner::step`] processes at most; the rest stay
/// in the driver's queue for the next turn, a few milliseconds later.
pub const MAX_RX_PER_STEP: u32 = 32;

impl Runner {
    /// Takes the radio.
    pub fn new(radio: Radio) -> Self {
        Runner {
            radio,
            rx: [0; MAX_MAC_FRAME_SIZE],
            delay: Delay::new(),
            rx_frames: 0,
            tx_frames: 0,
            step_max_us: 0,
            rx_bursts_cut: 0,
        }
    }

    /// One turn of the loop: returns when the stack has nothing more to
    /// do right now, with the time it wants to run next.
    pub fn step<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        node: &mut Node<C, R, S>,
    ) -> Option<Instant> {
        self.step_observed(node, |_, _| {})
    }

    /// [`Runner::step`] that shows every frame to `observe`, with the
    /// channel it went over.
    pub fn step_observed<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        node: &mut Node<C, R, S>,
        mut observe: impl FnMut(Traffic<'_>, u8),
    ) -> Option<Instant> {
        let started = esp_hal::time::Instant::now();
        node.poll(now());
        let mut received = 0u32;
        loop {
            let mut moved = false;
            while let Some(action) = node.next_radio_action() {
                moved = true;
                match action {
                    MacAction::Transmit { frame, options, .. } => {
                        let result = self.radio.transmit(&frame, options);
                        self.tx_frames = self.tx_frames.wrapping_add(1);
                        observe(
                            Traffic::Tx {
                                frame: &frame,
                                ack_requested: options.ack_request,
                                acked: result.as_ref().is_ok_and(|r| r.acked),
                                fault: result.is_err(),
                            },
                            self.radio.channel(),
                        );
                        node.on_tx_complete(result);
                    }
                    MacAction::SetChannel { channel, .. } => {
                        let _ = self.radio.set_channel(channel);
                    }
                    MacAction::Configure(c) => self.radio.configure(&c),
                    MacAction::SetPending { .. } => {}
                    MacAction::EnergyDetect { .. } => {
                        let level = self.radio.energy_detect();
                        node.on_energy_result(level);
                    }
                }
            }
            while received < MAX_RX_PER_STEP
                && let Some((n, meta)) = self.radio.receive(&mut self.rx)
            {
                moved = true;
                received += 1;
                self.rx_frames = self.rx_frames.wrapping_add(1);
                observe(
                    Traffic::Rx {
                        frame: &self.rx[..n],
                        rssi: meta.rssi_dbm,
                        lqi: meta.lqi,
                    },
                    self.radio.channel(),
                );
                node.on_radio_frame(&self.rx[..n], meta);
            }
            if !moved {
                break;
            }
            node.poll(now());
        }
        if received >= MAX_RX_PER_STEP && self.radio.frame_pending() {
            // A burst: the rest of the loop (USB, watchdog) runs before
            // the next frames; the idle wait ends at once on them.
            self.rx_bursts_cut = self.rx_bursts_cut.wrapping_add(1);
        }
        self.radio.flush();
        let us = started.elapsed().as_micros();
        self.step_max_us = self.step_max_us.max(u32::try_from(us).unwrap_or(u32::MAX));
        node.next_deadline()
    }

    /// Waits until `deadline` (at most 250 ms without one), a received
    /// frame or the button ending the wait early.
    pub fn idle(&mut self, deadline: Option<Instant>) {
        self.idle_until(deadline, || false);
    }

    /// [`Runner::idle`] that also returns when `wake` says so (polled
    /// every millisecond: a button, a sensor threshold).
    pub fn idle_until(&mut self, deadline: Option<Instant>, mut wake: impl FnMut() -> bool) {
        let start = now();
        let limit = deadline.map_or(250, |d| {
            d.as_millis().saturating_sub(start.as_millis()).min(250)
        });
        while now().as_millis() - start.as_millis() < limit {
            if self.radio.frame_pending() || wake() {
                return;
            }
            self.delay.delay_millis(1);
        }
    }
}
