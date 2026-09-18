//! The main loop: the sans-I/O stack driven by the radio and the clock.
//!
//! ```ignore
//! let board = Board::init();
//! let mut node = Router::new(board.ieee).build(board.rng, board.storage);
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
}

impl Runner {
    /// Takes the radio.
    pub fn new(radio: Radio) -> Self {
        Runner {
            radio,
            rx: [0; MAX_MAC_FRAME_SIZE],
            delay: Delay::new(),
            rx_frames: 0,
            tx_frames: 0,
        }
    }

    /// One turn of the loop: returns when the stack has nothing more to
    /// do right now, with the time it wants to run next.
    pub fn step<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        node: &mut Node<C, R, S>,
    ) -> Option<Instant> {
        node.poll(now());
        loop {
            let mut moved = false;
            while let Some(action) = node.next_radio_action() {
                moved = true;
                match action {
                    MacAction::Transmit { frame, options, .. } => {
                        let result = self.radio.transmit(&frame, options);
                        self.tx_frames = self.tx_frames.wrapping_add(1);
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
            while let Some((n, meta)) = self.radio.receive(&mut self.rx) {
                moved = true;
                self.rx_frames = self.rx_frames.wrapping_add(1);
                node.on_radio_frame(&self.rx[..n], meta);
            }
            if !moved {
                break;
            }
            node.poll(now());
        }
        self.radio.flush();
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
