//! Board support for the hub firmware (`src/bin/hub.rs`): the USB link
//! that carries Panweave Hub Protocol frames, the registry storage, and
//! the watchdog.
//!
//! The USB-C connector of the Super Mini is the chip's USB Serial/JTAG
//! controller: one CDC-ACM serial port on the host, no driver to install.
//! The hub uses it for protocol frames only — the hub image prints
//! nothing, so no log line can corrupt the stream (a panic message from
//! `esp-backtrace` is the one exception; the framing discards it). All
//! transfers are non-blocking: a host that is absent or not reading never
//! stalls the radio loop.

use esp_hal::Blocking;
use esp_hal::peripherals::{RTC_TIMER, USB_DEVICE};
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::time::Duration;
use esp_hal::usb::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx, UsbSerialJtagTx};
use panweave::storage::{Key, Kind, Storage, StorageError};
use panweave_hub::Session;

use embedded_storage::nor_flash::NorFlash;
use panweave_hub::protocol::StoreUsage;
use panweave_storage::nor_flash::NorFlashStore;

use crate::board::SharedStore;

/// A flash store's counters and room, for the hub's storage diagnostics.
pub fn store_usage<F: NorFlash>(s: &NorFlashStore<F>) -> StoreUsage {
    StoreUsage {
        capacity: s.capacity(),
        free: s.free(),
        writes: s.stats.writes,
        compactions: s.stats.compactions,
        corrupt_records: s.stats.corrupt_records,
        io_errors: s.stats.io_errors,
        formatted_at_open: s.stats.formatted_at_open,
    }
}

/// Octets read from USB per loop turn: bounds the time spent on the host
/// before the radio is served again.
pub const RX_BUDGET: usize = 256;

/// How long queued output may wait for a host that takes nothing before
/// it is dropped (the host is gone; a returning host starts at a frame
/// boundary and learns of the loss through `EventsDropped`).
pub const STALL_MS: u64 = 2000;

/// The USB Serial/JTAG port as a byte link.
pub struct UsbLink {
    rx: UsbSerialJtagRx<'static, Blocking>,
    tx: UsbSerialJtagTx<'static, Blocking>,
    buf: [u8; RX_BUDGET],
    len: usize,
    last_progress: u64,
    /// Octets received from the host (wrapping).
    pub rx_bytes: u32,
    /// Octets handed to the controller (wrapping).
    pub tx_bytes: u32,
}

impl UsbLink {
    /// Takes the USB controller.
    pub fn new(usb: USB_DEVICE<'static>) -> Self {
        let (rx, tx) = UsbSerialJtag::new(usb).split();
        UsbLink {
            rx,
            tx,
            buf: [0; RX_BUDGET],
            len: 0,
            last_progress: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// Moves received octets into the link's buffer; returns whether any
    /// are waiting (also usable as a wake-up condition while idle).
    pub fn fill(&mut self) -> bool {
        while self.len < RX_BUDGET {
            match self.rx.read_byte() {
                Ok(b) => {
                    self.buf[self.len] = b;
                    self.len += 1;
                    self.rx_bytes = self.rx_bytes.wrapping_add(1);
                }
                Err(_) => break,
            }
        }
        self.len > 0
    }

    /// Hands the waiting octets to `f`.
    pub fn receive(&mut self, f: impl FnOnce(&[u8])) {
        self.fill();
        if self.len > 0 {
            f(&self.buf[..self.len]);
            self.len = 0;
        }
    }

    /// Sends what the session has queued, as far as the controller's FIFO
    /// takes it; drops the queue after [`STALL_MS`] without progress and
    /// returns how many octets were dropped then.
    pub fn transmit<const TX: usize>(&mut self, session: &mut Session<TX>, now_ms: u64) -> usize {
        // Keep each explicitly flushed packet short. A full endpoint
        // packet alone does not terminate a USB transfer on the host.
        // Bound work per turn, and never wait for FIFO space.
        let mut sent = 0;
        for _ in 0..4 {
            let tx = &mut self.tx;
            let n =
                panweave_hub::esp32c6::transmit_usb_chunk(session, |b| tx.write_byte_nb(b).is_ok());
            if n == 0 {
                break;
            }
            let _ = self.tx.flush_tx_nb();
            sent += n;
        }
        self.tx_bytes = self
            .tx_bytes
            .wrapping_add(u32::try_from(sent).unwrap_or(u32::MAX));
        if sent > 0 || session.tx_len() == 0 {
            self.last_progress = now_ms;
        } else if now_ms.saturating_sub(self.last_progress) > STALL_MS {
            self.last_progress = now_ms;
            return session.discard_tx();
        }
        0
    }
}

/// The registry storage: the hub partition when the partition table has
/// one, else none (the registry then lives in RAM only and is lost at
/// every reset; the hub is configured non-persistent, never touches the
/// storage, and reports it to hosts).
pub enum HubStore {
    /// The `hubdata` flash partition.
    Flash(SharedStore),
    /// No storage.
    None,
}

impl Storage for HubStore {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        match self {
            HubStore::Flash(s) => s.store(key, data),
            HubStore::None => Err(StorageError::Io),
        }
    }

    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        match self {
            HubStore::Flash(s) => s.load(key, buf),
            HubStore::None => Ok(None),
        }
    }

    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        match self {
            HubStore::Flash(s) => s.erase(key),
            HubStore::None => Ok(()),
        }
    }

    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        match self {
            HubStore::Flash(s) => s.erase_kind(kind),
            HubStore::None => Ok(()),
        }
    }
}

/// The RTC watchdog: resets the chip when the loop stops feeding it.
pub struct Watchdog {
    rtc: Rtc<'static>,
}

impl Watchdog {
    /// Arms startup protection using a temporary borrow of the RTC
    /// peripheral. Dropping esp-hal's Rtc does not disable the watchdog.
    pub fn arm_early(rtc_timer: RTC_TIMER<'_>, seconds: u64) {
        let mut rtc = Rtc::new(rtc_timer);
        Self::configure(&mut rtc, seconds);
    }

    fn configure(rtc: &mut Rtc<'_>, seconds: u64) {
        rtc.rwdt
            .set_timeout(RwdtStage::Stage0, Duration::from_secs(seconds));
        rtc.rwdt.enable();
        rtc.rwdt.feed();
    }

    /// Starts the watchdog with a `seconds` timeout.
    pub fn start(rtc_timer: RTC_TIMER<'static>, seconds: u64) -> Self {
        let mut rtc = Rtc::new(rtc_timer);
        Self::configure(&mut rtc, seconds);
        Watchdog { rtc }
    }

    /// Feeds the watchdog.
    pub fn feed(&mut self) {
        self.rtc.rwdt.feed();
    }
}
