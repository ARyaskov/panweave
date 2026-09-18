//! The ESP32-C6 802.15.4 radio behind the stack's MAC actions.
//!
//! `esp-radio` gives raw frame transmit / receive with hardware
//! acknowledgements both ways, address filtering and CCA; Panweave's
//! `MacService` does the rest (retries, indirect queue, association,
//! scanning). What the driver cannot do is documented on
//! [`Radio::CAPABILITIES`] and [`Radio::energy_detect`].
//!
//! The driver applies its configuration (channel, addresses, auto-ack)
//! when it starts a transmission or a reception, not when it is set,
//! and it never leaves the receive state on its own. A configuration
//! change therefore takes effect at the next frame the stack sends;
//! when none follows, [`Radio::flush`] sends a frame addressed to this
//! device itself, which every other radio filters out, so that a
//! coordinator switching channel or a joiner changing PAN does not wait
//! for its next Link Status.

use core::sync::atomic::{AtomicBool, Ordering};

use esp_hal::peripherals::IEEE802154;
use esp_radio::ieee802154::{Config, Ieee802154, rssi_to_lqi};
use panweave::mac::constants::MAX_MAC_FRAME_SIZE;
use panweave::mac::radio::{
    RadioCapabilities, RadioConfig, RadioError, RxMetadata, TxOptions, TxResult,
};
use panweave::types::{Channel, ExtendedAddress, PanId, ShortAddress};

static TX_DONE: AtomicBool = AtomicBool::new(false);
static TX_FAILED: AtomicBool = AtomicBool::new(false);
static RX_READY: AtomicBool = AtomicBool::new(false);

fn on_tx_done() {
    TX_DONE.store(true, Ordering::SeqCst);
}

fn on_tx_failed() {
    TX_FAILED.store(true, Ordering::SeqCst);
}

fn on_rx_available() {
    RX_READY.store(true, Ordering::SeqCst);
}

/// Time a transmission may take before it is reported as a fault:
/// CSMA back-off, the frame, the acknowledgement wait.
const TX_TIMEOUT_MS: u64 = 100;

/// Frame-pending bit of the first frame-control octet.
const FCF_FRAME_PENDING: u8 = 0x10;

/// The 802.15.4 radio.
pub struct Radio {
    drv: Ieee802154<'static>,
    cfg: Config,
    ieee: ExtendedAddress,
    short: ShortAddress,
    pan_id: PanId,
    /// The driver's configuration changed since the last transmission.
    dirty: bool,
    seq: u8,
    /// Frames the driver's queue could not hold (it reports "queue
    /// full" only in its log).
    pub dropped: u32,
}

impl Radio {
    /// What the hardware does for the MAC service.
    pub const CAPABILITIES: RadioCapabilities = RadioCapabilities {
        auto_ack: true,
        ack_wait: true,
        retries: false,
        address_filter: true,
        // The driver sets the frame-pending bit in every acknowledgement
        // it sends (it has no pending-address table yet): a sleepy child
        // polls once more than needed, never too little.
        pending_bit: false,
        timestamps: false,
        promiscuous: true,
    };

    /// Takes the radio peripheral. `ieee` is this device's extended
    /// address (the hardware filter needs it before the stack's first
    /// `Configure`).
    pub fn new(peripheral: IEEE802154<'static>, ieee: ExtendedAddress) -> Self {
        let mut drv = Ieee802154::new(peripheral);
        drv.set_tx_done_callback_fn(on_tx_done);
        drv.set_tx_failed_callback_fn(on_tx_failed);
        drv.set_rx_available_callback_fn(on_rx_available);
        let cfg = Config {
            auto_ack_tx: true,
            auto_ack_rx: true,
            enhance_ack_tx: false,
            promiscuous: false,
            coordinator: false,
            rx_when_idle: true,
            txpower: 10,
            channel: 11,
            pan_id: Some(PanId::BROADCAST.0),
            short_addr: Some(ShortAddress::NO_SHORT_ADDRESS.0),
            ext_addr: Some(ieee.0),
            rx_queue_size: 16,
            ..Config::default()
        };
        drv.set_config(cfg);
        drv.start_receive();
        Radio {
            drv,
            cfg,
            ieee,
            short: ShortAddress::NO_SHORT_ADDRESS,
            pan_id: PanId::BROADCAST,
            dirty: false,
            seq: 0,
            dropped: 0,
        }
    }

    /// Applies the stack's addressing and filtering configuration.
    pub fn configure(&mut self, c: &RadioConfig) {
        self.short = c.short_address;
        self.pan_id = c.pan_id;
        self.ieee = c.extended_address;
        self.cfg.pan_id = Some(c.pan_id.0);
        self.cfg.short_addr = Some(c.short_address.0);
        self.cfg.ext_addr = Some(c.extended_address.0);
        self.cfg.coordinator = c.pan_coordinator;
        self.cfg.rx_when_idle = c.rx_on_when_idle;
        self.cfg.promiscuous = c.promiscuous;
        self.drv.set_config(self.cfg);
        self.dirty = true;
    }

    /// Selects a 2.4 GHz channel (11–26).
    ///
    /// # Errors
    ///
    /// `InvalidChannel` for a channel of another page.
    pub fn set_channel(&mut self, channel: Channel) -> Result<(), RadioError> {
        if !channel.is_2_4ghz() {
            return Err(RadioError::InvalidChannel);
        }
        self.cfg.channel = channel.raw();
        self.drv.set_config(self.cfg);
        self.dirty = true;
        Ok(())
    }

    /// Sets the transmit power (dBm, clamped to the chip's range).
    pub fn set_tx_power(&mut self, dbm: i8) -> i8 {
        let dbm = dbm.clamp(-24, 20);
        self.cfg.txpower = dbm;
        self.drv.set_config(self.cfg);
        self.dirty = true;
        dbm
    }

    /// The current channel.
    pub fn channel(&self) -> u8 {
        self.cfg.channel
    }

    /// Transmits `frame` (a MAC frame without FCS) and waits for the
    /// outcome: the acknowledgement when one was requested, otherwise
    /// the end of the transmission.
    ///
    /// # Errors
    ///
    /// `FrameTooLong`; `ChannelAccessFailure` when an unacknowledged
    /// frame's CCA failed; `HardwareFault` when the driver refused the
    /// frame or never reported its outcome.
    pub fn transmit(&mut self, frame: &[u8], options: TxOptions) -> Result<TxResult, RadioError> {
        if frame.len() > MAX_MAC_FRAME_SIZE {
            return Err(RadioError::FrameTooLong);
        }
        // The driver's length octet counts the FCS the hardware appends:
        // two octets of room after the frame.
        let mut buf = [0u8; MAX_MAC_FRAME_SIZE + 2];
        buf[..frame.len()].copy_from_slice(frame);
        TX_DONE.store(false, Ordering::SeqCst);
        TX_FAILED.store(false, Ordering::SeqCst);
        if let Some(dbm) = options.tx_power_dbm
            && dbm != self.cfg.txpower
        {
            self.set_tx_power(dbm);
        }
        self.drv
            .transmit_raw(&buf[..frame.len() + 2], options.csma)
            .map_err(|_| RadioError::HardwareFault)?;
        self.dirty = false;
        let start = crate::now();
        loop {
            if TX_DONE.load(Ordering::SeqCst) {
                break;
            }
            if TX_FAILED.load(Ordering::SeqCst) {
                // A CCA failure or an acknowledgement that never came:
                // the driver does not say which. For an acknowledged
                // frame the MAC service retries either way.
                return if options.ack_request {
                    Ok(TxResult::default())
                } else {
                    Err(RadioError::ChannelAccessFailure)
                };
            }
            if crate::now().as_millis() - start.as_millis() > TX_TIMEOUT_MS {
                return Err(RadioError::HardwareFault);
            }
        }
        if !options.ack_request {
            return Ok(TxResult::default());
        }
        Ok(match self.drv.get_ack_frame() {
            Some(ack) => TxResult {
                acked: true,
                frame_pending: ack
                    .data
                    .get(1)
                    .is_some_and(|fcf| fcf & FCF_FRAME_PENDING != 0),
                timestamp_us: None,
            },
            None => TxResult::default(),
        })
    }

    /// The next received frame, copied into `buf` without its FCS, with
    /// its metadata.
    pub fn receive(&mut self, buf: &mut [u8; MAX_MAC_FRAME_SIZE]) -> Option<(usize, RxMetadata)> {
        loop {
            RX_READY.store(false, Ordering::SeqCst);
            let raw = self.drv.raw_received()?;
            // data[0]: PSDU length including the two FCS octets, which
            // the hardware replaces by RSSI and a status octet.
            let len = usize::from(raw.data[0]);
            if len < 3 || len >= raw.data.len() {
                self.dropped = self.dropped.wrapping_add(1);
                continue;
            }
            let n = len - 2;
            if n > MAX_MAC_FRAME_SIZE {
                self.dropped = self.dropped.wrapping_add(1);
                continue;
            }
            buf[..n].copy_from_slice(&raw.data[1..=n]);
            #[allow(clippy::cast_possible_wrap)]
            let rssi = raw.data[n + 1] as i8;
            return Some((
                n,
                RxMetadata {
                    lqi: rssi_to_lqi(rssi),
                    rssi_dbm: rssi,
                    timestamp_us: None,
                    acked_by_hardware: false,
                    channel: Channel::new_2_4ghz(raw.channel),
                },
            ));
        }
    }

    /// True when the driver signalled a frame since the last
    /// [`Radio::receive`].
    pub fn frame_pending(&self) -> bool {
        RX_READY.load(Ordering::SeqCst)
    }

    /// Energy detection is not available through `esp-radio` (no ED
    /// scan or RSSI sampling API): every channel reads as quiet and a
    /// forming coordinator takes the first channel of its mask.
    pub fn energy_detect(&mut self) -> u8 {
        0
    }

    /// Makes a pending configuration change effective now (see the
    /// module documentation): a frame from this device to itself.
    pub fn flush(&mut self) {
        if !self.dirty {
            return;
        }
        // Data frame, PAN ID compression, extended destination and
        // source, no acknowledgement request, frame version 2003.
        let mut f = [0u8; 21];
        f[0] = 0x41;
        f[1] = 0xCC;
        self.seq = self.seq.wrapping_add(1);
        f[2] = self.seq;
        f[3..5].copy_from_slice(&self.pan_id.0.to_le_bytes());
        f[5..13].copy_from_slice(&self.ieee.0.to_le_bytes());
        f[13..21].copy_from_slice(&self.ieee.0.to_le_bytes());
        let _ = self.transmit(&f, TxOptions::UNACKED);
        self.dirty = false;
    }

    /// Whether a configuration change waits for a transmission.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}
