//! Radio hardware abstraction.
//!
//! A [`Radio`] is the lowest-level boundary of Panweave: it moves complete
//! MAC frames (without FCS) to and from the air on one channel, and reports
//! reception metadata. Everything above it — sequence numbers,
//! acknowledgements, retries, indirect queues, association, scanning — is
//! implemented by [`crate::service::MacService`] unless the radio
//! advertises hardware support for a capability via [`RadioCapabilities`].
//!
//! The trait is `async` and executor-agnostic. Implementations must not
//! spawn tasks; the Panweave runtime polls them.

use core::fmt;

use panweave_types::{Channel, ChannelPage, ExtendedAddress, PanId, ShortAddress};

/// Errors reported by a radio backend.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RadioError {
    /// CSMA-CA failed to find a clear channel (`CHANNEL_ACCESS_FAILURE`).
    ChannelAccessFailure,
    /// No acknowledgement was received (only from radios with hardware
    /// ack-wait; software ack handling lives in the MAC service).
    NoAck,
    /// The frame exceeds `aMaxPHYPacketSize` or the backend's limit.
    FrameTooLong,
    /// The requested channel or page is not supported.
    InvalidChannel,
    /// The receive buffer was too small for the incoming frame.
    BufferTooSmall,
    /// The radio is asleep or otherwise unable to perform the operation.
    NotReady,
    /// The backend hit a hardware or transport fault; a reset is advised.
    HardwareFault,
    /// The transport to an external RCP failed.
    Transport,
}

impl fmt::Display for RadioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RadioError::ChannelAccessFailure => "channel access failure",
            RadioError::NoAck => "no acknowledgement",
            RadioError::FrameTooLong => "frame too long",
            RadioError::InvalidChannel => "invalid channel",
            RadioError::BufferTooSmall => "receive buffer too small",
            RadioError::NotReady => "radio not ready",
            RadioError::HardwareFault => "hardware fault",
            RadioError::Transport => "transport failure",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RadioError {}

/// Static description of what the backend does in hardware.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RadioCapabilities {
    /// The radio transmits acknowledgements for frames that request one
    /// and pass its address filter. When false the MAC service transmits
    /// them.
    pub auto_ack: bool,
    /// [`Radio::transmit`] with [`TxOptions::ack_request`] waits for the
    /// acknowledgement and reports [`TxResult::acked`]. When false the MAC
    /// service waits for the ack frame itself.
    pub ack_wait: bool,
    /// The radio performs `macMaxFrameRetries` retransmissions itself.
    pub retries: bool,
    /// The radio filters by PAN ID / addresses per [`RadioConfig`]. When
    /// false the MAC service filters in software.
    pub address_filter: bool,
    /// The radio sets the frame-pending bit in hardware acknowledgements
    /// based on a pending-address list ([`Radio::set_pending`]).
    pub pending_bit: bool,
    /// Receive metadata includes a usable timestamp.
    pub timestamps: bool,
    /// Promiscuous mode is available.
    pub promiscuous: bool,
}

/// Addressing and filtering configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RadioConfig {
    /// Local PAN identifier (`0xFFFF` accepts any PAN, used while
    /// scanning/joining).
    pub pan_id: PanId,
    /// Local short address (`0xFFFE` when none).
    pub short_address: ShortAddress,
    /// Local extended address.
    pub extended_address: ExtendedAddress,
    /// Whether this device acts as PAN coordinator (accepts frames with
    /// no destination address in intra-PAN frames).
    pub pan_coordinator: bool,
    /// Keep the receiver on while idle.
    pub rx_on_when_idle: bool,
    /// Receive every frame regardless of address (sniffer/PCAP mode).
    pub promiscuous: bool,
}

impl Default for RadioConfig {
    fn default() -> Self {
        RadioConfig {
            pan_id: PanId::BROADCAST,
            short_address: ShortAddress::NO_SHORT_ADDRESS,
            extended_address: ExtendedAddress::ZERO,
            pan_coordinator: false,
            rx_on_when_idle: true,
            promiscuous: false,
        }
    }
}

/// Per-transmission options.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxOptions {
    /// The frame requests an acknowledgement.
    pub ack_request: bool,
    /// Use CSMA-CA (always true for Zigbee data; false only for ack
    /// frames transmitted by a software MAC).
    pub csma: bool,
    /// Transmit power in dBm, if the backend supports control.
    pub tx_power_dbm: Option<i8>,
}

impl TxOptions {
    /// CSMA transmission with acknowledgement request.
    pub const ACKED: TxOptions = TxOptions {
        ack_request: true,
        csma: true,
        tx_power_dbm: None,
    };
    /// CSMA transmission without acknowledgement.
    pub const UNACKED: TxOptions = TxOptions {
        ack_request: false,
        csma: true,
        tx_power_dbm: None,
    };
    /// Immediate transmission without CSMA (acknowledgement frames).
    pub const IMMEDIATE: TxOptions = TxOptions {
        ack_request: false,
        csma: false,
        tx_power_dbm: None,
    };
}

/// Result of a completed transmission.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxResult {
    /// An acknowledgement was received (meaningful only with hardware
    /// ack-wait).
    pub acked: bool,
    /// The acknowledgement carried the frame-pending bit.
    pub frame_pending: bool,
    /// Transmission timestamp, if available (µs, radio clock).
    pub timestamp_us: Option<u64>,
}

/// Metadata attached to a received frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxMetadata {
    /// Link quality indicator 0–255 as defined by IEEE 802.15.4.
    pub lqi: u8,
    /// Received signal strength in dBm.
    pub rssi_dbm: i8,
    /// Reception timestamp in µs of the radio clock, if available.
    pub timestamp_us: Option<u64>,
    /// The frame was acknowledged by hardware (informational).
    pub acked_by_hardware: bool,
    /// Channel the frame was received on.
    pub channel: Option<Channel>,
}

/// A received frame length plus metadata; the bytes live in the caller's
/// buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxFrame {
    /// Number of valid bytes in the receive buffer (excluding FCS).
    pub len: usize,
    /// Metadata.
    pub meta: RxMetadata,
}

/// An IEEE 802.15.4 radio.
///
/// Frames passed to and from this trait are complete MAC frames without
/// the FCS, at most [`crate::constants::MAX_MAC_FRAME_SIZE`] bytes.
pub trait Radio {
    /// Backend capabilities (constant per backend instance).
    fn capabilities(&self) -> RadioCapabilities;

    /// Selects the channel page and channel.
    fn set_channel(
        &mut self,
        page: ChannelPage,
        channel: Channel,
    ) -> impl Future<Output = Result<(), RadioError>>;

    /// Applies addressing / filtering configuration.
    fn configure(&mut self, config: &RadioConfig) -> impl Future<Output = Result<(), RadioError>>;

    /// Sets the transmit power in dBm; backends clamp to their range and
    /// return the applied value.
    fn set_tx_power(&mut self, dbm: i8) -> impl Future<Output = Result<i8, RadioError>>;

    /// Transmits `frame`. With hardware ack-wait the future completes after
    /// the ack timeout; otherwise as soon as the frame is on the air.
    fn transmit(
        &mut self,
        frame: &[u8],
        options: TxOptions,
    ) -> impl Future<Output = Result<TxResult, RadioError>>;

    /// Receives the next frame into `buf`.
    ///
    /// The future stays pending until a frame arrives; cancelling it must
    /// be safe and must not lose frames already received by hardware.
    fn receive(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<RxFrame, RadioError>>;

    /// Measures energy on the current channel for `duration_symbols`
    /// symbols and returns the peak energy level 0–255.
    fn energy_detect(
        &mut self,
        duration_symbols: u32,
    ) -> impl Future<Output = Result<u8, RadioError>>;

    /// Updates the hardware pending-address list used for the frame-pending
    /// bit in automatic acknowledgements. Backends without
    /// [`RadioCapabilities::pending_bit`] ignore this.
    fn set_pending(
        &mut self,
        short: &[ShortAddress],
        extended: &[ExtendedAddress],
    ) -> impl Future<Output = Result<(), RadioError>>;

    /// Puts the radio into its lowest-power state; frames are not received
    /// until [`Radio::wake`].
    fn sleep(&mut self) -> impl Future<Output = Result<(), RadioError>>;

    /// Wakes the radio.
    fn wake(&mut self) -> impl Future<Output = Result<(), RadioError>>;

    /// Resets the radio, keeping configuration where possible.
    fn reset(&mut self) -> impl Future<Output = Result<(), RadioError>>;
}
