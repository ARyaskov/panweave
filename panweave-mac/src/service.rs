//! Sans-I/O MAC service.
//!
//! [`MacService`] implements the MLME/MCPS behaviour Zigbee relies on
//! (IEEE 802.15.4-2015 §6, restricted per R23.2 Annex D):
//!
//! * MCPS-DATA with acknowledged transmission, `macMaxFrameRetries`
//!   retries and `macAckWaitDuration` timing (software ack-wait when the
//!   radio has none);
//! * indirect transmission to sleepy children with
//!   `macTransactionPersistenceTime` expiry, served on Data Request;
//! * MLME-POLL (data request to the parent);
//! * MLME-ASSOCIATE request / indication / response / confirm, including
//!   the `macResponseWaitTime` data-request step;
//! * MLME-SCAN active (beacon request + beacon collection) and energy
//!   detection over a channel mask;
//! * MLME-START (PAN, channel, coordinator role) and beacon transmission in
//!   response to Beacon Request when `association_permit` or the device is
//!   a router/coordinator;
//! * software address filtering and acknowledgement generation for radios
//!   that lack them.
//!
//! The service never touches hardware. The driver feeds it received frames
//! ([`MacService::on_receive`]), transmission completions
//! ([`MacService::on_tx_complete`]), energy results and time
//! ([`MacService::poll_timers`]); it drains [`MacAction`]s to execute on
//! the radio and [`MacEvent`]s to deliver upward. Data frames are handed
//! upward synchronously and zero-copy through [`RxDisposition`].

use heapless::{Deque, Vec};

use panweave_codec::{Decode, Encode, Reader, Writer};
use panweave_types::{
    Channel, ChannelMask, ChannelPage, Duration, ExtendedAddress, Instant, MacCapability,
    MacStatus, PanId, ShortAddress,
};

use crate::constants::{self, MAX_MAC_FRAME_SIZE};
use crate::frame::{
    AddressMode, Beacon, Frame, FrameControl, FrameType, FrameVersion, Header, MacAddress,
    MacCommand, SuperframeSpec,
};
use crate::ie::{EnhancedBeacon, EnhancedBeaconRequest, HEADER_TERMINATION_1};
use crate::power::{PowerControlTable, PowerEntry, PowerLimits};
use crate::radio::{RadioCapabilities, RadioConfig, RxMetadata, TxOptions, TxResult};

/// Fixed-capacity buffer holding one MAC frame.
pub type FrameBuf = Vec<u8, MAX_MAC_FRAME_SIZE>;

/// Maximum beacon payload Zigbee places in a beacon (R23.2 §3.6.8 uses
/// 15 octets; room is left for beacon appendix TLVs).
pub const MAX_BEACON_PAYLOAD: usize = 52;

/// Number of outgoing frames that can be queued before backpressure.
pub const TX_QUEUE_CAPACITY: usize = 4;

/// Number of indirect (pending) frames for sleepy children.
pub const INDIRECT_CAPACITY: usize = 8;

/// Capacity of the action and event queues.
pub const QUEUE_CAPACITY: usize = 8;

/// Links in the Power Control Information Table (Annex D.11.2.3).
pub const POWER_ENTRIES: usize = 16;

/// Entries of `mibJoiningIeeeList` mirrored into the PIB (Table D-4).
pub const JOINING_LIST_CAPACITY: usize = 16;

/// `mibJoiningPolicy` (Table D-4): whether an Enhanced Beacon Request
/// with the EB Filter IE is answered (D.11.1.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoiningPolicy {
    /// No Enhanced Beacon for joining devices.
    NoJoin,
    /// Every joining device gets an Enhanced Beacon.
    #[default]
    AllJoin,
    /// Only devices on `mibJoiningIeeeList` do.
    IeeeListJoin,
}

/// Opaque handle identifying a transmission request in its confirm.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxHandle(pub u16);

/// Errors returned by service requests.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacError {
    /// The payload does not fit in a MAC frame with the required header.
    FrameTooLong,
    /// The outgoing queue is full; retry after draining actions.
    QueueFull,
    /// The indirect transaction table is full (`TRANSACTION_OVERFLOW`).
    TransactionOverflow,
    /// Another scan or association is already in progress.
    Busy,
    /// The request is invalid in the current state (e.g. poll without a
    /// coordinator address).
    InvalidRequest,
    /// Internal encoding failure (should not happen for valid input).
    Codec,
}

/// Static configuration.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MacServiceConfig {
    /// Radio capabilities that determine which MAC functions run in
    /// software.
    pub radio: RadioCapabilities,
    /// `macMaxFrameRetries`.
    pub max_frame_retries: u8,
    /// Software acknowledgement wait time (padded above
    /// `macAckWaitDuration` to absorb driver latency).
    pub ack_wait: Duration,
    /// `macResponseWaitTime`.
    pub response_wait: Duration,
    /// `macTransactionPersistenceTime`.
    pub transaction_persistence: Duration,
    /// Extra time an end device keeps listening after a data-request ack
    /// with frame pending, waiting for the indirect frame
    /// (`macMaxFrameTotalWaitTime` is derived from CSMA parameters in the
    /// standard; a conservative fixed value is used).
    pub poll_wait: Duration,
    /// Transmit power limits for power control (Annex D.11.2.4.4).
    pub power_limits: PowerLimits,
    /// Answer Enhanced Beacon Requests with Enhanced Beacons (Annex
    /// D.11.1; optional at 2.4 GHz). Enhanced Beacons are always
    /// understood on reception.
    pub enhanced_beacons: bool,
}

impl Default for MacServiceConfig {
    fn default() -> Self {
        MacServiceConfig {
            radio: RadioCapabilities::default(),
            max_frame_retries: constants::MAX_FRAME_RETRIES,
            ack_wait: Duration::from_millis(5),
            response_wait: constants::response_wait_time(),
            transaction_persistence: constants::transaction_persistence_time(),
            poll_wait: Duration::from_millis(100),
            power_limits: PowerLimits::default(),
            enhanced_beacons: false,
        }
    }
}

/// An action the driver must perform on the radio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacAction {
    /// Transmit a frame; call [`MacService::on_tx_complete`] afterwards.
    Transmit {
        /// Handle to report completion with.
        handle: TxHandle,
        /// Encoded frame without FCS.
        frame: FrameBuf,
        /// Transmission options.
        options: TxOptions,
    },
    /// Change channel.
    SetChannel {
        /// Channel page.
        page: ChannelPage,
        /// Channel.
        channel: Channel,
    },
    /// Apply a new radio configuration.
    Configure(RadioConfig),
    /// Update the hardware pending-address list.
    SetPending {
        /// Short addresses with pending frames.
        short: Vec<ShortAddress, INDIRECT_CAPACITY>,
        /// Extended addresses with pending frames.
        extended: Vec<ExtendedAddress, INDIRECT_CAPACITY>,
    },
    /// Perform energy detection on the current channel and report via
    /// [`MacService::on_energy_result`].
    EnergyDetect {
        /// Measurement duration in symbols.
        duration_symbols: u32,
    },
}

/// Scan type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ScanKind {
    /// Active scan: beacon request then collect beacons.
    Active,
    /// Energy detection scan.
    Energy,
}

/// Status of a completed data transmission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TxStatus {
    /// Transmitted (and acknowledged when requested).
    Success,
    /// No acknowledgement after all retries.
    NoAck,
    /// Channel access failure after all retries.
    ChannelAccessFailure,
    /// Indirect transaction expired before the child polled.
    TransactionExpired,
    /// The radio reported a fault.
    RadioError,
}

/// An event for the layer above the MAC.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacEvent {
    /// A child polled and a deferred indirect transaction
    /// ([`MacService::data_request_deferred`]) is due: the poll was
    /// acknowledged with frame pending, so the caller must hand the
    /// frame over now with [`MacService::data_request`] (direct).
    IndirectReady {
        /// The deferred transaction.
        handle: TxHandle,
    },
    /// A Data Request (poll) command was received from a child (R23.2
    /// §3.6.10 keepalive by MAC data poll).
    PollIndication {
        /// The polling device.
        device: MacAddress,
    },
    /// Completion of a data request.
    DataConfirm {
        /// The handle returned by [`MacService::data_request`].
        handle: TxHandle,
        /// Outcome.
        status: TxStatus,
        /// Whether the acknowledgement had the frame-pending bit set.
        frame_pending: bool,
    },
    /// A scan finished. For energy scans the per-channel results are read
    /// with [`MacService::energy_results`].
    ScanConfirm {
        /// Which scan.
        kind: ScanKind,
        /// Channels that were scanned.
        channels: ChannelMask,
    },
    /// A device asked to associate; answer with
    /// [`MacService::associate_response`].
    AssociateIndication {
        /// Joiner extended address.
        device: ExtendedAddress,
        /// Joiner capability information.
        capability: MacCapability,
        /// Link quality of the request.
        lqi: u8,
    },
    /// Outcome of an association request.
    AssociateConfirm {
        /// Allocated short address (`0xFFFE` on failure).
        short_address: ShortAddress,
        /// Association status.
        status: MacStatus,
    },
    /// The indirect association response was delivered (or expired).
    CommStatus {
        /// The joiner the response was for.
        device: ExtendedAddress,
        /// Delivery outcome.
        status: TxStatus,
    },
    /// Outcome of a poll: `frame_pending` reports whether the parent
    /// signalled pending data; the data itself arrives through
    /// [`MacService::on_receive`].
    PollConfirm {
        /// True when the parent acknowledged with frame pending.
        frame_pending: bool,
        /// Outcome of the data request transmission.
        status: TxStatus,
    },
    /// A PAN ID conflict notification or a beacon with a conflicting PAN
    /// coordinator was observed (NWK handles resolution).
    PanIdConflict {
        /// The conflicting PAN identifier.
        pan_id: PanId,
    },
}

/// A received frame that the upper layer must handle, borrowed from the
/// driver's receive buffer.
#[derive(Clone, Copy, Debug)]
pub enum RxDisposition<'a> {
    /// Fully handled inside the MAC (ack, command, filtered, malformed).
    Handled,
    /// A data frame for this device.
    Data {
        /// Parsed frame; `payload` is the MSDU.
        frame: Frame<'a>,
        /// Reception metadata.
        meta: RxMetadata,
    },
    /// A beacon (during an active scan or spontaneously).
    Beacon {
        /// MAC header.
        header: Header<'a>,
        /// Parsed beacon body.
        beacon: Beacon<'a>,
        /// Reception metadata.
        meta: RxMetadata,
    },
    /// A frame that passed filtering but is neither data nor beacon and
    /// not consumed by the MAC (e.g. an unknown command); exposed for
    /// diagnostics.
    Other {
        /// Parsed frame.
        frame: Frame<'a>,
        /// Reception metadata.
        meta: RxMetadata,
    },
}

/// A request from the upper layer (documented on the corresponding
/// method; this enum exists for drivers that forward requests over a
/// channel).
#[derive(Clone, Debug)]
pub enum MacRequest {
    /// Poll the parent.
    Poll,
    /// Enable or disable association permit.
    SetAssociationPermit(bool),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum InFlightKind {
    Data {
        handle: TxHandle,
    },
    Beacon,
    BeaconRequest,
    AssocRequest,
    AssocDataRequest,
    Poll,
    IndirectData {
        handle: TxHandle,
    },
    /// An indirect frame the caller builds only once the child polls
    /// (see [`MacService::data_request_deferred`]).
    DeferredData {
        handle: TxHandle,
    },
    IndirectAssocResponse {
        device: ExtendedAddress,
    },
}

#[derive(Clone, Debug)]
struct InFlight {
    kind: InFlightKind,
    frame: FrameBuf,
    seq: u8,
    ack_request: bool,
    /// Negotiated transmit power for the link (D.11.2.3).
    tx_power_dbm: Option<i8>,
    retries_left: u8,
    /// Set when the radio has been asked to transmit and completion is
    /// awaited.
    awaiting_tx: bool,
    /// Deadline for a software ack.
    ack_deadline: Option<Instant>,
}

#[derive(Clone, Debug)]
struct QueuedTx {
    kind: InFlightKind,
    frame: FrameBuf,
    seq: u8,
    ack_request: bool,
    options: TxOptions,
}

#[derive(Clone, Debug)]
struct IndirectEntry {
    dst: MacAddress,
    kind: InFlightKind,
    frame: FrameBuf,
    seq: u8,
    expires: Instant,
}

#[derive(Clone, Copy, Debug)]
struct ScanState {
    kind: ScanKind,
    channels: ChannelMask,
    current: Option<Channel>,
    /// End of the dwell on the current channel.
    dwell_end: Instant,
    dwell: Duration,
    duration_symbols: u32,
    /// Channel/page to restore afterwards.
    restore: (ChannelPage, Channel),
    /// Send Enhanced Beacon Requests with this content instead of
    /// Beacon Requests (Annex D.11.1).
    enhanced: Option<EnhancedBeaconRequest>,
}

#[derive(Clone, Copy, Debug)]
enum AssocPhase {
    /// Association request queued/in flight.
    Requesting,
    /// Waiting `macResponseWaitTime` before polling for the response.
    WaitingResponseTime { at: Instant },
    /// Data request sent; waiting for the association response frame.
    Polling { deadline: Instant },
}

#[derive(Clone, Copy, Debug)]
struct AssocState {
    coordinator: MacAddress,
    pan_id: PanId,
    phase: AssocPhase,
}

/// MAC PAN information base subset used by Zigbee.
#[derive(Clone, Debug)]
pub struct Pib {
    /// `macPANId`.
    pub pan_id: PanId,
    /// `macShortAddress`.
    pub short_address: ShortAddress,
    /// `macExtendedAddress`.
    pub extended_address: ExtendedAddress,
    /// `macCoordShortAddress` (the parent for end devices).
    pub coord_short_address: ShortAddress,
    /// `macCoordExtendedAddress`.
    pub coord_extended_address: ExtendedAddress,
    /// True when this device is the PAN coordinator.
    pub pan_coordinator: bool,
    /// True for routers and the coordinator (respond to beacon requests).
    pub beacon_capable: bool,
    /// `macAssociationPermit`.
    pub association_permit: bool,
    /// `macRxOnWhenIdle`.
    pub rx_on_when_idle: bool,
    /// Current channel page.
    pub page: ChannelPage,
    /// Current channel.
    pub channel: Channel,
    /// `macBeaconPayload`.
    pub beacon_payload: Vec<u8, MAX_BEACON_PAYLOAD>,
    /// `macDSN`.
    pub dsn: u8,
    /// `macBSN`.
    pub bsn: u8,
    /// `mibJoiningPolicy` (Table D-4), mirrored from the network layer
    /// that owns the joining list and its expiry.
    pub joining_policy: JoiningPolicy,
    /// `mibJoiningIeeeList`.
    pub joining_ieee_list: Vec<ExtendedAddress, JOINING_LIST_CAPACITY>,
}

impl Default for Pib {
    fn default() -> Self {
        Pib {
            pan_id: PanId::BROADCAST,
            short_address: ShortAddress::NO_SHORT_ADDRESS,
            extended_address: ExtendedAddress::ZERO,
            coord_short_address: ShortAddress::NO_SHORT_ADDRESS,
            coord_extended_address: ExtendedAddress::ZERO,
            pan_coordinator: false,
            beacon_capable: false,
            association_permit: false,
            rx_on_when_idle: true,
            page: ChannelPage::PAGE_0,
            channel: Channel::DEFAULT_2_4GHZ,
            beacon_payload: Vec::new(),
            dsn: 0,
            bsn: 0,
            joining_policy: JoiningPolicy::AllJoin,
            joining_ieee_list: Vec::new(),
        }
    }
}

/// The MAC service state machine.
pub struct MacService {
    config: MacServiceConfig,
    /// PAN information base.
    pub pib: Pib,
    in_flight: Option<InFlight>,
    tx_queue: Deque<QueuedTx, TX_QUEUE_CAPACITY>,
    indirect: Vec<IndirectEntry, INDIRECT_CAPACITY>,
    actions: Deque<MacAction, QUEUE_CAPACITY>,
    events: Deque<MacEvent, QUEUE_CAPACITY>,
    scan: Option<ScanState>,
    assoc: Option<AssocState>,
    energy: [u8; 27],
    next_handle: u16,
    /// Deadline while waiting for indirect data after a poll ack with
    /// frame pending.
    poll_wait_until: Option<Instant>,
    /// True when the radio configuration needs re-applying.
    config_dirty: bool,
    now: Instant,
    /// Power Control Information Table (Annex D.11.2.3).
    power: PowerControlTable<POWER_ENTRIES>,
}

impl MacService {
    /// Creates a service with the given configuration and extended
    /// address. Sequence numbers should be seeded with
    /// [`MacService::seed_sequence_numbers`].
    pub fn new(config: MacServiceConfig, extended_address: ExtendedAddress) -> Self {
        let mut pib = Pib::default();
        pib.extended_address = extended_address;
        let config_limits = config.power_limits;
        MacService {
            config,
            pib,
            in_flight: None,
            tx_queue: Deque::new(),
            indirect: Vec::new(),
            actions: Deque::new(),
            events: Deque::new(),
            scan: None,
            assoc: None,
            energy: [0; 27],
            next_handle: 1,
            poll_wait_until: None,
            config_dirty: true,
            now: Instant::ZERO,
            power: PowerControlTable::new(config_limits),
        }
    }

    /// Seeds `macDSN` and `macBSN` with random values (IEEE 802.15.4
    /// requires random initial sequence numbers).
    pub fn seed_sequence_numbers(&mut self, dsn: u8, bsn: u8) {
        self.pib.dsn = dsn;
        self.pib.bsn = bsn;
    }

    /// The configuration in use.
    pub const fn config(&self) -> &MacServiceConfig {
        &self.config
    }

    // ------------------------------------------------------------------
    // Output queues
    // ------------------------------------------------------------------

    /// Takes the next radio action to execute.
    pub fn next_action(&mut self) -> Option<MacAction> {
        self.flush_config();
        self.start_next_transmission();
        self.actions.pop_front()
    }

    /// Takes the next event for the upper layer.
    pub fn next_event(&mut self) -> Option<MacEvent> {
        self.events.pop_front()
    }

    /// True when there are pending actions or events.
    pub fn has_output(&self) -> bool {
        !self.actions.is_empty() || !self.events.is_empty() || self.config_dirty
    }

    /// The earliest instant at which [`MacService::poll_timers`] must be
    /// called, if any timer is armed.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut consider = |i: Instant| {
            next = Some(next.map_or(i, |n| if i < n { i } else { n }));
        };
        if let Some(f) = &self.in_flight
            && let Some(d) = f.ack_deadline
        {
            consider(d);
        }
        for e in &self.indirect {
            consider(e.expires);
        }
        if let Some(s) = &self.scan
            && s.current.is_some()
        {
            consider(s.dwell_end);
        }
        if let Some(a) = &self.assoc {
            match a.phase {
                AssocPhase::WaitingResponseTime { at } => consider(at),
                AssocPhase::Polling { deadline } => consider(deadline),
                AssocPhase::Requesting => {}
            }
        }
        if let Some(p) = self.poll_wait_until {
            consider(p);
        }
        next
    }

    fn push_event(&mut self, ev: MacEvent) {
        // Events are protocol-critical (confirms); the queue is sized so
        // that a driver draining after every input never overflows. If it
        // does, the oldest event is dropped and a debug assertion fires.
        if self.events.push_back(ev).is_err() {
            debug_assert!(false, "MAC event queue overflow");
            let _ = self.events.pop_front();
            let _ = self.events.push_back(ev);
        }
    }

    fn push_action(&mut self, a: MacAction) {
        if let Err(a) = self.actions.push_back(a) {
            debug_assert!(false, "MAC action queue overflow");
            let _ = self.actions.pop_front();
            let _ = self.actions.push_back(a);
        }
    }

    fn radio_config(&self) -> RadioConfig {
        RadioConfig {
            pan_id: self.pib.pan_id,
            short_address: self.pib.short_address,
            extended_address: self.pib.extended_address,
            pan_coordinator: self.pib.pan_coordinator,
            rx_on_when_idle: self.pib.rx_on_when_idle,
            promiscuous: false,
        }
    }

    fn flush_config(&mut self) {
        if self.config_dirty {
            self.config_dirty = false;
            let cfg = self.radio_config();
            self.push_action(MacAction::Configure(cfg));
        }
    }

    // ------------------------------------------------------------------
    // PIB management (MLME-START / MLME-SET)
    // ------------------------------------------------------------------

    /// Starts operating on `pan_id` / `channel` (MLME-START). `coordinator`
    /// marks the PAN coordinator; `beacon_capable` makes the device answer
    /// beacon requests (routers and the coordinator).
    pub fn start(
        &mut self,
        pan_id: PanId,
        page: ChannelPage,
        channel: Channel,
        short_address: ShortAddress,
        coordinator: bool,
        beacon_capable: bool,
    ) {
        self.pib.pan_id = pan_id;
        self.pib.page = page;
        self.pib.channel = channel;
        self.pib.short_address = short_address;
        self.pib.pan_coordinator = coordinator;
        self.pib.beacon_capable = beacon_capable;
        self.push_action(MacAction::SetChannel { page, channel });
        self.config_dirty = true;
    }

    /// Sets the local short address (after association).
    pub fn set_short_address(&mut self, addr: ShortAddress) {
        self.pib.short_address = addr;
        self.config_dirty = true;
    }

    /// Sets the PAN identifier (after association or PAN ID update).
    pub fn set_pan_id(&mut self, pan_id: PanId) {
        self.pib.pan_id = pan_id;
        self.config_dirty = true;
    }

    /// Changes channel (frequency agility).
    pub fn set_channel(&mut self, page: ChannelPage, channel: Channel) {
        self.pib.page = page;
        self.pib.channel = channel;
        self.push_action(MacAction::SetChannel { page, channel });
    }

    /// The Power Control Information Table (Annex D.11.2.3).
    pub fn power_table(&self) -> &PowerControlTable<POWER_ENTRIES> {
        &self.power
    }

    /// The Power Control Information Table, for the network layer's
    /// MLME-SET-POWER-INFORMATION-TABLE.request.
    pub fn power_table_mut(&mut self) -> &mut PowerControlTable<POWER_ENTRIES> {
        &mut self.power
    }

    /// Sets the parent (coordinator) addresses for end devices.
    pub fn set_coordinator(&mut self, short: ShortAddress, extended: ExtendedAddress) {
        self.pib.coord_short_address = short;
        self.pib.coord_extended_address = extended;
    }

    /// Sets `macRxOnWhenIdle`.
    pub fn set_rx_on_when_idle(&mut self, on: bool) {
        self.pib.rx_on_when_idle = on;
        self.config_dirty = true;
    }

    /// Sets `macAssociationPermit`.
    pub fn set_association_permit(&mut self, permit: bool) {
        self.pib.association_permit = permit;
    }

    /// Sets the beacon payload; longer payloads are truncated to
    /// [`MAX_BEACON_PAYLOAD`] and reported by the returned `false`.
    pub fn set_beacon_payload(&mut self, payload: &[u8]) -> bool {
        self.pib.beacon_payload.clear();
        let n = payload.len().min(MAX_BEACON_PAYLOAD);
        let _ = self
            .pib
            .beacon_payload
            .extend_from_slice(payload.get(..n).unwrap_or(&[]));
        n == payload.len()
    }

    /// Resets all transient state (MLME-RESET), keeping the extended
    /// address and configuration.
    pub fn reset(&mut self) {
        let ext = self.pib.extended_address;
        self.pib = Pib::default();
        self.pib.extended_address = ext;
        self.in_flight = None;
        self.tx_queue.clear();
        self.indirect.clear();
        self.scan = None;
        self.assoc = None;
        self.poll_wait_until = None;
        self.config_dirty = true;
    }

    // ------------------------------------------------------------------
    // Sequence numbers and header helpers
    // ------------------------------------------------------------------

    fn next_dsn(&mut self) -> u8 {
        let v = self.pib.dsn;
        self.pib.dsn = self.pib.dsn.wrapping_add(1);
        v
    }

    fn next_bsn(&mut self) -> u8 {
        let v = self.pib.bsn;
        self.pib.bsn = self.pib.bsn.wrapping_add(1);
        v
    }

    fn own_address(&self) -> MacAddress {
        if self.pib.short_address == ShortAddress::NO_SHORT_ADDRESS {
            MacAddress::Extended(self.pib.extended_address)
        } else {
            MacAddress::Short(self.pib.short_address)
        }
    }

    fn alloc_handle(&mut self) -> TxHandle {
        let h = TxHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        h
    }

    fn build_frame(header: &Header<'_>, body: &impl Encode) -> Result<FrameBuf, MacError> {
        let mut buf = FrameBuf::new();
        let total = header.encoded_len() + body.encoded_len();
        if total > MAX_MAC_FRAME_SIZE {
            return Err(MacError::FrameTooLong);
        }
        buf.resize_default(total)
            .map_err(|_| MacError::FrameTooLong)?;
        let mut w = Writer::new(&mut buf);
        header.encode(&mut w).map_err(|_| MacError::Codec)?;
        body.encode(&mut w).map_err(|_| MacError::Codec)?;
        Ok(buf)
    }

    fn enqueue(&mut self, q: QueuedTx) -> Result<(), MacError> {
        self.tx_queue.push_back(q).map_err(|_| MacError::QueueFull)
    }

    // ------------------------------------------------------------------
    // MCPS-DATA
    // ------------------------------------------------------------------

    /// Queues a data frame (MCPS-DATA.request).
    ///
    /// `dst_pan` is the destination PAN; the source PAN is `macPANId` and
    /// is compressed when equal. When `indirect` is set the frame is held
    /// for the addressed sleepy child until it polls or the transaction
    /// expires. The returned handle appears in the matching
    /// [`MacEvent::DataConfirm`].
    ///
    /// May transmit; does not persist state.
    pub fn data_request(
        &mut self,
        dst_pan: PanId,
        dst: MacAddress,
        payload: &[u8],
        ack_request: bool,
        indirect: bool,
    ) -> Result<TxHandle, MacError> {
        let seq = self.next_dsn();
        let header = Header::new(
            FrameType::Data,
            seq,
            dst_pan,
            dst,
            self.pib.pan_id,
            self.own_address(),
        );
        let ack_request = ack_request && !dst.is_broadcast();
        let header = Header {
            frame_control: header.frame_control.with_ack_request(ack_request),
            ..header
        };
        let frame = Self::build_frame(&header, &payload)?;
        let handle = self.alloc_handle();
        if indirect {
            self.add_indirect(IndirectEntry {
                dst,
                kind: InFlightKind::IndirectData { handle },
                frame,
                seq,
                expires: self.now + self.config.transaction_persistence,
            })?;
        } else {
            self.enqueue(QueuedTx {
                kind: InFlightKind::Data { handle },
                frame,
                seq,
                ack_request,
                options: TxOptions {
                    tx_power_dbm: self.power.tx_power_for(&dst),
                    ..if ack_request {
                        TxOptions::ACKED
                    } else {
                        TxOptions::UNACKED
                    }
                },
            })?;
        }
        Ok(handle)
    }

    /// Registers an indirect transaction whose frame is produced only
    /// when the child polls: the pending-address list and the frame
    /// pending bit of the poll acknowledgement include `dst`, and the
    /// poll raises [`MacEvent::IndirectReady`] instead of transmitting.
    /// The caller then secures the frame with a fresh counter and sends
    /// it with [`data_request`](Self::data_request) while the child is
    /// listening, so a frame secured at queue time can never be
    /// overtaken by later transmissions (NWK freshness, R23.2 §3.6.2.2).
    /// Expires like any indirect transaction (`DataConfirm` with
    /// `TransactionExpired`).
    pub fn data_request_deferred(&mut self, dst: MacAddress) -> Result<TxHandle, MacError> {
        let handle = self.alloc_handle();
        self.add_indirect(IndirectEntry {
            dst,
            kind: InFlightKind::DeferredData { handle },
            frame: FrameBuf::new(),
            seq: 0,
            expires: self.now + self.config.transaction_persistence,
        })?;
        Ok(handle)
    }

    /// Queues an inter-PAN data frame (ZCL8 §13.3.4.5): destination PAN
    /// `dst_pan` (the broadcast PAN for touchlink), an explicit source
    /// PAN and the extended source address, never indirect.
    ///
    /// May transmit; does not persist state.
    pub fn data_request_inter_pan(
        &mut self,
        dst_pan: PanId,
        dst: MacAddress,
        src_pan: PanId,
        payload: &[u8],
        ack_request: bool,
    ) -> Result<TxHandle, MacError> {
        let seq = self.next_dsn();
        let header = Header::new(
            FrameType::Data,
            seq,
            dst_pan,
            dst,
            src_pan,
            MacAddress::Extended(self.pib.extended_address),
        );
        let ack_request = ack_request && !dst.is_broadcast();
        let header = Header {
            frame_control: header.frame_control.with_ack_request(ack_request),
            ..header
        };
        let frame = Self::build_frame(&header, &payload)?;
        let handle = self.alloc_handle();
        self.enqueue(QueuedTx {
            kind: InFlightKind::Data { handle },
            frame,
            seq,
            ack_request,
            options: if ack_request {
                TxOptions::ACKED
            } else {
                TxOptions::UNACKED
            },
        })?;
        Ok(handle)
    }

    /// Removes a queued indirect frame (MCPS-PURGE).
    pub fn purge(&mut self, handle: TxHandle) -> bool {
        let before = self.indirect.len();
        self.indirect.retain(|e| {
            !matches!(
                e.kind,
                InFlightKind::IndirectData { handle: h } | InFlightKind::DeferredData { handle: h }
                    if h == handle
            )
        });
        let removed = self.indirect.len() != before;
        if removed {
            self.update_pending_list();
        }
        removed
    }

    fn add_indirect(&mut self, entry: IndirectEntry) -> Result<(), MacError> {
        self.indirect
            .push(entry)
            .map_err(|_| MacError::TransactionOverflow)?;
        self.update_pending_list();
        Ok(())
    }

    fn update_pending_list(&mut self) {
        if !self.config.radio.pending_bit {
            return;
        }
        let mut short = Vec::new();
        let mut extended = Vec::new();
        for e in &self.indirect {
            match e.dst {
                MacAddress::Short(s) => {
                    let _ = short.push(s);
                }
                MacAddress::Extended(x) => {
                    let _ = extended.push(x);
                }
                MacAddress::None => {}
            }
        }
        self.push_action(MacAction::SetPending { short, extended });
    }

    fn has_indirect_for(&self, addr: MacAddress, ext: Option<ExtendedAddress>) -> bool {
        self.indirect.iter().any(|e| {
            e.dst == addr || matches!((e.dst, ext), (MacAddress::Extended(x), Some(y)) if x == y)
        })
    }

    // ------------------------------------------------------------------
    // MLME-POLL
    // ------------------------------------------------------------------

    /// Sends a Data Request to the parent (MLME-POLL.request).
    ///
    /// May transmit.
    pub fn poll(&mut self) -> Result<(), MacError> {
        let dst = if self.pib.coord_short_address != ShortAddress::NO_SHORT_ADDRESS {
            MacAddress::Short(self.pib.coord_short_address)
        } else if self.pib.coord_extended_address != ExtendedAddress::ZERO {
            MacAddress::Extended(self.pib.coord_extended_address)
        } else {
            return Err(MacError::InvalidRequest);
        };
        let seq = self.next_dsn();
        let header = Header::new(
            FrameType::Command,
            seq,
            self.pib.pan_id,
            dst,
            self.pib.pan_id,
            self.own_address(),
        );
        let header = Header {
            frame_control: header.frame_control.with_ack_request(true),
            ..header
        };
        let frame = Self::build_frame(&header, &MacCommand::DataRequest)?;
        self.enqueue(QueuedTx {
            kind: InFlightKind::Poll,
            frame,
            seq,
            ack_request: true,
            options: TxOptions::ACKED,
        })
    }

    // ------------------------------------------------------------------
    // MLME-SCAN
    // ------------------------------------------------------------------

    /// Starts an active or energy scan over `channels` with the IEEE
    /// scan-duration exponent `duration` (R23.2 Annex D.9 recommends 3 for
    /// 2.4 GHz). Beacons are delivered through [`RxDisposition::Beacon`];
    /// completion through [`MacEvent::ScanConfirm`].
    ///
    /// May transmit (beacon requests) and changes channel.
    pub fn scan(
        &mut self,
        kind: ScanKind,
        channels: ChannelMask,
        duration: u8,
    ) -> Result<(), MacError> {
        self.scan_with(kind, channels, duration, None)
    }

    /// An active scan that sends Enhanced Beacon Requests (Annex
    /// D.11.1): `request` carries the EB Filter IE (joining) or the
    /// Rejoin IE (rejoining); the TX Power IE is filled with the
    /// maximum power when absent (D.11.2.4.2).
    pub fn scan_enhanced(
        &mut self,
        channels: ChannelMask,
        duration: u8,
        request: EnhancedBeaconRequest,
    ) -> Result<(), MacError> {
        let request = EnhancedBeaconRequest {
            tx_power: request.tx_power.or(Some(self.power.limits.max_dbm)),
            ..request
        };
        self.scan_with(ScanKind::Active, channels, duration, Some(request))
    }

    fn scan_with(
        &mut self,
        kind: ScanKind,
        channels: ChannelMask,
        duration: u8,
        enhanced: Option<EnhancedBeaconRequest>,
    ) -> Result<(), MacError> {
        if self.scan.is_some() || self.assoc.is_some() {
            return Err(MacError::Busy);
        }
        if channels.is_empty() {
            return Err(MacError::InvalidRequest);
        }
        let dwell = constants::scan_duration_per_channel(duration);
        let n = duration.min(14);
        let duration_symbols =
            u32::try_from(constants::BASE_SUPERFRAME_DURATION_SYMBOLS * ((1u64 << n) + 1))
                .unwrap_or(u32::MAX);
        self.energy = [0; 27];
        self.scan = Some(ScanState {
            kind,
            channels,
            current: None,
            dwell_end: self.now,
            dwell,
            duration_symbols,
            restore: (self.pib.page, self.pib.channel),
            enhanced,
        });
        self.scan_next_channel();
        Ok(())
    }

    /// Per-channel energy levels from the last energy scan, indexed by
    /// channel number.
    pub const fn energy_results(&self) -> &[u8; 27] {
        &self.energy
    }

    fn scan_next_channel(&mut self) {
        let Some(mut s) = self.scan else { return };
        let next = s
            .channels
            .iter()
            .find(|c| s.current.is_none_or(|cur| c.raw() > cur.raw()));
        match next {
            Some(ch) => {
                s.current = Some(ch);
                s.dwell_end = self.now + s.dwell;
                self.scan = Some(s);
                self.push_action(MacAction::SetChannel {
                    page: self.pib.page,
                    channel: ch,
                });
                match s.kind {
                    ScanKind::Active if s.enhanced.is_some() => {
                        self.send_enhanced_beacon_request(s.enhanced.unwrap_or_default());
                    }
                    ScanKind::Active => {
                        // Beacon request: broadcast PAN, broadcast short dst,
                        // no source address.
                        let seq = self.next_dsn();
                        let header = Header::new(
                            FrameType::Command,
                            seq,
                            PanId::BROADCAST,
                            MacAddress::Short(ShortAddress::BROADCAST_ALL),
                            PanId::BROADCAST,
                            MacAddress::None,
                        );
                        if let Ok(frame) = Self::build_frame(&header, &MacCommand::BeaconRequest) {
                            let _ = self.enqueue(QueuedTx {
                                kind: InFlightKind::BeaconRequest,
                                frame,
                                seq,
                                ack_request: false,
                                options: TxOptions::UNACKED,
                            });
                        }
                    }
                    ScanKind::Energy => {
                        self.push_action(MacAction::EnergyDetect {
                            duration_symbols: s.duration_symbols,
                        });
                    }
                }
            }
            None => {
                self.scan = None;
                let (page, channel) = s.restore;
                self.push_action(MacAction::SetChannel { page, channel });
                self.push_event(MacEvent::ScanConfirm {
                    kind: s.kind,
                    channels: s.channels,
                });
            }
        }
    }

    /// Reports the result of an [`MacAction::EnergyDetect`].
    pub fn on_energy_result(&mut self, level: u8) {
        if let Some(s) = self.scan
            && s.kind == ScanKind::Energy
            && let Some(ch) = s.current
            && let Some(slot) = self.energy.get_mut(usize::from(ch.raw()))
        {
            *slot = (*slot).max(level);
            // Energy scans advance as soon as the measurement completes.
            self.scan_next_channel();
        }
    }

    /// True while a scan is running.
    pub const fn scanning(&self) -> bool {
        self.scan.is_some()
    }

    // ------------------------------------------------------------------
    // MLME-ASSOCIATE
    // ------------------------------------------------------------------

    /// Starts association with `coordinator` on `pan_id`
    /// (MLME-ASSOCIATE.request). The device must already be on the
    /// coordinator's channel. Outcome: [`MacEvent::AssociateConfirm`].
    ///
    /// May transmit.
    pub fn associate(
        &mut self,
        pan_id: PanId,
        coordinator: MacAddress,
        capability: MacCapability,
    ) -> Result<(), MacError> {
        if self.scan.is_some() || self.assoc.is_some() {
            return Err(MacError::Busy);
        }
        if coordinator == MacAddress::None {
            return Err(MacError::InvalidRequest);
        }
        // R23.2 Annex D.4 Table D-1: destination PAN + coordinator
        // address, source PAN 0xFFFF with the extended address.
        let seq = self.next_dsn();
        let header = Header::new(
            FrameType::Command,
            seq,
            pan_id,
            coordinator,
            PanId::BROADCAST,
            MacAddress::Extended(self.pib.extended_address),
        );
        let header = Header {
            frame_control: header.frame_control.with_ack_request(true),
            ..header
        };
        let frame = Self::build_frame(&header, &MacCommand::AssociationRequest { capability })?;
        self.enqueue(QueuedTx {
            kind: InFlightKind::AssocRequest,
            frame,
            seq,
            ack_request: true,
            options: TxOptions::ACKED,
        })?;
        self.assoc = Some(AssocState {
            coordinator,
            pan_id,
            phase: AssocPhase::Requesting,
        });
        self.pib.pan_id = pan_id;
        match coordinator {
            MacAddress::Short(s) => self.pib.coord_short_address = s,
            MacAddress::Extended(e) => self.pib.coord_extended_address = e,
            MacAddress::None => {}
        }
        self.config_dirty = true;
        Ok(())
    }

    /// Answers an [`MacEvent::AssociateIndication`]
    /// (MLME-ASSOCIATE.response). The response is transmitted indirectly
    /// when the joiner polls; delivery is reported by
    /// [`MacEvent::CommStatus`].
    pub fn associate_response(
        &mut self,
        device: ExtendedAddress,
        short_address: ShortAddress,
        status: MacStatus,
    ) -> Result<(), MacError> {
        // R23.2 Annex D.4 Table D-3: intra-PAN, both extended addresses.
        let seq = self.next_dsn();
        let header = Header::new(
            FrameType::Command,
            seq,
            self.pib.pan_id,
            MacAddress::Extended(device),
            self.pib.pan_id,
            MacAddress::Extended(self.pib.extended_address),
        );
        let header = Header {
            frame_control: header.frame_control.with_ack_request(true),
            ..header
        };
        let frame = Self::build_frame(
            &header,
            &MacCommand::AssociationResponse {
                short_address,
                status,
            },
        )?;
        self.add_indirect(IndirectEntry {
            dst: MacAddress::Extended(device),
            kind: InFlightKind::IndirectAssocResponse { device },
            frame,
            seq,
            expires: self.now + self.config.transaction_persistence,
        })
    }

    // ------------------------------------------------------------------
    // Transmission pipeline
    // ------------------------------------------------------------------

    fn start_next_transmission(&mut self) {
        if self.in_flight.is_some() {
            return;
        }
        let Some(q) = self.tx_queue.pop_front() else {
            return;
        };
        let handle_for_action = match q.kind {
            InFlightKind::Data { handle } | InFlightKind::IndirectData { handle } => handle,
            _ => TxHandle(0),
        };
        let retries = if q.ack_request && !self.config.radio.retries {
            self.config.max_frame_retries
        } else {
            0
        };
        self.in_flight = Some(InFlight {
            kind: q.kind,
            frame: q.frame.clone(),
            seq: q.seq,
            ack_request: q.ack_request,
            tx_power_dbm: q.options.tx_power_dbm,
            retries_left: retries,
            awaiting_tx: true,
            ack_deadline: None,
        });
        self.push_action(MacAction::Transmit {
            handle: handle_for_action,
            frame: q.frame,
            options: q.options,
        });
    }

    /// Reports completion of a [`MacAction::Transmit`].
    pub fn on_tx_complete(&mut self, result: Result<TxResult, crate::radio::RadioError>) {
        let Some(mut f) = self.in_flight.take() else {
            return;
        };
        if !f.awaiting_tx {
            self.in_flight = Some(f);
            return;
        }
        f.awaiting_tx = false;
        match result {
            Err(crate::radio::RadioError::ChannelAccessFailure) => {
                if f.retries_left > 0 {
                    f.retries_left -= 1;
                    self.retransmit(f);
                } else {
                    self.finish_in_flight(f, TxStatus::ChannelAccessFailure, false);
                }
            }
            Err(_) => self.finish_in_flight(f, TxStatus::RadioError, false),
            Ok(res) => {
                if !f.ack_request {
                    self.finish_in_flight(f, TxStatus::Success, false);
                } else if self.config.radio.ack_wait {
                    if res.acked {
                        self.finish_in_flight(f, TxStatus::Success, res.frame_pending);
                    } else if f.retries_left > 0 && !self.config.radio.retries {
                        f.retries_left -= 1;
                        self.retransmit(f);
                    } else {
                        self.finish_in_flight(f, TxStatus::NoAck, false);
                    }
                } else {
                    f.ack_deadline = Some(self.now + self.config.ack_wait);
                    self.in_flight = Some(f);
                }
            }
        }
    }

    fn retransmit(&mut self, mut f: InFlight) {
        f.awaiting_tx = true;
        f.ack_deadline = None;
        let handle = match f.kind {
            InFlightKind::Data { handle } | InFlightKind::IndirectData { handle } => handle,
            _ => TxHandle(0),
        };
        let frame = f.frame.clone();
        let options = TxOptions {
            tx_power_dbm: f.tx_power_dbm,
            ..if f.ack_request {
                TxOptions::ACKED
            } else {
                TxOptions::UNACKED
            }
        };
        self.in_flight = Some(f);
        self.push_action(MacAction::Transmit {
            handle,
            frame,
            options,
        });
    }

    fn finish_in_flight(&mut self, f: InFlight, status: TxStatus, frame_pending: bool) {
        match f.kind {
            InFlightKind::Data { handle }
            | InFlightKind::IndirectData { handle }
            | InFlightKind::DeferredData { handle } => {
                self.push_event(MacEvent::DataConfirm {
                    handle,
                    status,
                    frame_pending,
                });
            }
            InFlightKind::Beacon | InFlightKind::BeaconRequest => {}
            InFlightKind::AssocRequest => {
                if status == TxStatus::Success {
                    if let Some(a) = &mut self.assoc {
                        a.phase = AssocPhase::WaitingResponseTime {
                            at: self.now + self.config.response_wait,
                        };
                    }
                } else {
                    self.assoc = None;
                    self.push_event(MacEvent::AssociateConfirm {
                        short_address: ShortAddress::NO_SHORT_ADDRESS,
                        status: match status {
                            TxStatus::NoAck => MacStatus::NoAck,
                            TxStatus::ChannelAccessFailure => MacStatus::ChannelAccessFailure,
                            _ => MacStatus::TransactionExpired,
                        },
                    });
                }
            }
            InFlightKind::AssocDataRequest => {
                if status == TxStatus::Success && frame_pending {
                    if let Some(a) = &mut self.assoc {
                        a.phase = AssocPhase::Polling {
                            deadline: self.now + self.config.poll_wait,
                        };
                    }
                } else {
                    self.assoc = None;
                    self.push_event(MacEvent::AssociateConfirm {
                        short_address: ShortAddress::NO_SHORT_ADDRESS,
                        status: if status == TxStatus::Success {
                            MacStatus::NoData
                        } else {
                            MacStatus::NoAck
                        },
                    });
                }
            }
            InFlightKind::Poll => {
                if status == TxStatus::Success && frame_pending {
                    self.poll_wait_until = Some(self.now + self.config.poll_wait);
                }
                self.push_event(MacEvent::PollConfirm {
                    frame_pending,
                    status,
                });
            }
            InFlightKind::IndirectAssocResponse { device } => {
                self.push_event(MacEvent::CommStatus { device, status });
            }
        }
    }

    // ------------------------------------------------------------------
    // Timers
    // ------------------------------------------------------------------

    /// Advances time and fires expired timers. Must be called at least by
    /// [`MacService::next_deadline`] and before feeding inputs so that
    /// timestamps are current.
    pub fn poll_timers(&mut self, now: Instant) {
        self.now = now;
        self.power.expire(now);

        // Software ack timeout.
        if let Some(f) = &self.in_flight
            && let Some(d) = f.ack_deadline
            && now.has_reached(d)
            && let Some(mut f) = self.in_flight.take()
        {
            if f.retries_left > 0 {
                f.retries_left -= 1;
                self.retransmit(f);
            } else {
                self.finish_in_flight(f, TxStatus::NoAck, false);
            }
        }

        // Indirect transaction expiry.
        let mut expired: Vec<InFlightKind, INDIRECT_CAPACITY> = Vec::new();
        self.indirect.retain(|e| {
            if now.has_reached(e.expires) {
                let _ = expired.push(e.kind);
                false
            } else {
                true
            }
        });
        if !expired.is_empty() {
            self.update_pending_list();
            for k in expired {
                match k {
                    InFlightKind::IndirectData { handle }
                    | InFlightKind::DeferredData { handle } => {
                        self.push_event(MacEvent::DataConfirm {
                            handle,
                            status: TxStatus::TransactionExpired,
                            frame_pending: false,
                        });
                    }
                    InFlightKind::IndirectAssocResponse { device } => {
                        self.push_event(MacEvent::CommStatus {
                            device,
                            status: TxStatus::TransactionExpired,
                        });
                    }
                    _ => {}
                }
            }
        }

        // Active scan dwell.
        if let Some(s) = self.scan
            && s.kind == ScanKind::Active
            && s.current.is_some()
            && now.has_reached(s.dwell_end)
        {
            self.scan_next_channel();
        }

        // Association phases.
        if let Some(a) = self.assoc {
            match a.phase {
                AssocPhase::WaitingResponseTime { at } if now.has_reached(at) => {
                    let seq = self.next_dsn();
                    // Table D-2: data request to the coordinator with our
                    // extended address, intra-PAN.
                    let header = Header::new(
                        FrameType::Command,
                        seq,
                        a.pan_id,
                        a.coordinator,
                        a.pan_id,
                        MacAddress::Extended(self.pib.extended_address),
                    );
                    let header = Header {
                        frame_control: header.frame_control.with_ack_request(true),
                        ..header
                    };
                    if let Ok(frame) = Self::build_frame(&header, &MacCommand::DataRequest) {
                        if self
                            .enqueue(QueuedTx {
                                kind: InFlightKind::AssocDataRequest,
                                frame,
                                seq,
                                ack_request: true,
                                options: TxOptions::ACKED,
                            })
                            .is_ok()
                        {
                            if let Some(a) = &mut self.assoc {
                                a.phase = AssocPhase::Polling {
                                    deadline: now + self.config.response_wait,
                                };
                            }
                        } else {
                            self.assoc = None;
                            self.push_event(MacEvent::AssociateConfirm {
                                short_address: ShortAddress::NO_SHORT_ADDRESS,
                                status: MacStatus::TransactionOverflow,
                            });
                        }
                    }
                }
                AssocPhase::Polling { deadline } if now.has_reached(deadline) => {
                    self.assoc = None;
                    self.push_event(MacEvent::AssociateConfirm {
                        short_address: ShortAddress::NO_SHORT_ADDRESS,
                        status: MacStatus::NoData,
                    });
                }
                _ => {}
            }
        }

        if let Some(p) = self.poll_wait_until
            && now.has_reached(p)
        {
            self.poll_wait_until = None;
        }
    }

    /// True while the end device should keep its receiver on after a poll
    /// (parent signalled pending data) or a transmission is in progress.
    pub fn needs_receiver(&self) -> bool {
        self.poll_wait_until.is_some()
            || self.in_flight.is_some()
            || !self.tx_queue.is_empty()
            || self.assoc.is_some()
            || self.scan.is_some()
    }

    // ------------------------------------------------------------------
    // Reception
    // ------------------------------------------------------------------

    fn addressed_to_me(&self, h: &Header<'_>) -> bool {
        if self.config.radio.address_filter && self.scan.is_none() {
            return true;
        }
        let dst_pan_ok = match h.effective_dst_pan() {
            Some(p) => p == self.pib.pan_id || p == PanId::BROADCAST,
            None => false,
        };
        match h.dst {
            MacAddress::None => {
                // Beacons and frames to the PAN coordinator.
                h.frame_control.frame_type() == FrameType::Beacon
                    || (self.pib.pan_coordinator && h.effective_src_pan() == Some(self.pib.pan_id))
            }
            MacAddress::Short(s) => {
                dst_pan_ok
                    && (s == ShortAddress::BROADCAST_ALL
                        || (s == self.pib.short_address && s != ShortAddress::NO_SHORT_ADDRESS))
            }
            MacAddress::Extended(e) => dst_pan_ok && e == self.pib.extended_address,
        }
    }

    fn send_ack(&mut self, seq: u8, frame_pending: bool) {
        if self.config.radio.auto_ack {
            return;
        }
        let header = Header::ack(seq, frame_pending);
        if let Ok(frame) = Self::build_frame(&header, &&[][..]) {
            // Acks bypass the queue: they must go out immediately and never
            // wait behind pending data.
            self.push_action(MacAction::Transmit {
                handle: TxHandle(0),
                frame,
                options: TxOptions::IMMEDIATE,
            });
        }
    }

    /// Processes a received frame. `bytes` excludes the FCS.
    ///
    /// Returns what the upper layer must handle; data and beacons are
    /// borrowed from `bytes`.
    pub fn on_receive<'a>(&mut self, bytes: &'a [u8], meta: RxMetadata) -> RxDisposition<'a> {
        let mut r = Reader::new(bytes);
        let Ok(frame) = Frame::decode(&mut r) else {
            // Malformed: silently discard (R23.2 §1.2.5).
            return RxDisposition::Handled;
        };
        let h = frame.header;

        // Acknowledgements are matched against the in-flight frame.
        if h.frame_control.frame_type() == FrameType::Ack {
            self.on_ack(h.sequence, h.frame_control.frame_pending());
            return RxDisposition::Handled;
        }

        if !self.addressed_to_me(&h) {
            return RxDisposition::Handled;
        }

        // Frames from our own short address are echoes; ignore.
        match h.frame_control.frame_type() {
            FrameType::Beacon
                if h.frame_control.version() == FrameVersion::V2015
                    && h.frame_control.ie_present() =>
            {
                // Enhanced Beacon (Annex D.11.1.2): the standard beacon
                // information comes from the EB Payload IE; the TX Power
                // IE sets the power of the link (D.11.2.4.2).
                let Ok(eb) = EnhancedBeacon::parse(frame.payload) else {
                    return RxDisposition::Handled;
                };
                // Only the device that asked adopts the power (a
                // bystander did not measure this path).
                if let (Some(p), Some(e), true) =
                    (eb.tx_power, h.src.extended(), self.scan.is_some())
                {
                    let _ = self.power.set(PowerEntry {
                        short: eb.sender_short,
                        extended: e,
                        tx_power_dbm: p,
                        last_rssi_dbm: meta.rssi_dbm,
                        nwk_negotiated: false,
                        created: self.now,
                    });
                }
                let beacon = Beacon {
                    superframe: eb.superframe,
                    pending_short: 0,
                    pending_extended: 0,
                    payload: eb.beacon_payload,
                };
                let header = Header {
                    frame_control: h.frame_control,
                    sequence: h.sequence,
                    dst_pan: None,
                    dst: MacAddress::None,
                    src_pan: h.src_pan,
                    src: MacAddress::Short(eb.sender_short),
                    header_ies: &[],
                };
                RxDisposition::Beacon {
                    header,
                    beacon,
                    meta,
                }
            }
            FrameType::Beacon => {
                let Ok(beacon) = Beacon::decode_exact(frame.payload) else {
                    return RxDisposition::Handled;
                };
                // Coordinator conflict detection (IEEE 802.15.4 §6.3.2):
                // another PAN coordinator on our PAN ID.
                if self.pib.pan_coordinator
                    && beacon.superframe.pan_coordinator
                    && h.effective_src_pan() == Some(self.pib.pan_id)
                    && self.scan.is_none()
                {
                    self.push_event(MacEvent::PanIdConflict {
                        pan_id: self.pib.pan_id,
                    });
                }
                RxDisposition::Beacon {
                    header: h,
                    beacon,
                    meta,
                }
            }
            FrameType::Data => {
                if h.frame_control.ack_request() && !h.dst.is_broadcast() {
                    let pending = self.has_indirect_for(h.src, h.src.extended());
                    if let Some(seq) = h.sequence {
                        self.send_ack(seq, pending);
                    }
                }
                RxDisposition::Data { frame, meta }
            }
            FrameType::Command => self.on_command(frame, meta),
            FrameType::Ack | FrameType::Other(_) => RxDisposition::Handled,
        }
    }

    fn on_ack(&mut self, seq: Option<u8>, frame_pending: bool) {
        let Some(f) = &self.in_flight else { return };
        if f.ack_deadline.is_none() || Some(f.seq) != seq {
            return;
        }
        if let Some(f) = self.in_flight.take() {
            self.finish_in_flight(f, TxStatus::Success, frame_pending);
        }
    }

    fn on_command<'a>(&mut self, frame: Frame<'a>, meta: RxMetadata) -> RxDisposition<'a> {
        let h = frame.header;
        if h.frame_control.version() == FrameVersion::V2015 && h.frame_control.ie_present() {
            if let Ok(ebr) = EnhancedBeaconRequest::parse(frame.payload) {
                self.on_enhanced_beacon_request(&ebr, &h, meta);
            }
            return RxDisposition::Handled;
        }
        let Ok(cmd) = MacCommand::decode_exact(frame.payload) else {
            return RxDisposition::Handled;
        };
        match cmd {
            MacCommand::BeaconRequest => {
                if self.pib.beacon_capable
                    && self.pib.pan_id != PanId::BROADCAST
                    && self.scan.is_none()
                {
                    self.send_beacon();
                }
                RxDisposition::Handled
            }
            MacCommand::AssociationRequest { capability } => {
                let Some(seq) = h.sequence else {
                    return RxDisposition::Handled;
                };
                // Acknowledge (no pending data yet) then indicate upward.
                self.send_ack(seq, false);
                if let Some(device) = h.src.extended() {
                    if self.pib.association_permit {
                        self.push_event(MacEvent::AssociateIndication {
                            device,
                            capability,
                            lqi: meta.lqi,
                        });
                    } else {
                        // Not permitted: respond with access denied so the
                        // joiner does not wait the full response time.
                        let _ = self.associate_response(
                            device,
                            ShortAddress::NO_SHORT_ADDRESS,
                            MacStatus::PanAccessDenied,
                        );
                    }
                }
                RxDisposition::Handled
            }
            MacCommand::AssociationResponse {
                short_address,
                status,
            } => {
                if let Some(seq) = h.sequence {
                    self.send_ack(seq, false);
                }
                if let Some(a) = self.assoc
                    && matches!(a.phase, AssocPhase::Polling { .. })
                {
                    self.assoc = None;
                    if status == MacStatus::Success {
                        self.pib.short_address = short_address;
                        if let Some(e) = h.src.extended() {
                            self.pib.coord_extended_address = e;
                        }
                        self.config_dirty = true;
                    } else {
                        self.pib.pan_id = PanId::BROADCAST;
                        self.config_dirty = true;
                    }
                    self.push_event(MacEvent::AssociateConfirm {
                        short_address,
                        status,
                    });
                }
                RxDisposition::Handled
            }
            MacCommand::DataRequest => {
                self.push_event(MacEvent::PollIndication { device: h.src });
                let pending_idx = self.indirect.iter().position(|e| {
                    e.dst == h.src
                        || matches!((e.dst, h.src.extended()), (MacAddress::Extended(x), Some(y)) if x == y)
                        || matches!((e.dst, h.src.short()), (MacAddress::Short(x), Some(y)) if x == y)
                });
                if let Some(seq) = h.sequence {
                    self.send_ack(seq, pending_idx.is_some());
                }
                if let Some(idx) = pending_idx {
                    let entry = self.indirect.swap_remove(idx);
                    self.update_pending_list();
                    if let InFlightKind::DeferredData { handle } = entry.kind {
                        // The child listens now: the caller produces the
                        // frame and sends it directly.
                        self.push_event(MacEvent::IndirectReady { handle });
                        return RxDisposition::Handled;
                    }
                    let q = QueuedTx {
                        kind: entry.kind,
                        frame: entry.frame,
                        seq: entry.seq,
                        ack_request: true,
                        options: TxOptions {
                            tx_power_dbm: self.power.tx_power_for(&entry.dst),
                            ..TxOptions::ACKED
                        },
                    };
                    if self.enqueue(q).is_err() {
                        match entry.kind {
                            InFlightKind::IndirectData { handle } => {
                                self.push_event(MacEvent::DataConfirm {
                                    handle,
                                    status: TxStatus::TransactionExpired,
                                    frame_pending: false,
                                });
                            }
                            InFlightKind::IndirectAssocResponse { device } => {
                                self.push_event(MacEvent::CommStatus {
                                    device,
                                    status: TxStatus::TransactionExpired,
                                });
                            }
                            _ => {}
                        }
                    }
                }
                RxDisposition::Handled
            }
            MacCommand::PanIdConflictNotification => {
                if let Some(seq) = h.sequence {
                    self.send_ack(seq, false);
                }
                if self.pib.pan_coordinator {
                    self.push_event(MacEvent::PanIdConflict {
                        pan_id: self.pib.pan_id,
                    });
                }
                RxDisposition::Handled
            }
            MacCommand::DisassociationNotification { .. }
            | MacCommand::OrphanNotification
            | MacCommand::CoordinatorRealignment { .. } => {
                // Not used by Zigbee (leave is handled at the NWK layer;
                // orphan scans are replaced by rejoin). Acknowledge and drop.
                if h.frame_control.ack_request()
                    && let Some(seq) = h.sequence
                {
                    self.send_ack(seq, false);
                }
                RxDisposition::Handled
            }
            MacCommand::Other { .. } => RxDisposition::Other { frame, meta },
        }
    }

    fn send_beacon(&mut self) {
        let seq = self.next_bsn();
        let header = Header::new(
            FrameType::Beacon,
            seq,
            PanId::BROADCAST,
            MacAddress::None,
            self.pib.pan_id,
            self.own_address(),
        );
        let payload = self.pib.beacon_payload.clone();
        let beacon = Beacon::non_beacon(
            self.pib.pan_coordinator,
            self.pib.association_permit,
            &payload,
        );
        if let Ok(frame) = Self::build_frame(&header, &beacon) {
            let _ = self.enqueue(QueuedTx {
                kind: InFlightKind::Beacon,
                frame,
                seq,
                ack_request: false,
                options: TxOptions::UNACKED,
            });
        }
    }

    /// Enhanced Beacon Request received (Annex D.11.1.1-D.11.1.3): a
    /// joining request is answered when joining is permitted, the link
    /// quality filter passes and `mibJoiningPolicy` admits the device; a
    /// rejoin request when its extended PAN ID is ours. The percent
    /// filter is not applied (every eligible device answers). The
    /// Enhanced Beacon goes out at the power the TX Power IE and RSSI of
    /// the request call for (D.11.2.4.2), which also seeds the entry of
    /// the link in the Power Control Information Table.
    fn on_enhanced_beacon_request(
        &mut self,
        ebr: &EnhancedBeaconRequest,
        h: &Header<'_>,
        meta: RxMetadata,
    ) {
        if !self.config.enhanced_beacons
            || !self.pib.beacon_capable
            || self.pib.pan_id == PanId::BROADCAST
            || self.scan.is_some()
        {
            return;
        }
        let respond = if let Some(f) = ebr.filter {
            (!f.permit_joining_on || self.pib.association_permit)
                && f.link_quality.is_none_or(|q| meta.lqi >= q)
                && match self.pib.joining_policy {
                    JoiningPolicy::NoJoin => false,
                    JoiningPolicy::AllJoin => true,
                    JoiningPolicy::IeeeListJoin => h
                        .src
                        .extended()
                        .is_some_and(|e| self.pib.joining_ieee_list.contains(&e)),
                }
        } else if let Some((epid, _)) = ebr.rejoin {
            // The extended PAN ID sits at octets 3..11 of the Zigbee
            // beacon payload (§3.6.7).
            self.pib
                .beacon_payload
                .get(3..11)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .is_some_and(|b| ExtendedAddress(u64::from_le_bytes(b)) == epid)
        } else {
            false
        };
        if !respond {
            return;
        }
        let tx_power = ebr
            .tx_power
            .map(|p| self.power.limits.power_for_path(p, meta.rssi_dbm));
        if let (Some(p), Some(e)) = (tx_power, h.src.extended()) {
            let _ = self.power.set(PowerEntry {
                short: ebr
                    .rejoin
                    .map_or(ShortAddress::NO_SHORT_ADDRESS, |(_, s)| s),
                extended: e,
                tx_power_dbm: p,
                last_rssi_dbm: meta.rssi_dbm,
                nwk_negotiated: false,
                created: self.now,
            });
        }
        self.send_enhanced_beacon(tx_power);
    }

    /// Sends an Enhanced Beacon (D.11.1.2): frame version 2, no
    /// destination, extended source with the PAN ID, the beacon
    /// information in the EB Payload IE and the TX Power IE.
    fn send_enhanced_beacon(&mut self, tx_power: Option<i8>) {
        let seq = self.next_bsn();
        let fc = FrameControl::new(FrameType::Beacon, FrameVersion::V2015)
            .with_dst_mode(AddressMode::None)
            .with_src_mode(AddressMode::Extended)
            .with_ie_present(true);
        let header = Header {
            frame_control: fc,
            sequence: Some(seq),
            dst_pan: None,
            dst: MacAddress::None,
            src_pan: Some(self.pib.pan_id),
            src: MacAddress::Extended(self.pib.extended_address),
            header_ies: &HEADER_TERMINATION_1,
        };
        let payload = self.pib.beacon_payload.clone();
        let eb = EnhancedBeacon {
            beacon_payload: &payload,
            superframe: SuperframeSpec::non_beacon(
                self.pib.pan_coordinator,
                self.pib.association_permit,
            ),
            sender_short: self.pib.short_address,
            tx_power,
        };
        if let Ok(frame) = Self::build_frame(&header, &eb) {
            let _ = self.enqueue(QueuedTx {
                kind: InFlightKind::Beacon,
                frame,
                seq,
                ack_request: false,
                options: TxOptions {
                    tx_power_dbm: tx_power,
                    ..TxOptions::UNACKED
                },
            });
        }
    }

    /// Sends an Enhanced Beacon Request (D.11.1.1, Figure D-1): frame
    /// version 2, broadcast PAN and short destination, extended source
    /// with PAN ID compression, HT1 then the payload IEs.
    fn send_enhanced_beacon_request(&mut self, request: EnhancedBeaconRequest) {
        let seq = self.next_dsn();
        let fc = FrameControl::new(FrameType::Command, FrameVersion::V2015)
            .with_dst_mode(AddressMode::Short)
            .with_src_mode(AddressMode::Extended)
            .with_pan_id_compression(true)
            .with_ie_present(true);
        let header = Header {
            frame_control: fc,
            sequence: Some(seq),
            dst_pan: Some(PanId::BROADCAST),
            dst: MacAddress::Short(ShortAddress::BROADCAST_ALL),
            src_pan: None,
            src: MacAddress::Extended(self.pib.extended_address),
            header_ies: &HEADER_TERMINATION_1,
        };
        if let Ok(frame) = Self::build_frame(&header, &request) {
            let _ = self.enqueue(QueuedTx {
                kind: InFlightKind::BeaconRequest,
                frame,
                seq,
                ack_request: false,
                options: TxOptions {
                    tx_power_dbm: request.tx_power,
                    ..TxOptions::UNACKED
                },
            });
        }
    }

    /// Number of indirect frames currently held.
    pub fn indirect_len(&self) -> usize {
        self.indirect.len()
    }

    /// Number of frames waiting in the transmit queue (excluding the one in
    /// flight).
    pub fn tx_queue_len(&self) -> usize {
        self.tx_queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::RadioError;

    fn svc(caps: RadioCapabilities) -> MacService {
        let cfg = MacServiceConfig {
            radio: caps,
            ..MacServiceConfig::default()
        };
        let mut s = MacService::new(cfg, ExtendedAddress(0x1122_3344_5566_7788));
        s.start(
            PanId(0x1234),
            ChannelPage::PAGE_0,
            Channel::new_2_4ghz(15).unwrap(),
            ShortAddress(0x0001),
            false,
            true,
        );
        s.poll_timers(Instant::ZERO);
        // Drain configuration actions.
        while let Some(a) = s.next_action() {
            assert!(matches!(
                a,
                MacAction::SetChannel { .. } | MacAction::Configure(_)
            ));
        }
        s
    }

    fn take_transmit(s: &mut MacService) -> (TxHandle, FrameBuf, TxOptions) {
        loop {
            match s.next_action() {
                Some(MacAction::Transmit {
                    handle,
                    frame,
                    options,
                }) => return (handle, frame, options),
                Some(_) => continue,
                None => panic!("no transmit action"),
            }
        }
    }

    #[test]
    fn software_ack_retries_then_no_ack() {
        let mut s = svc(RadioCapabilities::default());
        let h = s
            .data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress(0x0002)),
                &[1, 2, 3],
                true,
                false,
            )
            .unwrap();
        let mut now = Instant::ZERO;
        for _ in 0..=constants::MAX_FRAME_RETRIES {
            let (_, frame, opts) = take_transmit(&mut s);
            assert!(opts.ack_request);
            let f = Frame::decode_exact(&frame).unwrap();
            assert!(f.header.frame_control.ack_request());
            assert_eq!(f.payload, &[1, 2, 3]);
            s.on_tx_complete(Ok(TxResult::default()));
            assert!(s.next_event().is_none());
            now += s.config.ack_wait;
            s.poll_timers(now);
        }
        assert_eq!(
            s.next_event(),
            Some(MacEvent::DataConfirm {
                handle: h,
                status: TxStatus::NoAck,
                frame_pending: false
            })
        );
        assert!(s.next_action().is_none());
    }

    #[test]
    fn software_ack_success_matches_sequence() {
        let mut s = svc(RadioCapabilities::default());
        let h = s
            .data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress(0x0002)),
                &[9],
                true,
                false,
            )
            .unwrap();
        let (_, frame, _) = take_transmit(&mut s);
        let seq = Frame::decode_exact(&frame)
            .unwrap()
            .header
            .sequence
            .unwrap();
        s.on_tx_complete(Ok(TxResult::default()));
        // Wrong sequence is ignored.
        let wrong = [0x02, 0x00, seq.wrapping_add(1)];
        assert!(matches!(
            s.on_receive(&wrong, RxMetadata::default()),
            RxDisposition::Handled
        ));
        assert!(s.next_event().is_none());
        let ack = [0x12, 0x00, seq];
        s.on_receive(&ack, RxMetadata::default());
        assert_eq!(
            s.next_event(),
            Some(MacEvent::DataConfirm {
                handle: h,
                status: TxStatus::Success,
                frame_pending: true
            })
        );
    }

    #[test]
    fn hardware_ack_wait_reports_result_directly() {
        let mut s = svc(RadioCapabilities {
            ack_wait: true,
            retries: true,
            auto_ack: true,
            address_filter: true,
            ..RadioCapabilities::default()
        });
        let h = s
            .data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress(0x0002)),
                &[9],
                true,
                false,
            )
            .unwrap();
        let _ = take_transmit(&mut s);
        s.on_tx_complete(Ok(TxResult {
            acked: true,
            frame_pending: false,
            timestamp_us: None,
        }));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::DataConfirm {
                handle: h,
                status: TxStatus::Success,
                frame_pending: false
            })
        );
        let h2 = s
            .data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress(0x0002)),
                &[9],
                true,
                false,
            )
            .unwrap();
        let _ = take_transmit(&mut s);
        s.on_tx_complete(Err(RadioError::NoAck));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::DataConfirm {
                handle: h2,
                status: TxStatus::RadioError,
                frame_pending: false
            })
        );
    }

    #[test]
    fn broadcast_data_is_not_acked() {
        let mut s = svc(RadioCapabilities::default());
        let h = s
            .data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress::BROADCAST_ALL),
                &[1],
                true,
                false,
            )
            .unwrap();
        let (_, frame, opts) = take_transmit(&mut s);
        assert!(!opts.ack_request);
        assert!(
            !Frame::decode_exact(&frame)
                .unwrap()
                .header
                .frame_control
                .ack_request()
        );
        s.on_tx_complete(Ok(TxResult::default()));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::DataConfirm {
                handle: h,
                status: TxStatus::Success,
                frame_pending: false
            })
        );
    }

    #[test]
    fn indirect_frame_served_on_data_request_and_expires() {
        let mut s = svc(RadioCapabilities::default());
        let child = ShortAddress(0x0042);
        let h = s
            .data_request(PanId(0x1234), MacAddress::Short(child), &[7, 7], true, true)
            .unwrap();
        assert_eq!(s.indirect_len(), 1);
        assert!(s.next_action().is_none(), "indirect frames are not sent");

        // Data request from the child (intra-PAN, short addresses).
        let dr = Header::new(
            FrameType::Command,
            5,
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0001)),
            PanId(0x1234),
            MacAddress::Short(child),
        );
        let dr = Header {
            frame_control: dr.frame_control.with_ack_request(true),
            ..dr
        };
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        dr.encode(&mut w).unwrap();
        MacCommand::DataRequest.encode(&mut w).unwrap();
        let n = w.position();
        assert!(matches!(
            s.on_receive(&buf[..n], RxMetadata::default()),
            RxDisposition::Handled
        ));
        // First action: immediate ack with frame pending.
        let (_, ack, opts) = take_transmit(&mut s);
        assert!(!opts.csma);
        let ackh = Header::decode_exact(&ack).unwrap();
        assert_eq!(ackh.frame_control.frame_type(), FrameType::Ack);
        assert!(ackh.frame_control.frame_pending());
        assert_eq!(ackh.sequence, Some(5));
        s.on_tx_complete(Ok(TxResult::default()));
        // Then the data frame.
        let (_, data, opts) = take_transmit(&mut s);
        assert!(opts.ack_request);
        assert_eq!(Frame::decode_exact(&data).unwrap().payload, &[7, 7]);
        assert_eq!(s.indirect_len(), 0);
        s.on_tx_complete(Ok(TxResult::default()));
        let seq = Frame::decode_exact(&data).unwrap().header.sequence.unwrap();
        s.on_receive(&[0x02, 0x00, seq], RxMetadata::default());
        assert!(matches!(
            s.next_event(),
            Some(MacEvent::PollIndication { .. })
        ));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::DataConfirm {
                handle: h,
                status: TxStatus::Success,
                frame_pending: false
            })
        );

        // Expiry path.
        let h2 = s
            .data_request(PanId(0x1234), MacAddress::Short(child), &[1], true, true)
            .unwrap();
        s.poll_timers(Instant::ZERO + s.config.transaction_persistence);
        assert_eq!(
            s.next_event(),
            Some(MacEvent::DataConfirm {
                handle: h2,
                status: TxStatus::TransactionExpired,
                frame_pending: false
            })
        );
        assert_eq!(s.indirect_len(), 0);
    }

    #[test]
    fn beacon_request_triggers_beacon_when_capable() {
        let mut s = svc(RadioCapabilities::default());
        s.set_beacon_payload(&[0xAB, 0xCD]);
        s.set_association_permit(true);
        // Beacon request: dst PAN 0xFFFF, dst 0xFFFF, no src.
        let br = Header::new(
            FrameType::Command,
            1,
            PanId::BROADCAST,
            MacAddress::Short(ShortAddress::BROADCAST_ALL),
            PanId::BROADCAST,
            MacAddress::None,
        );
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        br.encode(&mut w).unwrap();
        MacCommand::BeaconRequest.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(&buf[..n], &[0x03, 0x08, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x07]);
        s.on_receive(&buf[..n], RxMetadata::default());
        let (_, frame, opts) = take_transmit(&mut s);
        assert!(!opts.ack_request);
        let f = Frame::decode_exact(&frame).unwrap();
        assert_eq!(f.header.frame_control.frame_type(), FrameType::Beacon);
        assert_eq!(f.header.src_pan, Some(PanId(0x1234)));
        assert_eq!(f.header.src, MacAddress::Short(ShortAddress(0x0001)));
        let b = Beacon::decode_exact(f.payload).unwrap();
        assert!(b.superframe.association_permit);
        assert!(!b.superframe.pan_coordinator);
        assert_eq!(b.payload, &[0xAB, 0xCD]);

        // An end device (not beacon capable) stays silent.
        let mut ed = svc(RadioCapabilities::default());
        ed.pib.beacon_capable = false;
        ed.on_receive(&buf[..n], RxMetadata::default());
        assert!(ed.next_action().is_none());
    }

    #[test]
    fn active_scan_sends_beacon_requests_per_channel_and_confirms() {
        let mut s = svc(RadioCapabilities::default());
        let mask = ChannelMask::EMPTY
            .with(Channel::new_2_4ghz(11).unwrap())
            .with(Channel::new_2_4ghz(20).unwrap());
        s.scan(ScanKind::Active, mask, 3).unwrap();
        let mut now = Instant::ZERO;
        for ch in [11u8, 20] {
            assert_eq!(
                s.next_action(),
                Some(MacAction::SetChannel {
                    page: ChannelPage::PAGE_0,
                    channel: Channel::new(ch).unwrap()
                })
            );
            let (_, frame, _) = take_transmit(&mut s);
            let f = Frame::decode_exact(&frame).unwrap();
            assert_eq!(
                MacCommand::decode_exact(f.payload).unwrap(),
                MacCommand::BeaconRequest
            );
            s.on_tx_complete(Ok(TxResult::default()));
            // A beacon arriving during the dwell is delivered upward.
            let bh = Header::new(
                FrameType::Beacon,
                3,
                PanId::BROADCAST,
                MacAddress::None,
                PanId(0x5555),
                MacAddress::Short(ShortAddress(0)),
            );
            let mut buf = [0u8; 32];
            let mut w = Writer::new(&mut buf);
            bh.encode(&mut w).unwrap();
            Beacon::non_beacon(true, true, &[1]).encode(&mut w).unwrap();
            let n = w.position();
            assert!(matches!(
                s.on_receive(&buf[..n], RxMetadata::default()),
                RxDisposition::Beacon { .. }
            ));
            now += constants::scan_duration_per_channel(3);
            s.poll_timers(now);
        }
        // Restore original channel and confirm.
        assert_eq!(
            s.next_action(),
            Some(MacAction::SetChannel {
                page: ChannelPage::PAGE_0,
                channel: Channel::new(15).unwrap()
            })
        );
        assert_eq!(
            s.next_event(),
            Some(MacEvent::ScanConfirm {
                kind: ScanKind::Active,
                channels: mask
            })
        );
        assert!(!s.scanning());
    }

    #[test]
    fn energy_scan_collects_levels() {
        let mut s = svc(RadioCapabilities::default());
        let mask = ChannelMask::EMPTY
            .with(Channel::new(11).unwrap())
            .with(Channel::new(12).unwrap());
        s.scan(ScanKind::Energy, mask, 2).unwrap();
        for (ch, level) in [(11u8, 40u8), (12, 200)] {
            assert_eq!(
                s.next_action(),
                Some(MacAction::SetChannel {
                    page: ChannelPage::PAGE_0,
                    channel: Channel::new(ch).unwrap()
                })
            );
            assert!(matches!(
                s.next_action(),
                Some(MacAction::EnergyDetect { .. })
            ));
            s.on_energy_result(level);
        }
        assert!(matches!(
            s.next_action(),
            Some(MacAction::SetChannel { .. })
        ));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::ScanConfirm {
                kind: ScanKind::Energy,
                channels: mask
            })
        );
        assert_eq!(s.energy_results()[11], 40);
        assert_eq!(s.energy_results()[12], 200);
        assert_eq!(s.energy_results()[13], 0);
    }

    #[test]
    fn association_handshake_joiner_side() {
        let mut s = MacService::new(
            MacServiceConfig::default(),
            ExtendedAddress(0xAAAA_BBBB_CCCC_DDDD),
        );
        s.poll_timers(Instant::ZERO);
        s.start(
            PanId::BROADCAST,
            ChannelPage::PAGE_0,
            Channel::new(15).unwrap(),
            ShortAddress::NO_SHORT_ADDRESS,
            false,
            false,
        );
        while s.next_action().is_some() {}
        s.associate(
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0000)),
            MacCapability::SLEEPY_END_DEVICE,
        )
        .unwrap();
        // Association request goes out with our extended address and
        // source PAN 0xFFFF (no compression).
        let (_, frame, opts) = take_transmit(&mut s);
        assert!(opts.ack_request);
        let f = Frame::decode_exact(&frame).unwrap();
        assert_eq!(f.header.dst_pan, Some(PanId(0x1234)));
        assert_eq!(f.header.src_pan, Some(PanId::BROADCAST));
        assert_eq!(
            f.header.src,
            MacAddress::Extended(ExtendedAddress(0xAAAA_BBBB_CCCC_DDDD))
        );
        assert!(matches!(
            MacCommand::decode_exact(f.payload).unwrap(),
            MacCommand::AssociationRequest { .. }
        ));
        let seq = f.header.sequence.unwrap();
        s.on_tx_complete(Ok(TxResult::default()));
        s.on_receive(&[0x02, 0x00, seq], RxMetadata::default());
        // Wait macResponseWaitTime → data request.
        let t = Instant::ZERO + s.config.response_wait;
        s.poll_timers(t);
        let (_, frame, _) = take_transmit(&mut s);
        let f = Frame::decode_exact(&frame).unwrap();
        assert_eq!(
            MacCommand::decode_exact(f.payload).unwrap(),
            MacCommand::DataRequest
        );
        assert_eq!(f.header.dst_pan, Some(PanId(0x1234)));
        assert_eq!(f.header.src_pan, None, "intra-PAN data request");
        let seq = f.header.sequence.unwrap();
        s.on_tx_complete(Ok(TxResult::default()));
        // Ack with frame pending.
        s.on_receive(&[0x12, 0x00, seq], RxMetadata::default());
        // Association response arrives.
        let rh = Header::new(
            FrameType::Command,
            9,
            PanId(0x1234),
            MacAddress::Extended(ExtendedAddress(0xAAAA_BBBB_CCCC_DDDD)),
            PanId(0x1234),
            MacAddress::Extended(ExtendedAddress(0x0000_0000_0000_0001)),
        );
        let rh = Header {
            frame_control: rh.frame_control.with_ack_request(true),
            ..rh
        };
        let mut buf = [0u8; 40];
        let mut w = Writer::new(&mut buf);
        rh.encode(&mut w).unwrap();
        MacCommand::AssociationResponse {
            short_address: ShortAddress(0x7788),
            status: MacStatus::Success,
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        s.on_receive(&buf[..n], RxMetadata::default());
        // Software ack for the response is sent.
        let (_, ack, _) = take_transmit(&mut s);
        assert_eq!(Header::decode_exact(&ack).unwrap().sequence, Some(9));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::AssociateConfirm {
                short_address: ShortAddress(0x7788),
                status: MacStatus::Success
            })
        );
        assert_eq!(s.pib.short_address, ShortAddress(0x7788));
        assert_eq!(
            s.pib.coord_extended_address,
            ExtendedAddress(0x0000_0000_0000_0001)
        );
    }

    #[test]
    fn association_timeout_reports_no_data() {
        let mut s = MacService::new(
            MacServiceConfig::default(),
            ExtendedAddress(0xAAAA_BBBB_CCCC_DDDD),
        );
        s.poll_timers(Instant::ZERO);
        while s.next_action().is_some() {}
        s.associate(
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0000)),
            MacCapability::ROUTER,
        )
        .unwrap();
        let (_, frame, _) = take_transmit(&mut s);
        let seq = Frame::decode_exact(&frame)
            .unwrap()
            .header
            .sequence
            .unwrap();
        s.on_tx_complete(Ok(TxResult::default()));
        s.on_receive(&[0x02, 0x00, seq], RxMetadata::default());
        let t = Instant::ZERO + s.config.response_wait;
        s.poll_timers(t);
        let (_, frame, _) = take_transmit(&mut s);
        let seq = Frame::decode_exact(&frame)
            .unwrap()
            .header
            .sequence
            .unwrap();
        s.on_tx_complete(Ok(TxResult::default()));
        // Ack without frame pending → NO_DATA.
        s.on_receive(&[0x02, 0x00, seq], RxMetadata::default());
        assert_eq!(
            s.next_event(),
            Some(MacEvent::AssociateConfirm {
                short_address: ShortAddress::NO_SHORT_ADDRESS,
                status: MacStatus::NoData
            })
        );
    }

    #[test]
    fn association_indication_and_indirect_response_parent_side() {
        let mut s = svc(RadioCapabilities::default());
        s.pib.pan_coordinator = true;
        s.set_association_permit(true);
        let joiner = ExtendedAddress(0x0102_0304_0506_0708);
        let ah = Header::new(
            FrameType::Command,
            11,
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0001)),
            PanId::BROADCAST,
            MacAddress::Extended(joiner),
        );
        let ah = Header {
            frame_control: ah.frame_control.with_ack_request(true),
            ..ah
        };
        let mut buf = [0u8; 40];
        let mut w = Writer::new(&mut buf);
        ah.encode(&mut w).unwrap();
        MacCommand::AssociationRequest {
            capability: MacCapability::ROUTER,
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        s.on_receive(
            &buf[..n],
            RxMetadata {
                lqi: 200,
                ..RxMetadata::default()
            },
        );
        let (_, ack, _) = take_transmit(&mut s);
        assert_eq!(Header::decode_exact(&ack).unwrap().sequence, Some(11));
        s.on_tx_complete(Ok(TxResult::default()));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::AssociateIndication {
                device: joiner,
                capability: MacCapability::ROUTER,
                lqi: 200
            })
        );
        s.associate_response(joiner, ShortAddress(0x1000), MacStatus::Success)
            .unwrap();
        assert_eq!(s.indirect_len(), 1);
        // Joiner polls with its extended address.
        let dr = Header::new(
            FrameType::Command,
            12,
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0001)),
            PanId(0x1234),
            MacAddress::Extended(joiner),
        );
        let dr = Header {
            frame_control: dr.frame_control.with_ack_request(true),
            ..dr
        };
        let mut w = Writer::new(&mut buf);
        dr.encode(&mut w).unwrap();
        MacCommand::DataRequest.encode(&mut w).unwrap();
        let n = w.position();
        s.on_receive(&buf[..n], RxMetadata::default());
        let (_, ack, _) = take_transmit(&mut s);
        assert!(
            Header::decode_exact(&ack)
                .unwrap()
                .frame_control
                .frame_pending()
        );
        s.on_tx_complete(Ok(TxResult::default()));
        let (_, rsp, _) = take_transmit(&mut s);
        let f = Frame::decode_exact(&rsp).unwrap();
        assert_eq!(f.header.dst, MacAddress::Extended(joiner));
        assert_eq!(
            MacCommand::decode_exact(f.payload).unwrap(),
            MacCommand::AssociationResponse {
                short_address: ShortAddress(0x1000),
                status: MacStatus::Success
            }
        );
        let seq = f.header.sequence.unwrap();
        s.on_tx_complete(Ok(TxResult::default()));
        s.on_receive(&[0x02, 0x00, seq], RxMetadata::default());
        assert!(matches!(
            s.next_event(),
            Some(MacEvent::PollIndication { .. })
        ));
        assert_eq!(
            s.next_event(),
            Some(MacEvent::CommStatus {
                device: joiner,
                status: TxStatus::Success
            })
        );
    }

    #[test]
    fn association_denied_when_permit_off() {
        let mut s = svc(RadioCapabilities::default());
        s.set_association_permit(false);
        let joiner = ExtendedAddress(0x0102_0304_0506_0708);
        let ah = Header::new(
            FrameType::Command,
            11,
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0001)),
            PanId::BROADCAST,
            MacAddress::Extended(joiner),
        );
        let mut buf = [0u8; 40];
        let mut w = Writer::new(&mut buf);
        ah.encode(&mut w).unwrap();
        MacCommand::AssociationRequest {
            capability: MacCapability::ROUTER,
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        s.on_receive(&buf[..n], RxMetadata::default());
        assert!(s.next_event().is_none());
        assert_eq!(s.indirect_len(), 1, "access-denied response queued");
    }

    #[test]
    fn software_filter_drops_foreign_frames() {
        let mut s = svc(RadioCapabilities::default());
        let other = Header::new(
            FrameType::Data,
            1,
            PanId(0x9999),
            MacAddress::Short(ShortAddress(0x0001)),
            PanId(0x9999),
            MacAddress::Short(ShortAddress(0x0002)),
        );
        let mut buf = [0u8; 32];
        let n = other.encode_to_slice(&mut buf).unwrap();
        assert!(matches!(
            s.on_receive(&buf[..n], RxMetadata::default()),
            RxDisposition::Handled
        ));
        let mine = Header::new(
            FrameType::Data,
            1,
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0001)),
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0002)),
        );
        let n = mine.encode_to_slice(&mut buf).unwrap();
        assert!(matches!(
            s.on_receive(&buf[..n], RxMetadata::default()),
            RxDisposition::Data { .. }
        ));
        // Malformed input never panics.
        for len in 0..n {
            let _ = s.on_receive(&buf[..len], RxMetadata::default());
        }
    }

    #[test]
    fn poll_reports_frame_pending() {
        let mut s = svc(RadioCapabilities::default());
        assert_eq!(s.poll(), Err(MacError::InvalidRequest));
        s.set_coordinator(ShortAddress(0x0000), ExtendedAddress(1));
        s.poll().unwrap();
        let (_, frame, _) = take_transmit(&mut s);
        let f = Frame::decode_exact(&frame).unwrap();
        assert_eq!(
            MacCommand::decode_exact(f.payload).unwrap(),
            MacCommand::DataRequest
        );
        let seq = f.header.sequence.unwrap();
        s.on_tx_complete(Ok(TxResult::default()));
        s.on_receive(&[0x12, 0x00, seq], RxMetadata::default());
        assert_eq!(
            s.next_event(),
            Some(MacEvent::PollConfirm {
                frame_pending: true,
                status: TxStatus::Success
            })
        );
        assert!(s.needs_receiver());
        s.poll_timers(Instant::ZERO + s.config.poll_wait);
        assert!(!s.needs_receiver());
    }

    #[test]
    fn queue_is_bounded() {
        let mut s = svc(RadioCapabilities::default());
        for _ in 0..TX_QUEUE_CAPACITY {
            s.data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress(2)),
                &[1],
                false,
                false,
            )
            .unwrap();
        }
        assert_eq!(
            s.data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress(2)),
                &[1],
                false,
                false
            ),
            Err(MacError::QueueFull)
        );
        let big = [0u8; 120];
        assert_eq!(
            s.data_request(
                PanId(0x1234),
                MacAddress::Short(ShortAddress(2)),
                &big,
                false,
                false
            ),
            Err(MacError::FrameTooLong)
        );
    }
}
