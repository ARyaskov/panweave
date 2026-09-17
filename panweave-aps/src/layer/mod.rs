//! The sans-I/O APS sub-layer (R23.2 §2.2 and §4.4).
//!
//! [`Aps`] consumes NLDE-DATA indications and confirms from the NWK layer
//! plus APSDE/APSME requests from the application, and produces
//! [`ApsAction`]s (NLDE-DATA requests, persistence hints) and
//! [`ApsEvent`]s (confirms and management indications). Data indications
//! are returned directly from [`Aps::on_nwk_data`] so that the ASDU is
//! borrowed rather than copied.
//!
//! Time is injected: the runtime calls [`Aps::poll_timers`] and consults
//! [`Aps::next_deadline`].

use heapless::{Deque, Vec};
use panweave_security::aux_header::{KeyIdentifier, SecurityLevel};
use panweave_security::cipher::BlockCipher;
use panweave_security::frame_counter::Reservation;
use panweave_types::time::Instant;
use panweave_types::{
    ApsStatus, ClusterId, Endpoint, ExtendedAddress, GroupAddress, Key128, KeySequenceNumber,
    KeyType, ProfileId, ShortAddress,
};

use crate::aib::{Aib, constants};
use crate::command::{ApsCommandId, RequestKeyType, UpdateDeviceStatus};
use crate::frame::Header;
use crate::security::ApsSecurity;
use crate::tables::{BindingTable, DuplicateRejectionTable, GroupTable};

pub mod cmd;
mod rx;
mod tx;

pub use cmd::KeyRoute;
pub use rx::{DataIndication, Delivery, RelayInfo, SecurityStatus};

/// Maximum ASDU after reassembly (`apsMaxSizeASDU`, at least 128 per
/// Table 2-28).
pub const MAX_ASDU: usize = 256;

/// Capacity of a single APS frame buffer handed to the NWK layer.
pub const MAX_APS_FRAME: usize = 108;

/// Default NWK payload available to the APS: `MAX_NPDU` (116) minus the
/// 8-octet NWK header, the 14-octet NWK auxiliary header and the 4-octet
/// MIC.
pub const DEFAULT_NWK_MAX_PAYLOAD: usize = 90;

/// Maximum joiner TLV payload retained from an Update Device command.
pub const MAX_JOINER_TLVS: usize = constants::JOINER_TLVS_UNFRAGMENTED_MAX_SIZE;

/// Number of outstanding transmissions.
pub const PENDING_TX: usize = 6;

/// Capacity of the action and event queues.
pub const QUEUE_CAPACITY: usize = 16;

/// A frame handed to the NWK layer.
pub type FrameBuf = Vec<u8, MAX_APS_FRAME>;

/// Owned ASDU storage.
pub type AsduBuf = Vec<u8, MAX_ASDU>;

/// Identifier of an APSDE-DATA or APSME request; echoed in confirms.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RequestId(pub u16);

/// Identifier of an NLDE-DATA request issued by the APS; the runtime maps
/// it to the NWK transaction and reports the confirm with
/// [`Aps::on_nwk_data_confirm`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NwkHandle(pub u16);

/// Request errors reported synchronously.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApsError {
    /// The device is not on a network (§2.2.8.4.1).
    NotJoined,
    /// A parameter is out of range (`ILLEGAL_REQUEST` / `INVALID_PARAMETER`).
    InvalidParameter,
    /// The ASDU does not fit and cannot be fragmented (`ASDU_TOO_LONG`).
    AsduTooLong,
    /// No binding matches the source endpoint and cluster
    /// (`NO_BOUND_DEVICE`).
    NoBoundDevice,
    /// The extended destination has no known short address
    /// (`NO_SHORT_ADDRESS`).
    NoShortAddress,
    /// No usable link key for the destination (`SECURITY_FAIL`).
    NoKey,
    /// The request is not valid in the current role or state.
    IllegalRequest,
    /// No transmission slot is free.
    Busy,
}

impl ApsError {
    /// The confirm status corresponding to this error.
    pub const fn status(self) -> ApsStatus {
        match self {
            ApsError::NotJoined | ApsError::IllegalRequest => ApsStatus::IllegalRequest,
            ApsError::InvalidParameter => ApsStatus::InvalidParameter,
            ApsError::AsduTooLong => ApsStatus::AsduTooLong,
            ApsError::NoBoundDevice => ApsStatus::NoBoundDevice,
            ApsError::NoShortAddress => ApsStatus::NoShortAddress,
            ApsError::NoKey => ApsStatus::SecurityFail,
            ApsError::Busy => ApsStatus::TableFull,
        }
    }
}

/// APSDE-DATA.request TxOptions (§2.2.4.1.1, Table 2-2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxOptions {
    /// Bit 0: APS security (link key) enabled.
    pub security: bool,
    /// Bit 2: acknowledged transmission.
    pub ack: bool,
    /// Bit 3: fragmentation permitted.
    pub fragmentation_permitted: bool,
    /// Bit 4: include the extended nonce in the auxiliary header.
    pub extended_nonce: bool,
}

impl TxOptions {
    /// Acknowledged, unsecured.
    pub const ACKED: TxOptions = TxOptions {
        security: false,
        ack: true,
        fragmentation_permitted: true,
        extended_nonce: false,
    };
    /// Unacknowledged, unsecured.
    pub const NONE: TxOptions = TxOptions {
        security: false,
        ack: false,
        fragmentation_permitted: false,
        extended_nonce: false,
    };
}

/// Destination of an APSDE-DATA.request (DstAddrMode, Table 2-2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Destination {
    /// 0x00: indirect via the binding table.
    Bound,
    /// 0x01: group address.
    Group(GroupAddress),
    /// 0x02: 16-bit address and endpoint (broadcast addresses allowed).
    Short {
        /// NWK address.
        address: ShortAddress,
        /// Destination endpoint (0xff for all endpoints on broadcasts).
        endpoint: Endpoint,
    },
    /// 0x03: 64-bit address and endpoint.
    Extended {
        /// IEEE address.
        address: ExtendedAddress,
        /// Destination endpoint.
        endpoint: Endpoint,
    },
    /// Relay through a parent router (§4.6.3.7): the Trust Center relays
    /// downstream to `joiner` via `parent`; a joiner relays upstream via
    /// its parent with `joiner` set to `None`.
    Relayed {
        /// The parent router that relays.
        parent: ShortAddress,
        /// The joining device (downstream) or `None` (upstream).
        joiner: Option<ExtendedAddress>,
        /// Destination endpoint of the relayed frame.
        endpoint: Endpoint,
    },
}

/// APSDE-DATA.request parameters.
#[derive(Clone, Copy, Debug)]
pub struct DataRequest<'a> {
    /// Destination.
    pub destination: Destination,
    /// Profile identifier.
    pub profile: ProfileId,
    /// Cluster identifier.
    pub cluster: ClusterId,
    /// Source endpoint.
    pub src_endpoint: Endpoint,
    /// The ASDU.
    pub asdu: &'a [u8],
    /// Transmit options.
    pub options: TxOptions,
    /// NWK radius (`None` = default).
    pub radius: Option<u8>,
    /// NWK source aliasing (R23.2 §2.2.4.1.1 UseAlias / AliasSrcAddr /
    /// AliasSeqNumb, used by Green Power proxies): the NWK source address
    /// and sequence number to put in the frame; the APS counter takes the
    /// alias sequence number. Acknowledged transmission is not allowed
    /// with an alias.
    pub alias: Option<(ShortAddress, u8)>,
}

/// Address information the APS needs from the NWK layer.
pub trait NwkView {
    /// IEEE address of a network address (address map / neighbor table).
    fn ieee_of(&self, short: ShortAddress) -> Option<ExtendedAddress>;
    /// Network address of an IEEE address.
    fn short_of(&self, ieee: ExtendedAddress) -> Option<ShortAddress>;
    /// Network address of `ieee` if it is a joined-but-unauthenticated
    /// child of this device (neighbor relationship 0x05).
    fn unauthenticated_child(&self, ieee: ExtendedAddress) -> Option<ShortAddress>;
}

/// Device security state as seen by the APS (§4.6.3.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DeviceState {
    /// Not on a network.
    NotJoined,
    /// Joined but not yet authorized (waiting for the network key).
    JoinedUnauthorized,
    /// Joined and authorized.
    JoinedAuthorized,
}

/// Static configuration.
#[derive(Clone, Copy, Debug)]
pub struct ApsConfig {
    /// NWK payload available for an APS frame.
    pub nwk_max_payload: usize,
    /// This device is the Trust Center.
    pub is_trust_center: bool,
    /// Joining device policy `requireLinkKeyEncryptionForApsTransportKey`:
    /// a Transport Key with the network key must be APS-encrypted while
    /// joined-but-unauthorized (§4.4.2.3).
    pub require_link_key_encryption_for_transport_key: bool,
    /// `nwkSecurityLevel` used for APS security processing.
    pub security_level: SecurityLevel,
    /// Data frames that are neither NWK- nor APS-secured are delivered
    /// (false on a secured network, §4.6.3.2.3.2).
    pub accept_unsecured_data: bool,
}

impl Default for ApsConfig {
    fn default() -> Self {
        ApsConfig {
            nwk_max_payload: DEFAULT_NWK_MAX_PAYLOAD,
            is_trust_center: false,
            require_link_key_encryption_for_transport_key: true,
            security_level: SecurityLevel::EncMic32,
            accept_unsecured_data: false,
        }
    }
}

/// What the runtime persists on a [`ApsAction::Persist`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PersistItem {
    /// The key-pair set changed.
    LinkKeys,
    /// The binding table changed.
    Bindings,
    /// The group table changed.
    Groups,
    /// Scalar AIB attributes changed (Trust Center address, …).
    Aib,
}

/// Outputs for the runtime.
#[derive(Debug)]
pub enum ApsAction {
    /// NLDE-DATA.request.
    NwkData {
        /// Handle echoed in [`Aps::on_nwk_data_confirm`].
        handle: NwkHandle,
        /// NWK destination.
        dst: ShortAddress,
        /// Radius (`None` = default).
        radius: Option<u8>,
        /// Enable route discovery.
        discover_route: bool,
        /// Apply NWK security.
        secure: bool,
        /// NWK source alias (address, sequence number).
        alias: Option<(ShortAddress, u8)>,
        /// The APS frame.
        frame: FrameBuf,
    },
    /// Persist an outgoing link-key counter reservation, then call
    /// [`Aps::commit_counter_reservation`].
    CounterReservation {
        /// Key-pair partner.
        partner: ExtendedAddress,
        /// The reservation.
        reservation: Reservation,
    },
    /// Persist the named state.
    Persist(PersistItem),
}

/// Frame counter synchronization is needed with `partner`
/// (`UNVERIFIED_FRAME_COUNTER`, §4.6.3.8): the runtime issues a
/// Security_Challenge_req, rate limited by `apsChallengePeriodTimeoutSeconds`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChallengeNeeded {
    /// The partner whose incoming counter is unverified.
    pub partner: ExtendedAddress,
}

/// A key delivered by a Transport Key command.
#[derive(Clone, Debug)]
pub enum TransportedKey {
    /// Standard network key (StandardKeyType 0x01).
    Network {
        /// The key.
        key: Key128,
        /// Sequence number.
        sequence: KeySequenceNumber,
        /// Originator (all ones in a distributed network).
        source: ExtendedAddress,
    },
    /// Trust Center link key (0x04), already installed in the key-pair
    /// set as UNVERIFIED.
    TrustCenterLink {
        /// The Trust Center.
        source: ExtendedAddress,
    },
    /// Application link key (0x03), already installed as VERIFIED.
    ApplicationLink {
        /// The partner.
        partner: ExtendedAddress,
        /// This device requested the key.
        initiator: bool,
    },
}

/// Management indications and confirms.
#[derive(Clone, Debug)]
pub enum ApsEvent {
    /// APSDE-DATA.confirm.
    DataConfirm {
        /// The request.
        id: RequestId,
        /// Outcome.
        status: ApsStatus,
    },
    /// Outcome of an APSME command transmission.
    CommandConfirm {
        /// The request.
        id: RequestId,
        /// The command.
        command: ApsCommandId,
        /// Outcome.
        status: ApsStatus,
    },
    /// APSME-TRANSPORT-KEY.indication. For a network key the runtime
    /// installs the key in the NWK layer (active when
    /// [`DeviceState::JoinedUnauthorized`] → alternate otherwise).
    TransportKey {
        /// Sender.
        src: ExtendedAddress,
        /// The key.
        key: TransportedKey,
        /// The device became authorized by this key.
        authorizes: bool,
    },
    /// APSME-UPDATE-DEVICE.indication (Trust Center only).
    UpdateDevice {
        /// The reporting router's network address.
        src: ShortAddress,
        /// The reporting router's IEEE address, if known.
        src_ieee: Option<ExtendedAddress>,
        /// The device that joined / rejoined / left.
        device: ExtendedAddress,
        /// Its network address.
        short: ShortAddress,
        /// What happened.
        status: UpdateDeviceStatus,
        /// Joiner TLVs.
        joiner_tlvs: Vec<u8, MAX_JOINER_TLVS>,
        /// The command was APS-encrypted.
        aps_secured: bool,
    },
    /// APSME-REMOVE-DEVICE.indication: the Trust Center asks this parent
    /// to remove `target`.
    RemoveDevice {
        /// The Trust Center.
        src: ExtendedAddress,
        /// The child to remove.
        target: ExtendedAddress,
    },
    /// APSME-REQUEST-KEY.indication (Trust Center only).
    RequestKey {
        /// Requesting device.
        src: ExtendedAddress,
        /// Its network address.
        src_short: ShortAddress,
        /// Requested key type.
        key_type: RequestKeyType,
        /// Partner for application link keys.
        partner: Option<ExtendedAddress>,
    },
    /// APSME-SWITCH-KEY.indication from the Trust Center.
    SwitchKey {
        /// The Trust Center.
        src: ExtendedAddress,
        /// Key to activate.
        sequence: KeySequenceNumber,
    },
    /// A Verify Key succeeded: `partner`'s key is now VERIFIED (Trust
    /// Center side, §4.4.7.2.3 step 7).
    KeyVerified {
        /// The verifying device.
        partner: ExtendedAddress,
        /// Key type.
        key_type: KeyType,
        /// Relay information when the Verify Key arrived through a
        /// parent router (the partner is still unauthorized).
        relayed: Option<RelayInfo>,
    },
    /// APSME-CONFIRM-KEY.indication (joiner side).
    ConfirmKey {
        /// The Trust Center or partner.
        src: ExtendedAddress,
        /// Key type.
        key_type: KeyType,
        /// Status.
        status: ApsStatus,
    },
    /// A frame from `partner` authenticated but its counter is unverified
    /// (§4.6.3.8): challenge the partner.
    FrameCounterUnverified {
        /// The partner.
        partner: ExtendedAddress,
    },
}

/// Diagnostic counters (never contain secrets).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ApsStats {
    /// Frames dropped as malformed.
    pub malformed: u32,
    /// Frames dropped by security processing.
    pub security_dropped: u32,
    /// Frames dropped by policy (state, Trust Center origin, Table 4-6).
    pub policy_dropped: u32,
    /// Duplicates rejected.
    pub duplicates: u32,
    /// Acknowledgements sent.
    pub acks_sent: u32,
    /// Acknowledged transmissions that timed out (all retries).
    pub ack_failures: u32,
    /// Retransmissions.
    pub retries: u32,
    /// Fragmented ASDUs reassembled.
    pub reassembled: u32,
    /// Events dropped because the queue was full.
    pub events_dropped: u32,
    /// Actions dropped because the queue was full.
    pub actions_dropped: u32,
}

/// Loopback delivery of a locally originated frame (group member or
/// bound to self, §2.2.8.4.1).
#[derive(Clone, Debug)]
pub struct Loopback {
    /// Destination endpoint or group.
    pub delivery: Delivery,
    /// Profile.
    pub profile: ProfileId,
    /// Cluster.
    pub cluster: ClusterId,
    /// Source endpoint.
    pub src_endpoint: Endpoint,
    /// The ASDU.
    pub asdu: AsduBuf,
}

/// The APS sub-layer.
pub struct Aps<
    C: BlockCipher,
    const KEYS: usize,
    const BINDINGS: usize,
    const GROUPS: usize,
    const DUPS: usize,
> {
    /// Scalar AIB attributes.
    pub aib: Aib,
    /// Configuration.
    pub config: ApsConfig,
    /// Key-pair set and APS frame security.
    pub security: ApsSecurity<C, KEYS>,
    /// Binding table.
    pub bindings: BindingTable<BINDINGS>,
    /// Group table.
    pub groups: GroupTable<GROUPS>,
    /// Statistics.
    pub stats: ApsStats,
    pub(crate) dedup: DuplicateRejectionTable<DUPS>,
    pub(crate) local_ieee: ExtendedAddress,
    pub(crate) local_short: ShortAddress,
    pub(crate) state: DeviceState,
    pub(crate) counter: u8,
    pub(crate) now: Instant,
    pub(crate) actions: Deque<ApsAction, QUEUE_CAPACITY>,
    pub(crate) events: Deque<ApsEvent, QUEUE_CAPACITY>,
    pub(crate) pending: Vec<tx::PendingTx, PENDING_TX>,
    pub(crate) requests: Vec<tx::RequestState, PENDING_TX>,
    pub(crate) reassembly: Option<rx::Reassembly>,
    pub(crate) loopback: Option<Loopback>,
    pub(crate) next_request: u16,
    pub(crate) next_handle: u16,
}

impl<
    C: BlockCipher,
    const KEYS: usize,
    const BINDINGS: usize,
    const GROUPS: usize,
    const DUPS: usize,
> Aps<C, KEYS, BINDINGS, GROUPS, DUPS>
{
    /// Creates the layer for the device with IEEE address `local_ieee`.
    pub fn new(local_ieee: ExtendedAddress, config: ApsConfig) -> Self {
        Aps {
            aib: Aib::new(),
            config,
            security: ApsSecurity::new(),
            bindings: BindingTable::new(),
            groups: GroupTable::new(),
            stats: ApsStats::default(),
            dedup: DuplicateRejectionTable::new(),
            local_ieee,
            local_short: ShortAddress::NO_SHORT_ADDRESS,
            state: DeviceState::NotJoined,
            counter: 0,
            now: Instant::from_millis(0),
            actions: Deque::new(),
            events: Deque::new(),
            pending: Vec::new(),
            requests: Vec::new(),
            reassembly: None,
            loopback: None,
            next_request: 1,
            next_handle: 1,
        }
    }

    /// Next action for the runtime.
    pub fn next_action(&mut self) -> Option<ApsAction> {
        self.actions.pop_front()
    }

    /// Next event for the application.
    pub fn next_event(&mut self) -> Option<ApsEvent> {
        self.events.pop_front()
    }

    /// True when actions or events are queued.
    pub fn has_output(&self) -> bool {
        !self.actions.is_empty() || !self.events.is_empty()
    }

    /// Takes the pending loopback indication, if any.
    pub fn take_loopback(&mut self) -> Option<Loopback> {
        self.loopback.take()
    }

    /// Local IEEE address.
    pub const fn local_ieee(&self) -> ExtendedAddress {
        self.local_ieee
    }

    /// Local network address.
    pub const fn local_short(&self) -> ShortAddress {
        self.local_short
    }

    /// Current device state.
    pub const fn state(&self) -> DeviceState {
        self.state
    }

    /// Updates the network address and state after a join, rejoin or
    /// leave (NLME-JOIN.confirm / NLME-LEAVE). A secured rejoin lands in
    /// [`DeviceState::JoinedAuthorized`]; an association or unsecured
    /// rejoin in [`DeviceState::JoinedUnauthorized`].
    pub fn set_network_state(&mut self, short: ShortAddress, state: DeviceState) {
        self.local_short = short;
        self.state = state;
        if state == DeviceState::NotJoined {
            self.fail_all_pending(ApsStatus::IllegalRequest);
            self.reassembly = None;
            self.dedup.clear();
        }
    }

    /// Marks the device authorized (the network key was installed by
    /// other means, e.g. a coordinator forming a network or a
    /// pre-configured network key).
    pub fn set_authorized(&mut self) {
        self.state = DeviceState::JoinedAuthorized;
    }

    /// Current time.
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// Acknowledges a persisted link-key counter reservation and resumes
    /// transmissions that were waiting for it.
    pub fn commit_counter_reservation(&mut self, partner: ExtendedAddress, r: Reservation) {
        self.security.commit_counter_reservation(partner, r);
        self.release_counter_pending();
        self.service_pending();
    }

    /// Advances time: acknowledgement timeouts, reassembly expiry and
    /// pending transmissions.
    pub fn poll_timers(&mut self, now: Instant) {
        if now.as_millis() > self.now.as_millis() {
            self.now = now;
        }
        self.expire_acks();
        self.expire_reassembly();
        self.request_counter_reservations();
        self.service_pending();
    }

    /// Earliest time [`Self::poll_timers`] should run.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut best: Option<Instant> = None;
        let mut consider = |t: Instant| {
            best = Some(match best {
                Some(b) if b.as_millis() <= t.as_millis() => b,
                _ => t,
            });
        };
        for p in &self.pending {
            match p.state {
                tx::TxState::AwaitingAck { deadline } => consider(deadline),
                tx::TxState::Ready => consider(self.now),
                _ => {}
            }
        }
        if let Some(r) = &self.reassembly {
            consider(r.deadline);
        }
        best
    }

    pub(crate) fn push_action(&mut self, a: ApsAction) {
        if self.actions.push_back(a).is_err() {
            self.stats.actions_dropped = self.stats.actions_dropped.saturating_add(1);
        }
    }

    pub(crate) fn push_event(&mut self, e: ApsEvent) {
        if self.events.push_back(e).is_err() {
            self.stats.events_dropped = self.stats.events_dropped.saturating_add(1);
        }
    }

    /// Sets the next APS counter value. R23.2 §2.2.5.1.7 only requires
    /// the counter to increment per transmission; starting at a random
    /// value after a reset keeps a rebooted device's first frames from
    /// colliding with entries still live in its peers' duplicate
    /// rejection tables (§2.2.8.4.2).
    pub fn seed_counter(&mut self, initial: u8) {
        self.counter = initial;
    }

    pub(crate) fn next_counter(&mut self) -> u8 {
        let c = self.counter;
        self.counter = self.counter.wrapping_add(1);
        c
    }

    pub(crate) fn alloc_request(&mut self) -> RequestId {
        let id = RequestId(self.next_request);
        self.next_request = self.next_request.wrapping_add(1).max(1);
        id
    }

    pub(crate) fn alloc_handle(&mut self) -> NwkHandle {
        let h = NwkHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        h
    }

    /// The Trust Center's key-pair entry partner address (the pre-installed
    /// placeholder while the Trust Center is unknown).
    pub(crate) fn trust_center_partner(&self) -> ExtendedAddress {
        self.aib.trust_center_address
    }

    /// Selects the key-pair partner and key identifier for securing a
    /// frame to `dst_ieee` (§4.4.1.1 step 1).
    pub(crate) fn link_key_for(&self, dst_ieee: ExtendedAddress) -> Option<ExtendedAddress> {
        if self.security.entry(dst_ieee).is_some() {
            return Some(dst_ieee);
        }
        None
    }

    /// Maximum ASDU that fits in one frame with the given header and
    /// security choice.
    pub(crate) fn frame_payload_max(&self, header: &Header, aps_security: Option<bool>) -> usize {
        use panweave_codec::Encode;
        let overhead = header.encoded_len()
            + aps_security.map_or(0, |ext| {
                ApsSecurity::<C, KEYS>::aux_header_len(ext) + self.config.security_level.mic_len()
            });
        self.config.nwk_max_payload.saturating_sub(overhead)
    }

    pub(crate) const fn key_id_for_command(cmd: ApsCommandId, key_type: KeyType) -> KeyIdentifier {
        match (cmd, key_type) {
            (ApsCommandId::TransportKey, KeyType::StandardNetworkKey) => {
                KeyIdentifier::KeyTransport
            }
            (ApsCommandId::TransportKey, _) => KeyIdentifier::KeyLoad,
            _ => KeyIdentifier::Data,
        }
    }
}
