//! The sans-I/O NWK layer state machine (R23.2 §3.6).
//!
//! [`Nwk`] consumes MAC-level inputs (received frames, beacons, MAC
//! confirmations, time) and higher-layer requests, and produces
//! [`NwkAction`]s for the MAC driver plus [`NwkEvent`]s for the APS layer.
//! It owns every NIB table and all NWK timers. It never touches hardware,
//! clocks, storage or global state; randomness comes from the injected
//! [`Rng`].
//!
//! Sub-modules split the behaviour by specification area:
//!
//! * [`tx`] — frame construction, security, unicast routing decision,
//!   NWK-level retries (§3.6.2.1, §3.6.4.3).
//! * [`rx`] — reception, filtering, security, relay, command dispatch
//!   (§3.6.2.2).
//! * [`route`] — route discovery, route reply, route record, network
//!   status handling, link status (§3.6.4).
//! * [`bcast`] — broadcast transactions and passive acknowledgement
//!   (§3.6.6).
//! * [`join`] — discovery, formation, joining, rejoining, leaving,
//!   permit joining, PAN-ID conflict (§3.6.1).
//! * [`maint`] — link status periods, child aging, end-device timeout
//!   negotiation (§3.6.10) and the timer loop.

mod bcast;
mod join;
mod maint;
mod route;
mod rx;
mod tx;

use heapless::{Deque, Vec};

use panweave_mac::service::{ScanKind, TxHandle, TxStatus};
use panweave_security::cipher::BlockCipher;
use panweave_security::frame_counter::Reservation;
use panweave_types::{
    Channel, ChannelMask, ChannelPage, Duration, ExtendedAddress, Instant, MacCapability,
    MacStatus, NwkStatus, PanId, Rng, ShortAddress,
};

use crate::address_map::AddressMap;
use crate::broadcast::BroadcastTransactionTable;
use crate::command::NetworkStatusCode;
use crate::discovery::DiscoveryTable;
use crate::neighbor::NeighborTable;
use crate::nib::Nib;
use crate::routing::{RouteDiscoveryTable, RoutingTable, SourceRouteTable};
use crate::security::NwkSecurity;

pub use join::{JoinMethod, JoinParams};
pub use rx::RxOutcome;

/// Maximum NPDU size: MAC payload with short addressing on both sides
/// (127 − 2 FCS − 9 header) minus nothing else.
pub const MAX_NPDU: usize = 116;

/// Fixed-capacity NPDU buffer.
pub type NpduBuf = Vec<u8, MAX_NPDU>;

/// Discovery table size (`nwkDiscoveryTableSize` default 6).
pub const DISCOVERY_TABLE_SIZE: usize = 6;

/// Number of unicast frames that can wait for a route or retry.
pub const PENDING_TX: usize = 4;

/// Number of broadcast frames buffered for relay.
pub const BROADCAST_BUFFERS: usize = 2;

/// Number of route requests buffered for jittered retransmission.
pub const PENDING_RREQ: usize = 4;

/// Capacity of the action/event queues.
pub const QUEUE_CAPACITY: usize = 16;

/// Maximum joiner TLV bytes carried in a join indication
/// (`apscJoinerTLVsUnfragmentedMaxSize` is 79; a smaller bound keeps the
/// event small).
pub const MAX_JOINER_TLVS: usize = 64;

/// Identifier of a higher-layer data request, echoed in
/// [`NwkEvent::DataConfirm`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxId(pub u16);

/// Errors returned synchronously by requests.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NwkError {
    /// The request is invalid in the current state
    /// (`INV_REQUESTTYPE`).
    InvalidRequest,
    /// A parameter is out of range (`INVALID_PARAMETER`).
    InvalidParameter,
    /// The payload does not fit in an NPDU.
    FrameTooLong,
    /// A queue or table is full; retry later (`FRAME_NOT_BUFFERED`).
    Busy,
    /// Security processing failed (no key, counter, or cipher failure).
    Security(NwkStatus),
    /// No route and route discovery not permitted (`ROUTE_ERROR`).
    RouteError,
    /// The device is not joined (`INV_REQUESTTYPE`).
    NotJoined,
    /// The outgoing frame counter cannot be used until the pending
    /// [`NwkAction::CounterReservation`] has been committed; the frame is
    /// retried automatically.
    CounterPending,
}

/// Static configuration of the layer.
#[derive(Clone, Debug)]
pub struct NwkConfig {
    /// Enable NWK security (`nwkSecurityLevel > 0`).
    pub security_enabled: bool,
    /// Use passive acknowledgement for broadcasts.
    pub passive_ack: bool,
    /// Act as a concentrator and keep a source route table.
    pub concentrator: bool,
    /// Concentrator discovery period in seconds (0 = manual).
    pub concentrator_discovery_time_secs: u32,
    /// Radius for many-to-one route requests (`nwkConcentratorRadius`).
    pub concentrator_radius: u8,
    /// Advertise hub connectivity in the Router Information TLV.
    pub hub_connectivity: bool,
    /// Keepalive methods a router parent advertises (parent information
    /// bits); both by default.
    pub keepalive_methods: u8,
    /// Whether to include the beacon appendix (R23 attach mechanisms).
    pub r23_beacon_appendix: bool,
}

impl Default for NwkConfig {
    fn default() -> Self {
        NwkConfig {
            security_enabled: true,
            passive_ack: true,
            concentrator: false,
            concentrator_discovery_time_secs: 0,
            concentrator_radius: 0,
            hub_connectivity: false,
            keepalive_methods: 0x03,
            r23_beacon_appendix: true,
        }
    }
}

/// An action the driver must perform on the MAC service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NwkAction {
    /// Send an NPDU as a MAC data frame.
    MacData {
        /// Internal identifier echoed in [`Nwk::on_mac_data_confirm`].
        handle: TxHandle,
        /// MAC destination short address.
        dst: ShortAddress,
        /// The NPDU.
        frame: NpduBuf,
        /// Request a MAC acknowledgement.
        ack: bool,
        /// Queue for indirect transmission to a sleepy child.
        indirect: bool,
    },
    /// Start a MAC scan.
    MacScan {
        /// Active or energy.
        kind: ScanKind,
        /// Channels.
        channels: ChannelMask,
        /// Scan duration exponent.
        duration: u8,
    },
    /// Start MAC association with a candidate parent (the driver must
    /// switch to `channel` first).
    MacAssociate {
        /// PAN.
        pan_id: PanId,
        /// Coordinator short address.
        coordinator: ShortAddress,
        /// Channel page.
        page: ChannelPage,
        /// Channel.
        channel: Channel,
        /// Capability information.
        capability: MacCapability,
    },
    /// Answer an association indication.
    MacAssociateResponse {
        /// Joiner.
        device: ExtendedAddress,
        /// Allocated address.
        short: ShortAddress,
        /// Status.
        status: MacStatus,
    },
    /// Start operating on a PAN (MLME-START).
    MacStart {
        /// PAN.
        pan_id: PanId,
        /// Page.
        page: ChannelPage,
        /// Channel.
        channel: Channel,
        /// Local short address.
        short: ShortAddress,
        /// PAN coordinator role.
        coordinator: bool,
        /// Respond to beacon requests.
        beacon_capable: bool,
    },
    /// Update `macAssociationPermit`.
    MacSetPermit(bool),
    /// Update the beacon payload.
    MacSetBeaconPayload(Vec<u8, 52>),
    /// Update the local short address.
    MacSetShortAddress(ShortAddress),
    /// Update the PAN identifier.
    MacSetPanId(PanId),
    /// Change channel.
    MacSetChannel {
        /// Page.
        page: ChannelPage,
        /// Channel.
        channel: Channel,
    },
    /// Set the parent addresses for polling.
    MacSetCoordinator {
        /// Parent short address.
        short: ShortAddress,
        /// Parent extended address.
        extended: ExtendedAddress,
    },
    /// Set `macRxOnWhenIdle`.
    MacSetRxOnWhenIdle(bool),
    /// Poll the parent (data request).
    MacPoll,
    /// Persistent NIB data changed; the runtime should schedule a commit.
    Persist,
    /// An outgoing frame-counter reservation must be persisted, then
    /// acknowledged with [`Nwk::commit_counter_reservation`].
    CounterReservation(Reservation),
}

/// Events for the next higher layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NwkEvent {
    /// Outcome of a data request (NLDE-DATA.confirm).
    DataConfirm {
        /// Request identifier.
        id: TxId,
        /// Status.
        status: NwkStatus,
    },
    /// Network discovery finished; results are in [`Nwk::discovery`].
    DiscoveryConfirm {
        /// Status.
        status: NwkStatus,
    },
    /// Network formation finished.
    FormationConfirm {
        /// Status.
        status: NwkStatus,
    },
    /// Join / rejoin finished (NLME-JOIN.confirm).
    JoinConfirm {
        /// Status.
        status: NwkStatus,
        /// Assigned network address.
        network_address: ShortAddress,
        /// Extended PAN ID joined.
        extended_pan_id: ExtendedAddress,
        /// Whether this was a rejoin.
        rejoin: bool,
        /// Whether the attach was secured (no key transport expected).
        secured: bool,
    },
    /// A child joined or rejoined (NLME-JOIN.indication).
    JoinIndication {
        /// Child extended address.
        device: ExtendedAddress,
        /// Child network address.
        network_address: ShortAddress,
        /// Capability information.
        capability: MacCapability,
        /// Attach mechanism.
        method: JoinMethod,
        /// Joiner Encapsulation TLV contents (R23), if any.
        joiner_tlvs: Vec<u8, MAX_JOINER_TLVS>,
    },
    /// The router is operating (NLME-START-ROUTER.confirm).
    StartRouterConfirm {
        /// Status.
        status: NwkStatus,
    },
    /// A device left, or this device was asked to leave
    /// (NLME-LEAVE.indication). `device == None` means the local device.
    LeaveIndication {
        /// The device that left, or `None` for self.
        device: Option<ExtendedAddress>,
        /// Network address of the device that left (`None` for self).
        short: Option<ShortAddress>,
        /// The device was a child of this router (§4.6.3.6.2).
        child: bool,
        /// Rejoin flag.
        rejoin: bool,
    },
    /// Outcome of a leave request.
    LeaveConfirm {
        /// Target (`None` = self).
        device: Option<ExtendedAddress>,
        /// Network address the target had (`None` for self).
        short: Option<ShortAddress>,
        /// Status.
        status: NwkStatus,
    },
    /// Network status indication (NLME-NWK-STATUS.indication).
    NetworkStatus {
        /// Address the status refers to.
        address: ShortAddress,
        /// Code.
        code: NetworkStatusCode,
    },
    /// Route discovery finished.
    RouteDiscoveryConfirm {
        /// Destination (broadcast address for many-to-one).
        destination: ShortAddress,
        /// Status.
        status: NwkStatus,
    },
    /// Permit-joining state changed.
    PermitJoining(bool),
    /// An end device child aged out or was removed.
    ChildRemoved {
        /// Child.
        device: ExtendedAddress,
    },
    /// The parent did not deliver the network key in time; the join
    /// failed with `NO_KEY` (already reported via `JoinConfirm`) and the
    /// device has left.
    AuthenticationTimeout,
    /// A Rejoin/Commissioning request was received from a device that is
    /// not a neighbor, or an end device sent through a different parent
    /// (lost child processing, §3.6.2.3).
    LostChild {
        /// Child.
        device: ExtendedAddress,
    },
    /// A PAN ID conflict was detected or resolved.
    PanIdChanged {
        /// New PAN identifier.
        pan_id: PanId,
    },
    /// An end device timeout response was received (parent information
    /// updated).
    ParentInformationUpdated,
    /// The active network key sequence changed (Switch Key applied).
    KeySwitched,
}

/// Requests accepted by [`Nwk::request`]; each also has a direct method.
#[derive(Clone, Debug)]
pub enum NwkRequest {
    /// Poll the parent for pending data.
    Poll,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingTx {
    id: TxId,
    /// Plaintext NPDU (header + payload) as originally built, kept for
    /// re-encryption on retry.
    frame: NpduBuf,
    /// Length of the NWK header inside `frame`.
    header_len: usize,
    /// Final destination.
    dst: ShortAddress,
    /// Next hop chosen for the current attempt.
    next_hop: ShortAddress,
    /// MAC handle of the current attempt.
    mac_handle: Option<TxHandle>,
    /// NWK-level retries remaining (`nwkcUnicastRetries`).
    retries_left: u8,
    /// Earliest time for the next attempt.
    retry_at: Option<Instant>,
    /// Waiting for a route to `dst`.
    awaiting_route: bool,
    /// Frame must be secured.
    secure: bool,
    /// Indirect (sleepy child).
    indirect: bool,
    /// The frame is a relay on behalf of `src` (report failures with a
    /// Network Status instead of a confirm).
    relayed_from: Option<ShortAddress>,
    /// Originator is one of our end-device children (route record on
    /// their behalf).
    source_route: bool,
    /// Kind of frame for confirm routing.
    kind: TxKind,
    /// Time the entry was created (for expiry while awaiting a route).
    created: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TxKind {
    /// Higher-layer data (confirm to APS).
    Data,
    /// A NWK command that needs no confirm.
    Command,
    /// A leave command whose confirm drives the leave procedure.
    Leave {
        /// Target (`None` = self).
        device: Option<ExtendedAddress>,
    },
    /// Join / rejoin request awaiting a response.
    JoinRequest,
    /// Rejoin/commissioning response toward a child (join indication after
    /// success).
    JoinResponse {
        /// Child.
        device: ExtendedAddress,
        /// How the child attached (reported in the join indication).
        method: JoinMethod,
    },
    /// Route reply relay (link failure → network status).
    RouteReply {
        /// Route reply originator (responder of the discovery).
        responder: ShortAddress,
    },
    /// End device timeout request.
    TimeoutRequest,
}

#[derive(Clone, Debug)]
pub(crate) struct BroadcastBuf {
    source: ShortAddress,
    sequence: u8,
    /// Secured NPDU ready for (re)transmission (empty until secured).
    frame: NpduBuf,
    /// Plaintext kept while the frame counter reservation is pending:
    /// `(npdu, header_len, secure)`.
    plaintext: Option<(NpduBuf, usize, bool)>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingRreq {
    frame: NpduBuf,
    due: Instant,
    retries_left: u8,
    interval: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ScanPurpose {
    Discovery,
    FormationEnergy,
    FormationActive,
    /// Active scan to verify a PAN ID choice / detect conflicts.
    PanIdConflict,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ScanState {
    purpose: ScanPurpose,
    channels: ChannelMask,
    duration: u8,
    /// For discovery: only report networks with permit joining.
    only_permit_join: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct FormationState {
    channels: ChannelMask,
    energy: [u8; 27],
    /// Networks found per channel during the active scan.
    networks_per_channel: [u8; 27],
    /// PAN IDs observed (to avoid conflicts), bounded.
    seen_pan_ids: Vec<PanId, 16>,
    distributed: bool,
}

/// The NWK layer.
///
/// Type parameters: block cipher `C`, random generator `R`, and table
/// capacities for neighbors, routes, route discoveries and broadcast
/// transactions.
pub struct Nwk<
    C: BlockCipher,
    R: Rng,
    const NEIGHBORS: usize,
    const ROUTES: usize,
    const RDT: usize,
    const BTT: usize,
> {
    /// Scalar NIB attributes.
    pub nib: Nib,
    /// Configuration.
    pub config: NwkConfig,
    /// Neighbor table.
    pub neighbors: NeighborTable<NEIGHBORS>,
    /// Routing table.
    pub routes: RoutingTable<ROUTES>,
    /// Route record (source route) table.
    pub source_routes: SourceRouteTable<ROUTES>,
    /// Address map.
    pub address_map: AddressMap<ROUTES>,
    /// Security material.
    pub security: NwkSecurity<C, NEIGHBORS>,
    pub(crate) rdt: RouteDiscoveryTable<RDT>,
    pub(crate) btt: BroadcastTransactionTable<BTT>,
    pub(crate) discovery: DiscoveryTable<DISCOVERY_TABLE_SIZE>,
    pub(crate) rng: R,
    pub(crate) actions: Deque<NwkAction, QUEUE_CAPACITY>,
    pub(crate) events: Deque<NwkEvent, QUEUE_CAPACITY>,
    pub(crate) pending: Vec<PendingTx, PENDING_TX>,
    pub(crate) bcast_bufs: Vec<BroadcastBuf, BROADCAST_BUFFERS>,
    pub(crate) pending_rreq: Vec<PendingRreq, PENDING_RREQ>,
    pub(crate) scan: Option<ScanState>,
    pub(crate) formation: Option<FormationState>,
    pub(crate) join: Option<join::JoinState>,
    pub(crate) permit_until: Option<Instant>,
    pub(crate) link_status_due: Option<Instant>,
    pub(crate) child_age_last: Instant,
    pub(crate) now: Instant,
    pub(crate) rreq_id: u8,
    pub(crate) next_tx_id: u16,
    pub(crate) next_mac_handle: u16,
    /// Time the node started operating on the network (broadcast
    /// self-origin suppression, §3.6.6).
    pub(crate) operating_since: Option<Instant>,
    /// Pending PAN ID update to apply at `at`.
    pub(crate) pan_id_update: Option<(PanId, u8, Instant)>,
    /// Keepalive deadline for end devices.
    pub(crate) keepalive_due: Option<Instant>,
    /// Timeout for an outstanding End Device Timeout Request.
    pub(crate) timeout_request_deadline: Option<Instant>,
    /// Joiner TLVs of the child whose attach response is in flight.
    pub(crate) pending_joiner_tlvs: Option<Vec<u8, MAX_JOINER_TLVS>>,
    /// The network uses distributed security (no Trust Center).
    pub(crate) distributed_network: bool,
    /// Rejoin flag of a local leave in progress.
    pub(crate) leaving_rejoin: Option<bool>,
    /// Statistics.
    pub stats: NwkStats,
}

/// Counters useful for diagnostics (never contain secrets).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NwkStats {
    /// Frames dropped as malformed.
    pub malformed: u32,
    /// Frames dropped by security processing.
    pub security_failures: u32,
    /// Frames dropped as replays (bad frame counter).
    pub replays: u32,
    /// Frames relayed.
    pub relayed: u32,
    /// Broadcasts relayed.
    pub broadcasts_relayed: u32,
    /// Route requests received.
    pub route_requests: u32,
    /// Unknown commands received.
    pub unknown_commands: u32,
    /// Frames dropped because no route existed.
    pub no_route: u32,
}

impl<
    C: BlockCipher,
    R: Rng,
    const NEIGHBORS: usize,
    const ROUTES: usize,
    const RDT: usize,
    const BTT: usize,
> Nwk<C, R, NEIGHBORS, ROUTES, RDT, BTT>
{
    /// Creates a layer with a fresh NIB.
    pub fn new(nib: Nib, config: NwkConfig, mut rng: R) -> Self {
        let mut nib = nib;
        nib.sequence_number = rng.next_u8();
        nib.is_concentrator = config.concentrator;
        nib.concentrator_radius = config.concentrator_radius;
        nib.concentrator_discovery_time_secs = config.concentrator_discovery_time_secs;
        nib.hub_connectivity = config.hub_connectivity;
        Nwk {
            nib,
            config,
            neighbors: NeighborTable::new(),
            routes: RoutingTable::new(),
            source_routes: SourceRouteTable::new(),
            address_map: AddressMap::new(),
            security: NwkSecurity::new(),
            rdt: RouteDiscoveryTable::new(),
            btt: BroadcastTransactionTable::new(),
            discovery: DiscoveryTable::new(),
            rreq_id: rng.next_u8(),
            rng,
            actions: Deque::new(),
            events: Deque::new(),
            pending: Vec::new(),
            bcast_bufs: Vec::new(),
            pending_rreq: Vec::new(),
            scan: None,
            formation: None,
            join: None,
            permit_until: None,
            link_status_due: None,
            child_age_last: Instant::ZERO,
            now: Instant::ZERO,
            next_tx_id: 1,
            next_mac_handle: 1,
            operating_since: None,
            pan_id_update: None,
            keepalive_due: None,
            timeout_request_deadline: None,
            pending_joiner_tlvs: None,
            distributed_network: false,
            leaving_rejoin: None,
            stats: NwkStats::default(),
        }
    }

    /// Takes the next action for the driver.
    pub fn next_action(&mut self) -> Option<NwkAction> {
        self.actions.pop_front()
    }

    /// Takes the next event for the higher layer.
    pub fn next_event(&mut self) -> Option<NwkEvent> {
        self.events.pop_front()
    }

    /// True when actions or events are queued.
    pub fn has_output(&self) -> bool {
        !self.actions.is_empty() || !self.events.is_empty()
    }

    /// The discovery table (after [`NwkEvent::DiscoveryConfirm`]).
    pub const fn discovery(&self) -> &DiscoveryTable<DISCOVERY_TABLE_SIZE> {
        &self.discovery
    }

    /// Current time as last supplied to [`Nwk::poll_timers`].
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// Mutable access to the random generator.
    pub fn rng(&mut self) -> &mut R {
        &mut self.rng
    }

    pub(crate) fn push_action(&mut self, a: NwkAction) {
        if let Err(a) = self.actions.push_back(a) {
            debug_assert!(false, "NWK action queue overflow");
            let _ = self.actions.pop_front();
            let _ = self.actions.push_back(a);
        }
    }

    pub(crate) fn push_event(&mut self, e: NwkEvent) {
        if let Err(e) = self.events.push_back(e) {
            debug_assert!(false, "NWK event queue overflow");
            let _ = self.events.pop_front();
            let _ = self.events.push_back(e);
        }
    }

    pub(crate) fn alloc_tx_id(&mut self) -> TxId {
        let id = TxId(self.next_tx_id);
        self.next_tx_id = self.next_tx_id.wrapping_add(1).max(1);
        id
    }

    pub(crate) fn alloc_mac_handle(&mut self) -> TxHandle {
        let h = TxHandle(self.next_mac_handle);
        self.next_mac_handle = self.next_mac_handle.wrapping_add(1).max(1);
        h
    }

    /// Uniform random duration in `lo..=hi`.
    pub(crate) fn jitter(&mut self, lo: Duration, hi: Duration) -> Duration {
        let span = hi.as_millis().saturating_sub(lo.as_millis());
        let off = if span == 0 {
            0
        } else {
            u64::from(self.rng.below(u32::try_from(span + 1).unwrap_or(u32::MAX)))
        };
        Duration::from_millis(lo.as_millis() + off)
    }

    /// Records the outcome of persisting a counter reservation.
    pub fn commit_counter_reservation(&mut self, r: Reservation) {
        self.security.commit_counter_reservation(r);
    }

    /// Checks whether a counter reservation is needed and emits the action.
    pub(crate) fn maybe_reserve_counter(&mut self) {
        if let Some(r) = self.security.start_counter_reservation() {
            self.push_action(NwkAction::CounterReservation(r));
        }
    }

    /// Restores persisted state after a warm start (§3.6.1.12): the
    /// caller sets NIB identity fields and keys, then calls this to derive
    /// operating state.
    pub fn warm_start(&mut self) {
        if self.nib.network_address != ShortAddress::NO_SHORT_ADDRESS
            && self.nib.pan_id != PanId::BROADCAST
            && self.security.has_key()
        {
            self.nib.joined = true;
            self.nib.authenticated = true;
        }
        // Children get a full timeout period after reboot (§3.6.10.8).
        for e in self.neighbors.iter_mut() {
            if e.relationship.is_child() && e.is_end_device() {
                e.timeout_counter_secs = e.device_timeout_secs;
                e.keepalive_received = false;
            }
        }
    }

    /// Whether the layer is joined and holds the network key.
    pub const fn is_operational(&self) -> bool {
        self.nib.joined && self.nib.authenticated
    }

    /// Maps a MAC transmit status to a NWK status.
    pub(crate) const fn mac_status_to_nwk(s: TxStatus) -> NwkStatus {
        match s {
            TxStatus::Success => NwkStatus::Success,
            TxStatus::NoAck => NwkStatus::Unknown(0xE9),
            TxStatus::ChannelAccessFailure => NwkStatus::Unknown(0xE1),
            TxStatus::TransactionExpired => NwkStatus::Unknown(0xF0),
            TxStatus::RadioError => NwkStatus::Unknown(0xE3),
        }
    }
}
