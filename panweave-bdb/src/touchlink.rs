//! Touchlink commissioning (BDB 3.1 §12; ZCL8 §13.3): the initiator
//! procedure (§12.1) — device discovery over the primary and secondary
//! channel sets, target selection, optional device information and
//! identify, network start / join with address and group assignment —
//! and the target procedure (§12.2) — scan responses, the transaction
//! lifetime, network start / join / update requests under a stealing
//! policy, and the touchlink reset. Both are sans-I/O machines driving a
//! [`TouchlinkNode`] (the runtime), fed with inter-PAN frames by
//! [`Initiator::on_inter_pan`] / [`Target::on_inter_pan`] and with time
//! by `poll`.

use heapless::Vec;
use panweave_codec::Writer;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    Channel, ChannelMask, CommandId, ExtendedAddress, Key128, LogicalDeviceType, PanId,
    ShortAddress,
};
use panweave_zcl::clusters::touchlink as tl;
use panweave_zcl::frame::Direction;

use crate::NodeError;
use crate::constants::{TL_PRIMARY_CHANNEL_SET, TL_SECONDARY_CHANNEL_SET};

/// Largest inter-PAN command payload.
pub const MAX_PAYLOAD: usize = 64;
/// Candidates remembered from one device discovery.
pub const MAX_CANDIDATES: usize = 4;
/// Sub-devices a node reports.
pub const MAX_SUB_DEVICES: usize = 8;
/// Scan requests on the first channel (§12.1 step 2).
const FIRST_CHANNEL_SCANS: u8 = 5;
/// Smallest free range worth splitting (implementation threshold,
/// §13.3.4.8.1).
const MIN_RANGE: u16 = 16;

/// Destination of an inter-PAN command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterPanDestination {
    /// Broadcast (short 0xffff, no acknowledgement).
    Broadcast,
    /// Unicast to an IEEE address (acknowledged).
    Device(ExtendedAddress),
}

/// The network a node operates on, as touchlink sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkInfo {
    /// Extended PAN identifier.
    pub extended_pan_id: u64,
    /// PAN identifier.
    pub pan_id: PanId,
    /// Logical channel.
    pub channel: Channel,
    /// `nwkUpdateId`.
    pub update_id: u8,
    /// Network address.
    pub short: ShortAddress,
    /// On a centralized security network (Trust Center present).
    pub centralized: bool,
}

/// Network parameters a target starts or joins with, and a factory new
/// initiator adopts.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkParams {
    /// Extended PAN identifier.
    pub extended_pan_id: u64,
    /// PAN identifier.
    pub pan_id: PanId,
    /// Logical channel.
    pub channel: Channel,
    /// `nwkUpdateId`.
    pub update_id: u8,
    /// Network key.
    pub key: Key128,
    /// Own network address.
    pub short: ShortAddress,
    /// Group identifier range for the endpoints (begin, end), when any.
    pub groups: Option<(u16, u16)>,
    /// Free ranges granted for further assignment.
    pub ranges: Option<AddressRanges>,
    /// A neighbour to add: the initiator (IEEE, short) of a network
    /// start.
    pub neighbour: Option<(ExtendedAddress, ShortAddress)>,
}

/// `aplFreeNwkAddrRange*` and `aplFreeGroupIDRange*` (Table 13-22).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddressRanges {
    /// Free network address range begin.
    pub addresses_begin: u16,
    /// Free network address range end.
    pub addresses_end: u16,
    /// Free group identifier range begin.
    pub groups_begin: u16,
    /// Free group identifier range end.
    pub groups_end: u16,
}

impl AddressRanges {
    /// The factory-new ranges (§13.3.4.8).
    pub const FACTORY_NEW: AddressRanges = AddressRanges {
        addresses_begin: 0x0001,
        addresses_end: 0xfff7,
        groups_begin: 0x0001,
        groups_end: 0xfeff,
    };
    /// No ranges (joined by network steering).
    pub const NONE: AddressRanges = AddressRanges {
        addresses_begin: 0,
        addresses_end: 0,
        groups_begin: 0,
        groups_end: 0,
    };

    /// Whether this node assigns addresses.
    pub const fn is_capable(&self) -> bool {
        self.addresses_begin != 0
    }

    /// Takes the next network address (§13.3.4.8.1).
    pub fn next_address(&mut self) -> Option<ShortAddress> {
        if !self.is_capable() || self.addresses_begin > self.addresses_end {
            return None;
        }
        let a = self.addresses_begin;
        self.addresses_begin = self.addresses_begin.saturating_add(1);
        Some(ShortAddress(a))
    }

    /// Takes `count` group identifiers (§13.3.4.8.2).
    pub fn take_groups(&mut self, count: u8) -> Option<(u16, u16)> {
        if count == 0 || self.groups_begin == 0 {
            return None;
        }
        let end = self.groups_begin.checked_add(u16::from(count) - 1)?;
        if end > self.groups_end {
            return None;
        }
        let begin = self.groups_begin;
        self.groups_begin = end.saturating_add(1);
        Some((begin, end))
    }

    /// Splits the upper halves off for an address-assignment-capable
    /// joiner; `None` when a half would fall under the threshold.
    pub fn split(&mut self) -> Option<AddressRanges> {
        if !self.is_capable() {
            return None;
        }
        let addr_span = self.addresses_end.checked_sub(self.addresses_begin)?;
        let group_span = self.groups_end.checked_sub(self.groups_begin)?;
        if addr_span / 2 < MIN_RANGE || group_span / 2 < MIN_RANGE {
            return None;
        }
        let addr_mid = self.addresses_begin + addr_span / 2;
        let group_mid = self.groups_begin + group_span / 2;
        let upper = AddressRanges {
            addresses_begin: addr_mid + 1,
            addresses_end: self.addresses_end,
            groups_begin: group_mid + 1,
            groups_end: self.groups_end,
        };
        self.addresses_end = addr_mid;
        self.groups_end = group_mid;
        Some(upper)
    }
}

/// What the machines need from the node.
pub trait TouchlinkNode {
    /// Current time.
    fn now(&self) -> Instant;
    /// A random 32-bit value.
    fn random_u32(&mut self) -> u32;
    /// IEEE address.
    fn ieee(&self) -> ExtendedAddress;
    /// Logical device type.
    fn role(&self) -> LogicalDeviceType;
    /// The device information table (§13.3.4.4).
    fn sub_devices(&self, out: &mut Vec<tl::DeviceRecord, MAX_SUB_DEVICES>);
    /// The current network, `None` when factory new / not on a network.
    fn network(&self) -> Option<NetworkInfo>;
    /// The network key of the current network (an initiator transports
    /// it to a joining target).
    fn network_key(&self) -> Option<Key128>;
    /// Switches the radio to `channel` (the inter-PAN channel).
    fn set_channel(&mut self, channel: Channel);
    /// Sends an inter-PAN Touchlink Commissioning command.
    fn send_inter_pan(
        &mut self,
        dst: InterPanDestination,
        src_pan: PanId,
        command: CommandId,
        direction: Direction,
        payload: &[u8],
    ) -> Result<(), NodeError>;
    /// Identifies for `seconds` (0 stops, 0xffff default).
    fn identify(&mut self, seconds: u16);
    /// Key bitmask of the supported transport keys (§13.3.2.3.1.5).
    fn key_bitmask(&self) -> u16;
    /// Encrypts a network key for transport (§13.3.4.11).
    fn encrypt_network_key(
        &mut self,
        key_index: u8,
        transaction: u32,
        response: u32,
        key: &Key128,
    ) -> Option<[u8; 16]>;
    /// Decrypts a received network key.
    fn decrypt_network_key(
        &mut self,
        key_index: u8,
        transaction: u32,
        response: u32,
        encrypted: &[u8; 16],
    ) -> Option<Key128>;
    /// Target: starts a new distributed network with `params` (leaving
    /// the old one first) and adds the initiator as a neighbour.
    fn start_network(&mut self, params: &NetworkParams) -> Result<(), NodeError>;
    /// Target: joins the initiator's network with `params` (leaving the
    /// old one first): a router starts routing, an end device rejoins.
    fn join_network(&mut self, params: &NetworkParams) -> Result<(), NodeError>;
    /// Initiator: adopts the network the target started and rejoins.
    fn adopt_network(&mut self, params: &NetworkParams) -> Result<(), NodeError>;
    /// Applies a newer `nwkUpdateId` and channel (§13.3.4.9).
    fn update_network(&mut self, update_id: u8, channel: Channel);
    /// Resets to factory new (§13.2).
    fn factory_reset(&mut self);
}

/// A discovered target (§12.1 step 5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Candidate {
    /// IEEE address (MAC source of the scan response).
    pub ieee: ExtendedAddress,
    /// Source PAN of the scan response.
    pub pan: PanId,
    /// Channel it answered on.
    pub channel: Channel,
    /// RSSI of the response, corrected.
    pub rssi: i8,
    /// The scan response.
    pub response: tl::ScanResponse,
}

/// Why an initiator procedure failed (§12.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Failure {
    /// No scan responses.
    NoScanResponses,
    /// No common key with the target.
    NoCommonKey,
    /// The initiator is on a centralized network (step 9).
    NotPermitted,
    /// The initiator cannot assign addresses (step 10).
    NotAddressAssignmentCapable,
    /// No network could be started (steps 13, 15).
    NoNetwork,
    /// The target refused or did not answer (step 23).
    TargetFailure,
    /// The node refused an operation.
    Node(NodeError),
}

/// Result of an initiator step.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InitiatorOutcome {
    /// Discovery finished: pick a target with [`Initiator::select`].
    Discovered(Vec<Candidate, MAX_CANDIDATES>),
    /// A Device Information Response arrived.
    DeviceInformation(tl::DeviceInformationResponse),
    /// The procedure succeeded with `target`.
    Success {
        /// The commissioned target.
        target: ExtendedAddress,
        /// The target's network address on the (new) network.
        short: ShortAddress,
    },
    /// The target was reset to factory new.
    ResetSent,
    /// The procedure failed.
    Failed(Failure),
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum InitiatorState {
    Idle,
    Scanning {
        channels: ChannelMask,
        remaining: ChannelMask,
        current: Channel,
        sends_left: u8,
        secondary_pending: bool,
        next_send: Instant,
    },
    Selecting,
    WaitingStart {
        deadline: Instant,
        params: NetworkParams,
    },
    WaitingJoin {
        deadline: Instant,
        short: ShortAddress,
    },
    StartupDelay {
        deadline: Instant,
        params: Option<NetworkParams>,
        short: ShortAddress,
    },
}

/// The initiator procedure (§12.1).
#[derive(Clone, Debug)]
pub struct Initiator {
    /// The transport key index to use (4 master, 15 certification).
    pub key_index: u8,
    /// The address and group ranges this node assigns from.
    pub ranges: AddressRanges,
    /// Own RSSI correction.
    pub rssi_correction: u8,
    transaction: u32,
    state: InitiatorState,
    candidates: Vec<Candidate, MAX_CANDIDATES>,
    target: Option<Candidate>,
    reset: bool,
    src_pan: PanId,
}

impl Initiator {
    /// A new initiator with the factory-new ranges.
    pub const fn new(key_index: u8) -> Self {
        Initiator {
            key_index,
            ranges: AddressRanges::FACTORY_NEW,
            rssi_correction: 0,
            transaction: 0,
            state: InitiatorState::Idle,
            candidates: Vec::new(),
            target: None,
            reset: false,
            src_pan: PanId(0xffff),
        }
    }

    /// Whether a procedure is running.
    pub fn is_busy(&self) -> bool {
        !matches!(self.state, InitiatorState::Idle)
    }

    /// The transaction identifier of the running procedure.
    pub const fn transaction(&self) -> u32 {
        self.transaction
    }

    /// The targets found by the last device discovery.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Next instant `poll` should run.
    pub fn next_deadline(&self) -> Option<Instant> {
        match &self.state {
            InitiatorState::Scanning { next_send, .. } => Some(*next_send),
            InitiatorState::WaitingStart { deadline, .. }
            | InitiatorState::WaitingJoin { deadline, .. }
            | InitiatorState::StartupDelay { deadline, .. } => Some(*deadline),
            _ => None,
        }
    }

    /// Starts device discovery (§12.1 steps 1–2); `extended` also scans
    /// the secondary channel set, `reset` marks a touchlink reset of the
    /// eventual target.
    pub fn start(&mut self, node: &mut impl TouchlinkNode, extended: bool, reset: bool) {
        let mut trid = node.random_u32();
        while trid == 0 {
            trid = node.random_u32();
        }
        self.transaction = trid;
        self.candidates.clear();
        self.target = None;
        self.reset = reset;
        self.src_pan = node.network().map_or_else(
            || PanId(0x0001 + u16::try_from(trid & 0x7ffe).unwrap_or(1)),
            |n| n.pan_id,
        );
        let channels = TL_PRIMARY_CHANNEL_SET;
        let Some(first) = channels.first() else {
            self.state = InitiatorState::Idle;
            return;
        };
        self.state = InitiatorState::Scanning {
            channels,
            remaining: channels.without(first),
            current: first,
            sends_left: FIRST_CHANNEL_SCANS,
            secondary_pending: extended,
            next_send: node.now(),
        };
        node.set_channel(first);
    }

    fn scan_request(&self, node: &mut impl TouchlinkNode) -> Result<(), NodeError> {
        let on_network = node.network().is_some();
        let req = tl::ScanRequest {
            transaction: self.transaction,
            zigbee: tl::ZigbeeInfo {
                logical_type: match node.role() {
                    LogicalDeviceType::Coordinator => 0,
                    LogicalDeviceType::Router => 1,
                    LogicalDeviceType::EndDevice => 2,
                },
                rx_on_when_idle: node.role() != LogicalDeviceType::EndDevice,
            },
            touchlink: tl::TouchlinkInfo {
                factory_new: !on_network,
                address_assignment: self.ranges.is_capable(),
                initiator: true,
                priority_request: false,
                profile_interop: true,
            },
        };
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).map_err(|_| NodeError::Unsupported)?;
        let n = w.position();
        node.send_inter_pan(
            InterPanDestination::Broadcast,
            self.src_pan,
            tl::CMD_SCAN_REQUEST,
            Direction::ToServer,
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Advances the timers.
    pub fn poll(
        &mut self,
        node: &mut impl TouchlinkNode,
        now: Instant,
    ) -> Option<InitiatorOutcome> {
        match self.state.clone() {
            InitiatorState::Scanning {
                channels,
                remaining,
                current,
                sends_left,
                secondary_pending,
                next_send,
            } => {
                if !now.has_reached(next_send) {
                    return None;
                }
                if sends_left > 0 {
                    let _ = self.scan_request(node);
                    self.state = InitiatorState::Scanning {
                        channels,
                        remaining,
                        current,
                        sends_left: sends_left - 1,
                        secondary_pending,
                        next_send: now.saturating_add(Duration::from_millis(tl::SCAN_TIME_BASE_MS)),
                    };
                    return None;
                }
                if let Some(next) = remaining.first() {
                    node.set_channel(next);
                    self.state = InitiatorState::Scanning {
                        channels,
                        remaining: remaining.without(next),
                        current: next,
                        sends_left: 1,
                        secondary_pending,
                        next_send: now,
                    };
                    return None;
                }
                if secondary_pending {
                    let secondary = TL_SECONDARY_CHANNEL_SET;
                    if let Some(first) = secondary.first() {
                        node.set_channel(first);
                        self.state = InitiatorState::Scanning {
                            channels: secondary,
                            remaining: secondary.without(first),
                            current: first,
                            sends_left: 1,
                            secondary_pending: false,
                            next_send: now,
                        };
                        return None;
                    }
                }
                if self.candidates.is_empty() {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoScanResponses));
                }
                self.state = InitiatorState::Selecting;
                Some(InitiatorOutcome::Discovered(self.candidates.clone()))
            }
            InitiatorState::WaitingStart { deadline, .. }
            | InitiatorState::WaitingJoin { deadline, .. } => {
                if now.has_reached(deadline) {
                    self.state = InitiatorState::Idle;
                    Some(InitiatorOutcome::Failed(
                        if matches!(self.state, InitiatorState::WaitingStart { .. }) {
                            Failure::NoNetwork
                        } else {
                            Failure::TargetFailure
                        },
                    ))
                } else {
                    None
                }
            }
            InitiatorState::StartupDelay {
                deadline,
                params,
                short,
            } => {
                if !now.has_reached(deadline) {
                    return None;
                }
                self.state = InitiatorState::Idle;
                if let Some(p) = params
                    && let Err(e) = node.adopt_network(&p)
                {
                    return Some(InitiatorOutcome::Failed(Failure::Node(e)));
                }
                let target = self.target.map_or(ExtendedAddress::ZERO, |c| c.ieee);
                Some(InitiatorOutcome::Success { target, short })
            }
            _ => None,
        }
    }

    /// A received inter-PAN Touchlink command (server → client
    /// direction) from `src` on `src_pan` with `rssi`.
    pub fn on_inter_pan(
        &mut self,
        node: &mut impl TouchlinkNode,
        src: ExtendedAddress,
        src_pan: PanId,
        command: CommandId,
        payload: &[u8],
        rssi: i8,
    ) -> Option<InitiatorOutcome> {
        match command {
            tl::CMD_SCAN_RESPONSE => {
                let InitiatorState::Scanning { current, .. } = self.state else {
                    return None;
                };
                let r = tl::ScanResponse::parse(payload).ok()?;
                if r.transaction != self.transaction {
                    return None;
                }
                if self.candidates.iter().any(|c| c.ieee == src) {
                    return None;
                }
                let corrected = rssi.saturating_add(i8::try_from(r.rssi_correction).unwrap_or(0));
                let c = Candidate {
                    ieee: src,
                    pan: src_pan,
                    channel: current,
                    rssi: corrected,
                    response: r,
                };
                let _ = self.candidates.push(c);
                None
            }
            tl::CMD_DEVICE_INFORMATION_RESPONSE => {
                let r = tl::DeviceInformationResponse::parse(payload).ok()?;
                (r.transaction == self.transaction)
                    .then_some(InitiatorOutcome::DeviceInformation(r))
            }
            tl::CMD_NETWORK_START_RESPONSE => {
                let InitiatorState::WaitingStart { params, .. } = self.state.clone() else {
                    return None;
                };
                let r = tl::NetworkStartResponse::parse(payload).ok()?;
                if r.transaction != self.transaction || self.target.is_none_or(|t| t.ieee != src) {
                    return None;
                }
                if r.status != tl::STATUS_SUCCESS {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoNetwork));
                }
                let channel = Channel::new_2_4ghz(r.channel).unwrap_or(params.channel);
                let adopted = NetworkParams {
                    extended_pan_id: r.extended_pan_id,
                    pan_id: PanId(r.pan_id),
                    channel,
                    update_id: r.update_id,
                    ..params
                };
                let short = self
                    .target
                    .map_or(ShortAddress::NO_SHORT_ADDRESS, |_| ShortAddress(0x0002));
                self.state = InitiatorState::StartupDelay {
                    deadline: node
                        .now()
                        .saturating_add(Duration::from_millis(tl::MIN_STARTUP_DELAY_MS)),
                    params: Some(adopted),
                    short,
                };
                None
            }
            tl::CMD_NETWORK_JOIN_ROUTER_RESPONSE | tl::CMD_NETWORK_JOIN_END_DEVICE_RESPONSE => {
                let InitiatorState::WaitingJoin { short, .. } = self.state else {
                    return None;
                };
                let r = tl::StatusResponse::parse(payload).ok()?;
                if r.transaction != self.transaction || self.target.is_none_or(|t| t.ieee != src) {
                    return None;
                }
                if r.status != tl::STATUS_SUCCESS {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::TargetFailure));
                }
                self.state = InitiatorState::StartupDelay {
                    deadline: node
                        .now()
                        .saturating_add(Duration::from_millis(tl::MIN_STARTUP_DELAY_MS)),
                    params: None,
                    short,
                };
                None
            }
            _ => None,
        }
    }

    /// Requests the device information table of a discovered target
    /// (§12.1 step 6).
    pub fn request_device_information(
        &mut self,
        node: &mut impl TouchlinkNode,
        target: &Candidate,
        start_index: u8,
    ) -> Result<(), NodeError> {
        node.set_channel(target.channel);
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        tl::DeviceInformationRequest {
            transaction: self.transaction,
            start_index,
        }
        .encode(&mut w)
        .map_err(|_| NodeError::Unsupported)?;
        let n = w.position();
        node.send_inter_pan(
            InterPanDestination::Device(target.ieee),
            self.src_pan,
            tl::CMD_DEVICE_INFORMATION_REQUEST,
            Direction::ToServer,
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Asks a discovered target to identify (§12.1 step 6).
    pub fn identify_target(
        &mut self,
        node: &mut impl TouchlinkNode,
        target: &Candidate,
        duration: u16,
    ) -> Result<(), NodeError> {
        node.set_channel(target.channel);
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        tl::IdentifyRequest {
            transaction: self.transaction,
            duration,
        }
        .encode(&mut w)
        .map_err(|_| NodeError::Unsupported)?;
        let n = w.position();
        node.send_inter_pan(
            InterPanDestination::Device(target.ieee),
            self.src_pan,
            tl::CMD_IDENTIFY_REQUEST,
            Direction::ToServer,
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Selects a discovered target and continues the procedure (§12.1
    /// steps 7–24).
    pub fn select(
        &mut self,
        node: &mut impl TouchlinkNode,
        target: &Candidate,
    ) -> Option<InitiatorOutcome> {
        if !matches!(self.state, InitiatorState::Selecting) {
            return None;
        }
        self.target = Some(*target);
        node.set_channel(target.channel);
        let r = &target.response;
        let network = node.network();
        let same_network = network.is_some_and(|n| n.extended_pan_id == r.extended_pan_id);
        if same_network && !self.reset {
            // Step 8: reconcile nwkUpdateId.
            let n = network?;
            let newer = tl::newer_update_id(n.update_id, r.update_id);
            if newer != n.update_id {
                if let Some(ch) = Channel::new_2_4ghz(r.channel) {
                    node.update_network(newer, ch);
                }
            } else if n.update_id != r.update_id {
                let _ = self.network_update(node, target, &n);
            }
            self.state = InitiatorState::Idle;
            return Some(InitiatorOutcome::Success {
                target: target.ieee,
                short: ShortAddress(r.network_address),
            });
        }
        // Step 9–10.
        if network.is_some_and(|n| n.centralized) {
            self.state = InitiatorState::Idle;
            return Some(InitiatorOutcome::Failed(Failure::NotPermitted));
        }
        if !self.ranges.is_capable() {
            self.state = InitiatorState::Idle;
            return Some(InitiatorOutcome::Failed(
                Failure::NotAddressAssignmentCapable,
            ));
        }
        if node.key_bitmask() & r.key_bitmask & (1 << self.key_index) == 0 {
            self.state = InitiatorState::Idle;
            return Some(InitiatorOutcome::Failed(Failure::NoCommonKey));
        }
        if self.reset {
            // Step 21.
            let mut buf = [0u8; 4];
            let mut w = Writer::new(&mut buf);
            let _ = w.u32_le(self.transaction);
            let sent = node.send_inter_pan(
                InterPanDestination::Device(target.ieee),
                self.src_pan,
                tl::CMD_RESET_TO_FACTORY_NEW_REQUEST,
                Direction::ToServer,
                &buf,
            );
            self.state = InitiatorState::Idle;
            return Some(match sent {
                Ok(()) => InitiatorOutcome::ResetSent,
                Err(e) => InitiatorOutcome::Failed(Failure::Node(e)),
            });
        }
        // A factory new initiator takes the first address for itself
        // before assigning the target's (§13.3.4.8.1).
        let own = if network.is_none() {
            self.ranges.next_address()
        } else {
            None
        };
        let Some(assignment) = self.assign(r) else {
            self.state = InitiatorState::Idle;
            return Some(InitiatorOutcome::Failed(Failure::NoNetwork));
        };
        match network {
            None => {
                // Steps 11–14: a factory new initiator starts a network
                // with a router target (a router initiator forms one
                // itself, which this machine leaves to the BDB
                // formation procedure).
                if node.role() == LogicalDeviceType::Router {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoNetwork));
                }
                if !r.zigbee.is_router() {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoNetwork));
                }
                let key = Key128::from_bytes(random_key(node));
                let Some(encrypted) =
                    node.encrypt_network_key(self.key_index, self.transaction, r.response, &key)
                else {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoCommonKey));
                };
                let own = own.unwrap_or(ShortAddress(0x0001));
                let req = tl::NetworkStartRequest {
                    transaction: self.transaction,
                    extended_pan_id: 0,
                    key_index: self.key_index,
                    encrypted_key: encrypted,
                    channel: 0,
                    pan_id: 0,
                    assignment,
                    initiator_ieee: node.ieee().0,
                    initiator_address: own.0,
                };
                let mut buf = [0u8; MAX_PAYLOAD];
                let mut w = Writer::new(&mut buf);
                if req.encode(&mut w).is_err() {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoNetwork));
                }
                let n = w.position();
                if let Err(e) = node.send_inter_pan(
                    InterPanDestination::Device(target.ieee),
                    self.src_pan,
                    tl::CMD_NETWORK_START_REQUEST,
                    Direction::ToServer,
                    buf.get(..n).unwrap_or(&[]),
                ) {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::Node(e)));
                }
                self.state = InitiatorState::WaitingStart {
                    deadline: node
                        .now()
                        .saturating_add(Duration::from_millis(tl::RX_WINDOW_MS)),
                    params: NetworkParams {
                        extended_pan_id: 0,
                        pan_id: PanId(0),
                        channel: target.channel,
                        update_id: 0,
                        key,
                        short: own,
                        groups: None,
                        ranges: Some(self.ranges),
                        neighbour: Some((target.ieee, ShortAddress(assignment.network_address))),
                    },
                };
                None
            }
            Some(n) => {
                // Step 22: join the target to our network.
                let Some(key) = node.network_key() else {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoNetwork));
                };
                let Some(encrypted) =
                    node.encrypt_network_key(self.key_index, self.transaction, r.response, &key)
                else {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::NoCommonKey));
                };
                let req = tl::NetworkJoinRequest {
                    transaction: self.transaction,
                    extended_pan_id: n.extended_pan_id,
                    key_index: self.key_index,
                    encrypted_key: encrypted,
                    update_id: n.update_id,
                    channel: n.channel.raw(),
                    pan_id: n.pan_id.0,
                    assignment,
                };
                let mut buf = [0u8; MAX_PAYLOAD];
                let mut w = Writer::new(&mut buf);
                if req.encode(&mut w).is_err() {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::TargetFailure));
                }
                let len = w.position();
                let command = if r.zigbee.is_router() {
                    tl::CMD_NETWORK_JOIN_ROUTER_REQUEST
                } else {
                    tl::CMD_NETWORK_JOIN_END_DEVICE_REQUEST
                };
                if let Err(e) = node.send_inter_pan(
                    InterPanDestination::Device(target.ieee),
                    self.src_pan,
                    command,
                    Direction::ToServer,
                    buf.get(..len).unwrap_or(&[]),
                ) {
                    self.state = InitiatorState::Idle;
                    return Some(InitiatorOutcome::Failed(Failure::Node(e)));
                }
                self.state = InitiatorState::WaitingJoin {
                    deadline: node
                        .now()
                        .saturating_add(Duration::from_millis(tl::RX_WINDOW_MS)),
                    short: ShortAddress(assignment.network_address),
                };
                None
            }
        }
    }

    /// Address and group assignment for a target (§12.1.1.3 – .5).
    fn assign(&mut self, r: &tl::ScanResponse) -> Option<tl::NetworkAssignment> {
        let address = self.ranges.next_address()?;
        let groups = if r.total_groups > 0 {
            self.ranges.take_groups(r.total_groups)
        } else {
            None
        };
        let free = if r.touchlink.address_assignment {
            self.ranges.split()
        } else {
            None
        };
        Some(tl::NetworkAssignment {
            network_address: address.0,
            groups_begin: groups.map_or(0, |g| g.0),
            groups_end: groups.map_or(0, |g| g.1),
            free_addresses_begin: free.map_or(0, |f| f.addresses_begin),
            free_addresses_end: free.map_or(0, |f| f.addresses_end),
            free_groups_begin: free.map_or(0, |f| f.groups_begin),
            free_groups_end: free.map_or(0, |f| f.groups_end),
        })
    }

    /// Network Update Request to a target that missed a channel change
    /// (§13.3.4.9.1).
    fn network_update(
        &self,
        node: &mut impl TouchlinkNode,
        target: &Candidate,
        n: &NetworkInfo,
    ) -> Result<(), NodeError> {
        let mut buf = [0u8; 24];
        let mut w = Writer::new(&mut buf);
        tl::NetworkUpdateRequest {
            transaction: self.transaction,
            extended_pan_id: n.extended_pan_id,
            update_id: n.update_id,
            channel: n.channel.raw(),
            pan_id: n.pan_id.0,
            network_address: target.response.network_address,
        }
        .encode(&mut w)
        .map_err(|_| NodeError::Unsupported)?;
        let len = w.position();
        node.send_inter_pan(
            InterPanDestination::Device(target.ieee),
            self.src_pan,
            tl::CMD_NETWORK_UPDATE_REQUEST,
            Direction::ToServer,
            buf.get(..len).unwrap_or(&[]),
        )
    }
}

fn random_key(node: &mut impl TouchlinkNode) -> [u8; 16] {
    let mut k = [0u8; 16];
    for chunk in k.chunks_exact_mut(4) {
        chunk.copy_from_slice(&node.random_u32().to_le_bytes());
    }
    k
}

/// Target policy (§12.2 steps 9 and 16): whether to start or join
/// networks on request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TargetPolicy {
    /// Accept requests while factory new / on a distributed network.
    pub accept: bool,
    /// Accept requests even while on a centralized network (stealing).
    pub allow_stealing: bool,
    /// Weakest acceptable scan request RSSI.
    pub rssi_threshold: i8,
    /// Own RSSI correction.
    pub rssi_correction: u8,
    /// Request priority in scan responses.
    pub priority: bool,
}

impl TargetPolicy {
    /// Accept everything on distributed / factory-new nodes, no stealing.
    pub const DEFAULT: TargetPolicy = TargetPolicy {
        accept: true,
        allow_stealing: false,
        rssi_threshold: -90,
        rssi_correction: 0,
        priority: false,
    };
}

/// Result of a target step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TargetOutcome {
    /// A scan response was sent to `initiator`.
    Responded {
        /// The initiator.
        initiator: ExtendedAddress,
    },
    /// The node started a new network for `initiator`.
    Started {
        /// The initiator.
        initiator: ExtendedAddress,
    },
    /// The node joined the initiator's network.
    Joined {
        /// The initiator.
        initiator: ExtendedAddress,
    },
    /// The node was reset to factory new.
    Reset,
    /// A request was refused by policy.
    Refused,
}

/// The target procedure (§12.2).
#[derive(Clone, Debug)]
pub struct Target {
    /// Policy.
    pub policy: TargetPolicy,
    transaction: Option<(u32, ExtendedAddress, PanId, Channel, Instant)>,
    response_id: u32,
    proposed_channel: Option<Channel>,
}

impl Target {
    /// A new target.
    pub const fn new(policy: TargetPolicy) -> Self {
        Target {
            policy,
            transaction: None,
            response_id: 0,
            proposed_channel: None,
        }
    }

    /// Whether a transaction is open (the receiver stays on, §13.3.4.6).
    pub fn is_active(&self) -> bool {
        self.transaction.is_some()
    }

    /// When the open transaction expires.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.transaction.map(|t| t.4)
    }

    /// Expires the transaction.
    pub fn poll(&mut self, now: Instant) {
        if self.transaction.is_some_and(|t| now.has_reached(t.4)) {
            self.transaction = None;
        }
    }

    fn reply(
        &self,
        node: &mut impl TouchlinkNode,
        dst: ExtendedAddress,
        command: CommandId,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let src_pan = node.network().map_or_else(
            || self.transaction.map_or(PanId(0x0001), |t| t.2),
            |n| n.pan_id,
        );
        node.send_inter_pan(
            InterPanDestination::Device(dst),
            src_pan,
            command,
            Direction::ToClient,
            payload,
        )
    }

    /// A received inter-PAN Touchlink command (client → server) from
    /// `src` on `src_pan`, heard on `channel` with `rssi`.
    pub fn on_inter_pan(
        &mut self,
        node: &mut impl TouchlinkNode,
        src: ExtendedAddress,
        src_pan: PanId,
        channel: Channel,
        command: CommandId,
        payload: &[u8],
        rssi: i8,
    ) -> Option<TargetOutcome> {
        let now = node.now();
        self.poll(now);
        if command == tl::CMD_SCAN_REQUEST {
            let req = tl::ScanRequest::parse(payload).ok()?;
            if rssi <= self.policy.rssi_threshold || !req.touchlink.initiator {
                return None;
            }
            // The initiator repeats its scan request (five times on the
            // first channel): the response identifier must stay the same
            // within one transaction or the key transport would diverge.
            let same = self.transaction.is_some_and(|t| t.0 == req.transaction);
            self.transaction = Some((
                req.transaction,
                src,
                src_pan,
                channel,
                now.saturating_add(Duration::from_millis(tl::TRANSACTION_LIFETIME_MS)),
            ));
            if !same {
                self.response_id = node.random_u32();
            }
            let mut subs = Vec::new();
            node.sub_devices(&mut subs);
            let network = node.network();
            let total_groups = subs
                .iter()
                .map(|d| d.group_count)
                .fold(0u8, u8::saturating_add);
            let rsp = tl::ScanResponse {
                transaction: req.transaction,
                rssi_correction: self.policy.rssi_correction,
                zigbee: tl::ZigbeeInfo {
                    logical_type: match node.role() {
                        LogicalDeviceType::Coordinator => 0,
                        LogicalDeviceType::Router => 1,
                        LogicalDeviceType::EndDevice => 2,
                    },
                    rx_on_when_idle: node.role() != LogicalDeviceType::EndDevice,
                },
                touchlink: tl::TouchlinkInfo {
                    factory_new: network.is_none(),
                    address_assignment: false,
                    initiator: false,
                    priority_request: self.policy.priority,
                    profile_interop: true,
                },
                key_bitmask: node.key_bitmask(),
                response: self.response_id,
                extended_pan_id: network.map_or(0, |n| n.extended_pan_id),
                update_id: network.map_or(0, |n| n.update_id),
                channel: network.map_or(0, |n| n.channel.raw()),
                pan_id: network.map_or(0, |n| n.pan_id.0),
                network_address: network.map_or(0xffff, |n| n.short.0),
                sub_devices: u8::try_from(subs.len()).unwrap_or(u8::MAX),
                total_groups,
                sub_device: (subs.len() == 1).then(|| {
                    let d = subs.first().copied().unwrap_or(tl::DeviceRecord {
                        ieee: 0,
                        endpoint: 0,
                        profile: 0,
                        device: 0,
                        version: 0,
                        group_count: 0,
                        sort: 0,
                    });
                    tl::SubDevice {
                        endpoint: d.endpoint,
                        profile: d.profile,
                        device: d.device,
                        version: d.version,
                        group_count: d.group_count,
                    }
                }),
            };
            let mut buf = [0u8; MAX_PAYLOAD];
            let mut w = Writer::new(&mut buf);
            rsp.encode(&mut w).ok()?;
            let n = w.position();
            self.reply(
                node,
                src,
                tl::CMD_SCAN_RESPONSE,
                buf.get(..n).unwrap_or(&[]),
            )
            .ok()?;
            return Some(TargetOutcome::Responded { initiator: src });
        }
        let (trid, initiator, _, _, _) = self.transaction?;
        if src != initiator {
            return None;
        }
        match command {
            tl::CMD_DEVICE_INFORMATION_REQUEST => {
                let req = tl::DeviceInformationRequest::parse(payload).ok()?;
                if req.transaction != trid {
                    return None;
                }
                let mut subs = Vec::new();
                node.sub_devices(&mut subs);
                let mut records = Vec::new();
                for d in subs
                    .iter()
                    .skip(usize::from(req.start_index))
                    .take(tl::MAX_DEVICE_RECORDS)
                {
                    let _ = records.push(*d);
                }
                let rsp = tl::DeviceInformationResponse {
                    transaction: trid,
                    sub_devices: u8::try_from(subs.len()).unwrap_or(u8::MAX),
                    start_index: req.start_index,
                    records,
                };
                let mut buf = [0u8; 8 + 16 * tl::MAX_DEVICE_RECORDS];
                let mut w = Writer::new(&mut buf);
                rsp.encode(&mut w).ok()?;
                let n = w.position();
                let _ = self.reply(
                    node,
                    src,
                    tl::CMD_DEVICE_INFORMATION_RESPONSE,
                    buf.get(..n).unwrap_or(&[]),
                );
                None
            }
            tl::CMD_IDENTIFY_REQUEST => {
                let req = tl::IdentifyRequest::parse(payload).ok()?;
                if req.transaction == trid {
                    node.identify(req.duration);
                }
                None
            }
            tl::CMD_NETWORK_UPDATE_REQUEST => {
                let req = tl::NetworkUpdateRequest::parse(payload).ok()?;
                let n = node.network()?;
                if req.transaction != trid
                    || req.extended_pan_id != n.extended_pan_id
                    || req.pan_id != n.pan_id.0
                    || tl::newer_update_id(n.update_id, req.update_id) == n.update_id
                {
                    return None;
                }
                let ch = Channel::new_2_4ghz(req.channel)?;
                node.update_network(req.update_id, ch);
                None
            }
            tl::CMD_RESET_TO_FACTORY_NEW_REQUEST => {
                if tl::parse_transaction(payload).ok()? != trid {
                    return None;
                }
                self.transaction = None;
                node.factory_reset();
                Some(TargetOutcome::Reset)
            }
            tl::CMD_NETWORK_START_REQUEST => {
                let req = tl::NetworkStartRequest::parse(payload).ok()?;
                if req.transaction != trid || node.role() != LogicalDeviceType::Router {
                    return None;
                }
                let refuse = |this: &Self, node: &mut _| {
                    let rsp = tl::NetworkStartResponse {
                        transaction: trid,
                        status: tl::STATUS_FAILURE,
                        extended_pan_id: 0,
                        update_id: 0,
                        channel: 0,
                        pan_id: 0,
                    };
                    let mut buf = [0u8; 24];
                    let mut w = Writer::new(&mut buf);
                    let _ = rsp.encode(&mut w);
                    let n = w.position();
                    let _ = this.reply(
                        node,
                        src,
                        tl::CMD_NETWORK_START_RESPONSE,
                        buf.get(..n).unwrap_or(&[]),
                    );
                };
                if !self.allowed(node) {
                    refuse(self, node);
                    return Some(TargetOutcome::Refused);
                }
                let Some(key) = node.decrypt_network_key(
                    req.key_index,
                    trid,
                    self.response_id,
                    &req.encrypted_key,
                ) else {
                    refuse(self, node);
                    return Some(TargetOutcome::Refused);
                };
                // Step 10: choose the parameters the initiator left open.
                let channel = Channel::new_2_4ghz(req.channel)
                    .or(self.proposed_channel)
                    .or_else(|| TL_PRIMARY_CHANNEL_SET.first())?;
                let mut epid = req.extended_pan_id;
                while epid == 0 || epid == u64::MAX {
                    epid = (u64::from(node.random_u32()) << 32) | u64::from(node.random_u32());
                }
                let mut pan = req.pan_id;
                while pan == 0 || pan == 0xffff {
                    pan = u16::try_from(node.random_u32() & 0xffff).unwrap_or(1);
                }
                let params = NetworkParams {
                    extended_pan_id: epid,
                    pan_id: PanId(pan),
                    channel,
                    update_id: 0,
                    key,
                    short: ShortAddress(req.assignment.network_address),
                    groups: (req.assignment.groups_begin != 0)
                        .then_some((req.assignment.groups_begin, req.assignment.groups_end)),
                    ranges: (req.assignment.free_addresses_begin != 0).then_some(AddressRanges {
                        addresses_begin: req.assignment.free_addresses_begin,
                        addresses_end: req.assignment.free_addresses_end,
                        groups_begin: req.assignment.free_groups_begin,
                        groups_end: req.assignment.free_groups_end,
                    }),
                    neighbour: Some((
                        ExtendedAddress(req.initiator_ieee),
                        ShortAddress(req.initiator_address),
                    )),
                };
                let rsp = tl::NetworkStartResponse {
                    transaction: trid,
                    status: tl::STATUS_SUCCESS,
                    extended_pan_id: epid,
                    update_id: 0,
                    channel: channel.raw(),
                    pan_id: pan,
                };
                let mut buf = [0u8; 24];
                let mut w = Writer::new(&mut buf);
                rsp.encode(&mut w).ok()?;
                let n = w.position();
                let _ = self.reply(
                    node,
                    src,
                    tl::CMD_NETWORK_START_RESPONSE,
                    buf.get(..n).unwrap_or(&[]),
                );
                self.transaction = None;
                node.start_network(&params).ok()?;
                Some(TargetOutcome::Started { initiator: src })
            }
            tl::CMD_NETWORK_JOIN_ROUTER_REQUEST | tl::CMD_NETWORK_JOIN_END_DEVICE_REQUEST => {
                let req = tl::NetworkJoinRequest::parse(payload).ok()?;
                let (expect_role, response) = if command == tl::CMD_NETWORK_JOIN_ROUTER_REQUEST {
                    (
                        LogicalDeviceType::Router,
                        tl::CMD_NETWORK_JOIN_ROUTER_RESPONSE,
                    )
                } else {
                    (
                        LogicalDeviceType::EndDevice,
                        tl::CMD_NETWORK_JOIN_END_DEVICE_RESPONSE,
                    )
                };
                if req.transaction != trid || node.role() != expect_role {
                    return None;
                }
                let key = if self.allowed(node) {
                    node.decrypt_network_key(
                        req.key_index,
                        trid,
                        self.response_id,
                        &req.encrypted_key,
                    )
                } else {
                    None
                };
                let status = if key.is_some() {
                    tl::STATUS_SUCCESS
                } else {
                    tl::STATUS_FAILURE
                };
                let mut buf = [0u8; 8];
                let mut w = Writer::new(&mut buf);
                tl::StatusResponse {
                    transaction: trid,
                    status,
                }
                .encode(&mut w)
                .ok()?;
                let n = w.position();
                let _ = self.reply(node, src, response, buf.get(..n).unwrap_or(&[]));
                let Some(key) = key else {
                    return Some(TargetOutcome::Refused);
                };
                let channel = Channel::new_2_4ghz(req.channel)?;
                let params = NetworkParams {
                    extended_pan_id: req.extended_pan_id,
                    pan_id: PanId(req.pan_id),
                    channel,
                    update_id: req.update_id,
                    key,
                    short: ShortAddress(req.assignment.network_address),
                    groups: (req.assignment.groups_begin != 0)
                        .then_some((req.assignment.groups_begin, req.assignment.groups_end)),
                    ranges: (req.assignment.free_addresses_begin != 0).then_some(AddressRanges {
                        addresses_begin: req.assignment.free_addresses_begin,
                        addresses_end: req.assignment.free_addresses_end,
                        groups_begin: req.assignment.free_groups_begin,
                        groups_end: req.assignment.free_groups_end,
                    }),
                    neighbour: None,
                };
                self.transaction = None;
                node.join_network(&params).ok()?;
                Some(TargetOutcome::Joined { initiator: src })
            }
            _ => None,
        }
    }

    fn allowed(&self, node: &impl TouchlinkNode) -> bool {
        if !self.policy.accept {
            return false;
        }
        match node.network() {
            Some(n) if n.centralized => self.policy.allow_stealing,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Sent {
        dst: InterPanDestination,
        src_pan: PanId,
        command: CommandId,
        direction: Direction,
        payload: Vec<u8, MAX_PAYLOAD>,
    }

    struct FakeNode {
        now: Instant,
        ieee: ExtendedAddress,
        role: LogicalDeviceType,
        network: Option<NetworkInfo>,
        key: Option<Key128>,
        channel: Channel,
        sent: Vec<Sent, 64>,
        seed: u32,
        identify: Option<u16>,
        started: Option<NetworkParams>,
        joined: Option<NetworkParams>,
        adopted: Option<NetworkParams>,
        reset: bool,
        updated: Option<(u8, Channel)>,
    }

    impl FakeNode {
        fn new(ieee: u64, role: LogicalDeviceType) -> Self {
            FakeNode {
                now: Instant::from_millis(0),
                ieee: ExtendedAddress(ieee),
                role,
                network: None,
                key: None,
                channel: Channel::new_2_4ghz(11).unwrap(),
                sent: Vec::new(),
                seed: 0x1234_5678,
                identify: None,
                started: None,
                joined: None,
                adopted: None,
                reset: false,
                updated: None,
            }
        }

        fn last(&self) -> &Sent {
            self.sent.last().unwrap()
        }
    }

    impl TouchlinkNode for FakeNode {
        fn now(&self) -> Instant {
            self.now
        }
        fn random_u32(&mut self) -> u32 {
            self.seed = self.seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            self.seed | 1
        }
        fn ieee(&self) -> ExtendedAddress {
            self.ieee
        }
        fn role(&self) -> LogicalDeviceType {
            self.role
        }
        fn sub_devices(&self, out: &mut Vec<tl::DeviceRecord, MAX_SUB_DEVICES>) {
            let _ = out.push(tl::DeviceRecord {
                ieee: self.ieee.0,
                endpoint: 1,
                profile: 0x0104,
                device: 0x0100,
                version: 1,
                group_count: 1,
                sort: 0,
            });
        }
        fn network(&self) -> Option<NetworkInfo> {
            self.network
        }
        fn network_key(&self) -> Option<Key128> {
            self.key.clone()
        }
        fn set_channel(&mut self, channel: Channel) {
            self.channel = channel;
        }
        fn send_inter_pan(
            &mut self,
            dst: InterPanDestination,
            src_pan: PanId,
            command: CommandId,
            direction: Direction,
            payload: &[u8],
        ) -> Result<(), NodeError> {
            let _ = self.sent.push(Sent {
                dst,
                src_pan,
                command,
                direction,
                payload: Vec::from_slice(payload).unwrap(),
            });
            Ok(())
        }
        fn identify(&mut self, seconds: u16) {
            self.identify = Some(seconds);
        }
        fn key_bitmask(&self) -> u16 {
            1 << 15
        }
        fn encrypt_network_key(&mut self, i: u8, t: u32, r: u32, key: &Key128) -> Option<[u8; 16]> {
            (i == 15).then(|| {
                let mut b = *key.as_bytes();
                for (k, x) in b
                    .iter_mut()
                    .zip(t.to_le_bytes().iter().chain(r.to_le_bytes().iter()).cycle())
                {
                    *k ^= x;
                }
                b
            })
        }
        fn decrypt_network_key(&mut self, i: u8, t: u32, r: u32, e: &[u8; 16]) -> Option<Key128> {
            self.encrypt_network_key(i, t, r, &Key128::from_bytes(*e))
                .map(Key128::from_bytes)
        }
        fn start_network(&mut self, p: &NetworkParams) -> Result<(), NodeError> {
            self.started = Some(p.clone());
            Ok(())
        }
        fn join_network(&mut self, p: &NetworkParams) -> Result<(), NodeError> {
            self.joined = Some(p.clone());
            Ok(())
        }
        fn adopt_network(&mut self, p: &NetworkParams) -> Result<(), NodeError> {
            self.adopted = Some(p.clone());
            Ok(())
        }
        fn update_network(&mut self, update_id: u8, channel: Channel) {
            self.updated = Some((update_id, channel));
        }
        fn factory_reset(&mut self) {
            self.reset = true;
        }
    }

    /// Runs the initiator's discovery to completion, feeding the target.
    fn discover(
        init: &mut Initiator,
        i: &mut FakeNode,
        target: &mut Target,
        t: &mut FakeNode,
    ) -> Vec<Candidate, MAX_CANDIDATES> {
        init.start(i, false, false);
        let mut answered = false;
        for _ in 0..200 {
            i.now = i.now.saturating_add(Duration::from_millis(250));
            t.now = i.now;
            let before = i.sent.len();
            let now = i.now;
            if let Some(o) = init.poll(i, now) {
                match o {
                    InitiatorOutcome::Discovered(c) => return c,
                    other => panic!("{other:?}"),
                }
            }
            if i.sent.len() > before && !answered {
                let s = i.last().clone();
                assert_eq!(s.command, tl::CMD_SCAN_REQUEST);
                assert_eq!(s.dst, InterPanDestination::Broadcast);
                let out = target
                    .on_inter_pan(t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40);
                assert_eq!(out, Some(TargetOutcome::Responded { initiator: i.ieee }));
                let r = t.last().clone();
                assert_eq!(r.command, tl::CMD_SCAN_RESPONSE);
                assert_eq!(r.direction, Direction::ToClient);
                init.on_inter_pan(i, t.ieee, r.src_pan, r.command, &r.payload, -50);
                answered = true;
            }
        }
        panic!("discovery did not finish");
    }

    #[test]
    fn ranges_assign_and_split() {
        let mut r = AddressRanges::FACTORY_NEW;
        assert_eq!(r.next_address(), Some(ShortAddress(1)));
        assert_eq!(r.take_groups(2), Some((1, 2)));
        let upper = r.split().unwrap();
        assert!(upper.addresses_begin > r.addresses_end);
        assert_eq!(upper.addresses_end, 0xfff7);
        assert!(!AddressRanges::NONE.is_capable());
        let mut small = AddressRanges {
            addresses_begin: 1,
            addresses_end: 10,
            groups_begin: 1,
            groups_end: 10,
        };
        assert!(small.split().is_none());
    }

    #[test]
    fn factory_new_end_device_starts_a_network_with_a_router_target() {
        let mut i = FakeNode::new(0xA, LogicalDeviceType::EndDevice);
        let mut t = FakeNode::new(0xB, LogicalDeviceType::Router);
        let mut init = Initiator::new(15);
        let mut target = Target::new(TargetPolicy::DEFAULT);
        let candidates = discover(&mut init, &mut i, &mut target, &mut t);
        assert_eq!(candidates.len(), 1);
        let c = candidates[0];
        assert_eq!(c.ieee, t.ieee);
        assert!(c.response.touchlink.factory_new);
        assert_eq!(c.response.sub_devices, 1);
        // Identify and device information on the way.
        init.identify_target(&mut i, &c, 3).unwrap();
        let s = i.last().clone();
        target.on_inter_pan(
            &mut t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40,
        );
        assert_eq!(t.identify, Some(3));
        init.request_device_information(&mut i, &c, 0).unwrap();
        let s = i.last().clone();
        target.on_inter_pan(
            &mut t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40,
        );
        let r = t.last().clone();
        let o = init.on_inter_pan(&mut i, t.ieee, r.src_pan, r.command, &r.payload, -50);
        assert!(matches!(o, Some(InitiatorOutcome::DeviceInformation(d)) if d.records.len() == 1));
        // Select: network start request → target starts, response → adopt.
        assert_eq!(init.select(&mut i, &c), None);
        let s = i.last().clone();
        assert_eq!(s.command, tl::CMD_NETWORK_START_REQUEST);
        let req = tl::NetworkStartRequest::parse(&s.payload).unwrap();
        assert_eq!(req.initiator_address, 0x0001);
        assert_eq!(req.assignment.network_address, 0x0002);
        let o = target.on_inter_pan(
            &mut t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40,
        );
        assert_eq!(o, Some(TargetOutcome::Started { initiator: i.ieee }));
        let started = t.started.clone().unwrap();
        assert_eq!(started.short, ShortAddress(0x0002));
        assert_eq!(started.neighbour, Some((i.ieee, ShortAddress(0x0001))));
        assert_ne!(started.extended_pan_id, 0);
        let r = t.last().clone();
        assert_eq!(r.command, tl::CMD_NETWORK_START_RESPONSE);
        assert_eq!(
            init.on_inter_pan(&mut i, t.ieee, r.src_pan, r.command, &r.payload, -50),
            None
        );
        i.now = i
            .now
            .saturating_add(Duration::from_millis(tl::MIN_STARTUP_DELAY_MS));
        let now = i.now;
        let o = init.poll(&mut i, now);
        assert_eq!(
            o,
            Some(InitiatorOutcome::Success {
                target: t.ieee,
                short: ShortAddress(0x0002)
            })
        );
        let adopted = i.adopted.clone().unwrap();
        assert_eq!(adopted.extended_pan_id, started.extended_pan_id);
        assert_eq!(adopted.key, started.key, "the key survived transport");
        assert_eq!(adopted.short, ShortAddress(0x0001));
        assert!(!init.is_busy());
    }

    #[test]
    fn initiator_on_a_network_joins_a_router_and_respects_stealing_policy() {
        let mut i = FakeNode::new(0xA, LogicalDeviceType::Router);
        i.network = Some(NetworkInfo {
            extended_pan_id: 0x5555,
            pan_id: PanId(0x1234),
            channel: Channel::new_2_4ghz(15).unwrap(),
            update_id: 2,
            short: ShortAddress(1),
            centralized: false,
        });
        i.key = Some(Key128::from_bytes([3; 16]));
        let mut t = FakeNode::new(0xB, LogicalDeviceType::Router);
        t.network = Some(NetworkInfo {
            extended_pan_id: 0x7777,
            pan_id: PanId(0x4321),
            channel: Channel::new_2_4ghz(20).unwrap(),
            update_id: 0,
            short: ShortAddress(9),
            centralized: true,
        });
        let mut init = Initiator::new(15);
        init.ranges.next_address();
        let mut target = Target::new(TargetPolicy::DEFAULT);
        let candidates = discover(&mut init, &mut i, &mut target, &mut t);
        let c = candidates[0];
        assert_eq!(init.select(&mut i, &c), None);
        let s = i.last().clone();
        assert_eq!(s.command, tl::CMD_NETWORK_JOIN_ROUTER_REQUEST);
        // The target sits on a centralized network: stealing refused.
        let o = target.on_inter_pan(
            &mut t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40,
        );
        assert_eq!(o, Some(TargetOutcome::Refused));
        let r = t.last().clone();
        let o = init.on_inter_pan(&mut i, t.ieee, r.src_pan, r.command, &r.payload, -50);
        assert_eq!(o, Some(InitiatorOutcome::Failed(Failure::TargetFailure)));
        // Allowed: the target joins.
        target.policy.allow_stealing = true;
        let candidates = discover(&mut init, &mut i, &mut target, &mut t);
        let c = candidates[0];
        init.select(&mut i, &c);
        let s = i.last().clone();
        let o = target.on_inter_pan(
            &mut t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40,
        );
        assert_eq!(o, Some(TargetOutcome::Joined { initiator: i.ieee }));
        let joined = t.joined.clone().unwrap();
        assert_eq!(joined.extended_pan_id, 0x5555);
        assert_eq!(joined.key, Key128::from_bytes([3; 16]));
        assert_eq!(joined.update_id, 2);
        let r = t.last().clone();
        assert_eq!(r.command, tl::CMD_NETWORK_JOIN_ROUTER_RESPONSE);
        assert_eq!(
            init.on_inter_pan(&mut i, t.ieee, r.src_pan, r.command, &r.payload, -50),
            None
        );
        i.now = i
            .now
            .saturating_add(Duration::from_millis(tl::MIN_STARTUP_DELAY_MS));
        let now2 = i.now;
        assert!(matches!(
            init.poll(&mut i, now2),
            Some(InitiatorOutcome::Success { short, .. }) if short == joined.short
        ));
    }

    #[test]
    fn same_network_reconciles_update_id_and_reset_sends_the_request() {
        let mut i = FakeNode::new(0xA, LogicalDeviceType::Router);
        let net = NetworkInfo {
            extended_pan_id: 0x5555,
            pan_id: PanId(0x1234),
            channel: Channel::new_2_4ghz(15).unwrap(),
            update_id: 5,
            short: ShortAddress(1),
            centralized: false,
        };
        i.network = Some(net);
        i.key = Some(Key128::from_bytes([3; 16]));
        let mut t = FakeNode::new(0xB, LogicalDeviceType::Router);
        t.network = Some(NetworkInfo {
            update_id: 3,
            short: ShortAddress(9),
            ..net
        });
        let mut init = Initiator::new(15);
        let mut target = Target::new(TargetPolicy::DEFAULT);
        let candidates = discover(&mut init, &mut i, &mut target, &mut t);
        let c = candidates[0];
        let o = init.select(&mut i, &c);
        assert!(
            matches!(o, Some(InitiatorOutcome::Success { short, .. }) if short == ShortAddress(9))
        );
        let s = i.last().clone();
        assert_eq!(s.command, tl::CMD_NETWORK_UPDATE_REQUEST);
        target.on_inter_pan(
            &mut t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40,
        );
        assert_eq!(t.updated, Some((5, net.channel)));
        // Reset to factory new.
        init.start(&mut i, false, true);
        let candidates = discover_after_start(&mut init, &mut i, &mut target, &mut t);
        let c = candidates[0];
        assert_eq!(init.select(&mut i, &c), Some(InitiatorOutcome::ResetSent));
        let s = i.last().clone();
        assert_eq!(s.command, tl::CMD_RESET_TO_FACTORY_NEW_REQUEST);
        let o = target.on_inter_pan(
            &mut t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40,
        );
        assert_eq!(o, Some(TargetOutcome::Reset));
        assert!(t.reset);
    }

    /// Like `discover` but for a procedure already started.
    fn discover_after_start(
        init: &mut Initiator,
        i: &mut FakeNode,
        target: &mut Target,
        t: &mut FakeNode,
    ) -> Vec<Candidate, MAX_CANDIDATES> {
        let mut answered = false;
        for _ in 0..200 {
            i.now = i.now.saturating_add(Duration::from_millis(250));
            t.now = i.now;
            let before = i.sent.len();
            let now = i.now;
            if let Some(InitiatorOutcome::Discovered(c)) = init.poll(i, now) {
                return c;
            }
            if i.sent.len() > before && !answered {
                let s = i.last().clone();
                target.on_inter_pan(t, i.ieee, s.src_pan, i.channel, s.command, &s.payload, -40);
                let r = t.last().clone();
                init.on_inter_pan(i, t.ieee, r.src_pan, r.command, &r.payload, -50);
                answered = true;
            }
        }
        panic!("discovery did not finish");
    }

    #[test]
    fn target_ignores_weak_scans_wrong_transactions_and_expires() {
        let mut t = FakeNode::new(0xB, LogicalDeviceType::Router);
        let mut target = Target::new(TargetPolicy::DEFAULT);
        let req = tl::ScanRequest {
            transaction: 77,
            zigbee: tl::ZigbeeInfo::ROUTER,
            touchlink: tl::TouchlinkInfo {
                factory_new: true,
                address_assignment: true,
                initiator: true,
                priority_request: false,
                profile_interop: true,
            },
        };
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        let ch = Channel::new_2_4ghz(11).unwrap();
        assert_eq!(
            target.on_inter_pan(
                &mut t,
                ExtendedAddress(1),
                PanId(5),
                ch,
                tl::CMD_SCAN_REQUEST,
                &buf[..6],
                -95
            ),
            None,
            "below the RSSI threshold"
        );
        let mut not_initiator = req;
        not_initiator.touchlink.initiator = false;
        let mut w = Writer::new(&mut buf);
        not_initiator.encode(&mut w).unwrap();
        assert_eq!(
            target.on_inter_pan(
                &mut t,
                ExtendedAddress(1),
                PanId(5),
                ch,
                tl::CMD_SCAN_REQUEST,
                &buf[..6],
                -40
            ),
            None
        );
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert!(
            target
                .on_inter_pan(
                    &mut t,
                    ExtendedAddress(1),
                    PanId(5),
                    ch,
                    tl::CMD_SCAN_REQUEST,
                    &buf[..6],
                    -40
                )
                .is_some()
        );
        assert!(target.is_active());
        // Wrong transaction identifier on an identify request: ignored.
        let mut w = Writer::new(&mut buf);
        tl::IdentifyRequest {
            transaction: 78,
            duration: 5,
        }
        .encode(&mut w)
        .unwrap();
        target.on_inter_pan(
            &mut t,
            ExtendedAddress(1),
            PanId(5),
            ch,
            tl::CMD_IDENTIFY_REQUEST,
            &buf[..6],
            -40,
        );
        assert_eq!(t.identify, None);
        // Another initiator cannot use the transaction.
        let mut w = Writer::new(&mut buf);
        tl::IdentifyRequest {
            transaction: 77,
            duration: 5,
        }
        .encode(&mut w)
        .unwrap();
        target.on_inter_pan(
            &mut t,
            ExtendedAddress(2),
            PanId(5),
            ch,
            tl::CMD_IDENTIFY_REQUEST,
            &buf[..6],
            -40,
        );
        assert_eq!(t.identify, None);
        target.on_inter_pan(
            &mut t,
            ExtendedAddress(1),
            PanId(5),
            ch,
            tl::CMD_IDENTIFY_REQUEST,
            &buf[..6],
            -40,
        );
        assert_eq!(t.identify, Some(5));
        // The transaction expires after aplcInterPANTransIdLifetime.
        t.now = t
            .now
            .saturating_add(Duration::from_millis(tl::TRANSACTION_LIFETIME_MS));
        target.poll(t.now);
        assert!(!target.is_active());
    }
}
