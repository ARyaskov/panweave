//! The [`Stack`] type: configuration, events and the public control API.

use heapless::{Deque, Vec};
use panweave_aps::layer::NwkView;
use panweave_aps::layer::{Aps, ApsConfig, DeviceState, NwkHandle, RequestId};
use panweave_mac::radio::{RadioError, RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacService, MacServiceConfig, TxHandle};
use panweave_nwk::layer::{Nwk, NwkConfig, TxId};
use panweave_nwk::nib::Nib;
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_security::trust_center::TrustCenterPolicy;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ChannelMask, ClusterId, CryptoRng, Endpoint, ExtendedAddress, Key128, KeyAttributes,
    KeySequenceNumber, LogicalDeviceType, MacCapability, ManufacturerCode, NwkStatus, PanId,
    ShortAddress, TransactionSequence,
};
use panweave_zcl::clusters::basic;
use panweave_zcl::layer::{EndpointInstance, Origin, Zcl};
use panweave_zdo::descriptor::{
    NodeDescriptor, PowerDescriptor, ServerMask, SimpleDescriptor, frequency_band,
};
use panweave_zdo::layer::Zdo;

/// NWK layer with the stack's table sizes.
pub type StackNwk<C, R> = Nwk<C, R, 16, 16, 4, 8>;
/// APS layer with the stack's table sizes.
pub type StackAps<C> = Aps<C, 8, 8, 8, 8>;
/// ZDO with up to 4 endpoints.
pub type StackZdo = Zdo<4>;
/// ZCL with 2 endpoints × 8 clusters × 16 attributes.
pub type StackZcl = Zcl<2, 8, 16>;

/// Queue capacity for stack events.
pub const EVENT_CAPACITY: usize = 16;

/// Maximum copied application frame.
pub const MAX_APP_FRAME: usize = 96;

/// How a device joins.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinMode {
    /// MAC association (§3.6.1.4.1).
    Association,
    /// Secured NWK rejoin with the current network key.
    SecuredRejoin,
    /// Trust Center rejoin (unsecured NWK rejoin, key redelivered).
    TrustCenterRejoin,
}

/// Static stack configuration.
#[derive(Clone, Debug)]
pub struct StackConfig {
    /// Logical device type.
    pub role: LogicalDeviceType,
    /// End device with `rxOnWhenIdle = FALSE` (polls its parent).
    pub sleepy: bool,
    /// IEEE address.
    pub ieee: ExtendedAddress,
    /// Manufacturer code advertised in the node descriptor.
    pub manufacturer_code: ManufacturerCode,
    /// Trust Center policies (coordinator only).
    pub trust_center_policy: TrustCenterPolicy,
    /// Pre-configured Trust Center link key for joining: partner (the
    /// Trust Center's IEEE address, or `ExtendedAddress::BROADCAST` when
    /// unknown), key and kind. Defaults to the well-known global key.
    pub preconfigured_link_key: (ExtendedAddress, Key128, LinkKeyKind),
    /// Form / join a distributed security network.
    pub distributed: bool,
    /// Channels used for formation and discovery.
    pub channels: ChannelMask,
    /// Scan duration exponent.
    pub scan_duration: u8,
    /// Manufacturer name for the Basic cluster.
    pub manufacturer_name: &'static [u8],
    /// Model identifier for the Basic cluster.
    pub model: &'static [u8],
    /// ZDO configuration attributes (R23.2 §2.5.5): scan attempts and
    /// the interval between discovery scans, rejoin intervals.
    pub zdo: panweave_zdo::ConfigAttributes,
    /// Base MAC data poll interval of a sleepy end device (BDB 3.1 §6.5:
    /// at most 7.5 s to keep parent buffers alive).
    pub poll_interval: Duration,
    /// Fast poll interval used right after a transmission to collect the
    /// response.
    pub fast_poll_interval: Duration,
    /// Number of fast polls after each transmission.
    pub fast_polls: u8,
}

impl StackConfig {
    /// Configuration for `role` with the well-known Trust Center link key.
    pub fn new(role: LogicalDeviceType, ieee: ExtendedAddress) -> Self {
        StackConfig {
            role,
            sleepy: false,
            ieee,
            manufacturer_code: ManufacturerCode(0x0000),
            trust_center_policy: TrustCenterPolicy::default(),
            preconfigured_link_key: (
                ExtendedAddress::BROADCAST,
                Key128::WELL_KNOWN_GLOBAL_TCLK,
                LinkKeyKind::Global,
            ),
            distributed: false,
            channels: ChannelMask::BDB_PRIMARY,
            scan_duration: 3,
            manufacturer_name: b"Panweave",
            model: b"Node",
            zdo: panweave_zdo::ConfigAttributes::DEFAULT,
            poll_interval: Duration::from_secs(3),
            fast_poll_interval: Duration::from_millis(100),
            fast_polls: 3,
        }
    }

    /// MAC capability information for this configuration (§3.4.6.3.1).
    pub const fn capability(&self) -> MacCapability {
        match (self.role, self.sleepy) {
            (LogicalDeviceType::Coordinator | LogicalDeviceType::Router, _) => {
                MacCapability::ROUTER
            }
            (LogicalDeviceType::EndDevice, false) => MacCapability::END_DEVICE_RX_ON,
            (LogicalDeviceType::EndDevice, true) => MacCapability::SLEEPY_END_DEVICE,
        }
    }
}

/// A copied ZDP transaction (response or notification).
#[derive(Clone, Debug)]
pub struct ZdpData {
    /// Sender.
    pub src: ShortAddress,
    /// Transaction sequence.
    pub seq: TransactionSequence,
    /// Cluster.
    pub cluster: ClusterId,
    /// Transaction data.
    pub data: Vec<u8, MAX_APP_FRAME>,
    /// Matched an outstanding request.
    pub matched: bool,
}

/// A copied ZCL frame for the application.
#[derive(Clone, Debug)]
pub struct ZclFrame {
    /// Origin (addresses, endpoint, header).
    pub origin: Origin,
    /// Payload after the ZCL header.
    pub payload: Vec<u8, MAX_APP_FRAME>,
}

/// Application-level events.
#[derive(Clone, Debug)]
pub enum StackEvent {
    /// The coordinator formed a network.
    NetworkFormed {
        /// PAN identifier.
        pan_id: PanId,
        /// Extended PAN identifier.
        extended_pan_id: ExtendedAddress,
    },
    /// Formation failed.
    FormationFailed(NwkStatus),
    /// This device joined and is authorized (has the network key).
    Joined {
        /// Assigned network address.
        short: ShortAddress,
        /// PAN identifier.
        pan_id: PanId,
        /// Rejoin.
        rejoin: bool,
    },
    /// Joining failed.
    JoinFailed(NwkStatus),
    /// This device left the network.
    Left {
        /// Rejoin requested.
        rejoin: bool,
    },
    /// A device joined through this node (Trust Center / parent view)
    /// and was authorized.
    DeviceAuthorized {
        /// IEEE address.
        ieee: ExtendedAddress,
        /// Network address.
        short: ShortAddress,
    },
    /// A Device_annce was received.
    DeviceAnnounce {
        /// IEEE address.
        ieee: ExtendedAddress,
        /// Network address.
        short: ShortAddress,
        /// Capability.
        capability: MacCapability,
    },
    /// A ZDP response or notification.
    Zdp(ZdpData),
    /// A ZDP request timed out.
    ZdpTimeout {
        /// Sequence.
        seq: TransactionSequence,
        /// Request cluster.
        cluster: ClusterId,
        /// Destination the request was sent to.
        dst: ShortAddress,
    },
    /// A cluster-specific ZCL command for the application.
    ZclCommand(ZclFrame),
    /// A ZCL global response.
    ZclResponse(ZclFrame),
    /// A ZCL attribute report.
    ZclReport(ZclFrame),
    /// The Trust Center link key was updated (verified).
    LinkKeyUpdated,
    /// A dynamic link key negotiation with `partner` failed or timed out;
    /// the previous key-pair entry was restored (R23.2 §4.4.9).
    KeyNegotiationFailed {
        /// The peer.
        partner: ExtendedAddress,
    },
    /// The Trust Center handed out a symmetric authentication token
    /// (passphrase) for future key negotiations (§2.4.3.4.2).
    AuthenticationTokenStored,
    /// A device left the network: one of this router's children, or (at
    /// the Trust Center) any device reported by its parent (§4.6.3.6).
    DeviceLeft {
        /// The device.
        ieee: ExtendedAddress,
        /// It intends to rejoin.
        rejoin: bool,
    },
    /// A pre-R23 device reported a PAN ID conflict to this network
    /// manager (NLME-NETWORK-STATUS 0x14, §3.6.1.13.2). Conflicts this
    /// device detects itself are counted in `nwkPanIdConflictCount`.
    PanIdConflictReport {
        /// The reporting device.
        from: ShortAddress,
    },
    /// The network's PAN ID changed (Network Update, §3.6.1.13.4).
    PanIdChanged {
        /// The new PAN ID.
        pan_id: PanId,
    },
    /// `partner`'s APS frame counter was synchronized with a challenge
    /// (§4.6.3.8): APS-encrypted frames from it are accepted again.
    FrameCounterSynchronized {
        /// The partner.
        partner: ExtendedAddress,
    },
    /// Identify server state changed (`seconds` remaining, 0 = stopped).
    Identify {
        /// Endpoint.
        endpoint: Endpoint,
        /// Remaining seconds.
        seconds: u16,
    },
    /// Identify Trigger Effect received.
    TriggerEffect {
        /// Endpoint.
        endpoint: Endpoint,
        /// Effect identifier.
        effect: u8,
        /// Effect variant.
        variant: u8,
    },
}

/// The endpoint could not be registered (duplicate number, endpoint 0 or
/// 255, or no space).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EndpointError;

/// Join / formation progress.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Phase {
    Idle,
    Forming,
    Discovering(JoinMode),
    Joining(JoinMode),
    AwaitingKey,
    Operating,
}

/// An energy scan requested by the network manager
/// (Mgmt_NWK_Update_req, §2.4.3.3.9.2 step 5).
#[derive(Clone, Copy, Debug)]
pub(crate) struct EnergyScanRequest {
    pub src: ShortAddress,
    pub seq: TransactionSequence,
    pub channels: ChannelMask,
    pub duration: u8,
    /// Scans still to run after the current one (ScanCount).
    pub remaining: u8,
}

/// An outstanding APS frame counter challenge (§4.6.3.8.1).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Challenge {
    pub target: ExtendedAddress,
    pub value: u64,
    pub deadline: Instant,
}

/// A child whose network key is in flight (Trust Center side).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingChild {
    pub ieee: ExtendedAddress,
    pub short: ShortAddress,
    pub request: RequestId,
}

/// The composed stack.
pub struct Stack<C: BlockCipher, R: CryptoRng, S: Storage> {
    /// MAC service.
    pub mac: MacService,
    /// NWK layer.
    pub nwk: StackNwk<C, R>,
    /// APS layer.
    pub aps: StackAps<C>,
    /// ZDO.
    pub zdo: StackZdo,
    /// ZCL dispatcher.
    pub zcl: StackZcl,
    /// Storage backend.
    pub storage: S,
    /// Configuration.
    pub config: StackConfig,
    pub(crate) now: Instant,
    pub(crate) events: Deque<StackEvent, EVENT_CAPACITY>,
    pub(crate) mac_handles: Vec<(TxHandle, TxHandle), 8>,
    pub(crate) aps_handles: Vec<(TxId, NwkHandle), 8>,
    pub(crate) phase: Phase,
    pub(crate) pending_children: Vec<PendingChild, 4>,
    pub(crate) network_key_sequence: KeySequenceNumber,
    pub(crate) next_poll: Option<Instant>,
    pub(crate) fast_polls_left: u8,
    pub(crate) dlk: crate::dlk::DlkState,
    /// Outstanding APS frame counter challenge (`apsChallengeTargetEui64`,
    /// `apsChallengeValue`, `apsChallengePeriodRemainingSeconds`).
    pub(crate) challenge: Option<Challenge>,
    pub(crate) energy_scan: Option<EnergyScanRequest>,
    /// Discovery retries left for the join in progress
    /// (`:Config_NWK_Scan_Attempts`) and when the next scan may start.
    pub(crate) scan_attempts_left: u8,
    pub(crate) next_scan: Option<(Instant, ChannelMask, u8)>,
    /// Channels and duration of the discovery in progress.
    pub(crate) last_scan: (ChannelMask, u8),
    /// Events dropped on overflow.
    pub dropped_events: u32,
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Builds a stack. `rng` must be cryptographically secure: it seeds
    /// NWK jitter and addresses and generates network and link keys.
    pub fn new(config: StackConfig, mac_config: MacServiceConfig, rng: R, storage: S) -> Self {
        let mac = MacService::new(mac_config, config.ieee);
        let mut nib = Nib::new(config.role, config.ieee);
        nib.rx_on_when_idle = !config.sleepy;
        nib.capability_information = config.capability();
        let mut nwk = Nwk::new(nib, NwkConfig::default(), rng);
        let is_tc = config.role == LogicalDeviceType::Coordinator && !config.distributed;
        let mut aps = Aps::new(
            config.ieee,
            ApsConfig {
                is_trust_center: is_tc,
                ..ApsConfig::default()
            },
        );
        aps.seed_counter(nwk.rng().next_u8());
        if is_tc {
            aps.aib.trust_center_address = config.ieee;
        } else {
            aps.aib.trust_center_address = if config.distributed {
                ExtendedAddress::BROADCAST
            } else {
                config.preconfigured_link_key.0
            };
            let (partner, key, kind) = config.preconfigured_link_key.clone();
            let mut e = LinkKeyEntry::provisional(partner, key, kind);
            e.attributes = KeyAttributes::ProvisionalKey;
            let _ = aps.security.install(e);
        }
        let node = NodeDescriptor {
            logical_type: config.role,
            fragmentation_supported: true,
            aps_flags: 0,
            frequency_band: frequency_band::BAND_2400,
            mac_capability: config.capability(),
            manufacturer_code: config.manufacturer_code,
            max_buffer_size: 82,
            max_incoming_transfer_size: u16::try_from(panweave_aps::MAX_ASDU).unwrap_or(128),
            server_mask: ServerMask::new(if is_tc {
                ServerMask::PRIMARY_TRUST_CENTER | ServerMask::NETWORK_MANAGER
            } else {
                0
            }),
            max_outgoing_transfer_size: u16::try_from(panweave_aps::MAX_ASDU).unwrap_or(128),
            descriptor_capability: 0,
        };
        let power = if config.sleepy {
            PowerDescriptor {
                mode: panweave_zdo::descriptor::PowerMode::Periodic,
                available_sources: PowerDescriptor::SOURCE_DISPOSABLE,
                current_source: PowerDescriptor::SOURCE_DISPOSABLE,
                level: panweave_zdo::descriptor::PowerLevel::Percent100,
            }
        } else {
            PowerDescriptor::MAINS
        };
        let zdo = Zdo::new(node, power);
        Stack {
            mac,
            nwk,
            aps,
            zdo,
            zcl: Zcl::new(),
            storage,
            config,
            now: Instant::from_millis(0),
            events: Deque::new(),
            mac_handles: Vec::new(),
            aps_handles: Vec::new(),
            phase: Phase::Idle,
            pending_children: Vec::new(),
            network_key_sequence: KeySequenceNumber(0),
            next_poll: None,
            fast_polls_left: 0,
            dlk: crate::dlk::DlkState::default(),
            challenge: None,
            energy_scan: None,
            scan_attempts_left: 0,
            next_scan: None,
            last_scan: (ChannelMask::EMPTY, 0),
            dropped_events: 0,
        }
    }

    /// Registers an application endpoint on both the ZDO (simple
    /// descriptor) and the ZCL dispatcher. The endpoint gets a Basic
    /// cluster server automatically when it does not have one.
    pub fn add_endpoint(
        &mut self,
        descriptor: SimpleDescriptor,
        mut instance: EndpointInstance<8, 16>,
    ) -> Result<(), EndpointError> {
        if instance
            .cluster(basic::ID, panweave_zcl::Role::Server)
            .is_none()
        {
            let power = if self.config.sleepy {
                basic::power_source::BATTERY
            } else {
                basic::power_source::MAINS_SINGLE_PHASE
            };
            if let Ok(b) = basic::server(power, self.config.manufacturer_name, self.config.model) {
                let _ = instance.add_instance(b);
            }
        }
        self.zdo
            .add_endpoint(descriptor)
            .map_err(|_| EndpointError)?;
        self.zcl.add_endpoint(instance).map_err(|_| EndpointError)
    }

    /// Next application event.
    pub fn next_event(&mut self) -> Option<StackEvent> {
        self.events.pop_front()
    }

    pub(crate) fn push_event(&mut self, e: StackEvent) {
        if self.events.push_back(e).is_err() {
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
    }

    /// True when joined and authorized.
    pub fn is_operating(&self) -> bool {
        self.phase == Phase::Operating
    }

    /// Local network address.
    pub fn short_address(&self) -> ShortAddress {
        self.nwk.nib.network_address
    }

    /// PAN identifier.
    pub fn pan_id(&self) -> PanId {
        self.nwk.nib.pan_id
    }

    /// Forms a network with the given network key (coordinator, or a
    /// router forming a distributed network). The key is installed as
    /// sequence 0.
    pub fn form_network_with_key(&mut self, key: Key128) -> Result<(), NwkStatus> {
        let (channels, duration) = (self.config.channels, self.config.scan_duration);
        self.form_network_with_key_on(key, channels, duration)
    }

    /// [`Stack::form_network_with_key`] over an explicit channel list.
    pub fn form_network_with_key_on(
        &mut self,
        key: Key128,
        channels: ChannelMask,
        scan_duration: u8,
    ) -> Result<(), NwkStatus> {
        if self.phase != Phase::Idle {
            return Err(NwkStatus::InvalidRequest);
        }
        self.network_key_sequence = KeySequenceNumber(0);
        self.nwk.set_network_key(KeySequenceNumber(0), key, true);
        let distributed = self.config.distributed;
        self.nwk
            .network_formation(channels, scan_duration, distributed)
            .map_err(|_| NwkStatus::InvalidRequest)?;
        self.phase = Phase::Forming;
        Ok(())
    }

    /// Forms a network with a freshly generated random network key.
    pub fn form_network(&mut self) -> Result<(), NwkStatus> {
        let (channels, duration) = (self.config.channels, self.config.scan_duration);
        self.form_network_on(channels, duration)
    }

    /// [`Stack::form_network`] over an explicit channel list.
    pub fn form_network_on(
        &mut self,
        channels: ChannelMask,
        scan_duration: u8,
    ) -> Result<(), NwkStatus> {
        let mut k = [0u8; 16];
        self.nwk.rng().fill_bytes(&mut k);
        self.form_network_with_key_on(Key128::from_bytes(k), channels, scan_duration)
    }

    /// Starts joining: discovery followed by association or rejoin.
    pub fn join(&mut self, mode: JoinMode) -> Result<(), NwkStatus> {
        let (channels, duration) = (self.config.channels, self.config.scan_duration);
        self.join_on(mode, channels, duration)
    }

    /// [`Stack::join`] over an explicit channel list.
    pub fn join_on(
        &mut self,
        mode: JoinMode,
        channels: ChannelMask,
        scan_duration: u8,
    ) -> Result<(), NwkStatus> {
        let attempts = self.config.zdo.scan_attempts;
        self.join_with(mode, channels, scan_duration, attempts)
    }

    /// [`Self::join_on`] with an explicit number of discovery attempts
    /// (`:Config_NWK_Scan_Attempts`, §2.5.4.5.1); commissioning procedures
    /// that schedule their own retries pass 1.
    pub fn join_with(
        &mut self,
        mode: JoinMode,
        channels: ChannelMask,
        scan_duration: u8,
        attempts: u8,
    ) -> Result<(), NwkStatus> {
        if !matches!(self.phase, Phase::Idle) && mode == JoinMode::Association {
            return Err(NwkStatus::InvalidRequest);
        }
        if matches!(
            self.phase,
            Phase::Discovering(_) | Phase::Joining(_) | Phase::Forming
        ) {
            return Err(NwkStatus::InvalidRequest);
        }
        self.nwk
            .network_discovery(channels, scan_duration, mode == JoinMode::Association)
            .map_err(|_| NwkStatus::InvalidRequest)?;
        self.phase = Phase::Discovering(mode);
        // §2.5.4.5.1: discovery is repeated up to :Config_NWK_Scan_Attempts
        // times, :Config_NWK_Time_btwn_Scans apart, before failing.
        self.scan_attempts_left = attempts.max(1) - 1;
        self.next_scan = None;
        self.last_scan = (channels, scan_duration);
        Ok(())
    }

    /// Permits joining on this device for `seconds` (0 closes, 0xff → 0xfe).
    pub fn permit_join(&mut self, seconds: u8) -> Result<(), NwkStatus> {
        let s = if seconds == 0xff { 0xfe } else { seconds };
        self.nwk
            .permit_joining(s)
            .map_err(|_| NwkStatus::InvalidRequest)
    }

    /// Permits joining network-wide: locally and through a broadcast
    /// Mgmt_Permit_Joining_req to all routers (BDB 3.1 network steering on
    /// a network, §8.2 / R23.2 §2.4.3.3.7).
    pub fn permit_join_network(&mut self, seconds: u8) -> Result<(), NwkStatus> {
        self.permit_join(seconds)?;
        let mut tlvs = [0u8; 40];
        let n = self.permit_joining_tlvs(&mut tlvs);
        let req = panweave_zdo::zdp::MgmtPermitJoiningReq {
            duration: if seconds == 0xff { 0xfe } else { seconds },
            tc_significance: true,
            tlvs: tlvs.get(..n).unwrap_or(&[]),
        };
        self.zdo
            .send_unsolicited(
                ShortAddress::BROADCAST_ROUTERS,
                panweave_zdo::cluster::MGMT_PERMIT_JOINING_REQ,
                &req,
            )
            .map_err(|_| NwkStatus::InvalidRequest)?;
        self.pump();
        Ok(())
    }

    /// Trust Center: removes `device` from the network (§4.6.3.6.1). A
    /// child of this device receives a NWK Leave; otherwise its parent
    /// `parent` receives an APS Remove Device and issues the leave.
    pub fn remove_device(
        &mut self,
        device: ExtendedAddress,
        parent: Option<ExtendedAddress>,
    ) -> Result<(), NwkStatus> {
        if !self.aps.config.is_trust_center {
            return Err(NwkStatus::InvalidRequest);
        }
        let is_child = self
            .nwk
            .neighbors
            .by_extended(device)
            .is_some_and(|n| n.relationship.is_child());
        let r = if is_child {
            self.nwk
                .leave(Some(device), false, false)
                .map_err(|_| NwkStatus::InvalidRequest)
        } else {
            let parent = parent.ok_or(NwkStatus::UnknownDevice)?;
            let parent_short = crate::context::AddrView(&self.nwk)
                .short_of(parent)
                .ok_or(NwkStatus::UnknownDevice)?;
            self.aps
                .remove_device(parent, parent_short, device)
                .map(|_| ())
                .map_err(|_| NwkStatus::InvalidRequest)
        };
        self.pump();
        r
    }

    /// Network manager: changes the PAN ID (§3.6.1.13.3), using
    /// `nwkNextPanId` when staged. The application decides when a
    /// conflict warrants it (§2.3.4); the stack never changes it alone.
    pub fn change_pan_id(&mut self) -> Result<(), NwkStatus> {
        let r = self
            .nwk
            .change_pan_id()
            .map_err(|_| NwkStatus::InvalidRequest);
        self.pump();
        r
    }

    /// Number of PAN ID conflicts detected since the last
    /// Security_Get_Configuration query (`nwkPanIdConflictCount`).
    pub const fn pan_id_conflicts(&self) -> u16 {
        self.nwk.nib.pan_id_conflict_count
    }

    /// Leaves the network.
    pub fn leave(&mut self, rejoin: bool) -> Result<(), NwkStatus> {
        self.nwk
            .leave(None, rejoin, false)
            .map_err(|_| NwkStatus::InvalidRequest)
    }

    /// Current stack time.
    pub const fn now(&self) -> Instant {
        self.now
    }

    // ---------------------------------------------------------------
    // Radio interface
    // ---------------------------------------------------------------

    /// A received PHY frame (without FCS).
    pub fn on_radio_frame(&mut self, bytes: &[u8], meta: RxMetadata) {
        self.handle_radio_frame(bytes, meta);
        self.pump();
    }

    /// Completion of the last [`MacAction::Transmit`].
    pub fn on_tx_complete(&mut self, result: Result<TxResult, RadioError>) {
        self.mac.on_tx_complete(result);
        self.pump();
    }

    /// Energy detection result for [`MacAction::EnergyDetect`].
    pub fn on_energy_result(&mut self, level: u8) {
        self.mac.on_energy_result(level);
        self.pump();
    }

    /// Next radio action.
    pub fn next_radio_action(&mut self) -> Option<MacAction> {
        self.mac.next_action()
    }

    /// Advances time and runs every layer.
    pub fn poll(&mut self, now: Instant) {
        if now.as_millis() > self.now.as_millis() {
            self.now = now;
        }
        let now = self.now;
        self.mac.poll_timers(now);
        self.nwk.poll_timers(now);
        self.aps.poll_timers(now);
        self.zdo.poll_timers(now);
        self.zcl.poll_timers(now);
        self.poll_dlk(now);
        if self.challenge.is_some_and(|c| now.has_reached(c.deadline)) {
            self.challenge = None;
        }
        if let Some((at, channels, duration)) = self.next_scan
            && now.has_reached(at)
        {
            self.next_scan = None;
            if let Phase::Discovering(mode) = self.phase
                && self
                    .nwk
                    .network_discovery(channels, duration, mode == JoinMode::Association)
                    .is_err()
            {
                self.phase = Phase::Idle;
                self.push_event(StackEvent::JoinFailed(NwkStatus::NoNetworks));
            }
        }
        self.service_polling(now);
        self.pump();
    }

    /// Periodic and fast MAC data polling of a sleepy end device.
    fn service_polling(&mut self, now: Instant) {
        if !self.config.sleepy || !matches!(self.phase, Phase::Operating | Phase::AwaitingKey) {
            return;
        }
        match self.next_poll {
            Some(t) if now.has_reached(t) => {
                self.nwk.request(panweave_nwk::layer::NwkRequest::Poll);
                if self.fast_polls_left > 0 {
                    self.fast_polls_left -= 1;
                    self.next_poll = Some(now.saturating_add(self.config.fast_poll_interval));
                } else {
                    self.next_poll = Some(now.saturating_add(self.config.poll_interval));
                }
            }
            Some(_) => {}
            None => self.next_poll = Some(now.saturating_add(self.config.poll_interval)),
        }
    }

    /// Schedules a burst of fast polls (after a transmission).
    pub(crate) fn schedule_fast_polls(&mut self) {
        if self.config.sleepy && matches!(self.phase, Phase::Operating | Phase::AwaitingKey) {
            self.fast_polls_left = self.config.fast_polls;
            let t = self.now.saturating_add(self.config.fast_poll_interval);
            self.next_poll = Some(match self.next_poll {
                Some(n) if n.as_millis() < t.as_millis() => n,
                _ => t,
            });
        }
    }

    /// Earliest time [`Stack::poll`] should run again.
    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.mac.next_deadline(),
            self.nwk.next_deadline(),
            self.aps.next_deadline(),
            self.zdo.next_deadline(),
            self.zcl.next_deadline(),
            self.dlk_deadline(),
            self.challenge.map(|c| c.deadline),
            self.next_scan.map(|(at, _, _)| at),
            self.next_poll
                .filter(|_| self.config.sleepy && self.phase == Phase::Operating),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|t| t.as_millis())
    }

    /// Whether the receiver must stay on (routers, rx-on end devices, or
    /// a sleepy device with a poll in progress).
    pub fn needs_receiver(&self) -> bool {
        !self.config.sleepy || self.mac.needs_receiver()
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// The device state the APS should be in for `authorized`.
    pub(crate) fn aps_state(authorized: bool) -> DeviceState {
        if authorized {
            DeviceState::JoinedAuthorized
        } else {
            DeviceState::JoinedUnauthorized
        }
    }
}
