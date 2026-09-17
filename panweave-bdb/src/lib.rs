//! Base Device Behavior 3.1 (document 22-65816-030) commissioning
//! procedures as a sans-I/O state machine: network formation (§8),
//! off- and on-network steering (§9), the rejoin procedure (§10) and
//! finding & binding (§11), plus the environmental configuration of §5.
//!
//! The machine never touches a radio: it drives an abstract [`Node`]
//! (implemented by `panweave-runtime` for its `Stack`) and consumes
//! [`Event`]s the node reports back. Every procedure is started by a
//! method on [`Bdb`], advanced by [`Bdb::on_event`] / [`Bdb::poll`], and
//! finishes with an [`Outcome`].
//!
//! Touchlink (§12) lives in [`touchlink`] as its own pair of machines;
//! the certificate-based key exchange is not implemented (see
//! `conformance/bdb-3_1.toml`).
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod touchlink;

use heapless::Vec;
use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_device_library::{ClusterClass, FbRole, classify, finding_binding_role};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ChannelMask, ClusterId, Endpoint, ExtendedAddress, GroupAddress, LogicalDeviceType,
    ShortAddress,
};

/// Constants of BDB 3.1 §5.1–§5.3.
pub mod constants {
    use panweave_types::ChannelMask;
    use panweave_types::time::Duration;

    /// `bdbcMaxSameNetworkRetryAttempts` (§5.1.1).
    pub const MAX_SAME_NETWORK_RETRY_ATTEMPTS: u8 = 10;
    /// `bdbcMinCommissioningTime` in seconds (§5.1.2).
    pub const MIN_COMMISSIONING_TIME_SECS: u8 = 180;
    /// `bdbcRecSameNetworkRetryAttempts` (§5.1.3).
    pub const REC_SAME_NETWORK_RETRY_ATTEMPTS: u8 = 3;
    /// `bdbcTLPrimaryChannelSet` (§5.2.1).
    pub const TL_PRIMARY_CHANNEL_SET: ChannelMask = ChannelMask(0x0210_8800);
    /// `bdbcTLSecondaryChannelSet` (§5.2.2).
    pub const TL_SECONDARY_CHANNEL_SET: ChannelMask = ChannelMask(0x07FF_F800 ^ 0x0210_8800);
    /// `bdbcMinFastPollDurationAfterJoin`: 120 quarter seconds (§5.3.1).
    pub const MIN_FAST_POLL_DURATION_AFTER_JOIN: Duration = Duration::from_secs(30);
    /// Upper bound of the optional random delay before off-network
    /// steering (§9.8).
    pub const MAX_STEERING_DELAY: Duration = Duration::from_secs(5);
}

/// Configuration attributes and node policies (§5.4, §5.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Config {
    /// `bdbcfPrimaryChannelList` (§5.4.1); empty to skip the primary scan.
    pub primary_channels: ChannelMask,
    /// `bdbcfSecondaryChannelList` (§5.4.3); empty to skip the secondary
    /// scan.
    pub secondary_channels: ChannelMask,
    /// `bdbcfScanDuration` (§5.4.2).
    pub scan_duration: u8,
    /// `bdbcfTrustCenterNodeJoinTimeout` in seconds (§5.4.4).
    pub trust_center_node_join_timeout_secs: u8,
    /// `bdbcfSecurityTimeoutPeriod` (§5.4.5).
    pub security_timeout: Duration,
    /// `acceptNewUnsolicitedApplicationLinkKey` (§5.7.1).
    pub accept_new_unsolicited_application_link_key: bool,
    /// `requireCBKESuccess` (§5.7.1).
    pub require_cbke_success: bool,
    /// Join attempts on the same network before giving up on a channel
    /// list (§9.8 step 7; at most
    /// [`constants::MAX_SAME_NETWORK_RETRY_ATTEMPTS`]).
    pub same_network_retries: u8,
    /// Duration the commissioning window stays open when this node opens
    /// it (at least [`constants::MIN_COMMISSIONING_TIME_SECS`]).
    pub commissioning_time_secs: u8,
    /// Time to wait for Identify Query Responses (§11.2 step 3).
    pub identify_query_timeout: Duration,
    /// Time to wait for a ZDO response during finding & binding.
    pub zdo_timeout: Duration,
}

impl Config {
    /// Defaults for the 2.4 GHz band (Tables 4–7, 10).
    pub const DEFAULT_2_4GHZ: Config = Config {
        primary_channels: ChannelMask::BDB_PRIMARY,
        secondary_channels: ChannelMask::BDB_SECONDARY,
        scan_duration: 3,
        trust_center_node_join_timeout_secs: 0x0f,
        security_timeout: Duration::from_millis(0x2710),
        accept_new_unsolicited_application_link_key: true,
        require_cbke_success: false,
        same_network_retries: constants::REC_SAME_NETWORK_RETRY_ATTEMPTS,
        commissioning_time_secs: constants::MIN_COMMISSIONING_TIME_SECS,
        identify_query_timeout: Duration::from_secs(5),
        zdo_timeout: Duration::from_secs(5),
    };
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT_2_4GHZ
    }
}

/// Kind of join the node is asked to perform.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinKind {
    /// MAC association / Network Commissioning join (RejoinNetwork 0x00).
    Association,
    /// NWK rejoin secured with the network key.
    SecuredRejoin,
    /// Unsecured NWK rejoin (Trust Center rejoin).
    TrustCenterRejoin,
}

/// Errors reported by a [`Node`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NodeError {
    /// The node cannot start the operation now.
    Busy,
    /// The operation is not available (unknown endpoint, no such
    /// cluster, …).
    Unsupported,
    /// The binding table is full (APS `TABLE_FULL`).
    TableFull,
}

/// Maximum clusters considered per endpoint during finding & binding.
pub const MAX_CLUSTERS: usize = 16;

/// Maximum respondents remembered during finding & binding (§6.4
/// requires handling at least one).
pub const MAX_RESPONDENTS: usize = 8;

/// A cluster instance on the local initiator endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LocalCluster {
    /// Cluster identifier.
    pub id: ClusterId,
    /// True for a client (initiator of client-to-server transactions).
    pub client: bool,
}

/// The stack facilities the procedures need. Implemented by the runtime.
pub trait Node {
    /// Logical device type.
    fn role(&self) -> LogicalDeviceType;
    /// Current time.
    fn now(&self) -> Instant;
    /// True on a centralized network (`apsTrustCenterAddress` is not the
    /// all-ones address).
    fn is_centralized(&self) -> bool;
    /// True when the Trust Center link key entry is `VERIFIED_KEY`.
    fn trust_center_key_verified(&self) -> bool;
    /// Mask containing only the current (last) logical channel.
    fn current_channel(&self) -> ChannelMask;
    /// NLME-NETWORK-FORMATION.request over `channels`.
    fn form_network(&mut self, channels: ChannelMask, scan_duration: u8) -> Result<(), NodeError>;
    /// Discovery over `channels` followed by the requested join.
    fn join(
        &mut self,
        kind: JoinKind,
        channels: ChannelMask,
        scan_duration: u8,
    ) -> Result<(), NodeError>;
    /// NLME-LEAVE.request for this device (no rejoin, keep children).
    fn leave(&mut self) -> Result<(), NodeError>;
    /// NLME-PERMIT-JOINING.request (routers and coordinators).
    fn permit_join(&mut self, seconds: u8) -> Result<(), NodeError>;
    /// Broadcast Mgmt_Permit_Joining_req with TC significance.
    fn broadcast_permit_join(&mut self, seconds: u8) -> Result<(), NodeError>;
    /// Keep a sleepy end device in fast-poll mode for `duration`.
    fn fast_poll(&mut self, duration: Duration);
    /// Set `IdentifyTime` on the Identify server of `endpoint`.
    fn identify(&mut self, endpoint: Endpoint, seconds: u16) -> Result<(), NodeError>;
    /// Broadcast an Identify Query from `endpoint`.
    fn identify_query(&mut self, endpoint: Endpoint) -> Result<(), NodeError>;
    /// Unicast Simple_Desc_req.
    fn simple_desc_req(&mut self, addr: ShortAddress, endpoint: Endpoint) -> Result<(), NodeError>;
    /// Unicast IEEE_addr_req.
    fn ieee_addr_req(&mut self, addr: ShortAddress) -> Result<(), NodeError>;
    /// Known IEEE address of a short address.
    fn ieee_of(&self, addr: ShortAddress) -> Option<ExtendedAddress>;
    /// Clusters implemented on the local endpoint.
    fn local_clusters(&self, endpoint: Endpoint, out: &mut Vec<LocalCluster, MAX_CLUSTERS>);
    /// APSME-BIND.request.
    fn bind(&mut self, entry: BindingEntry) -> Result<(), NodeError>;
    /// Unicast Groups cluster Add Group to a respondent endpoint.
    fn add_group(
        &mut self,
        addr: ShortAddress,
        endpoint: Endpoint,
        group: GroupAddress,
    ) -> Result<(), NodeError>;
}

/// Events the node reports to the machine.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// NLME-NETWORK-FORMATION.confirm.
    FormationConfirm {
        /// Success.
        success: bool,
    },
    /// Join or rejoin finished (including network key delivery).
    JoinConfirm {
        /// Success.
        success: bool,
    },
    /// A unique Trust Center link key was obtained and verified.
    LinkKeyUpdated,
    /// This device left the network.
    Left,
    /// Identify Query Response received on `endpoint` from `src`.
    IdentifyQueryResponse {
        /// Responding device.
        src: ShortAddress,
        /// Responding endpoint.
        src_endpoint: Endpoint,
        /// Local endpoint the response arrived at.
        endpoint: Endpoint,
    },
    /// Simple_Desc_rsp.
    SimpleDescriptor {
        /// Device.
        src: ShortAddress,
        /// Endpoint described.
        endpoint: Endpoint,
        /// Success status.
        success: bool,
        /// Input (server) clusters.
        inputs: Vec<ClusterId, MAX_CLUSTERS>,
        /// Output (client) clusters.
        outputs: Vec<ClusterId, MAX_CLUSTERS>,
    },
    /// IEEE_addr_rsp.
    IeeeAddress {
        /// Short address asked for.
        short: ShortAddress,
        /// IEEE address, `None` on failure.
        ieee: Option<ExtendedAddress>,
    },
    /// `IdentifyTime` on `endpoint` changed (0 = stopped).
    Identify {
        /// Endpoint.
        endpoint: Endpoint,
        /// Remaining seconds.
        seconds: u16,
    },
}

/// Why a procedure failed (names from the procedure figures).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Failure {
    /// Formation / steering: the node is already on a network.
    AlreadyOnNetwork,
    /// The node is not on a network.
    NotOnNetwork,
    /// The logical device type cannot form a network.
    NotPermittedToForm,
    /// Formation failed on the primary and secondary lists.
    ScanChannelsExhausted,
    /// Steering found no network to join.
    NoNetwork,
    /// The Trust Center link key exchange did not complete.
    UnsuccessfulKeyExchange,
    /// The rejoin procedure failed on every channel list.
    RejoinUnsuccessful,
    /// No Identify Query Response was received.
    NoIdentifyQueryResponse,
    /// The binding table is full.
    BindingTableFull,
    /// The node refused an operation.
    Node(NodeError),
    /// Another procedure is running.
    Busy,
}

/// End of a procedure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Network formation (§8.1).
    Formation(Result<(), Failure>),
    /// Off-network steering (§9.8) — on success the node joined.
    Steering(Result<(), Failure>),
    /// Rejoin (§10.1).
    Rejoin(Result<(), Failure>),
    /// Target finding & binding (§11.1) finished identifying.
    FindingBindingTarget {
        /// Endpoint.
        endpoint: Endpoint,
    },
    /// Initiator finding & binding (§11.2).
    FindingBindingInitiator {
        /// Endpoint.
        endpoint: Endpoint,
        /// Bindings created.
        bindings: u8,
        /// Result.
        result: Result<(), Failure>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    /// Attempting on the given channel list.
    Primary,
    Secondary,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RejoinStage {
    SecuredCurrent,
    TcCurrent,
    Primary,
    Secondary,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SteeringPhase {
    /// Discovery + join in progress on the current list.
    Joining,
    /// Joined a centralized network; waiting for the TCLK exchange.
    AwaitingLinkKey,
    /// Leaving after a failed key exchange.
    Leaving,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FbPhase {
    /// Waiting for Identify Query Responses.
    Querying,
    /// Waiting for the Simple_Desc_rsp of `respondents[index]`.
    SimpleDesc,
    /// Waiting for the IEEE address of `respondents[index]`.
    IeeeAddr,
}

#[derive(Clone, Debug)]
struct FbState {
    endpoint: Endpoint,
    group: Option<GroupAddress>,
    filter: Vec<ClusterId, MAX_CLUSTERS>,
    respondents: Vec<(ShortAddress, Endpoint), MAX_RESPONDENTS>,
    index: usize,
    phase: FbPhase,
    bindings: u8,
    /// Matching clusters of the current respondent awaiting an IEEE
    /// address.
    pending: Vec<ClusterId, MAX_CLUSTERS>,
}

#[derive(Clone, Debug)]
enum Procedure {
    Idle,
    Formation {
        stage: Stage,
    },
    Steering {
        stage: Stage,
        phase: SteeringPhase,
        attempts: u8,
    },
    Rejoin {
        stage: RejoinStage,
    },
    FindingBinding(FbState),
}

/// The commissioning state machine.
#[derive(Debug)]
pub struct Bdb {
    /// Configuration.
    pub config: Config,
    on_network: bool,
    procedure: Procedure,
    deadline: Option<Instant>,
    /// Target endpoints currently identifying for finding & binding.
    targets: Vec<Endpoint, 4>,
}

impl Bdb {
    /// New machine; `on_network` restores `bdbgNodeIsOnANetwork` (§6.7).
    pub const fn new(config: Config, on_network: bool) -> Self {
        Bdb {
            config,
            on_network,
            procedure: Procedure::Idle,
            deadline: None,
            targets: Vec::new(),
        }
    }

    /// `bdbgNodeIsOnANetwork` (§5.5.1).
    pub const fn is_on_network(&self) -> bool {
        self.on_network
    }

    /// Records that the node formed or joined a network outside the
    /// machine (e.g. the runtime's own join API) or left it.
    pub const fn set_on_network(&mut self, on: bool) {
        self.on_network = on;
    }

    /// True while a procedure is running.
    pub const fn is_busy(&self) -> bool {
        !matches!(self.procedure, Procedure::Idle)
    }

    /// Earliest timeout.
    pub const fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn list(&self, stage: Stage) -> ChannelMask {
        match stage {
            Stage::Primary => self.config.primary_channels,
            Stage::Secondary => self.config.secondary_channels,
        }
    }

    // ------------------------------------------------------------------
    // Network formation (§8.1)
    // ------------------------------------------------------------------

    /// Starts the Network Formation procedure.
    pub fn form_network(&mut self, node: &mut impl Node) -> Result<(), Failure> {
        if self.is_busy() {
            return Err(Failure::Busy);
        }
        if self.on_network {
            return Err(Failure::AlreadyOnNetwork);
        }
        if node.role() == LogicalDeviceType::EndDevice {
            return Err(Failure::NotPermittedToForm);
        }
        self.procedure = Procedure::Formation {
            stage: Stage::Primary,
        };
        self.start_formation_stage(node, Stage::Primary)
    }

    fn start_formation_stage(&mut self, node: &mut impl Node, stage: Stage) -> Result<(), Failure> {
        let channels = self.list(stage);
        if channels.is_empty() {
            return match stage {
                Stage::Primary => self.start_formation_stage(node, Stage::Secondary),
                Stage::Secondary => {
                    self.procedure = Procedure::Idle;
                    Err(Failure::ScanChannelsExhausted)
                }
            };
        }
        self.procedure = Procedure::Formation { stage };
        node.form_network(channels, self.config.scan_duration)
            .map_err(|e| {
                self.procedure = Procedure::Idle;
                Failure::Node(e)
            })
    }

    // ------------------------------------------------------------------
    // Network steering (§9.7, §9.8)
    // ------------------------------------------------------------------

    /// On-network steering (§9.7): opens the network for
    /// `commissioning_time_secs`.
    pub fn steer_on_network(&mut self, node: &mut impl Node) -> Result<(), Failure> {
        if !self.on_network {
            return Err(Failure::NotOnNetwork);
        }
        let secs = self
            .config
            .commissioning_time_secs
            .max(constants::MIN_COMMISSIONING_TIME_SECS);
        node.broadcast_permit_join(secs).map_err(Failure::Node)?;
        if node.role() != LogicalDeviceType::EndDevice {
            node.permit_join(secs).map_err(Failure::Node)?;
        }
        Ok(())
    }

    /// Local closing of the network (§9.7.1).
    pub fn close_network(&mut self, node: &mut impl Node) -> Result<(), Failure> {
        node.broadcast_permit_join(0).map_err(Failure::Node)?;
        if node.role() != LogicalDeviceType::EndDevice {
            node.permit_join(0).map_err(Failure::Node)?;
        }
        Ok(())
    }

    /// Off-network steering (§9.8): discover and join an open network.
    pub fn steer(&mut self, node: &mut impl Node) -> Result<(), Failure> {
        if self.is_busy() {
            return Err(Failure::Busy);
        }
        if self.on_network {
            return Err(Failure::AlreadyOnNetwork);
        }
        self.start_steering_stage(node, Stage::Primary)
    }

    fn start_steering_stage(&mut self, node: &mut impl Node, stage: Stage) -> Result<(), Failure> {
        let channels = self.list(stage);
        if channels.is_empty() {
            return match stage {
                Stage::Primary => self.start_steering_stage(node, Stage::Secondary),
                Stage::Secondary => {
                    self.procedure = Procedure::Idle;
                    Err(Failure::NoNetwork)
                }
            };
        }
        self.procedure = Procedure::Steering {
            stage,
            phase: SteeringPhase::Joining,
            attempts: 0,
        };
        node.join(JoinKind::Association, channels, self.config.scan_duration)
            .map_err(|e| {
                self.procedure = Procedure::Idle;
                Failure::Node(e)
            })
    }

    /// Steps 12–15 of §9.8 after a successful join.
    fn finish_steering(&mut self, node: &mut impl Node) -> Outcome {
        self.on_network = true;
        self.procedure = Procedure::Idle;
        self.deadline = None;
        let secs = self
            .config
            .commissioning_time_secs
            .max(constants::MIN_COMMISSIONING_TIME_SECS);
        let _ = node.broadcast_permit_join(secs);
        if node.role() != LogicalDeviceType::EndDevice {
            let _ = node.permit_join(secs);
        }
        node.fast_poll(constants::MIN_FAST_POLL_DURATION_AFTER_JOIN);
        Outcome::Steering(Ok(()))
    }

    // ------------------------------------------------------------------
    // Rejoin (§10.1)
    // ------------------------------------------------------------------

    /// Starts the Rejoin procedure. `lost_trust_center` selects the entry
    /// point of step 1 (skip the secured rejoin on the current channel
    /// when Trust Center connectivity was lost on a centralized network
    /// with a verified key).
    pub fn rejoin(&mut self, node: &mut impl Node, lost_trust_center: bool) -> Result<(), Failure> {
        if self.is_busy() {
            return Err(Failure::Busy);
        }
        let verified = node.is_centralized() && node.trust_center_key_verified();
        let stage = if verified && lost_trust_center {
            RejoinStage::TcCurrent
        } else {
            RejoinStage::SecuredCurrent
        };
        self.start_rejoin_stage(node, stage)
    }

    fn start_rejoin_stage(
        &mut self,
        node: &mut impl Node,
        stage: RejoinStage,
    ) -> Result<(), Failure> {
        let verified = node.is_centralized() && node.trust_center_key_verified();
        let (kind, channels) = match stage {
            RejoinStage::SecuredCurrent => (JoinKind::SecuredRejoin, node.current_channel()),
            RejoinStage::TcCurrent => {
                if !verified {
                    return self.start_rejoin_stage(node, RejoinStage::Primary);
                }
                (JoinKind::TrustCenterRejoin, node.current_channel())
            }
            // §10.1 steps 3–4: at least one rejoin attempt on every channel
            // of the list; a secured rejoin is valid on both network types.
            RejoinStage::Primary => (JoinKind::SecuredRejoin, self.config.primary_channels),
            RejoinStage::Secondary => (JoinKind::SecuredRejoin, self.config.secondary_channels),
        };
        if channels.is_empty() {
            return match stage {
                RejoinStage::Primary => self.start_rejoin_stage(node, RejoinStage::Secondary),
                _ => {
                    self.procedure = Procedure::Idle;
                    Err(Failure::RejoinUnsuccessful)
                }
            };
        }
        self.procedure = Procedure::Rejoin { stage };
        node.join(kind, channels, self.config.scan_duration)
            .map_err(|e| {
                self.procedure = Procedure::Idle;
                Failure::Node(e)
            })
    }

    // ------------------------------------------------------------------
    // Finding & binding (§11)
    // ------------------------------------------------------------------

    /// Target endpoint finding & binding (§11.1): identify for
    /// `commissioning_time_secs`. Runs alongside other procedures.
    pub fn find_and_bind_target(
        &mut self,
        node: &mut impl Node,
        endpoint: Endpoint,
    ) -> Result<(), Failure> {
        if !self.on_network {
            return Err(Failure::NotOnNetwork);
        }
        let secs = self
            .config
            .commissioning_time_secs
            .max(constants::MIN_COMMISSIONING_TIME_SECS);
        node.identify(endpoint, u16::from(secs))
            .map_err(Failure::Node)?;
        if !self.targets.contains(&endpoint) {
            let _ = self.targets.push(endpoint);
        }
        Ok(())
    }

    /// Initiator endpoint finding & binding (§11.2). `group` requests
    /// group bindings (plus Add Group on the respondents); `clusters`
    /// restricts the clusters considered (empty: every application
    /// cluster for which the endpoint is the initiator, per the Device
    /// Type Library classification).
    pub fn find_and_bind_initiator(
        &mut self,
        node: &mut impl Node,
        endpoint: Endpoint,
        group: Option<GroupAddress>,
        clusters: &[ClusterId],
    ) -> Result<(), Failure> {
        if self.is_busy() {
            return Err(Failure::Busy);
        }
        if !self.on_network {
            return Err(Failure::NotOnNetwork);
        }
        node.identify_query(endpoint).map_err(Failure::Node)?;
        let mut filter = Vec::new();
        for c in clusters {
            let _ = filter.push(*c);
        }
        self.procedure = Procedure::FindingBinding(FbState {
            endpoint,
            group,
            filter,
            respondents: Vec::new(),
            index: 0,
            phase: FbPhase::Querying,
            bindings: 0,
            pending: Vec::new(),
        });
        self.deadline = Some(node.now() + self.config.identify_query_timeout);
        Ok(())
    }

    /// Moves to the next respondent (step 10) or finishes.
    fn fb_next_respondent(&mut self, node: &mut impl Node, advance: bool) -> Option<Outcome> {
        let Procedure::FindingBinding(fb) = &mut self.procedure else {
            return None;
        };
        if advance {
            fb.index += 1;
        }
        loop {
            let Some(&(addr, ep)) = fb.respondents.get(fb.index) else {
                let out = Outcome::FindingBindingInitiator {
                    endpoint: fb.endpoint,
                    bindings: fb.bindings,
                    result: Ok(()),
                };
                self.procedure = Procedure::Idle;
                self.deadline = None;
                return Some(out);
            };
            match node.simple_desc_req(addr, ep) {
                Ok(()) => {
                    fb.phase = FbPhase::SimpleDesc;
                    self.deadline = Some(node.now() + self.config.zdo_timeout);
                    return None;
                }
                Err(_) => fb.index += 1,
            }
        }
    }

    /// Steps 6–9 for one respondent whose descriptor is known.
    fn fb_bind_matches(
        &mut self,
        node: &mut impl Node,
        inputs: &[ClusterId],
        outputs: &[ClusterId],
    ) -> Option<Outcome> {
        let Procedure::FindingBinding(fb) = &mut self.procedure else {
            return None;
        };
        let (addr, ep) = *fb.respondents.get(fb.index)?;
        let mut local = Vec::new();
        node.local_clusters(fb.endpoint, &mut local);
        let mut matches: Vec<ClusterId, MAX_CLUSTERS> = Vec::new();
        for c in &local {
            let matched = if c.client {
                inputs.contains(&c.id)
            } else {
                outputs.contains(&c.id)
            };
            // Step 6: only application clusters for which this endpoint
            // is the transaction initiator (type 1 client, type 2 server)
            // are bound; utility clusters never are.
            let selected = if fb.filter.is_empty() {
                match finding_binding_role(c.id, !c.client) {
                    Some(FbRole::Initiator) => true,
                    Some(FbRole::Target) => false,
                    None => classify(c.id) != ClusterClass::Utility,
                }
            } else {
                fb.filter.contains(&c.id)
            };
            if matched && selected {
                let _ = matches.push(c.id);
            }
        }
        if matches.is_empty() {
            return self.fb_next_respondent(node, true);
        }
        let destination = match fb.group {
            Some(g) => BindingDestination::Group(g),
            None => match node.ieee_of(addr) {
                Some(ieee) => BindingDestination::Unicast {
                    address: ieee,
                    endpoint: ep,
                },
                None => {
                    // Step 7: the IEEE address must be learnt first.
                    fb.pending = matches;
                    fb.phase = FbPhase::IeeeAddr;
                    return match node.ieee_addr_req(addr) {
                        Ok(()) => {
                            self.deadline = Some(node.now() + self.config.zdo_timeout);
                            None
                        }
                        Err(_) => self.fb_next_respondent(node, true),
                    };
                }
            },
        };
        self.fb_create_bindings(node, &matches, destination)
    }

    fn fb_create_bindings(
        &mut self,
        node: &mut impl Node,
        matches: &[ClusterId],
        destination: BindingDestination,
    ) -> Option<Outcome> {
        let Procedure::FindingBinding(fb) = &mut self.procedure else {
            return None;
        };
        let (addr, ep) = *fb.respondents.get(fb.index)?;
        let mut created = 0u8;
        for cluster in matches {
            match node.bind(BindingEntry {
                src_endpoint: fb.endpoint,
                cluster: *cluster,
                destination,
            }) {
                Ok(()) => created = created.saturating_add(1),
                Err(NodeError::TableFull) => {
                    let out = Outcome::FindingBindingInitiator {
                        endpoint: fb.endpoint,
                        bindings: fb.bindings.saturating_add(created),
                        result: Err(Failure::BindingTableFull),
                    };
                    self.procedure = Procedure::Idle;
                    self.deadline = None;
                    return Some(out);
                }
                Err(_) => {}
            }
        }
        fb.bindings = fb.bindings.saturating_add(created);
        // Step 9: configure the group on the respondent.
        if created > 0
            && let Some(g) = fb.group
        {
            let _ = node.add_group(addr, ep, g);
        }
        self.fb_next_respondent(node, true)
    }

    // ------------------------------------------------------------------
    // Event and time handling
    // ------------------------------------------------------------------

    /// Feeds a node event. Returns the outcome of a procedure that
    /// finished.
    pub fn on_event(&mut self, node: &mut impl Node, event: &Event) -> Option<Outcome> {
        if let Event::Identify { endpoint, seconds } = event
            && *seconds == 0
            && let Some(i) = self.targets.iter().position(|e| e == endpoint)
        {
            let _ = self.targets.swap_remove(i);
            return Some(Outcome::FindingBindingTarget {
                endpoint: *endpoint,
            });
        }
        match self.procedure.clone() {
            Procedure::Idle => None,
            Procedure::Formation { stage } => match event {
                Event::FormationConfirm { success: true } => {
                    self.on_network = true;
                    self.procedure = Procedure::Idle;
                    Some(Outcome::Formation(Ok(())))
                }
                Event::FormationConfirm { success: false } => match stage {
                    Stage::Primary => self
                        .start_formation_stage(node, Stage::Secondary)
                        .err()
                        .map(|f| Outcome::Formation(Err(f))),
                    Stage::Secondary => {
                        self.procedure = Procedure::Idle;
                        Some(Outcome::Formation(Err(Failure::ScanChannelsExhausted)))
                    }
                },
                _ => None,
            },
            Procedure::Steering {
                stage,
                phase,
                attempts,
            } => self.on_steering_event(node, stage, phase, attempts, event),
            Procedure::Rejoin { stage } => match event {
                Event::JoinConfirm { success: true } => {
                    self.on_network = true;
                    self.procedure = Procedure::Idle;
                    Some(Outcome::Rejoin(Ok(())))
                }
                Event::JoinConfirm { success: false } => {
                    let next = match stage {
                        RejoinStage::SecuredCurrent => RejoinStage::TcCurrent,
                        RejoinStage::TcCurrent => RejoinStage::Primary,
                        RejoinStage::Primary => RejoinStage::Secondary,
                        RejoinStage::Secondary => {
                            self.procedure = Procedure::Idle;
                            return Some(Outcome::Rejoin(Err(Failure::RejoinUnsuccessful)));
                        }
                    };
                    self.start_rejoin_stage(node, next)
                        .err()
                        .map(|f| Outcome::Rejoin(Err(f)))
                }
                _ => None,
            },
            Procedure::FindingBinding(fb) => self.on_fb_event(node, &fb, event),
        }
    }

    fn on_steering_event(
        &mut self,
        node: &mut impl Node,
        stage: Stage,
        phase: SteeringPhase,
        attempts: u8,
        event: &Event,
    ) -> Option<Outcome> {
        match (phase, event) {
            (SteeringPhase::Joining, Event::JoinConfirm { success: true }) => {
                // §9.3: on a distributed network the join is complete; on
                // a centralized network the TCLK exchange must succeed.
                if node.is_centralized() && !node.trust_center_key_verified() {
                    self.procedure = Procedure::Steering {
                        stage,
                        phase: SteeringPhase::AwaitingLinkKey,
                        attempts,
                    };
                    self.deadline = Some(node.now() + self.config.security_timeout);
                    None
                } else {
                    Some(self.finish_steering(node))
                }
            }
            (SteeringPhase::Joining, Event::JoinConfirm { success: false }) => {
                self.steering_retry(node, stage, attempts)
            }
            (SteeringPhase::AwaitingLinkKey, Event::LinkKeyUpdated) => {
                Some(self.finish_steering(node))
            }
            (SteeringPhase::Leaving, Event::Left) => {
                self.deadline = None;
                self.steering_retry(node, stage, attempts)
            }
            _ => None,
        }
    }

    /// Step 7 / 10 / 11: retry the same list or move to the next one.
    fn steering_retry(
        &mut self,
        node: &mut impl Node,
        stage: Stage,
        attempts: u8,
    ) -> Option<Outcome> {
        let attempts = attempts.saturating_add(1);
        let limit = self
            .config
            .same_network_retries
            .clamp(1, constants::MAX_SAME_NETWORK_RETRY_ATTEMPTS);
        if attempts < limit {
            self.procedure = Procedure::Steering {
                stage,
                phase: SteeringPhase::Joining,
                attempts,
            };
            return node
                .join(
                    JoinKind::Association,
                    self.list(stage),
                    self.config.scan_duration,
                )
                .err()
                .map(|e| {
                    self.procedure = Procedure::Idle;
                    Outcome::Steering(Err(Failure::Node(e)))
                });
        }
        match stage {
            Stage::Primary => self
                .start_steering_stage(node, Stage::Secondary)
                .err()
                .map(|f| Outcome::Steering(Err(f))),
            Stage::Secondary => {
                self.procedure = Procedure::Idle;
                Some(Outcome::Steering(Err(Failure::NoNetwork)))
            }
        }
    }

    fn on_fb_event(
        &mut self,
        node: &mut impl Node,
        fb: &FbState,
        event: &Event,
    ) -> Option<Outcome> {
        match (fb.phase, event) {
            (
                FbPhase::Querying,
                Event::IdentifyQueryResponse {
                    src,
                    src_endpoint,
                    endpoint,
                },
            ) if *endpoint == fb.endpoint => {
                if let Procedure::FindingBinding(state) = &mut self.procedure
                    && !state.respondents.contains(&(*src, *src_endpoint))
                {
                    let _ = state.respondents.push((*src, *src_endpoint));
                }
                None
            }
            (
                FbPhase::SimpleDesc,
                Event::SimpleDescriptor {
                    src,
                    endpoint,
                    success,
                    inputs,
                    outputs,
                },
            ) if fb.respondents.get(fb.index) == Some(&(*src, *endpoint)) => {
                if *success {
                    self.fb_bind_matches(node, inputs, outputs)
                } else {
                    self.fb_next_respondent(node, true)
                }
            }
            (FbPhase::IeeeAddr, Event::IeeeAddress { short, ieee })
                if fb.respondents.get(fb.index).map(|r| r.0) == Some(*short) =>
            {
                match ieee {
                    Some(ieee) => {
                        let ep = fb.respondents.get(fb.index).map_or(Endpoint(0), |r| r.1);
                        let matches = fb.pending.clone();
                        self.fb_create_bindings(
                            node,
                            &matches,
                            BindingDestination::Unicast {
                                address: *ieee,
                                endpoint: ep,
                            },
                        )
                    }
                    None => self.fb_next_respondent(node, true),
                }
            }
            _ => None,
        }
    }

    /// Advances timeouts.
    pub fn poll(&mut self, node: &mut impl Node, now: Instant) -> Option<Outcome> {
        let due = self.deadline?;
        if !now.has_reached(due) {
            return None;
        }
        self.deadline = None;
        match self.procedure.clone() {
            Procedure::Steering {
                stage,
                phase: SteeringPhase::AwaitingLinkKey,
                attempts,
            } => {
                // §9.3 step 9 / §9.8 step 9: unsuccessful key exchange —
                // leave and retry.
                self.procedure = Procedure::Steering {
                    stage,
                    phase: SteeringPhase::Leaving,
                    attempts,
                };
                match node.leave() {
                    Ok(()) => {
                        self.deadline = Some(now + self.config.zdo_timeout);
                        None
                    }
                    Err(_) => self.steering_retry(node, stage, attempts),
                }
            }
            Procedure::Steering {
                stage,
                phase: SteeringPhase::Leaving,
                attempts,
            } => {
                // No leave confirmation: treat the network as left.
                self.on_network = false;
                self.steering_retry(node, stage, attempts)
            }
            Procedure::FindingBinding(fb) => match fb.phase {
                FbPhase::Querying => {
                    if fb.respondents.is_empty() {
                        self.procedure = Procedure::Idle;
                        Some(Outcome::FindingBindingInitiator {
                            endpoint: fb.endpoint,
                            bindings: 0,
                            result: Err(Failure::NoIdentifyQueryResponse),
                        })
                    } else {
                        self.fb_next_respondent(node, false)
                    }
                }
                FbPhase::SimpleDesc | FbPhase::IeeeAddr => self.fb_next_respondent(node, true),
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec as StdVec;

    use super::*;

    #[derive(Default)]
    struct Fake {
        role_ed: bool,
        centralized: bool,
        verified: bool,
        now: Instant,
        joins: StdVec<(JoinKind, ChannelMask)>,
        forms: StdVec<ChannelMask>,
        permits: StdVec<u8>,
        broadcasts: StdVec<u8>,
        left: u32,
        binds: StdVec<BindingEntry>,
        groups: StdVec<(ShortAddress, Endpoint, GroupAddress)>,
        queries: u32,
        simple: StdVec<(ShortAddress, Endpoint)>,
        ieee_reqs: StdVec<ShortAddress>,
        known: Option<(ShortAddress, ExtendedAddress)>,
        table_full: bool,
    }

    impl Node for Fake {
        fn role(&self) -> LogicalDeviceType {
            if self.role_ed {
                LogicalDeviceType::EndDevice
            } else {
                LogicalDeviceType::Router
            }
        }
        fn now(&self) -> Instant {
            self.now
        }
        fn is_centralized(&self) -> bool {
            self.centralized
        }
        fn trust_center_key_verified(&self) -> bool {
            self.verified
        }
        fn current_channel(&self) -> ChannelMask {
            ChannelMask(1 << 15)
        }
        fn form_network(&mut self, c: ChannelMask, _d: u8) -> Result<(), NodeError> {
            self.forms.push(c);
            Ok(())
        }
        fn join(&mut self, k: JoinKind, c: ChannelMask, _d: u8) -> Result<(), NodeError> {
            self.joins.push((k, c));
            Ok(())
        }
        fn leave(&mut self) -> Result<(), NodeError> {
            self.left += 1;
            Ok(())
        }
        fn permit_join(&mut self, s: u8) -> Result<(), NodeError> {
            self.permits.push(s);
            Ok(())
        }
        fn broadcast_permit_join(&mut self, s: u8) -> Result<(), NodeError> {
            self.broadcasts.push(s);
            Ok(())
        }
        fn fast_poll(&mut self, _d: Duration) {}
        fn identify(&mut self, _e: Endpoint, _s: u16) -> Result<(), NodeError> {
            Ok(())
        }
        fn identify_query(&mut self, _e: Endpoint) -> Result<(), NodeError> {
            self.queries += 1;
            Ok(())
        }
        fn simple_desc_req(&mut self, a: ShortAddress, e: Endpoint) -> Result<(), NodeError> {
            self.simple.push((a, e));
            Ok(())
        }
        fn ieee_addr_req(&mut self, a: ShortAddress) -> Result<(), NodeError> {
            self.ieee_reqs.push(a);
            Ok(())
        }
        fn ieee_of(&self, a: ShortAddress) -> Option<ExtendedAddress> {
            self.known.filter(|k| k.0 == a).map(|k| k.1)
        }
        fn local_clusters(&self, _e: Endpoint, out: &mut Vec<LocalCluster, MAX_CLUSTERS>) {
            let _ = out.push(LocalCluster {
                id: ClusterId(0x0006),
                client: true,
            });
            let _ = out.push(LocalCluster {
                id: ClusterId(0x0402),
                client: false,
            });
        }
        fn bind(&mut self, e: BindingEntry) -> Result<(), NodeError> {
            if self.table_full {
                return Err(NodeError::TableFull);
            }
            self.binds.push(e);
            Ok(())
        }
        fn add_group(
            &mut self,
            a: ShortAddress,
            e: Endpoint,
            g: GroupAddress,
        ) -> Result<(), NodeError> {
            self.groups.push((a, e, g));
            Ok(())
        }
    }

    #[test]
    fn formation_falls_back_to_secondary_list() {
        let mut n = Fake::default();
        let mut b = Bdb::new(Config::DEFAULT_2_4GHZ, false);
        b.form_network(&mut n).unwrap();
        assert_eq!(n.forms, vec![ChannelMask::BDB_PRIMARY]);
        assert!(
            b.on_event(&mut n, &Event::FormationConfirm { success: false })
                .is_none()
        );
        assert_eq!(n.forms[1], ChannelMask::BDB_SECONDARY);
        assert_eq!(
            b.on_event(&mut n, &Event::FormationConfirm { success: false }),
            Some(Outcome::Formation(Err(Failure::ScanChannelsExhausted)))
        );
        assert!(!b.is_on_network());
        b.form_network(&mut n).unwrap();
        assert_eq!(
            b.on_event(&mut n, &Event::FormationConfirm { success: true }),
            Some(Outcome::Formation(Ok(())))
        );
        assert!(b.is_on_network());
        assert_eq!(b.form_network(&mut n), Err(Failure::AlreadyOnNetwork));
        n.role_ed = true;
        let mut b = Bdb::new(Config::DEFAULT_2_4GHZ, false);
        assert_eq!(b.form_network(&mut n), Err(Failure::NotPermittedToForm));
    }

    #[test]
    fn steering_retries_then_secondary_then_opens_network() {
        let mut n = Fake {
            centralized: true,
            ..Fake::default()
        };
        let mut b = Bdb::new(Config::DEFAULT_2_4GHZ, false);
        b.steer(&mut n).unwrap();
        for _ in 0..2 {
            assert!(
                b.on_event(&mut n, &Event::JoinConfirm { success: false })
                    .is_none()
            );
        }
        assert_eq!(n.joins.len(), 3);
        assert!(n.joins.iter().all(|j| j.1 == ChannelMask::BDB_PRIMARY));
        assert!(
            b.on_event(&mut n, &Event::JoinConfirm { success: false })
                .is_none()
        );
        assert_eq!(n.joins[3].1, ChannelMask::BDB_SECONDARY);
        // Joined; the TCLK exchange must complete.
        assert!(
            b.on_event(&mut n, &Event::JoinConfirm { success: true })
                .is_none()
        );
        assert_eq!(b.next_deadline(), Some(Instant::from_millis(10_000)));
        assert_eq!(
            b.on_event(&mut n, &Event::LinkKeyUpdated),
            Some(Outcome::Steering(Ok(())))
        );
        assert!(b.is_on_network());
        assert_eq!(n.broadcasts, vec![180]);
        assert_eq!(n.permits, vec![180]);
        assert_eq!(b.steer(&mut n), Err(Failure::AlreadyOnNetwork));
    }

    #[test]
    fn steering_leaves_after_failed_key_exchange() {
        let mut n = Fake {
            centralized: true,
            ..Fake::default()
        };
        let mut cfg = Config::DEFAULT_2_4GHZ;
        cfg.secondary_channels = ChannelMask::EMPTY;
        cfg.same_network_retries = 1;
        let mut b = Bdb::new(cfg, false);
        b.steer(&mut n).unwrap();
        assert!(
            b.on_event(&mut n, &Event::JoinConfirm { success: true })
                .is_none()
        );
        n.now = Instant::from_millis(10_001);
        assert!(
            {
                let t = n.now;
                b.poll(&mut n, t)
            }
            .is_none()
        );
        assert_eq!(n.left, 1);
        assert_eq!(
            b.on_event(&mut n, &Event::Left),
            Some(Outcome::Steering(Err(Failure::NoNetwork)))
        );
        assert!(!b.is_on_network());
    }

    #[test]
    fn rejoin_walks_the_channel_lists() {
        let mut n = Fake {
            centralized: true,
            verified: true,
            ..Fake::default()
        };
        let mut b = Bdb::new(Config::DEFAULT_2_4GHZ, true);
        b.rejoin(&mut n, false).unwrap();
        assert_eq!(n.joins[0], (JoinKind::SecuredRejoin, ChannelMask(1 << 15)));
        b.on_event(&mut n, &Event::JoinConfirm { success: false });
        assert_eq!(
            n.joins[1],
            (JoinKind::TrustCenterRejoin, ChannelMask(1 << 15))
        );
        b.on_event(&mut n, &Event::JoinConfirm { success: false });
        assert_eq!(
            n.joins[2],
            (JoinKind::SecuredRejoin, ChannelMask::BDB_PRIMARY)
        );
        b.on_event(&mut n, &Event::JoinConfirm { success: false });
        assert_eq!(
            n.joins[3],
            (JoinKind::SecuredRejoin, ChannelMask::BDB_SECONDARY)
        );
        assert_eq!(
            b.on_event(&mut n, &Event::JoinConfirm { success: false }),
            Some(Outcome::Rejoin(Err(Failure::RejoinUnsuccessful)))
        );
        // Lost Trust Center: start with the TC rejoin.
        b.rejoin(&mut n, true).unwrap();
        assert_eq!(n.joins[4].0, JoinKind::TrustCenterRejoin);
        assert_eq!(
            b.on_event(&mut n, &Event::JoinConfirm { success: true }),
            Some(Outcome::Rejoin(Ok(())))
        );
        // Distributed network: no TC rejoin stage.
        n.centralized = false;
        b.rejoin(&mut n, false).unwrap();
        b.on_event(&mut n, &Event::JoinConfirm { success: false });
        assert_eq!(
            n.joins.last().unwrap(),
            &(JoinKind::SecuredRejoin, ChannelMask::BDB_PRIMARY)
        );
    }

    #[test]
    fn finding_and_binding_initiator_binds_matching_clusters() {
        let ieee = ExtendedAddress(0x1122);
        let mut n = Fake::default();
        let mut b = Bdb::new(Config::DEFAULT_2_4GHZ, true);
        b.find_and_bind_initiator(&mut n, Endpoint(1), None, &[])
            .unwrap();
        assert_eq!(n.queries, 1);
        let rsp = Event::IdentifyQueryResponse {
            src: ShortAddress(0x2222),
            src_endpoint: Endpoint(3),
            endpoint: Endpoint(1),
        };
        assert!(b.on_event(&mut n, &rsp).is_none());
        assert!(b.on_event(&mut n, &rsp).is_none());
        n.now = Instant::from_millis(5_000);
        assert!(
            {
                let t = n.now;
                b.poll(&mut n, t)
            }
            .is_none()
        );
        assert_eq!(n.simple, vec![(ShortAddress(0x2222), Endpoint(3))]);
        let mut inputs = Vec::new();
        let _ = inputs.push(ClusterId(0x0006));
        let _ = inputs.push(ClusterId(0x0008));
        let mut outputs = Vec::new();
        let _ = outputs.push(ClusterId(0x0402));
        assert!(
            b.on_event(
                &mut n,
                &Event::SimpleDescriptor {
                    src: ShortAddress(0x2222),
                    endpoint: Endpoint(3),
                    success: true,
                    inputs,
                    outputs,
                }
            )
            .is_none()
        );
        // IEEE unknown: requested before binding.
        assert_eq!(n.ieee_reqs, vec![ShortAddress(0x2222)]);
        assert_eq!(
            b.on_event(
                &mut n,
                &Event::IeeeAddress {
                    short: ShortAddress(0x2222),
                    ieee: Some(ieee),
                }
            ),
            Some(Outcome::FindingBindingInitiator {
                endpoint: Endpoint(1),
                bindings: 2,
                result: Ok(()),
            })
        );
        assert_eq!(n.binds.len(), 2);
        assert!(n.binds.iter().all(|e| e.destination
            == BindingDestination::Unicast {
                address: ieee,
                endpoint: Endpoint(3)
            }));
        assert!(n.binds.iter().any(|e| e.cluster == ClusterId(0x0006)));
        assert!(n.binds.iter().any(|e| e.cluster == ClusterId(0x0402)));
    }

    #[test]
    fn finding_and_binding_group_and_failures() {
        let mut n = Fake {
            known: Some((ShortAddress(0x2222), ExtendedAddress(1))),
            ..Fake::default()
        };
        let mut b = Bdb::new(Config::DEFAULT_2_4GHZ, true);
        // No responses.
        b.find_and_bind_initiator(&mut n, Endpoint(1), None, &[])
            .unwrap();
        n.now = Instant::from_millis(5_000);
        assert_eq!(
            {
                let t = n.now;
                b.poll(&mut n, t)
            },
            Some(Outcome::FindingBindingInitiator {
                endpoint: Endpoint(1),
                bindings: 0,
                result: Err(Failure::NoIdentifyQueryResponse),
            })
        );
        // Group binding with a cluster filter.
        b.find_and_bind_initiator(
            &mut n,
            Endpoint(1),
            Some(GroupAddress(0x0010)),
            &[ClusterId(0x0006)],
        )
        .unwrap();
        b.on_event(
            &mut n,
            &Event::IdentifyQueryResponse {
                src: ShortAddress(0x2222),
                src_endpoint: Endpoint(3),
                endpoint: Endpoint(1),
            },
        );
        n.now = Instant::from_millis(10_000);
        {
            let t = n.now;
            b.poll(&mut n, t)
        };
        let mut inputs = Vec::new();
        let _ = inputs.push(ClusterId(0x0006));
        let mut outputs = Vec::new();
        let _ = outputs.push(ClusterId(0x0402));
        assert_eq!(
            b.on_event(
                &mut n,
                &Event::SimpleDescriptor {
                    src: ShortAddress(0x2222),
                    endpoint: Endpoint(3),
                    success: true,
                    inputs: inputs.clone(),
                    outputs: outputs.clone(),
                }
            ),
            Some(Outcome::FindingBindingInitiator {
                endpoint: Endpoint(1),
                bindings: 1,
                result: Ok(()),
            })
        );
        assert_eq!(n.binds.len(), 1);
        assert_eq!(
            n.binds[0].destination,
            BindingDestination::Group(GroupAddress(0x0010))
        );
        assert_eq!(
            n.groups,
            vec![(ShortAddress(0x2222), Endpoint(3), GroupAddress(0x0010))]
        );
        // Full table.
        n.table_full = true;
        b.find_and_bind_initiator(&mut n, Endpoint(1), None, &[])
            .unwrap();
        b.on_event(
            &mut n,
            &Event::IdentifyQueryResponse {
                src: ShortAddress(0x2222),
                src_endpoint: Endpoint(3),
                endpoint: Endpoint(1),
            },
        );
        n.now = Instant::from_millis(20_000);
        {
            let t = n.now;
            b.poll(&mut n, t)
        };
        assert_eq!(
            b.on_event(
                &mut n,
                &Event::SimpleDescriptor {
                    src: ShortAddress(0x2222),
                    endpoint: Endpoint(3),
                    success: true,
                    inputs,
                    outputs,
                }
            ),
            Some(Outcome::FindingBindingInitiator {
                endpoint: Endpoint(1),
                bindings: 0,
                result: Err(Failure::BindingTableFull),
            })
        );
        assert!(!b.is_busy());
    }

    #[test]
    fn target_reports_when_identification_stops() {
        let mut n = Fake::default();
        let mut b = Bdb::new(Config::DEFAULT_2_4GHZ, false);
        assert_eq!(
            b.find_and_bind_target(&mut n, Endpoint(1)),
            Err(Failure::NotOnNetwork)
        );
        b.set_on_network(true);
        b.find_and_bind_target(&mut n, Endpoint(1)).unwrap();
        assert!(
            b.on_event(
                &mut n,
                &Event::Identify {
                    endpoint: Endpoint(1),
                    seconds: 5
                }
            )
            .is_none()
        );
        assert_eq!(
            b.on_event(
                &mut n,
                &Event::Identify {
                    endpoint: Endpoint(1),
                    seconds: 0
                }
            ),
            Some(Outcome::FindingBindingTarget {
                endpoint: Endpoint(1)
            })
        );
    }
}
