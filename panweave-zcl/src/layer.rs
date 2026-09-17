//! Endpoint dispatch (ZCL8 §2.3.1, §2.3.2): routes APS data indications to
//! cluster instances, executes global commands, generates Default
//! Responses (§2.5.12.2), hands cluster-specific commands and responses
//! to the application, and drives attribute reporting to bound
//! destinations (§2.5.11).

use heapless::{Deque, Vec};
use panweave_aps::layer::{DataIndication, Delivery};
use panweave_aps::{Destination, TxOptions};
use panweave_codec::{Decode, Encode, Writer};
use panweave_types::time::Instant;
use panweave_types::{
    ClusterId, CommandId, Endpoint, ManufacturerCode, ProfileId, ShortAddress, TransactionSequence,
};

use crate::cluster::{ClusterDef, ClusterInstance, GlobalOutcome, Role};
use crate::clusters::groups::{self, GroupStore};
use crate::clusters::identify;
use crate::frame::{Direction, Frame, FrameType, Header, ZclStatus};
use crate::global::{DefaultResponse, command};

/// Largest ZCL frame built by the layer (unfragmented APS payload).
pub const MAX_ZCL: usize = 80;

/// Queue capacity.
pub const QUEUE_CAPACITY: usize = 8;

/// A ZCL frame buffer.
pub type ZclBuf = Vec<u8, MAX_ZCL>;

/// An application endpoint with its cluster instances.
#[derive(Debug)]
pub struct EndpointInstance<const C: usize, const A: usize> {
    /// Endpoint number.
    pub endpoint: Endpoint,
    /// Profile.
    pub profile: ProfileId,
    /// Clusters.
    pub clusters: Vec<ClusterInstance<A>, C>,
}

impl<const C: usize, const A: usize> EndpointInstance<C, A> {
    /// Creates an empty endpoint.
    pub const fn new(endpoint: Endpoint, profile: ProfileId) -> Self {
        EndpointInstance {
            endpoint,
            profile,
            clusters: Vec::new(),
        }
    }

    /// Adds a cluster instance; fails when the (id, role) pair exists or
    /// the endpoint is full.
    pub fn add_cluster(
        &mut self,
        def: ClusterDef,
        role: Role,
    ) -> Result<&mut ClusterInstance<A>, ZclError> {
        if self.cluster_mut(def.id, role).is_some() {
            return Err(ZclError::NotFound);
        }
        self.clusters
            .push(ClusterInstance::new(def, role))
            .map_err(|_| ZclError::Busy)?;
        self.clusters.last_mut().ok_or(ZclError::Busy)
    }

    /// Adds a pre-built cluster instance.
    pub fn add_instance(&mut self, c: ClusterInstance<A>) -> Result<(), ClusterInstance<A>> {
        if self.cluster(c.def.id, c.role).is_some() {
            return Err(c);
        }
        self.clusters.push(c)
    }

    /// Finds a cluster instance.
    pub fn cluster(&self, id: ClusterId, role: Role) -> Option<&ClusterInstance<A>> {
        self.clusters
            .iter()
            .find(|c| c.def.id == id && c.role == role)
    }

    /// Finds a cluster instance mutably.
    pub fn cluster_mut(&mut self, id: ClusterId, role: Role) -> Option<&mut ClusterInstance<A>> {
        self.clusters
            .iter_mut()
            .find(|c| c.def.id == id && c.role == role)
    }
}

/// Outputs for the runtime.
#[derive(Debug)]
pub enum ZclAction {
    /// APSDE-DATA.request carrying a ZCL frame.
    Send {
        /// Destination.
        destination: Destination,
        /// Profile.
        profile: ProfileId,
        /// Cluster.
        cluster: ClusterId,
        /// Source endpoint.
        src_endpoint: Endpoint,
        /// The ZCL frame.
        frame: ZclBuf,
        /// Transmit options.
        options: TxOptions,
    },
}

/// Layer-generated notifications for the application.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ZclEvent {
    /// `IdentifyTime` of the Identify server on `endpoint` changed
    /// (command received or countdown elapsed); `seconds` is the new
    /// value, 0 when identification stops (§3.5.2.2.1).
    Identify {
        /// Endpoint.
        endpoint: Endpoint,
        /// Remaining seconds.
        seconds: u16,
    },
    /// Trigger Effect received by the Identify server on `endpoint`
    /// (§3.5.2.3.3).
    TriggerEffect {
        /// Endpoint.
        endpoint: Endpoint,
        /// Effect identifier.
        effect: u8,
        /// Effect variant.
        variant: u8,
    },
}

/// Where a received command came from (for replies).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Origin {
    /// Sender network address.
    pub src: ShortAddress,
    /// Sender endpoint.
    pub src_endpoint: Endpoint,
    /// Local endpoint the command was delivered to.
    pub endpoint: Endpoint,
    /// Profile of the frame.
    pub profile: ProfileId,
    /// Cluster.
    pub cluster: ClusterId,
    /// Header of the received frame.
    pub header: Header,
    /// Delivered by broadcast or group (no Default Responses).
    pub broadcast: bool,
}

/// A received ZCL frame for the application.
#[derive(Clone, Copy, Debug)]
pub enum ZclIndication<'a> {
    /// A cluster-specific command for a cluster instance on the given
    /// endpoint. The application must respond (or call
    /// [`Zcl::default_response`]) when `origin.header.control.disable_default_response`
    /// is clear.
    Command {
        /// Origin.
        origin: Origin,
        /// Command payload.
        payload: &'a [u8],
    },
    /// A global response (Read Attributes Response, Write Attributes
    /// Response, Configure Reporting Response, Default Response, …) to a
    /// request this device sent.
    Response {
        /// Origin.
        origin: Origin,
        /// Payload (decode with [`crate::global`] records).
        payload: &'a [u8],
    },
    /// Report Attributes received by a client-side cluster instance.
    Report {
        /// Origin.
        origin: Origin,
        /// Attribute report records (decode with
        /// [`crate::global::Records`] of [`crate::global::AttributeValue`]).
        payload: &'a [u8],
    },
}

/// Errors from send helpers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ZclError {
    /// The frame does not fit.
    TooLarge,
    /// The queue is full.
    Busy,
    /// Unknown endpoint or cluster.
    NotFound,
}

/// The ZCL dispatcher.
pub struct Zcl<const E: usize, const C: usize, const A: usize> {
    endpoints: Vec<EndpointInstance<C, A>, E>,
    seq: TransactionSequence,
    actions: Deque<ZclAction, QUEUE_CAPACITY>,
    events: Deque<ZclEvent, QUEUE_CAPACITY>,
    now: Instant,
    /// Actions or events dropped on overflow.
    pub dropped: u32,
}

impl<const E: usize, const C: usize, const A: usize> Default for Zcl<E, C, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const E: usize, const C: usize, const A: usize> Zcl<E, C, A> {
    /// Empty dispatcher.
    pub const fn new() -> Self {
        Zcl {
            endpoints: Vec::new(),
            seq: TransactionSequence(0),
            actions: Deque::new(),
            events: Deque::new(),
            now: Instant::from_millis(0),
            dropped: 0,
        }
    }

    /// Registers an endpoint.
    pub fn add_endpoint(
        &mut self,
        ep: EndpointInstance<C, A>,
    ) -> Result<(), EndpointInstance<C, A>> {
        if self.endpoints.iter().any(|e| e.endpoint == ep.endpoint) {
            return Err(ep);
        }
        self.endpoints.push(ep)
    }

    /// The endpoint instance.
    pub fn endpoint(&self, endpoint: Endpoint) -> Option<&EndpointInstance<C, A>> {
        self.endpoints.iter().find(|e| e.endpoint == endpoint)
    }

    /// The endpoint instance, mutably.
    pub fn endpoint_mut(&mut self, endpoint: Endpoint) -> Option<&mut EndpointInstance<C, A>> {
        self.endpoints.iter_mut().find(|e| e.endpoint == endpoint)
    }

    /// A cluster instance on an endpoint.
    pub fn cluster(
        &self,
        endpoint: Endpoint,
        id: ClusterId,
        role: Role,
    ) -> Option<&ClusterInstance<A>> {
        self.endpoint(endpoint)?.cluster(id, role)
    }

    /// A cluster instance on an endpoint, mutably.
    pub fn cluster_mut(
        &mut self,
        endpoint: Endpoint,
        id: ClusterId,
        role: Role,
    ) -> Option<&mut ClusterInstance<A>> {
        self.endpoint_mut(endpoint)?.cluster_mut(id, role)
    }

    /// Registered endpoints.
    pub fn endpoints(&self) -> &[EndpointInstance<C, A>] {
        &self.endpoints
    }

    /// Next action.
    pub fn next_action(&mut self) -> Option<ZclAction> {
        self.actions.pop_front()
    }

    fn push_action(&mut self, a: ZclAction) {
        if self.actions.push_back(a).is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// Next layer event.
    pub fn next_event(&mut self) -> Option<ZclEvent> {
        self.events.pop_front()
    }

    fn push_event(&mut self, e: ZclEvent) {
        if self.events.push_back(e).is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// Allocates a transaction sequence number.
    pub fn next_seq(&mut self) -> TransactionSequence {
        let s = self.seq;
        self.seq = s.wrapping_next();
        s
    }

    /// Current time.
    pub const fn now(&self) -> Instant {
        self.now
    }

    fn build(header: &Header, payload: &[u8]) -> Result<ZclBuf, ZclError> {
        let mut buf = ZclBuf::new();
        buf.resize(MAX_ZCL, 0).map_err(|_| ZclError::TooLarge)?;
        let n = Frame {
            header: *header,
            payload,
        }
        .encode_to_slice(buf.as_mut_slice())
        .map_err(|_| ZclError::TooLarge)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Sends a ZCL frame from `src_endpoint` to `destination`.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        destination: Destination,
        profile: ProfileId,
        cluster: ClusterId,
        src_endpoint: Endpoint,
        header: &Header,
        payload: &[u8],
        options: TxOptions,
    ) -> Result<(), ZclError> {
        let frame = Self::build(header, payload)?;
        self.push_action(ZclAction::Send {
            destination,
            profile,
            cluster,
            src_endpoint,
            frame,
            options,
        });
        Ok(())
    }

    /// Sends a global command (client side) with a fresh sequence number
    /// and returns it.
    #[allow(clippy::too_many_arguments)]
    pub fn send_global(
        &mut self,
        destination: Destination,
        profile: ProfileId,
        cluster: ClusterId,
        src_endpoint: Endpoint,
        command: CommandId,
        direction: Direction,
        manufacturer: Option<ManufacturerCode>,
        payload: &[u8],
    ) -> Result<TransactionSequence, ZclError> {
        let seq = self.next_seq();
        let mut header = Header::global(seq, command, direction);
        if let Some(m) = manufacturer {
            header = header.with_manufacturer(m);
        }
        let ack = matches!(destination, Destination::Short { address, .. } if address.is_unicast())
            || matches!(destination, Destination::Extended { .. });
        let options = TxOptions {
            ack,
            ..TxOptions::ACKED
        };
        self.send(
            destination,
            profile,
            cluster,
            src_endpoint,
            &header,
            payload,
            options,
        )?;
        Ok(seq)
    }

    /// Sends a cluster-specific command with a fresh sequence number.
    #[allow(clippy::too_many_arguments)]
    pub fn send_command(
        &mut self,
        destination: Destination,
        profile: ProfileId,
        cluster: ClusterId,
        src_endpoint: Endpoint,
        command: CommandId,
        direction: Direction,
        manufacturer: Option<ManufacturerCode>,
        payload: &[u8],
    ) -> Result<TransactionSequence, ZclError> {
        let seq = self.next_seq();
        let mut header = Header::cluster_specific(seq, command, direction);
        if let Some(m) = manufacturer {
            header = header.with_manufacturer(m);
        }
        let ack = matches!(destination, Destination::Short { address, .. } if address.is_unicast())
            || matches!(destination, Destination::Extended { .. });
        let options = TxOptions {
            ack,
            ..TxOptions::ACKED
        };
        self.send(
            destination,
            profile,
            cluster,
            src_endpoint,
            &header,
            payload,
            options,
        )?;
        Ok(seq)
    }

    /// Replies to `origin` with a cluster-specific or global response
    /// command carrying the same transaction sequence.
    pub fn respond(
        &mut self,
        origin: &Origin,
        command: CommandId,
        frame_type: FrameType,
        payload: &[u8],
    ) -> Result<(), ZclError> {
        let header = origin.header.response(command, frame_type);
        self.send(
            Destination::Short {
                address: origin.src,
                endpoint: origin.src_endpoint,
            },
            origin.profile,
            origin.cluster,
            origin.endpoint,
            &header,
            payload,
            TxOptions::ACKED,
        )
    }

    /// Sends a Default Response for `origin` when the rules of §2.5.12.2
    /// call for one: unicast, not itself a Default Response, and either
    /// an error or Disable Default Response clear.
    pub fn default_response(&mut self, origin: &Origin, status: ZclStatus) -> Result<(), ZclError> {
        if origin.broadcast
            || (origin.header.control.frame_type == FrameType::Global
                && origin.header.command == command::DEFAULT_RESPONSE)
        {
            return Ok(());
        }
        if status.is_success() && origin.header.control.disable_default_response {
            return Ok(());
        }
        let mut payload = [0u8; 2];
        DefaultResponse {
            command: origin.header.command,
            status,
        }
        .encode_to_slice(&mut payload)
        .map_err(|_| ZclError::TooLarge)?;
        self.respond(
            origin,
            command::DEFAULT_RESPONSE,
            FrameType::Global,
            &payload,
        )
    }

    /// Processes an APSDE-DATA.indication for an application endpoint.
    /// `groups` is the node's group table: it decides which endpoints a
    /// group delivery targets and executes Groups cluster commands.
    pub fn on_data<'a>(
        &mut self,
        ind: &DataIndication<'a>,
        groups: &mut impl GroupStore,
    ) -> Option<ZclIndication<'a>> {
        let frame = Frame::decode_exact(ind.asdu).ok()?;
        let broadcast = ind.nwk_broadcast || !matches!(ind.delivery, Delivery::Endpoint(_));
        let mut result: Option<ZclIndication<'a>> = None;
        for i in 0..self.endpoints.len() {
            let ep = self.endpoints.get(i)?.endpoint;
            let target = match ind.delivery {
                Delivery::Endpoint(e) => e == ep,
                Delivery::AllEndpoints => true,
                Delivery::Group(g) => groups.contains(g, ep),
            };
            if !target {
                continue;
            }
            let profile = self.endpoints.get(i)?.profile;
            if ind.profile != profile && ind.profile != ProfileId::WILDCARD {
                continue;
            }
            let origin = Origin {
                src: ind.src,
                src_endpoint: ind.src_endpoint,
                endpoint: ep,
                profile: ind.profile,
                cluster: ind.cluster,
                header: frame.header,
                broadcast,
            };
            let role = match frame.header.control.direction {
                Direction::ToServer => Role::Server,
                Direction::ToClient => Role::Client,
            };
            let has_cluster = self
                .endpoints
                .get(i)
                .is_some_and(|e| e.cluster(ind.cluster, role).is_some());
            if !has_cluster {
                // Responses may still target a client instance that only
                // sent the request; hand them up regardless.
                if frame.header.control.frame_type == FrameType::Global
                    && is_global_response(frame.header.command)
                {
                    result.get_or_insert(ZclIndication::Response {
                        origin,
                        payload: frame.payload,
                    });
                    continue;
                }
                let _ = self.default_response(&origin, ZclStatus::UnsupportedCluster);
                continue;
            }
            match frame.header.control.frame_type {
                FrameType::Global => {
                    if frame.header.command == command::REPORT_ATTRIBUTES {
                        result.get_or_insert(ZclIndication::Report {
                            origin,
                            payload: frame.payload,
                        });
                        continue;
                    }
                    if is_global_response(frame.header.command) {
                        result.get_or_insert(ZclIndication::Response {
                            origin,
                            payload: frame.payload,
                        });
                        continue;
                    }
                    let mut out = [0u8; MAX_ZCL];
                    let mut w = Writer::new(&mut out);
                    // Leave room for the response header.
                    let hdr_len = frame.header.encoded_len();
                    let _ = w.reserve(hdr_len);
                    let now = self.now;
                    let outcome = self
                        .endpoints
                        .get_mut(i)
                        .and_then(|e| e.cluster_mut(ind.cluster, role))
                        .map(|c| c.handle_global(&frame.header, frame.payload, &mut w, now));
                    let n = w.position();
                    match outcome {
                        Some(GlobalOutcome::Response(cmd)) => {
                            let header = frame.header.response(cmd, FrameType::Global);
                            if let Some(payload) = out.get(hdr_len..n)
                                && let Ok(fr) = Self::build(&header, payload)
                                && (!broadcast || cmd != command::DEFAULT_RESPONSE)
                            {
                                self.push_action(ZclAction::Send {
                                    destination: Destination::Short {
                                        address: ind.src,
                                        endpoint: ind.src_endpoint,
                                    },
                                    profile: ind.profile,
                                    cluster: ind.cluster,
                                    src_endpoint: ep,
                                    frame: fr,
                                    options: TxOptions::ACKED,
                                });
                            }
                        }
                        Some(GlobalOutcome::None) => {
                            let _ = self.default_response(&origin, ZclStatus::Success);
                        }
                        Some(GlobalOutcome::Default(status)) => {
                            let _ = self.default_response(&origin, status);
                        }
                        None => {}
                    }
                }
                FrameType::ClusterSpecific => {
                    if ind.cluster == identify::ID && role == Role::Server {
                        self.handle_identify(i, &origin, frame.header.command, frame.payload);
                        continue;
                    }
                    if ind.cluster == groups::ID && role == Role::Server {
                        self.handle_groups(i, &origin, frame.header.command, frame.payload, groups);
                        continue;
                    }
                    result.get_or_insert(ZclIndication::Command {
                        origin,
                        payload: frame.payload,
                    });
                }
                FrameType::Reserved(_) => {
                    let _ = self.default_response(&origin, ZclStatus::MalformedCommand);
                }
            }
        }
        result
    }

    /// Identify server commands are executed by the layer (§3.5.2.3):
    /// the application observes them through [`ZclEvent`].
    fn handle_identify(
        &mut self,
        ep_index: usize,
        origin: &Origin,
        cmd: CommandId,
        payload: &[u8],
    ) {
        let now = self.now;
        let Some(c) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(identify::ID, Role::Server))
        else {
            return;
        };
        let endpoint = origin.endpoint;
        match identify::handle(c, cmd, payload, now) {
            identify::Outcome::QueryResponse(t) => {
                let header = origin.header.response(
                    identify::CMD_IDENTIFY_QUERY_RESPONSE,
                    FrameType::ClusterSpecific,
                );
                if let Ok(fr) = Self::build(&header, &t.to_le_bytes()) {
                    self.push_action(ZclAction::Send {
                        destination: Destination::Short {
                            address: origin.src,
                            endpoint: origin.src_endpoint,
                        },
                        profile: origin.profile,
                        cluster: identify::ID,
                        src_endpoint: endpoint,
                        frame: fr,
                        options: TxOptions::ACKED,
                    });
                }
            }
            identify::Outcome::Set(seconds) => {
                self.push_event(ZclEvent::Identify { endpoint, seconds });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            identify::Outcome::Effect(effect, variant) => {
                self.push_event(ZclEvent::TriggerEffect {
                    endpoint,
                    effect,
                    variant,
                });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            identify::Outcome::Silent => {}
            identify::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
        }
    }

    /// Groups server commands are executed by the layer against the
    /// node's group table (§3.6.2.3).
    fn handle_groups(
        &mut self,
        ep_index: usize,
        origin: &Origin,
        cmd: CommandId,
        payload: &[u8],
        store: &mut impl GroupStore,
    ) {
        let endpoint = origin.endpoint;
        let identifying = self
            .endpoints
            .get(ep_index)
            .and_then(|e| e.cluster(identify::ID, Role::Server))
            .is_some_and(|c| identify::identify_time(c) > 0);
        let mut out = [0u8; MAX_ZCL];
        let mut w = Writer::new(&mut out);
        let outcome = groups::handle(
            store,
            endpoint,
            cmd,
            payload,
            !origin.broadcast,
            identifying,
            &mut w,
        );
        let n = w.position();
        match outcome {
            groups::Outcome::Response(rsp) => {
                let header = origin.header.response(rsp, FrameType::ClusterSpecific);
                if let Some(payload) = out.get(..n)
                    && let Ok(fr) = Self::build(&header, payload)
                {
                    self.push_action(ZclAction::Send {
                        destination: Destination::Short {
                            address: origin.src,
                            endpoint: origin.src_endpoint,
                        },
                        profile: origin.profile,
                        cluster: groups::ID,
                        src_endpoint: endpoint,
                        frame: fr,
                        options: TxOptions::ACKED,
                    });
                }
            }
            groups::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
            groups::Outcome::None => {}
        }
    }

    /// Starts (or stops, with 0) identification on an endpoint's Identify
    /// server; used by finding & binding targets (BDB 3.1 §11.1).
    pub fn set_identify_time(&mut self, endpoint: Endpoint, seconds: u16) -> Result<(), ZclError> {
        let now = self.now;
        let c = self
            .cluster_mut(endpoint, identify::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        identify::set_identify_time(c, seconds, now);
        self.push_event(ZclEvent::Identify { endpoint, seconds });
        Ok(())
    }

    /// Advances time and emits Report Attributes frames for due
    /// attributes towards bound destinations (§2.5.11, Table 2-4).
    pub fn poll_timers(&mut self, now: Instant) {
        self.now = now;
        // Identify countdowns (§3.5.2.2.1).
        for i in 0..self.endpoints.len() {
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            let endpoint = ep.endpoint;
            if let Some(c) = ep.cluster_mut(identify::ID, Role::Server)
                && let Some(seconds) = identify::tick(c, now)
            {
                self.push_event(ZclEvent::Identify { endpoint, seconds });
            }
        }
        let n_eps = self.endpoints.len();
        for i in 0..n_eps {
            let n_clusters = self.endpoints.get(i).map_or(0, |e| e.clusters.len());
            for j in 0..n_clusters {
                let mut out = [0u8; MAX_ZCL];
                let mut w = Writer::new(&mut out);
                let _ = w.reserve(3);
                let Some(ep) = self.endpoints.get_mut(i) else {
                    break;
                };
                let (endpoint, profile) = (ep.endpoint, ep.profile);
                let Some(c) = ep.clusters.get_mut(j) else {
                    break;
                };
                if c.role != Role::Server {
                    continue;
                }
                let cluster = c.def.id;
                if c.collect_reports(now, &mut w) == 0 {
                    continue;
                }
                let n = w.position();
                let seq = self.next_seq();
                let header = Header::global(seq, command::REPORT_ATTRIBUTES, Direction::ToClient)
                    .disable_default_response(true);
                if let Some(payload) = out.get(3..n)
                    && let Ok(frame) = Self::build(&header, payload)
                {
                    self.push_action(ZclAction::Send {
                        destination: Destination::Bound,
                        profile,
                        cluster,
                        src_endpoint: endpoint,
                        frame,
                        options: TxOptions::ACKED,
                    });
                }
            }
        }
    }

    /// Earliest scheduled report or cluster tick.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.endpoints
            .iter()
            .flat_map(|e| e.clusters.iter())
            .flat_map(|c| [c.next_report(), c.tick])
            .flatten()
            .min_by_key(|t| t.as_millis())
    }
}

/// Global commands that are responses (delivered to the application).
const fn is_global_response(c: CommandId) -> bool {
    matches!(
        c,
        command::READ_ATTRIBUTES_RESPONSE
            | command::WRITE_ATTRIBUTES_RESPONSE
            | command::CONFIGURE_REPORTING_RESPONSE
            | command::READ_REPORTING_CONFIGURATION_RESPONSE
            | command::DEFAULT_RESPONSE
            | command::DISCOVER_ATTRIBUTES_RESPONSE
            | command::WRITE_ATTRIBUTES_STRUCTURED_RESPONSE
            | command::DISCOVER_COMMANDS_RECEIVED_RESPONSE
            | command::DISCOVER_COMMANDS_GENERATED_RESPONSE
            | command::DISCOVER_ATTRIBUTES_EXTENDED_RESPONSE
    )
}
