//! Endpoint dispatch (ZCL8 §2.3.1, §2.3.2): routes APS data indications to
//! cluster instances, executes global commands, generates Default
//! Responses (§2.5.12.2), hands cluster-specific commands and responses
//! to the application, and drives attribute reporting to bound
//! destinations (§2.5.11).

use heapless::{Deque, Vec};
use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::{Destination, TxOptions};
use panweave_codec::{Decode, Encode, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, CommandId, Endpoint, GroupAddress, ManufacturerCode, ProfileId, ShortAddress,
    TransactionSequence,
};

use crate::cluster::{ClusterDef, ClusterInstance, GlobalOutcome, Role};
use crate::clusters::groups::{self, GroupStore};
use crate::clusters::{
    alarms, basic, color_control, commissioning, door_lock, hvac, ias_ace, ias_wd, ias_zone,
    identify, level, on_off, poll_control, scenes, time, window_covering,
};
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
    /// Scene table of the endpoint's Scenes server (§3.7.2.3).
    pub scenes: scenes::SceneTable,
}

impl<const C: usize, const A: usize> EndpointInstance<C, A> {
    /// Creates an empty endpoint.
    pub const fn new(endpoint: Endpoint, profile: ProfileId) -> Self {
        EndpointInstance {
            endpoint,
            profile,
            clusters: Vec::new(),
            scenes: scenes::SceneTable::new(),
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

    /// Adds a pre-built cluster instance; the instance is handed back when
    /// the endpoint already has that cluster / role or is full.
    #[allow(clippy::result_large_err)]
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
    /// `OnOff` of the On/Off server on `endpoint` changed (§3.8.2.3).
    OnOff {
        /// Endpoint.
        endpoint: Endpoint,
        /// New state.
        on: bool,
    },
    /// Off With Effect received (§3.8.2.3.4): the device is off; the
    /// effect is the application's to render.
    OffWithEffect {
        /// Endpoint.
        endpoint: Endpoint,
        /// Effect identifier.
        effect: u8,
        /// Effect variant.
        variant: u8,
    },
    /// `CurrentLevel` of the Level Control server changed (§3.10).
    Level {
        /// Endpoint.
        endpoint: Endpoint,
        /// New level.
        level: u8,
        /// The transition completed.
        done: bool,
    },
    /// A scene was recalled on `endpoint` (§3.7.2.4.7).
    SceneRecalled {
        /// Endpoint.
        endpoint: Endpoint,
        /// Group.
        group: u16,
        /// Scene.
        scene: u8,
    },
    /// Poll Control server on `endpoint`: fast poll mode starts or ends
    /// (§3.16.4.1.4); poll at `ShortPollInterval` while `fast`.
    FastPoll {
        /// Endpoint.
        endpoint: Endpoint,
        /// Fast poll mode active.
        fast: bool,
        /// Interval to poll at (short or long).
        interval: Duration,
    },
    /// Poll Control server on `endpoint`: `LongPollInterval` changed.
    LongPollInterval {
        /// Endpoint.
        endpoint: Endpoint,
        /// New interval.
        interval: Duration,
    },
    /// Poll Control client on `endpoint` received a Check-in from `src`
    /// and answered it with its policy (§3.16.5.3).
    CheckIn {
        /// Endpoint.
        endpoint: Endpoint,
        /// The server's address.
        src: ShortAddress,
        /// The server's endpoint.
        src_endpoint: Endpoint,
    },
    /// Reset to Factory Defaults received (§3.2.2.3.1): every attribute
    /// of every cluster was restored.
    FactoryReset,
    /// An Alarms server on `endpoint` received Reset Alarm (`Some`) or
    /// Reset All Alarms (`None`): the application clears the condition
    /// and raises the alarm again if it persists (§3.11.2.4.1).
    AlarmReset {
        /// Endpoint.
        endpoint: Endpoint,
        /// The alarm code and cluster, or `None` for all alarms.
        alarm: Option<(u8, ClusterId)>,
    },
    /// The Time server on `endpoint` was set over the network
    /// (§3.12.2.2.1): the application synchronizes its clock to `utc`.
    TimeSet {
        /// Endpoint.
        endpoint: Endpoint,
        /// UTC seconds since 2000-01-01.
        utc: u32,
    },
    /// The IAS Zone server on `endpoint` was enrolled by its CIE with
    /// `zone_id` (§8.2.2.2.1).
    ZoneEnrolled {
        /// Endpoint.
        endpoint: Endpoint,
        /// Zone identifier.
        zone_id: u8,
    },
    /// The IAS Zone server on `endpoint` entered test mode for
    /// `Some(seconds)` or resumed normal operation (`None`) (§8.2.2.2.2).
    ZoneTestMode {
        /// Endpoint.
        endpoint: Endpoint,
        /// Test duration, `None` for normal operation.
        seconds: Option<u8>,
    },
    /// The Window Covering server on `endpoint` accepted a motion
    /// command or recalled a scene (§7.4.2.2, §7.4.2.4): the application
    /// drives the motor and reports positions back.
    WindowCovering {
        /// Endpoint.
        endpoint: Endpoint,
        /// What to do.
        command: window_covering::Command,
    },
    /// The Commissioning server on `endpoint` accepted a Restart Device
    /// (§13.2.2.3.1): after `delay` seconds plus RAND(`jitter` × 80) ms
    /// the runtime leaves the network and, when `install`, applies the
    /// startup set read with `commissioning::load`.
    Restart {
        /// Endpoint.
        endpoint: Endpoint,
        /// Install the startup set (else restart with the stack state).
        install: bool,
        /// Restart right after the delay rather than at a convenient moment.
        immediate: bool,
        /// Delay in seconds.
        delay: u8,
        /// Jitter field.
        jitter: u8,
    },
    /// The IAS ACE server on `endpoint` received a request for the
    /// application (§8.3.2.3): Arm (code validated, panel status set)
    /// or an Emergency / Fire / Panic.
    Ace {
        /// Endpoint.
        endpoint: Endpoint,
        /// The request.
        request: ias_ace::Request,
    },
    /// The IAS WD server on `endpoint` starts `Some(warning)` or stops
    /// (`None`: Stop received or the duration elapsed) (§8.4.2.2.1).
    Warning {
        /// Endpoint.
        endpoint: Endpoint,
        /// The warning, `None` to stop.
        warning: Option<ias_wd::Warning>,
    },
    /// The IAS WD server on `endpoint` squawks (§8.4.2.2.2).
    Squawk {
        /// Endpoint.
        endpoint: Endpoint,
        /// The squawk.
        squawk: ias_wd::Squawk,
    },
    /// The Door Lock server on `endpoint` accepted an RF operation, a
    /// scene recall or an automatic relock fired (§7.3.2.15): the
    /// application moves the bolt and reports back with
    /// [`Zcl::set_lock_state`]; `user` is the PIN user or
    /// [`door_lock::NO_USER`].
    DoorLock {
        /// Endpoint.
        endpoint: Endpoint,
        /// Lock or unlock.
        action: door_lock::Action,
        /// User identifier.
        user: u16,
    },
    /// A Setpoint Raise/Lower adjusted the thermostat on `endpoint`
    /// (§6.3.2.3.1): the new occupied setpoints in 0.01 °C.
    Setpoints {
        /// Endpoint.
        endpoint: Endpoint,
        /// Heating setpoint, when implemented.
        heat: Option<i16>,
        /// Cooling setpoint, when implemented.
        cool: Option<i16>,
    },
    /// The Color Control engine on `endpoint` moved: `mode` is the
    /// `EnhancedColorMode`, `a` / `b` the pair it names (enhanced hue and
    /// saturation, X and Y, or colour temperature mireds and 0);
    /// `done` when every transition finished (§5.2.2.3).
    Color {
        /// Endpoint.
        endpoint: Endpoint,
        /// `EnhancedColorMode`.
        mode: u8,
        /// First value of the mode.
        a: u16,
        /// Second value of the mode.
        b: u16,
        /// Transitions complete.
        done: bool,
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
    /// Protected with APS link-key security: replies are protected the
    /// same way.
    pub aps_secured: bool,
}

impl Origin {
    /// Transmit options for a reply: acknowledged, APS-secured when the
    /// request was.
    pub const fn reply_options(&self) -> TxOptions {
        TxOptions {
            security: self.aps_secured,
            ..TxOptions::ACKED
        }
    }
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
    /// Clusters whose frames must arrive APS link-key secured; an
    /// unsecured frame for one of them is refused with a Default
    /// Response FAILURE under the network key (SE 1.4a §5.4.6). `None`
    /// accepts everything.
    link_key_policy: Option<LinkKeyPolicy>,
}

/// A predicate naming the clusters that require APS link-key security
/// on a profile (`(profile, cluster) -> required`).
pub type LinkKeyPolicy = fn(ProfileId, ClusterId) -> bool;

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
            link_key_policy: None,
        }
    }

    /// Installs the link-key policy: frames of clusters the predicate
    /// names that arrive without APS link-key security are answered
    /// with a Default Response FAILURE and not processed (SE 1.4a
    /// §5.4.6). Frames secured beyond what is required are accepted and
    /// their responses use the same security.
    pub fn set_link_key_policy(&mut self, policy: Option<LinkKeyPolicy>) {
        self.link_key_policy = policy;
    }

    /// Registers an endpoint.
    #[allow(clippy::result_large_err)]
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
            origin.reply_options(),
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
                aps_secured: ind.security == SecurityStatus::LinkKey,
            };
            // A Default Response is exempt: it is how a peer reports the
            // refusal itself, under the network key.
            let is_default_response = frame.header.control.frame_type == FrameType::Global
                && frame.header.command == command::DEFAULT_RESPONSE;
            if let Some(policy) = self.link_key_policy
                && !origin.aps_secured
                && !is_default_response
                && policy(profile, ind.cluster)
            {
                let _ = self.default_response(&origin, ZclStatus::Failure);
                continue;
            }
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
                    if role == Role::Server
                        && ind.cluster == ias_zone::ID
                        && matches!(
                            frame.header.command,
                            command::WRITE_ATTRIBUTES
                                | command::WRITE_ATTRIBUTES_UNDIVIDED
                                | command::WRITE_ATTRIBUTES_NO_RESPONSE
                        )
                        && let Some(c) = self
                            .endpoints
                            .get_mut(i)
                            .and_then(|e| e.cluster_mut(ias_zone::ID, Role::Server))
                    {
                        ias_zone::after_write(c, ind.src, ind.src_endpoint, now);
                    }
                    if role == Role::Server
                        && ind.cluster == window_covering::ID
                        && matches!(
                            frame.header.command,
                            command::WRITE_ATTRIBUTES
                                | command::WRITE_ATTRIBUTES_UNDIVIDED
                                | command::WRITE_ATTRIBUTES_NO_RESPONSE
                        )
                        && let Some(c) = self
                            .endpoints
                            .get_mut(i)
                            .and_then(|e| e.cluster_mut(window_covering::ID, Role::Server))
                    {
                        window_covering::after_write(c);
                    }
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
                                    options: origin.reply_options(),
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
                    let cmd = frame.header.command;
                    let payload = frame.payload;
                    if role == Role::Server {
                        match ind.cluster {
                            identify::ID => {
                                self.handle_identify(i, &origin, cmd, payload);
                                continue;
                            }
                            groups::ID => {
                                self.handle_groups(i, &origin, cmd, payload, groups);
                                continue;
                            }
                            on_off::ID => {
                                self.handle_on_off(i, &origin, cmd, payload);
                                continue;
                            }
                            level::ID => {
                                self.handle_level(i, &origin, cmd, payload);
                                continue;
                            }
                            scenes::ID => {
                                self.handle_scenes(i, &origin, cmd, payload, groups);
                                continue;
                            }
                            poll_control::ID => {
                                self.handle_poll_control(i, &origin, cmd, payload);
                                continue;
                            }
                            basic::ID if cmd == basic::CMD_RESET_TO_FACTORY_DEFAULTS => {
                                self.factory_reset();
                                let _ = self.default_response(&origin, ZclStatus::Success);
                                continue;
                            }
                            alarms::ID => {
                                self.handle_alarms(i, &origin, cmd, payload);
                                continue;
                            }
                            ias_zone::ID => {
                                self.handle_ias_zone(i, &origin, cmd, payload);
                                continue;
                            }
                            door_lock::ID => {
                                self.handle_door_lock(i, &origin, cmd, payload);
                                continue;
                            }
                            ias_ace::ID => {
                                self.handle_ias_ace(i, &origin, cmd, payload);
                                continue;
                            }
                            commissioning::ID => {
                                let Some(c) = self
                                    .endpoints
                                    .get_mut(i)
                                    .and_then(|e| e.cluster_mut(commissioning::ID, Role::Server))
                                else {
                                    continue;
                                };
                                let endpoint = origin.endpoint;
                                match commissioning::handle(c, cmd, payload) {
                                    commissioning::Outcome::Reply { response, restart } => {
                                        self.reply_cluster_specific(
                                            &origin,
                                            response.command,
                                            &[response.status.raw()],
                                        );
                                        if let Some(r) = restart {
                                            self.push_event(ZclEvent::Restart {
                                                endpoint,
                                                install: r.install,
                                                immediate: r.immediate,
                                                delay: r.delay,
                                                jitter: r.jitter,
                                            });
                                        }
                                    }
                                    commissioning::Outcome::Default(status) => {
                                        let _ = self.default_response(&origin, status);
                                    }
                                }
                                continue;
                            }
                            ias_wd::ID => {
                                let Some(c) = self
                                    .endpoints
                                    .get_mut(i)
                                    .and_then(|e| e.cluster_mut(ias_wd::ID, Role::Server))
                                else {
                                    continue;
                                };
                                let endpoint = origin.endpoint;
                                let now = self.now;
                                match ias_wd::handle(c, cmd, payload, now) {
                                    ias_wd::Outcome::Warning(w) => {
                                        self.push_event(ZclEvent::Warning {
                                            endpoint,
                                            warning: w.is_active().then_some(w),
                                        });
                                        let _ = self.default_response(&origin, ZclStatus::Success);
                                    }
                                    ias_wd::Outcome::Squawk(squawk) => {
                                        self.push_event(ZclEvent::Squawk { endpoint, squawk });
                                        let _ = self.default_response(&origin, ZclStatus::Success);
                                    }
                                    ias_wd::Outcome::Ignored => {
                                        let _ = self.default_response(&origin, ZclStatus::Success);
                                    }
                                    ias_wd::Outcome::Default(status) => {
                                        let _ = self.default_response(&origin, status);
                                    }
                                }
                                continue;
                            }
                            color_control::ID => {
                                self.handle_color(i, &origin, cmd, payload);
                                continue;
                            }
                            window_covering::ID => {
                                let Some(c) = self
                                    .endpoints
                                    .get(i)
                                    .and_then(|e| e.cluster(window_covering::ID, Role::Server))
                                else {
                                    continue;
                                };
                                let endpoint = origin.endpoint;
                                match window_covering::handle(c, cmd, payload) {
                                    window_covering::Outcome::Execute(command) => {
                                        if let Some(sc) = self
                                            .endpoints
                                            .get_mut(i)
                                            .and_then(|e| e.cluster_mut(scenes::ID, Role::Server))
                                        {
                                            scenes::invalidate(sc);
                                        }
                                        self.push_event(ZclEvent::WindowCovering {
                                            endpoint,
                                            command,
                                        });
                                        let _ = self.default_response(&origin, ZclStatus::Success);
                                    }
                                    window_covering::Outcome::Default(status) => {
                                        let _ = self.default_response(&origin, status);
                                    }
                                }
                                continue;
                            }
                            hvac::thermostat::ID => {
                                let Some(c) = self.endpoints.get_mut(i).and_then(|e| {
                                    e.cluster_mut(hvac::thermostat::ID, Role::Server)
                                }) else {
                                    continue;
                                };
                                let endpoint = origin.endpoint;
                                match hvac::thermostat::handle(c, cmd, payload) {
                                    hvac::thermostat::Outcome::Adjusted { heat, cool } => {
                                        if let Some(sc) = self
                                            .endpoints
                                            .get_mut(i)
                                            .and_then(|e| e.cluster_mut(scenes::ID, Role::Server))
                                        {
                                            scenes::invalidate(sc);
                                        }
                                        self.push_event(ZclEvent::Setpoints {
                                            endpoint,
                                            heat,
                                            cool,
                                        });
                                        let _ = self.default_response(&origin, ZclStatus::Success);
                                    }
                                    hvac::thermostat::Outcome::Default(status) => {
                                        let _ = self.default_response(&origin, status);
                                    }
                                }
                                continue;
                            }
                            _ => {}
                        }
                    } else if ind.cluster == poll_control::ID {
                        self.handle_poll_control(i, &origin, cmd, payload);
                        continue;
                    } else if ind.cluster == ias_zone::ID
                        && role == Role::Client
                        && cmd == ias_zone::CMD_ZONE_STATUS_CHANGE_NOTIFICATION
                        && let Some(change) = ias_zone::StatusChange::parse(payload)
                    {
                        // A CIE relays the zone status to its ACE clients
                        // (§8.3.2.4.4); the application still sees the
                        // notification.
                        self.ace_zone_status(i, change.zone_id, change.zone_status);
                    }
                    result.get_or_insert(ZclIndication::Command { origin, payload });
                }
                FrameType::Reserved(_) => {
                    let _ = self.default_response(&origin, ZclStatus::MalformedCommand);
                }
            }
        }
        result
    }

    /// Alarms server commands (§3.11.2.4): the table is kept by the
    /// layer, resets are handed to the application.
    fn handle_alarms(&mut self, ep_index: usize, origin: &Origin, cmd: CommandId, payload: &[u8]) {
        let Some(c) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(alarms::ID, Role::Server))
        else {
            return;
        };
        let endpoint = origin.endpoint;
        let mut out = [0u8; 8];
        match alarms::handle(c, cmd, payload, &mut out) {
            alarms::Outcome::Reset(alarm) => {
                self.push_event(ZclEvent::AlarmReset { endpoint, alarm });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            alarms::Outcome::Response(n) => {
                let header = origin
                    .header
                    .response(alarms::CMD_GET_ALARM_RESPONSE, FrameType::ClusterSpecific);
                if let Some(payload) = out.get(..n)
                    && let Ok(fr) = Self::build(&header, payload)
                {
                    self.push_action(ZclAction::Send {
                        destination: Destination::Short {
                            address: origin.src,
                            endpoint: origin.src_endpoint,
                        },
                        profile: origin.profile,
                        cluster: alarms::ID,
                        src_endpoint: endpoint,
                        frame: fr,
                        options: origin.reply_options(),
                    });
                }
            }
            alarms::Outcome::LogCleared => {
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            alarms::Outcome::Unsupported => {
                let _ = self.default_response(origin, ZclStatus::UnsupportedClusterCommand);
            }
            alarms::Outcome::Malformed => {
                let _ = self.default_response(origin, ZclStatus::MalformedCommand);
            }
        }
    }

    /// Raises an alarm of `cluster` with `code` on `endpoint`
    /// (§3.11.2.5.1): logs it in the endpoint's Alarms server
    /// (time-stamped from a Time server on the same endpoint when
    /// present) and sends an Alarm command to the bound clients.
    pub fn raise_alarm(
        &mut self,
        endpoint: Endpoint,
        cluster: ClusterId,
        code: u8,
    ) -> Result<(), ZclError> {
        let now = self.now;
        let ep = self.endpoint(endpoint).ok_or(ZclError::NotFound)?;
        let profile = ep.profile;
        let stamp = ep
            .cluster(time::ID, Role::Server)
            .and_then(|t| time::now(t, now))
            .unwrap_or(alarms::NO_TIME);
        let c = self
            .cluster_mut(endpoint, alarms::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        let payload = alarms::log(
            c,
            alarms::Entry {
                code,
                cluster,
                time: stamp,
            },
        );
        let seq = self.next_seq();
        let header = Header::cluster_specific(seq, alarms::CMD_ALARM, Direction::ToClient)
            .disable_default_response(true);
        let frame = Self::build(&header, &payload)?;
        self.push_action(ZclAction::Send {
            destination: Destination::Bound,
            profile,
            cluster: alarms::ID,
            src_endpoint: endpoint,
            frame,
            options: TxOptions::ACKED,
        });
        Ok(())
    }

    /// Sets the clock of the Time server on `endpoint` (the
    /// application's real-time clock, §3.12.2.2.1).
    pub fn set_time(&mut self, endpoint: Endpoint, utc: u32) -> Result<(), ZclError> {
        let now = self.now;
        let c = self
            .cluster_mut(endpoint, time::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        time::set(c, utc, now);
        Ok(())
    }

    /// The Time server's current UTC time on `endpoint`, `None` when
    /// unset or absent.
    pub fn time(&self, endpoint: Endpoint) -> Option<u32> {
        let c = self.cluster(endpoint, time::ID, Role::Server)?;
        time::now(c, self.now)
    }

    /// IAS Zone server commands (§8.2.2.2): enrolment and test mode,
    /// accepted from the CIE only.
    fn handle_ias_zone(
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
            .and_then(|e| e.cluster_mut(ias_zone::ID, Role::Server))
        else {
            return;
        };
        let endpoint = origin.endpoint;
        match ias_zone::handle(c, origin.src, cmd, payload, now) {
            ias_zone::Outcome::Enrolled(zone_id) => {
                self.push_event(ZclEvent::ZoneEnrolled { endpoint, zone_id });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            ias_zone::Outcome::Refused(_) => {
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            ias_zone::Outcome::TestMode(seconds) => {
                self.push_event(ZclEvent::ZoneTestMode { endpoint, seconds });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            ias_zone::Outcome::NotAuthorized => {
                let _ = self.default_response(origin, ZclStatus::NotAuthorized);
            }
            ias_zone::Outcome::Unsupported => {
                let _ = self.default_response(origin, ZclStatus::UnsupportedClusterCommand);
            }
            ias_zone::Outcome::Malformed => {
                let _ = self.default_response(origin, ZclStatus::MalformedCommand);
            }
        }
    }

    /// Local time for the Door Lock event notifications from a Time
    /// server on the same endpoint (§7.3.2.3).
    fn local_time(&self, ep_index: usize) -> u32 {
        let now = self.now;
        self.endpoints
            .get(ep_index)
            .and_then(|ep| ep.cluster(time::ID, Role::Server))
            .and_then(|t| time::now(t, now).and_then(|utc| time::local_times(t, utc)))
            .map_or(door_lock::NO_TIME, |(_, local)| local)
    }

    /// Door Lock server commands (§7.3.2.15): the response goes back to
    /// the requester, the bolt operation to the application, the event
    /// notification to the bound clients and a tamper alarm through the
    /// Alarms cluster.
    fn handle_door_lock(
        &mut self,
        ep_index: usize,
        origin: &Origin,
        cmd: CommandId,
        payload: &[u8],
    ) {
        let now = self.now;
        let local_time = self.local_time(ep_index);
        let Some(c) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(door_lock::ID, Role::Server))
        else {
            return;
        };
        let endpoint = origin.endpoint;
        let outcome = door_lock::handle(c, cmd, payload, now, local_time);
        if let Some((action, user)) = outcome.action {
            self.push_event(ZclEvent::DoorLock {
                endpoint,
                action,
                user,
            });
        }
        if let Some(frame) = outcome.notify {
            self.send_door_lock_frame(ep_index, frame);
        }
        if let Some(code) = outcome.alarm {
            let _ = self.raise_alarm(endpoint, door_lock::ID, code);
        }
        match outcome.response {
            Some(frame) => self.reply_cluster_specific(origin, frame.command, &frame.payload),
            None => {
                let _ = self.default_response(origin, outcome.status);
            }
        }
    }

    /// Sends a Door Lock event notification to the bound clients.
    fn send_door_lock_frame(&mut self, ep_index: usize, frame: door_lock::Frame) {
        let Some(ep) = self.endpoints.get(ep_index) else {
            return;
        };
        let (endpoint, profile) = (ep.endpoint, ep.profile);
        let seq = self.next_seq();
        let header = Header::cluster_specific(seq, frame.command, Direction::ToClient)
            .disable_default_response(true);
        if let Ok(fr) = Self::build(&header, &frame.payload) {
            self.push_action(ZclAction::Send {
                destination: Destination::Bound,
                profile,
                cluster: door_lock::ID,
                src_endpoint: endpoint,
                frame: fr,
                options: TxOptions::ACKED,
            });
        }
    }

    /// Reports the bolt position of the Door Lock server on `endpoint`
    /// (`LockState`, Table 7-9).
    pub fn set_lock_state(&mut self, endpoint: Endpoint, state: u8) -> Result<bool, ZclError> {
        let c = self
            .cluster_mut(endpoint, door_lock::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        Ok(door_lock::set_lock_state(c, state))
    }

    /// Sends a Door Lock Operation Event Notification for an event the
    /// application observed (keypad, manual or RFID sources), when its
    /// mask bit is set; returns whether it was sent.
    pub fn door_lock_operation_event(
        &mut self,
        endpoint: Endpoint,
        source: u8,
        code: u8,
        user: u16,
        pin: &[u8],
    ) -> Result<bool, ZclError> {
        let i = self
            .endpoints
            .iter()
            .position(|e| e.endpoint == endpoint)
            .ok_or(ZclError::NotFound)?;
        let local_time = self.local_time(i);
        let c = self
            .cluster_mut(endpoint, door_lock::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        let Some(frame) = door_lock::operation_event(c, source, code, user, pin, local_time) else {
            return Ok(false);
        };
        self.send_door_lock_frame(i, frame);
        Ok(true)
    }

    /// Sends a Door Lock Programming Event Notification for a change the
    /// application made locally (keypad or RFID sources), when its mask
    /// bit is set; returns whether it was sent.
    pub fn door_lock_programming_event(
        &mut self,
        endpoint: Endpoint,
        source: u8,
        code: u8,
        user_id: u16,
    ) -> Result<bool, ZclError> {
        let i = self
            .endpoints
            .iter()
            .position(|e| e.endpoint == endpoint)
            .ok_or(ZclError::NotFound)?;
        let local_time = self.local_time(i);
        let c = self
            .cluster_mut(endpoint, door_lock::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        let user = door_lock::users(c)
            .get(usize::from(user_id))
            .cloned()
            .unwrap_or_default();
        let Some(frame) = door_lock::programming_event(c, source, code, &user, user_id, local_time)
        else {
            return Ok(false);
        };
        self.send_door_lock_frame(i, frame);
        Ok(true)
    }

    /// IAS ACE server commands (§8.3.2.3): answered from the panel
    /// state, with Arm / Emergency / Fire / Panic handed to the
    /// application.
    fn handle_ias_ace(&mut self, ep_index: usize, origin: &Origin, cmd: CommandId, payload: &[u8]) {
        let Some(c) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(ias_ace::ID, Role::Server))
        else {
            return;
        };
        let endpoint = origin.endpoint;
        let outcome = ias_ace::handle(c, cmd, payload);
        if let Some(request) = outcome.request {
            self.push_event(ZclEvent::Ace { endpoint, request });
        }
        if let Some(frame) = outcome.notify {
            self.send_ace_frame(ep_index, frame);
        }
        match outcome.response {
            Some(frame) => self.reply_cluster_specific(origin, frame.command, &frame.payload),
            None => {
                let _ = self.default_response(origin, outcome.status);
            }
        }
    }

    /// Sends an IAS ACE command to the bound clients.
    fn send_ace_frame(&mut self, ep_index: usize, frame: ias_ace::Frame) {
        let Some(ep) = self.endpoints.get(ep_index) else {
            return;
        };
        let (endpoint, profile) = (ep.endpoint, ep.profile);
        let seq = self.next_seq();
        let header = Header::cluster_specific(seq, frame.command, Direction::ToClient)
            .disable_default_response(true);
        if let Ok(fr) = Self::build(&header, &frame.payload) {
            self.push_action(ZclAction::Send {
                destination: Destination::Bound,
                profile,
                cluster: ias_ace::ID,
                src_endpoint: endpoint,
                frame: fr,
                options: TxOptions::ACKED,
            });
        }
    }

    fn ace_zone_status(&mut self, ep_index: usize, zone_id: u8, status: u16) {
        let frame = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(ias_ace::ID, Role::Server))
            .and_then(|c| ias_ace::set_zone_status(c, zone_id, status));
        if let Some(frame) = frame {
            self.send_ace_frame(ep_index, frame);
        }
    }

    /// Records a zone status in the IAS ACE server on `endpoint` and
    /// sends Zone Status Changed to the bound clients (§8.3.2.4.4);
    /// `Ok(false)` for an unknown zone.
    pub fn ace_set_zone_status(
        &mut self,
        endpoint: Endpoint,
        zone_id: u8,
        status: u16,
    ) -> Result<bool, ZclError> {
        let i = self
            .endpoints
            .iter()
            .position(|e| e.endpoint == endpoint)
            .ok_or(ZclError::NotFound)?;
        let c = self
            .cluster_mut(endpoint, ias_ace::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        let Some(frame) = ias_ace::set_zone_status(c, zone_id, status) else {
            return Ok(false);
        };
        self.send_ace_frame(i, frame);
        Ok(true)
    }

    /// Sets the panel status of the IAS ACE server on `endpoint` and
    /// sends Panel Status Changed to the bound clients (§8.3.2.4.5).
    pub fn ace_set_panel_status(
        &mut self,
        endpoint: Endpoint,
        status: u8,
        seconds_remaining: u8,
        alarm: u8,
    ) -> Result<(), ZclError> {
        let i = self
            .endpoints
            .iter()
            .position(|e| e.endpoint == endpoint)
            .ok_or(ZclError::NotFound)?;
        let c = self
            .cluster_mut(endpoint, ias_ace::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        let frame = ias_ace::set_panel_status(c, status, seconds_remaining, alarm)
            .ok_or(ZclError::NotFound)?;
        self.send_ace_frame(i, frame);
        if status == ias_ace::panel_status::DISARMED
            && let Some(list) = self
                .cluster(endpoint, ias_ace::ID, Role::Server)
                .and_then(ias_ace::bypassed_zone_list)
        {
            self.send_ace_frame(i, list);
        }
        Ok(())
    }

    /// Sets the zone status of the IAS Zone server on `endpoint`
    /// (§8.2.2.1.1.3); a change is notified to the CIE.
    pub fn set_zone_status(&mut self, endpoint: Endpoint, status: u16) -> Result<bool, ZclError> {
        let now = self.now;
        let c = self
            .cluster_mut(endpoint, ias_zone::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        Ok(ias_zone::set_status(c, status, now))
    }

    /// Trip-to-Pair trigger of the IAS Zone server on `endpoint`
    /// (§8.2.2.1.3): requests enrolment from the configured CIE.
    pub fn request_zone_enrollment(&mut self, endpoint: Endpoint) -> Result<bool, ZclError> {
        let now = self.now;
        let c = self
            .cluster_mut(endpoint, ias_zone::ID, Role::Server)
            .ok_or(ZclError::NotFound)?;
        Ok(ias_zone::request_enrollment(c, now))
    }

    /// Color Control server commands (§5.2.2.3) run by the layer's
    /// transition engine.
    fn handle_color(&mut self, ep_index: usize, origin: &Origin, cmd: CommandId, payload: &[u8]) {
        let now = self.now;
        let Some(ep) = self.endpoints.get_mut(ep_index) else {
            return;
        };
        let on_off_state = ep.cluster(on_off::ID, Role::Server).map(on_off::is_on);
        let Some(c) = ep.cluster_mut(color_control::ID, Role::Server) else {
            return;
        };
        match color_control::handle(c, cmd, payload, on_off_state, now) {
            color_control::Outcome::Applied => {
                if let Some(sc) = ep.cluster_mut(scenes::ID, Role::Server) {
                    scenes::invalidate(sc);
                }
                self.service_color(ep_index);
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            color_control::Outcome::Suppressed => {
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            color_control::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
        }
    }

    /// Runs the Color Control engine of one endpoint once.
    fn service_color(&mut self, ep_index: usize) {
        let now = self.now;
        let Some(ep) = self.endpoints.get_mut(ep_index) else {
            return;
        };
        let endpoint = ep.endpoint;
        let Some(c) = ep.cluster_mut(color_control::ID, Role::Server) else {
            return;
        };
        let Some(t) = color_control::tick(c, now) else {
            return;
        };
        if t.changed || t.done {
            let mode = c.u8(color_control::ENHANCED_COLOR_MODE.id).unwrap_or(0);
            let (a, b) = match mode {
                color_control::color_mode::XY => (
                    c.u16(color_control::CURRENT_X.id).unwrap_or(0),
                    c.u16(color_control::CURRENT_Y.id).unwrap_or(0),
                ),
                color_control::color_mode::COLOR_TEMPERATURE => (
                    c.u16(color_control::COLOR_TEMPERATURE_MIREDS.id)
                        .unwrap_or(0),
                    0,
                ),
                _ => (
                    color_control::enhanced_hue(c),
                    u16::from(c.u8(color_control::CURRENT_SATURATION.id).unwrap_or(0)),
                ),
            };
            self.push_event(ZclEvent::Color {
                endpoint,
                mode,
                a,
                b,
                done: t.done,
            });
        }
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
                        options: origin.reply_options(),
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
                        options: origin.reply_options(),
                    });
                }
            }
            groups::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
            groups::Outcome::None => {}
        }
    }

    /// Sends a cluster-specific response to `origin` built from `payload`.
    fn reply_cluster_specific(&mut self, origin: &Origin, cmd: CommandId, payload: &[u8]) {
        let header = origin.header.response(cmd, FrameType::ClusterSpecific);
        if let Ok(fr) = Self::build(&header, payload) {
            self.push_action(ZclAction::Send {
                destination: Destination::Short {
                    address: origin.src,
                    endpoint: origin.src_endpoint,
                },
                profile: origin.profile,
                cluster: origin.cluster,
                src_endpoint: origin.endpoint,
                frame: fr,
                options: origin.reply_options(),
            });
        }
    }

    /// On/Off server commands are executed by the layer (§3.8.2.3); the
    /// Level Control coupling (Table 3-55) and the global scene
    /// (§3.8.2.2.2) are applied across the endpoint's clusters.
    fn handle_on_off(&mut self, ep_index: usize, origin: &Origin, cmd: CommandId, payload: &[u8]) {
        let now = self.now;
        let Some(c) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(on_off::ID, Role::Server))
        else {
            return;
        };
        let before = on_off::is_on(c);
        match on_off::handle(c, cmd, payload, now) {
            on_off::Outcome::Set(on) => {
                self.after_on_off(ep_index, before, on, true);
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            on_off::Outcome::OffWithEffect {
                effect,
                variant,
                store_global_scene,
            } => {
                if store_global_scene {
                    self.store_global_scene(ep_index);
                }
                if let Some(c) = self
                    .endpoints
                    .get_mut(ep_index)
                    .and_then(|e| e.cluster_mut(on_off::ID, Role::Server))
                {
                    on_off::turn_off_with_effect(c, now);
                }
                self.after_on_off(ep_index, before, false, true);
                self.push_event(ZclEvent::OffWithEffect {
                    endpoint: origin.endpoint,
                    effect,
                    variant,
                });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            on_off::Outcome::RecallGlobalScene => {
                let entry = self.endpoints.get_mut(ep_index).and_then(|e| {
                    let t = &e.scenes;
                    e.clusters
                        .iter_mut()
                        .find(|c| c.def.id == scenes::ID && c.role == Role::Server)
                        .and_then(|c| scenes::global(c, t))
                });
                match entry {
                    Some(e) => {
                        self.apply_scene(ep_index, &e.fields, e.tenths());
                        self.push_event(ZclEvent::SceneRecalled {
                            endpoint: origin.endpoint,
                            group: 0,
                            scene: 0,
                        });
                    }
                    // No global scene stored: plain On (§3.8.2.3.5.1).
                    None => self.set_on_off_at(ep_index, true),
                }
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            on_off::Outcome::Discarded => {
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            on_off::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
        }
    }

    /// Bookkeeping after `OnOff` was (re)written on endpoint `ep_index`:
    /// the change event, the Level Control fade (Table 3-55, on a change
    /// only) and scene invalidation.
    fn after_on_off(&mut self, ep_index: usize, before: bool, on: bool, level_effect: bool) {
        let now = self.now;
        let Some(ep) = self.endpoints.get_mut(ep_index) else {
            return;
        };
        let endpoint = ep.endpoint;
        if before == on {
            return;
        }
        if level_effect && let Some(l) = ep.cluster_mut(level::ID, Role::Server) {
            level::on_off_effect(l, on, now);
        }
        if let Some(sc) = ep.cluster_mut(scenes::ID, Role::Server) {
            scenes::invalidate(sc);
        }
        self.push_event(ZclEvent::OnOff { endpoint, on });
        if level_effect {
            self.service_level(ep_index);
        }
    }

    fn set_on_off_at(&mut self, ep_index: usize, on: bool) {
        let now = self.now;
        let Some(c) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(on_off::ID, Role::Server))
        else {
            return;
        };
        let before = on_off::is_on(c);
        on_off::set_on(c, on, now);
        self.after_on_off(ep_index, before, on, true);
    }

    /// Application-side On/Off change (a local switch): applies the
    /// same coupling as a received command. Returns whether it changed.
    pub fn set_on_off(&mut self, endpoint: Endpoint, on: bool) -> Result<bool, ZclError> {
        let i = self
            .endpoints
            .iter()
            .position(|e| e.endpoint == endpoint)
            .ok_or(ZclError::NotFound)?;
        let now = self.now;
        let c = self
            .endpoints
            .get_mut(i)
            .and_then(|e| e.cluster_mut(on_off::ID, Role::Server))
            .ok_or(ZclError::NotFound)?;
        let before = on_off::is_on(c);
        on_off::set_on(c, on, now);
        self.after_on_off(i, before, on, true);
        Ok(before != on)
    }

    /// Level Control server commands (§3.10.2.3).
    fn handle_level(&mut self, ep_index: usize, origin: &Origin, cmd: CommandId, payload: &[u8]) {
        let now = self.now;
        let Some(ep) = self.endpoints.get_mut(ep_index) else {
            return;
        };
        let on_off_state = ep.cluster(on_off::ID, Role::Server).map(on_off::is_on);
        let Some(c) = ep.cluster_mut(level::ID, Role::Server) else {
            return;
        };
        match level::handle(c, cmd, payload, on_off_state, now) {
            level::Outcome::Applied { turn_on } => {
                if let Some(sc) = ep.cluster_mut(scenes::ID, Role::Server) {
                    scenes::invalidate(sc);
                }
                if turn_on && on_off_state == Some(false) {
                    // §3.10.2.3.6 / §3.10.2.1.3: no Table 3-55 fade, the
                    // level command drives the transition.
                    if let Some(oc) = ep.cluster_mut(on_off::ID, Role::Server) {
                        on_off::set_on(oc, true, now);
                    }
                    self.after_on_off(ep_index, false, true, false);
                }
                self.service_level(ep_index);
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            level::Outcome::Suppressed => {
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            level::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
        }
    }

    /// Runs the Level Control transition engine of one endpoint once.
    fn service_level(&mut self, ep_index: usize) {
        let now = self.now;
        let Some(ep) = self.endpoints.get_mut(ep_index) else {
            return;
        };
        let endpoint = ep.endpoint;
        let Some(c) = ep.cluster_mut(level::ID, Role::Server) else {
            return;
        };
        let Some(t) = level::tick(c, now) else {
            return;
        };
        if t.changed || t.done {
            self.push_event(ZclEvent::Level {
                endpoint,
                level: t.level,
                done: t.done,
            });
        }
        if t.turn_off {
            self.set_on_off_at(ep_index, false);
        }
    }

    /// Current extension field sets of the endpoint (§3.7.2.4.2.1).
    fn scene_fields(&self, ep_index: usize) -> Vec<u8, { scenes::MAX_EXTENSION_BYTES }> {
        let mut buf = [0u8; scenes::MAX_EXTENSION_BYTES];
        let mut w = Writer::new(&mut buf);
        if let Some(ep) = self.endpoints.get(ep_index) {
            if let Some(c) = ep.cluster(on_off::ID, Role::Server) {
                scenes::write_field_set(&mut w, on_off::ID, &on_off::scene_fields(c));
            }
            if let Some(c) = ep.cluster(level::ID, Role::Server) {
                scenes::write_field_set(&mut w, level::ID, &level::scene_fields(c));
            }
            if let Some(c) = ep.cluster(color_control::ID, Role::Server) {
                scenes::write_field_set(&mut w, color_control::ID, &color_control::scene_fields(c));
            }
            if let Some(c) = ep.cluster(hvac::thermostat::ID, Role::Server) {
                scenes::write_field_set(
                    &mut w,
                    hvac::thermostat::ID,
                    &hvac::thermostat::scene_fields(c),
                );
            }
            if let Some(c) = ep.cluster(window_covering::ID, Role::Server) {
                scenes::write_field_set(
                    &mut w,
                    window_covering::ID,
                    &window_covering::scene_fields(c),
                );
            }
            if let Some(c) = ep.cluster(door_lock::ID, Role::Server) {
                scenes::write_field_set(&mut w, door_lock::ID, &door_lock::scene_fields(c));
            }
        }
        let n = w.position();
        Vec::from_slice(buf.get(..n).unwrap_or(&[])).unwrap_or_default()
    }

    fn store_global_scene(&mut self, ep_index: usize) {
        let fields = self.scene_fields(ep_index);
        if let Some(ep) = self.endpoints.get_mut(ep_index) {
            let t = &mut ep.scenes;
            if let Some(c) = ep
                .clusters
                .iter_mut()
                .find(|c| c.def.id == scenes::ID && c.role == Role::Server)
            {
                scenes::store_global(c, t, &fields);
            }
        }
    }

    /// Applies extension field sets to the endpoint's clusters over
    /// `tenths` tenths of a second (§3.7.2.4.7.2 step 4).
    fn apply_scene(&mut self, ep_index: usize, fields: &[u8], tenths: u16) {
        let now = self.now;
        let has_level = scenes::FieldSets(fields).any(|(c, _)| c == level::ID);
        for (cluster, f) in scenes::FieldSets(fields) {
            let Some(ep) = self.endpoints.get_mut(ep_index) else {
                return;
            };
            if cluster == on_off::ID
                && let Some(c) = ep.cluster_mut(on_off::ID, Role::Server)
            {
                let before = on_off::is_on(c);
                if let Some(on) = on_off::apply_scene_fields(c, f, now) {
                    self.after_on_off(ep_index, before, on, !has_level);
                }
            } else if cluster == level::ID
                && let Some(c) = ep.cluster_mut(level::ID, Role::Server)
            {
                level::apply_scene_fields(c, f, tenths, now);
                self.service_level(ep_index);
            } else if cluster == color_control::ID
                && let Some(c) = ep.cluster_mut(color_control::ID, Role::Server)
            {
                color_control::apply_scene_fields(c, f, tenths, now);
                self.service_color(ep_index);
            } else if cluster == hvac::thermostat::ID
                && let Some(c) = ep.cluster_mut(hvac::thermostat::ID, Role::Server)
            {
                hvac::thermostat::apply_scene_fields(c, f);
            } else if cluster == window_covering::ID
                && let Some(c) = ep.cluster(window_covering::ID, Role::Server)
                && let Some(command) = window_covering::apply_scene_fields(c, f, tenths)
            {
                let endpoint = ep.endpoint;
                self.push_event(ZclEvent::WindowCovering { endpoint, command });
            } else if cluster == door_lock::ID
                && let Some(c) = ep.cluster_mut(door_lock::ID, Role::Server)
            {
                door_lock::apply_scene_fields(c, f, tenths, now);
            }
        }
        // The recalled scene is what the device shows now.
        if let Some(sc) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(scenes::ID, Role::Server))
        {
            sc.set_bool(scenes::SCENE_VALID.id, true);
        }
    }

    /// Scenes server commands are executed by the layer against the
    /// instance's scene table (§3.7.2.4).
    fn handle_scenes(
        &mut self,
        ep_index: usize,
        origin: &Origin,
        cmd: CommandId,
        payload: &[u8],
        groups: &mut impl GroupStore,
    ) {
        let endpoint = origin.endpoint;
        let unicast = !origin.broadcast;
        let member = |g: u16| groups.contains(GroupAddress(g), endpoint);
        let mut out = [0u8; MAX_ZCL];
        let mut w = Writer::new(&mut out);
        let Some(ep) = self.endpoints.get_mut(ep_index) else {
            return;
        };
        let t = &mut ep.scenes;
        let Some(c) = ep
            .clusters
            .iter_mut()
            .find(|c| c.def.id == scenes::ID && c.role == Role::Server)
        else {
            return;
        };
        let outcome = scenes::handle(c, t, cmd, payload, unicast, &member, &mut w);
        let outcome = match outcome {
            scenes::Outcome::Store { group, scene } => {
                let fields = self.scene_fields(ep_index);
                let Some(ep) = self.endpoints.get_mut(ep_index) else {
                    return;
                };
                let t = &mut ep.scenes;
                match ep
                    .clusters
                    .iter_mut()
                    .find(|c| c.def.id == scenes::ID && c.role == Role::Server)
                {
                    Some(c) => scenes::complete_store(c, t, group, scene, &fields, unicast, &mut w),
                    None => return,
                }
            }
            scenes::Outcome::Recall {
                group,
                scene,
                tenths,
            } => {
                let fields = self
                    .endpoints
                    .get(ep_index)
                    .and_then(|e| e.scenes.get(group, scene).map(|e| e.fields.clone()));
                if let Some(f) = fields {
                    self.apply_scene(ep_index, &f, tenths);
                }
                self.push_event(ZclEvent::SceneRecalled {
                    endpoint,
                    group,
                    scene,
                });
                scenes::Outcome::Default(ZclStatus::Success)
            }
            other => other,
        };
        let n = w.position();
        match outcome {
            scenes::Outcome::Response(rsp) => {
                if let Some(payload) = out.get(..n) {
                    self.reply_cluster_specific(origin, rsp, payload);
                }
            }
            scenes::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
            scenes::Outcome::None
            | scenes::Outcome::Store { .. }
            | scenes::Outcome::Recall { .. } => {}
        }
    }

    /// Poll Control commands on a server (§3.16.5) or client (Check-in,
    /// §3.16.4.4) instance.
    fn handle_poll_control(
        &mut self,
        ep_index: usize,
        origin: &Origin,
        cmd: CommandId,
        payload: &[u8],
    ) {
        let now = self.now;
        let role = match origin.header.control.direction {
            Direction::ToServer => Role::Server,
            Direction::ToClient => Role::Client,
        };
        let endpoint = origin.endpoint;
        let Some(c) = self
            .endpoints
            .get_mut(ep_index)
            .and_then(|e| e.cluster_mut(poll_control::ID, role))
        else {
            return;
        };
        let long = poll_control::long_poll_interval(c);
        let short = poll_control::short_poll_interval(c);
        match poll_control::handle(c, cmd, payload, now) {
            poll_control::Outcome::FastPoll(_) => {
                self.push_event(ZclEvent::FastPoll {
                    endpoint,
                    fast: true,
                    interval: short,
                });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            poll_control::Outcome::FastPollEnded => {
                self.push_event(ZclEvent::FastPoll {
                    endpoint,
                    fast: false,
                    interval: long,
                });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            poll_control::Outcome::LongPollInterval(interval) => {
                self.push_event(ZclEvent::LongPollInterval { endpoint, interval });
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            poll_control::Outcome::ShortPollInterval(_) => {
                let _ = self.default_response(origin, ZclStatus::Success);
            }
            poll_control::Outcome::CheckInResponse(p) => {
                self.reply_cluster_specific(origin, poll_control::CMD_CHECK_IN_RESPONSE, &p);
                self.push_event(ZclEvent::CheckIn {
                    endpoint,
                    src: origin.src,
                    src_endpoint: origin.src_endpoint,
                });
            }
            poll_control::Outcome::Default(status) => {
                let _ = self.default_response(origin, status);
            }
        }
    }

    /// Reset to Factory Defaults (§3.2.2.3.1): every attribute of every
    /// cluster on every endpoint returns to its default; network state,
    /// bindings and groups are untouched.
    pub fn factory_reset(&mut self) {
        let now = self.now;
        for ep in &mut self.endpoints {
            for c in &mut ep.clusters {
                c.reset_to_defaults(now);
            }
        }
        self.push_event(ZclEvent::FactoryReset);
    }

    /// Runs the cluster timers of every endpoint (Identify, On/Off timed
    /// off, Level Control transitions, Poll Control check-ins).
    fn service_cluster_timers(&mut self, now: Instant) {
        for i in 0..self.endpoints.len() {
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            let (endpoint, profile) = (ep.endpoint, ep.profile);
            if let Some(c) = ep.cluster_mut(identify::ID, Role::Server)
                && let Some(seconds) = identify::tick(c, now)
            {
                self.push_event(ZclEvent::Identify { endpoint, seconds });
            }
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            if let Some(c) = ep.cluster_mut(time::ID, Role::Server) {
                let before = match &c.state {
                    crate::cluster::ClusterState::Time(k) => k.published,
                    _ => time::INVALID,
                };
                // A write over the air shows as a Time value the server
                // did not publish itself; it is applied at once.
                let written = c.u64(time::TIME.id).is_some_and(|v| v != u64::from(before));
                if (written || c.tick.is_some_and(|t| now.has_reached(t)))
                    && let Some(utc) = time::tick(c, now)
                    && written
                {
                    self.push_event(ZclEvent::TimeSet { endpoint, utc });
                }
            }
            let local_time = self.local_time(i);
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            if let Some(c) = ep.cluster_mut(ias_wd::ID, Role::Server)
                && ias_wd::tick(c, now)
            {
                self.push_event(ZclEvent::Warning {
                    endpoint,
                    warning: None,
                });
            }
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            if let Some(c) = ep.cluster_mut(door_lock::ID, Role::Server)
                && c.tick.is_some_and(|t| now.has_reached(t))
                && let Some((action, frame)) = door_lock::tick(c, now, local_time)
            {
                self.push_event(ZclEvent::DoorLock {
                    endpoint,
                    action,
                    user: door_lock::NO_USER,
                });
                if let Some(frame) = frame {
                    self.send_door_lock_frame(i, frame);
                }
            }
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            let mut zone_sends: Vec<(ias_zone::Send, (ShortAddress, Endpoint)), 4> = Vec::new();
            if let Some(c) = ep.cluster_mut(ias_zone::ID, Role::Server)
                && c.tick.is_some_and(|t| now.has_reached(t))
            {
                while let Some(item) = ias_zone::tick(c, now) {
                    if zone_sends.push(item).is_err() {
                        break;
                    }
                }
            }
            for (send, (dst, dst_ep)) in zone_sends {
                let (cmd, payload): (CommandId, &[u8]) = match &send {
                    ias_zone::Send::StatusChange(p) => {
                        (ias_zone::CMD_ZONE_STATUS_CHANGE_NOTIFICATION, p)
                    }
                    ias_zone::Send::EnrollRequest(p) => (ias_zone::CMD_ZONE_ENROLL_REQUEST, p),
                };
                let seq = self.next_seq();
                let header = Header::cluster_specific(seq, cmd, Direction::ToClient)
                    .disable_default_response(true);
                if let Ok(frame) = Self::build(&header, payload) {
                    self.push_action(ZclAction::Send {
                        destination: Destination::Short {
                            address: dst,
                            endpoint: dst_ep,
                        },
                        profile,
                        cluster: ias_zone::ID,
                        src_endpoint: endpoint,
                        frame,
                        options: TxOptions::ACKED,
                    });
                }
            }
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            if let Some(c) = ep.cluster_mut(on_off::ID, Role::Server)
                && let Some(on) = on_off::tick(c, now)
            {
                self.after_on_off(i, !on, on, true);
            }
            self.service_level(i);
            self.service_color(i);
            let Some(ep) = self.endpoints.get_mut(i) else {
                break;
            };
            if let Some(c) = ep.cluster_mut(poll_control::ID, Role::Server) {
                let long = poll_control::long_poll_interval(c);
                let short = poll_control::short_poll_interval(c);
                match poll_control::tick(c, now) {
                    Some(poll_control::Tick::CheckIn) => {
                        let seq = self.next_seq();
                        let header = Header::cluster_specific(
                            seq,
                            poll_control::CMD_CHECK_IN,
                            Direction::ToClient,
                        )
                        .disable_default_response(true);
                        if let Ok(frame) = Self::build(&header, &[]) {
                            self.push_action(ZclAction::Send {
                                destination: Destination::Bound,
                                profile,
                                cluster: poll_control::ID,
                                src_endpoint: endpoint,
                                frame,
                                options: TxOptions::ACKED,
                            });
                        }
                        self.push_event(ZclEvent::FastPoll {
                            endpoint,
                            fast: true,
                            interval: short,
                        });
                    }
                    Some(poll_control::Tick::FastPollEnded) => {
                        self.push_event(ZclEvent::FastPoll {
                            endpoint,
                            fast: false,
                            interval: long,
                        });
                    }
                    None => {}
                }
            }
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
        self.service_cluster_timers(now);
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
