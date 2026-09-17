//! Touchlink commissioning integration (BDB 3.1 §12, ZCL8 §13.3): the
//! stack carries the initiator and target machines of
//! `panweave-bdb::touchlink`, sends and receives inter-PAN frames
//! straight through the MAC (they never enter the NWK layer), switches
//! channels for the scans, transports the network key with
//! `panweave-security::touchlink`, and applies the resulting network
//! parameters — forming, adopting or rejoining once any leave has
//! completed.

use heapless::Vec;
use panweave_aps::interpan::{InterPanDelivery, InterPanHeader};
use panweave_bdb::NodeError;
use panweave_bdb::touchlink::{
    AddressRanges, Candidate, Failure, Initiator, InitiatorOutcome, InterPanDestination,
    MAX_SUB_DEVICES, NetworkInfo, NetworkParams, Target, TargetOutcome, TargetPolicy,
    TouchlinkNode,
};
use panweave_codec::{Encode, Writer};
use panweave_mac::frame::{Frame as MacFrame, MacAddress};
use panweave_security::cipher::BlockCipher;
use panweave_security::touchlink as tl_security;
use panweave_storage::Storage;
use panweave_types::time::Instant;
use panweave_types::{
    Channel, ChannelMask, CommandId, CryptoRng, ExtendedAddress, Key128, KeySequenceNumber,
    LogicalDeviceType, NwkStatus, PanId, ShortAddress, TransactionSequence,
};
use panweave_zcl::clusters::touchlink as tl;
use panweave_zcl::frame::{Direction, Frame as ZclFrame, Header};

use crate::provision::{AdoptParams, FormationParams};
use crate::stack::{JoinMode, Phase, Stack, StackEvent};

/// Touchlink configuration.
#[derive(Clone, Debug)]
pub struct TouchlinkConfig {
    /// Key index used to transport the network key: 4 (master, needs
    /// `master_key`) or 15 (certification).
    pub key_index: u8,
    /// The touchlink master key (a licensed secret), when available.
    pub master_key: Option<Key128>,
    /// Target policy.
    pub policy: TargetPolicy,
    /// Address and group ranges this node assigns from.
    pub ranges: AddressRanges,
}

impl TouchlinkConfig {
    /// Certification key, default policy, factory-new ranges.
    pub const CERTIFICATION: TouchlinkConfig = TouchlinkConfig {
        key_index: tl_security::KEY_INDEX_CERTIFICATION,
        master_key: None,
        policy: TargetPolicy::DEFAULT,
        ranges: AddressRanges::FACTORY_NEW,
    };
}

/// Network parameters waiting for a leave to complete.
#[derive(Clone, Debug)]
enum Pending {
    Start(NetworkParams),
    Join(NetworkParams),
    Adopt(NetworkParams),
}

/// The two procedures; taken out of the stack while they run so they
/// can drive it as their [`TouchlinkNode`].
#[derive(Debug)]
pub struct Machines {
    /// The initiator procedure.
    pub initiator: Initiator,
    /// The target procedure.
    pub target: Target,
}

/// Touchlink state of the stack.
#[derive(Debug)]
pub struct Touchlink {
    /// The procedures (`None` only while one of them is running).
    pub machines: Option<Machines>,
    master_key: Option<Key128>,
    seq: u8,
    /// Channel to return to after a scan.
    restore_channel: Option<Channel>,
    pending: Option<Pending>,
}

/// Touchlink events for the application.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TouchlinkEvent {
    /// Initiator: discovery finished with `count` candidates; read them
    /// with `Stack::touchlink_candidates` and choose with
    /// `Stack::touchlink_select`.
    Discovered {
        /// Number of candidates.
        count: u8,
    },
    /// Initiator: a Device Information Response arrived.
    DeviceInformation(tl::DeviceInformationResponse),
    /// Initiator: the target was commissioned.
    Success {
        /// The target.
        target: ExtendedAddress,
        /// Its network address.
        short: ShortAddress,
    },
    /// Initiator: the reset request was sent.
    ResetSent,
    /// Initiator: the procedure failed.
    Failed(Failure),
    /// Target: answered a scan from `initiator`.
    Scanned {
        /// The initiator.
        initiator: ExtendedAddress,
    },
    /// Target: started a network for `initiator`.
    Started {
        /// The initiator.
        initiator: ExtendedAddress,
    },
    /// Target: joined the network of `initiator`.
    Joined {
        /// The initiator.
        initiator: ExtendedAddress,
    },
    /// Target: refused a request by policy.
    Refused,
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Enables touchlink commissioning (both roles).
    pub fn enable_touchlink(&mut self, config: TouchlinkConfig) {
        let mut initiator = Initiator::new(config.key_index);
        initiator.ranges = config.ranges;
        self.touchlink = Some(Touchlink {
            machines: Some(Machines {
                initiator,
                target: Target::new(config.policy),
            }),
            master_key: config.master_key,
            seq: 0,
            restore_channel: None,
            pending: None,
        });
    }

    fn take_machines(&mut self) -> Option<Machines> {
        self.touchlink.as_mut().and_then(|t| t.machines.take())
    }

    fn put_machines(&mut self, m: Machines) {
        if let Some(t) = self.touchlink.as_mut() {
            t.machines = Some(m);
        }
    }

    /// Starts the initiator touchlink procedure (§12.1): `extended` also
    /// scans the secondary channels, `reset` resets the chosen target.
    pub fn touchlink_start(&mut self, extended: bool, reset: bool) -> Result<(), NwkStatus> {
        let mut m = self.take_machines().ok_or(NwkStatus::InvalidRequest)?;
        if m.initiator.is_busy() || !matches!(self.phase, Phase::Idle | Phase::Operating) {
            self.put_machines(m);
            return Err(NwkStatus::InvalidRequest);
        }
        let restore = (self.phase == Phase::Operating).then_some(self.nwk.nib.channel);
        if let Some(t) = self.touchlink.as_mut() {
            t.restore_channel = restore;
        }
        m.initiator.start(self, extended, reset);
        self.put_machines(m);
        self.pump();
        Ok(())
    }

    /// The targets found by the last touchlink device discovery.
    pub fn touchlink_candidates(&self) -> &[Candidate] {
        self.touchlink
            .as_ref()
            .and_then(|t| t.machines.as_ref())
            .map_or(&[], |m| m.initiator.candidates())
    }

    /// Selects a discovered target (§12.1 step 5).
    pub fn touchlink_select(&mut self, candidate: &Candidate) -> Result<(), NwkStatus> {
        let mut m = self.take_machines().ok_or(NwkStatus::InvalidRequest)?;
        let out = m.initiator.select(self, candidate);
        self.put_machines(m);
        if let Some(o) = out {
            self.on_initiator_outcome(o);
        }
        self.pump();
        Ok(())
    }

    /// Asks a discovered target to identify (§12.1 step 6).
    pub fn touchlink_identify(
        &mut self,
        candidate: &Candidate,
        duration: u16,
    ) -> Result<(), NwkStatus> {
        let mut m = self.take_machines().ok_or(NwkStatus::InvalidRequest)?;
        let r = m.initiator.identify_target(self, candidate, duration);
        self.put_machines(m);
        self.pump();
        r.map_err(|_| NwkStatus::InvalidRequest)
    }

    /// Requests a discovered target's device information table.
    pub fn touchlink_device_information(
        &mut self,
        candidate: &Candidate,
        start_index: u8,
    ) -> Result<(), NwkStatus> {
        let mut m = self.take_machines().ok_or(NwkStatus::InvalidRequest)?;
        let r = m
            .initiator
            .request_device_information(self, candidate, start_index);
        self.put_machines(m);
        self.pump();
        r.map_err(|_| NwkStatus::InvalidRequest)
    }

    fn on_initiator_outcome(&mut self, o: InitiatorOutcome) {
        let done = !matches!(
            o,
            InitiatorOutcome::Discovered(_) | InitiatorOutcome::DeviceInformation(_)
        );
        let event = match o {
            InitiatorOutcome::Discovered(c) => TouchlinkEvent::Discovered {
                count: u8::try_from(c.len()).unwrap_or(u8::MAX),
            },
            InitiatorOutcome::DeviceInformation(d) => TouchlinkEvent::DeviceInformation(d),
            InitiatorOutcome::Success { target, short } => {
                TouchlinkEvent::Success { target, short }
            }
            InitiatorOutcome::ResetSent => TouchlinkEvent::ResetSent,
            InitiatorOutcome::Failed(f) => TouchlinkEvent::Failed(f),
        };
        if done {
            self.restore_touchlink_channel();
        }
        self.push_event(StackEvent::Touchlink(event));
    }

    fn on_target_outcome(&mut self, o: TargetOutcome) {
        let event = match o {
            TargetOutcome::Responded { initiator } => TouchlinkEvent::Scanned { initiator },
            TargetOutcome::Started { initiator } => TouchlinkEvent::Started { initiator },
            TargetOutcome::Joined { initiator } => TouchlinkEvent::Joined { initiator },
            // `factory_reset` already reported `StackEvent::FactoryReset`.
            TargetOutcome::Reset => return,
            TargetOutcome::Refused => TouchlinkEvent::Refused,
        };
        self.push_event(StackEvent::Touchlink(event));
    }

    /// Returns to the operating channel after a scan.
    fn restore_touchlink_channel(&mut self) {
        if let Some(t) = self.touchlink.as_mut()
            && let Some(ch) = t.restore_channel.take()
            && self.phase == Phase::Operating
        {
            let page = self.nwk.nib.channel_page;
            self.mac.set_channel(page, ch);
        }
    }

    /// An inter-PAN frame from the MAC.
    pub(crate) fn on_inter_pan(&mut self, frame: &MacFrame<'_>, rssi: i8, channel: Channel) {
        let Some(src) = frame.header.src.extended() else {
            return;
        };
        let Some(src_pan) = frame.header.effective_src_pan() else {
            return;
        };
        let Ok((ip, zcl)) = InterPanHeader::decode(frame.payload) else {
            return;
        };
        if ip.cluster != tl::ID || ip.profile != tl::PROFILE_ID || ip.secured {
            return;
        }
        let Ok((header, n)) = Header::decode_prefix(zcl) else {
            return;
        };
        let payload = zcl.get(n..).unwrap_or(&[]);
        let Some(mut m) = self.take_machines() else {
            return;
        };
        let command = header.command;
        match header.control.direction {
            Direction::ToServer => {
                let out = m
                    .target
                    .on_inter_pan(self, src, src_pan, channel, command, payload, rssi);
                self.put_machines(m);
                if let Some(o) = out {
                    self.on_target_outcome(o);
                }
            }
            Direction::ToClient => {
                let out = m
                    .initiator
                    .on_inter_pan(self, src, src_pan, command, payload, rssi);
                self.put_machines(m);
                if let Some(o) = out {
                    self.on_initiator_outcome(o);
                }
            }
        }
    }

    /// Advances the touchlink timers.
    pub(crate) fn poll_touchlink(&mut self, now: Instant) {
        let Some(mut m) = self.take_machines() else {
            return;
        };
        m.target.poll(now);
        let out = m.initiator.poll(self, now);
        self.put_machines(m);
        if let Some(o) = out {
            self.on_initiator_outcome(o);
        }
    }

    /// Earliest touchlink deadline.
    pub(crate) fn touchlink_deadline(&self) -> Option<Instant> {
        let m = self.touchlink.as_ref()?.machines.as_ref()?;
        match (m.initiator.next_deadline(), m.target.next_deadline()) {
            (Some(a), Some(b)) => Some(if a.as_millis() < b.as_millis() { a } else { b }),
            (a, None) => a,
            (None, b) => b,
        }
    }

    /// Applies network parameters deferred by a leave.
    pub(crate) fn apply_pending_touchlink(&mut self) {
        let Some(p) = self.touchlink.as_mut().and_then(|t| t.pending.take()) else {
            return;
        };
        let _ = match p {
            Pending::Start(params) => self.touchlink_start_network(&params),
            Pending::Join(params) => self.touchlink_join_network(&params),
            Pending::Adopt(params) => self.touchlink_adopt_network(&params),
        };
    }

    fn defer_or<F>(&mut self, pending: Pending, apply: F) -> Result<(), NodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), NodeError>,
    {
        if self.phase == Phase::Idle {
            return apply(self);
        }
        if let Some(t) = self.touchlink.as_mut() {
            t.pending = Some(pending);
        }
        self.leave_with(false, false).map_err(|_| NodeError::Busy)
    }

    fn touchlink_start_network(&mut self, p: &NetworkParams) -> Result<(), NodeError> {
        self.config.distributed = true;
        self.aps.aib.trust_center_address = ExtendedAddress::BROADCAST;
        self.form_network_params(&FormationParams {
            key: Some(p.key.clone()),
            extended_pan_id: Some(ExtendedAddress(p.extended_pan_id)),
            pan_id: Some(p.pan_id),
            channels: Some(ChannelMask(0).with(p.channel)),
            network_address: Some(p.short),
            update_id: p.update_id,
        })
        .map_err(|_| NodeError::Busy)
    }

    fn touchlink_join_network(&mut self, p: &NetworkParams) -> Result<(), NodeError> {
        self.config.distributed = true;
        match self.config.role {
            LogicalDeviceType::EndDevice => self.touchlink_adopt_network(p),
            _ => self
                .adopt_network(&AdoptParams {
                    extended_pan_id: ExtendedAddress(p.extended_pan_id),
                    pan_id: p.pan_id,
                    channel: p.channel,
                    network_address: Some(p.short),
                    key: p.key.clone(),
                    key_sequence: KeySequenceNumber(0),
                    update_id: p.update_id,
                    trust_center: ExtendedAddress::BROADCAST,
                })
                .map_err(|_| NodeError::Busy),
        }
    }

    /// Installs the parameters and rejoins (an end device or a factory
    /// new initiator, §12.1 step 18 / §12.2 step 21).
    fn touchlink_adopt_network(&mut self, p: &NetworkParams) -> Result<(), NodeError> {
        self.config.distributed = true;
        self.aps.aib.trust_center_address = ExtendedAddress::BROADCAST;
        self.network_key_sequence = KeySequenceNumber(0);
        self.nwk
            .set_network_key(KeySequenceNumber(0), p.key.clone(), true);
        self.nwk.nib.extended_pan_id = ExtendedAddress(p.extended_pan_id);
        self.nwk.nib.network_address = p.short;
        self.nwk.nib.update_id = p.update_id;
        self.join_on(
            JoinMode::SecuredRejoin,
            ChannelMask(0).with(p.channel),
            self.config.scan_duration,
        )
        .map_err(|_| NodeError::Busy)
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> TouchlinkNode for Stack<C, R, S> {
    fn now(&self) -> Instant {
        self.now
    }

    fn random_u32(&mut self) -> u32 {
        self.nwk.rng().next_u32()
    }

    fn ieee(&self) -> ExtendedAddress {
        self.config.ieee
    }

    fn role(&self) -> LogicalDeviceType {
        self.config.role
    }

    fn sub_devices(&self, out: &mut Vec<tl::DeviceRecord, MAX_SUB_DEVICES>) {
        for (i, d) in self.zdo.endpoints().iter().enumerate() {
            let _ = out.push(tl::DeviceRecord {
                ieee: self.config.ieee.0,
                endpoint: d.endpoint.0,
                profile: d.profile.0,
                device: d.device.0,
                version: d.device_version & 0x0f,
                group_count: 0,
                sort: u8::try_from(i + 1).unwrap_or(0),
            });
        }
    }

    fn network(&self) -> Option<NetworkInfo> {
        (self.phase == Phase::Operating).then(|| NetworkInfo {
            extended_pan_id: self.nwk.nib.extended_pan_id.0,
            pan_id: self.nwk.nib.pan_id,
            channel: self.nwk.nib.channel,
            update_id: self.nwk.nib.update_id,
            short: self.nwk.nib.network_address,
            centralized: self.aps.aib.trust_center_address != ExtendedAddress::BROADCAST,
        })
    }

    fn network_key(&self) -> Option<Key128> {
        self.nwk.security.keys.active().map(|s| s.key.clone())
    }

    fn set_channel(&mut self, channel: Channel) {
        let page = self.nwk.nib.channel_page;
        self.mac.set_channel(page, channel);
    }

    fn send_inter_pan(
        &mut self,
        dst: InterPanDestination,
        src_pan: PanId,
        command: CommandId,
        direction: Direction,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let seq = {
            let t = self.touchlink.as_mut().ok_or(NodeError::Unsupported)?;
            t.seq = t.seq.wrapping_add(1);
            t.seq
        };
        let (mac_dst, delivery, ack) = match dst {
            InterPanDestination::Broadcast => (
                MacAddress::Short(ShortAddress::BROADCAST_ALL),
                InterPanDelivery::Broadcast,
                false,
            ),
            InterPanDestination::Device(e) => {
                (MacAddress::Extended(e), InterPanDelivery::Unicast, true)
            }
        };
        let mut buf = [0u8; 100];
        let mut w = Writer::new(&mut buf);
        InterPanHeader::new(delivery, tl::ID, tl::PROFILE_ID)
            .encode(&mut w)
            .map_err(|_| NodeError::Unsupported)?;
        let header = Header::cluster_specific(TransactionSequence(seq), command, direction)
            .disable_default_response(true);
        ZclFrame { header, payload }
            .encode(&mut w)
            .map_err(|_| NodeError::Unsupported)?;
        let n = w.position();
        self.mac
            .data_request_inter_pan(
                PanId::BROADCAST,
                mac_dst,
                src_pan,
                buf.get(..n).unwrap_or(&[]),
                ack,
            )
            .map(|_| ())
            .map_err(|_| NodeError::Busy)
    }

    fn identify(&mut self, seconds: u16) {
        let endpoints: Vec<_, 8> = self.zdo.endpoints().iter().map(|d| d.endpoint).collect();
        for ep in endpoints {
            let _ = self.zcl.set_identify_time(ep, seconds);
        }
    }

    fn key_bitmask(&self) -> u16 {
        let mut mask = 1 << tl_security::KEY_INDEX_CERTIFICATION;
        if self
            .touchlink
            .as_ref()
            .is_some_and(|t| t.master_key.is_some())
        {
            mask |= 1 << tl_security::KEY_INDEX_MASTER;
        }
        mask
    }

    fn encrypt_network_key(
        &mut self,
        key_index: u8,
        transaction: u32,
        response: u32,
        key: &Key128,
    ) -> Option<[u8; 16]> {
        let master = self.touchlink.as_ref().and_then(|t| t.master_key.clone());
        tl_security::encrypt_network_key::<C>(
            key_index,
            master.as_ref(),
            transaction,
            response,
            key,
        )
    }

    fn decrypt_network_key(
        &mut self,
        key_index: u8,
        transaction: u32,
        response: u32,
        encrypted: &[u8; 16],
    ) -> Option<Key128> {
        let master = self.touchlink.as_ref().and_then(|t| t.master_key.clone());
        tl_security::decrypt_network_key::<C>(
            key_index,
            master.as_ref(),
            transaction,
            response,
            encrypted,
        )
    }

    fn start_network(&mut self, params: &NetworkParams) -> Result<(), NodeError> {
        let p = params.clone();
        self.defer_or(Pending::Start(params.clone()), move |s| {
            s.touchlink_start_network(&p)
        })
    }

    fn join_network(&mut self, params: &NetworkParams) -> Result<(), NodeError> {
        let p = params.clone();
        self.defer_or(Pending::Join(params.clone()), move |s| {
            s.touchlink_join_network(&p)
        })
    }

    fn adopt_network(&mut self, params: &NetworkParams) -> Result<(), NodeError> {
        let p = params.clone();
        self.defer_or(Pending::Adopt(params.clone()), move |s| {
            s.touchlink_adopt_network(&p)
        })
    }

    fn update_network(&mut self, update_id: u8, channel: Channel) {
        self.nwk.nib.update_id = update_id;
        self.nwk.nib.channel = channel;
        let page = self.nwk.nib.channel_page;
        self.mac.set_channel(page, channel);
        let _ = self.persist_nib();
    }

    fn factory_reset(&mut self) {
        if self.phase != Phase::Idle {
            let _ = self.leave_with(false, false);
        }
        let _ = self.erase_persisted();
        self.push_event(StackEvent::FactoryReset);
    }
}
