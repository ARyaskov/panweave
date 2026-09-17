//! The Zigbee Device Object (R23.2 §2.5) as a sans-I/O state machine:
//! ZDP server processing (§2.4.4), ZDP client requests with response
//! matching and timeouts (§2.4.3, `apsZdoResponseTimeout`), device and
//! parent announcements.
//!
//! Network and APS state the ZDO needs (neighbour/route/binding tables,
//! permit joining, leave) is reached through the [`ZdoContext`] trait,
//! which the runtime implements over the NWK and APS layers.

use heapless::{Deque, Vec};
use panweave_aps::layer::{DataIndication, Delivery, RelayInfo, SecurityStatus};
use panweave_codec::{Decode, Encode, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, Endpoint, ExtendedAddress, LogicalDeviceType, MacCapability, ProfileId,
    ShortAddress, TransactionSequence,
};

use panweave_codec::tlv::{self, Tlv};
use panweave_nwk::tlv::tag as tlv_tag;

use crate::descriptor::{NodeDescriptor, PowerDescriptor, SimpleDescriptor};
use crate::security::{self, GetConfigurationReq, SelectedKeyNegotiationMethod};
use crate::zdp::{
    ActiveEpReq, AddrRequestType, AddrRsp, BindReq, ClearAllBindingsReq, DeviceAnnce,
    EndpointListRsp, IeeeAddrReq, MatchDescReq, MgmtBindReq, MgmtLeaveReq, MgmtLqiReq,
    MgmtNwkBeaconSurveyReq, MgmtNwkBeaconSurveyRsp, MgmtNwkEnhancedUpdateReq,
    MgmtNwkIeeeJoiningListReq, MgmtNwkIeeeJoiningListRsp, MgmtNwkUpdateNotify, MgmtNwkUpdateReq,
    MgmtPermitJoiningReq, MgmtRtgReq, NeighborRecord, NodeDescReq, NodeDescRsp, NwkAddrReq,
    ParentAnnce, ParentAnnceRsp, PowerDescReq, PowerDescRsp, RouteRecord, SimpleDescReq,
    SimpleDescRsp, StatusRsp, SystemServerDiscoveryReq, SystemServerDiscoveryRsp, TableRsp,
    U16List, ZdpFrame, ZdpStatus, cluster,
};

/// Largest ZDP frame (transaction data) built by the ZDO. Unfragmented
/// ZDO messages must fit the APS payload (§2.4.2.8.3).
pub const MAX_ZDP: usize = 96;

/// Outstanding client requests.
pub const PENDING_REQUESTS: usize = 8;

/// Queue capacity.
pub const QUEUE_CAPACITY: usize = 8;

/// A ZDP frame buffer.
pub type ZdpBuf = Vec<u8, MAX_ZDP>;

/// What the ZDO needs from the network and APS layers.
pub trait ZdoContext {
    /// Local network address.
    fn local_short(&self) -> ShortAddress;
    /// Local IEEE address.
    fn local_ieee(&self) -> ExtendedAddress;
    /// Extended PAN identifier of the current network.
    fn extended_pan_id(&self) -> ExtendedAddress;
    /// The Trust Center's IEEE address (all ones on a distributed network).
    fn trust_center(&self) -> ExtendedAddress;
    /// This device is the Trust Center.
    fn is_trust_center(&self) -> bool;
    /// This device is joined but not yet authorized (no network key):
    /// the Trust Center may still be unknown (§4.6.3.2.3).
    fn awaiting_authorization(&self) -> bool;
    /// Logical device type.
    fn logical_type(&self) -> LogicalDeviceType;
    /// Calls `f` for every end-device child (address discovery, §2.4.3.1.1).
    fn end_device_children(&self, f: &mut dyn FnMut(ExtendedAddress, ShortAddress));
    /// Number of neighbour table entries (Mgmt_Lqi).
    fn neighbor_count(&self) -> u8;
    /// Neighbour record at `index`.
    fn neighbor_record(&self, index: u8) -> Option<NeighborRecord>;
    /// Number of routing table entries (Mgmt_Rtg).
    fn route_count(&self) -> u8;
    /// Routing record at `index`.
    fn route_record(&self, index: u8) -> Option<RouteRecord>;
    /// Number of binding table entries (Mgmt_Bind).
    fn binding_count(&self) -> u8;
    /// Binding record at `index`.
    fn binding_record(&self, index: u8) -> Option<BindReq>;
    /// APSME-BIND.request.
    fn bind(&mut self, req: &BindReq) -> ZdpStatus;
    /// APSME-UNBIND.request.
    fn unbind(&mut self, req: &BindReq) -> ZdpStatus;
    /// Removes bindings towards `device` (`ExtendedAddress::BROADCAST` =
    /// all).
    fn clear_bindings(&mut self, device: ExtendedAddress);
    /// NLME-PERMIT-JOINING.request; `from_trust_center` tells a Trust
    /// Center whether to apply its policy (§4.7.3.4).
    fn permit_joining(&mut self, duration: u8, from_trust_center: bool) -> ZdpStatus;
    /// `mibJoiningPolicy` and `IeeeJoiningListUpdateID` of the enabled
    /// MAC interface (Mgmt_NWK_IEEE_Joining_List, §2.4.3.3.11.2).
    fn joining_policy(&self) -> (u8, u8) {
        (0, 0)
    }
    /// Entry `index` of `mibJoiningIeeeList`, `None` past the end.
    fn joining_list_entry(&self, index: u8) -> Option<ExtendedAddress> {
        let _ = index;
        None
    }
    /// Applies a Mgmt_NWK_IEEE_Joining_List_rsp (§2.4.4.3.11.2).
    fn set_joining_list(
        &mut self,
        policy: u8,
        total: u8,
        start_index: u8,
        entries: &[ExtendedAddress],
    ) {
        let _ = (policy, total, start_index, entries);
    }
    /// Stores the network-wide beacon appendix TLVs (Mgmt_Permit_Joining
    /// from the Trust Center, §2.4.3.3.7.2).
    fn set_beacon_appendix(&mut self, tlvs: &[u8]);
    /// NLME-LEAVE.request for `device` (zero = this device).
    fn leave(&mut self, device: ExtendedAddress, remove_children: bool, rejoin: bool) -> ZdpStatus;
    /// A Device_annce was received: update address maps and detect
    /// conflicts (§2.4.3.1.11.2).
    fn device_announced(
        &mut self,
        ieee: ExtendedAddress,
        short: ShortAddress,
        capability: MacCapability,
    );
    /// A Parent_annce listed `child` as another router's child; returns
    /// true when it is our end-device child with keepalive received so
    /// that it is reported back (§2.4.3.1.12.2).
    fn claims_child(&self, child: ExtendedAddress) -> bool;
    /// A Parent_annce_rsp says `child` is also claimed by `router`; the
    /// local entry should be removed (§2.4.4.2.19).
    fn child_claimed_elsewhere(&mut self, child: ExtendedAddress, router: ShortAddress);

    // ---- Security services (§2.4.3.4) --------------------------------

    /// APSME-KEY-NEGOTIATION.indication for a Security_Start_Key_Negotiation_req
    /// from `partner` carrying its public `point`; derives the link key
    /// and returns the local public point (§2.4.3.4.1.4). `aps_encrypted`
    /// reports the request's APS security so that the authorization rule
    /// of §2.4.4.4.1 can be applied.
    fn key_negotiation(
        &mut self,
        partner: ExtendedAddress,
        point: &[u8; 32],
        aps_encrypted: bool,
    ) -> Result<[u8; 32], ZdpStatus>;
    /// Security_Retrieve_Authentication_Token_req at the Trust Center:
    /// the passphrase to hand to `requester` (§2.4.3.4.2.4 steps 2–7).
    fn authentication_token(&mut self, requester: ExtendedAddress) -> Result<[u8; 16], ZdpStatus>;
    /// Security_Get_Authentication_Level_req: (InitialJoinMethod,
    /// ActiveLinkKeyType) of `target` from the key-pair set
    /// (§2.4.3.4.3.4 steps 6–8).
    fn authentication_level(&self, target: ExtendedAddress) -> Result<(u8, u8), ZdpStatus>;
    /// Security_Start_Key_Update_req from the Trust Center: start the
    /// selected method (§2.4.3.4.6.4 steps 4–5). Returns `NoMatch` when
    /// the method is unsupported.
    fn start_key_update(
        &mut self,
        method: &SelectedKeyNegotiationMethod,
        via: Option<RelayInfo>,
    ) -> ZdpStatus;
    /// Security_Decommission_req: removes the key-pair entries and
    /// bindings of `devices`; true when something was removed
    /// (§2.4.3.4.7.4 steps 7–8).
    fn decommission(&mut self, devices: &[ExtendedAddress]) -> bool;
    /// Security_Set_Configuration_req: applies one global TLV
    /// (§2.4.3.4.4.3 step 3).
    fn set_configuration(&mut self, tlv: &Tlv<'_>) -> ZdpStatus;
    /// Security_Get_Configuration_req: writes the current value of the
    /// global TLV `tag`; false when the device has no value for it
    /// (§2.4.3.4.5.2 step 2).
    fn get_configuration(&mut self, tag: u8, w: &mut Writer<'_>) -> bool;
    /// Security_Challenge_req from `sender` (§4.6.3.8.4): the responder's
    /// current APS frame counter, the challenge frame counter used and
    /// the MIC; `None` without a key-pair entry for the sender.
    fn answer_frame_counter_challenge(
        &mut self,
        sender: ExtendedAddress,
        challenge: u64,
    ) -> Option<(u32, u32, [u8; 8])>;
}

/// Outputs for the runtime.
#[derive(Debug)]
pub enum ZdoAction {
    /// Send a ZDP frame (profile 0x0000, endpoints 0) to `dst`. Unicasts
    /// request an APS acknowledgement (§2.4.2.8.4).
    Send {
        /// Destination network address (may be a broadcast address).
        dst: ShortAddress,
        /// ZDP cluster.
        cluster: ClusterId,
        /// Complete ZDP frame (sequence number and data).
        frame: ZdpBuf,
        /// Reply through a relay (the request arrived relayed).
        via: Option<RelayInfo>,
        /// APS-encrypt the frame with the destination's link key (the
        /// security services of §2.4.3.4 and their responses).
        secure: bool,
    },
}

/// Events for the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZdoEvent {
    /// No response arrived within `apsZdoResponseTimeout`.
    Timeout {
        /// Transaction sequence of the request.
        seq: TransactionSequence,
        /// Request cluster.
        cluster: ClusterId,
        /// Destination of the request.
        dst: ShortAddress,
    },
    /// A Mgmt_NWK_Update_req needs an energy scan, channel change or
    /// attribute update; reply with [`Zdo::nwk_update_notify`] for scans.
    NwkUpdateRequest {
        /// Requester.
        src: ShortAddress,
        /// Transaction sequence to echo.
        seq: TransactionSequence,
        /// The request.
        req: MgmtNwkUpdateReq,
        /// The request was broadcast (no error responses).
        broadcast: bool,
    },
    /// A Mgmt_NWK_Enhanced_Update_req (§2.4.3.3.10): the same processing
    /// as [`ZdoEvent::NwkUpdateRequest`] on the single page carried, or
    /// an enhanced scan when asked for; reply with
    /// [`Zdo::nwk_enhanced_update_notify`].
    NwkEnhancedUpdateRequest {
        /// Requester.
        src: ShortAddress,
        /// Transaction sequence to echo.
        seq: TransactionSequence,
        /// The request.
        req: MgmtNwkEnhancedUpdateReq,
        /// The request was broadcast (no error responses).
        broadcast: bool,
    },
    /// A unicast Mgmt_NWK_Beacon_Survey_req (§2.4.3.3.12): run the scan
    /// and reply with [`Zdo::beacon_survey_rsp`].
    BeaconSurveyRequest {
        /// Requester.
        src: ShortAddress,
        /// Transaction sequence to echo.
        seq: TransactionSequence,
        /// The request.
        req: MgmtNwkBeaconSurveyReq,
    },
    /// A Mgmt_NWK_IEEE_Joining_List_rsp arrived (solicited or as the
    /// unsolicited broadcast) and was applied to the joining list.
    JoiningListUpdated,
}

/// A received ZDP frame of interest to the application.
#[derive(Clone, Copy, Debug)]
pub enum ZdoIndication<'a> {
    /// A response (cluster with bit 15 set) or notify.
    Response {
        /// Sender.
        src: ShortAddress,
        /// Transaction sequence.
        seq: TransactionSequence,
        /// Response cluster.
        cluster: ClusterId,
        /// Transaction data (decode with the `zdp` types).
        data: &'a [u8],
        /// The response matched an outstanding request.
        matched: bool,
        /// Sender IEEE address when known.
        src_ieee: Option<ExtendedAddress>,
        /// APS security of the frame.
        security: SecurityStatus,
        /// The response arrived through a relay.
        relayed: Option<RelayInfo>,
    },
    /// Device_annce received (already applied through the context).
    DeviceAnnounce {
        /// Sender.
        src: ShortAddress,
        /// Announced IEEE address.
        ieee: ExtendedAddress,
        /// Announced network address.
        short: ShortAddress,
        /// Capability.
        capability: MacCapability,
    },
}

/// Request errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ZdoError {
    /// The frame does not fit.
    TooLarge,
    /// Too many outstanding requests.
    Busy,
    /// Invalid parameter.
    InvalidParameter,
}

struct PendingRequest {
    seq: TransactionSequence,
    cluster: ClusterId,
    dst: ShortAddress,
    deadline: Instant,
}

/// The ZDO.
pub struct Zdo<const EPS: usize> {
    /// Node descriptor.
    pub node: NodeDescriptor,
    /// Node power descriptor.
    pub power: PowerDescriptor,
    /// `apsZdoRestrictedMode`.
    pub restricted_mode: bool,
    /// `apsZdoResponseTimeout`.
    pub response_timeout: Duration,
    endpoints: Vec<SimpleDescriptor, EPS>,
    seq: TransactionSequence,
    pending: Vec<PendingRequest, PENDING_REQUESTS>,
    actions: Deque<ZdoAction, QUEUE_CAPACITY>,
    events: Deque<ZdoEvent, QUEUE_CAPACITY>,
    now: Instant,
    /// Events dropped on queue overflow.
    pub dropped: u32,
}

impl<const EPS: usize> Zdo<EPS> {
    /// Creates a ZDO with the given descriptors.
    pub fn new(node: NodeDescriptor, power: PowerDescriptor) -> Self {
        Zdo {
            node,
            power,
            restricted_mode: false,
            response_timeout: Duration::from_secs(3),
            endpoints: Vec::new(),
            seq: TransactionSequence(0),
            pending: Vec::new(),
            actions: Deque::new(),
            events: Deque::new(),
            now: Instant::from_millis(0),
            dropped: 0,
        }
    }

    /// Registers an application endpoint (simple descriptor).
    pub fn add_endpoint(&mut self, desc: SimpleDescriptor) -> Result<(), SimpleDescriptor> {
        if desc.endpoint == Endpoint(0)
            || desc.endpoint == Endpoint::BROADCAST
            || self.endpoints.iter().any(|d| d.endpoint == desc.endpoint)
        {
            return Err(desc);
        }
        self.endpoints.push(desc)
    }

    /// Registered endpoints.
    pub fn endpoints(&self) -> &[SimpleDescriptor] {
        &self.endpoints
    }

    /// The simple descriptor of `endpoint`.
    pub fn endpoint(&self, endpoint: Endpoint) -> Option<&SimpleDescriptor> {
        self.endpoints.iter().find(|d| d.endpoint == endpoint)
    }

    /// Next action.
    pub fn next_action(&mut self) -> Option<ZdoAction> {
        self.actions.pop_front()
    }

    /// Next event.
    pub fn next_event(&mut self) -> Option<ZdoEvent> {
        self.events.pop_front()
    }

    /// Advances time; expires outstanding requests.
    pub fn poll_timers(&mut self, now: Instant) {
        self.now = now;
        let mut i = 0;
        while i < self.pending.len() {
            let expired = self
                .pending
                .get(i)
                .is_some_and(|p| now.has_reached(p.deadline));
            if expired {
                let p = self.pending.swap_remove(i);
                self.push_event(ZdoEvent::Timeout {
                    seq: p.seq,
                    cluster: p.cluster,
                    dst: p.dst,
                });
            } else {
                i += 1;
            }
        }
    }

    /// Earliest deadline.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .map(|p| p.deadline)
            .min_by_key(|d| d.as_millis())
    }

    fn push_event(&mut self, e: ZdoEvent) {
        if self.events.push_back(e).is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn push_action(&mut self, a: ZdoAction) {
        if self.actions.push_back(a).is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn next_seq(&mut self) -> TransactionSequence {
        let s = self.seq;
        self.seq = s.wrapping_next();
        s
    }

    fn frame(seq: TransactionSequence, payload: &impl Encode) -> Result<ZdpBuf, ZdoError> {
        let mut buf = ZdpBuf::new();
        buf.resize(MAX_ZDP, 0).map_err(|_| ZdoError::TooLarge)?;
        let mut w = Writer::new(buf.as_mut_slice());
        w.u8(seq.0).map_err(|_| ZdoError::TooLarge)?;
        payload.encode(&mut w).map_err(|_| ZdoError::TooLarge)?;
        let n = w.position();
        buf.truncate(n);
        Ok(buf)
    }

    /// Sends a ZDP request and tracks the response (unicast) or fires
    /// and forgets (broadcast). Returns the transaction sequence.
    pub fn request(
        &mut self,
        dst: ShortAddress,
        cluster: ClusterId,
        payload: &impl Encode,
    ) -> Result<TransactionSequence, ZdoError> {
        if cluster::is_response(cluster) {
            return Err(ZdoError::InvalidParameter);
        }
        let seq = self.next_seq();
        let frame = Self::frame(seq, payload)?;
        if dst.is_unicast() {
            self.pending
                .push(PendingRequest {
                    seq,
                    cluster,
                    dst,
                    deadline: self.now.saturating_add(self.response_timeout),
                })
                .map_err(|_| ZdoError::Busy)?;
        }
        self.push_action(ZdoAction::Send {
            dst,
            cluster,
            frame,
            via: None,
            secure: false,
        });
        Ok(seq)
    }

    /// Sends a tracked request through a relay (a joining device towards
    /// the Trust Center, or the Trust Center towards a joiner, §4.6.3.5).
    pub fn request_via(
        &mut self,
        dst: ShortAddress,
        cluster: ClusterId,
        payload: &impl Encode,
        via: RelayInfo,
    ) -> Result<TransactionSequence, ZdoError> {
        if cluster::is_response(cluster) {
            return Err(ZdoError::InvalidParameter);
        }
        let seq = self.next_seq();
        let frame = Self::frame(seq, payload)?;
        self.pending
            .push(PendingRequest {
                seq,
                cluster,
                dst,
                deadline: self.now.saturating_add(self.response_timeout),
            })
            .map_err(|_| ZdoError::Busy)?;
        self.push_action(ZdoAction::Send {
            dst,
            cluster,
            frame,
            via: Some(via),
            secure: false,
        });
        Ok(seq)
    }

    /// Sends a ZDP request without tracking a response (announcements,
    /// notifications).
    pub fn send_unsolicited(
        &mut self,
        dst: ShortAddress,
        cluster: ClusterId,
        payload: &impl Encode,
    ) -> Result<TransactionSequence, ZdoError> {
        let seq = self.next_seq();
        let frame = Self::frame(seq, payload)?;
        self.push_action(ZdoAction::Send {
            dst,
            cluster,
            frame,
            via: None,
            secure: false,
        });
        Ok(seq)
    }

    fn respond(
        &mut self,
        dst: ShortAddress,
        seq: TransactionSequence,
        request_cluster: ClusterId,
        payload: &impl Encode,
        via: Option<RelayInfo>,
    ) {
        self.respond_with(dst, seq, request_cluster, payload, via, false);
    }

    fn respond_with(
        &mut self,
        dst: ShortAddress,
        seq: TransactionSequence,
        request_cluster: ClusterId,
        payload: &impl Encode,
        via: Option<RelayInfo>,
        secure: bool,
    ) {
        if let Ok(frame) = Self::frame(seq, payload) {
            self.push_action(ZdoAction::Send {
                dst,
                cluster: cluster::response_of(request_cluster),
                frame,
                via,
                secure,
            });
        }
    }

    /// Sends a tracked request APS-encrypted with `dst`'s link key
    /// (Security_Retrieve_Authentication_Token_req,
    /// Security_Get_Authentication_Level_req, …, §2.4.3.4).
    pub fn request_secured(
        &mut self,
        dst: ShortAddress,
        cluster: ClusterId,
        payload: &impl Encode,
    ) -> Result<TransactionSequence, ZdoError> {
        if cluster::is_response(cluster) {
            return Err(ZdoError::InvalidParameter);
        }
        let seq = self.next_seq();
        let frame = Self::frame(seq, payload)?;
        self.pending
            .push(PendingRequest {
                seq,
                cluster,
                dst,
                deadline: self.now.saturating_add(self.response_timeout),
            })
            .map_err(|_| ZdoError::Busy)?;
        self.push_action(ZdoAction::Send {
            dst,
            cluster,
            frame,
            via: None,
            secure: true,
        });
        Ok(seq)
    }

    /// Broadcasts Device_annce (§2.4.3.1.11).
    pub fn device_announce(
        &mut self,
        short: ShortAddress,
        ieee: ExtendedAddress,
        capability: MacCapability,
    ) -> Result<TransactionSequence, ZdoError> {
        self.send_unsolicited(
            ShortAddress::BROADCAST_RX_ON,
            cluster::DEVICE_ANNCE,
            &DeviceAnnce {
                short,
                ieee,
                capability,
            },
        )
    }

    /// Broadcasts Parent_annce (§2.4.3.1.12) with the given end-device
    /// children (at most those that fit in one frame; the caller sends
    /// additional messages for the rest).
    pub fn parent_announce(&mut self, children: &[ExtendedAddress]) -> Result<usize, ZdoError> {
        let max = (MAX_ZDP - 2) / 8;
        let n = children.len().min(max);
        let mut bytes: Vec<u8, MAX_ZDP> = Vec::new();
        for c in children.iter().take(n) {
            bytes
                .extend_from_slice(&c.to_le_bytes())
                .map_err(|_| ZdoError::TooLarge)?;
        }
        self.send_unsolicited(
            ShortAddress::BROADCAST_ROUTERS,
            cluster::PARENT_ANNCE,
            &ParentAnnce {
                children: crate::zdp::Eui64List(&bytes),
            },
        )?;
        Ok(n)
    }

    /// Sends a Mgmt_NWK_Update_notify (energy scan results) in reply to a
    /// [`ZdoEvent::NwkUpdateRequest`].
    pub fn nwk_update_notify(
        &mut self,
        dst: ShortAddress,
        seq: TransactionSequence,
        notify: &MgmtNwkUpdateNotify<'_>,
    ) {
        self.respond(dst, seq, cluster::MGMT_NWK_UPDATE_REQ, notify, None);
    }

    /// Sends a Mgmt_NWK_Enhanced_Update_notify in reply to a
    /// [`ZdoEvent::NwkEnhancedUpdateRequest`].
    pub fn nwk_enhanced_update_notify(
        &mut self,
        dst: ShortAddress,
        seq: TransactionSequence,
        notify: &MgmtNwkUpdateNotify<'_>,
    ) {
        self.respond(
            dst,
            seq,
            cluster::MGMT_NWK_ENHANCED_UPDATE_REQ,
            notify,
            None,
        );
    }

    /// Sends a Mgmt_NWK_Beacon_Survey_rsp in reply to a
    /// [`ZdoEvent::BeaconSurveyRequest`].
    pub fn beacon_survey_rsp(
        &mut self,
        dst: ShortAddress,
        seq: TransactionSequence,
        rsp: &MgmtNwkBeaconSurveyRsp,
    ) {
        self.respond(dst, seq, cluster::MGMT_NWK_BEACON_SURVEY_REQ, rsp, None);
    }

    /// Sends a Mgmt_NWK_Unsolicited_Enhanced_Update_notify to the network
    /// manager (§2.4.4.3.12).
    pub fn unsolicited_enhanced_update_notify(
        &mut self,
        manager: ShortAddress,
        notify: &crate::zdp::MgmtNwkUnsolicitedEnhancedUpdateNotify,
    ) -> Result<TransactionSequence, ZdoError> {
        self.send_unsolicited(
            manager,
            cluster::MGMT_NWK_UNSOLICITED_ENHANCED_UPDATE_NOTIFY,
            notify,
        )
    }

    /// Broadcasts the joining list to the network (the unsolicited
    /// Mgmt_NWK_IEEE_Joining_List_rsp of §2.4.4.3.11.1): one frame per
    /// fragment of `entries`, which are the addresses from `start_index`.
    pub fn broadcast_joining_list(
        &mut self,
        update_id: u8,
        policy: u8,
        total: u8,
        start_index: u8,
        entries: &[ExtendedAddress],
    ) -> Result<(), ZdoError> {
        let mut bytes: Vec<u8, 64> = Vec::new();
        for e in entries {
            bytes
                .extend_from_slice(&e.0.to_le_bytes())
                .map_err(|_| ZdoError::TooLarge)?;
        }
        let rsp = MgmtNwkIeeeJoiningListRsp {
            status: ZdpStatus::Success,
            update_id,
            policy,
            total,
            start_index,
            list: crate::zdp::Eui64List(&bytes),
        };
        self.send_unsolicited(
            ShortAddress::BROADCAST_RX_ON,
            cluster::response_of(cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ),
            &rsp,
        )
        .map(|_| ())
    }

    /// Answers a Mgmt_NWK_IEEE_Joining_List_req from the context's
    /// joining list (§2.4.3.3.11.2 steps 2–5).
    fn answer_joining_list(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        req: MgmtNwkIeeeJoiningListReq,
        ctx: &impl ZdoContext,
        via: Option<RelayInfo>,
    ) {
        let (policy, update_id) = ctx.joining_policy();
        let mut total: u8 = 0;
        while total < u8::MAX && ctx.joining_list_entry(total).is_some() {
            total += 1;
        }
        if total == 0 {
            let rsp = MgmtNwkIeeeJoiningListRsp {
                status: ZdpStatus::Success,
                update_id,
                policy,
                total: 0,
                start_index: 0,
                list: crate::zdp::Eui64List(&[]),
            };
            self.respond(src, seq, cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ, &rsp, via);
            return;
        }
        if req.start_index >= total {
            let rsp = MgmtNwkIeeeJoiningListRsp {
                status: ZdpStatus::InvalidIndex,
                update_id: 0,
                policy: 0,
                total: 0,
                start_index: 0,
                list: crate::zdp::Eui64List(&[]),
            };
            self.respond(src, seq, cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ, &rsp, via);
            return;
        }
        // Fill up to the MTU: the fixed part is 6 octets plus the ZDP
        // sequence, leaving room for eight addresses.
        let mut bytes: Vec<u8, 64> = Vec::new();
        let mut i = req.start_index;
        while let Some(e) = ctx.joining_list_entry(i) {
            if bytes.extend_from_slice(&e.0.to_le_bytes()).is_err() {
                break;
            }
            i = i.saturating_add(1);
            if i == u8::MAX {
                break;
            }
        }
        let rsp = MgmtNwkIeeeJoiningListRsp {
            status: ZdpStatus::Success,
            update_id,
            policy,
            total,
            start_index: req.start_index,
            list: crate::zdp::Eui64List(&bytes),
        };
        self.respond(src, seq, cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ, &rsp, via);
    }

    /// Processes an APSDE-DATA.indication for endpoint 0 / profile 0.
    pub fn on_data<'a>(
        &mut self,
        ind: &DataIndication<'a>,
        ctx: &mut impl ZdoContext,
    ) -> Option<ZdoIndication<'a>> {
        if ind.profile != ProfileId::ZDP {
            return None;
        }
        if !matches!(
            ind.delivery,
            Delivery::Endpoint(Endpoint(0)) | Delivery::AllEndpoints
        ) {
            return None;
        }
        let frame = ZdpFrame::decode_exact(ind.asdu).ok()?;
        if cluster::is_response(ind.cluster) {
            if ind.cluster == cluster::response_of(cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ)
                && let Ok(rsp) = MgmtNwkIeeeJoiningListRsp::decode_exact(frame.data)
                && rsp.status == ZdpStatus::Success
            {
                // §2.4.4.3.11.2: solicited or the unsolicited broadcast.
                let mut entries: Vec<ExtendedAddress, 8> = Vec::new();
                for e in rsp.list.iter() {
                    let _ = entries.push(e);
                }
                ctx.set_joining_list(rsp.policy, rsp.total, rsp.start_index, &entries);
                self.push_event(ZdoEvent::JoiningListUpdated);
            }
            let matched = self
                .pending
                .iter()
                .position(|p| p.seq == frame.seq && cluster::response_of(p.cluster) == ind.cluster)
                .map(|i| {
                    self.pending.swap_remove(i);
                });
            return Some(ZdoIndication::Response {
                src: ind.src,
                seq: frame.seq,
                cluster: ind.cluster,
                data: frame.data,
                matched: matched.is_some(),
                src_ieee: ind.src_ieee,
                security: ind.security,
                relayed: ind.relayed,
            });
        }
        // Broadcast requests never generate error responses (§2.4.4.1).
        self.handle_request(ind, &frame, ind.nwk_broadcast, ctx)
    }

    fn restricted_ok(&self, ind: &DataIndication<'_>, ctx: &impl ZdoContext) -> bool {
        if !self.restricted_mode {
            return true;
        }
        ind.security == SecurityStatus::LinkKey && ind.src_ieee == Some(ctx.trust_center())
    }

    #[allow(clippy::too_many_lines)]
    fn handle_request<'a>(
        &mut self,
        ind: &DataIndication<'a>,
        frame: &ZdpFrame<'a>,
        broadcast: bool,
        ctx: &mut impl ZdoContext,
    ) -> Option<ZdoIndication<'a>> {
        let src = ind.src;
        let seq = frame.seq;
        let data = frame.data;
        let via = ind.relayed;
        let me = ctx.local_short();
        match ind.cluster {
            cluster::NWK_ADDR_REQ => {
                let req = NwkAddrReq::decode_exact(data).ok()?;
                let mut found: Option<ShortAddress> = None;
                if req.ieee == ctx.local_ieee() {
                    found = Some(me);
                } else {
                    ctx.end_device_children(&mut |ieee, short| {
                        if ieee == req.ieee {
                            found = Some(short);
                        }
                    });
                }
                let Some(short) = found else {
                    if !broadcast {
                        self.respond(
                            src,
                            seq,
                            ind.cluster,
                            &AddrRsp {
                                status: ZdpStatus::DeviceNotFound,
                                ieee: req.ieee,
                                short: ShortAddress::BROADCAST_ALL,
                                associated: None,
                            },
                            via,
                        );
                    }
                    return None;
                };
                self.addr_response(
                    src,
                    seq,
                    ind.cluster,
                    req.request_type,
                    req.start_index,
                    req.ieee,
                    short,
                    broadcast,
                    via,
                    ctx,
                );
            }
            cluster::IEEE_ADDR_REQ => {
                let req = IeeeAddrReq::decode_exact(data).ok()?;
                let mut found: Option<ExtendedAddress> = None;
                if req.addr == me {
                    found = Some(ctx.local_ieee());
                } else {
                    ctx.end_device_children(&mut |ieee, short| {
                        if short == req.addr {
                            found = Some(ieee);
                        }
                    });
                }
                let Some(ieee) = found else {
                    if !broadcast {
                        self.respond(
                            src,
                            seq,
                            ind.cluster,
                            &AddrRsp {
                                status: ZdpStatus::DeviceNotFound,
                                ieee: ExtendedAddress::BROADCAST,
                                short: req.addr,
                                associated: None,
                            },
                            via,
                        );
                    }
                    return None;
                };
                self.addr_response(
                    src,
                    seq,
                    ind.cluster,
                    req.request_type,
                    req.start_index,
                    ieee,
                    req.addr,
                    broadcast,
                    via,
                    ctx,
                );
            }
            cluster::NODE_DESC_REQ => {
                let req = NodeDescReq::decode_exact(data).ok()?;
                let (status, descriptor) = if req.addr == me {
                    (ZdpStatus::Success, Some(self.node))
                } else {
                    (Self::not_local(ctx), None)
                };
                let mut tlv = [0u8; 8];
                let n = crate::fragmentation_parameters_tlv(&mut tlv, me, self.node);
                self.respond(
                    src,
                    seq,
                    ind.cluster,
                    &NodeDescRsp {
                        status,
                        addr: req.addr,
                        descriptor,
                        tlvs: tlv.get(..n).unwrap_or(&[]),
                    },
                    via,
                );
            }
            cluster::POWER_DESC_REQ => {
                let req = PowerDescReq::decode_exact(data).ok()?;
                let (status, descriptor) = if req.addr == me {
                    (ZdpStatus::Success, Some(self.power))
                } else {
                    (Self::not_local(ctx), None)
                };
                self.respond(
                    src,
                    seq,
                    ind.cluster,
                    &PowerDescRsp {
                        status,
                        addr: req.addr,
                        descriptor,
                    },
                    via,
                );
            }
            cluster::SIMPLE_DESC_REQ => {
                let req = SimpleDescReq::decode_exact(data).ok()?;
                let mut buf = [0u8; 72];
                let (status, desc): (ZdpStatus, Option<&[u8]>) = if req.addr != me {
                    (Self::not_local(ctx), None)
                } else if req.endpoint == Endpoint(0) || req.endpoint == Endpoint::BROADCAST {
                    (ZdpStatus::InvalidEndpoint, None)
                } else {
                    match self.endpoint(req.endpoint) {
                        Some(d) => match d.encode_to_slice(&mut buf) {
                            Ok(n) => (ZdpStatus::Success, Some(&buf[..n])),
                            Err(_) => (ZdpStatus::NoDescriptor, None),
                        },
                        None => (ZdpStatus::NotActive, None),
                    }
                };
                self.respond(
                    src,
                    seq,
                    ind.cluster,
                    &SimpleDescRsp {
                        status,
                        addr: req.addr,
                        descriptor: desc,
                    },
                    via,
                );
            }
            cluster::ACTIVE_EP_REQ => {
                let req = ActiveEpReq::decode_exact(data).ok()?;
                let mut eps: Vec<u8, EPS> = Vec::new();
                let status = if req.addr == me {
                    for d in &self.endpoints {
                        let _ = eps.push(d.endpoint.0);
                    }
                    ZdpStatus::Success
                } else {
                    Self::not_local(ctx)
                };
                self.respond(
                    src,
                    seq,
                    ind.cluster,
                    &EndpointListRsp {
                        status,
                        addr: req.addr,
                        endpoints: &eps,
                    },
                    via,
                );
            }
            cluster::MATCH_DESC_REQ => {
                let req = MatchDescReq::decode_exact(data).ok()?;
                if req.addr != me && req.addr != ShortAddress::BROADCAST_RX_ON {
                    if !broadcast {
                        self.respond(
                            src,
                            seq,
                            ind.cluster,
                            &EndpointListRsp {
                                status: Self::not_local(ctx),
                                addr: req.addr,
                                endpoints: &[],
                            },
                            via,
                        );
                    }
                    return None;
                }
                let mut eps: Vec<u8, EPS> = Vec::new();
                for d in &self.endpoints {
                    if Self::matches(d, &req) {
                        let _ = eps.push(d.endpoint.0);
                    }
                }
                if eps.is_empty() {
                    if !broadcast {
                        self.respond(
                            src,
                            seq,
                            ind.cluster,
                            &EndpointListRsp {
                                status: ZdpStatus::NoMatch,
                                addr: me,
                                endpoints: &[],
                            },
                            via,
                        );
                    }
                    return None;
                }
                self.respond(
                    src,
                    seq,
                    ind.cluster,
                    &EndpointListRsp {
                        status: ZdpStatus::Success,
                        addr: me,
                        endpoints: &eps,
                    },
                    via,
                );
            }
            cluster::DEVICE_ANNCE => {
                let a = DeviceAnnce::decode_exact(data).ok()?;
                ctx.device_announced(a.ieee, a.short, a.capability);
                return Some(ZdoIndication::DeviceAnnounce {
                    src,
                    ieee: a.ieee,
                    short: a.short,
                    capability: a.capability,
                });
            }
            cluster::PARENT_ANNCE => {
                if ctx.logical_type() == LogicalDeviceType::EndDevice {
                    return None;
                }
                let a = ParentAnnce::decode_exact(data).ok()?;
                let mut ours: Vec<u8, MAX_ZDP> = Vec::new();
                for child in a.children.iter() {
                    if ctx.claims_child(child)
                        && ours.extend_from_slice(&child.to_le_bytes()).is_err()
                    {
                        break;
                    }
                }
                if !ours.is_empty() {
                    self.respond(
                        src,
                        seq,
                        ind.cluster,
                        &ParentAnnceRsp {
                            status: ZdpStatus::Success,
                            children: crate::zdp::Eui64List(&ours),
                        },
                        via,
                    );
                }
            }
            cluster::SYSTEM_SERVER_DISCOVERY_REQ => {
                let req = SystemServerDiscoveryReq::decode_exact(data).ok()?;
                let matching = req.mask.servers() & self.node.server_mask.servers();
                if matching != 0 {
                    self.respond(
                        src,
                        seq,
                        ind.cluster,
                        &SystemServerDiscoveryRsp {
                            status: ZdpStatus::Success,
                            mask: crate::descriptor::ServerMask(matching),
                        },
                        via,
                    );
                }
            }
            cluster::BIND_REQ | cluster::UNBIND_REQ => {
                if broadcast {
                    return None;
                }
                let status = if !self.restricted_ok(ind, ctx) {
                    ZdpStatus::NotAuthorized
                } else {
                    match BindReq::decode_exact(data) {
                        Ok(req) => {
                            if req.src_endpoint == Endpoint(0)
                                || req.src_endpoint == Endpoint::BROADCAST
                            {
                                ZdpStatus::InvalidEndpoint
                            } else if req.src != ctx.local_ieee()
                                && ctx.logical_type() != LogicalDeviceType::Coordinator
                            {
                                ZdpStatus::NotSupported
                            } else if ind.cluster == cluster::BIND_REQ {
                                ctx.bind(&req)
                            } else {
                                ctx.unbind(&req)
                            }
                        }
                        Err(_) => ZdpStatus::InvalidRequestType,
                    }
                };
                self.respond(src, seq, ind.cluster, &StatusRsp { status }, via);
            }
            cluster::CLEAR_ALL_BINDINGS_REQ => {
                if broadcast {
                    return None;
                }
                let status = if !self.restricted_ok(ind, ctx) {
                    ZdpStatus::NotAuthorized
                } else {
                    let req = ClearAllBindingsReq::decode_exact(data).ok()?;
                    match req.eui64s() {
                        Some(list) => {
                            for e in list.iter() {
                                ctx.clear_bindings(e);
                            }
                            ZdpStatus::Success
                        }
                        None => ZdpStatus::InvalidRequestType,
                    }
                };
                self.respond(src, seq, ind.cluster, &StatusRsp { status }, via);
            }
            cluster::MGMT_LQI_REQ => {
                let req = MgmtLqiReq::decode_exact(data).ok()?;
                self.table_response::<NeighborRecord, 2>(
                    src,
                    seq,
                    ind.cluster,
                    req.start_index,
                    ctx.neighbor_count(),
                    |i| ctx.neighbor_record(i),
                    via,
                );
            }
            cluster::MGMT_RTG_REQ => {
                let req = MgmtRtgReq::decode_exact(data).ok()?;
                self.table_response::<RouteRecord, 8>(
                    src,
                    seq,
                    ind.cluster,
                    req.start_index,
                    ctx.route_count(),
                    |i| ctx.route_record(i),
                    via,
                );
            }
            cluster::MGMT_BIND_REQ => {
                let req = MgmtBindReq::decode_exact(data).ok()?;
                self.table_response::<BindReq, 3>(
                    src,
                    seq,
                    ind.cluster,
                    req.start_index,
                    ctx.binding_count(),
                    |i| ctx.binding_record(i),
                    via,
                );
            }
            cluster::MGMT_LEAVE_REQ => {
                let req = MgmtLeaveReq::decode_exact(data).ok()?;
                let status = if !self.restricted_ok(ind, ctx) {
                    ZdpStatus::NotAuthorized
                } else {
                    ZdpStatus::Success
                };
                if !broadcast {
                    // The response precedes the leave (§2.4.3.3.5.2).
                    self.respond(src, seq, ind.cluster, &StatusRsp { status }, via);
                }
                if status.is_success() {
                    let device = if req.device == ExtendedAddress::ZERO {
                        ctx.local_ieee()
                    } else {
                        req.device
                    };
                    let _ = ctx.leave(device, req.remove_children, req.rejoin);
                }
            }
            cluster::MGMT_PERMIT_JOINING_REQ => {
                let req = MgmtPermitJoiningReq::decode_exact(data).ok()?;
                let duration = if req.duration == 0xFF {
                    0xFE
                } else {
                    req.duration
                };
                let from_tc = ind.src_ieee == Some(ctx.trust_center());
                if from_tc && !req.tlvs.is_empty() {
                    ctx.set_beacon_appendix(req.tlvs);
                }
                let status = ctx.permit_joining(duration, from_tc || ctx.is_trust_center());
                if !broadcast {
                    self.respond(src, seq, ind.cluster, &StatusRsp { status }, via);
                }
            }
            cluster::MGMT_NWK_UPDATE_REQ => {
                let req = MgmtNwkUpdateReq::decode_exact(data).ok()?;
                self.push_event(ZdoEvent::NwkUpdateRequest {
                    src,
                    seq,
                    req,
                    broadcast,
                });
            }
            cluster::MGMT_NWK_ENHANCED_UPDATE_REQ => {
                let req = MgmtNwkEnhancedUpdateReq::decode_exact(data).ok()?;
                self.push_event(ZdoEvent::NwkEnhancedUpdateRequest {
                    src,
                    seq,
                    req,
                    broadcast,
                });
            }
            cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ => {
                // Step 1: broadcasts are dropped.
                if broadcast {
                    return None;
                }
                let req = MgmtNwkIeeeJoiningListReq::decode_exact(data).ok()?;
                self.answer_joining_list(src, seq, req, ctx, via);
            }
            cluster::MGMT_NWK_BEACON_SURVEY_REQ => {
                if broadcast {
                    return None;
                }
                match MgmtNwkBeaconSurveyReq::decode_exact(data) {
                    Ok(req) => self.push_event(ZdoEvent::BeaconSurveyRequest { src, seq, req }),
                    Err(_) => {
                        let rsp = MgmtNwkBeaconSurveyRsp::failure(ZdpStatus::MissingTlv);
                        self.respond(src, seq, ind.cluster, &rsp, via);
                    }
                }
            }
            cluster::SECURITY_START_KEY_NEGOTIATION_REQ
            | cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ
            | cluster::SECURITY_GET_AUTHENTICATION_LEVEL_REQ
            | cluster::SECURITY_SET_CONFIGURATION_REQ
            | cluster::SECURITY_GET_CONFIGURATION_REQ
            | cluster::SECURITY_START_KEY_UPDATE_REQ
            | cluster::SECURITY_DECOMMISSION_REQ
            | cluster::SECURITY_CHALLENGE_REQ => {
                self.handle_security(ind, frame, broadcast, ctx);
            }
            other => {
                if !broadcast {
                    self.respond(
                        src,
                        seq,
                        other,
                        &StatusRsp {
                            status: ZdpStatus::NotSupported,
                        },
                        via,
                    );
                }
            }
        }
        None
    }

    /// Security client services (§2.4.3.4). Replies are built into a
    /// scratch buffer and sent with the request's relay information.
    #[allow(clippy::too_many_lines)]
    fn handle_security<'a>(
        &mut self,
        ind: &DataIndication<'a>,
        frame: &ZdpFrame<'a>,
        broadcast: bool,
        ctx: &mut impl ZdoContext,
    ) {
        let (src, seq, data, via) = (ind.src, frame.seq, frame.data, ind.relayed);
        let aps_encrypted = ind.security == SecurityStatus::LinkKey;
        let from_tc = ind.src_ieee == Some(ctx.trust_center());
        let centralized = ctx.trust_center() != ExtendedAddress::BROADCAST;
        let mut out = [0u8; MAX_ZDP];
        let mut w = Writer::new(&mut out);
        let status = match ind.cluster {
            cluster::SECURITY_START_KEY_NEGOTIATION_REQ => {
                let Some(sender) = ind.src_ieee else { return };
                match security::validate(data) {
                    Err(e) => {
                        if broadcast {
                            return;
                        }
                        e
                    }
                    Ok(set) => match security::PublicPoint::find(&set) {
                        None => ZdpStatus::MissingTlv,
                        Some(p) if p.device != sender => ZdpStatus::InvalidTlv,
                        Some(p) => match ctx.key_negotiation(p.device, &p.point, aps_encrypted) {
                            Ok(point) => {
                                let mine = security::PublicPoint {
                                    device: ctx.local_ieee(),
                                    point,
                                };
                                if mine.write(&mut w).is_err() {
                                    return;
                                }
                                ZdpStatus::Success
                            }
                            Err(e) => e,
                        },
                    },
                }
            }
            cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ => {
                if broadcast || !aps_encrypted {
                    return;
                }
                if !ctx.is_trust_center() {
                    ZdpStatus::NotSupported
                } else {
                    let Some(requester) = ind.src_ieee else {
                        return;
                    };
                    match security::validate(data) {
                        Err(e) => e,
                        Ok(set) => match security::AuthenticationTokenId::find(&set) {
                            None => ZdpStatus::InvalidTlv,
                            Some(id) if id.0 != tlv_tag::SYMMETRIC_PASSPHRASE => {
                                ZdpStatus::InvalidRequestType
                            }
                            Some(_) => match ctx.authentication_token(requester) {
                                Ok(token) => {
                                    if tlv::write_tlv(&mut w, tlv_tag::SYMMETRIC_PASSPHRASE, &token)
                                        .is_err()
                                    {
                                        return;
                                    }
                                    ZdpStatus::Success
                                }
                                Err(e) => e,
                            },
                        },
                    }
                }
            }
            cluster::SECURITY_GET_AUTHENTICATION_LEVEL_REQ => {
                if broadcast || !aps_encrypted {
                    return;
                }
                if !ctx.is_trust_center() {
                    ZdpStatus::NotAuthorized
                } else {
                    match security::validate(data) {
                        Err(e) => e,
                        Ok(set) => match security::TargetIeee::find(&set) {
                            None => ZdpStatus::InvalidRequestType,
                            Some(t)
                                if t.0 == ctx.local_ieee() || t.0 == ExtendedAddress::BROADCAST =>
                            {
                                ZdpStatus::InvalidRequestType
                            }
                            Some(t) => match ctx.authentication_level(t.0) {
                                Ok((initial, active)) => {
                                    let lvl = security::DeviceAuthenticationLevel {
                                        device: t.0,
                                        initial_join_method: initial,
                                        active_link_key_type: active,
                                    };
                                    if lvl.write(&mut w).is_err() {
                                        return;
                                    }
                                    ZdpStatus::Success
                                }
                                Err(e) => e,
                            },
                        },
                    }
                }
            }
            cluster::SECURITY_SET_CONFIGURATION_REQ => {
                if centralized && broadcast {
                    return;
                }
                if ctx.is_trust_center() || (centralized && !from_tc) {
                    ZdpStatus::NotAuthorized
                } else {
                    match security::validate(data) {
                        Err(e) => {
                            if broadcast {
                                return;
                            }
                            e
                        }
                        Ok(set) => {
                            let mut ps = security::ProcessingStatus::default();
                            let mut processed = 0;
                            for t in set.iter() {
                                if !tlv::is_global_tag(t.tag) {
                                    continue;
                                }
                                let st = ctx.set_configuration(&t);
                                if st == ZdpStatus::Success {
                                    processed += 1;
                                }
                                let _ = ps.0.push((t.tag, st));
                            }
                            if broadcast {
                                return;
                            }
                            if ps.0.is_empty() {
                                ZdpStatus::MissingTlv
                            } else {
                                if ps.write(&mut w).is_err() {
                                    return;
                                }
                                if processed > 0 {
                                    ZdpStatus::Success
                                } else {
                                    ZdpStatus::InvalidRequestType
                                }
                            }
                        }
                    }
                }
            }
            cluster::SECURITY_GET_CONFIGURATION_REQ => {
                if broadcast {
                    return;
                }
                if centralized && !from_tc {
                    ZdpStatus::NotAuthorized
                } else {
                    match GetConfigurationReq::decode_exact(data) {
                        Err(_) => ZdpStatus::InvalidRequestType,
                        Ok(req) => {
                            let mut status = ZdpStatus::Success;
                            for id in req.tlv_ids {
                                let mark = w.position();
                                if ctx.get_configuration(*id, &mut w) {
                                    continue;
                                }
                                if w.position() != mark {
                                    // The value did not fit (§2.4.3.4.5.2 step 5).
                                    status = ZdpStatus::FrameTooLarge;
                                    break;
                                }
                            }
                            if status != ZdpStatus::Success {
                                w = Writer::new(&mut out);
                            }
                            status
                        }
                    }
                }
            }
            cluster::SECURITY_START_KEY_UPDATE_REQ => {
                // While joining the Trust Center address may be unset:
                // it is learnt from the Sending Device EUI64 (step 3).
                let joining = ctx.awaiting_authorization();
                if !joining && (!centralized || !from_tc) {
                    ZdpStatus::NotAuthorized
                } else {
                    match security::validate(data) {
                        Err(_) => ZdpStatus::InvalidRequestType,
                        Ok(set) => match SelectedKeyNegotiationMethod::find(&set) {
                            None => ZdpStatus::InvalidRequestType,
                            Some(m)
                                if m.protocol
                                    == SelectedKeyNegotiationMethod::PROTOCOL_ZIGBEE_3_0 =>
                            {
                                ZdpStatus::InvalidRequestType
                            }
                            Some(m) => ctx.start_key_update(&m, via),
                        },
                    }
                }
            }
            cluster::SECURITY_DECOMMISSION_REQ => {
                if broadcast {
                    return;
                }
                if ctx.is_trust_center() || (centralized && !aps_encrypted) {
                    ZdpStatus::NotAuthorized
                } else {
                    match security::validate(data) {
                        Err(e) => e,
                        Ok(set) => match security::Eui64List::find(&set) {
                            None => ZdpStatus::InvalidRequestType,
                            Some(list) if list.0.contains(&ctx.local_ieee()) => {
                                ZdpStatus::InvalidRequestType
                            }
                            Some(list) => {
                                let devices: Vec<ExtendedAddress, { security::MAX_EUI64_LIST }> =
                                    list.0
                                        .iter()
                                        .copied()
                                        .filter(|a| *a != ExtendedAddress::BROADCAST)
                                        .collect();
                                if ctx.decommission(&devices) {
                                    ZdpStatus::Success
                                } else {
                                    // "NOT_FOUND" is not a ZDP enumeration;
                                    // NO_MATCH is the closest defined value
                                    // (ADR-0007).
                                    ZdpStatus::NoMatch
                                }
                            }
                        },
                    }
                }
            }
            cluster::SECURITY_CHALLENGE_REQ => {
                // §2.4.3.4.8.4: never APS encrypted, never broadcast.
                if broadcast {
                    return;
                }
                match security::validate(data) {
                    Err(e) => e,
                    Ok(set) => match security::FrameCounterChallenge::find(&set) {
                        None => ZdpStatus::MissingTlv,
                        Some(ch) => {
                            match ctx.answer_frame_counter_challenge(ch.sender, ch.challenge) {
                                None => ZdpStatus::NoMatch,
                                Some((aps_frame_counter, challenge_frame_counter, mic)) => {
                                    let rsp = security::FrameCounterResponse {
                                        responder: ctx.local_ieee(),
                                        challenge: ch.challenge,
                                        aps_frame_counter,
                                        challenge_frame_counter,
                                        mic,
                                    };
                                    if rsp.write(&mut w).is_err() {
                                        return;
                                    }
                                    ZdpStatus::Success
                                }
                            }
                        }
                    },
                }
            }
            _ => return,
        };
        let n = w.position();
        let tlvs = out.get(..n).unwrap_or(&[]);
        self.respond_with(
            src,
            seq,
            ind.cluster,
            &security::StartKeyNegotiationRsp { status, tlvs },
            via,
            aps_encrypted,
        );
    }

    /// Status for a descriptor request about another device
    /// (§2.4.4.2.3.3): end devices answer INV_REQUESTTYPE, routers
    /// DEVICE_NOT_FOUND.
    fn not_local(ctx: &impl ZdoContext) -> ZdpStatus {
        if ctx.logical_type() == LogicalDeviceType::EndDevice {
            ZdpStatus::InvalidRequestType
        } else {
            ZdpStatus::DeviceNotFound
        }
    }

    /// Simple descriptor matching rules (§2.4.4.2.7.2): the profile must
    /// match (or be the wildcard) and at least one requested input
    /// cluster is served or one requested output cluster is consumed.
    fn matches(d: &SimpleDescriptor, req: &MatchDescReq<'_>) -> bool {
        if req.profile != ProfileId::WILDCARD && req.profile != d.profile {
            return false;
        }
        req.input.clusters().any(|c| d.has_input(c))
            || req.output.clusters().any(|c| d.has_output(c))
    }

    #[allow(clippy::too_many_arguments)]
    fn addr_response(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        req_cluster: ClusterId,
        request_type: AddrRequestType,
        start_index: u8,
        ieee: ExtendedAddress,
        short: ShortAddress,
        broadcast: bool,
        via: Option<RelayInfo>,
        ctx: &impl ZdoContext,
    ) {
        match request_type {
            AddrRequestType::Single => self.respond(
                src,
                seq,
                req_cluster,
                &AddrRsp {
                    status: ZdpStatus::Success,
                    ieee,
                    short,
                    associated: None,
                },
                via,
            ),
            AddrRequestType::Extended => {
                if ctx.logical_type() == LogicalDeviceType::EndDevice {
                    self.respond(
                        src,
                        seq,
                        req_cluster,
                        &AddrRsp {
                            status: ZdpStatus::Success,
                            ieee,
                            short,
                            associated: None,
                        },
                        via,
                    );
                    return;
                }
                let mut list: Vec<u8, MAX_ZDP> = Vec::new();
                let mut index = 0u8;
                let cap = (MAX_ZDP - 1 - 13) / 2;
                ctx.end_device_children(&mut |_, s| {
                    if index >= start_index && list.len() / 2 < cap {
                        let _ = list.extend_from_slice(&s.0.to_le_bytes());
                    }
                    index = index.saturating_add(1);
                });
                self.respond(
                    src,
                    seq,
                    req_cluster,
                    &AddrRsp {
                        status: ZdpStatus::Success,
                        ieee: ctx.local_ieee(),
                        short: ctx.local_short(),
                        associated: Some((start_index, U16List(&list))),
                    },
                    via,
                );
            }
            AddrRequestType::Reserved(_) => {
                if !broadcast {
                    self.respond(
                        src,
                        seq,
                        req_cluster,
                        &AddrRsp {
                            status: ZdpStatus::InvalidRequestType,
                            ieee,
                            short,
                            associated: None,
                        },
                        via,
                    );
                }
            }
        }
    }

    /// Builds a Mgmt_*_rsp table response with up to `MAX` records.
    #[allow(clippy::too_many_arguments)]
    fn table_response<T: Encode, const MAX: usize>(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        req_cluster: ClusterId,
        start_index: u8,
        total: u8,
        mut record: impl FnMut(u8) -> Option<T>,
        via: Option<RelayInfo>,
    ) {
        let mut records: Vec<u8, MAX_ZDP> = Vec::new();
        let mut count = 0u8;
        let mut index = start_index;
        while usize::from(count) < MAX && index < total {
            let Some(rec) = record(index) else { break };
            let mut tmp = [0u8; 32];
            let Ok(n) = rec.encode_to_slice(&mut tmp) else {
                break;
            };
            if records.len() + n + 4 > MAX_ZDP - 1 || records.extend_from_slice(&tmp[..n]).is_err()
            {
                break;
            }
            count += 1;
            index = index.saturating_add(1);
        }
        self.respond(
            src,
            seq,
            req_cluster,
            &TableRsp {
                status: ZdpStatus::Success,
                total,
                start_index,
                count,
                records: &records,
            },
            via,
        );
    }
}
