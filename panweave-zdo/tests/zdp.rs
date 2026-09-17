//! ZDO server/client behaviour over a direct link between two ZDOs.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::BindingDestination;
use panweave_codec::Decode;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ChannelMask, ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, MacCapability,
    ManufacturerCode, ProfileId, ShortAddress, TransactionSequence,
};
use panweave_zdo::descriptor::{
    NodeDescriptor, PowerDescriptor, ServerMask, SimpleDescriptor, frequency_band,
};
use panweave_zdo::layer::{Zdo, ZdoAction, ZdoContext, ZdoEvent, ZdoIndication};
use panweave_zdo::zdp::{
    ActiveEpReq, AddrRequestType, AddrRsp, BindReq, EndpointListRsp, IeeeAddrReq, MatchDescReq,
    MgmtLeaveReq, MgmtLqiReq, MgmtNwkUpdateReq, MgmtPermitJoiningReq, NeighborDeviceType,
    NeighborRecord, NeighborRelationship, NodeDescReq, NodeDescRsp, NwkAddrReq, SimpleDescReq,
    SimpleDescRsp, StatusRsp, TableRsp, TriState, U16List, ZdpStatus, cluster,
};

const A_SHORT: ShortAddress = ShortAddress(0x0000);
const A_IEEE: ExtendedAddress = ExtendedAddress(0xA);
const B_SHORT: ShortAddress = ShortAddress(0x1111);
const B_IEEE: ExtendedAddress = ExtendedAddress(0xB);
const CHILD_IEEE: ExtendedAddress = ExtendedAddress(0xC);
const CHILD_SHORT: ShortAddress = ShortAddress(0x2222);

struct Ctx {
    short: ShortAddress,
    ieee: ExtendedAddress,
    logical: LogicalDeviceType,
    tc: bool,
    children: Vec<(ExtendedAddress, ShortAddress)>,
    bindings: Vec<BindReq>,
    permit: Option<u8>,
    left: Option<(ExtendedAddress, bool, bool)>,
    announced: Vec<(ExtendedAddress, ShortAddress)>,
    beacon_tlvs: Vec<u8>,
}

impl Ctx {
    fn new(short: ShortAddress, ieee: ExtendedAddress, logical: LogicalDeviceType) -> Self {
        Ctx {
            short,
            ieee,
            logical,
            tc: short == A_SHORT,
            children: Vec::new(),
            bindings: Vec::new(),
            permit: None,
            left: None,
            announced: Vec::new(),
            beacon_tlvs: Vec::new(),
        }
    }
}

impl ZdoContext for Ctx {
    fn local_short(&self) -> ShortAddress {
        self.short
    }
    fn local_ieee(&self) -> ExtendedAddress {
        self.ieee
    }
    fn extended_pan_id(&self) -> ExtendedAddress {
        ExtendedAddress(0xEE)
    }
    fn trust_center(&self) -> ExtendedAddress {
        A_IEEE
    }
    fn is_trust_center(&self) -> bool {
        self.tc
    }
    fn logical_type(&self) -> LogicalDeviceType {
        self.logical
    }
    fn end_device_children(&self, f: &mut dyn FnMut(ExtendedAddress, ShortAddress)) {
        for (i, s) in &self.children {
            f(*i, *s);
        }
    }
    fn neighbor_count(&self) -> u8 {
        self.children.len() as u8
    }
    fn neighbor_record(&self, index: u8) -> Option<NeighborRecord> {
        let (ieee, short) = *self.children.get(usize::from(index))?;
        Some(NeighborRecord {
            extended_pan_id: self.extended_pan_id(),
            ieee,
            short,
            device_type: NeighborDeviceType::EndDevice,
            rx_on_when_idle: TriState::No,
            relationship: NeighborRelationship::Child,
            permit_joining: TriState::Unknown,
            depth: 1,
            lqa: 180,
        })
    }
    fn route_count(&self) -> u8 {
        0
    }
    fn route_record(&self, _index: u8) -> Option<panweave_zdo::zdp::RouteRecord> {
        None
    }
    fn binding_count(&self) -> u8 {
        self.bindings.len() as u8
    }
    fn binding_record(&self, index: u8) -> Option<BindReq> {
        self.bindings.get(usize::from(index)).copied()
    }
    fn bind(&mut self, req: &BindReq) -> ZdpStatus {
        self.bindings.push(*req);
        ZdpStatus::Success
    }
    fn unbind(&mut self, req: &BindReq) -> ZdpStatus {
        match self.bindings.iter().position(|b| b == req) {
            Some(i) => {
                self.bindings.remove(i);
                ZdpStatus::Success
            }
            None => ZdpStatus::NoEntry,
        }
    }
    fn clear_bindings(&mut self, device: ExtendedAddress) {
        if device == ExtendedAddress::BROADCAST {
            self.bindings.clear();
        }
    }
    fn permit_joining(&mut self, duration: u8, _from_tc: bool) -> ZdpStatus {
        self.permit = Some(duration);
        ZdpStatus::Success
    }
    fn set_beacon_appendix(&mut self, tlvs: &[u8]) {
        self.beacon_tlvs = tlvs.to_vec();
    }
    fn leave(&mut self, device: ExtendedAddress, remove_children: bool, rejoin: bool) -> ZdpStatus {
        self.left = Some((device, remove_children, rejoin));
        ZdpStatus::Success
    }
    fn device_announced(&mut self, ieee: ExtendedAddress, short: ShortAddress, _c: MacCapability) {
        self.announced.push((ieee, short));
    }
    fn claims_child(&self, child: ExtendedAddress) -> bool {
        self.children.iter().any(|(i, _)| *i == child)
    }
    fn child_claimed_elsewhere(&mut self, _child: ExtendedAddress, _router: ShortAddress) {}
    fn awaiting_authorization(&self) -> bool {
        false
    }
    fn key_negotiation(
        &mut self,
        _partner: ExtendedAddress,
        point: &[u8; 32],
        _aps_encrypted: bool,
    ) -> Result<[u8; 32], ZdpStatus> {
        // Echo the point: the tests only check the frame plumbing.
        Ok(*point)
    }
    fn authentication_token(&mut self, _r: ExtendedAddress) -> Result<[u8; 16], ZdpStatus> {
        Ok([0x42; 16])
    }
    fn authentication_level(&self, _t: ExtendedAddress) -> Result<(u8, u8), ZdpStatus> {
        Ok((1, 3))
    }
    fn start_key_update(
        &mut self,
        _m: &panweave_zdo::security::SelectedKeyNegotiationMethod,
        _via: Option<panweave_aps::layer::RelayInfo>,
    ) -> ZdpStatus {
        ZdpStatus::Success
    }
    fn decommission(&mut self, devices: &[ExtendedAddress]) -> bool {
        !devices.is_empty()
    }
    fn set_configuration(&mut self, _tlv: &panweave_codec::tlv::Tlv<'_>) -> ZdpStatus {
        ZdpStatus::Success
    }
    fn get_configuration(&mut self, _tag: u8, _w: &mut panweave_codec::Writer<'_>) -> bool {
        false
    }
    fn answer_frame_counter_challenge(
        &mut self,
        _sender: ExtendedAddress,
        _challenge: u64,
    ) -> Option<(u32, u32, [u8; 8])> {
        Some((77, 1, [9; 8]))
    }
}

fn node_desc(lt: LogicalDeviceType) -> NodeDescriptor {
    NodeDescriptor {
        logical_type: lt,
        fragmentation_supported: true,
        aps_flags: 0,
        frequency_band: frequency_band::BAND_2400,
        mac_capability: MacCapability::ROUTER,
        manufacturer_code: ManufacturerCode(0x1234),
        max_buffer_size: 82,
        max_incoming_transfer_size: 256,
        server_mask: ServerMask::new(if lt == LogicalDeviceType::Coordinator {
            ServerMask::PRIMARY_TRUST_CENTER
        } else {
            0
        }),
        max_outgoing_transfer_size: 256,
        descriptor_capability: 0,
    }
}

struct Pair {
    a: Zdo<4>,
    b: Zdo<4>,
    ca: Ctx,
    cb: Ctx,
    now: Instant,
    /// Frames delivered: (from, to, cluster, data).
    log: Vec<(ShortAddress, ShortAddress, ClusterId, Vec<u8>)>,
    responses: Vec<(ShortAddress, TransactionSequence, ClusterId, Vec<u8>, bool)>,
    announces: Vec<(ExtendedAddress, ShortAddress)>,
}

impl Pair {
    fn new() -> Self {
        let mut a = Zdo::<4>::new(
            node_desc(LogicalDeviceType::Coordinator),
            PowerDescriptor::MAINS,
        );
        let mut b = Zdo::<4>::new(node_desc(LogicalDeviceType::Router), PowerDescriptor::MAINS);
        a.add_endpoint(
            SimpleDescriptor::new(
                Endpoint(1),
                ProfileId::HOME_AUTOMATION,
                DeviceId(0x0005),
                0,
                &[ClusterId(0x0000)],
                &[ClusterId(0x0006), ClusterId(0x0008)],
            )
            .unwrap(),
        )
        .unwrap();
        b.add_endpoint(
            SimpleDescriptor::new(
                Endpoint(1),
                ProfileId::HOME_AUTOMATION,
                DeviceId(0x0100),
                1,
                &[ClusterId(0x0000), ClusterId(0x0006)],
                &[],
            )
            .unwrap(),
        )
        .unwrap();
        b.add_endpoint(
            SimpleDescriptor::new(
                Endpoint(2),
                ProfileId::HOME_AUTOMATION,
                DeviceId(0x0101),
                1,
                &[ClusterId(0x0008)],
                &[],
            )
            .unwrap(),
        )
        .unwrap();
        let mut cb = Ctx::new(B_SHORT, B_IEEE, LogicalDeviceType::Router);
        cb.children.push((CHILD_IEEE, CHILD_SHORT));
        let now = Instant::from_millis(10_000);
        a.poll_timers(now);
        b.poll_timers(now);
        Pair {
            a,
            b,
            ca: Ctx::new(A_SHORT, A_IEEE, LogicalDeviceType::Coordinator),
            cb,
            now,
            log: Vec::new(),
            responses: Vec::new(),
            announces: Vec::new(),
        }
    }

    fn deliver(
        zdo: &mut Zdo<4>,
        ctx: &mut Ctx,
        from: ShortAddress,
        from_ieee: ExtendedAddress,
        dst: ShortAddress,
        cluster: ClusterId,
        data: &[u8],
        security: SecurityStatus,
        responses: &mut Vec<(ShortAddress, TransactionSequence, ClusterId, Vec<u8>, bool)>,
        announces: &mut Vec<(ExtendedAddress, ShortAddress)>,
    ) {
        let ind = DataIndication {
            src: from,
            src_ieee: Some(from_ieee),
            src_endpoint: Endpoint(0),
            delivery: Delivery::Endpoint(Endpoint(0)),
            profile: ProfileId::ZDP,
            cluster,
            asdu: data,
            security,
            lqi: 200,
            relayed: None,
            counter: 0,
            nwk_broadcast: dst.is_broadcast(),
        };
        match zdo.on_data(&ind, ctx) {
            Some(ZdoIndication::Response {
                src,
                seq,
                cluster,
                data,
                matched,
                ..
            }) => responses.push((src, seq, cluster, data.to_vec(), matched)),
            Some(ZdoIndication::DeviceAnnounce { ieee, short, .. }) => {
                announces.push((ieee, short));
            }
            None => {}
        }
    }

    fn run(&mut self) {
        self.run_with(SecurityStatus::NwkKey);
    }

    fn run_with(&mut self, security: SecurityStatus) {
        loop {
            let mut progressed = false;
            while let Some(ZdoAction::Send {
                dst,
                cluster,
                frame,
                ..
            }) = self.a.next_action()
            {
                progressed = true;
                self.log.push((A_SHORT, dst, cluster, frame.to_vec()));
                if dst == B_SHORT || dst.is_broadcast() {
                    Self::deliver(
                        &mut self.b,
                        &mut self.cb,
                        A_SHORT,
                        A_IEEE,
                        dst,
                        cluster,
                        &frame,
                        security,
                        &mut self.responses,
                        &mut self.announces,
                    );
                }
            }
            while let Some(ZdoAction::Send {
                dst,
                cluster,
                frame,
                ..
            }) = self.b.next_action()
            {
                progressed = true;
                self.log.push((B_SHORT, dst, cluster, frame.to_vec()));
                if dst == A_SHORT || dst.is_broadcast() {
                    Self::deliver(
                        &mut self.a,
                        &mut self.ca,
                        B_SHORT,
                        B_IEEE,
                        dst,
                        cluster,
                        &frame,
                        security,
                        &mut self.responses,
                        &mut self.announces,
                    );
                }
            }
            if !progressed {
                break;
            }
        }
    }

    fn last_response(&self) -> &(ShortAddress, TransactionSequence, ClusterId, Vec<u8>, bool) {
        self.responses.last().expect("response")
    }
}

#[test]
fn descriptor_discovery() {
    let mut p = Pair::new();
    let tlv = [0x47u8, 0x04, 0x00, 0x00, 0x01, 0x00, 0x01];
    let seq =
        p.a.request(
            B_SHORT,
            cluster::NODE_DESC_REQ,
            &NodeDescReq {
                addr: B_SHORT,
                tlvs: &tlv,
            },
        )
        .unwrap();
    p.run();
    let (src, rseq, c, data, matched) = p.last_response();
    assert_eq!(
        (*src, *rseq, *c, *matched),
        (B_SHORT, seq, ClusterId(0x8002), true)
    );
    let rsp = NodeDescRsp::decode_exact(data).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert_eq!(
        rsp.descriptor.unwrap().logical_type,
        LogicalDeviceType::Router
    );
    assert!(!rsp.tlvs.is_empty(), "fragmentation parameters TLV present");

    // Descriptor of another device: routers answer DEVICE_NOT_FOUND.
    p.a.request(
        B_SHORT,
        cluster::NODE_DESC_REQ,
        &NodeDescReq {
            addr: ShortAddress(0x9999),
            tlvs: &[],
        },
    )
    .unwrap();
    p.run();
    let rsp = NodeDescRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!(rsp.status, ZdpStatus::DeviceNotFound);
    assert!(rsp.descriptor.is_none());

    p.a.request(
        B_SHORT,
        cluster::ACTIVE_EP_REQ,
        &ActiveEpReq { addr: B_SHORT },
    )
    .unwrap();
    p.run();
    let rsp = EndpointListRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!(rsp.endpoints, &[1, 2]);

    p.a.request(
        B_SHORT,
        cluster::SIMPLE_DESC_REQ,
        &SimpleDescReq {
            addr: B_SHORT,
            endpoint: Endpoint(2),
        },
    )
    .unwrap();
    p.run();
    let rsp = SimpleDescRsp::decode_exact(&p.last_response().3).unwrap();
    let d = SimpleDescriptor::decode_exact(rsp.descriptor.unwrap()).unwrap();
    assert_eq!(d.device, DeviceId(0x0101));
    assert!(d.has_input(ClusterId(8)));

    p.a.request(
        B_SHORT,
        cluster::SIMPLE_DESC_REQ,
        &SimpleDescReq {
            addr: B_SHORT,
            endpoint: Endpoint(7),
        },
    )
    .unwrap();
    p.run();
    assert_eq!(
        SimpleDescRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::NotActive
    );

    // Match: an endpoint serving On/Off (0x0006) under the HA profile.
    let want = [0x06u8, 0x00];
    p.a.request(
        ShortAddress::BROADCAST_RX_ON,
        cluster::MATCH_DESC_REQ,
        &MatchDescReq {
            addr: ShortAddress::BROADCAST_RX_ON,
            profile: ProfileId::HOME_AUTOMATION,
            input: U16List(&want),
            output: U16List(&[]),
        },
    )
    .unwrap();
    p.run();
    let (_, _, c, data, matched) = p.last_response();
    assert_eq!(*c, ClusterId(0x8006));
    assert!(!matched, "broadcast requests are not tracked");
    let rsp = EndpointListRsp::decode_exact(data).unwrap();
    assert_eq!(rsp.endpoints, &[1]);
    // No match on broadcast: silence.
    let n = p.responses.len();
    let want = [0x0Bu8, 0x04];
    p.a.request(
        ShortAddress::BROADCAST_RX_ON,
        cluster::MATCH_DESC_REQ,
        &MatchDescReq {
            addr: ShortAddress::BROADCAST_RX_ON,
            profile: ProfileId::WILDCARD,
            input: U16List(&want),
            output: U16List(&[]),
        },
    )
    .unwrap();
    p.run();
    assert_eq!(p.responses.len(), n);
}

#[test]
fn address_discovery_with_children() {
    let mut p = Pair::new();
    p.a.request(
        ShortAddress::BROADCAST_RX_ON,
        cluster::NWK_ADDR_REQ,
        &NwkAddrReq {
            ieee: CHILD_IEEE,
            request_type: AddrRequestType::Single,
            start_index: 0,
        },
    )
    .unwrap();
    p.run();
    let rsp = AddrRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!(
        (rsp.status, rsp.ieee, rsp.short),
        (ZdpStatus::Success, CHILD_IEEE, CHILD_SHORT)
    );
    assert!(rsp.associated.is_none());

    p.a.request(
        B_SHORT,
        cluster::IEEE_ADDR_REQ,
        &IeeeAddrReq {
            addr: B_SHORT,
            request_type: AddrRequestType::Extended,
            start_index: 0,
        },
    )
    .unwrap();
    p.run();
    let rsp = AddrRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!(rsp.ieee, B_IEEE);
    let (start, list) = rsp.associated.unwrap();
    assert_eq!(start, 0);
    assert_eq!(list.addresses().next(), Some(CHILD_SHORT));

    // Unknown address, unicast: DEVICE_NOT_FOUND; broadcast: silence.
    p.a.request(
        B_SHORT,
        cluster::IEEE_ADDR_REQ,
        &IeeeAddrReq {
            addr: ShortAddress(0x7777),
            request_type: AddrRequestType::Single,
            start_index: 0,
        },
    )
    .unwrap();
    p.run();
    assert_eq!(
        AddrRsp::decode_exact(&p.last_response().3).unwrap().status,
        ZdpStatus::DeviceNotFound
    );
    let n = p.responses.len();
    p.a.request(
        ShortAddress::BROADCAST_RX_ON,
        cluster::NWK_ADDR_REQ,
        &NwkAddrReq {
            ieee: ExtendedAddress(0x77),
            request_type: AddrRequestType::Single,
            start_index: 0,
        },
    )
    .unwrap();
    p.run();
    assert_eq!(p.responses.len(), n);
}

#[test]
fn binding_and_restricted_mode() {
    let mut p = Pair::new();
    let req = BindReq {
        src: B_IEEE,
        src_endpoint: Endpoint(1),
        cluster: ClusterId(6),
        destination: BindingDestination::Unicast {
            address: A_IEEE,
            endpoint: Endpoint(1),
        },
    };
    p.a.request(B_SHORT, cluster::BIND_REQ, &req).unwrap();
    p.run();
    assert_eq!(
        StatusRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::Success
    );
    assert_eq!(p.cb.bindings.len(), 1);
    // Restricted mode: NWK-secured requests from the TC are refused.
    p.b.restricted_mode = true;
    p.a.request(B_SHORT, cluster::UNBIND_REQ, &req).unwrap();
    p.run();
    assert_eq!(
        StatusRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::NotAuthorized
    );
    assert_eq!(p.cb.bindings.len(), 1);
    // APS-encrypted requests from the TC are accepted.
    p.a.request(B_SHORT, cluster::UNBIND_REQ, &req).unwrap();
    p.run_with(SecurityStatus::LinkKey);
    assert_eq!(
        StatusRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::Success
    );
    assert!(p.cb.bindings.is_empty());
    p.b.restricted_mode = false;
    // Binding on behalf of another device is NOT_SUPPORTED on a router.
    let other = BindReq {
        src: ExtendedAddress(0x99),
        ..req
    };
    p.a.request(B_SHORT, cluster::BIND_REQ, &other).unwrap();
    p.run();
    assert_eq!(
        StatusRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::NotSupported
    );
}

#[test]
fn management_requests() {
    let mut p = Pair::new();
    p.a.request(
        B_SHORT,
        cluster::MGMT_LQI_REQ,
        &MgmtLqiReq { start_index: 0 },
    )
    .unwrap();
    p.run();
    let rsp = TableRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!((rsp.total, rsp.count), (1, 1));
    let rec = rsp.iter::<NeighborRecord>().next().unwrap().unwrap();
    assert_eq!(rec.ieee, CHILD_IEEE);

    p.a.request(
        B_SHORT,
        cluster::MGMT_PERMIT_JOINING_REQ,
        &MgmtPermitJoiningReq {
            duration: 0xFF,
            tc_significance: true,
            tlvs: &[],
        },
    )
    .unwrap();
    p.run();
    assert_eq!(
        StatusRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::Success
    );
    assert_eq!(p.cb.permit, Some(0xFE), "0xff is treated as 0xfe");

    p.a.request(
        B_SHORT,
        cluster::MGMT_LEAVE_REQ,
        &MgmtLeaveReq {
            device: ExtendedAddress::ZERO,
            remove_children: false,
            rejoin: true,
        },
    )
    .unwrap();
    p.run();
    assert_eq!(
        StatusRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::Success
    );
    assert_eq!(p.cb.left, Some((B_IEEE, false, true)));

    // Energy scan request surfaces as an event.
    p.a.request(
        B_SHORT,
        cluster::MGMT_NWK_UPDATE_REQ,
        &MgmtNwkUpdateReq {
            scan_channels: ChannelMask::ALL_2_4GHZ,
            scan_duration: 2,
            scan_count: Some(1),
            update_id: None,
            manager: None,
        },
    )
    .unwrap();
    p.run();
    assert!(matches!(
        p.b.next_event(),
        Some(ZdoEvent::NwkUpdateRequest { src, .. }) if src == A_SHORT
    ));

    // Unknown request: NOT_SUPPORTED for unicast, nothing for broadcast.
    p.a.request(
        B_SHORT,
        ClusterId(0x0077),
        &StatusRsp {
            status: ZdpStatus::Success,
        },
    )
    .unwrap();
    p.run();
    let (_, _, c, data, _) = p.last_response();
    assert_eq!(*c, ClusterId(0x8077));
    assert_eq!(
        StatusRsp::decode_exact(data).unwrap().status,
        ZdpStatus::NotSupported
    );
    let n = p.responses.len();
    p.a.request(
        ShortAddress::BROADCAST_RX_ON,
        ClusterId(0x0077),
        &StatusRsp {
            status: ZdpStatus::Success,
        },
    )
    .unwrap();
    p.run();
    assert_eq!(p.responses.len(), n);
}

#[test]
fn device_announce_and_timeouts() {
    let mut p = Pair::new();
    p.b.device_announce(B_SHORT, B_IEEE, MacCapability::ROUTER)
        .unwrap();
    p.run();
    assert_eq!(p.ca.announced, vec![(B_IEEE, B_SHORT)]);
    assert_eq!(p.announces, vec![(B_IEEE, B_SHORT)]);

    // A request to a silent device times out after apsZdoResponseTimeout.
    let seq =
        p.a.request(
            ShortAddress(0x4444),
            cluster::ACTIVE_EP_REQ,
            &ActiveEpReq {
                addr: ShortAddress(0x4444),
            },
        )
        .unwrap();
    p.run();
    assert!(p.a.next_event().is_none());
    p.now = p.now.saturating_add(Duration::from_millis(2999));
    p.a.poll_timers(p.now);
    assert!(p.a.next_event().is_none());
    p.now = p.now.saturating_add(Duration::from_millis(1));
    p.a.poll_timers(p.now);
    assert_eq!(
        p.a.next_event(),
        Some(ZdoEvent::Timeout {
            seq,
            cluster: cluster::ACTIVE_EP_REQ,
            dst: ShortAddress(0x4444)
        })
    );
    assert!(p.a.next_deadline().is_none());
}

#[test]
fn security_services() {
    use panweave_codec::Writer;
    use panweave_zdo::security::{
        self, AuthenticationTokenId, DeviceAuthenticationLevel, Eui64List,
        GetAuthenticationLevelReq, GetConfigurationReq, PublicPoint,
        RetrieveAuthenticationTokenReq, SelectedKeyNegotiationMethod, StartKeyNegotiationReq,
        StartKeyNegotiationRsp, StartKeyUpdateReq, TargetIeee,
    };
    let mut p = Pair::new();
    let mut buf = [0u8; 96];

    // Start_Key_Negotiation: B asks A (the Trust Center); the context
    // echoes the point; the response carries A's point.
    let mut w = Writer::new(&mut buf);
    PublicPoint {
        device: B_IEEE,
        point: [0x5A; 32],
    }
    .write(&mut w)
    .unwrap();
    let n = w.position();
    p.b.request(
        A_SHORT,
        cluster::SECURITY_START_KEY_NEGOTIATION_REQ,
        &StartKeyNegotiationReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run();
    let (_, _, c, data, matched) = p.last_response().clone();
    assert_eq!(c, ClusterId(0x8040));
    assert!(matched);
    let rsp = StartKeyNegotiationRsp::decode_exact(&data).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    let set = security::validate(rsp.tlvs).unwrap();
    assert_eq!(
        PublicPoint::find(&set),
        Some(PublicPoint {
            device: A_IEEE,
            point: [0x5A; 32]
        })
    );
    // A point claiming another device is INVALID_TLV; none is MISSING_TLV.
    let mut w = Writer::new(&mut buf);
    PublicPoint {
        device: CHILD_IEEE,
        point: [1; 32],
    }
    .write(&mut w)
    .unwrap();
    let n = w.position();
    p.b.request(
        A_SHORT,
        cluster::SECURITY_START_KEY_NEGOTIATION_REQ,
        &StartKeyNegotiationReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run();
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::InvalidTlv
    );
    p.b.request(
        A_SHORT,
        cluster::SECURITY_START_KEY_NEGOTIATION_REQ,
        &StartKeyNegotiationReq { tlvs: &[] },
    )
    .unwrap();
    p.run();
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::MissingTlv
    );

    // Retrieve_Authentication_Token: dropped without APS security, served
    // by the Trust Center with the passphrase TLV otherwise.
    let mut w = Writer::new(&mut buf);
    AuthenticationTokenId(69).write(&mut w).unwrap();
    let n = w.position();
    let before = p.responses.len();
    p.b.request(
        A_SHORT,
        cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ,
        &RetrieveAuthenticationTokenReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run();
    assert_eq!(p.responses.len(), before);
    p.b.request(
        A_SHORT,
        cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ,
        &RetrieveAuthenticationTokenReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    let rsp = StartKeyNegotiationRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    let set = security::validate(rsp.tlvs).unwrap();
    assert_eq!(set.value(69), Some(&[0x42u8; 16][..]));
    // Wrong token type.
    let mut w = Writer::new(&mut buf);
    AuthenticationTokenId(7).write(&mut w).unwrap();
    let n = w.position();
    p.b.request(
        A_SHORT,
        cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ,
        &RetrieveAuthenticationTokenReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::InvalidRequestType
    );

    // Get_Authentication_Level at the Trust Center.
    let mut w = Writer::new(&mut buf);
    TargetIeee(CHILD_IEEE).write(&mut w).unwrap();
    let n = w.position();
    p.b.request(
        A_SHORT,
        cluster::SECURITY_GET_AUTHENTICATION_LEVEL_REQ,
        &GetAuthenticationLevelReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    let rsp = StartKeyNegotiationRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert_eq!(
        DeviceAuthenticationLevel::find(&security::validate(rsp.tlvs).unwrap()),
        Some(DeviceAuthenticationLevel {
            device: CHILD_IEEE,
            initial_join_method: 1,
            active_link_key_type: 3,
        })
    );
    // Asking a non-Trust-Center: NOT_AUTHORIZED.
    p.a.request(
        B_SHORT,
        cluster::SECURITY_GET_AUTHENTICATION_LEVEL_REQ,
        &GetAuthenticationLevelReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::NotAuthorized
    );

    // Start_Key_Update from the Trust Center to B is accepted; from B to
    // the Trust Center it is NOT_AUTHORIZED.
    let mut w = Writer::new(&mut buf);
    SelectedKeyNegotiationMethod {
        protocol: 1,
        secret: 255,
        sender: A_IEEE,
    }
    .write(&mut w)
    .unwrap();
    let n = w.position();
    p.a.request(
        B_SHORT,
        cluster::SECURITY_START_KEY_UPDATE_REQ,
        &StartKeyUpdateReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::Success
    );
    p.b.request(
        A_SHORT,
        cluster::SECURITY_START_KEY_UPDATE_REQ,
        &StartKeyUpdateReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::NotAuthorized
    );

    // Decommission: rejected at the Trust Center, applied at B.
    let mut list = Eui64List(heapless::Vec::new());
    list.0.push(CHILD_IEEE).unwrap();
    let mut w = Writer::new(&mut buf);
    list.write(&mut w).unwrap();
    let n = w.position();
    p.a.request(
        B_SHORT,
        cluster::SECURITY_DECOMMISSION_REQ,
        &security::DecommissionReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::Success
    );
    p.b.request(
        A_SHORT,
        cluster::SECURITY_DECOMMISSION_REQ,
        &security::DecommissionReq { tlvs: &buf[..n] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    assert_eq!(
        StartKeyNegotiationRsp::decode_exact(&p.last_response().3)
            .unwrap()
            .status,
        ZdpStatus::NotAuthorized
    );

    // Get_Configuration: the test context has no values → empty SUCCESS.
    p.a.request(
        B_SHORT,
        cluster::SECURITY_GET_CONFIGURATION_REQ,
        &GetConfigurationReq { tlv_ids: &[75, 66] },
    )
    .unwrap();
    p.run_with(SecurityStatus::LinkKey);
    let rsp = StartKeyNegotiationRsp::decode_exact(&p.last_response().3).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert!(rsp.tlvs.is_empty());
}
