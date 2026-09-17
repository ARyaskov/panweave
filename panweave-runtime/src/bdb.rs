//! BDB 3.1 integration: [`Stack`] as a [`panweave_bdb::Node`] and the
//! translation of [`StackEvent`]s into [`panweave_bdb::Event`]s.

use heapless::Vec;
use panweave_aps::Destination;
use panweave_aps::tables::BindingEntry;
use panweave_bdb::{Event as BdbEvent, JoinKind, LocalCluster, MAX_CLUSTERS, Node, NodeError};
use panweave_codec::Decode;
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ChannelMask, CryptoRng, Endpoint, ExtendedAddress, GroupAddress, KeyAttributes,
    LogicalDeviceType, ShortAddress,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::{groups, identify};
use panweave_zcl::frame::{Direction, FrameType};
use panweave_zdo::descriptor::SimpleDescriptor;
use panweave_zdo::zdp::{AddrRequestType, AddrRsp, IeeeAddrReq, SimpleDescReq, SimpleDescRsp};
use panweave_zdo::{ZdpStatus, cluster};

use crate::context::AddrView;
use crate::stack::{JoinMode, Stack, StackEvent};

impl<C: BlockCipher, R: CryptoRng, S: Storage> Node for Stack<C, R, S> {
    fn role(&self) -> LogicalDeviceType {
        self.config.role
    }

    fn now(&self) -> Instant {
        self.now
    }

    fn is_centralized(&self) -> bool {
        !self.aps.aib.is_distributed()
    }

    fn trust_center_key_verified(&self) -> bool {
        self.aps
            .security
            .entry(self.aps.aib.trust_center_address)
            .is_some_and(|e| e.attributes == KeyAttributes::VerifiedKey)
    }

    fn current_channel(&self) -> ChannelMask {
        ChannelMask::EMPTY
            .with(self.nwk.nib.channel)
            .with_page(self.nwk.nib.channel_page)
    }

    fn form_network(&mut self, channels: ChannelMask, scan_duration: u8) -> Result<(), NodeError> {
        self.form_network_on(channels, scan_duration)
            .map_err(|_| NodeError::Busy)
    }

    fn join(
        &mut self,
        kind: JoinKind,
        channels: ChannelMask,
        scan_duration: u8,
    ) -> Result<(), NodeError> {
        let mode = match kind {
            JoinKind::Association => JoinMode::Association,
            JoinKind::SecuredRejoin => JoinMode::SecuredRejoin,
            JoinKind::TrustCenterRejoin => JoinMode::TrustCenterRejoin,
        };
        // BDB §8.2 runs its own primary/secondary channel retries: one
        // discovery per request.
        self.join_with(mode, channels, scan_duration, 1)
            .map_err(|_| NodeError::Busy)
    }

    fn leave(&mut self) -> Result<(), NodeError> {
        Stack::leave(self, false).map_err(|_| NodeError::Busy)?;
        self.pump();
        Ok(())
    }

    fn permit_join(&mut self, seconds: u8) -> Result<(), NodeError> {
        if self.config.role == LogicalDeviceType::EndDevice {
            return Err(NodeError::Unsupported);
        }
        Stack::permit_join(self, seconds).map_err(|_| NodeError::Busy)
    }

    fn broadcast_permit_join(&mut self, seconds: u8) -> Result<(), NodeError> {
        self.broadcast_permit_join(seconds)
            .map_err(|_| NodeError::Busy)
    }

    fn fast_poll(&mut self, duration: Duration) {
        self.fast_poll_for(duration);
    }

    fn identify(&mut self, endpoint: Endpoint, seconds: u16) -> Result<(), NodeError> {
        self.zcl
            .set_identify_time(endpoint, seconds)
            .map_err(|_| NodeError::Unsupported)?;
        self.pump();
        Ok(())
    }

    fn identify_query(&mut self, endpoint: Endpoint) -> Result<(), NodeError> {
        let profile = self
            .zcl
            .endpoint(endpoint)
            .map(|e| e.profile)
            .ok_or(NodeError::Unsupported)?;
        self.zcl
            .send_command(
                Destination::Short {
                    address: ShortAddress::BROADCAST_ALL,
                    endpoint: Endpoint::BROADCAST,
                },
                profile,
                identify::ID,
                endpoint,
                identify::CMD_IDENTIFY_QUERY,
                Direction::ToServer,
                None,
                &[],
            )
            .map_err(|_| NodeError::Busy)?;
        self.pump();
        Ok(())
    }

    fn simple_desc_req(&mut self, addr: ShortAddress, endpoint: Endpoint) -> Result<(), NodeError> {
        self.zdp_request(
            addr,
            cluster::SIMPLE_DESC_REQ,
            &SimpleDescReq { addr, endpoint },
        )
        .map(|_| ())
        .map_err(|_| NodeError::Busy)
    }

    fn ieee_addr_req(&mut self, addr: ShortAddress) -> Result<(), NodeError> {
        self.zdp_request(
            addr,
            cluster::IEEE_ADDR_REQ,
            &IeeeAddrReq {
                addr,
                request_type: AddrRequestType::Single,
                start_index: 0,
            },
        )
        .map(|_| ())
        .map_err(|_| NodeError::Busy)
    }

    fn ieee_of(&self, addr: ShortAddress) -> Option<ExtendedAddress> {
        use panweave_aps::layer::NwkView;
        AddrView(&self.nwk).ieee_of(addr)
    }

    fn local_clusters(&self, endpoint: Endpoint, out: &mut Vec<LocalCluster, MAX_CLUSTERS>) {
        let Some(ep) = self.zcl.endpoint(endpoint) else {
            return;
        };
        for c in &ep.clusters {
            let _ = out.push(LocalCluster {
                id: c.def.id,
                client: c.role == Role::Client,
            });
        }
    }

    fn bind(&mut self, entry: BindingEntry) -> Result<(), NodeError> {
        match self.aps.bindings.bind(entry) {
            Ok(()) => {
                let _ = self.persist_bindings();
                Ok(())
            }
            Err(panweave_types::ApsStatus::TableFull) => Err(NodeError::TableFull),
            Err(_) => Err(NodeError::Unsupported),
        }
    }

    fn add_group(
        &mut self,
        addr: ShortAddress,
        endpoint: Endpoint,
        group: GroupAddress,
    ) -> Result<(), NodeError> {
        let (src, profile) = self
            .zcl
            .endpoints()
            .first()
            .map(|e| (e.endpoint, e.profile))
            .ok_or(NodeError::Unsupported)?;
        self.zcl
            .send_command(
                Destination::Short {
                    address: addr,
                    endpoint,
                },
                profile,
                groups::ID,
                src,
                groups::CMD_ADD_GROUP,
                Direction::ToServer,
                None,
                &groups::add_group_payload(group),
            )
            .map_err(|_| NodeError::Busy)?;
        self.pump();
        Ok(())
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Translates a stack event for the BDB machine; `None` when the
    /// event is of no interest to commissioning.
    pub fn bdb_event(event: &StackEvent) -> Option<BdbEvent> {
        Some(match event {
            StackEvent::NetworkFormed { .. } => BdbEvent::FormationConfirm { success: true },
            StackEvent::FormationFailed(_) => BdbEvent::FormationConfirm { success: false },
            StackEvent::Joined { .. } => BdbEvent::JoinConfirm { success: true },
            StackEvent::JoinFailed(_) => BdbEvent::JoinConfirm { success: false },
            StackEvent::LinkKeyUpdated => BdbEvent::LinkKeyUpdated,
            // BDB 3.1 §10.2.4 step 3: a pre-r21 Trust Center ends the
            // update procedure successfully without a new key.
            StackEvent::LinkKeyUpdateSkipped { .. } => BdbEvent::LinkKeyUpdated,
            StackEvent::Left { .. } => BdbEvent::Left,
            StackEvent::Identify { endpoint, seconds } => BdbEvent::Identify {
                endpoint: *endpoint,
                seconds: *seconds,
            },
            StackEvent::ZclCommand(f)
                if f.origin.cluster == identify::ID
                    && f.origin.header.control.frame_type == FrameType::ClusterSpecific
                    && f.origin.header.control.direction == Direction::ToClient
                    && f.origin.header.command == identify::CMD_IDENTIFY_QUERY_RESPONSE =>
            {
                BdbEvent::IdentifyQueryResponse {
                    src: f.origin.src,
                    src_endpoint: f.origin.src_endpoint,
                    endpoint: f.origin.endpoint,
                }
            }
            StackEvent::Zdp(z) if z.cluster == cluster::response_of(cluster::SIMPLE_DESC_REQ) => {
                let rsp = SimpleDescRsp::decode_exact(&z.data).ok()?;
                let desc = rsp
                    .descriptor
                    .and_then(|d| SimpleDescriptor::decode_exact(d).ok());
                let mut inputs = Vec::new();
                let mut outputs = Vec::new();
                let endpoint = desc.as_ref().map_or(Endpoint(0), |d| d.endpoint);
                if let Some(d) = &desc {
                    for c in &d.input_clusters {
                        let _ = inputs.push(*c);
                    }
                    for c in &d.output_clusters {
                        let _ = outputs.push(*c);
                    }
                }
                BdbEvent::SimpleDescriptor {
                    src: rsp.addr,
                    endpoint,
                    success: rsp.status == ZdpStatus::Success && desc.is_some(),
                    inputs,
                    outputs,
                }
            }
            StackEvent::Zdp(z) if z.cluster == cluster::response_of(cluster::IEEE_ADDR_REQ) => {
                let rsp = AddrRsp::decode_exact(&z.data).ok()?;
                BdbEvent::IeeeAddress {
                    short: rsp.short,
                    ieee: (rsp.status == ZdpStatus::Success).then_some(rsp.ieee),
                }
            }
            StackEvent::ZdpTimeout {
                dst, cluster: c, ..
            } if *c == cluster::SIMPLE_DESC_REQ => BdbEvent::SimpleDescriptor {
                src: *dst,
                endpoint: Endpoint(0),
                success: false,
                inputs: Vec::new(),
                outputs: Vec::new(),
            },
            StackEvent::ZdpTimeout {
                dst, cluster: c, ..
            } if *c == cluster::IEEE_ADDR_REQ => BdbEvent::IeeeAddress {
                short: *dst,
                ieee: None,
            },
            _ => return None,
        })
    }

    /// Broadcasts Mgmt_Permit_Joining_req (TC significance set) without
    /// touching the local permit flag (BDB 3.1 §9.7 step 2).
    pub fn broadcast_permit_join(&mut self, seconds: u8) -> Result<(), panweave_zdo::ZdoError> {
        let mut tlvs = [0u8; 40];
        let n = self.permit_joining_tlvs(&mut tlvs);
        let req = panweave_zdo::zdp::MgmtPermitJoiningReq {
            duration: if seconds == 0xff { 0xfe } else { seconds },
            tc_significance: true,
            tlvs: tlvs.get(..n).unwrap_or(&[]),
        };
        self.zdo.send_unsolicited(
            ShortAddress::BROADCAST_ROUTERS,
            cluster::MGMT_PERMIT_JOINING_REQ,
            &req,
        )?;
        self.pump();
        Ok(())
    }

    /// TLV Data of a Trust Center's Mgmt_Permit_Joining_req
    /// (§2.4.3.3.7.2): the Beacon Appendix Encapsulation with the
    /// Supported Key Negotiation Methods and Fragmentation Parameters
    /// global TLVs. Empty for devices that are not the Trust Center.
    pub(crate) fn permit_joining_tlvs(&self, out: &mut [u8]) -> usize {
        if !self.aps.config.is_trust_center {
            return 0;
        }
        let mut w = panweave_codec::Writer::new(out);
        let ok = panweave_nwk::tlv::write_encapsulation(
            &mut w,
            panweave_nwk::tlv::tag::BEACON_APPENDIX_ENCAPSULATION,
            |w| {
                panweave_nwk::tlv::SupportedKeyNegotiationMethods {
                    protocols: self.aps.aib.supported_key_negotiation_methods,
                    secrets: panweave_nwk::tlv::SupportedKeyNegotiationMethods::SECRET_AUTH_TOKEN
                        | panweave_nwk::tlv::SupportedKeyNegotiationMethods::SECRET_INSTALL_CODE,
                    source: Some(self.config.ieee),
                }
                .write(w)?;
                panweave_nwk::tlv::FragmentationParameters {
                    node: self.nwk.nib.network_address,
                    options: 0,
                    max_incoming_transfer_unit: self.aps.aib.max_size_asdu,
                }
                .write(w)
            },
        )
        .is_ok();
        if ok { w.position() } else { 0 }
    }

    /// Keeps a sleepy end device polling at the fast rate for `duration`
    /// (BDB 3.1 §5.3.1, §6.6).
    pub fn fast_poll_for(&mut self, duration: Duration) {
        let interval = self.config.fast_poll_interval.as_millis().max(1);
        let polls = duration.as_millis().div_ceil(interval);
        let polls = u8::try_from(polls).unwrap_or(u8::MAX);
        self.fast_polls_left = self.fast_polls_left.max(polls);
        if self.config.sleepy && self.next_poll.is_none() {
            self.next_poll = Some(self.now);
        }
    }
}
