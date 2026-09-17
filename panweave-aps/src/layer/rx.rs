//! APS reception: filtering, security, duplicate rejection, group and
//! broadcast delivery, acknowledgements and reassembly (R23.2
//! §2.2.8.4.2, §2.2.8.4.3, §2.2.8.4.5.4, §4.4.1.2).

use panweave_security::aux_header::KeyIdentifier;
use panweave_security::cipher::BlockCipher;
use panweave_security::frame::SecurityError;
use panweave_types::time::Instant;
use panweave_types::{ClusterId, Endpoint, ExtendedAddress, GroupAddress, ProfileId, ShortAddress};

use super::{Aps, ApsAction, ApsEvent, AsduBuf, DeviceState, NwkView, PersistItem};
use crate::aib::constants;
use crate::frame::{Addressing, DeliveryMode, ExtendedHeader, Fragmentation, FrameType, Header};

/// How a received frame addresses local endpoints.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Delivery {
    /// One endpoint.
    Endpoint(Endpoint),
    /// Every active endpoint 0x01–0xfe (broadcast to endpoint 0xff).
    AllEndpoints,
    /// Every endpoint that is a member of the group (see
    /// [`crate::tables::GroupTable::endpoints`]).
    Group(GroupAddress),
}

/// Security applied to a received frame (APSDE-DATA.indication
/// SecurityStatus).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityStatus {
    /// Neither NWK nor APS security.
    Unsecured,
    /// NWK security only.
    NwkKey,
    /// APS link-key security (and normally NWK security).
    LinkKey,
}

/// Relay information for a frame that arrived inside a Relay Message
/// command (§4.6.3.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RelayInfo {
    /// The parent router that relayed the frame.
    pub parent: ShortAddress,
    /// The joining device (the remote end of the relay).
    pub joiner: ExtendedAddress,
}

/// APSDE-DATA.indication.
#[derive(Clone, Copy, Debug)]
pub struct DataIndication<'a> {
    /// Source network address (the joiner's parent for relayed frames).
    pub src: ShortAddress,
    /// Source IEEE address when known.
    pub src_ieee: Option<ExtendedAddress>,
    /// Source endpoint.
    pub src_endpoint: Endpoint,
    /// Local delivery target.
    pub delivery: Delivery,
    /// Profile identifier.
    pub profile: ProfileId,
    /// Cluster identifier.
    pub cluster: ClusterId,
    /// The ASDU (reassembled when fragmented).
    pub asdu: &'a [u8],
    /// Security status.
    pub security: SecurityStatus,
    /// Link quality of the last hop.
    pub lqi: u8,
    /// Set when the frame was relayed through a parent router.
    pub relayed: Option<RelayInfo>,
    /// APS counter of the frame.
    pub counter: u8,
    /// The NWK destination was a broadcast address.
    pub nwk_broadcast: bool,
}

/// Per-frame reception context.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RxContext {
    pub src: ShortAddress,
    pub dst: ShortAddress,
    pub src_ieee: Option<ExtendedAddress>,
    pub nwk_secured: bool,
    pub lqi: u8,
    pub relayed: Option<RelayInfo>,
}

/// One incoming fragmented transaction (window size 1).
pub(crate) struct Reassembly {
    pub src: ShortAddress,
    pub src_ieee: Option<ExtendedAddress>,
    pub header: Header,
    pub block_count: u8,
    pub next_block: u8,
    pub buf: AsduBuf,
    pub deadline: Instant,
    pub complete: bool,
    pub security: SecurityStatus,
    pub lqi: u8,
}

/// Security outcome of a frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameSecurity {
    pub status: SecurityStatus,
    /// The key-pair partner whose key unsecured the frame.
    pub partner: Option<ExtendedAddress>,
    pub key_id: KeyIdentifier,
    pub extended_nonce: bool,
}

impl<
    C: BlockCipher,
    const KEYS: usize,
    const BINDINGS: usize,
    const GROUPS: usize,
    const DUPS: usize,
> Aps<C, KEYS, BINDINGS, GROUPS, DUPS>
{
    /// NLDE-DATA.indication. `buf` holds the APS frame and is decrypted
    /// in place; `src`/`dst` are the NWK addresses, `src_ieee` the IEEE
    /// address of the sender when the NWK layer knows it, `nwk_secured`
    /// whether NWK security was applied. Returns a data indication when
    /// the frame (or a completed reassembly) is to be delivered.
    pub fn on_nwk_data<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        src: ShortAddress,
        dst: ShortAddress,
        src_ieee: Option<ExtendedAddress>,
        nwk_secured: bool,
        lqi: u8,
        view: &impl NwkView,
    ) -> Option<DataIndication<'a>> {
        let src_ieee = src_ieee.or_else(|| view.ieee_of(src));
        let ctx = RxContext {
            src,
            dst,
            src_ieee,
            nwk_secured,
            lqi,
            relayed: None,
        };
        self.process_frame(buf, ctx, view, 0)
    }

    /// Processes one APS frame (possibly the inner frame of a relay).
    pub(crate) fn process_frame<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        ctx: RxContext,
        view: &impl NwkView,
        depth: u8,
    ) -> Option<DataIndication<'a>> {
        let (header, header_len) = match Header::decode_prefix(buf) {
            Ok(h) => h,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return None;
            }
        };
        let mut sec = FrameSecurity {
            status: if ctx.nwk_secured {
                SecurityStatus::NwkKey
            } else {
                SecurityStatus::Unsecured
            },
            partner: None,
            key_id: KeyIdentifier::Data,
            extended_nonce: false,
        };
        let mut payload_range = header_len..buf.len();
        if header.control.security {
            // APS command frames restore their own level; data frames use
            // nwkSecurityLevel (§4.4.1.2 step 5). Both are the same level
            // on this stack.
            let level = self.config.security_level;
            let sender = ctx.relayed.map(|r| r.joiner).or(ctx.src_ieee);
            let fallback = if self.state == DeviceState::JoinedUnauthorized {
                Some(self.trust_center_partner())
            } else {
                None
            };
            match self
                .security
                .unsecure_incoming(buf, header_len, level, sender, fallback)
            {
                Ok(u) => {
                    payload_range = u.payload_start..u.payload_end;
                    sec = FrameSecurity {
                        status: SecurityStatus::LinkKey,
                        partner: Some(u.partner),
                        key_id: u.key_id,
                        extended_nonce: u.extended_nonce,
                    };
                }
                Err(SecurityError::UnverifiedFrameCounter) => {
                    if let Some(partner) = sender {
                        self.push_event(ApsEvent::FrameCounterUnverified { partner });
                    }
                    self.stats.security_dropped = self.stats.security_dropped.saturating_add(1);
                    return None;
                }
                Err(err) => {
                    if err == SecurityError::BadFrameCounter {
                        self.stats.fc_failures = self.stats.fc_failures.saturating_add(1);
                    }
                    // §4.7.4.1.2.7: during a Trust Center rejoin an APS
                    // command that fails may come from a replacement
                    // Trust Center under the hashed link key.
                    let old_tc = self.aib.trust_center_address;
                    let retry = header.control.frame_type == FrameType::Command
                        && self.state == DeviceState::JoinedUnauthorized
                        && !self.aib.is_distributed();
                    match retry
                        .then(|| {
                            self.security
                                .unsecure_swap_out(buf, header_len, level, old_tc)
                        })
                        .transpose()
                    {
                        Ok(Some((new_tc, key_id, start, end))) => {
                            self.aib.trust_center_address = new_tc;
                            self.push_action(ApsAction::Persist(PersistItem::Aib));
                            self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
                            self.push_event(ApsEvent::TrustCenterSwapped {
                                old: old_tc,
                                new: new_tc,
                            });
                            payload_range = start..end;
                            sec = FrameSecurity {
                                status: SecurityStatus::LinkKey,
                                partner: Some(new_tc),
                                key_id,
                                extended_nonce: true,
                            };
                        }
                        _ => {
                            self.stats.security_dropped =
                                self.stats.security_dropped.saturating_add(1);
                            return None;
                        }
                    }
                }
            }
        }
        match header.control.frame_type {
            FrameType::Ack => {
                self.on_ack(ctx.src, &header);
                None
            }
            FrameType::Command => {
                let start = payload_range.start;
                let end = payload_range.end;
                self.handle_command(buf, start, end, &header, ctx, sec, view, depth)
            }
            FrameType::Data => {
                if ctx.dst.is_broadcast() {
                    self.stats.rx_bcast = self.stats.rx_bcast.saturating_add(1);
                } else {
                    self.stats.rx_ucast = self.stats.rx_ucast.saturating_add(1);
                }
                let start = payload_range.start;
                let end = payload_range.end;
                self.handle_data(buf, start, end, &header, ctx, sec)
            }
            FrameType::InterPan => {
                self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_data<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        start: usize,
        end: usize,
        header: &Header,
        ctx: RxContext,
        sec: FrameSecurity,
    ) -> Option<DataIndication<'a>> {
        let mut ctx = ctx;
        // Unsecured frames the parent forwarded from the Trust Center
        // are limited to the key negotiation services a joining device
        // processes before authorization (§4.6.3.2.3.1).
        // The Trust Center likewise accepts a relayed joiner's
        // Security_Start_Key_Negotiation_req / Start_Key_Update_rsp
        // (§4.6.3.2.2.2).
        let negotiation = sec.status == SecurityStatus::Unsecured
            && !ctx.nwk_secured
            && header.profile == Some(ProfileId::ZDP)
            && match (self.state, ctx.relayed.is_some(), header.cluster) {
                (
                    DeviceState::JoinedUnauthorized,
                    _,
                    Some(ClusterId(0x0045) | ClusterId(0x8040) | ClusterId(0x8041)),
                ) => true,
                (
                    DeviceState::JoinedAuthorized,
                    true,
                    Some(ClusterId(0x0040) | ClusterId(0x8045)),
                ) => self.config.is_trust_center,
                _ => false,
            };
        if self.state != DeviceState::JoinedAuthorized && ctx.relayed.is_none() {
            // While joined-but-unauthorized only frames the parent
            // extracted from a Tunnel / Relay Message Downstream reach
            // us: APS-secured by the Trust Center with an extended nonce
            // (§4.6.3.7.3). They are treated as relayed.
            let from_tc = sec.status == SecurityStatus::LinkKey
                && sec.extended_nonce
                && sec.partner == Some(self.trust_center_partner());
            if self.state != DeviceState::JoinedUnauthorized || !(from_tc || negotiation) {
                self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                return None;
            }
            ctx.relayed = Some(RelayInfo {
                parent: ctx.src,
                joiner: self.local_ieee,
            });
            // The parent only forwards what the Trust Center relayed.
            ctx.src_ieee = Some(self.trust_center_partner());
        }
        if sec.status == SecurityStatus::Unsecured
            && !self.config.accept_unsecured_data
            && !negotiation
        {
            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
            return None;
        }
        let (Some(src_endpoint), Some(cluster), Some(profile)) =
            (header.src_endpoint, header.cluster, header.profile)
        else {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return None;
        };
        let delivery = match (header.control.delivery_mode, header.destination) {
            (DeliveryMode::Group, Some(Addressing::Group(g))) => {
                if !self.groups.is_member(g) {
                    return None;
                }
                Delivery::Group(g)
            }
            (DeliveryMode::Broadcast, Some(Addressing::Endpoint(ep))) => {
                if ep == Endpoint::BROADCAST {
                    Delivery::AllEndpoints
                } else {
                    Delivery::Endpoint(ep)
                }
            }
            (DeliveryMode::Unicast, Some(Addressing::Endpoint(ep))) => {
                if ep == Endpoint::BROADCAST && ctx.dst.is_broadcast() {
                    Delivery::AllEndpoints
                } else {
                    Delivery::Endpoint(ep)
                }
            }
            _ => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return None;
            }
        };
        let unicast = ctx.dst.is_unicast()
            && header.control.delivery_mode == DeliveryMode::Unicast
            && ctx.relayed.is_none();
        let ack_requested = header.control.ack_request && unicast;
        // Frames tunneled to an unauthorized device carry an extended
        // nonce and bypass duplicate rejection (§4.6.3.7.3).
        let skip_dedup = sec.extended_nonce && self.state != DeviceState::JoinedAuthorized;

        if header.fragmentation() != Fragmentation::None {
            if header.control.delivery_mode != DeliveryMode::Unicast
                || !header.control.ack_request
                || ctx.relayed.is_some()
            {
                // Fragmentation requires acknowledged unicast
                // (§2.2.8.4.5); reject otherwise.
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return None;
            }
            return self.handle_fragment(buf, start, end, header, ctx, sec, delivery);
        }

        if !skip_dedup
            && self.dedup.check_and_record(
                ctx.src,
                header.counter,
                self.now,
                constants::DUPLICATE_REJECTION_TIMEOUT,
            )
        {
            self.stats.duplicates = self.stats.duplicates.saturating_add(1);
            if ack_requested {
                self.send_ack(header, None, ctx, sec);
            }
            return None;
        }
        if ack_requested {
            self.send_ack(header, None, ctx, sec);
        }
        let asdu = buf.get(start..end)?;
        Some(DataIndication {
            src: ctx.src,
            // Relayed frames come from the joiner (at the Trust Center) or
            // from the Trust Center (at the joiner).
            src_ieee: ctx
                .relayed
                .map(|r| r.joiner)
                .filter(|j| *j != self.local_ieee)
                .or(ctx.src_ieee),
            src_endpoint,
            delivery,
            profile,
            cluster,
            asdu,
            security: sec.status,
            lqi: ctx.lqi,
            relayed: ctx.relayed,
            counter: header.counter,
            nwk_broadcast: ctx.dst.is_broadcast(),
        })
    }

    /// Reassembly with window size 1 (blocks arrive in order).
    #[allow(clippy::too_many_arguments)]
    fn handle_fragment<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        start: usize,
        end: usize,
        header: &Header,
        ctx: RxContext,
        sec: FrameSecurity,
        delivery: Delivery,
    ) -> Option<DataIndication<'a>> {
        let ext = header.extended?;
        let block = match ext.fragmentation {
            Fragmentation::First => 0u8,
            Fragmentation::Part => ext.block_number,
            Fragmentation::None => return None,
        };
        let payload = buf.get(start..end)?;
        let now = self.now;
        // Drop an expired transaction.
        if let Some(r) = &self.reassembly
            && now.has_reached(r.deadline)
        {
            self.reassembly = None;
        }
        let same = self
            .reassembly
            .as_ref()
            .is_some_and(|r| r.src == ctx.src && r.header.counter == header.counter);
        if block == 0 {
            if same {
                // Duplicate first block (or duplicate transaction).
                self.send_ack(header, Some(ack_ext(ext.fragmentation, 0)), ctx, sec);
                return None;
            }
            if self.reassembly.as_ref().is_some_and(|r| !r.complete) {
                // Another transaction is in progress; reject (§2.2.8.4.5.4).
                self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                return None;
            }
            if ext.block_number == 0 || payload.is_empty() {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return None;
            }
            let mut r = Reassembly {
                src: ctx.src,
                src_ieee: ctx.src_ieee,
                header: *header,
                block_count: ext.block_number,
                next_block: 1,
                buf: AsduBuf::new(),
                deadline: now.saturating_add(constants::FRAGMENT_RECEIVE_TIMEOUT),
                complete: false,
                security: sec.status,
                lqi: ctx.lqi,
            };
            if r.buf.extend_from_slice(payload).is_err() {
                // DEFRAG_UNSUPPORTED: larger than apsMaxSizeASDU.
                self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                return None;
            }
            self.send_ack(header, Some(ack_ext(ext.fragmentation, 0)), ctx, sec);
            if r.block_count == 1 {
                r.complete = true;
                r.deadline = now.saturating_add(constants::FRAGMENT_PERSISTENCE);
                self.reassembly = Some(r);
                self.stats.reassembled = self.stats.reassembled.saturating_add(1);
                return self.reassembled_indication(delivery);
            }
            self.reassembly = Some(r);
            return None;
        }
        if !same {
            // No matching transaction: no acknowledgement (§2.2.8.4.5.4).
            return None;
        }
        let r = self.reassembly.as_mut()?;
        if r.complete || block < r.next_block {
            // Duplicate block: acknowledge again.
            let frag = ext.fragmentation;
            self.send_ack(header, Some(ack_ext(frag, block)), ctx, sec);
            return None;
        }
        if block != r.next_block || block >= r.block_count {
            // Outside the receive window.
            return None;
        }
        if r.buf.extend_from_slice(payload).is_err() {
            self.reassembly = None;
            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
            return None;
        }
        r.next_block = block.saturating_add(1);
        r.deadline = now.saturating_add(constants::FRAGMENT_RECEIVE_TIMEOUT);
        let last = r.next_block == r.block_count;
        if last {
            r.complete = true;
            r.deadline = now.saturating_add(constants::FRAGMENT_PERSISTENCE);
        }
        self.send_ack(header, Some(ack_ext(ext.fragmentation, block)), ctx, sec);
        if last {
            self.stats.reassembled = self.stats.reassembled.saturating_add(1);
            return self.reassembled_indication(delivery);
        }
        None
    }

    fn reassembled_indication(&mut self, delivery: Delivery) -> Option<DataIndication<'_>> {
        let r = self.reassembly.as_ref()?;
        Some(DataIndication {
            src: r.src,
            src_ieee: r.src_ieee,
            src_endpoint: r.header.src_endpoint?,
            delivery,
            profile: r.header.profile?,
            cluster: r.header.cluster?,
            asdu: &r.buf,
            security: r.security,
            lqi: r.lqi,
            relayed: None,
            counter: r.header.counter,
            nwk_broadcast: false,
        })
    }

    /// Drops a completed or timed-out reassembly.
    pub(crate) fn expire_reassembly(&mut self) {
        if let Some(r) = &self.reassembly
            && self.now.has_reached(r.deadline)
        {
            self.reassembly = None;
        }
    }

    /// Sends an APS acknowledgement for `of` (§2.2.8.4.3.2). The
    /// acknowledgement mirrors the security of the acknowledged frame
    /// (APS link key when the frame was APS-secured, NWK security
    /// otherwise) — an implementation choice; the specification only
    /// fixes the header fields.
    pub(crate) fn send_ack(
        &mut self,
        of: &Header,
        ext: Option<ExtendedHeader>,
        ctx: RxContext,
        sec: FrameSecurity,
    ) {
        let mut ack = Header::ack_for(of, ext);
        let partner = sec.partner.filter(|_| sec.key_id == KeyIdentifier::Data);
        ack = ack.secured(partner.is_some());
        let frame = match self.secure_frame(&ack, &[], partner, KeyIdentifier::Data, false) {
            Ok(f) => f,
            Err(crate::security::SecureError::CounterPending) => {
                // The acknowledgement is lost this once; the sender
                // retries after the reservation is persisted.
                self.request_counter_reservations();
                return;
            }
            Err(_) => return,
        };
        self.stats.acks_sent = self.stats.acks_sent.saturating_add(1);
        if let Some(relay) = ctx.relayed {
            let tc = self.config.is_trust_center;
            self.send_relay_command(relay.parent, relay.joiner, &frame, tc, tc);
            return;
        }
        let handle = self.alloc_handle();
        self.push_action(ApsAction::NwkData {
            handle,
            dst: ctx.src,
            radius: None,
            discover_route: true,
            secure: ctx.nwk_secured,
            alias: None,
            frame,
        });
    }
}

/// Extended header of a fragment acknowledgement: same fragmentation
/// value, the acknowledged block, bit 0 set and the bits above the window
/// set (window size 1, §2.2.8.4.5.4).
const fn ack_ext(fragmentation: Fragmentation, block: u8) -> ExtendedHeader {
    ExtendedHeader {
        fragmentation,
        block_number: block,
        ack_bitfield: Some(0xFF),
    }
}
