//! APS transmission: APSDE-DATA.request, acknowledgements and
//! retransmissions (R23.2 §2.2.8.4.1, §2.2.8.4.3, §2.2.8.4.4) and
//! fragmented transmissions with window size 1 (§2.2.8.4.5.3).

use heapless::Vec;
use panweave_codec::Encode;
use panweave_security::aux_header::KeyIdentifier;
use panweave_security::cipher::BlockCipher;
use panweave_types::time::Instant;
use panweave_types::{
    ApsStatus, Endpoint, ExtendedAddress, Key128, KeyAttributes, NwkStatus, ShortAddress,
};
use zeroize::Zeroize;

use super::{
    Aps, ApsAction, ApsError, ApsEvent, AsduBuf, DataRequest, Delivery, Destination, DeviceState,
    FrameBuf, Loopback, NwkHandle, NwkView, RequestId, TxOptions,
};
use crate::aib::constants;
use crate::command::ApsCommandId;
use crate::frame::{Addressing, ExtendedHeader, Fragmentation, Header};
use crate::security::SecureError;
use crate::tables::BindingDestination;

/// Transmission state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TxState {
    /// Ready to (re)transmit the current block.
    Ready,
    /// Waiting for a link-key counter reservation to be committed.
    CounterPending,
    /// Handed to the NWK layer; waiting for NLDE-DATA.confirm.
    AwaitingNwkConfirm,
    /// Waiting for the APS acknowledgement.
    AwaitingAck {
        /// `apscAckWaitDuration` deadline.
        deadline: Instant,
    },
}

/// What a pending entry carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TxKind {
    Data,
    Command(ApsCommandId),
}

/// Follow-up applied when a command is confirmed successfully.
#[derive(Clone)]
pub(crate) enum PostAction {
    /// Replace `partner`'s link key (a transported Trust Center link key,
    /// §4.4.2.1.3) and mark it UNVERIFIED until Verify Key.
    ReplaceKey {
        partner: ExtendedAddress,
        key: Key128,
    },
}

/// Command that wraps the frame built from the ASDU (Tunnel / Relay).
#[derive(Clone, Copy)]
pub(crate) enum Wrap {
    /// Relay Message Downstream (`downstream`) or Upstream: the ASDU is
    /// the inner data frame payload, secured with `inner_partner`'s data
    /// key when set.
    Relay {
        joiner: ExtendedAddress,
        downstream: bool,
        inner_header: Header,
        inner_partner: Option<ExtendedAddress>,
    },
    /// Tunnel: the ASDU is an APS command payload secured with the
    /// joiner's key-transport key.
    Tunnel {
        joiner: ExtendedAddress,
        inner_header: Header,
        inner_partner: ExtendedAddress,
    },
}

/// An outstanding transmission.
pub(crate) struct PendingTx {
    pub request: RequestId,
    pub kind: TxKind,
    pub handle: Option<NwkHandle>,
    pub dst: ShortAddress,
    /// Key-pair partner when APS security applies.
    pub partner: Option<ExtendedAddress>,
    pub key_id: KeyIdentifier,
    pub extended_nonce: bool,
    pub header: Header,
    pub asdu: AsduBuf,
    pub nwk_secure: bool,
    pub radius: Option<u8>,
    pub alias: Option<(ShortAddress, u8)>,
    pub ack: bool,
    /// Total blocks (0 = not fragmented).
    pub block_count: u8,
    /// Current block index.
    pub block: u8,
    pub block_size: usize,
    pub retries: u8,
    pub state: TxState,
    pub post: Option<PostAction>,
    pub wrap: Option<Wrap>,
}

impl Drop for PendingTx {
    fn drop(&mut self) {
        // Command payloads may carry key material.
        self.asdu.as_mut_slice().zeroize();
    }
}

/// Bookkeeping for one APSDE-DATA / APSME request that may fan out to
/// several transmissions (binding table destinations).
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestState {
    pub id: RequestId,
    pub remaining: u8,
    pub status: ApsStatus,
    pub command: Option<ApsCommandId>,
}

/// Parameters of one transmission.
pub(crate) struct TxParams {
    pub request: RequestId,
    pub kind: TxKind,
    pub dst: ShortAddress,
    pub partner: Option<ExtendedAddress>,
    pub key_id: KeyIdentifier,
    pub extended_nonce: bool,
    pub header: Header,
    pub nwk_secure: bool,
    pub radius: Option<u8>,
    pub alias: Option<(ShortAddress, u8)>,
    pub ack: bool,
    pub post: Option<PostAction>,
    pub wrap: Option<Wrap>,
}

impl<
    C: BlockCipher,
    const KEYS: usize,
    const BINDINGS: usize,
    const GROUPS: usize,
    const DUPS: usize,
> Aps<C, KEYS, BINDINGS, GROUPS, DUPS>
{
    /// APSDE-DATA.request (§2.2.4.1.1). Returns the request identifier
    /// echoed in [`ApsEvent::DataConfirm`]. Bound and group frames that
    /// have local members are also delivered through
    /// [`Aps::take_loopback`].
    pub fn data_request(
        &mut self,
        req: &DataRequest<'_>,
        view: &impl NwkView,
    ) -> Result<RequestId, ApsError> {
        if self.state == DeviceState::NotJoined {
            return Err(ApsError::NotJoined);
        }
        if req.asdu.len() > super::MAX_ASDU {
            return Err(ApsError::AsduTooLong);
        }
        if req.src_endpoint == Endpoint::BROADCAST {
            return Err(ApsError::InvalidParameter);
        }
        // §2.2.4.1.1: an aliased frame carries the alias sequence number
        // as its APS counter and cannot be acknowledged.
        if req.alias.is_some() && req.options.ack {
            return Err(ApsError::InvalidParameter);
        }
        let counter = match req.alias {
            Some((_, seq)) => seq,
            None => self.next_counter(),
        };
        let id = self.alloc_request();
        match req.destination {
            Destination::Bound => {
                let mut dests: Vec<BindingDestination, 8> = Vec::new();
                for d in self.bindings.destinations(req.src_endpoint, req.cluster) {
                    if dests.push(d).is_err() {
                        break;
                    }
                }
                if dests.is_empty() {
                    return Err(ApsError::NoBoundDevice);
                }
                let mut count = 0u8;
                let mut loopback_ep: Option<Delivery> = None;
                let mut first_err: Option<ApsError> = None;
                for d in dests {
                    let r = match d {
                        BindingDestination::Unicast { address, endpoint } => {
                            if address == self.local_ieee {
                                loopback_ep = Some(Delivery::Endpoint(endpoint));
                                continue;
                            }
                            match view.short_of(address) {
                                Some(short) => self.queue_data(
                                    id,
                                    short,
                                    Some(address),
                                    Addressing::Endpoint(endpoint),
                                    req,
                                    counter,
                                ),
                                None => Err(ApsError::NoShortAddress),
                            }
                        }
                        BindingDestination::Group(g) => {
                            if self.groups.is_member(g) {
                                loopback_ep = Some(Delivery::Group(g));
                            }
                            self.queue_data(
                                id,
                                ShortAddress::BROADCAST_RX_ON,
                                None,
                                Addressing::Group(g),
                                req,
                                counter,
                            )
                        }
                    };
                    match r {
                        Ok(()) => count = count.saturating_add(1),
                        Err(e) => {
                            first_err.get_or_insert(e);
                        }
                    }
                }
                if let Some(d) = loopback_ep {
                    self.set_loopback(d, req);
                }
                if count == 0 {
                    if loopback_ep.is_some() {
                        self.push_event(ApsEvent::DataConfirm {
                            id,
                            status: ApsStatus::Success,
                        });
                        return Ok(id);
                    }
                    return Err(first_err.unwrap_or(ApsError::NoBoundDevice));
                }
                self.track_request(id, count, None)?;
            }
            Destination::Group(g) => {
                if self.groups.is_member(g) {
                    self.set_loopback(Delivery::Group(g), req);
                }
                self.queue_data(
                    id,
                    ShortAddress::BROADCAST_RX_ON,
                    None,
                    Addressing::Group(g),
                    req,
                    counter,
                )?;
                self.track_request(id, 1, None)?;
            }
            Destination::Short { address, endpoint } => {
                if address == ShortAddress::NO_SHORT_ADDRESS {
                    return Err(ApsError::InvalidParameter);
                }
                let partner = if req.options.security {
                    view.ieee_of(address)
                } else {
                    None
                };
                self.queue_data(
                    id,
                    address,
                    partner,
                    Addressing::Endpoint(endpoint),
                    req,
                    counter,
                )?;
                self.track_request(id, 1, None)?;
            }
            Destination::Extended { address, endpoint } => {
                let short = view.short_of(address).ok_or(ApsError::NoShortAddress)?;
                self.queue_data(
                    id,
                    short,
                    Some(address),
                    Addressing::Endpoint(endpoint),
                    req,
                    counter,
                )?;
                self.track_request(id, 1, None)?;
            }
            Destination::Relayed {
                parent,
                joiner: Some(j),
                endpoint,
            } if parent == self.local_short || view.unauthenticated_child(j) == Some(parent) => {
                // The Trust Center is the joiner's parent: deliver the
                // frame the way a relaying parent would after extracting
                // it, NWK-unsecured to the unauthorized child.
                let short = view.unauthenticated_child(j).ok_or(ApsError::NoKey)?;
                self.queue_direct_to_joiner(id, short, j, endpoint, req, counter)?;
                self.track_request(id, 1, None)?;
            }
            Destination::Relayed {
                parent,
                joiner,
                endpoint,
            } => {
                self.queue_relayed(id, parent, joiner, endpoint, req, counter)?;
                self.track_request(id, 1, None)?;
            }
        }
        self.service_pending();
        Ok(id)
    }

    fn set_loopback(&mut self, delivery: Delivery, req: &DataRequest<'_>) {
        if let Ok(asdu) = AsduBuf::from_slice(req.asdu) {
            self.loopback = Some(Loopback {
                delivery,
                profile: req.profile,
                cluster: req.cluster,
                src_endpoint: req.src_endpoint,
                asdu,
            });
        }
    }

    fn queue_data(
        &mut self,
        id: RequestId,
        dst: ShortAddress,
        dst_ieee: Option<ExtendedAddress>,
        addressing: Addressing,
        req: &DataRequest<'_>,
        counter: u8,
    ) -> Result<(), ApsError> {
        let unicast = dst.is_unicast() && matches!(addressing, Addressing::Endpoint(_));
        let mut header = Header::data(
            addressing,
            req.cluster,
            req.profile,
            req.src_endpoint,
            counter,
        );
        if !unicast && matches!(addressing, Addressing::Endpoint(_)) {
            header = header.broadcast();
        }
        // Acknowledgements are never requested for broadcasts or groups
        // (§2.2.8.4.3).
        let ack = req.options.ack && unicast;
        header = header.with_ack_request(ack);
        let partner = if req.options.security {
            let ieee = dst_ieee.ok_or(ApsError::NoKey)?;
            Some(self.link_key_for(ieee).ok_or(ApsError::NoKey)?)
        } else {
            None
        };
        header = header.secured(partner.is_some());
        self.queue_tx(
            TxParams {
                request: id,
                kind: TxKind::Data,
                dst,
                partner,
                key_id: KeyIdentifier::Data,
                extended_nonce: req.options.extended_nonce,
                header,
                nwk_secure: true,
                radius: req.radius,
                alias: req.alias,
                ack,
                post: None,
                wrap: None,
            },
            req.asdu,
            req.options.fragmentation_permitted && ack,
        )
    }

    /// A data frame for an unauthorized child of this device: unicast,
    /// unacknowledged, NWK-unsecured (§4.6.3.2.1 as performed by the
    /// parent).
    fn queue_direct_to_joiner(
        &mut self,
        id: RequestId,
        short: ShortAddress,
        joiner: ExtendedAddress,
        endpoint: Endpoint,
        req: &DataRequest<'_>,
        counter: u8,
    ) -> Result<(), ApsError> {
        let mut header = Header::data(
            Addressing::Endpoint(endpoint),
            req.cluster,
            req.profile,
            req.src_endpoint,
            counter,
        )
        .with_ack_request(false);
        let partner = if req.options.security {
            Some(self.link_key_for(joiner).ok_or(ApsError::NoKey)?)
        } else {
            None
        };
        header = header.secured(partner.is_some());
        self.queue_tx(
            TxParams {
                request: id,
                kind: TxKind::Data,
                dst: short,
                partner,
                key_id: KeyIdentifier::Data,
                extended_nonce: true,
                header,
                nwk_secure: false,
                radius: Some(1),
                alias: None,
                ack: false,
                post: None,
                wrap: None,
            },
            req.asdu,
            false,
        )
    }

    /// Queues one transmission; fragments when needed.
    pub(crate) fn queue_tx(
        &mut self,
        p: TxParams,
        asdu: &[u8],
        fragmentation_permitted: bool,
    ) -> Result<(), ApsError> {
        let aps_sec = p.partner.map(|_| p.extended_nonce);
        let single_max = if p.wrap.is_some() {
            usize::MAX
        } else {
            self.frame_payload_max(&p.header, aps_sec)
        };
        let (block_count, block_size) = if asdu.len() <= single_max {
            (0u8, asdu.len())
        } else {
            if !fragmentation_permitted || matches!(p.kind, TxKind::Command(_)) {
                return Err(ApsError::AsduTooLong);
            }
            let frag_header = p.header.with_extended(ExtendedHeader {
                fragmentation: Fragmentation::First,
                block_number: 0,
                ack_bitfield: None,
            });
            let block_size = self.frame_payload_max(&frag_header, aps_sec);
            if block_size == 0 {
                return Err(ApsError::AsduTooLong);
            }
            let count = asdu.len().div_ceil(block_size);
            if count > 255 {
                return Err(ApsError::AsduTooLong);
            }
            #[allow(clippy::cast_possible_truncation)]
            (count as u8, block_size)
        };
        let asdu = AsduBuf::from_slice(asdu).map_err(|_| ApsError::AsduTooLong)?;
        let entry = PendingTx {
            request: p.request,
            kind: p.kind,
            handle: None,
            dst: p.dst,
            partner: p.partner,
            key_id: p.key_id,
            extended_nonce: p.extended_nonce,
            header: p.header,
            asdu,
            nwk_secure: p.nwk_secure,
            radius: p.radius,
            alias: p.alias,
            ack: p.ack,
            block_count,
            block: 0,
            block_size,
            retries: 0,
            state: TxState::Ready,
            post: p.post,
            wrap: p.wrap,
        };
        self.pending.push(entry).map_err(|_| ApsError::Busy)
    }

    pub(crate) fn track_request(
        &mut self,
        id: RequestId,
        count: u8,
        command: Option<ApsCommandId>,
    ) -> Result<(), ApsError> {
        self.requests
            .push(RequestState {
                id,
                remaining: count,
                status: ApsStatus::Success,
                command,
            })
            .map_err(|_| {
                self.pending.retain(|p| p.request != id);
                ApsError::Busy
            })
    }

    /// Encodes `header`, appends `payload` and applies APS security with
    /// `partner`'s key (fresh frame counter) when `header.control.security`
    /// is set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn secure_frame(
        &mut self,
        header: &Header,
        payload: &[u8],
        partner: Option<ExtendedAddress>,
        key_id: KeyIdentifier,
        extended_nonce: bool,
    ) -> Result<FrameBuf, SecureError> {
        use panweave_security::frame::SecurityError;
        let partner = partner.filter(|_| header.control.security);
        let header_len = header.encoded_len();
        let aux_len = partner.map_or(0, |_| {
            crate::security::ApsSecurity::<C, KEYS>::aux_header_len(extended_nonce)
        });
        let mic_len = partner.map_or(0, |_| self.config.security_level.mic_len());
        let total = header_len + aux_len + payload.len() + mic_len;
        let mut buf = FrameBuf::new();
        buf.resize(total, 0)
            .map_err(|_| SecureError::Security(SecurityError::BufferTooSmall))?;
        let mut w = panweave_codec::Writer::new(buf.as_mut_slice());
        header
            .encode(&mut w)
            .map_err(|_| SecureError::Security(SecurityError::Malformed))?;
        let body_start = header_len + aux_len;
        if let Some(slot) = buf.get_mut(body_start..body_start + payload.len()) {
            slot.copy_from_slice(payload);
        }
        if let Some(partner) = partner {
            let level = self.config.security_level;
            let local = self.local_ieee;
            let n = self.security.secure_outgoing(
                buf.as_mut_slice(),
                header_len,
                payload.len(),
                level,
                partner,
                key_id,
                local,
                extended_nonce,
            )?;
            buf.truncate(n);
        }
        Ok(buf)
    }

    /// Builds the frame for the current block of `pending[idx]`, applying
    /// APS security with a fresh frame counter. Wrapped entries first
    /// build and secure the inner frame, then the wrapper command.
    fn build_frame(&mut self, idx: usize) -> Result<FrameBuf, SecureError> {
        use crate::command::{ApsCommand, RelayMessage, Tunnel};
        let Some(p) = self.pending.get(idx) else {
            return Err(SecureError::NoKey);
        };
        let (partner, key_id, ext, wrap, mut header) =
            (p.partner, p.key_id, p.extended_nonce, p.wrap, p.header);
        let mut wrapped: AsduBuf = AsduBuf::new();
        let (start, end) = if p.block_count == 0 {
            (0, p.asdu.len())
        } else {
            let e = if p.block == 0 {
                ExtendedHeader {
                    fragmentation: Fragmentation::First,
                    block_number: p.block_count,
                    ack_bitfield: None,
                }
            } else {
                ExtendedHeader {
                    fragmentation: Fragmentation::Part,
                    block_number: p.block,
                    ack_bitfield: None,
                }
            };
            header = header.with_extended(e);
            let start = usize::from(p.block) * p.block_size;
            (start, (start + p.block_size).min(p.asdu.len()))
        };
        if let Some(wrap) = wrap {
            let asdu: AsduBuf = AsduBuf::from_slice(p.asdu.get(start..end).unwrap_or(&[]))
                .map_err(|_| SecureError::NoKey)?;
            let inner = match wrap {
                Wrap::Relay {
                    inner_header,
                    inner_partner,
                    ..
                } => self.secure_frame(
                    &inner_header,
                    &asdu,
                    inner_partner,
                    KeyIdentifier::Data,
                    true,
                )?,
                Wrap::Tunnel {
                    inner_header,
                    inner_partner,
                    ..
                } => self.secure_frame(
                    &inner_header,
                    &asdu,
                    Some(inner_partner),
                    KeyIdentifier::KeyTransport,
                    true,
                )?,
            };
            let cmd = match wrap {
                Wrap::Relay {
                    joiner, downstream, ..
                } => {
                    let r = RelayMessage {
                        joiner,
                        message: &inner,
                    };
                    if downstream {
                        ApsCommand::RelayDownstream(r)
                    } else {
                        ApsCommand::RelayUpstream(r)
                    }
                }
                Wrap::Tunnel { joiner, .. } => ApsCommand::Tunnel(Tunnel {
                    destination: joiner,
                    tunneled: &inner,
                }),
            };
            wrapped
                .resize(super::MAX_ASDU, 0)
                .map_err(|_| SecureError::NoKey)?;
            let n = cmd
                .encode_to_slice(wrapped.as_mut_slice())
                .map_err(|_| SecureError::NoKey)?;
            wrapped.truncate(n);
            return self.secure_frame(&header, &wrapped, partner, key_id, ext);
        }
        let Some(p) = self.pending.get(idx) else {
            return Err(SecureError::NoKey);
        };
        let payload: AsduBuf = AsduBuf::from_slice(p.asdu.get(start..end).unwrap_or(&[]))
            .map_err(|_| SecureError::NoKey)?;
        self.secure_frame(&header, &payload, partner, key_id, ext)
    }

    /// Hands every ready transmission to the NWK layer.
    pub(crate) fn service_pending(&mut self) {
        let mut idx = 0;
        while idx < self.pending.len() {
            let Some(p) = self.pending.get(idx) else {
                break;
            };
            if p.state != TxState::Ready {
                idx += 1;
                continue;
            }
            match self.build_frame(idx) {
                Ok(frame) => {
                    let handle = self.alloc_handle();
                    let Some(p) = self.pending.get_mut(idx) else {
                        break;
                    };
                    p.handle = Some(handle);
                    p.state = TxState::AwaitingNwkConfirm;
                    let (dst, radius, secure, alias) = (p.dst, p.radius, p.nwk_secure, p.alias);
                    self.push_action(ApsAction::NwkData {
                        handle,
                        dst,
                        radius,
                        discover_route: dst.is_unicast(),
                        secure,
                        alias,
                        frame,
                    });
                    idx += 1;
                }
                Err(SecureError::CounterPending) => {
                    if let Some(p) = self.pending.get_mut(idx) {
                        p.state = TxState::CounterPending;
                    }
                    self.request_counter_reservations();
                    idx += 1;
                }
                Err(_) => {
                    self.complete(idx, ApsStatus::SecurityFail);
                }
            }
        }
    }

    /// Re-arms transmissions parked on a counter reservation.
    pub(crate) fn release_counter_pending(&mut self) {
        for p in &mut self.pending {
            if p.state == TxState::CounterPending {
                p.state = TxState::Ready;
            }
        }
    }

    /// NLDE-DATA.confirm for the transmission identified by `handle`.
    pub fn on_nwk_data_confirm(&mut self, handle: NwkHandle, status: NwkStatus) {
        let Some(idx) = self.pending.iter().position(|p| p.handle == Some(handle)) else {
            return;
        };
        let Some(p) = self.pending.get_mut(idx) else {
            return;
        };
        if p.state != TxState::AwaitingNwkConfirm {
            return;
        }
        p.handle = None;
        if status.is_success() {
            if p.ack {
                p.state = TxState::AwaitingAck {
                    deadline: self.now.saturating_add(constants::ACK_WAIT_DURATION),
                };
            } else {
                self.complete(idx, ApsStatus::Success);
            }
            return;
        }
        // NWK failure: acknowledged frames retry like a lost
        // acknowledgement; others fail with the NWK status.
        if p.ack && p.retries < constants::MAX_FRAME_RETRIES {
            p.retries += 1;
            p.state = TxState::Ready;
            self.stats.retries = self.stats.retries.saturating_add(1);
            self.service_pending();
        } else {
            let st = ApsStatus::from_raw(status.raw());
            self.complete(idx, st);
        }
    }

    /// Matches a received acknowledgement (§2.2.8.4.4, §2.2.8.4.5.3).
    pub(crate) fn on_ack(&mut self, src: ShortAddress, ack: &Header) {
        let Some(idx) = self.pending.iter().position(|p| {
            if p.dst != src || p.header.counter != ack.counter {
                return false;
            }
            if !matches!(p.state, TxState::AwaitingAck { .. }) {
                return false;
            }
            match p.kind {
                TxKind::Command(_) => ack.control.ack_format,
                TxKind::Data => {
                    !ack.control.ack_format
                        && ack.cluster == p.header.cluster
                        && ack.src_endpoint == p.header.dst_endpoint()
                        && ack.dst_endpoint() == p.header.src_endpoint
                }
            }
        }) else {
            return;
        };
        let Some(p) = self.pending.get_mut(idx) else {
            return;
        };
        if p.block_count != 0 {
            let acked = ack
                .extended
                .is_some_and(|e| e.block_number == p.block && e.ack_bitfield.unwrap_or(1) & 1 != 0);
            if !acked {
                return;
            }
            let next = p.block.saturating_add(1);
            if next < p.block_count {
                p.block = next;
                p.retries = 0;
                p.state = TxState::Ready;
                self.service_pending();
                return;
            }
        }
        self.complete(idx, ApsStatus::Success);
    }

    /// Times out acknowledged transmissions and retransmits.
    pub(crate) fn expire_acks(&mut self) {
        let now = self.now;
        let mut idx = 0;
        while idx < self.pending.len() {
            let Some(p) = self.pending.get_mut(idx) else {
                break;
            };
            if let TxState::AwaitingAck { deadline } = p.state
                && now.has_reached(deadline)
            {
                if p.retries < constants::MAX_FRAME_RETRIES {
                    p.retries += 1;
                    p.state = TxState::Ready;
                    self.stats.retries = self.stats.retries.saturating_add(1);
                } else {
                    self.stats.ack_failures = self.stats.ack_failures.saturating_add(1);
                    self.complete(idx, ApsStatus::NoAck);
                    continue;
                }
            }
            idx += 1;
        }
    }

    /// Finishes `pending[idx]` with `status` and confirms the request
    /// once all its transmissions are done.
    pub(crate) fn complete(&mut self, idx: usize, status: ApsStatus) {
        if idx >= self.pending.len() {
            return;
        }
        let p = self.pending.swap_remove(idx);
        if status.is_success()
            && let Some(PostAction::ReplaceKey { partner, key }) = p.post.clone()
        {
            self.security.replace_key(
                partner,
                key,
                KeyAttributes::UnverifiedKey,
                panweave_security::material::LinkKeyKind::Unique,
            );
            self.push_action(ApsAction::Persist(super::PersistItem::LinkKeys));
        }
        let request = p.request;
        drop(p);
        let Some(ri) = self.requests.iter().position(|r| r.id == request) else {
            return;
        };
        let Some(r) = self.requests.get_mut(ri) else {
            return;
        };
        if !status.is_success() && r.status.is_success() {
            r.status = status;
        }
        r.remaining = r.remaining.saturating_sub(1);
        if r.remaining == 0 {
            let r = self.requests.swap_remove(ri);
            match r.command {
                Some(command) => self.push_event(ApsEvent::CommandConfirm {
                    id: r.id,
                    command,
                    status: r.status,
                }),
                None => self.push_event(ApsEvent::DataConfirm {
                    id: r.id,
                    status: r.status,
                }),
            }
        }
    }

    /// Fails every outstanding transmission.
    pub(crate) fn fail_all_pending(&mut self, status: ApsStatus) {
        while !self.pending.is_empty() {
            self.complete(0, status);
        }
        self.requests.clear();
    }

    /// Number of outstanding transmissions.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Queues a data frame relayed through a parent router
    /// (§4.6.3.7.5): the APS data frame is built (and APS-secured with
    /// the joiner's / Trust Center's link key) at transmission time and
    /// embedded in a Relay Message Downstream or Upstream command to
    /// `parent`.
    fn queue_relayed(
        &mut self,
        id: RequestId,
        parent: ShortAddress,
        joiner: Option<ExtendedAddress>,
        endpoint: Endpoint,
        req: &DataRequest<'_>,
        counter: u8,
    ) -> Result<(), ApsError> {
        let partner_ieee = match joiner {
            Some(j) => j,
            None => self.trust_center_partner(),
        };
        let mut inner_header = Header::data(
            Addressing::Endpoint(endpoint),
            req.cluster,
            req.profile,
            req.src_endpoint,
            counter,
        )
        .with_ack_request(false);
        let inner_partner = if req.options.security {
            Some(self.link_key_for(partner_ieee).ok_or(ApsError::NoKey)?)
        } else {
            None
        };
        inner_header = inner_header.secured(inner_partner.is_some());
        let cmd_counter = self.next_counter();
        let downstream = joiner.is_some();
        let cmd_id = if downstream {
            ApsCommandId::RelayMessageDownstream
        } else {
            ApsCommandId::RelayMessageUpstream
        };
        // The relay command is NWK-secured towards the Trust Center; a
        // joiner sends it unsecured to its parent (§4.6.3.2.1).
        self.queue_tx(
            TxParams {
                request: id,
                kind: TxKind::Command(cmd_id),
                dst: parent,
                partner: None,
                key_id: KeyIdentifier::Data,
                extended_nonce: false,
                header: Header::command(cmd_counter, false).with_ack_request(true),
                nwk_secure: downstream,
                radius: None,
                alias: None,
                ack: true,
                post: None,
                // The Relay Message TLV names the joiner: the destination
                // downstream, the (local) source upstream.
                wrap: Some(Wrap::Relay {
                    joiner: joiner.unwrap_or(self.local_ieee),
                    downstream,
                    inner_header,
                    inner_partner,
                }),
            },
            req.asdu,
            false,
        )
    }

    /// Requests persistence for every link-key counter that needs a
    /// reservation.
    pub(crate) fn request_counter_reservations(&mut self) {
        while let Some((partner, reservation)) = self.security.start_counter_reservation() {
            self.push_action(ApsAction::CounterReservation {
                partner,
                reservation,
            });
        }
    }

    /// Default options for a unicast request.
    pub const fn default_options() -> TxOptions {
        TxOptions::ACKED
    }
}
