//! Transmission path: NPDU construction, security, routing decision,
//! NWK-level retries and MAC confirm handling (R23.2 §3.6.2.1, §3.6.4.3,
//! §3.6.4.8).

use panweave_codec::{Encode, Writer};
use panweave_mac::service::{TxHandle, TxStatus};
use panweave_security::cipher::BlockCipher;
use panweave_types::{Duration, Instant, NwkStatus, Rng, ShortAddress};

use super::{MAX_NPDU, NpduBuf, Nwk, NwkAction, NwkError, NwkEvent, PendingTx, TxId, TxKind};
use crate::command::{NetworkStatus, NetworkStatusCode, NwkCommand};
use crate::frame::{DiscoverRoute, FrameType, Header};
use crate::nib::constants;
use crate::routing::{RouteEntry, RouteStatus};
use crate::security::NwkSecurity;

/// Delay before retrying a frame parked on a pending counter reservation.
pub(crate) const COUNTER_RETRY_DELAY: Duration = Duration::from_millis(2);

/// Where a unicast frame goes next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RouteDecision {
    /// Transmit directly (neighbor, child, or parent) to this MAC address.
    Direct(ShortAddress),
    /// Forward via a routing table next hop.
    NextHop(ShortAddress),
    /// A discovery is underway or must be started; buffer the frame.
    Discover,
    /// No route and discovery not permitted.
    NoRoute,
}

impl<
    C: BlockCipher,
    R: Rng,
    const NEIGHBORS: usize,
    const ROUTES: usize,
    const RDT: usize,
    const BTT: usize,
> Nwk<C, R, NEIGHBORS, ROUTES, RDT, BTT>
{
    /// Largest higher-layer payload that fits in a secured NPDU with a
    /// header of `header_len` octets.
    pub const fn max_payload(header_len: usize, secured: bool) -> usize {
        let overhead = if secured {
            header_len + NwkSecurity::<C, NEIGHBORS>::aux_header_len() + 4
        } else {
            header_len
        };
        MAX_NPDU.saturating_sub(overhead)
    }

    /// Builds a plaintext NPDU (header + payload) into a buffer.
    pub(crate) fn build_npdu(
        header: &Header<'_>,
        payload: &[u8],
    ) -> Result<(NpduBuf, usize), NwkError> {
        let header_len = header.encoded_len();
        let total = header_len + payload.len();
        if total > MAX_NPDU {
            return Err(NwkError::FrameTooLong);
        }
        let mut buf = NpduBuf::new();
        buf.resize_default(total)
            .map_err(|_| NwkError::FrameTooLong)?;
        let mut w = Writer::new(&mut buf);
        header
            .encode(&mut w)
            .map_err(|_| NwkError::InvalidParameter)?;
        w.bytes(payload).map_err(|_| NwkError::FrameTooLong)?;
        Ok((buf, header_len))
    }

    /// Builds a command NPDU.
    pub(crate) fn build_command(
        header: &Header<'_>,
        cmd: &NwkCommand<'_>,
    ) -> Result<(NpduBuf, usize), NwkError> {
        let mut payload = [0u8; MAX_NPDU];
        let n = cmd
            .encode_to_slice(&mut payload)
            .map_err(|_| NwkError::FrameTooLong)?;
        Self::build_npdu(header, payload.get(..n).unwrap_or(&[]))
    }

    /// Produces the on-air form of a plaintext NPDU: secured if `secure`,
    /// otherwise a verbatim copy.
    pub(crate) fn finalize_frame(
        &mut self,
        plaintext: &[u8],
        header_len: usize,
        secure: bool,
    ) -> Result<NpduBuf, NwkError> {
        let mut out = NpduBuf::new();
        if !secure {
            out.extend_from_slice(plaintext)
                .map_err(|_| NwkError::FrameTooLong)?;
            return Ok(out);
        }
        let aux_len = NwkSecurity::<C, NEIGHBORS>::aux_header_len();
        let payload_len = plaintext.len().saturating_sub(header_len);
        let mic_len = self.nib.security_level.mic_len();
        let total = header_len + aux_len + payload_len + mic_len;
        if total > MAX_NPDU {
            return Err(NwkError::FrameTooLong);
        }
        out.resize_default(total)
            .map_err(|_| NwkError::FrameTooLong)?;
        let (hdr, rest) = plaintext.split_at(header_len.min(plaintext.len()));
        out.get_mut(..header_len)
            .ok_or(NwkError::FrameTooLong)?
            .copy_from_slice(hdr);
        out.get_mut(header_len + aux_len..header_len + aux_len + payload_len)
            .ok_or(NwkError::FrameTooLong)?
            .copy_from_slice(rest);
        // Make sure the security bit is set in the on-air header.
        if let Some(b) = out.get_mut(1) {
            *b |= 0x02;
        }
        let level = self.nib.security_level;
        let ieee = self.nib.ieee_address;
        let n = match self
            .security
            .secure_outgoing(&mut out, header_len, payload_len, level, ieee)
        {
            Ok(n) => n,
            Err(panweave_security::frame::SecurityError::FrameCounter) => {
                // Either exhausted or waiting for a reservation commit.
                self.maybe_reserve_counter();
                if self.security.keys.outgoing.peek() == u32::MAX {
                    return Err(NwkError::Security(NwkStatus::MaxFrameCounter));
                }
                return Err(NwkError::CounterPending);
            }
            Err(panweave_security::frame::SecurityError::NoKey) => {
                return Err(NwkError::Security(NwkStatus::NoKey));
            }
            Err(_) => return Err(NwkError::Security(NwkStatus::BadCcmOutput)),
        };
        out.truncate(n);
        self.maybe_reserve_counter();
        Ok(out)
    }

    /// Decides the next hop for a unicast to `dst` (§3.6.4.3).
    pub(crate) fn route_unicast(&mut self, dst: ShortAddress, discover: bool) -> RouteDecision {
        if self.nib.is_end_device() {
            let parent = self.nib.parent_address;
            return if parent == ShortAddress::NO_SHORT_ADDRESS {
                RouteDecision::NoRoute
            } else {
                RouteDecision::Direct(parent)
            };
        }
        // End device child: deliver directly.
        if let Some(n) = self.neighbors.by_short(dst)
            && n.relationship.is_child()
        {
            return RouteDecision::Direct(dst);
        }
        // Router neighbor with a usable link: direct.
        if let Some(n) = self.neighbors.by_short(dst)
            && n.is_router()
            && n.outgoing_cost != 0
            && n.transmit_failure < 3
        {
            return RouteDecision::Direct(dst);
        }
        match self.routes.get_mut(dst) {
            Some(e) if e.status == RouteStatus::Active => {
                e.touch();
                let hop = e.next_hop;
                if let Some(n) = self.neighbors.by_short_mut(hop) {
                    n.router_outbound_activity = n.router_outbound_activity.saturating_add(1);
                }
                RouteDecision::NextHop(hop)
            }
            Some(e) if e.status == RouteStatus::DiscoveryUnderway => RouteDecision::Discover,
            _ if discover => RouteDecision::Discover,
            _ => {
                // Last resort: any neighbor entry at all.
                if self.neighbors.by_short(dst).is_some() {
                    RouteDecision::Direct(dst)
                } else {
                    RouteDecision::NoRoute
                }
            }
        }
    }

    /// NLDE-DATA.request: sends `payload` to `dst` (unicast or broadcast).
    ///
    /// * `radius`: `None` uses `2 * nwkcMaxDepth`.
    /// * `discover_route`: allow route discovery for unicasts.
    /// * `secure`: apply NWK security (must be true on a secured network
    ///   except for the specific unsecured joining frames).
    ///
    /// May transmit; does not persist.
    pub fn data_request(
        &mut self,
        dst: ShortAddress,
        payload: &[u8],
        radius: Option<u8>,
        discover_route: bool,
        secure: bool,
    ) -> Result<TxId, NwkError> {
        self.data_request_aliased(dst, payload, radius, discover_route, secure, None)
    }

    /// NLDE-DATA.request with UseAlias (§3.2.1.1.3): the NWK header
    /// carries the alias source address and sequence number while the
    /// auxiliary security header still names this device (Green Power
    /// proxies, GP Basic §A.3.6.3.3).
    pub fn data_request_aliased(
        &mut self,
        dst: ShortAddress,
        payload: &[u8],
        radius: Option<u8>,
        discover_route: bool,
        secure: bool,
        alias: Option<(ShortAddress, u8)>,
    ) -> Result<TxId, NwkError> {
        if !self.nib.joined {
            return Err(NwkError::NotJoined);
        }
        if alias.is_some_and(|(a, _)| !a.is_unicast()) {
            return Err(NwkError::InvalidParameter);
        }
        if dst == ShortAddress::NO_SHORT_ADDRESS
            || matches!(dst.kind(), panweave_types::ShortAddressKind::Reserved)
        {
            return Err(NwkError::InvalidParameter);
        }
        let secure = secure && self.config.security_enabled;
        let radius = radius.unwrap_or(constants::DEFAULT_RADIUS).max(1);
        let (src, seq) = match alias {
            Some((a, s)) => (a, s),
            None => (self.nib.network_address, self.nib.next_sequence()),
        };
        let mut header = Header::new(FrameType::Data, dst, src, radius, seq)
            .secured(secure)
            .with_discover_route(if discover_route && dst.is_unicast() {
                DiscoverRoute::Enable
            } else {
                DiscoverRoute::Suppress
            });
        if self.nib.is_end_device() && self.nib.parent_information.0 != 0 {
            header = header.with_end_device_initiator(true);
        }
        if !self.nib.authenticated && alias.is_none() {
            // A joined-but-unauthorized device identifies itself so that
            // the parent can match the frame to its unauthenticated child
            // (§4.6.3.2.1, Relay Message Upstream).
            header = header.with_src_ieee(self.nib.ieee_address);
        }
        if dst.is_broadcast() {
            let (frame, header_len) = Self::build_npdu(&header, payload)?;
            let id = self.alloc_tx_id();
            self.originate_broadcast(frame, header_len, secure)?;
            // Broadcasts are confirmed once the first transmission is
            // handed to the MAC (§3.6.6 gives no end-to-end confirm).
            self.push_event(NwkEvent::DataConfirm {
                id,
                status: NwkStatus::Success,
            });
            return Ok(id);
        }
        // §3.6.4.3.1: a concentrator with a route record for the
        // destination sends source routed; without intermediate relays
        // the frame goes straight to the destination.
        let mut relays: heapless::Vec<u8, { 2 * crate::frame::MAX_SOURCE_ROUTE_RELAYS }> =
            heapless::Vec::new();
        let mut first_hop = None;
        if self.config.concentrator
            && alias.is_none()
            && let Some(sr) = self.source_routes.get(dst)
            && !sr.relays.is_empty()
        {
            for r in &sr.relays {
                let _ = relays.extend_from_slice(&r.0.to_le_bytes());
            }
            first_hop = sr.relays.last().copied();
        }
        let id = self.alloc_tx_id();
        if let Some(hop) = first_hop {
            let index = u8::try_from(relays.len() / 2)
                .unwrap_or(1)
                .saturating_sub(1);
            let header = header.with_source_route(index, &relays);
            let (frame, header_len) = Self::build_npdu(&header, payload)?;
            self.transmit_pending(PendingTx {
                id,
                frame,
                header_len,
                dst,
                next_hop: hop,
                mac_handle: None,
                retries_left: constants::UNICAST_RETRIES,
                retry_at: None,
                awaiting_route: false,
                secure,
                indirect: false,
                relayed_from: None,
                source_route: true,
                kind: TxKind::Data,
                created: self.now,
            })?;
            return Ok(id);
        }
        let (frame, header_len) = Self::build_npdu(&header, payload)?;
        self.enqueue_unicast(PendingTx {
            id,
            frame,
            header_len,
            dst,
            next_hop: dst,
            mac_handle: None,
            retries_left: constants::UNICAST_RETRIES,
            retry_at: None,
            awaiting_route: false,
            secure,
            indirect: false,
            relayed_from: None,
            source_route: false,
            kind: TxKind::Data,
            created: self.now,
        })?;
        Ok(id)
    }

    /// Queues a unicast NPDU, resolving its route.
    pub(crate) fn enqueue_unicast(&mut self, mut entry: PendingTx) -> Result<(), NwkError> {
        let discover =
            entry.frame.get(0).is_some_and(|b| (b >> 6) & 0x3 == 1) && entry.kind == TxKind::Data;
        match self.route_unicast(entry.dst, discover) {
            RouteDecision::Direct(h) | RouteDecision::NextHop(h) => {
                entry.next_hop = h;
                // Sleepy end-device children get indirect delivery.
                if let Some(n) = self.neighbors.by_short(h)
                    && n.relationship.is_child()
                    && n.is_end_device()
                    && !n.rx_on_when_idle
                {
                    entry.indirect = true;
                }
                // §3.6.4.5.5: a Route Record precedes data to a
                // concentrator without a route cache.
                if entry.kind == TxKind::Data
                    && entry.relayed_from.is_none()
                    && let Some(r) = self.routes.get(entry.dst)
                    && r.many_to_one
                    && r.route_record_required
                {
                    self.send_route_record(entry.dst, None);
                }
                self.transmit_pending(entry)
            }
            RouteDecision::Discover => {
                entry.awaiting_route = true;
                let dst = entry.dst;
                self.pending.push(entry).map_err(|_| NwkError::Busy)?;
                self.start_route_discovery(dst, None, false)?;
                Ok(())
            }
            RouteDecision::NoRoute => {
                self.stats.no_route = self.stats.no_route.saturating_add(1);
                Err(NwkError::RouteError)
            }
        }
    }

    /// Secures and hands a pending unicast to the MAC. While the frame
    /// counter reservation is pending the entry is parked and retried by
    /// [`Self::service_pending`].
    pub(crate) fn transmit_pending(&mut self, mut entry: PendingTx) -> Result<(), NwkError> {
        if entry.indirect {
            // A sleepy child's frame is secured only when it polls
            // (§3.6.2.2 freshness: a counter taken now could be overtaken
            // by frames sent before the poll).
            let handle = self.alloc_mac_handle();
            entry.mac_handle = Some(handle);
            entry.awaiting_route = false;
            entry.retry_at = None;
            let dst = entry.next_hop;
            self.pending.push(entry).map_err(|_| NwkError::Busy)?;
            self.push_action(NwkAction::MacDataDeferred { handle, dst });
            return Ok(());
        }
        let on_air = match self.finalize_frame(&entry.frame, entry.header_len, entry.secure) {
            Ok(f) => f,
            Err(NwkError::CounterPending) => {
                entry.mac_handle = None;
                entry.retry_at = Some(self.now + COUNTER_RETRY_DELAY);
                return self.pending.push(entry).map_err(|_| NwkError::Busy);
            }
            Err(e) => return Err(e),
        };
        let handle = self.alloc_mac_handle();
        entry.mac_handle = Some(handle);
        entry.awaiting_route = false;
        entry.retry_at = None;
        let dst = entry.next_hop;
        let indirect = entry.indirect;
        self.pending.push(entry).map_err(|_| NwkError::Busy)?;
        self.nib.tx_total = self.nib.tx_total.saturating_add(1);
        self.push_action(NwkAction::MacData {
            handle,
            dst,
            frame: on_air,
            ack: true,
            indirect,
        });
        Ok(())
    }

    /// Sends a NWK command as a unicast (`mac_dst` is the next hop).
    pub(crate) fn send_command_unicast(
        &mut self,
        header: &Header<'_>,
        cmd: &NwkCommand<'_>,
        mac_dst: ShortAddress,
        secure: bool,
        indirect: bool,
        kind: TxKind,
    ) -> Result<(), NwkError> {
        let (frame, header_len) = Self::build_command(header, cmd)?;
        let id = self.alloc_tx_id();
        self.transmit_pending(PendingTx {
            id,
            frame,
            header_len,
            dst: header.dst,
            next_hop: mac_dst,
            mac_handle: None,
            retries_left: constants::UNICAST_RETRIES,
            retry_at: None,
            awaiting_route: false,
            secure: secure && self.config.security_enabled,
            indirect,
            relayed_from: None,
            source_route: false,
            kind,
            created: self.now,
        })
    }

    /// Sends a NWK command as a one-hop MAC broadcast without NWK-level
    /// retries (link status, leave announcements, route request initial
    /// transmissions handled elsewhere).
    pub(crate) fn send_command_broadcast_once(
        &mut self,
        header: &Header<'_>,
        cmd: &NwkCommand<'_>,
        secure: bool,
    ) -> Result<(), NwkError> {
        let (frame, header_len) = Self::build_command(header, cmd)?;
        let on_air =
            match self.finalize_frame(&frame, header_len, secure && self.config.security_enabled) {
                Ok(f) => f,
                // Periodic one-shot commands are simply skipped this round.
                Err(NwkError::CounterPending) => return Ok(()),
                Err(e) => return Err(e),
            };
        let handle = self.alloc_mac_handle();
        let mac_dst = if self.nib.is_end_device() {
            self.nib.parent_address
        } else {
            ShortAddress::BROADCAST_ALL
        };
        self.push_action(NwkAction::MacData {
            handle,
            dst: mac_dst,
            frame: on_air,
            ack: false,
            indirect: false,
        });
        Ok(())
    }

    /// Sends a Network Status command toward `dst` (unicast) reporting
    /// `code` for `about`.
    pub(crate) fn send_network_status(
        &mut self,
        dst: ShortAddress,
        about: ShortAddress,
        code: NetworkStatusCode,
    ) {
        if !self.nib.joined {
            return;
        }
        let seq = self.nib.next_sequence();
        let header = Header::new(
            FrameType::Command,
            dst,
            self.nib.network_address,
            constants::DEFAULT_RADIUS,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        let cmd = NwkCommand::NetworkStatus(NetworkStatus {
            status: code,
            dst: about,
            tlvs: &[],
        });
        let Ok((frame, header_len)) = Self::build_command(&header, &cmd) else {
            return;
        };
        let id = self.alloc_tx_id();
        let _ = self.enqueue_unicast(PendingTx {
            id,
            frame,
            header_len,
            dst,
            next_hop: dst,
            mac_handle: None,
            retries_left: 1,
            retry_at: None,
            awaiting_route: false,
            secure: self.config.security_enabled,
            indirect: false,
            relayed_from: None,
            source_route: false,
            kind: TxKind::Command,
            created: self.now,
        });
    }

    /// The sleepy child a [`NwkAction::MacDataDeferred`] transaction was
    /// registered for has polled and is listening: secure the frame now
    /// and hand it to the MAC as a direct transmission under the same
    /// handle.
    pub fn on_mac_indirect_ready(&mut self, handle: TxHandle) {
        let Some(pos) = self
            .pending
            .iter()
            .position(|p| p.mac_handle == Some(handle))
        else {
            return;
        };
        let (frame, header_len, secure, dst) = {
            let p = &self.pending[pos];
            (p.frame.clone(), p.header_len, p.secure, p.next_hop)
        };
        match self.finalize_frame(&frame, header_len, secure) {
            Ok(on_air) => {
                self.nib.tx_total = self.nib.tx_total.saturating_add(1);
                self.push_action(NwkAction::MacData {
                    handle,
                    dst,
                    frame: on_air,
                    ack: true,
                    indirect: false,
                });
            }
            Err(NwkError::CounterPending) => {
                // The counter reservation is not committed yet: register
                // the transaction again for the child's next poll.
                let mut entry = self.pending.swap_remove(pos);
                entry.mac_handle = None;
                entry.retry_at = Some(self.now + COUNTER_RETRY_DELAY);
                let _ = self.pending.push(entry);
            }
            Err(_) => {
                let entry = self.pending.swap_remove(pos);
                self.on_unicast_failed(entry, TxStatus::RadioError);
            }
        }
    }

    /// MCPS-DATA.confirm for a frame handed out via
    /// [`NwkAction::MacData`].
    pub fn on_mac_data_confirm(&mut self, handle: TxHandle, status: TxStatus) {
        let Some(pos) = self
            .pending
            .iter()
            .position(|p| p.mac_handle == Some(handle))
        else {
            // Broadcasts / one-shot commands carry no pending entry.
            return;
        };
        let mut entry = self.pending.swap_remove(pos);
        // Table 3-42 counters of the interface in use.
        if let Some(i) = self
            .interfaces
            .interface_for(self.nib.channel_page, self.nib.channel)
            .map(|e| e.index)
        {
            self.interfaces
                .note_tx(i, 0, !matches!(status, TxStatus::Success));
        }
        match status {
            TxStatus::Success => {
                if let Some(n) = self.neighbors.by_short_mut(entry.next_hop) {
                    n.transmit_failure = 0;
                }
                self.on_unicast_delivered(entry);
            }
            TxStatus::NoAck | TxStatus::ChannelAccessFailure | TxStatus::RadioError => {
                self.nib.tx_failures = self.nib.tx_failures.saturating_add(1);
                if let Some(n) = self.neighbors.by_short_mut(entry.next_hop) {
                    n.transmit_failure = n.transmit_failure.saturating_add(1);
                }
                if entry.retries_left > 0 && !entry.indirect {
                    entry.retries_left -= 1;
                    entry.mac_handle = None;
                    entry.retry_at = Some(self.now + constants::UNICAST_RETRY_DELAY);
                    if self.pending.push(entry).is_err() {
                        // Cannot keep it: report failure now.
                        // (Queue was just popped so this cannot happen.)
                    }
                } else {
                    self.on_unicast_failed(entry, status);
                }
            }
            TxStatus::TransactionExpired => self.on_unicast_failed(entry, status),
        }
    }

    fn on_unicast_delivered(&mut self, entry: PendingTx) {
        match entry.kind {
            TxKind::Data => self.push_event(NwkEvent::DataConfirm {
                id: entry.id,
                status: NwkStatus::Success,
            }),
            TxKind::Leave { device } => self.on_leave_sent(device, NwkStatus::Success),
            TxKind::JoinRequest => self.on_join_request_sent(true),
            TxKind::JoinResponse { device, method } => {
                self.on_join_response_delivered(device, true, method);
            }
            TxKind::TimeoutRequest => self.on_timeout_request_sent(true),
            TxKind::Command | TxKind::RouteReply { .. } => {}
        }
    }

    fn on_unicast_failed(&mut self, entry: PendingTx, status: TxStatus) {
        let hop = entry.next_hop;
        // Link failure handling (§3.6.4.8.1).
        let link_failed = matches!(status, TxStatus::NoAck | TxStatus::ChannelAccessFailure);
        if link_failed && self.nib.is_router_or_coordinator() {
            let invalidated = self.routes.invalidate_via(hop);
            if invalidated > 0 {
                self.stats.no_route = self.stats.no_route.saturating_add(1);
            }
        }
        match entry.kind {
            TxKind::Data => {
                if let Some(src) = entry.relayed_from {
                    // Relayed frame: tell the originator.
                    let code = if entry.source_route {
                        NetworkStatusCode::SourceRouteFailure
                    } else if self
                        .routes
                        .get(entry.dst)
                        .is_some_and(|r| r.many_to_one && !r.expired)
                    {
                        NetworkStatusCode::ManyToOneRouteFailure
                    } else {
                        NetworkStatusCode::LinkFailure
                    };
                    self.send_network_status(src, entry.dst, code);
                } else {
                    let nwk_status = if link_failed {
                        NwkStatus::RouteError
                    } else {
                        Self::mac_status_to_nwk(status)
                    };
                    self.push_event(NwkEvent::DataConfirm {
                        id: entry.id,
                        status: nwk_status,
                    });
                    if self.nib.is_end_device() && hop == self.nib.parent_address && link_failed {
                        self.push_event(NwkEvent::NetworkStatus {
                            address: hop,
                            code: NetworkStatusCode::ParentLinkFailure,
                        });
                    } else {
                        self.push_event(NwkEvent::NetworkStatus {
                            address: entry.dst,
                            code: NetworkStatusCode::LinkFailure,
                        });
                    }
                }
            }
            TxKind::Leave { device } => self.on_leave_sent(device, Self::mac_status_to_nwk(status)),
            TxKind::JoinRequest => self.on_join_request_sent(false),
            TxKind::JoinResponse { device, method } => {
                self.on_join_response_delivered(device, false, method);
            }
            TxKind::TimeoutRequest => self.on_timeout_request_sent(false),
            TxKind::RouteReply { responder } => {
                // §3.6.4.5.2.1: report link failure toward the responder.
                if link_failed {
                    self.send_network_status(responder, entry.dst, NetworkStatusCode::LinkFailure);
                }
            }
            TxKind::Command => {}
        }
    }

    /// Retries and expiries of pending unicasts; called from the timer
    /// loop.
    pub(crate) fn service_pending(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.pending.len() {
            let due_retry = self.pending[i].retry_at.is_some_and(|t| now.has_reached(t));
            let expired_wait = self.pending[i].awaiting_route
                && now.has_reached(self.pending[i].created + constants::ROUTE_DISCOVERY_TIME);
            if due_retry {
                let entry = self.pending.swap_remove(i);
                if self.transmit_pending(entry).is_err() {
                    // Dropped: nothing more to do.
                }
                continue;
            }
            if expired_wait {
                let entry = self.pending.swap_remove(i);
                self.stats.no_route = self.stats.no_route.saturating_add(1);
                if entry.kind == TxKind::Data && entry.relayed_from.is_none() {
                    self.push_event(NwkEvent::DataConfirm {
                        id: entry.id,
                        status: NwkStatus::RouteDiscoveryFailed,
                    });
                }
                continue;
            }
            i += 1;
        }
    }

    /// Releases frames waiting for a route to `dst` once it became active.
    pub(crate) fn release_waiting(&mut self, dst: ShortAddress) {
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].awaiting_route && self.pending[i].dst == dst {
                let entry = self.pending.swap_remove(i);
                let _ = self.enqueue_unicast(entry);
                continue;
            }
            i += 1;
        }
    }

    /// Fails frames waiting for a route to `dst` after discovery failed.
    pub(crate) fn fail_waiting(&mut self, dst: ShortAddress) {
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].awaiting_route && self.pending[i].dst == dst {
                let entry = self.pending.swap_remove(i);
                if entry.kind == TxKind::Data && entry.relayed_from.is_none() {
                    self.push_event(NwkEvent::DataConfirm {
                        id: entry.id,
                        status: NwkStatus::RouteDiscoveryFailed,
                    });
                } else if let Some(src) = entry.relayed_from {
                    self.send_network_status(src, dst, NetworkStatusCode::LinkFailure);
                }
                continue;
            }
            i += 1;
        }
    }

    /// Earliest pending retry/expiry deadline.
    pub(crate) fn pending_deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .filter_map(|p| {
                p.retry_at.or_else(|| {
                    if p.awaiting_route {
                        Some(p.created + constants::ROUTE_DISCOVERY_TIME)
                    } else {
                        None
                    }
                })
            })
            .min()
    }

    /// Number of frames currently pending (for backpressure decisions).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Adds a routing table entry (used by tests and by the runtime when
    /// restoring persisted routes).
    pub fn add_route(&mut self, dst: ShortAddress, next_hop: ShortAddress) -> bool {
        self.routes
            .insert(RouteEntry::new(
                dst,
                next_hop,
                RouteStatus::Active,
                self.nib.router_age_limit,
            ))
            .is_some()
    }

    /// Adds a relay list parsed from a received data frame's plaintext for
    /// a frame that we forward (helper for relays).
    pub(crate) fn relay_unicast(
        &mut self,
        plaintext: &[u8],
        header: &Header<'_>,
        secure: bool,
    ) -> Result<(), NwkError> {
        // Re-parse to get the header length in the plaintext copy.
        let parsed_len = Header::decode_prefix(plaintext).map_or(0, |h| h.1);
        let mut frame = NpduBuf::new();
        frame
            .extend_from_slice(plaintext)
            .map_err(|_| NwkError::FrameTooLong)?;
        // Decrement radius in the copy (§3.6.2.2) — the caller has already
        // checked it stays above zero.
        if let Some(r) = frame.get_mut(6) {
            *r = r.saturating_sub(1);
        }
        // Clear the end-device-initiator bit when relaying for a child
        // (§3.3.1.1.8).
        if let Some(b) = frame.get_mut(1) {
            *b &= !0x20;
        }
        let from_child_ed = self
            .neighbors
            .by_short(header.src)
            .is_some_and(|n| n.relationship.is_child() && n.is_end_device());
        let id = self.alloc_tx_id();
        let entry = PendingTx {
            id,
            frame,
            header_len: parsed_len,
            dst: header.dst,
            next_hop: header.dst,
            mac_handle: None,
            retries_left: constants::UNICAST_RETRIES,
            retry_at: None,
            awaiting_route: false,
            secure,
            indirect: false,
            relayed_from: Some(header.src),
            source_route: header.source_route.is_some(),
            kind: TxKind::Data,
            created: self.now,
        };
        self.stats.relayed = self.stats.relayed.saturating_add(1);
        if let Some(sr) = header.source_route {
            // Source routed relay (§3.6.4.3.2): next relay from the list.
            return self.relay_source_routed(entry, sr.relay_index);
        }
        // Route discovery on behalf of an end device child (§3.6.4.5.1
        // case 3) is allowed; otherwise only existing routes.
        let mut entry = entry;
        let discover =
            header.frame_control.discover_route() == DiscoverRoute::Enable && from_child_ed;
        match self.route_unicast(entry.dst, discover) {
            RouteDecision::Direct(h) | RouteDecision::NextHop(h) => {
                entry.next_hop = h;
                if let Some(n) = self.neighbors.by_short(h)
                    && n.relationship.is_child()
                    && n.is_end_device()
                    && !n.rx_on_when_idle
                {
                    entry.indirect = true;
                }
                // Many-to-one route record on behalf of a child (§3.6.4.5.5).
                if from_child_ed
                    && let Some(r) = self.routes.get(entry.dst)
                    && r.many_to_one
                    && r.route_record_required
                {
                    self.send_route_record(entry.dst, Some(header.src));
                }
                self.transmit_pending(entry)
            }
            RouteDecision::Discover => {
                entry.awaiting_route = true;
                let dst = entry.dst;
                self.pending.push(entry).map_err(|_| NwkError::Busy)?;
                self.start_route_discovery(dst, None, false)?;
                Ok(())
            }
            RouteDecision::NoRoute => {
                self.stats.no_route = self.stats.no_route.saturating_add(1);
                self.send_network_status(header.src, header.dst, NetworkStatusCode::LinkFailure);
                Err(NwkError::RouteError)
            }
        }
    }

    fn relay_source_routed(
        &mut self,
        mut entry: PendingTx,
        relay_index: u8,
    ) -> Result<(), NwkError> {
        // Parse the source route from the copied frame and compute the next
        // relay: index - 1, or the destination when index reaches 0.
        let frame_copy = entry.frame.clone();
        let Ok(h) = Header::decode_prefix(&frame_copy) else {
            return Err(NwkError::InvalidParameter);
        };
        let Some(sr) = h.0.source_route else {
            return Err(NwkError::InvalidParameter);
        };
        let my = self.nib.network_address;
        if relay_index == 0 {
            entry.next_hop = h.0.dst;
        } else {
            if sr.relay(usize::from(relay_index)) != Some(my) {
                return Err(NwkError::InvalidParameter);
            }
            let next_index = relay_index - 1;
            entry.next_hop = sr
                .relay(usize::from(next_index))
                .ok_or(NwkError::InvalidParameter)?;
            // Patch the relay index in the frame copy.
            let idx_offset = 8
                + usize::from(h.0.frame_control.dst_ieee()) * 8
                + usize::from(h.0.frame_control.src_ieee()) * 8
                + 1;
            if let Some(b) = entry.frame.get_mut(idx_offset) {
                *b = next_index;
            }
        }
        // Child end device destination: deliver directly.
        if let Some(n) = self.neighbors.by_short(h.0.dst)
            && n.relationship.is_child()
        {
            entry.next_hop = h.0.dst;
            entry.indirect = n.is_end_device() && !n.rx_on_when_idle;
        }
        // §3.6.4.3.2: clear route record required for the originator.
        if let Some(r) = self.routes.get_mut(h.0.src)
            && !r.no_route_cache
        {
            r.route_record_required = false;
        }
        self.transmit_pending(entry)
    }
}
