//! Routing (R23.2 §3.6.4): route discovery, route request/reply
//! processing, route record, network status handling and link status.

use heapless::Vec;
use panweave_codec::Decode;
use panweave_security::cipher::BlockCipher;
use panweave_types::{Duration, Instant, NwkStatus, Rng, ShortAddress};

use super::rx::CommandContext;
use super::{MAX_NPDU, Nwk, NwkAction, NwkError, NwkEvent, PendingRreq, TxKind};
use crate::command::{
    LinkStatus, LinkStatusEntry, ManyToOne, NetworkStatus, NetworkStatusCode, NwkCommand,
    RouteRecord, RouteReply, RouteRequest,
};
use crate::frame::{FrameType, Header};
use crate::neighbor::{NeighborEntry, Relationship};
use crate::nib::constants;
use crate::routing::{DiscoveryEntry, RouteEntry, RouteStatus, incoming_route_is_suitable};

impl<
    C: BlockCipher,
    R: Rng,
    const NEIGHBORS: usize,
    const ROUTES: usize,
    const RDT: usize,
    const BTT: usize,
> Nwk<C, R, NEIGHBORS, ROUTES, RDT, BTT>
{
    /// NLME-ROUTE-DISCOVERY.request. `dst == None` starts a many-to-one
    /// advertisement (this device becomes a concentrator);
    /// `no_route_cache` selects the many-to-one variant.
    ///
    /// May transmit.
    pub fn route_discovery(
        &mut self,
        dst: Option<ShortAddress>,
        radius: Option<u8>,
        no_route_cache: bool,
    ) -> Result<(), NwkError> {
        if !self.nib.is_router_or_coordinator() || !self.nib.joined {
            return Err(NwkError::InvalidRequest);
        }
        match dst {
            Some(d) if d.is_broadcast() => Err(NwkError::InvalidRequest),
            Some(d) => self.start_route_discovery(d, radius, false),
            None => {
                self.nib.is_concentrator = true;
                self.start_many_to_one(radius, no_route_cache)
            }
        }
    }

    /// Initiates unicast route discovery for `dst` (§3.6.4.5.1).
    pub(crate) fn start_route_discovery(
        &mut self,
        dst: ShortAddress,
        radius: Option<u8>,
        _from_child: bool,
    ) -> Result<(), NwkError> {
        if !self.nib.is_router_or_coordinator() {
            return Err(NwkError::InvalidRequest);
        }
        // Existing discovery for this destination: nothing to do.
        if self.rdt.any_pending_for(dst)
            && self
                .routes
                .get(dst)
                .is_some_and(|r| r.status == RouteStatus::DiscoveryUnderway)
        {
            return Ok(());
        }
        // Routing table entry.
        let age_limit = self.nib.router_age_limit;
        match self.routes.get_mut(dst) {
            Some(e) if e.status == RouteStatus::Active => {}
            Some(e) => e.status = RouteStatus::DiscoveryUnderway,
            None => {
                if self
                    .routes
                    .insert(RouteEntry::new(
                        dst,
                        ShortAddress::NO_SHORT_ADDRESS,
                        RouteStatus::DiscoveryUnderway,
                        age_limit,
                    ))
                    .is_none()
                {
                    return Err(NwkError::Busy);
                }
            }
        }
        self.stats.route_discoveries = self.stats.route_discoveries.saturating_add(1);
        self.rreq_id = self.rreq_id.wrapping_add(1);
        let id = self.rreq_id;
        self.nib.next_routing_sequence();
        let my = self.nib.network_address;
        let entry = DiscoveryEntry {
            request_id: id,
            source: my,
            sender: my,
            forward_cost: 0,
            residual_cost: 0xFF,
            expires: self.now + constants::ROUTE_DISCOVERY_TIME,
            destination: dst,
            local: true,
            confirmed: false,
        };
        if self.rdt.insert(entry, self.now).is_none() {
            return Err(NwkError::Busy);
        }
        let dst_ieee = self.address_map.extended_for(dst);
        let seq = self.nib.next_sequence();
        let header = Header::new(
            FrameType::Command,
            ShortAddress::BROADCAST_ROUTERS,
            my,
            radius.unwrap_or(constants::DEFAULT_RADIUS),
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        let cmd = NwkCommand::RouteRequest(RouteRequest {
            many_to_one: ManyToOne::No,
            id,
            dst,
            path_cost: 0,
            dst_ieee,
            tlvs: &[],
        });
        let (frame, header_len) = Self::build_command(&header, &cmd)?;
        self.queue_rreq(
            frame,
            header_len,
            constants::INITIAL_RREQ_RETRIES,
            constants::RREQ_RETRY_INTERVAL,
            true,
        )
    }

    /// Many-to-one route advertisement (§3.6.4.5.1).
    fn start_many_to_one(
        &mut self,
        radius: Option<u8>,
        no_route_cache: bool,
    ) -> Result<(), NwkError> {
        self.stats.route_discoveries = self.stats.route_discoveries.saturating_add(1);
        self.rreq_id = self.rreq_id.wrapping_add(1);
        let id = self.rreq_id;
        self.nib.next_routing_sequence();
        let my = self.nib.network_address;
        let entry = DiscoveryEntry {
            request_id: id,
            source: my,
            sender: my,
            forward_cost: 0,
            residual_cost: 0xFF,
            expires: self.now + constants::ROUTE_DISCOVERY_TIME,
            destination: ShortAddress::BROADCAST_ROUTERS,
            local: true,
            confirmed: true,
        };
        let _ = self.rdt.insert(entry, self.now);
        let radius = radius.unwrap_or(if self.nib.concentrator_radius == 0 {
            constants::DEFAULT_RADIUS
        } else {
            self.nib.concentrator_radius
        });
        let seq = self.nib.next_sequence();
        let header = Header::new(
            FrameType::Command,
            ShortAddress::BROADCAST_ROUTERS,
            my,
            radius,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        let cmd = NwkCommand::RouteRequest(RouteRequest {
            many_to_one: if no_route_cache {
                ManyToOne::NoRouteCache
            } else {
                ManyToOne::WithRouteCache
            },
            id,
            dst: ShortAddress::BROADCAST_ROUTERS,
            path_cost: 0,
            dst_ieee: None,
            tlvs: &[],
        });
        let (frame, header_len) = Self::build_command(&header, &cmd)?;
        // Many-to-one requests are not retried (§3.6.4.5.1).
        self.queue_rreq(frame, header_len, 0, constants::RREQ_RETRY_INTERVAL, true)?;
        self.push_event(NwkEvent::RouteDiscoveryConfirm {
            destination: ShortAddress::BROADCAST_ROUTERS,
            status: NwkStatus::Success,
        });
        Ok(())
    }

    /// Queues a route request for (re)transmission with jitter.
    fn queue_rreq(
        &mut self,
        frame: super::NpduBuf,
        header_len: usize,
        retries: u8,
        interval: Duration,
        immediate: bool,
    ) -> Result<(), NwkError> {
        let _ = header_len;
        let jitter = self.jitter(constants::MIN_RREQ_JITTER, constants::MAX_RREQ_JITTER);
        let due = if immediate {
            self.now
        } else {
            self.now + Duration::from_millis(jitter.as_millis() * 2)
        };
        let p = PendingRreq {
            frame,
            due,
            retries_left: retries,
            interval,
        };
        self.pending_rreq.push(p).map_err(|_| NwkError::Busy)?;
        if immediate {
            self.service_route_requests(self.now);
        }
        Ok(())
    }

    /// Transmits due route requests and schedules their retries.
    pub(crate) fn service_route_requests(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.pending_rreq.len() {
            if now.has_reached(self.pending_rreq[i].due) {
                let frame = self.pending_rreq[i].frame.clone();
                let header_len = Header::decode_prefix(&frame).map(|(_, n)| n).unwrap_or(0);
                let secure = self.config.security_enabled;
                match self.finalize_frame(&frame, header_len, secure) {
                    Ok(on_air) => {
                        let handle = self.alloc_mac_handle();
                        self.push_action(NwkAction::MacData {
                            handle,
                            dst: ShortAddress::BROADCAST_ALL,
                            frame: on_air,
                            ack: false,
                            indirect: false,
                        });
                    }
                    Err(NwkError::CounterPending) => {
                        self.pending_rreq[i].due = now + super::tx::COUNTER_RETRY_DELAY;
                        i += 1;
                        continue;
                    }
                    Err(_) => {}
                }
                let p = &mut self.pending_rreq[i];
                if p.retries_left > 0 {
                    p.retries_left -= 1;
                    let interval = p.interval;
                    let jitter =
                        self.jitter(constants::MIN_RREQ_JITTER, constants::MAX_RREQ_JITTER);
                    self.pending_rreq[i].due = now + interval + jitter;
                    i += 1;
                } else {
                    let _ = self.pending_rreq.swap_remove(i);
                }
            } else {
                i += 1;
            }
        }
    }

    /// Earliest route-request or discovery-table deadline.
    pub(crate) fn routing_deadline(&self) -> Option<Instant> {
        let a = self.pending_rreq.iter().map(|p| p.due).min();
        let b = self.rdt.next_expiry();
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, None) => x,
            (None, y) => y,
        }
    }

    /// Link cost from the previous hop `sender` (§3.6.4.5.1.2): the
    /// maximum of incoming and outgoing costs; `None` when the neighbor is
    /// unknown or has no outgoing cost (frame must be discarded).
    fn cost_from_neighbor(&self, sender: ShortAddress, lqi: u8) -> Option<u8> {
        let n = self.neighbors.by_short(sender)?;
        if n.outgoing_cost == 0 {
            return None;
        }
        let incoming = crate::neighbor::link_cost_from_lqa(n.lqa.value().max(1))
            .max(crate::neighbor::link_cost_from_lqa(lqi));
        Some(incoming.max(n.outgoing_cost))
    }

    /// Route Request processing (§3.6.4.5.1.1–§3.6.4.5.1.4).
    pub(crate) fn on_route_request(&mut self, ctx: &CommandContext, rreq: &RouteRequest<'_>) {
        self.stats.route_requests = self.stats.route_requests.saturating_add(1);
        if self.nib.is_end_device() || !ctx.secured {
            return;
        }
        let my = self.nib.network_address;
        let many = rreq.many_to_one.is_many_to_one();
        if rreq.many_to_one == ManyToOne::Reserved {
            return;
        }
        let Some(link_cost) = self.cost_from_neighbor(ctx.mac_src, ctx.lqi) else {
            return;
        };
        let new_cost = rreq.path_cost.saturating_add(link_cost);
        let age_limit = self.nib.router_age_limit;

        // Is the destination us or one of our end-device children?
        let child_dst = self
            .neighbors
            .by_short(rreq.dst)
            .is_some_and(|n| n.relationship.is_child() && n.is_end_device());
        let is_destination = !many && (rreq.dst == my || child_dst);

        // Route discovery table maintenance.
        let existing = self.rdt.get(ctx.src, rreq.id).copied();
        match existing {
            Some(e) => {
                if new_cost > e.forward_cost {
                    return;
                }
                if !incoming_route_is_suitable(self.routes.get(ctx.src), new_cost) && !many {
                    return;
                }
                if let Some(e) = self.rdt.get_mut(ctx.src, rreq.id) {
                    e.forward_cost = new_cost;
                    e.sender = ctx.mac_src;
                }
            }
            None => {
                if !self.routes.has_capacity_for(ctx.src) {
                    return;
                }
                let entry = DiscoveryEntry {
                    request_id: rreq.id,
                    source: ctx.src,
                    sender: ctx.mac_src,
                    forward_cost: new_cost,
                    residual_cost: 0xFF,
                    expires: self.now + constants::ROUTE_DISCOVERY_TIME,
                    destination: rreq.dst,
                    local: false,
                    confirmed: false,
                };
                if self.rdt.insert(entry, self.now).is_none() {
                    return;
                }
            }
        }

        // Reverse route toward the originator.
        let mut reverse = self.routes.get(ctx.src).copied().unwrap_or_else(|| {
            RouteEntry::new(ctx.src, ctx.mac_src, RouteStatus::Active, age_limit)
        });
        let was_many = reverse.many_to_one;
        reverse.next_hop = ctx.mac_src;
        reverse.status = RouteStatus::Active;
        reverse.path_cost = new_cost;
        if many {
            reverse.many_to_one = true;
            let no_cache = rreq.many_to_one == ManyToOne::NoRouteCache;
            let changed = self
                .routes
                .get(ctx.src)
                .is_none_or(|old| old.next_hop != ctx.mac_src);
            reverse.no_route_cache = no_cache;
            if changed || no_cache {
                reverse.route_record_required = true;
            }
            reverse.expired = false;
            let discovery_secs = self.nib.concentrator_discovery_time_secs;
            reverse.many_to_one_deadline = if discovery_secs > 0 {
                Some(
                    self.now
                        + Duration::from_secs(u64::from(discovery_secs))
                        + constants::ROUTE_DISCOVERY_TIME,
                )
            } else {
                None
            };
        } else {
            // §3.6.4.5.1.8: never clear the many-to-one flag.
            reverse.many_to_one = was_many;
        }
        let was_underway = self
            .routes
            .get(ctx.src)
            .is_some_and(|r| r.status == RouteStatus::DiscoveryUnderway);
        if self.routes.insert(reverse).is_none() {
            return;
        }
        if many && was_underway {
            self.release_waiting(ctx.src);
        }

        if is_destination {
            // Reply toward the originator via the sender (§3.6.4.5.1.5).
            let responder = rreq.dst;
            self.send_route_reply(ctx.src, rreq.id, responder, ctx.mac_src, link_cost);
            return;
        }

        // Forward: relay the request after jitter (§3.6.4.5.1.4).
        if ctx.radius <= 1 {
            return;
        }
        if !many {
            match self.routes.get_mut(rreq.dst) {
                Some(e) if e.status != RouteStatus::Active => {
                    e.status = RouteStatus::DiscoveryUnderway;
                }
                Some(_) => {}
                None => {
                    let _ = self.routes.insert(RouteEntry::new(
                        rreq.dst,
                        ShortAddress::NO_SHORT_ADDRESS,
                        RouteStatus::DiscoveryUnderway,
                        age_limit,
                    ));
                }
            }
        }
        // A relayed route request is not a new frame (§3.6.4.5): the NWK
        // source, source IEEE address and sequence number of the originator
        // are preserved; only the MAC source and the radius change
        // (§3.4.1.1, §3.4.1.2).
        let header = Header::new(
            FrameType::Command,
            ShortAddress::BROADCAST_ROUTERS,
            ctx.src,
            ctx.radius - 1,
            ctx.sequence,
        )
        .with_src_ieee(ctx.src_ieee.unwrap_or(self.nib.ieee_address))
        .secured(self.config.security_enabled);
        let _ = my;
        let cmd = NwkCommand::RouteRequest(RouteRequest {
            many_to_one: rreq.many_to_one,
            id: rreq.id,
            dst: rreq.dst,
            path_cost: new_cost,
            dst_ieee: rreq.dst_ieee,
            tlvs: &[],
        });
        if let Ok((frame, header_len)) = Self::build_command(&header, &cmd) {
            let _ = self.queue_rreq(
                frame,
                header_len,
                constants::RREQ_RETRIES,
                constants::RREQ_RETRY_INTERVAL,
                false,
            );
        }
    }

    /// Sends a Route Reply toward `originator` via `next_hop`.
    fn send_route_reply(
        &mut self,
        originator: ShortAddress,
        id: u8,
        responder: ShortAddress,
        next_hop: ShortAddress,
        path_cost: u8,
    ) {
        let my = self.nib.network_address;
        self.nib.next_routing_sequence();
        let seq = self.nib.next_sequence();
        let next_hop_ieee = self
            .neighbors
            .by_short(next_hop)
            .map(|n| n.extended)
            .or_else(|| self.address_map.extended_for(next_hop));
        let mut header = Header::new(
            FrameType::Command,
            next_hop,
            my,
            constants::DEFAULT_RADIUS,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        if let Some(e) = next_hop_ieee {
            header = header.with_dst_ieee(e);
        }
        let responder_ieee = if responder == my {
            Some(self.nib.ieee_address)
        } else {
            self.neighbors
                .by_short(responder)
                .map(|n| n.extended)
                .or_else(|| self.address_map.extended_for(responder))
        };
        let originator_ieee = self.address_map.extended_for(originator);
        let cmd = NwkCommand::RouteReply(RouteReply {
            id,
            originator,
            responder,
            path_cost,
            originator_ieee,
            responder_ieee,
            tlvs: &[],
        });
        let _ = self.send_command_unicast(
            &header,
            &cmd,
            next_hop,
            true,
            false,
            TxKind::RouteReply { responder },
        );
    }

    /// Route Reply processing (§3.6.4.5.2).
    pub(crate) fn on_route_reply(&mut self, ctx: &CommandContext, rrep: &RouteReply<'_>) {
        if !self.nib.is_router_or_coordinator() || !ctx.secured {
            return;
        }
        let my = self.nib.network_address;
        let Some(link_cost) = self.cost_from_neighbor(ctx.mac_src, ctx.lqi) else {
            return;
        };
        let cost = rrep.path_cost.saturating_add(link_cost);
        let age_limit = self.nib.router_age_limit;
        if let Some(oi) = rrep.originator_ieee {
            self.note_address(oi, rrep.originator, true);
        }
        if let Some(ri) = rrep.responder_ieee {
            self.note_address(ri, rrep.responder, true);
        }

        if rrep.originator == my {
            // We started the discovery.
            let Some(d) = self.rdt.get(my, rrep.id).copied() else {
                return;
            };
            let Some(route) = self.routes.get(d.destination).copied() else {
                let _ = self.rdt.remove(my, rrep.id);
                return;
            };
            let update = match route.status {
                RouteStatus::DiscoveryUnderway => true,
                RouteStatus::Active => cost < d.residual_cost,
                _ => true,
            };
            if !update {
                return;
            }
            let mut route = route;
            route.status = RouteStatus::Active;
            route.next_hop = ctx.mac_src;
            route.path_cost = cost;
            route.recent_activity = age_limit;
            let _ = self.routes.insert(route);
            if let Some(d) = self.rdt.get_mut(my, rrep.id) {
                d.residual_cost = cost;
            }
            self.release_waiting(d.destination);
            self.push_event(NwkEvent::RouteDiscoveryConfirm {
                destination: d.destination,
                status: NwkStatus::Success,
            });
            return;
        }

        // Intermediate: forward toward the originator via the RDT sender.
        let Some(d) = self.rdt.get(rrep.originator, rrep.id).copied() else {
            return;
        };
        if d.residual_cost < cost {
            return;
        }
        let dest = rrep.responder;
        let mut fwd =
            self.routes.get(dest).copied().unwrap_or_else(|| {
                RouteEntry::new(dest, ctx.mac_src, RouteStatus::Active, age_limit)
            });
        if !incoming_route_is_suitable(self.routes.get(dest), cost) {
            return;
        }
        fwd.next_hop = ctx.mac_src;
        fwd.status = RouteStatus::Active;
        fwd.path_cost = cost;
        let _ = self.routes.insert(fwd);
        if let Some(d) = self.rdt.get_mut(rrep.originator, rrep.id) {
            d.residual_cost = cost;
        }
        self.release_waiting(dest);
        // Reverse route toward the originator (§3.6.4.5.2.1).
        let next_hop = d.sender;
        let reverse_exists = self.routes.get(rrep.originator).is_some();
        if !reverse_exists {
            let mut rev =
                RouteEntry::new(rrep.originator, next_hop, RouteStatus::Active, age_limit);
            rev.path_cost = d.forward_cost;
            let _ = self.routes.insert(rev);
        }
        let hop_cost = self
            .neighbors
            .by_short(next_hop)
            .map_or(7, NeighborEntry::path_cost);
        let seq = self.nib.next_sequence();
        let radius = ctx.radius.max(2) - 1;
        let mut header = Header::new(FrameType::Command, next_hop, my, radius.max(1), seq)
            .with_src_ieee(self.nib.ieee_address)
            .secured(self.config.security_enabled);
        if let Some(e) = self
            .neighbors
            .by_short(next_hop)
            .map(|n| n.extended)
            .or_else(|| self.address_map.extended_for(next_hop))
        {
            header = header.with_dst_ieee(e);
        }
        let cmd = NwkCommand::RouteReply(RouteReply {
            id: rrep.id,
            originator: rrep.originator,
            responder: rrep.responder,
            path_cost: cost.saturating_add(hop_cost),
            originator_ieee: rrep.originator_ieee,
            responder_ieee: rrep.responder_ieee,
            tlvs: &[],
        });
        let _ = self.send_command_unicast(
            &header,
            &cmd,
            next_hop,
            true,
            false,
            TxKind::RouteReply {
                responder: rrep.responder,
            },
        );
    }

    /// Expires route discovery entries (§3.6.4.5.1.7, §3.6.4.6).
    pub(crate) fn service_route_discovery(&mut self, now: Instant) {
        let mut expired: Vec<DiscoveryEntry, 8> = Vec::new();
        self.rdt.expire(now, &mut expired);
        for e in expired {
            if !self.rdt.any_pending_for(e.destination)
                && let Some(r) = self.routes.get(e.destination)
                && r.status == RouteStatus::DiscoveryUnderway
            {
                let _ = self.routes.remove(e.destination);
                if e.local {
                    self.fail_waiting(e.destination);
                    self.push_event(NwkEvent::RouteDiscoveryConfirm {
                        destination: e.destination,
                        status: NwkStatus::RouteDiscoveryFailed,
                    });
                }
            }
        }
        self.routes.expire_many_to_one(now);
    }

    /// Sends a Route Record toward `concentrator` (§3.6.4.5.5). When
    /// `on_behalf_of` is a child, the relay list starts with our own
    /// address.
    pub(crate) fn send_route_record(
        &mut self,
        concentrator: ShortAddress,
        on_behalf_of: Option<ShortAddress>,
    ) {
        let my = self.nib.network_address;
        let Some(route) = self.routes.get(concentrator).copied() else {
            return;
        };
        let src = on_behalf_of.unwrap_or(my);
        let seq = self.nib.next_sequence();
        let header = Header::new(
            FrameType::Command,
            concentrator,
            src,
            constants::DEFAULT_RADIUS,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        let relays: [u8; 2] = my.0.to_le_bytes();
        let list: &[u8] = if on_behalf_of.is_some() { &relays } else { &[] };
        let cmd = NwkCommand::RouteRecord(RouteRecord::from_raw(list));
        if self
            .send_command_unicast(&header, &cmd, route.next_hop, true, false, TxKind::Command)
            .is_ok()
            && let Some(r) = self.routes.get_mut(concentrator)
        {
            r.route_record_required = false;
        }
    }

    /// Route Record processing at the destination (§3.6.4.5.5).
    pub(crate) fn on_route_record(&mut self, ctx: &CommandContext, rr: &RouteRecord<'_>) {
        if !ctx.secured {
            return;
        }
        let _ = self.source_routes.store_from_record(ctx.src, rr.relays());
    }

    /// Relays a Route Record not destined to us, appending our address.
    pub(crate) fn relay_route_record(
        &mut self,
        buf: &[u8],
        header_len: usize,
        payload_start: usize,
        payload_end: usize,
        secured: bool,
    ) {
        let Ok((h, _)) = Header::decode_prefix(buf) else {
            return;
        };
        if h.radius <= 1 {
            return;
        }
        let payload = buf.get(payload_start..payload_end).unwrap_or(&[]);
        let Ok(NwkCommand::RouteRecord(rr)) = NwkCommand::decode_exact(payload) else {
            return;
        };
        let mut relays: Vec<u8, { MAX_NPDU }> = Vec::new();
        if relays.extend_from_slice(rr.raw()).is_err()
            || relays
                .extend_from_slice(&self.nib.network_address.0.to_le_bytes())
                .is_err()
        {
            return;
        }
        let Some(next_hop) = self.next_hop_for(h.dst) else {
            return;
        };
        let header = Header {
            radius: h.radius - 1,
            ..h
        };
        let header = Header {
            source_route: None,
            ..header
        };
        let cmd = NwkCommand::RouteRecord(RouteRecord::from_raw(&relays));
        let _ = header_len;
        let _ = self.send_command_unicast(&header, &cmd, next_hop, secured, false, TxKind::Command);
    }

    /// Relays a Network Status command not destined to us (§3.6.4.8.1):
    /// parents drop routes on behalf of children.
    pub(crate) fn relay_network_status(
        &mut self,
        buf: &[u8],
        header_len: usize,
        payload_start: usize,
        payload_end: usize,
        secured: bool,
    ) {
        let Ok((h, _)) = Header::decode_prefix(buf) else {
            return;
        };
        if h.radius <= 1 {
            return;
        }
        let payload = buf.get(payload_start..payload_end).unwrap_or(&[]);
        let Ok(NwkCommand::NetworkStatus(ns)) = NwkCommand::decode_exact(payload) else {
            return;
        };
        let child = self
            .neighbors
            .by_short(h.dst)
            .is_some_and(|n| n.relationship.is_child() && n.is_end_device());
        if child {
            if ns.status.is_link_failure() {
                let _ = self.routes.remove(ns.dst);
            } else if ns.status == NetworkStatusCode::SourceRouteFailure {
                let _ = self.source_routes.remove(ns.dst);
            }
        }
        let Some(next_hop) = self.next_hop_for(h.dst) else {
            return;
        };
        let header = Header {
            radius: h.radius - 1,
            source_route: None,
            ..h
        };
        let cmd = NwkCommand::NetworkStatus(NetworkStatus {
            status: ns.status,
            dst: ns.dst,
            tlvs: &[],
        });
        let _ = header_len;
        let _ = self.send_command_unicast(&header, &cmd, next_hop, secured, false, TxKind::Command);
    }

    /// Next hop toward `dst` without triggering discovery.
    pub(crate) fn next_hop_for(&mut self, dst: ShortAddress) -> Option<ShortAddress> {
        match self.route_unicast(dst, false) {
            super::tx::RouteDecision::Direct(h) | super::tx::RouteDecision::NextHop(h) => Some(h),
            _ => None,
        }
    }

    /// Network Status command destined to us (§3.6.4.8.1).
    pub(crate) fn on_network_status(&mut self, ctx: &CommandContext, ns: &NetworkStatus<'_>) {
        if !ctx.secured && ns.status != NetworkStatusCode::UnknownCommand {
            // Unencrypted frames never change routing state (§3.6.1.10.3).
            return;
        }
        match ns.status {
            s if s.is_link_failure() => {
                let _ = self.routes.remove(ns.dst);
            }
            NetworkStatusCode::SourceRouteFailure => {
                let _ = self.source_routes.remove(ns.dst);
            }
            NetworkStatusCode::ManyToOneRouteFailure => {
                // Concentrator-side handling is the application's choice;
                // clear the route record flag so a fresh record is sent.
                if let Some(r) = self.routes.get_mut(ns.dst) {
                    r.route_record_required = true;
                }
            }
            NetworkStatusCode::AddressConflict => {
                self.on_address_conflict_reported(ns.dst);
            }
            _ => {}
        }
        self.push_event(NwkEvent::NetworkStatus {
            address: ns.dst,
            code: ns.status,
        });
    }

    // ------------------------------------------------------------------
    // Link status (§3.6.4.4)
    // ------------------------------------------------------------------

    /// Transmits a Link Status command listing router neighbors.
    pub(crate) fn send_link_status(&mut self) {
        if !self.nib.is_router_or_coordinator() || !self.nib.router_started {
            return;
        }
        // Collect and sort router neighbors by address (§3.4.8.3.2).
        let mut entries: Vec<LinkStatusEntry, NEIGHBORS> = Vec::new();
        for n in self.neighbors.routers() {
            if !n.short.is_unicast() {
                continue;
            }
            let _ = entries.push(LinkStatusEntry {
                address: n.short,
                incoming_cost: n.incoming_cost(),
                outgoing_cost: n.outgoing_cost,
            });
        }
        entries.sort_unstable_by_key(|e| e.address.0);
        let per_frame = LinkStatus::MAX_ENTRIES.min(28);
        let total = entries.len();
        let frames = if total == 0 {
            1
        } else {
            total.div_ceil(per_frame)
        };
        for f in 0..frames {
            let start = f * per_frame;
            let end = (start + per_frame).min(total);
            let mut raw: Vec<u8, { 3 * 32 }> = Vec::new();
            for e in entries.get(start..end).unwrap_or(&[]) {
                let _ = raw.extend_from_slice(&LinkStatus::encode_entry(e));
            }
            let ls = LinkStatus::from_raw(f == 0, f + 1 == frames, &raw);
            let seq = self.nib.next_sequence();
            let header = Header::new(
                FrameType::Command,
                ShortAddress::BROADCAST_ROUTERS,
                self.nib.network_address,
                1,
                seq,
            )
            .with_src_ieee(self.nib.ieee_address)
            .secured(self.config.security_enabled);
            let _ = self.send_command_broadcast_once(&header, &NwkCommand::LinkStatus(ls), true);
        }
    }

    /// Link Status reception (§3.6.4.4.2).
    pub(crate) fn on_link_status(&mut self, ctx: &CommandContext, ls: &LinkStatus<'_>) {
        if !self.nib.is_router_or_coordinator() || !ctx.secured {
            return;
        }
        let my = self.nib.network_address;
        let sender_ieee = ctx.src_ieee.or(ctx.secured_by);
        let age_limit = self.nib.router_age_limit;
        let exists = self.neighbors.by_short(ctx.src).is_some();
        if !exists {
            let Some(ext) = sender_ieee else { return };
            let mut e = NeighborEntry::new(
                ext,
                ctx.src,
                panweave_types::LogicalDeviceType::Router,
                true,
                Relationship::Sibling,
                ctx.lqi,
            );
            e.router_outbound_activity = age_limit;
            e.router_inbound_activity = age_limit;
            if self.neighbors.insert(e, age_limit).is_err() {
                return;
            }
            if ls.entry_count() == 0 {
                // Bootstrap: gratuitous link status after jitter.
                let j = self.jitter(
                    constants::MIN_ROUTER_BOOTSTRAP_JITTER,
                    constants::MAX_ROUTER_BOOTSTRAP_JITTER,
                );
                self.link_status_due = Some(self.now + j);
            }
        }
        // Range covered by this frame.
        let first = ls.entries().next().map(|e| e.address);
        let last = ls.entries().last().map(|e| e.address);
        let in_range = match (first, last) {
            (Some(f), Some(l)) => (ls.first_frame || my >= f) && (ls.last_frame || my <= l),
            _ => true,
        };
        if !in_range && ls.entry_count() != 0 {
            return;
        }
        let mine = ls.entries().find(|e| e.address == my);
        let mut connectivity: u32 = 0;
        for e in ls.entries() {
            if e.outgoing_cost != 0 {
                connectivity += u32::from(7u8.saturating_sub(e.incoming_cost.max(e.outgoing_cost)));
            }
        }
        if let Some(n) = self.neighbors.by_short_mut(ctx.src) {
            n.age = 0;
            n.lqa.push(ctx.lqi);
            n.outgoing_cost = mine.map_or(0, |e| e.incoming_cost);
            if ls.first_frame {
                n.router_age = n.router_age.saturating_add(1);
                n.router_connectivity = u8::try_from(connectivity.min(0xB6)).unwrap_or(0xB6);
            }
            if n.outgoing_cost == 0 {
                let hop = n.short;
                let _ = self.routes.invalidate_via(hop);
            }
        }
    }
}
