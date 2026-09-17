//! Reception path (R23.2 §3.6.2.2, §3.6.2.3, §3.6.1.10.2).

use panweave_codec::{Decode, Reader};
use panweave_security::cipher::BlockCipher;
use panweave_security::frame::SecurityError;
use panweave_types::{ExtendedAddress, Rng, ShortAddress, ShortAddressKind};

use super::{NpduBuf, Nwk, NwkEvent};
use crate::address_map::AddressMapUpdate;
use crate::command::{NetworkStatusCode, NwkCommand, NwkCommandId};
use crate::frame::{FrameType, Header, PROTOCOL_VERSION};
use crate::neighbor::{NeighborEntry, Relationship};

/// What the higher layer must do with a received frame.
#[derive(Clone, Copy, Debug)]
pub enum RxOutcome<'a> {
    /// Consumed by the NWK layer (command, relay, dropped).
    None,
    /// A data frame for this device (NLDE-DATA.indication).
    Data {
        /// NWK source address.
        src: ShortAddress,
        /// NWK destination address (broadcast or our address).
        dst: ShortAddress,
        /// Source IEEE address from the header, if present.
        src_ieee: Option<ExtendedAddress>,
        /// The sender's IEEE address as authenticated by NWK security
        /// (the securing device, i.e. the previous hop).
        secured_by: Option<ExtendedAddress>,
        /// Whether NWK security was applied.
        secured: bool,
        /// Link quality of the last hop.
        lqi: u8,
        /// The NWK payload (APS frame).
        payload: &'a [u8],
    },
    /// An inter-PAN frame (stub NWK header) for the inter-PAN APS
    /// service (Annex G / Green Power).
    InterPan {
        /// The bytes after the stub NWK frame control.
        payload: &'a [u8],
        /// Link quality.
        lqi: u8,
    },
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
    /// Processes an MCPS-DATA.indication. `buf` holds the NPDU and is
    /// decrypted in place; `mac_src` is the MAC source address of the
    /// frame; `lqi` the link quality.
    pub fn on_mac_data<'a>(
        &mut self,
        buf: &'a mut [u8],
        mac_src: ShortAddress,
        lqi: u8,
    ) -> RxOutcome<'a> {
        let (header, header_len) = match Header::decode_prefix(buf) {
            Ok(v) => v,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return RxOutcome::None;
            }
        };
        // Copy the header out: it borrows `buf`, which we mutate below.
        let fc = header.frame_control;
        let (dst, src, radius, sequence, dst_ieee, src_ieee) = (
            header.dst,
            header.src,
            header.radius,
            header.sequence,
            header.dst_ieee,
            header.src_ieee,
        );
        let has_source_route = header.source_route.is_some();
        let relay_index = header.source_route.map(|s| s.relay_index);

        if fc.frame_type() == FrameType::InterPan {
            return RxOutcome::InterPan {
                payload: buf.get(2..).unwrap_or(&[]),
                lqi,
            };
        }
        if fc.protocol_version() != PROTOCOL_VERSION || fc.frame_type() == FrameType::Reserved {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return RxOutcome::None;
        }
        if !self.nib.joined && self.join.is_none() {
            // Not on a network and not joining: only beacons matter.
            return RxOutcome::None;
        }

        // --- Security (§3.6.2.2) ------------------------------------------
        let is_command = fc.frame_type() == FrameType::Command;
        let my_short = self.nib.network_address;
        let for_me = dst == my_short || dst.is_broadcast();
        let mut secured_by: Option<ExtendedAddress> = None;
        let (payload_start, payload_end) = if fc.security() {
            if !self.config.security_enabled {
                return RxOutcome::None;
            }
            let level = self.nib.security_level;
            let all_fresh = self.nib.all_fresh;
            match self
                .security
                .unsecure_incoming(buf, header_len, level, all_fresh)
            {
                Ok(u) => {
                    secured_by = Some(u.sender);
                    (u.payload_start, u.payload_end)
                }
                Err(SecurityError::BadFrameCounter) => {
                    self.stats.replays = self.stats.replays.saturating_add(1);
                    return RxOutcome::None;
                }
                Err(_) => {
                    self.stats.security_failures = self.stats.security_failures.saturating_add(1);
                    return RxOutcome::None;
                }
            }
        } else {
            if self.config.security_enabled
                && !self.unsecured_frame_allowed(is_command, for_me, src, buf, header_len)
            {
                self.stats.security_failures = self.stats.security_failures.saturating_add(1);
                return RxOutcome::None;
            }
            (header_len, buf.len())
        };
        let secured = fc.security();

        // --- Address bookkeeping (§3.6.1.10.2) ------------------------------
        if let Some(e) = src_ieee {
            self.note_address(e, src, secured);
        }
        if let Some(sb) = secured_by {
            // Refresh LQA and last-seen data for the previous hop.
            if let Some(n) = self.neighbors.by_extended_mut(sb) {
                n.lqa.push(lqi);
                if n.short != mac_src && mac_src.is_unicast() {
                    n.short = mac_src;
                }
            }
        } else if let Some(n) = self.neighbors.by_short_mut(mac_src) {
            n.lqa.push(lqi);
        }
        if let Some(n) = self.neighbors.by_short_mut(mac_src)
            && n.is_router()
            && dst.is_unicast()
        {
            n.router_inbound_activity = n.router_inbound_activity.saturating_add(1);
        }
        // Local address conflict: a secured frame addressed to our short
        // address but a different IEEE address (§3.6.1.10.2).
        if secured
            && dst == my_short
            && let Some(di) = dst_ieee
            && di != self.nib.ieee_address
            && self.nib.is_router_or_coordinator()
        {
            self.on_local_address_conflict();
        }

        // --- End device initiator (§3.6.2.2) --------------------------------
        if fc.end_device_initiator() {
            if self.nib.is_end_device() {
                return RxOutcome::None;
            }
            let known_child = self
                .neighbors
                .by_short(src)
                .is_some_and(|n| n.is_end_device());
            if !known_child {
                // Unknown end device: tell it to rejoin (§3.6.2.2 2.b.i).
                if secured {
                    self.send_leave_to_unknown_child(src);
                }
                return RxOutcome::None;
            }
        }

        // --- Lost child examination (§3.6.2.3) ------------------------------
        if self.nib.is_router_or_coordinator() && secured {
            self.examine_lost_child(src, mac_src, dst, sequence);
        }

        // --- Broadcast (§3.6.6) ---------------------------------------------
        if dst.is_broadcast() {
            let deliver = self.on_broadcast_received(
                src,
                sequence,
                dst,
                radius,
                mac_src,
                buf,
                header_len,
                payload_start,
                payload_end,
                secured,
            );
            if !deliver {
                return RxOutcome::None;
            }
            if is_command {
                self.dispatch_command(
                    buf,
                    header_len,
                    payload_start,
                    payload_end,
                    mac_src,
                    lqi,
                    secured,
                    secured_by,
                );
                return RxOutcome::None;
            }
            return RxOutcome::Data {
                src,
                dst,
                src_ieee,
                secured_by,
                secured,
                lqi,
                payload: buf.get(payload_start..payload_end).unwrap_or(&[]),
            };
        }

        // --- Unicast for this device ----------------------------------------
        if dst == my_short {
            if let Some(idx) = relay_index
                && idx != 0
                && self.nib.is_router_or_coordinator()
            {
                // Source-routed frame passing through us while we are also
                // the NWK destination with a non-zero relay index: treat as
                // final delivery per §3.6.4.3.2 only when index is 0;
                // otherwise fall through to relay handling below.
            } else {
                if is_command {
                    self.dispatch_command(
                        buf,
                        header_len,
                        payload_start,
                        payload_end,
                        mac_src,
                        lqi,
                        secured,
                        secured_by,
                    );
                    return RxOutcome::None;
                }
                return RxOutcome::Data {
                    src,
                    dst,
                    src_ieee,
                    secured_by,
                    secured,
                    lqi,
                    payload: buf.get(payload_start..payload_end).unwrap_or(&[]),
                };
            }
        }

        // --- Relay (§3.6.2.2, §3.6.4.3) --------------------------------------
        if !self.nib.is_router_or_coordinator() || !self.nib.router_started {
            return RxOutcome::None;
        }
        if is_command {
            // Route replies not for us are discarded; other commands are
            // only relayed when unicast to another device (network status).
            let cmd_id = buf.get(payload_start).map(|b| NwkCommandId::from_raw(*b));
            match cmd_id {
                Some(NwkCommandId::NetworkStatus) => {
                    self.relay_network_status(buf, header_len, payload_start, payload_end, secured);
                }
                Some(NwkCommandId::RouteRecord) => {
                    self.relay_route_record(buf, header_len, payload_start, payload_end, secured);
                }
                _ => {}
            }
            return RxOutcome::None;
        }
        if radius <= 1 {
            // Radius exhausted after decrement: never retransmit.
            return RxOutcome::None;
        }
        if has_source_route && relay_index.is_some_and(|i| i != 0) {
            // Verify we are the addressed relay (§3.6.4.3.2).
            let (h, _) = match Header::decode_prefix(buf) {
                Ok(v) => v,
                Err(_) => return RxOutcome::None,
            };
            let ok = h
                .source_route
                .and_then(|s| s.next_relay())
                .is_some_and(|r| r == my_short);
            if !ok {
                return RxOutcome::None;
            }
        }
        let mut plaintext = NpduBuf::new();
        if plaintext
            .extend_from_slice(buf.get(..header_len).unwrap_or(&[]))
            .is_err()
            || plaintext
                .extend_from_slice(buf.get(payload_start..payload_end).unwrap_or(&[]))
                .is_err()
        {
            return RxOutcome::None;
        }
        // Clear the security bit in the plaintext copy; the relay re-applies
        // it when re-securing.
        if let Some(b) = plaintext.get_mut(1) {
            *b &= !0x02;
        }
        let Ok((h, _)) = Header::decode_prefix(&plaintext) else {
            return RxOutcome::None;
        };
        let h = Header {
            dst,
            src,
            radius,
            sequence,
            dst_ieee,
            src_ieee,
            ..h
        };
        let _ = self.relay_unicast(&plaintext, &h, secured);
        RxOutcome::None
    }

    /// Whether an unsecured frame may be processed (§3.6.2.2; see
    /// ADR-0002).
    fn unsecured_frame_allowed(
        &self,
        is_command: bool,
        for_me: bool,
        src: ShortAddress,
        buf: &[u8],
        header_len: usize,
    ) -> bool {
        let cmd_id = if is_command {
            buf.get(header_len).map(|b| NwkCommandId::from_raw(*b))
        } else {
            None
        };
        // APS frame control of a data frame: type in bits 0–1, security
        // in bit 5.
        let aps_fc = buf.get(header_len).copied().unwrap_or(0);
        let aps_command = aps_fc & 0x03 == 0x01;
        let aps_secured = aps_fc & 0x20 != 0;
        if self.nib.joined && self.nib.authenticated {
            if is_command {
                // Joined: only rejoin/commissioning requests destined to us.
                return matches!(
                    cmd_id,
                    Some(NwkCommandId::RejoinRequest | NwkCommandId::CommissioningRequest)
                ) && for_me;
            }
            // A parent accepts APS command frames (Relay Message
            // Upstream) from its own unauthenticated children
            // (§4.6.3.2.1); the APS checks the command.
            return for_me
                && aps_command
                && self
                    .neighbors
                    .by_short(src)
                    .is_some_and(|n| n.relationship == Relationship::UnauthenticatedChild);
        }
        // Not authenticated (joining / TC rejoin in progress): responses to
        // our own requests, and data frames that are APS commands
        // (Transport Key, Relay Message Downstream) or APS-secured frames
        // extracted by the parent from a Tunnel / Relay command; the APS
        // layer enforces the command identifier and key.
        match cmd_id {
            Some(NwkCommandId::RejoinResponse | NwkCommandId::CommissioningResponse) => {
                self.join.as_ref().is_some_and(|j| !j.secure)
            }
            Some(_) => false,
            // Data frames from the parent while joined-but-unauthorized:
            // the parent forwards the Trust Center's key negotiation
            // messages unsecured (§4.6.3.2.3.1); the APS layer restricts
            // them to the security services.
            None => {
                for_me
                    && (aps_command
                        || aps_secured
                        || (self.nib.joined && src == self.nib.parent_address))
            }
        }
    }

    /// Records an address pair learnt from a frame (§3.6.1.10.2). Only
    /// secured frames may trigger network-wide conflict handling.
    pub(crate) fn note_address(
        &mut self,
        ext: ExtendedAddress,
        short: ShortAddress,
        secured: bool,
    ) {
        if !ext.is_valid_device_address() || !short.is_unicast() {
            return;
        }
        // Neighbor table consistency.
        if let Some(n) = self.neighbors.by_extended_mut(ext) {
            if n.short != short && secured {
                n.short = short;
            }
        } else if let Some(n) = self.neighbors.by_short(short)
            && n.extended != ext
            && n.extended.is_valid_device_address()
            && secured
        {
            self.on_remote_address_conflict(short);
            return;
        }
        match self.address_map.record(ext, short) {
            AddressMapUpdate::Conflict { .. } if secured => self.on_remote_address_conflict(short),
            _ => {}
        }
    }

    /// Lost child processing (§3.6.2.3): an end device child heard via a
    /// different MAC source has switched parents.
    fn examine_lost_child(
        &mut self,
        src: ShortAddress,
        mac_src: ShortAddress,
        dst: ShortAddress,
        sequence: u8,
    ) {
        let Some(n) = self.neighbors.by_short(src) else {
            return;
        };
        if !n.is_end_device() || !n.relationship.is_child() || mac_src == src {
            return;
        }
        if dst.is_broadcast() && self.btt.get(src, sequence).is_some() {
            return;
        }
        let device = n.extended;
        if let Some(n) = self.neighbors.by_short_mut(src) {
            n.relationship = Relationship::LostChild;
        }
        self.push_event(NwkEvent::LostChild { device });
    }

    /// Removes neighbor entries still marked as lost children; called by
    /// the runtime after the APS layer had a chance to detect address
    /// conflicts (§3.6.2.3 step 6).
    pub fn purge_lost_children(&mut self) {
        let mut removed: heapless::Vec<ExtendedAddress, 8> = heapless::Vec::new();
        self.neighbors.retain(|e| {
            if e.relationship == Relationship::LostChild {
                let _ = removed.push(e.extended);
                false
            } else {
                true
            }
        });
        for d in removed {
            self.security.incoming.remove(d);
            self.push_event(NwkEvent::ChildRemoved { device: d });
        }
    }

    /// Dispatches a NWK command destined to this device.
    #[allow(clippy::too_many_arguments)]
    fn dispatch_command(
        &mut self,
        buf: &[u8],
        header_len: usize,
        payload_start: usize,
        payload_end: usize,
        mac_src: ShortAddress,
        lqi: u8,
        secured: bool,
        secured_by: Option<ExtendedAddress>,
    ) {
        let Ok((header, _)) = Header::decode_prefix(buf) else {
            return;
        };
        let payload = buf.get(payload_start..payload_end).unwrap_or(&[]);
        let mut r = Reader::new(payload);
        let cmd = match NwkCommand::decode(&mut r) {
            Ok(c) => c,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return;
            }
        };
        let ctx = CommandContext {
            src: header.src,
            dst: header.dst,
            src_ieee: header.src_ieee,
            dst_ieee: header.dst_ieee,
            mac_src,
            lqi,
            secured,
            secured_by,
            radius: header.radius,
            sequence: header.sequence,
        };
        let _ = header_len;
        match cmd {
            NwkCommand::RouteRequest(c) => self.on_route_request(&ctx, &c),
            NwkCommand::RouteReply(c) => self.on_route_reply(&ctx, &c),
            NwkCommand::NetworkStatus(c) => self.on_network_status(&ctx, &c),
            NwkCommand::Leave(c) => self.on_leave_command(&ctx, c),
            NwkCommand::RouteRecord(c) => self.on_route_record(&ctx, &c),
            NwkCommand::RejoinRequest(c) => self.on_rejoin_request(&ctx, c),
            NwkCommand::RejoinResponse(c) => self.on_rejoin_response(&ctx, c),
            NwkCommand::LinkStatus(c) => self.on_link_status(&ctx, &c),
            NwkCommand::NetworkReport(c) => self.on_network_report(&ctx, &c),
            NwkCommand::NetworkUpdate(c) => self.on_network_update(&ctx, c),
            NwkCommand::EndDeviceTimeoutRequest(c) => self.on_end_device_timeout_request(&ctx, c),
            NwkCommand::EndDeviceTimeoutResponse(c) => self.on_end_device_timeout_response(&ctx, c),
            NwkCommand::CommissioningRequest(c) => self.on_commissioning_request(&ctx, &c),
            NwkCommand::CommissioningResponse(c) => self.on_commissioning_response(&ctx, &c),
            NwkCommand::LinkPowerDelta(_) => {
                // Power negotiation is not supported (Annex D.11.2 optional);
                // silently ignored.
            }
            NwkCommand::Unknown { id, .. } => {
                self.stats.unknown_commands = self.stats.unknown_commands.saturating_add(1);
                if ctx.dst == self.nib.network_address && secured {
                    // §3.6.13: report unknown command to the source.
                    let _ = id;
                    self.send_network_status(ctx.src, ctx.src, NetworkStatusCode::UnknownCommand);
                }
            }
        }
    }

    /// Records a neighbor heard directly (router siblings learnt from link
    /// status, or the parent). Returns false when the table is full.
    pub(crate) fn ensure_neighbor(&mut self, entry: NeighborEntry) -> bool {
        let limit = self.nib.router_age_limit;
        self.neighbors.insert(entry, limit).is_ok()
    }

    /// Whether `addr` is one of the broadcast groups this device belongs to
    /// (Table 3-80).
    pub(crate) fn in_broadcast_group(&self, addr: ShortAddress) -> bool {
        match addr.kind() {
            ShortAddressKind::BroadcastAll => true,
            ShortAddressKind::BroadcastRxOnWhenIdle => self.nib.rx_on_when_idle,
            ShortAddressKind::BroadcastRouters => self.nib.is_router_or_coordinator(),
            ShortAddressKind::BroadcastLowPowerRouters => false,
            _ => false,
        }
    }
}

/// Context of a received NWK command.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CommandContext {
    pub src: ShortAddress,
    pub dst: ShortAddress,
    pub src_ieee: Option<ExtendedAddress>,
    pub dst_ieee: Option<ExtendedAddress>,
    pub mac_src: ShortAddress,
    pub lqi: u8,
    pub secured: bool,
    pub secured_by: Option<ExtendedAddress>,
    pub radius: u8,
    pub sequence: u8,
}
