//! Periodic maintenance: the timer loop, link status periods, child
//! aging (R23.2 §3.6.10), end-device timeout negotiation and keepalives.

use panweave_mac::frame::MacAddress;
use panweave_security::cipher::BlockCipher;
use panweave_types::{Duration, ExtendedAddress, Instant, Rng, ShortAddress};

use super::rx::CommandContext;
use super::{Nwk, NwkAction, NwkEvent, NwkRequest, TxKind};
use crate::command::{
    EndDeviceTimeoutRequest, EndDeviceTimeoutResponse, NetworkStatusCode, NwkCommand,
    ParentInformation, TimeoutResponseStatus,
};
use crate::frame::{FrameType, Header};
use crate::neighbor::Relationship;

impl<
    C: BlockCipher,
    R: Rng,
    const NEIGHBORS: usize,
    const ROUTES: usize,
    const RDT: usize,
    const BTT: usize,
> Nwk<C, R, NEIGHBORS, ROUTES, RDT, BTT>
{
    /// Advances time and runs every timer-driven procedure. Call whenever
    /// [`Nwk::next_deadline`] has passed and before feeding inputs.
    pub fn poll_timers(&mut self, now: Instant) {
        if now < self.now {
            return;
        }
        self.now = now;

        // Permit joining expiry (§3.6.1.2).
        if let Some(t) = self.permit_until
            && now.has_reached(t)
        {
            self.permit_until = None;
            self.push_action(NwkAction::MacSetPermit(false));
            self.push_event(NwkEvent::PermitJoining(false));
        }

        // Link status period (§3.6.4.4.1) and neighbor aging (§3.6.4.4.4).
        if let Some(t) = self.link_status_due
            && now.has_reached(t)
        {
            self.send_link_status();
            let stale = self.neighbors.link_status_tick(self.nib.router_age_limit);
            if stale > 0 {
                let hops: heapless::Vec<ShortAddress, 8> = self
                    .neighbors
                    .routers()
                    .filter(|n| n.outgoing_cost == 0 && n.age > self.nib.router_age_limit)
                    .map(|n| n.short)
                    .collect();
                for h in hops {
                    let _ = self.routes.invalidate_via(h);
                }
            }
            self.routes.link_status_tick();
            let jitter = self.jitter(Duration::ZERO, Duration::from_millis(1000));
            self.link_status_due = Some(now + self.nib.link_status_period + jitter);
            self.update_beacon_payload();
        }

        // Child aging and security timers (§3.6.10.1), once per second.
        let elapsed = now.saturating_duration_since(self.child_age_last).as_secs();
        if elapsed >= 1 {
            self.child_age_last = now;
            let mut expired: heapless::Vec<ExtendedAddress, 8> = heapless::Vec::new();
            let elapsed32 = u32::try_from(elapsed).unwrap_or(u32::MAX);
            self.neighbors.age_children(elapsed32, &mut expired);
            for d in expired {
                let _ = self.address_map.remove_extended(d);
                self.security.incoming.remove(d);
                self.push_event(NwkEvent::ChildRemoved { device: d });
            }
            // Local end-device timeout (§3.6.10.6) and keepalive.
            if self.nib.is_end_device() && self.nib.joined {
                let mut aged_out = false;
                if let Some(p) = self
                    .neighbors
                    .iter_mut()
                    .find(|n| n.relationship == Relationship::Parent)
                {
                    p.timeout_counter_secs = p.timeout_counter_secs.saturating_sub(elapsed32);
                    if p.timeout_counter_secs == 0 && p.device_timeout_secs != 0 {
                        // Assume aged out by the parent (§3.6.10.6).
                        p.timeout_counter_secs = p.device_timeout_secs;
                        aged_out = true;
                    }
                }
                if aged_out {
                    self.push_event(NwkEvent::NetworkStatus {
                        address: self.nib.parent_address,
                        code: NetworkStatusCode::ParentLinkFailure,
                    });
                }
            }
        }
        if self.nib.is_end_device()
            && self.nib.authenticated
            && let Some(t) = self.keepalive_due
            && now.has_reached(t)
        {
            self.send_keepalive();
        }
        if let Some(t) = self.timeout_request_deadline
            && now.has_reached(t)
        {
            self.timeout_request_deadline = None;
            // No response: treat as unsupported (§3.6.10.2) or parent link
            // failure when used as keepalive (§3.6.10.3).
            if self.nib.parent_information.timeout_request_keepalive() {
                self.push_event(NwkEvent::NetworkStatus {
                    address: self.nib.parent_address,
                    code: NetworkStatusCode::ParentLinkFailure,
                });
            }
        }

        self.service_join(now);
        self.service_pending(now);
        self.service_route_requests(now);
        self.service_route_discovery(now);
        self.service_broadcasts(now);
        self.service_pan_id_update(now);
        self.service_power_delta(now);
    }

    /// The earliest instant at which [`Nwk::poll_timers`] needs to run.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut consider = |i: Option<Instant>| {
            if let Some(i) = i {
                next = Some(next.map_or(i, |n| n.min(i)));
            }
        };
        consider(self.permit_until.filter(|t| *t != Instant::FAR_FUTURE));
        consider(self.link_status_due);
        if self.nib.joined && (self.neighbors.child_count() > 0 || self.nib.is_end_device()) {
            consider(Some(self.child_age_last + Duration::from_secs(1)));
        }
        consider(self.keepalive_due);
        consider(self.timeout_request_deadline);
        consider(self.power_deadline());
        consider(self.join_deadline());
        consider(self.pending_deadline());
        consider(self.routing_deadline());
        consider(self.btt.next_deadline());
        consider(self.pan_id_update.map(|(_, _, t)| t));
        next
    }

    /// Generic request entry point.
    pub fn request(&mut self, req: NwkRequest) {
        match req {
            NwkRequest::Poll => self.push_action(NwkAction::MacPoll),
        }
    }

    // ------------------------------------------------------------------
    // End device timeout (§3.6.10)
    // ------------------------------------------------------------------

    /// Sends an End Device Timeout Request to the parent.
    pub(crate) fn send_end_device_timeout_request(&mut self) {
        if !self.nib.is_end_device() || !self.nib.joined {
            return;
        }
        let parent = self.nib.parent_address;
        let seq = self.nib.next_sequence();
        let header = Header::new(FrameType::Command, parent, self.nib.network_address, 1, seq)
            .with_src_ieee(self.nib.ieee_address)
            .with_dst_ieee(self.nib.parent_ieee)
            .secured(self.config.security_enabled);
        let cmd = NwkCommand::EndDeviceTimeoutRequest(EndDeviceTimeoutRequest {
            timeout: self.nib.end_device_timeout,
            configuration: 0,
        });
        let _ =
            self.send_command_unicast(&header, &cmd, parent, true, false, TxKind::TimeoutRequest);
    }

    pub(crate) fn on_timeout_request_sent(&mut self, ok: bool) {
        if ok {
            self.timeout_request_deadline =
                Some(self.now + panweave_mac::constants::response_wait_time());
            if !self.nib.rx_on_when_idle {
                self.push_action(NwkAction::MacPoll);
            }
        } else if self.nib.parent_information.timeout_request_keepalive() {
            self.push_event(NwkEvent::NetworkStatus {
                address: self.nib.parent_address,
                code: NetworkStatusCode::ParentLinkFailure,
            });
        }
    }

    /// End Device Timeout Request received by a parent (§3.6.10.2).
    pub(crate) fn on_end_device_timeout_request(
        &mut self,
        ctx: &CommandContext,
        req: EndDeviceTimeoutRequest,
    ) {
        if !self.nib.is_router_or_coordinator() || !ctx.secured {
            return;
        }
        let Some(n) = self.neighbors.by_short(ctx.src) else {
            return;
        };
        if !n.is_end_device() || !n.relationship.is_child() {
            return;
        }
        let device = n.extended;
        let status = if !req.timeout.is_valid() {
            TimeoutResponseStatus::IncorrectValue
        } else if req.configuration != 0 {
            TimeoutResponseStatus::UnsupportedFeature
        } else {
            TimeoutResponseStatus::Success
        };
        if status == TimeoutResponseStatus::Success
            && let Some(n) = self.neighbors.by_short_mut(ctx.src)
        {
            n.set_timeout(req.timeout);
            n.end_device_configuration = req.configuration;
            n.keepalive_received = true;
            if n.relationship == Relationship::UnauthenticatedChild {
                // A secured frame proves the child holds the key.
                n.relationship = Relationship::Child;
                n.security_timer_secs = 0;
            }
        }
        // Bit 2: this parent negotiates power (§3.6.11.2, Annex K.7).
        let power = if self.config.power_control {
            ParentInformation::POWER_NEGOTIATION
        } else {
            0
        };
        let parent_info = ParentInformation((self.config.keepalive_methods & 0x03) | power);
        let seq = self.nib.next_sequence();
        let header = Header::new(
            FrameType::Command,
            ctx.src,
            self.nib.network_address,
            1,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .with_dst_ieee(device)
        .secured(self.config.security_enabled);
        let cmd = NwkCommand::EndDeviceTimeoutResponse(EndDeviceTimeoutResponse {
            status,
            parent_info,
        });
        let sleepy = self
            .neighbors
            .by_short(ctx.src)
            .is_some_and(|n| !n.rx_on_when_idle);
        let _ = self.send_command_unicast(&header, &cmd, ctx.src, true, sleepy, TxKind::Command);
        self.push_action(NwkAction::Persist);
    }

    /// End Device Timeout Response received by an end device.
    pub(crate) fn on_end_device_timeout_response(
        &mut self,
        ctx: &CommandContext,
        rsp: EndDeviceTimeoutResponse,
    ) {
        if !self.nib.is_end_device() || !ctx.secured || ctx.src != self.nib.parent_address {
            return;
        }
        self.timeout_request_deadline = None;
        if rsp.status == TimeoutResponseStatus::Success {
            self.nib.parent_information = rsp.parent_info;
            // §3.6.11.2: no Link Power Delta commands unless the parent
            // supports power negotiation.
            if !rsp.parent_info.power_negotiation() {
                self.nib.link_power_delta_transmit_rate = 0;
            } else if self.nib.link_power_delta_transmit_rate == 0 {
                self.nib.link_power_delta_transmit_rate =
                    self.config.end_device_power_delta_rate_secs;
            }
            self.refresh_power_delta_schedule();
            let secs = self.nib.end_device_timeout.seconds().unwrap_or(256 * 60);
            if let Some(p) = self
                .neighbors
                .iter_mut()
                .find(|n| n.relationship == Relationship::Parent)
            {
                p.device_timeout_secs = secs;
                p.timeout_counter_secs = secs;
            }
            // Keepalive three times per timeout period (§3.6.10.3).
            let period = Duration::from_secs(u64::from(secs / 3).max(1));
            self.keepalive_due = Some(self.now + period);
            self.push_action(NwkAction::Persist);
            self.push_event(NwkEvent::ParentInformationUpdated);
        } else {
            self.nib.parent_information = ParentInformation(0);
        }
    }

    /// Sends the keepalive selected by the parent information.
    fn send_keepalive(&mut self) {
        let secs = self.nib.end_device_timeout.seconds().unwrap_or(256 * 60);
        let period = Duration::from_secs(u64::from(secs / 3).max(1));
        self.keepalive_due = Some(self.now + period);
        if self.nib.parent_information.mac_data_poll_keepalive() {
            self.push_action(NwkAction::MacPoll);
        } else if self.nib.parent_information.timeout_request_keepalive() {
            self.send_end_device_timeout_request();
        }
        // Optimistic local refresh (§3.6.10.4: the end device assumes the
        // parent reset the counter).
        if let Some(p) = self
            .neighbors
            .iter_mut()
            .find(|n| n.relationship == Relationship::Parent)
        {
            p.timeout_counter_secs = p.device_timeout_secs;
        }
    }

    /// MLME-POLL.indication: a child polled us (§3.6.10.4).
    pub fn on_mac_poll_indication(&mut self, device: MacAddress) {
        if !self.nib.is_router_or_coordinator() {
            return;
        }
        let entry = match device {
            MacAddress::Short(s) => self.neighbors.by_short_mut(s),
            MacAddress::Extended(e) => self.neighbors.by_extended_mut(e),
            MacAddress::None => None,
        };
        match entry {
            Some(n) if n.relationship.is_child() => {
                if self.config.keepalive_methods & 0x01 != 0 {
                    n.timeout_counter_secs = n.device_timeout_secs;
                    n.keepalive_received = true;
                }
            }
            Some(_) => {}
            None => {
                // Unknown device polling us: tell it to rejoin via an
                // indirect leave (§3.6.10.4 step 1).
                if let MacAddress::Short(s) = device
                    && self.nib.joined
                {
                    let seq = self.nib.next_sequence();
                    let header =
                        Header::new(FrameType::Command, s, self.nib.network_address, 1, seq)
                            .with_src_ieee(self.nib.ieee_address)
                            .secured(self.config.security_enabled);
                    let cmd = NwkCommand::Leave(crate::command::Leave {
                        rejoin: true,
                        request: true,
                        remove_children: false,
                    });
                    let _ =
                        self.send_command_unicast(&header, &cmd, s, true, true, TxKind::Command);
                }
            }
        }
    }

    /// MLME-POLL.confirm for a poll requested by this layer or the
    /// runtime: `frame_pending` reports whether data followed.
    pub fn on_mac_poll_confirm(&mut self, success: bool, frame_pending: bool) {
        let _ = frame_pending;
        if !success && self.nib.is_end_device() && self.nib.joined {
            self.push_event(NwkEvent::NetworkStatus {
                address: self.nib.parent_address,
                code: NetworkStatusCode::ParentLinkFailure,
            });
        }
    }
}
