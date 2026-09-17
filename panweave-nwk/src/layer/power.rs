//! Power negotiation (R23.2 §3.6.11, §3.4.13): the periodic Link Power
//! Delta commands that tell each neighbor by how many dB it should raise
//! or lower its transmit power towards this device (`Popt − Prx`, the
//! optimal receive level minus the last RSSI), and the processing of
//! the commands received, which feeds the MAC's Power Control
//! Information Table (Annex D.11.2.3) through
//! [`NwkAction::MacAdjustTxPower`].
//!
//! Routers and the coordinator broadcast Notifications to all rx-on
//! neighbors (0xFFFD, radius 1); an rx-on end device unicasts a
//! Notification to its parent; a sleepy end device unicasts a Request,
//! polls (up to three times) for the Response and only then applies the
//! parent's delta. A router answers an end device child with a Response
//! carrying the child's delta only.

use heapless::Vec;
use panweave_security::cipher::BlockCipher;
use panweave_types::{Duration, ExtendedAddress, Instant, LogicalDeviceType, Rng, ShortAddress};

use super::rx::CommandContext;
use super::{Nwk, NwkAction, NwkEvent, TxKind};
use crate::command::{LinkPowerDelta, LinkPowerDeltaType, NwkCommand};
use crate::frame::{FrameType, Header};

/// Power delta records per frame (3 octets each; a secured command
/// with the source IEEE address leaves room for more).
const ENTRIES_PER_FRAME: usize = 24;
/// Upper bound of the one-off jitter (§3.4.13.7).
const MAX_JITTER: Duration = Duration::from_secs(10);
/// Polls a sleepy end device makes for the Response (§3.6.11.2.1).
const REQUEST_POLLS: u8 = 3;

/// A sleepy end device's outstanding Request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingRequest {
    /// When to poll next.
    pub next_poll: Instant,
    /// Polls left before the request is given up.
    pub polls_left: u8,
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
    /// Whether this device generates Link Power Delta commands right
    /// now: support enabled, joined, a non-zero rate, a started router
    /// or an end device whose parent supports the feature (§3.4.13.7,
    /// §3.6.11.2).
    fn power_delta_active(&self) -> bool {
        self.config.power_control
            && self.nib.joined
            && self.nib.authenticated
            && self.nib.link_power_delta_transmit_rate != 0
            && if self.nib.is_end_device() {
                self.nib.parent_information.power_negotiation()
            } else {
                self.nib.router_started
            }
    }

    /// Arms the periodic transmission when it is not already armed and
    /// the feature is active; disarms it otherwise.
    pub(crate) fn refresh_power_delta_schedule(&mut self) {
        if !self.power_delta_active() {
            self.power_delta_due = None;
            self.power_request = None;
        } else if self.power_delta_due.is_none() {
            self.schedule_power_delta();
        }
    }

    /// Next transmission: `nwkLinkPowerDeltaTransmitRate` plus a random
    /// jitter of up to 10 s (§3.4.13.7).
    fn schedule_power_delta(&mut self) {
        let rate = Duration::from_secs(u64::from(self.nib.link_power_delta_transmit_rate));
        let jitter = self.jitter(Duration::ZERO, MAX_JITTER);
        self.power_delta_due = Some(self.now + rate + jitter);
    }

    /// `Popt − Prx` for a neighbor whose last frame arrived at `rssi_dbm`.
    fn power_delta_for(&self, rssi_dbm: i8) -> i8 {
        self.config.optimal_rssi_dbm.saturating_sub(rssi_dbm)
    }

    /// Timer processing: periodic transmissions and the sleepy end
    /// device's polls for the Response.
    pub(crate) fn service_power_delta(&mut self, now: Instant) {
        if let Some(t) = self.power_delta_due
            && now.has_reached(t)
        {
            if self.power_delta_active() {
                self.send_power_delta();
                self.schedule_power_delta();
            } else {
                self.power_delta_due = None;
            }
        }
        if let Some(r) = self.power_request
            && now.has_reached(r.next_poll)
        {
            if r.polls_left == 0 {
                // No Response: back to full power until the parent
                // answers a later request (§3.4.13.7).
                self.power_request = None;
                self.push_action(NwkAction::MacResetTxPower);
            } else {
                self.power_request = Some(PendingRequest {
                    next_poll: now + panweave_mac::constants::response_wait_time(),
                    polls_left: r.polls_left - 1,
                });
                self.push_action(NwkAction::MacPoll);
            }
        }
    }

    /// Earliest power negotiation deadline.
    pub(crate) fn power_deadline(&self) -> Option<Instant> {
        match (
            self.power_delta_due,
            self.power_request.map(|r| r.next_poll),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Sends this period's Link Power Delta command(s) (§3.4.13.7).
    fn send_power_delta(&mut self) {
        if self.nib.is_end_device() {
            // Only the parent, unicast; a Request when sleepy.
            let parent = self.nib.parent_address;
            let Some(rssi) = self.neighbors.parent().and_then(|p| p.last_rssi_dbm) else {
                return;
            };
            let delta = self.power_delta_for(rssi);
            let kind = if self.nib.rx_on_when_idle {
                LinkPowerDeltaType::Notification
            } else {
                LinkPowerDeltaType::Request
            };
            let raw = entry(parent, delta);
            let cmd = LinkPowerDelta::from_raw(kind, &raw);
            let seq = self.nib.next_sequence();
            let mut header =
                Header::new(FrameType::Command, parent, self.nib.network_address, 1, seq)
                    .with_src_ieee(self.nib.ieee_address)
                    .secured(self.config.security_enabled);
            if self.nib.parent_ieee != ExtendedAddress::ZERO {
                header = header.with_dst_ieee(self.nib.parent_ieee);
            }
            if self
                .send_command_unicast(
                    &header,
                    &NwkCommand::LinkPowerDelta(cmd),
                    parent,
                    true,
                    false,
                    TxKind::Command,
                )
                .is_ok()
                && kind == LinkPowerDeltaType::Request
            {
                // Wait macResponseWaitTime, then poll for the Response
                // (§3.4.13.7, §3.6.11.2.1).
                self.power_request = Some(PendingRequest {
                    next_poll: self.now + panweave_mac::constants::response_wait_time(),
                    polls_left: REQUEST_POLLS,
                });
            }
            return;
        }
        // Router / coordinator: every active rx-on neighbor with a known
        // RSSI, as many one-hop broadcasts as needed.
        let mut entries: Vec<(ShortAddress, i8), NEIGHBORS> = Vec::new();
        for n in self.neighbors.iter() {
            if !n.rx_on_when_idle || !n.short.is_unicast() {
                continue;
            }
            let Some(rssi) = n.last_rssi_dbm else {
                continue;
            };
            let _ = entries.push((n.short, self.power_delta_for(rssi)));
        }
        if entries.is_empty() {
            return;
        }
        for chunk in entries.chunks(ENTRIES_PER_FRAME) {
            let mut raw: Vec<u8, { 3 * ENTRIES_PER_FRAME }> = Vec::new();
            for (a, d) in chunk {
                let _ = raw.extend_from_slice(&entry(*a, *d));
            }
            let cmd = LinkPowerDelta::from_raw(LinkPowerDeltaType::Notification, &raw);
            let seq = self.nib.next_sequence();
            let header = Header::new(
                FrameType::Command,
                ShortAddress::BROADCAST_RX_ON,
                self.nib.network_address,
                1,
                seq,
            )
            .with_src_ieee(self.nib.ieee_address)
            .secured(self.config.security_enabled);
            let _ =
                self.send_command_broadcast_once(&header, &NwkCommand::LinkPowerDelta(cmd), true);
        }
    }

    /// Link Power Delta received (§3.4.13.7).
    pub(crate) fn on_link_power_delta(&mut self, ctx: &CommandContext, cmd: &LinkPowerDelta<'_>) {
        if !self.config.power_control || !ctx.secured || cmd.kind == LinkPowerDeltaType::Reserved {
            return;
        }
        // Requests and Responses are unicast only (Table 3-63).
        if cmd.kind != LinkPowerDeltaType::Notification && ctx.dst.is_broadcast() {
            return;
        }
        // Step 1: the sender must be a neighbor.
        let Some(n) = self.neighbors.by_short(ctx.src) else {
            return;
        };
        let extended = ctx.src_ieee.unwrap_or(n.extended);
        let from_end_device = n.device_type == LogicalDeviceType::EndDevice;
        let sender_rx_on = n.rx_on_when_idle;
        // Step 2: our own record.
        let mine = cmd
            .entries()
            .find(|(a, _)| *a == self.nib.network_address)
            .map(|(_, d)| d);
        let end_device = self.nib.is_end_device();
        if mine.is_none() && end_device {
            return;
        }
        if let Some(n) = self.neighbors.by_short_mut(ctx.src) {
            n.last_rssi_dbm = Some(ctx.rssi_dbm);
        }
        // Step 3: adjust the link's power. A sleepy end device applies
        // only the Response to its own Request (§3.4.13.7 note).
        let apply =
            !(end_device && !self.nib.rx_on_when_idle && cmd.kind != LinkPowerDeltaType::Response);
        if apply && let Some(delta) = mine {
            self.push_action(NwkAction::MacAdjustTxPower {
                short: ctx.src,
                extended,
                delta_db: delta,
                rssi_dbm: ctx.rssi_dbm,
            });
        }
        if cmd.kind == LinkPowerDeltaType::Response {
            self.power_request = None;
        }
        self.push_event(NwkEvent::LinkPowerDelta {
            src: ctx.src,
            kind: cmd.kind,
            delta_db: mine,
        });
        // Step 4: an end device is done.
        if end_device {
            return;
        }
        // Step 5: a router answers its end device children, unicast,
        // with the child's own delta.
        if !from_end_device || cmd.kind == LinkPowerDeltaType::Response {
            return;
        }
        let delta = self.power_delta_for(ctx.rssi_dbm);
        let raw = entry(ctx.src, delta);
        let rsp = LinkPowerDelta::from_raw(LinkPowerDeltaType::Response, &raw);
        let seq = self.nib.next_sequence();
        let mut header = Header::new(
            FrameType::Command,
            ctx.src,
            self.nib.network_address,
            1,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        if extended != ExtendedAddress::ZERO {
            header = header.with_dst_ieee(extended);
        }
        let _ = self.send_command_unicast(
            &header,
            &NwkCommand::LinkPowerDelta(rsp),
            ctx.src,
            true,
            !sender_rx_on,
            TxKind::Command,
        );
    }
}

/// One power list record (Figure 3-35).
fn entry(address: ShortAddress, delta_db: i8) -> [u8; 3] {
    let a = address.0.to_le_bytes();
    [a[0], a[1], delta_db.to_le_bytes()[0]]
}
