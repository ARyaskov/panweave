//! End-to-end tests of the NWK layer over a virtual single-channel medium.
//!
//! The harness plays the role of the MAC service: it delivers
//! `NwkAction::MacData` frames to the addressed node(s), answers
//! association requests, and turns beacon payloads into beacons during
//! active scans. Everything runs on virtual time.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use panweave_mac::frame::{Beacon, MacAddress};
use panweave_mac::service::{ScanKind, TxStatus};
use panweave_nwk::layer::{JoinParams, Nwk, NwkAction, NwkConfig, NwkEvent, RxOutcome};
use panweave_nwk::nib::Nib;
use panweave_security::cipher::SoftwareAes;
use panweave_types::rng::DeterministicRng;
use panweave_types::{
    Channel, ChannelMask, ChannelPage, Duration, ExtendedAddress, Instant, Key128,
    KeySequenceNumber, LogicalDeviceType, MacCapability, MacStatus, NwkStatus, PanId, ShortAddress,
};

type Layer = Nwk<SoftwareAes, DeterministicRng, 16, 16, 8, 8>;

struct Node {
    nwk: Layer,
    ieee: ExtendedAddress,
    beacon_payload: Vec<u8>,
    beacon_capable: bool,
    permit: bool,
    short: ShortAddress,
    pan: PanId,
    /// Data frames delivered to the "APS" layer: (src, payload).
    received: Vec<(ShortAddress, Vec<u8>)>,
    events: Vec<NwkEvent>,
    /// Association responses pending delivery to a joiner.
    assoc_rsp: Option<(ExtendedAddress, ShortAddress, MacStatus)>,
    /// Frames queued for indirect delivery (this node is a parent).
    indirect: Vec<(ShortAddress, Vec<u8>, panweave_mac::service::TxHandle)>,
}

impl Node {
    fn new(kind: LogicalDeviceType, ieee: u64, seed: u64) -> Self {
        let nib = Nib::new(kind, ExtendedAddress(ieee));
        let cfg = NwkConfig::default();
        Node {
            nwk: Nwk::new(nib, cfg, DeterministicRng::seed(seed)),
            ieee: ExtendedAddress(ieee),
            beacon_payload: Vec::new(),
            beacon_capable: false,
            permit: false,
            short: ShortAddress::NO_SHORT_ADDRESS,
            pan: PanId::BROADCAST,
            received: Vec::new(),
            events: Vec::new(),
            assoc_rsp: None,
            indirect: Vec::new(),
        }
    }
}

struct Net {
    nodes: Vec<Node>,
    now: Instant,
    /// Drops every frame from `a` to `b` (directed) when present.
    blocked: Vec<(usize, usize)>,
    log: Vec<String>,
}

impl Net {
    fn new() -> Self {
        Net {
            nodes: Vec::new(),
            now: Instant::ZERO,
            blocked: Vec::new(),
            log: Vec::new(),
        }
    }

    fn add(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn reachable(&self, from: usize, to: usize) -> bool {
        from != to && !self.blocked.contains(&(from, to))
    }

    /// Runs until no node has pending actions, advancing virtual time to
    /// the next timer deadline when it lies within one second (short
    /// internal retries such as counter reservations and jitter).
    fn settle(&mut self) {
        for _ in 0..100_000 {
            let mut progressed = false;
            for i in 0..self.nodes.len() {
                self.nodes[i].nwk.poll_timers(self.now);
                while let Some(ev) = self.nodes[i].nwk.next_event() {
                    self.nodes[i].events.push(ev);
                }
                if let Some(a) = self.nodes[i].nwk.next_action() {
                    progressed = true;
                    self.perform(i, a);
                }
            }
            if !progressed {
                let next = self
                    .nodes
                    .iter()
                    .filter_map(|n| n.nwk.next_deadline())
                    .min();
                // Only short internal timers (counter retries, jitter) are
                // followed automatically; periodic maintenance is driven by
                // the tests through `run`.
                match next {
                    Some(t) if t <= self.now + Duration::from_millis(200) => {
                        self.now = t.max(self.now + Duration::from_millis(1));
                    }
                    _ => return,
                }
            }
        }
        panic!("network did not settle");
    }

    fn advance(&mut self, d: Duration) {
        self.now += d;
        self.settle();
    }

    /// Advances in steps of `step` for `total`, settling after each step.
    fn run(&mut self, total: Duration, step: Duration) {
        let end = self.now + total;
        while self.now < end {
            self.advance(step);
        }
    }

    fn perform(&mut self, i: usize, action: NwkAction) {
        match action {
            NwkAction::MacData {
                handle,
                dst,
                frame,
                ack,
                indirect,
            } => {
                let src = self.nodes[i].short;
                let pan = self.nodes[i].pan;
                self.log.push(format!(
                    "{i}: MacData dst={dst} len={} ack={ack} indirect={indirect}",
                    frame.len()
                ));
                if indirect {
                    self.nodes[i].indirect.push((dst, frame.to_vec(), handle));
                    return;
                }
                let mut delivered = false;
                let targets: Vec<usize> = (0..self.nodes.len())
                    .filter(|&j| {
                        self.reachable(i, j)
                            && (self.nodes[j].pan == pan || self.nodes[j].pan == PanId::BROADCAST)
                            && (dst == ShortAddress::BROADCAST_ALL || self.nodes[j].short == dst)
                    })
                    .collect();
                for j in targets {
                    delivered = true;
                    let mut buf = frame.to_vec();
                    self.deliver(j, &mut buf, src);
                }
                let status = if !ack || delivered {
                    TxStatus::Success
                } else {
                    TxStatus::NoAck
                };
                self.nodes[i].nwk.on_mac_data_confirm(handle, status);
            }
            NwkAction::MacScan {
                kind,
                channels,
                duration: _,
                enhanced: _,
            } => {
                let mut energy = [0u8; 27];
                if kind == ScanKind::Active {
                    let beacons: Vec<(usize, PanId, ShortAddress, Vec<u8>, bool, bool)> = self
                        .nodes
                        .iter()
                        .enumerate()
                        .filter(|(j, n)| self.reachable(i, *j) && n.beacon_capable)
                        .map(|(j, n)| {
                            (
                                j,
                                n.pan,
                                n.short,
                                n.beacon_payload.clone(),
                                n.permit,
                                n.short == ShortAddress::COORDINATOR,
                            )
                        })
                        .collect();
                    for (_, pan, short, payload, permit, coord) in beacons {
                        let beacon = Beacon::non_beacon(coord, permit, &payload);
                        let ch = channels.first().unwrap_or(Channel::DEFAULT_2_4GHZ);
                        self.nodes[i].nwk.on_mac_beacon(
                            pan,
                            MacAddress::Short(short),
                            &beacon,
                            ch,
                            ChannelPage::PAGE_0,
                            200,
                        );
                    }
                } else {
                    for c in channels.iter() {
                        energy[usize::from(c.raw())] = 10;
                    }
                }
                self.nodes[i].nwk.on_mac_scan_confirm(kind, &energy);
            }
            NwkAction::MacAssociate {
                pan_id,
                coordinator,
                capability,
                ..
            } => {
                let joiner = self.nodes[i].ieee;
                let parent = (0..self.nodes.len()).find(|&j| {
                    self.reachable(i, j)
                        && self.nodes[j].pan == pan_id
                        && self.nodes[j].short == coordinator
                });
                match parent {
                    Some(p) => {
                        self.nodes[p]
                            .nwk
                            .on_mac_associate_indication(joiner, capability, 200);
                        // Let the parent respond.
                        while let Some(a) = self.nodes[p].nwk.next_action() {
                            self.perform(p, a);
                        }
                        if let Some((dev, short, status)) = self.nodes[p].assoc_rsp.take() {
                            assert_eq!(dev, joiner);
                            self.nodes[i].nwk.on_mac_associate_confirm(short, status);
                            self.nodes[p].nwk.on_mac_comm_status(dev, TxStatus::Success);
                        }
                    }
                    None => {
                        self.nodes[i].nwk.on_mac_associate_confirm(
                            ShortAddress::NO_SHORT_ADDRESS,
                            MacStatus::NoAck,
                        );
                    }
                }
            }
            NwkAction::MacDataDeferred { handle, dst } => {
                // Held without a frame until the child polls.
                self.log.push(format!("{i}: MacDataDeferred dst={dst}"));
                self.nodes[i].indirect.push((dst, Vec::new(), handle));
            }
            NwkAction::MacAssociateResponse {
                device,
                short,
                status,
            } => {
                self.nodes[i].assoc_rsp = Some((device, short, status));
            }
            NwkAction::MacStart {
                pan_id,
                short,
                beacon_capable,
                ..
            } => {
                self.nodes[i].pan = pan_id;
                self.nodes[i].short = short;
                self.nodes[i].beacon_capable = beacon_capable;
            }
            NwkAction::MacSetPermit(p) => self.nodes[i].permit = p,
            NwkAction::MacSetBeaconPayload(v) => self.nodes[i].beacon_payload = v.to_vec(),
            NwkAction::MacSetShortAddress(s) => self.nodes[i].short = s,
            NwkAction::MacSetPanId(p) => self.nodes[i].pan = p,
            NwkAction::MacPoll => {
                // Deliver indirect frames queued at any parent for us.
                let me = self.nodes[i].short;
                let me_ieee = self.nodes[i].ieee;
                for p in 0..self.nodes.len() {
                    if !self.reachable(i, p) {
                        continue;
                    }
                    let mut keep = Vec::new();
                    let mut deliver = Vec::new();
                    for (dst, frame, handle) in self.nodes[p].indirect.drain(..) {
                        if dst == me {
                            deliver.push((frame, handle));
                        } else {
                            keep.push((dst, frame, handle));
                        }
                    }
                    self.nodes[p].indirect = keep;
                    let psrc = self.nodes[p].short;
                    for (mut frame, handle) in deliver {
                        if frame.is_empty() {
                            // Deferred: the parent secures it now and sends
                            // it directly (performed by the settle loop).
                            self.nodes[p].nwk.on_mac_indirect_ready(handle);
                            continue;
                        }
                        self.deliver(i, &mut frame, psrc);
                        self.nodes[p]
                            .nwk
                            .on_mac_data_confirm(handle, TxStatus::Success);
                    }
                    self.nodes[p]
                        .nwk
                        .on_mac_poll_indication(MacAddress::Short(me));
                    let _ = me_ieee;
                }
                self.nodes[i].nwk.on_mac_poll_confirm(true, false);
            }
            NwkAction::MacSetChannel { .. }
            | NwkAction::MacSetCoordinator { .. }
            | NwkAction::MacSetRxOnWhenIdle(_)
            | NwkAction::MacAdjustTxPower { .. }
            | NwkAction::MacResetTxPower
            | NwkAction::Persist => {}
            NwkAction::CounterReservation(r) => self.nodes[i].nwk.commit_counter_reservation(r),
        }
    }

    fn deliver(&mut self, j: usize, buf: &mut [u8], mac_src: ShortAddress) {
        let outcome = self.nodes[j].nwk.on_mac_data(buf, mac_src, 200, -40);
        if let RxOutcome::Data { src, payload, .. } = outcome {
            let p = payload.to_vec();
            self.nodes[j].received.push((src, p));
        }
    }

    fn take_events(&mut self, i: usize) -> Vec<NwkEvent> {
        std::mem::take(&mut self.nodes[i].events)
    }
}

const KEY: Key128 = Key128::from_bytes([0x11; 16]);

fn form_coordinator(net: &mut Net) -> usize {
    let mut c = Node::new(LogicalDeviceType::Coordinator, 0xC0, 1);
    c.nwk
        .set_network_key(KeySequenceNumber(0), KEY.clone(), true);
    let ci = net.add(c);
    net.nodes[ci]
        .nwk
        .network_formation(ChannelMask::BDB_PRIMARY, 3, false)
        .unwrap();
    net.settle();
    let evs = net.take_events(ci);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            NwkEvent::FormationConfirm {
                status: NwkStatus::Success
            }
        )),
        "{evs:?}"
    );
    assert_eq!(net.nodes[ci].short, ShortAddress::COORDINATOR);
    assert!(net.nodes[ci].beacon_capable);
    net.nodes[ci].nwk.permit_joining(255).unwrap();
    net.settle();
    ci
}

/// Joins `i` through MAC association and delivers the key as the Trust
/// Center would; returns the address assigned.
fn join_via_association(net: &mut Net, i: usize, as_router: bool, sleepy: bool) -> ShortAddress {
    net.nodes[i]
        .nwk
        .network_discovery(ChannelMask::BDB_PRIMARY, 3, true)
        .unwrap();
    net.settle();
    let evs = net.take_events(i);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            NwkEvent::DiscoveryConfirm {
                status: NwkStatus::Success
            }
        )),
        "{evs:?}"
    );
    let capability = if as_router {
        MacCapability::ROUTER
    } else if sleepy {
        MacCapability::SLEEPY_END_DEVICE
    } else {
        MacCapability::END_DEVICE_RX_ON
    };
    net.nodes[i]
        .nwk
        .join(JoinParams {
            extended_pan_id: None,
            rejoin: false,
            as_router,
            secure: false,
            capability,
            require_permit: true,
        })
        .unwrap();
    net.settle();
    let evs = net.take_events(i);
    let joined = evs.iter().find_map(|e| match e {
        NwkEvent::JoinConfirm {
            status: NwkStatus::Success,
            network_address,
            secured: false,
            ..
        } => Some(*network_address),
        _ => None,
    });
    let addr = joined.unwrap_or_else(|| panic!("join failed: {evs:?}"));
    assert!(addr.is_unicast());
    // Parent indicated the join.
    let parent = (0..net.nodes.len())
        .find(|&p| {
            net.nodes[p]
                .events
                .iter()
                .any(|e| matches!(e, NwkEvent::JoinIndication { device, .. } if *device == net.nodes[i].ieee))
        })
        .expect("parent join indication");
    net.take_events(parent);
    // Trust Center delivers the network key (APS transport key).
    net.nodes[i]
        .nwk
        .set_network_key(KeySequenceNumber(0), KEY.clone(), true);
    let joiner_ieee = net.nodes[i].ieee;
    net.nodes[parent].nwk.authenticate_child(joiner_ieee);
    net.settle();
    if as_router {
        net.nodes[i].nwk.start_router().unwrap();
        net.settle();
    }
    addr
}

#[test]
fn coordinator_forms_and_end_device_joins_and_exchanges_data() {
    let mut net = Net::new();
    let ci = form_coordinator(&mut net);
    let mut ed = Node::new(LogicalDeviceType::EndDevice, 0xED, 2);
    ed.nwk.nib.rx_on_when_idle = true;
    let ei = net.add(ed);
    let addr = join_via_association(&mut net, ei, false, false);
    assert!(net.nodes[ei].nwk.is_operational());
    // The end device negotiated its timeout with the parent (secured).
    let evs = net.take_events(ei);
    assert!(
        evs.iter()
            .any(|e| matches!(e, NwkEvent::ParentInformationUpdated)),
        "{evs:?}"
    );
    let child = net.nodes[ci].nwk.neighbors.by_short(addr).unwrap();
    assert_eq!(
        child.relationship,
        panweave_nwk::neighbor::Relationship::Child
    );
    assert!(child.keepalive_received);

    // Data end device → coordinator.
    net.nodes[ei]
        .nwk
        .data_request(ShortAddress::COORDINATOR, b"hello", None, true, true)
        .unwrap();
    net.settle();
    assert_eq!(
        net.nodes[ci].received.last().unwrap(),
        &(addr, b"hello".to_vec())
    );
    let evs = net.take_events(ei);
    assert!(evs.iter().any(|e| matches!(
        e,
        NwkEvent::DataConfirm {
            status: NwkStatus::Success,
            ..
        }
    )));

    // Data coordinator → end device.
    net.nodes[ci]
        .nwk
        .data_request(addr, b"world", None, true, true)
        .unwrap();
    net.settle();
    assert_eq!(
        net.nodes[ei].received.last().unwrap(),
        &(ShortAddress::COORDINATOR, b"world".to_vec())
    );
    // Replay protection: re-delivering the last frame is rejected. Use the
    // security statistics as the observable.
    let before = net.nodes[ei].nwk.stats.replays;
    let last = net
        .log
        .iter()
        .rev()
        .find(|l| l.starts_with(&format!("{ci}: MacData dst={addr}")))
        .cloned();
    assert!(last.is_some());
    // Broadcast from the coordinator reaches the end device.
    net.nodes[ci]
        .nwk
        .data_request(ShortAddress::BROADCAST_ALL, b"bcast", None, false, true)
        .unwrap();
    net.settle();
    assert_eq!(
        net.nodes[ei].received.last().unwrap(),
        &(ShortAddress::COORDINATOR, b"bcast".to_vec())
    );
    assert_eq!(net.nodes[ei].nwk.stats.replays, before);
    assert_eq!(net.nodes[ci].nwk.stats.security_failures, 0);
    assert_eq!(net.nodes[ei].nwk.stats.security_failures, 0);
}

#[test]
fn sleepy_end_device_receives_via_indirect_delivery() {
    let mut net = Net::new();
    let ci = form_coordinator(&mut net);
    let ed = Node::new(LogicalDeviceType::EndDevice, 0x5E, 3);
    let ei = net.add(ed);
    let addr = join_via_association(&mut net, ei, false, true);
    assert!(net.nodes[ei].nwk.is_operational());
    let child = net.nodes[ci].nwk.neighbors.by_short(addr).unwrap();
    assert!(!child.rx_on_when_idle);
    net.nodes[ci]
        .nwk
        .data_request(addr, b"wake", None, true, true)
        .unwrap();
    net.settle();
    assert!(
        !net.nodes[ci].indirect.is_empty(),
        "frame is held for the sleepy child"
    );
    assert!(net.nodes[ei].received.is_empty());
    // A broadcast the child overhears meanwhile must not make the held
    // frame stale: it is secured only when the child polls (§3.6.2.2).
    net.nodes[ci]
        .nwk
        .data_request(ShortAddress::BROADCAST_ALL, b"news", None, false, true)
        .unwrap();
    net.settle();
    assert_eq!(
        net.nodes[ei].received.last().unwrap(),
        &(ShortAddress::COORDINATOR, b"news".to_vec())
    );
    let replays = net.nodes[ei].nwk.stats.replays;
    // The child polls.
    net.nodes[ei]
        .nwk
        .request(panweave_nwk::layer::NwkRequest::Poll);
    net.settle();
    // Both held frames (the unicast and the broadcast's copy) arrive,
    // freshly secured: no replay.
    assert!(
        net.nodes[ei]
            .received
            .contains(&(ShortAddress::COORDINATOR, b"wake".to_vec()))
    );
    assert_eq!(net.nodes[ei].nwk.stats.replays, replays);
    assert!(net.nodes[ci].indirect.is_empty());
    let evs = net.take_events(ci);
    assert!(evs.iter().any(|e| matches!(
        e,
        NwkEvent::DataConfirm {
            status: NwkStatus::Success,
            ..
        }
    )));
}

#[test]
fn router_joins_and_routes_between_end_devices_of_different_parents() {
    let mut net = Net::new();
    let ci = form_coordinator(&mut net);
    // Router joins the coordinator.
    let r = Node::new(LogicalDeviceType::Router, 0xA0, 4);
    let ri = net.add(r);
    let r_addr = join_via_association(&mut net, ri, true, false);
    assert!(net.nodes[ri].beacon_capable);
    net.nodes[ri].nwk.permit_joining(255).unwrap();
    net.settle();
    // Link status exchange so both routers know each other's outgoing cost.
    net.run(Duration::from_secs(40), Duration::from_secs(1));
    let c_sees_r = net.nodes[ci].nwk.neighbors.by_short(r_addr).unwrap();
    assert!(
        c_sees_r.outgoing_cost > 0,
        "coordinator learnt router's incoming cost"
    );
    let r_sees_c = net.nodes[ri]
        .nwk
        .neighbors
        .by_short(ShortAddress::COORDINATOR)
        .unwrap();
    assert!(r_sees_c.outgoing_cost > 0);

    // End device joins the router only (cannot hear the coordinator).
    let ed = Node::new(LogicalDeviceType::EndDevice, 0xE1, 5);
    let ei = net.add(ed);
    net.blocked.push((ei, ci));
    net.blocked.push((ci, ei));
    // Restrict the end device to the router by making the coordinator
    // unreachable during discovery.
    let e_addr = join_via_association(&mut net, ei, false, false);
    assert_eq!(net.nodes[ei].nwk.nib.parent_address, r_addr);
    net.take_events(ei);
    net.take_events(ci);
    net.take_events(ri);

    // Coordinator sends to the end device: needs a route via the router.
    net.nodes[ci]
        .nwk
        .data_request(e_addr, b"routed", None, true, true)
        .unwrap();
    net.run(Duration::from_secs(2), Duration::from_millis(50));
    assert_eq!(
        net.nodes[ei]
            .received
            .last()
            .expect("end device got routed frame"),
        &(ShortAddress::COORDINATOR, b"routed".to_vec())
    );
    let evs = net.take_events(ci);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            NwkEvent::RouteDiscoveryConfirm {
                status: NwkStatus::Success,
                ..
            }
        )),
        "{evs:?}"
    );
    assert!(evs.iter().any(|e| matches!(
        e,
        NwkEvent::DataConfirm {
            status: NwkStatus::Success,
            ..
        }
    )));
    let route = net.nodes[ci]
        .nwk
        .routes
        .get(e_addr)
        .expect("route installed");
    assert_eq!(route.next_hop, r_addr);
    assert_eq!(route.status, panweave_nwk::routing::RouteStatus::Active);

    // Reply path: end device → coordinator through the router (relay).
    net.nodes[ei]
        .nwk
        .data_request(ShortAddress::COORDINATOR, b"back", None, true, true)
        .unwrap();
    net.run(Duration::from_secs(2), Duration::from_millis(50));
    assert_eq!(
        net.nodes[ci].received.last().unwrap(),
        &(e_addr, b"back".to_vec())
    );
    assert!(net.nodes[ri].nwk.stats.relayed >= 1);
}

#[test]
fn leave_and_child_aging() {
    let mut net = Net::new();
    let ci = form_coordinator(&mut net);
    let ed = Node::new(LogicalDeviceType::EndDevice, 0xE2, 6);
    let ei = net.add(ed);
    let e_addr = join_via_association(&mut net, ei, false, false);
    net.take_events(ci);
    net.take_events(ei);

    // Coordinator removes the child.
    let ed_ieee = net.nodes[ei].ieee;
    net.nodes[ci]
        .nwk
        .leave(Some(ed_ieee), false, false)
        .unwrap();
    net.settle();
    let evs = net.take_events(ei);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            NwkEvent::LeaveIndication {
                device: None,
                rejoin: false,
                ..
            }
        )),
        "{evs:?}"
    );
    assert!(!net.nodes[ei].nwk.nib.joined);
    assert!(net.nodes[ci].nwk.neighbors.by_short(e_addr).is_none());
    let evs = net.take_events(ci);
    assert!(
        evs.iter()
            .any(|e| matches!(e, NwkEvent::ChildRemoved { .. }))
    );

    // Rejoin the network; then let the child age out on the parent by
    // silencing it beyond its (10 s) negotiated timeout.
    let ed2 = Node::new(LogicalDeviceType::EndDevice, 0xE3, 7);
    let ei2 = net.add(ed2);
    net.nodes[ei2].nwk.nib.end_device_timeout = panweave_nwk::command::TimeoutIndex(0);
    let e2 = join_via_association(&mut net, ei2, false, false);
    assert!(net.nodes[ci].nwk.neighbors.by_short(e2).is_some());
    net.take_events(ci);
    // Cut the link so keepalives never arrive.
    net.blocked.push((ei2, ci));
    net.run(Duration::from_secs(15), Duration::from_secs(1));
    assert!(
        net.nodes[ci].nwk.neighbors.by_short(e2).is_none(),
        "child aged out"
    );
    let evs = net.take_events(ci);
    assert!(
        evs.iter()
            .any(|e| matches!(e, NwkEvent::ChildRemoved { .. }))
    );
}

#[test]
fn secured_rejoin_after_reboot_keeps_address() {
    let mut net = Net::new();
    let ci = form_coordinator(&mut net);
    let ed = Node::new(LogicalDeviceType::EndDevice, 0xE4, 8);
    let ei = net.add(ed);
    let e_addr = join_via_association(&mut net, ei, false, false);
    net.take_events(ci);
    net.take_events(ei);
    // Simulate a reboot: a fresh layer restored from persisted identity.
    let old = &net.nodes[ei].nwk;
    let mut nib = Nib::new(LogicalDeviceType::EndDevice, ExtendedAddress(0xE4));
    nib.network_address = old.nib.network_address;
    nib.pan_id = old.nib.pan_id;
    nib.extended_pan_id = old.nib.extended_pan_id;
    nib.channel = old.nib.channel;
    let reserved = old.security.keys.outgoing.reserved_until();
    let mut fresh: Layer = Nwk::new(nib, NwkConfig::default(), DeterministicRng::seed(9));
    fresh.set_network_key(KeySequenceNumber(0), KEY.clone(), true);
    fresh.security.restore_outgoing_counter(reserved);
    fresh.warm_start();
    net.nodes[ei].nwk = fresh;
    net.nodes[ei].received.clear();
    net.settle();
    // Rejoin securely.
    net.nodes[ei]
        .nwk
        .network_discovery(ChannelMask::BDB_PRIMARY, 3, false)
        .unwrap();
    net.settle();
    let epid = net.nodes[ci].nwk.nib.extended_pan_id;
    net.nodes[ei]
        .nwk
        .join(JoinParams {
            extended_pan_id: Some(epid),
            rejoin: true,
            as_router: false,
            secure: true,
            capability: MacCapability::END_DEVICE_RX_ON,
            require_permit: false,
        })
        .unwrap();
    net.settle();
    let evs = net.take_events(ei);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            NwkEvent::JoinConfirm { status: NwkStatus::Success, network_address, rejoin: true, secured: true, .. }
            if *network_address == e_addr
        )),
        "{evs:?}"
    );
    let evs = net.take_events(ci);
    assert!(
        evs.iter().any(|e| matches!(
            e,
            NwkEvent::JoinIndication {
                method: panweave_nwk::layer::JoinMethod::RejoinSecured
                    | panweave_nwk::layer::JoinMethod::CommissioningRejoinSecured,
                ..
            }
        )),
        "{evs:?}"
    );
    // Data still flows (frame counters continued from the reservation).
    net.nodes[ei]
        .nwk
        .data_request(ShortAddress::COORDINATOR, b"again", None, true, true)
        .unwrap();
    net.settle();
    assert_eq!(
        net.nodes[ci].received.last().unwrap(),
        &(e_addr, b"again".to_vec())
    );
    assert_eq!(net.nodes[ci].nwk.stats.replays, 0);
}

/// PAN ID conflicts are counted, never reported unsolicited (R23.2
/// §3.6.1.13.1); a legacy Network Report reaches the application as a
/// NETWORK-STATUS 0x14; the manager changes the PAN ID only on request
/// (§3.6.1.13.3) and routers follow the Network Update.
#[test]
fn pan_id_conflicts_are_counted_and_changes_are_explicit() {
    use panweave_codec::Encode;
    use panweave_nwk::beacon::BeaconPayload;
    use panweave_types::{ChannelPage, PanId};
    let mut net = Net::new();
    let ci = form_coordinator(&mut net);
    let ri = net.add(Node::new(LogicalDeviceType::Router, 0xB1, 2));
    let _ = join_via_association(&mut net, ri, true, false);
    net.settle();
    let pan = net.nodes[ci].pan;
    let log_before = net.log.len();

    // A foreign network on our PAN ID with another extended PAN ID.
    let foreign = BeaconPayload::new(ExtendedAddress(0xDEAD_BEEF_0000_0001), true, true, 0, &[]);
    let mut buf = [0u8; 32];
    let n = foreign.encode_to_slice(&mut buf).unwrap();
    let beacon = Beacon::non_beacon(true, true, &buf[..n]);
    for _ in 0..3 {
        net.nodes[ci].nwk.on_mac_beacon(
            pan,
            MacAddress::Short(ShortAddress(0x7777)),
            &beacon,
            Channel::DEFAULT_2_4GHZ,
            ChannelPage(0),
            100,
        );
    }
    net.settle();
    assert_eq!(net.nodes[ci].nwk.nib.pan_id_conflict_count, 3);
    assert_eq!(net.log.len(), log_before, "no unsolicited report");
    assert_eq!(net.nodes[ci].pan, pan, "no automatic PAN ID change");

    // The application decides: stage the next PAN ID and change.
    let staged = PanId(0x1234);
    net.nodes[ci].nwk.nib.next_pan_id = staged;
    net.nodes[ci].nwk.change_pan_id().unwrap();
    net.settle();
    net.advance(Duration::from_secs(10));
    net.settle();
    assert_eq!(net.nodes[ci].nwk.nib.pan_id, staged);
    assert_eq!(
        net.nodes[ri].nwk.nib.pan_id, staged,
        "router followed the Network Update"
    );
    assert_eq!(
        net.nodes[ri].nwk.nib.update_id,
        net.nodes[ci].nwk.nib.update_id
    );
    let evs = net.take_events(ri);
    assert!(
        evs.iter()
            .any(|e| matches!(e, NwkEvent::PanIdChanged { pan_id } if *pan_id == staged))
    );
}
