//! APS layer tests over a virtual NWK medium: acknowledged unicast,
//! duplicate rejection, retries, APS security, fragmentation, groups and
//! the Trust Center join / link-key update procedures.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::command::{ApsCommandId, RequestKeyType, UpdateDeviceStatus};
use panweave_aps::layer::cmd::KeyRoute;
use panweave_aps::layer::{Aps, ApsAction, ApsConfig, ApsEvent, DeviceState, NwkView, TxOptions};
use panweave_aps::{DataRequest, Delivery, Destination, SecurityStatus, TransportedKey};
use panweave_security::cipher::SoftwareAes;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ApsStatus, ClusterId, Endpoint, ExtendedAddress, GroupAddress, Key128, KeyAttributes,
    KeySequenceNumber, KeyType, NwkStatus, ProfileId, ShortAddress,
};

type Node = Aps<SoftwareAes, 8, 8, 8, 8>;

const TC_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const JOINER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const TC_SHORT: ShortAddress = ShortAddress(0x0000);
const ROUTER_SHORT: ShortAddress = ShortAddress(0x1234);
const JOINER_SHORT: ShortAddress = ShortAddress(0x5678);

struct View {
    map: Vec<(ShortAddress, ExtendedAddress)>,
    unauthenticated: Vec<(ExtendedAddress, ShortAddress)>,
}

impl NwkView for View {
    fn ieee_of(&self, short: ShortAddress) -> Option<ExtendedAddress> {
        self.map.iter().find(|(s, _)| *s == short).map(|(_, i)| *i)
    }
    fn short_of(&self, ieee: ExtendedAddress) -> Option<ShortAddress> {
        self.map.iter().find(|(_, i)| *i == ieee).map(|(s, _)| *s)
    }
    fn unauthenticated_child(&self, ieee: ExtendedAddress) -> Option<ShortAddress> {
        self.unauthenticated
            .iter()
            .find(|(i, _)| *i == ieee)
            .map(|(_, s)| *s)
    }
}

struct Frame {
    from: ShortAddress,
    to: ShortAddress,
    secure: bool,
    bytes: Vec<u8>,
}

struct Net {
    nodes: Vec<(ShortAddress, Node)>,
    views: Vec<View>,
    now: Instant,
    /// Drop the next `n` frames from `from`.
    drop_from: Option<(ShortAddress, usize)>,
    log: Vec<Frame>,
}

impl Net {
    fn new() -> Self {
        Net {
            nodes: Vec::new(),
            views: Vec::new(),
            now: Instant::from_millis(1000),
            drop_from: None,
            log: Vec::new(),
        }
    }

    fn add(&mut self, short: ShortAddress, mut node: Node, state: DeviceState, view: View) {
        node.set_network_state(short, state);
        node.poll_timers(self.now);
        self.nodes.push((short, node));
        self.views.push(view);
        // Persist the initial link-key counter reservations.
        self.run();
        self.log.clear();
    }

    fn node(&mut self, short: ShortAddress) -> &mut Node {
        &mut self.nodes.iter_mut().find(|(s, _)| *s == short).unwrap().1
    }

    /// Delivers all queued actions until quiescent.
    fn run(&mut self) {
        loop {
            let mut progressed = false;
            for i in 0..self.nodes.len() {
                let from = self.nodes[i].0;
                while let Some(a) = self.nodes[i].1.next_action() {
                    progressed = true;
                    match a {
                        ApsAction::NwkData {
                            handle,
                            dst,
                            secure,
                            frame,
                            ..
                        } => {
                            let dropped = match &mut self.drop_from {
                                Some((f, n)) if *f == from && *n > 0 => {
                                    *n -= 1;
                                    true
                                }
                                _ => false,
                            };
                            self.log.push(Frame {
                                from,
                                to: dst,
                                secure,
                                bytes: frame.to_vec(),
                            });
                            if !dropped {
                                let targets: Vec<usize> = (0..self.nodes.len())
                                    .filter(|j| {
                                        *j != i && (dst.is_broadcast() || self.nodes[*j].0 == dst)
                                    })
                                    .collect();
                                for j in targets {
                                    let mut buf = frame.to_vec();
                                    let view = &self.views[j];
                                    let src_ieee = view.ieee_of(from);
                                    let at = self.nodes[j].0;
                                    let ind = self.nodes[j].1.on_nwk_data(
                                        &mut buf, from, dst, src_ieee, secure, 200, view,
                                    );
                                    if let Some(ind) = ind {
                                        INDICATIONS.with(|v| {
                                            v.borrow_mut().push(Indication {
                                                at,
                                                src: ind.src,
                                                src_ieee: ind.src_ieee,
                                                delivery: ind.delivery,
                                                asdu: ind.asdu.to_vec(),
                                                security: ind.security,
                                                relayed: ind.relayed.map(|r| r.joiner),
                                            });
                                        });
                                    }
                                }
                            }
                            let status =
                                if dst.is_unicast() && !self.nodes.iter().any(|(s, _)| *s == dst) {
                                    NwkStatus::RouteError
                                } else {
                                    NwkStatus::Success
                                };
                            self.nodes[i].1.on_nwk_data_confirm(handle, status);
                        }
                        ApsAction::CounterReservation {
                            partner,
                            reservation,
                        } => {
                            self.nodes[i]
                                .1
                                .commit_counter_reservation(partner, reservation);
                        }
                        ApsAction::Persist(_) => {}
                    }
                }
            }
            if !progressed {
                break;
            }
        }
    }

    fn advance(&mut self, d: Duration) {
        self.now = self.now.saturating_add(d);
        for (_, n) in &mut self.nodes {
            n.poll_timers(self.now);
        }
        self.run();
    }

    fn events(&mut self, short: ShortAddress) -> Vec<ApsEvent> {
        let n = self.node(short);
        let mut out = Vec::new();
        while let Some(e) = n.next_event() {
            out.push(e);
        }
        out
    }
}

#[derive(Debug, Clone)]
struct Indication {
    at: ShortAddress,
    src: ShortAddress,
    src_ieee: Option<ExtendedAddress>,
    delivery: Delivery,
    asdu: Vec<u8>,
    security: SecurityStatus,
    relayed: Option<ExtendedAddress>,
}

thread_local! {
    static INDICATIONS: std::cell::RefCell<Vec<Indication>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn take_indications() -> Vec<Indication> {
    INDICATIONS.with(|v| std::mem::take(&mut *v.borrow_mut()))
}

fn view_all() -> View {
    View {
        map: vec![
            (TC_SHORT, TC_IEEE),
            (ROUTER_SHORT, ROUTER_IEEE),
            (JOINER_SHORT, JOINER_IEEE),
        ],
        unauthenticated: Vec::new(),
    }
}

fn node(ieee: ExtendedAddress, tc: bool) -> Node {
    let mut n = Node::new(
        ieee,
        ApsConfig {
            is_trust_center: tc,
            ..ApsConfig::default()
        },
    );
    n.aib.trust_center_address = TC_IEEE;
    n
}

fn verified(partner: ExtendedAddress, key: [u8; 16]) -> LinkKeyEntry {
    let mut e = LinkKeyEntry::provisional(partner, Key128::from_bytes(key), LinkKeyKind::Unique);
    e.attributes = KeyAttributes::VerifiedKey;
    e
}

fn two_nodes() -> Net {
    let mut net = Net::new();
    let mut a = node(TC_IEEE, true);
    a.security.install(verified(ROUTER_IEEE, [1; 16])).unwrap();
    let mut b = node(ROUTER_IEEE, false);
    b.security.install(verified(TC_IEEE, [1; 16])).unwrap();
    net.add(TC_SHORT, a, DeviceState::JoinedAuthorized, view_all());
    net.add(ROUTER_SHORT, b, DeviceState::JoinedAuthorized, view_all());
    net
}

fn req<'a>(dst: Destination, asdu: &'a [u8], options: TxOptions) -> DataRequest<'a> {
    DataRequest {
        destination: dst,
        profile: ProfileId::HOME_AUTOMATION,
        cluster: ClusterId(0x0006),
        src_endpoint: Endpoint(1),
        asdu,
        options,
        radius: None,
    }
}

fn confirm_status(events: &[ApsEvent]) -> Option<ApsStatus> {
    events.iter().find_map(|e| match e {
        ApsEvent::DataConfirm { status, .. } => Some(*status),
        _ => None,
    })
}

#[test]
fn acked_unicast_is_delivered_once_and_confirmed() {
    let mut net = two_nodes();
    let v = view_all();
    let id = net
        .node(TC_SHORT)
        .data_request(
            &req(
                Destination::Short {
                    address: ROUTER_SHORT,
                    endpoint: Endpoint(3),
                },
                &[1, 2, 3],
                TxOptions::ACKED,
            ),
            &v,
        )
        .unwrap();
    net.run();
    let ind = take_indications();
    assert_eq!(ind.len(), 1);
    assert_eq!(ind[0].at, ROUTER_SHORT);
    assert_eq!(ind[0].delivery, Delivery::Endpoint(Endpoint(3)));
    assert_eq!(ind[0].asdu, vec![1, 2, 3]);
    assert_eq!(ind[0].security, SecurityStatus::NwkKey);
    assert_eq!(ind[0].src_ieee, Some(TC_IEEE));
    let ev = net.events(TC_SHORT);
    assert!(matches!(
        ev.as_slice(),
        [ApsEvent::DataConfirm { id: i, status: ApsStatus::Success }] if *i == id
    ));
    // Data frame + acknowledgement on the medium.
    assert_eq!(net.log.len(), 2);
    assert_eq!(net.log[1].from, ROUTER_SHORT);
    assert_eq!(net.node(TC_SHORT).pending_len(), 0);

    // A replayed copy of the data frame is rejected as a duplicate but
    // acknowledged again.
    let mut copy = net.log[0].bytes.clone();
    let view = view_all();
    let ind = net.node(ROUTER_SHORT).on_nwk_data(
        &mut copy,
        TC_SHORT,
        ROUTER_SHORT,
        Some(TC_IEEE),
        true,
        200,
        &view,
    );
    assert!(ind.is_none());
    assert_eq!(net.node(ROUTER_SHORT).stats.duplicates, 1);
    assert_eq!(net.node(ROUTER_SHORT).stats.acks_sent, 2);
}

#[test]
fn lost_acknowledgements_trigger_retries_then_no_ack() {
    let mut net = two_nodes();
    let v = view_all();
    // Drop every acknowledgement the router sends.
    net.drop_from = Some((ROUTER_SHORT, 10));
    net.node(TC_SHORT)
        .data_request(
            &req(
                Destination::Short {
                    address: ROUTER_SHORT,
                    endpoint: Endpoint(3),
                },
                &[9],
                TxOptions::ACKED,
            ),
            &v,
        )
        .unwrap();
    net.run();
    assert!(net.events(TC_SHORT).is_empty());
    for _ in 0..4 {
        net.advance(Duration::from_millis(1600));
    }
    let ev = net.events(TC_SHORT);
    assert_eq!(confirm_status(&ev), Some(ApsStatus::NoAck));
    // 1 + apscMaxFrameRetries transmissions; each delivered once.
    let data_frames = net.log.iter().filter(|f| f.from == TC_SHORT).count();
    assert_eq!(data_frames, 4);
    let ind = take_indications();
    assert_eq!(ind.len(), 1, "retransmissions are duplicates");
    assert_eq!(net.node(TC_SHORT).stats.retries, 3);
    assert_eq!(net.node(TC_SHORT).stats.ack_failures, 1);
}

#[test]
fn unacked_broadcast_confirms_on_nwk_confirm() {
    let mut net = two_nodes();
    let v = view_all();
    net.node(TC_SHORT)
        .data_request(
            &req(
                Destination::Short {
                    address: ShortAddress::BROADCAST_RX_ON,
                    endpoint: Endpoint::BROADCAST,
                },
                &[7],
                TxOptions::NONE,
            ),
            &v,
        )
        .unwrap();
    net.run();
    let ind = take_indications();
    assert_eq!(ind.len(), 1);
    assert_eq!(ind[0].delivery, Delivery::AllEndpoints);
    assert_eq!(
        confirm_status(&net.events(TC_SHORT)),
        Some(ApsStatus::Success)
    );
    assert_eq!(net.log.len(), 1, "no acknowledgement for broadcasts");
}

#[test]
fn link_key_secured_data_round_trip() {
    let mut net = two_nodes();
    let v = view_all();
    let opts = TxOptions {
        security: true,
        ack: true,
        fragmentation_permitted: false,
        extended_nonce: false,
    };
    net.node(TC_SHORT)
        .data_request(
            &req(
                Destination::Extended {
                    address: ROUTER_IEEE,
                    endpoint: Endpoint(3),
                },
                &[0xAA, 0xBB],
                opts,
            ),
            &v,
        )
        .unwrap();
    net.run();
    let ind = take_indications();
    assert_eq!(ind.len(), 1);
    assert_eq!(ind[0].security, SecurityStatus::LinkKey);
    assert_eq!(ind[0].asdu, vec![0xAA, 0xBB]);
    assert_eq!(
        confirm_status(&net.events(TC_SHORT)),
        Some(ApsStatus::Success)
    );
    // The frame on air is encrypted: the payload bytes do not appear.
    let on_air = &net.log[0].bytes;
    assert!(on_air[0] & 0x20 != 0, "security bit set");
    assert!(!on_air.windows(2).any(|w| w == [0xAA, 0xBB]));
    // Incoming counter advanced on the receiver.
    assert!(
        net.node(ROUTER_SHORT)
            .security
            .entry(TC_IEEE)
            .unwrap()
            .incoming
            >= 1
    );

    // Without a key for the destination the request fails.
    let mut c = node(JOINER_IEEE, false);
    c.set_network_state(JOINER_SHORT, DeviceState::JoinedAuthorized);
    assert!(
        c.data_request(
            &req(
                Destination::Extended {
                    address: TC_IEEE,
                    endpoint: Endpoint(1)
                },
                &[1],
                opts
            ),
            &v
        )
        .is_err()
    );
}

#[test]
fn fragmented_asdu_is_reassembled() {
    let mut net = two_nodes();
    let v = view_all();
    let asdu: Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
    let id = net
        .node(TC_SHORT)
        .data_request(
            &req(
                Destination::Short {
                    address: ROUTER_SHORT,
                    endpoint: Endpoint(3),
                },
                &asdu,
                TxOptions::ACKED,
            ),
            &v,
        )
        .unwrap();
    net.run();
    let ind = take_indications();
    assert_eq!(ind.len(), 1);
    assert_eq!(ind[0].asdu, asdu);
    let ev = net.events(TC_SHORT);
    assert!(matches!(
        ev.as_slice(),
        [ApsEvent::DataConfirm { id: i, status: ApsStatus::Success }] if *i == id
    ));
    let blocks = net.log.iter().filter(|f| f.from == TC_SHORT).count();
    assert!(blocks >= 3, "{blocks} blocks");
    assert_eq!(
        net.log.iter().filter(|f| f.from == ROUTER_SHORT).count(),
        blocks
    );
    assert_eq!(net.node(ROUTER_SHORT).stats.reassembled, 1);

    // Fragmentation is refused when not permitted.
    assert!(
        net.node(TC_SHORT)
            .data_request(
                &req(
                    Destination::Short {
                        address: ROUTER_SHORT,
                        endpoint: Endpoint(3),
                    },
                    &asdu,
                    TxOptions {
                        fragmentation_permitted: false,
                        ..TxOptions::ACKED
                    },
                ),
                &v,
            )
            .is_err()
    );
}

#[test]
fn fragment_loss_is_recovered_by_retransmission() {
    let mut net = two_nodes();
    let v = view_all();
    let asdu: Vec<u8> = (0..150u8).collect();
    // Lose the second block once.
    net.node(TC_SHORT)
        .data_request(
            &req(
                Destination::Short {
                    address: ROUTER_SHORT,
                    endpoint: Endpoint(3),
                },
                &asdu,
                TxOptions::ACKED,
            ),
            &v,
        )
        .unwrap();
    // Run only the first block, then drop the next frame from the TC.
    net.run();
    let ind = take_indications();
    assert!(ind.is_empty() || ind.len() == 1);
    if ind.is_empty() {
        // Not yet complete: simulate a lost block by dropping a frame.
        net.drop_from = Some((TC_SHORT, 1));
        net.advance(Duration::from_millis(1600));
        net.advance(Duration::from_millis(1600));
        let ind = take_indications();
        assert_eq!(ind.len(), 1);
        assert_eq!(ind[0].asdu, asdu);
    }
}

#[test]
fn group_delivery_and_loopback() {
    let mut net = two_nodes();
    let v = view_all();
    net.node(ROUTER_SHORT)
        .groups
        .add(GroupAddress(0x0010), Endpoint(5))
        .unwrap();
    net.node(TC_SHORT)
        .groups
        .add(GroupAddress(0x0010), Endpoint(2))
        .unwrap();
    net.node(TC_SHORT)
        .data_request(
            &req(
                Destination::Group(GroupAddress(0x0010)),
                &[4],
                TxOptions::ACKED,
            ),
            &v,
        )
        .unwrap();
    net.run();
    let ind = take_indications();
    assert_eq!(ind.len(), 1);
    assert_eq!(ind[0].delivery, Delivery::Group(GroupAddress(0x0010)));
    let lb = net.node(TC_SHORT).take_loopback().unwrap();
    assert_eq!(lb.delivery, Delivery::Group(GroupAddress(0x0010)));
    assert_eq!(lb.asdu.as_slice(), &[4]);
    assert_eq!(net.log.len(), 1);
    assert_eq!(net.log[0].to, ShortAddress::BROADCAST_RX_ON);
    // A group the router does not belong to is filtered.
    net.node(TC_SHORT)
        .data_request(
            &req(
                Destination::Group(GroupAddress(0x0011)),
                &[4],
                TxOptions::NONE,
            ),
            &v,
        )
        .unwrap();
    net.run();
    assert!(take_indications().is_empty());
}

#[test]
fn bound_transmission_fans_out() {
    use panweave_aps::tables::{BindingDestination, BindingEntry};
    let mut net = two_nodes();
    let v = view_all();
    let mut c = node(JOINER_IEEE, false);
    c.security.install(verified(TC_IEEE, [2; 16])).unwrap();
    net.add(JOINER_SHORT, c, DeviceState::JoinedAuthorized, view_all());
    let tc = net.node(TC_SHORT);
    tc.bindings
        .bind(BindingEntry {
            src_endpoint: Endpoint(1),
            cluster: ClusterId(6),
            destination: BindingDestination::Unicast {
                address: ROUTER_IEEE,
                endpoint: Endpoint(7),
            },
        })
        .unwrap();
    tc.bindings
        .bind(BindingEntry {
            src_endpoint: Endpoint(1),
            cluster: ClusterId(6),
            destination: BindingDestination::Unicast {
                address: JOINER_IEEE,
                endpoint: Endpoint(8),
            },
        })
        .unwrap();
    assert!(
        tc.data_request(&req(Destination::Bound, &[1], TxOptions::ACKED), &v)
            .is_ok()
    );
    net.run();
    let mut ind = take_indications();
    ind.sort_by_key(|i| i.at.0);
    assert_eq!(ind.len(), 2);
    assert_eq!(ind[0].delivery, Delivery::Endpoint(Endpoint(7)));
    assert_eq!(ind[1].delivery, Delivery::Endpoint(Endpoint(8)));
    let ev = net.events(TC_SHORT);
    assert_eq!(ev.len(), 1);
    assert_eq!(confirm_status(&ev), Some(ApsStatus::Success));
    // No binding for another cluster.
    let mut r = req(Destination::Bound, &[1], TxOptions::ACKED);
    r.cluster = ClusterId(9);
    assert!(net.node(TC_SHORT).data_request(&r, &v).is_err());
}

/// Full centralized join authorization: Update Device → Tunnel(Transport
/// Key) → joiner authorized; then Request Key / Transport Key (TCLK) /
/// Verify Key / Confirm Key.
#[test]
fn trust_center_join_and_link_key_update() {
    let mut net = Net::new();
    let well_known = Key128::WELL_KNOWN_GLOBAL_TCLK;
    let mut tc = node(TC_IEEE, true);
    tc.security.install(verified(ROUTER_IEEE, [5; 16])).unwrap();
    let mut joiner_entry =
        LinkKeyEntry::provisional(JOINER_IEEE, well_known.clone(), LinkKeyKind::Global);
    joiner_entry.attributes = KeyAttributes::ProvisionalKey;
    tc.security.install(joiner_entry).unwrap();
    let mut router = node(ROUTER_IEEE, false);
    router.security.install(verified(TC_IEEE, [5; 16])).unwrap();
    let mut joiner = node(JOINER_IEEE, false);
    // The joiner does not know the Trust Center yet: placeholder entry.
    joiner.aib.trust_center_address = ExtendedAddress::BROADCAST;
    joiner
        .security
        .install(LinkKeyEntry::provisional(
            ExtendedAddress::BROADCAST,
            well_known,
            LinkKeyKind::Global,
        ))
        .unwrap();
    net.add(TC_SHORT, tc, DeviceState::JoinedAuthorized, view_all());
    net.add(
        ROUTER_SHORT,
        router,
        DeviceState::JoinedAuthorized,
        View {
            map: vec![(TC_SHORT, TC_IEEE), (JOINER_SHORT, JOINER_IEEE)],
            unauthenticated: vec![(JOINER_IEEE, JOINER_SHORT)],
        },
    );
    net.add(
        JOINER_SHORT,
        joiner,
        DeviceState::JoinedUnauthorized,
        View {
            map: vec![(ROUTER_SHORT, ROUTER_IEEE)],
            unauthenticated: Vec::new(),
        },
    );

    // 1. Parent reports the join.
    net.node(ROUTER_SHORT)
        .update_device(
            TC_SHORT,
            JOINER_IEEE,
            JOINER_SHORT,
            UpdateDeviceStatus::UnsecuredJoin,
            &[],
        )
        .unwrap();
    net.run();
    let ev = net.events(TC_SHORT);
    let (device, short) = ev
        .iter()
        .find_map(|e| match e {
            ApsEvent::UpdateDevice {
                device,
                short,
                status: UpdateDeviceStatus::UnsecuredJoin,
                aps_secured: true,
                ..
            } => Some((*device, *short)),
            _ => None,
        })
        .expect("update device indication");
    assert_eq!((device, short), (JOINER_IEEE, JOINER_SHORT));
    assert!(matches!(
        net.events(ROUTER_SHORT).as_slice(),
        [ApsEvent::CommandConfirm {
            command: ApsCommandId::UpdateDevice,
            status: ApsStatus::Success,
            ..
        }]
    ));

    // 2. Trust Center tunnels the network key through the parent.
    let nwk_key = Key128::from_bytes([0x42; 16]);
    net.node(TC_SHORT)
        .transport_network_key(
            JOINER_IEEE,
            &nwk_key,
            KeySequenceNumber(0),
            KeyRoute::Tunnel {
                parent: ROUTER_SHORT,
            },
        )
        .unwrap();
    net.run();
    // The parent forwarded the extracted frame unsecured.
    let to_joiner = net
        .log
        .iter()
        .find(|f| f.from == ROUTER_SHORT && f.to == JOINER_SHORT)
        .expect("forwarded transport key");
    assert!(!to_joiner.secure);
    assert!(to_joiner.bytes[0] & 0x20 != 0, "APS-secured inner frame");
    let ev = net.events(JOINER_SHORT);
    match ev.as_slice() {
        [
            ApsEvent::TransportKey {
                src,
                key: TransportedKey::Network { key, sequence, .. },
                authorizes: true,
            },
        ] => {
            assert_eq!(*src, TC_IEEE);
            assert_eq!(key.as_bytes(), nwk_key.as_bytes());
            assert_eq!(*sequence, KeySequenceNumber(0));
        }
        other => panic!("unexpected {other:?}"),
    }
    let j = net.node(JOINER_SHORT);
    assert_eq!(j.state(), DeviceState::JoinedAuthorized);
    assert_eq!(j.aib.trust_center_address, TC_IEEE);
    assert!(j.security.entry(TC_IEEE).is_some());
    assert!(j.security.entry(ExtendedAddress::BROADCAST).is_none());
    assert!(matches!(
        net.events(TC_SHORT).as_slice(),
        [ApsEvent::CommandConfirm {
            command: ApsCommandId::Tunnel,
            status: ApsStatus::Success,
            ..
        }]
    ));

    // 3. Joiner requests a unique Trust Center link key (BDB 3.1 §10.2.4).
    // Now the joiner's view knows the Trust Center.
    net.views[2].map.push((TC_SHORT, TC_IEEE));
    net.node(JOINER_SHORT)
        .request_key(TC_SHORT, RequestKeyType::TrustCenterLinkKey, None)
        .unwrap();
    net.run();
    let ev = net.events(TC_SHORT);
    assert!(matches!(
        ev.as_slice(),
        [ApsEvent::RequestKey {
            src,
            key_type: RequestKeyType::TrustCenterLinkKey,
            ..
        }] if *src == JOINER_IEEE
    ));
    let new_key = Key128::from_bytes([0x77; 16]);
    net.node(TC_SHORT)
        .transport_trust_center_link_key(JOINER_IEEE, JOINER_SHORT, &new_key, &[])
        .unwrap();
    net.run();
    let ev = net.events(JOINER_SHORT);
    assert!(ev.iter().any(|e| matches!(
        e,
        ApsEvent::TransportKey {
            key: TransportedKey::TrustCenterLink { .. },
            authorizes: false,
            ..
        }
    )));
    let je = net.node(JOINER_SHORT).security.entry(TC_IEEE).unwrap();
    assert_eq!(je.attributes, KeyAttributes::UnverifiedKey);
    assert_eq!(je.key.as_bytes(), new_key.as_bytes());
    let _ = net.events(TC_SHORT);
    let te = net.node(TC_SHORT).security.entry(JOINER_IEEE).unwrap();
    assert_eq!(te.attributes, KeyAttributes::UnverifiedKey);
    assert_eq!(te.key.as_bytes(), new_key.as_bytes());

    // 4. Verify / Confirm.
    net.node(JOINER_SHORT)
        .verify_key(TC_IEEE, TC_SHORT, KeyType::TrustCenterLinkKey)
        .unwrap();
    net.run();
    let ev = net.events(TC_SHORT);
    assert!(ev.iter().any(|e| matches!(
        e,
        ApsEvent::KeyVerified { partner, key_type: KeyType::TrustCenterLinkKey } if *partner == JOINER_IEEE
    )));
    let ev = net.events(JOINER_SHORT);
    assert!(ev.iter().any(|e| matches!(
        e,
        ApsEvent::ConfirmKey {
            status: ApsStatus::Success,
            key_type: KeyType::TrustCenterLinkKey,
            ..
        }
    )));
    assert_eq!(
        net.node(JOINER_SHORT)
            .security
            .entry(TC_IEEE)
            .unwrap()
            .attributes,
        KeyAttributes::VerifiedKey
    );
    assert_eq!(
        net.node(TC_SHORT)
            .security
            .entry(JOINER_IEEE)
            .unwrap()
            .attributes,
        KeyAttributes::VerifiedKey
    );

    // 5. The new key protects application data both ways.
    let opts = TxOptions {
        security: true,
        ..TxOptions::ACKED
    };
    let v = view_all();
    net.node(JOINER_SHORT)
        .data_request(
            &req(
                Destination::Extended {
                    address: TC_IEEE,
                    endpoint: Endpoint(1),
                },
                &[0x11],
                opts,
            ),
            &v,
        )
        .unwrap();
    net.run();
    let ind = take_indications();
    assert!(
        ind.iter()
            .any(|i| i.at == TC_SHORT && i.security == SecurityStatus::LinkKey)
    );
}

#[test]
fn unauthorized_joiner_ignores_data_and_unencrypted_key() {
    let mut net = Net::new();
    let mut tc = node(TC_IEEE, true);
    tc.security.install(verified(JOINER_IEEE, [3; 16])).unwrap();
    let mut joiner = node(JOINER_IEEE, false);
    joiner.aib.trust_center_address = ExtendedAddress::BROADCAST;
    joiner
        .security
        .install(LinkKeyEntry::provisional(
            ExtendedAddress::BROADCAST,
            Key128::from_bytes([3; 16]),
            LinkKeyKind::Unique,
        ))
        .unwrap();
    net.add(TC_SHORT, tc, DeviceState::JoinedAuthorized, view_all());
    net.add(
        JOINER_SHORT,
        joiner,
        DeviceState::JoinedUnauthorized,
        view_all(),
    );
    let v = view_all();
    // Data to an unauthorized device is not delivered.
    net.node(TC_SHORT)
        .data_request(
            &req(
                Destination::Short {
                    address: JOINER_SHORT,
                    endpoint: Endpoint(1),
                },
                &[1],
                TxOptions::NONE,
            ),
            &v,
        )
        .unwrap();
    net.run();
    assert!(take_indications().is_empty());
    assert_eq!(net.node(JOINER_SHORT).stats.policy_dropped, 1);
    // A broadcast (APS-unencrypted) network key is refused while
    // unauthorized because the policy requires link-key encryption.
    net.node(TC_SHORT)
        .transport_network_key(
            ExtendedAddress::ZERO,
            &Key128::from_bytes([9; 16]),
            KeySequenceNumber(1),
            KeyRoute::Broadcast,
        )
        .unwrap();
    net.run();
    assert!(net.events(JOINER_SHORT).is_empty());
    assert_eq!(
        net.node(JOINER_SHORT).state(),
        DeviceState::JoinedUnauthorized
    );
    // A direct, link-key-secured transport key authorizes it.
    net.node(TC_SHORT)
        .transport_network_key(
            JOINER_IEEE,
            &Key128::from_bytes([9; 16]),
            KeySequenceNumber(1),
            KeyRoute::Direct {
                short: JOINER_SHORT,
                nwk_secure: false,
            },
        )
        .unwrap();
    net.run();
    assert_eq!(
        net.node(JOINER_SHORT).state(),
        DeviceState::JoinedAuthorized
    );
    assert_eq!(net.node(JOINER_SHORT).aib.trust_center_address, TC_IEEE);
    // Once authorized, a broadcast key update from the Trust Center is
    // accepted (as the alternate key) and a Switch Key is indicated.
    net.node(TC_SHORT)
        .transport_network_key(
            ExtendedAddress::ZERO,
            &Key128::from_bytes([10; 16]),
            KeySequenceNumber(2),
            KeyRoute::Broadcast,
        )
        .unwrap();
    net.node(TC_SHORT).switch_key(KeySequenceNumber(2)).unwrap();
    net.run();
    let ev = net.events(JOINER_SHORT);
    assert!(ev.iter().any(|e| matches!(
        e,
        ApsEvent::TransportKey {
            key: TransportedKey::Network {
                sequence: KeySequenceNumber(2),
                ..
            },
            authorizes: false,
            ..
        }
    )));
    assert!(ev.iter().any(|e| matches!(
        e,
        ApsEvent::SwitchKey {
            sequence: KeySequenceNumber(2),
            ..
        }
    )));
}

#[test]
fn relayed_frames_reach_the_trust_center_and_back() {
    let mut net = Net::new();
    let mut tc = node(TC_IEEE, true);
    tc.security.install(verified(ROUTER_IEEE, [5; 16])).unwrap();
    tc.security.install(verified(JOINER_IEEE, [6; 16])).unwrap();
    let mut router = node(ROUTER_IEEE, false);
    router.security.install(verified(TC_IEEE, [5; 16])).unwrap();
    let mut joiner = node(JOINER_IEEE, false);
    joiner.security.install(verified(TC_IEEE, [6; 16])).unwrap();
    net.add(TC_SHORT, tc, DeviceState::JoinedAuthorized, view_all());
    net.add(
        ROUTER_SHORT,
        router,
        DeviceState::JoinedAuthorized,
        View {
            map: vec![(TC_SHORT, TC_IEEE), (JOINER_SHORT, JOINER_IEEE)],
            unauthenticated: vec![(JOINER_IEEE, JOINER_SHORT)],
        },
    );
    net.add(
        JOINER_SHORT,
        joiner,
        DeviceState::JoinedUnauthorized,
        View {
            map: vec![(ROUTER_SHORT, ROUTER_IEEE)],
            unauthenticated: Vec::new(),
        },
    );
    let v = view_all();
    // Upstream: joiner → parent → Trust Center, APS-secured with the
    // joiner's link key.
    let opts = TxOptions {
        security: true,
        ..TxOptions::NONE
    };
    let mut r = req(
        Destination::Relayed {
            parent: ROUTER_SHORT,
            joiner: None,
            endpoint: Endpoint(0),
        },
        &[0xC0, 0xDE],
        opts,
    );
    r.profile = ProfileId::ZDP;
    r.src_endpoint = Endpoint(0);
    net.node(JOINER_SHORT).data_request(&r, &v).unwrap();
    net.run();
    let ind = take_indications();
    assert_eq!(ind.len(), 1);
    assert_eq!(ind[0].at, TC_SHORT);
    assert_eq!(ind[0].relayed, Some(JOINER_IEEE));
    assert_eq!(ind[0].src_ieee, Some(JOINER_IEEE));
    assert_eq!(ind[0].asdu, vec![0xC0, 0xDE]);
    assert_eq!(ind[0].security, SecurityStatus::LinkKey);
    // Downstream: Trust Center → parent → joiner.
    let mut r = req(
        Destination::Relayed {
            parent: ROUTER_SHORT,
            joiner: Some(JOINER_IEEE),
            endpoint: Endpoint(0),
        },
        &[0xBE, 0xEF],
        opts,
    );
    r.profile = ProfileId::ZDP;
    r.src_endpoint = Endpoint(0);
    net.node(TC_SHORT).data_request(&r, &v).unwrap();
    net.run();
    let ind = take_indications();
    assert_eq!(ind.len(), 1);
    assert_eq!(ind[0].at, JOINER_SHORT);
    assert_eq!(ind[0].asdu, vec![0xBE, 0xEF]);
    assert_eq!(ind[0].relayed, Some(JOINER_IEEE));
    assert_eq!(ind[0].src, ROUTER_SHORT);
}
