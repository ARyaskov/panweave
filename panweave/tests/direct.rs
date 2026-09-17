//! A Zigbee Direct device end to end: the facade `Node` as the ZDD behind
//! the Commissioning Service: a coordinator formed through a Form
//! Network write, opened through Permit Joining, a router joined through
//! Join Network (MAC association), another adopted out of band, and a
//! Leave Network, with the Commissioning Status notifications a ZVD
//! would receive (ZD 1.1 §7.7.2).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave::mac::radio::{RxMetadata, TxResult};
use panweave::mac::service::MacAction;
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::storage::MemoryStorage;
use panweave::testkit::{TestRng, VirtualClock, VirtualMedium};
use panweave::types::time::Duration;
use panweave::types::{Channel, ChannelMask, ExtendedAddress, Key128, PanId, ShortAddress};
use panweave::{Coordinator, Event, Node, Router};
use panweave_direct::auth::Level;
use panweave_direct::commissioning::{
    Access, Characteristic, Commissioning, DeviceType, Domain, FormNetwork, JoinNetwork,
    JoinedStatus, JoiningMethod, LeaveNetwork, decode_status,
};

type N = Node<SoftwareAes, TestRng, MemoryStorage<64, 128>>;

/// Minimal host loop over the virtual medium.
struct World {
    medium: VirtualMedium,
    clock: VirtualClock,
    nodes: Vec<(N, usize, Vec<Event>)>,
}

impl World {
    fn add(&mut self, mut node: N) -> usize {
        let radio = self.medium.add_radio();
        node.poll(self.clock.now());
        self.nodes.push((node, radio, Vec::new()));
        self.nodes.len() - 1
    }

    fn settle(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                while let Some(a) = self.nodes[i].0.next_radio_action() {
                    moved = true;
                    match a {
                        MacAction::Transmit { frame, .. } => {
                            let now = self.clock.now();
                            let radio = self.nodes[i].1;
                            let (air, targets) = self.medium.transmit(radio, &frame);
                            if let Some(air) = air {
                                for t in targets {
                                    if let Some(j) = self.nodes.iter().position(|n| n.1 == t) {
                                        self.nodes[j].0.on_radio_frame(
                                            &air.bytes,
                                            RxMetadata {
                                                lqi: 200,
                                                rssi_dbm: -40,
                                                timestamp_us: None,
                                                acked_by_hardware: false,
                                                channel: Some(air.channel),
                                            },
                                        );
                                    }
                                }
                            }
                            self.nodes[i].0.on_tx_complete(Ok(TxResult {
                                acked: false,
                                frame_pending: false,
                                timestamp_us: Some(now.as_millis() * 1000),
                            }));
                        }
                        MacAction::SetChannel { channel, .. } => {
                            let radio = self.nodes[i].1;
                            self.medium.set_channel(radio, channel);
                        }
                        MacAction::EnergyDetect { .. } => self.nodes[i].0.on_energy_result(0),
                        MacAction::Configure(_) | MacAction::SetPending { .. } => {}
                    }
                }
                while let Some(e) = self.nodes[i].0.next_event() {
                    moved = true;
                    self.nodes[i].2.push(e);
                }
            }
            if !moved {
                break;
            }
        }
    }

    fn run_until(&mut self, timeout: Duration, mut pred: impl FnMut(&World) -> bool) -> bool {
        let end = self.clock.now() + timeout;
        loop {
            self.settle();
            if pred(self) {
                return true;
            }
            if self.clock.now().as_millis() >= end.as_millis() {
                return false;
            }
            let now = self.clock.now();
            let next = self
                .nodes
                .iter()
                .filter_map(|n| n.0.next_deadline())
                .min_by_key(|t| t.as_millis())
                .map_or(now + Duration::from_millis(250), |t| {
                    if t.as_millis() <= now.as_millis() {
                        now + Duration::from_millis(1)
                    } else {
                        t
                    }
                });
            let target = if next.as_millis() > now.as_millis() + 250 {
                now + Duration::from_millis(250)
            } else {
                next
            };
            self.clock.advance_to(target);
            for n in &mut self.nodes {
                n.0.poll(target);
            }
        }
    }
}

fn direct_done(w: &World, i: usize, d: Domain) -> Option<u8> {
    w.nodes[i].2.iter().find_map(|e| match e {
        Event::Direct { domain, status } if *domain == d => Some(*status),
        _ => None,
    })
}

fn report(w: &mut World, i: usize, svc: &mut Commissioning, d: Domain) -> Vec<u8> {
    let status = direct_done(w, i, d).expect("operation completed");
    svc.report(&w.nodes[i].0, d, status);
    w.nodes[i].2.clear();
    svc.next_notification().expect("notification").to_vec()
}

#[test]
fn zdd_form_open_join_adopt_and_leave() {
    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let channel = Channel::new_2_4ghz(15).unwrap();
    let mask = ChannelMask::EMPTY.with(channel);
    let nwk_key = Key128::from_bytes([0x5a; 16]);

    let mut coord = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    let c = w.add(coord);

    // Form Network over a provisioning session: PAN ID, channel and
    // network key chosen by the ZVD.
    let mut zvd_c = Commissioning::new(Level::Provisioning, false);
    let mut buf = [0u8; 128];
    let n = FormNetwork {
        pan_id: Some(PanId(0x1A62)),
        channels: Some(mask),
        network_key: Some(nwk_key.clone()),
        ..FormNetwork::default()
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_c.write(&mut w.nodes[c].0, Characteristic::FormNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(zvd_c.next_notification().is_none());
    assert!(w.run_until(Duration::from_secs(30), |w| {
        direct_done(w, c, Domain::FormNetwork).is_some()
    }));
    let note = report(&mut w, c, &mut zvd_c, Domain::FormNetwork);
    let (r, code) = decode_status(&note).unwrap();
    assert!(code.is_none());
    let r = r.unwrap();
    assert_eq!(r.status.joined, JoinedStatus::Commissioned);
    assert!(r.status.centralized && !r.status.open);
    let info = r.network.unwrap();
    assert_eq!(info.pan_id, PanId(0x1A62));
    assert_eq!(info.channel, mask);
    assert_eq!(info.device_type, DeviceType::Coordinator);
    assert_eq!(info.nwk_address, ShortAddress(0));
    let epid = info.extended_pan_id;
    // The provisioning session lost its write access once provisioned.
    assert_eq!(
        zvd_c.write(&mut w.nodes[c].0, Characteristic::PermitJoining, &[60]),
        Access::Unauthorized
    );
    let mut admin_c = Commissioning::new(Level::Admin, true);
    assert_eq!(
        admin_c.write(&mut w.nodes[c].0, Characteristic::PermitJoining, &[120]),
        Access::Ok
    );
    let (r, _) = decode_status(&admin_c.next_notification().unwrap()).unwrap();
    assert!(r.unwrap().status.open);
    w.settle();

    // A router ZDD joins by MAC association on the given channel and
    // extended PAN ID.
    let router = Router::new(ExtendedAddress(0x00DD_0000_0000_0002))
        .build::<SoftwareAes, _, _>(TestRng::seed(2), MemoryStorage::new());
    let r1 = w.add(router);
    let mut zvd_r = Commissioning::new(Level::Provisioning, false);
    let n = JoinNetwork {
        method: JoiningMethod::Association,
        extended_pan_id: Some(epid),
        pan_id: None,
        channels: Some(mask),
        network_key: None,
        link_key: None,
        nwk_address: None,
        trust_center: None,
        update_id: None,
        key_sequence: None,
        admin_key: None,
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_r.write(&mut w.nodes[r1].0, Characteristic::JoinNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(
        w.run_until(Duration::from_secs(120), |w| direct_done(
            w,
            r1,
            Domain::JoinNetwork
        )
        .is_some()),
        "{:?}",
        w.nodes[r1].2
    );
    let note = report(&mut w, r1, &mut zvd_r, Domain::JoinNetwork);
    let (r, code) = decode_status(&note).unwrap();
    assert!(code.is_none(), "{code:?}");
    let info = r.unwrap().network.unwrap();
    assert_eq!(info.extended_pan_id, epid);
    assert_eq!(info.pan_id, PanId(0x1A62));
    assert_eq!(info.trust_center, ExtendedAddress(0x00DD_0000_0000_0001));
    assert_eq!(info.device_type, DeviceType::Router);
    assert!(w.nodes[r1].0.stack.is_operating());

    // A second router is provisioned out of band with the full parameter
    // set and is on the network at once: the coordinator hears its
    // Device_annce.
    let router = Router::new(ExtendedAddress(0x00DD_0000_0000_0003))
        .build::<SoftwareAes, _, _>(TestRng::seed(3), MemoryStorage::new());
    let r2 = w.add(router);
    let mut zvd_r2 = Commissioning::new(Level::Provisioning, false);
    let n = JoinNetwork {
        method: JoiningMethod::OutOfBand,
        extended_pan_id: Some(epid),
        pan_id: Some(PanId(0x1A62)),
        channels: Some(mask),
        network_key: Some(nwk_key),
        link_key: None,
        nwk_address: Some(ShortAddress(0x3344)),
        trust_center: Some(ExtendedAddress(0x00DD_0000_0000_0001)),
        update_id: Some(0),
        key_sequence: Some(0),
        admin_key: None,
    }
    .encode(&mut buf)
    .unwrap();
    assert_eq!(
        zvd_r2.write(&mut w.nodes[r2].0, Characteristic::JoinNetwork, &buf[..n]),
        Access::Ok
    );
    assert!(w.run_until(Duration::from_secs(10), |w| {
        direct_done(w, r2, Domain::JoinNetwork).is_some()
    }));
    let note = report(&mut w, r2, &mut zvd_r2, Domain::JoinNetwork);
    let (r, _) = decode_status(&note).unwrap();
    assert_eq!(
        r.unwrap().network.unwrap().nwk_address,
        ShortAddress(0x3344)
    );
    assert!(
        w.run_until(Duration::from_secs(10), |w| w.nodes[c].2.iter().any(
            |e| matches!(
                e,
                Event::Stack(StackEvent::DeviceAnnounce {
                    ieee: ExtendedAddress(0x00DD_0000_0000_0003),
                    short: ShortAddress(0x3344),
                    ..
                })
            )
        ))
    );

    // Leave Network needs admin access on a provisioned ZDD.
    assert_eq!(
        zvd_r.write(&mut w.nodes[r1].0, Characteristic::LeaveNetwork, &[0, 0]),
        Access::Unauthorized
    );
    let mut admin_r = Commissioning::new(Level::Admin, true);
    let leave = LeaveNetwork {
        remove_children: false,
        rejoin: false,
    }
    .encode();
    assert_eq!(
        admin_r.write(&mut w.nodes[r1].0, Characteristic::LeaveNetwork, &leave),
        Access::Ok
    );
    assert!(w.run_until(Duration::from_secs(30), |w| {
        direct_done(w, r1, Domain::LeaveNetwork).is_some()
    }));
    let note = report(&mut w, r1, &mut admin_r, Domain::LeaveNetwork);
    let (r, code) = decode_status(&note).unwrap();
    assert_eq!(code, None);
    assert_eq!(r.unwrap().status.joined, JoinedStatus::NotCommissioned);
    assert_eq!(direct_done(&w, r1, Domain::LeaveNetwork), None);
}
