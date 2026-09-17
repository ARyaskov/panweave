//! The facade end to end: a coordinator and a light switch built with the
//! `Coordinator` / `EndDevice` builders and library endpoints, driven by
//! the plain sans-I/O loop an integrator writes (radio actions in, frames
//! out, `poll` at deadlines) over the testkit's virtual medium.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave::bdb::Outcome;
use panweave::endpoints;
use panweave::mac::radio::{RxMetadata, TxResult};
use panweave::mac::service::MacAction;
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::storage::MemoryStorage;
use panweave::testkit::{TestRng, VirtualClock, VirtualMedium};
use panweave::types::time::Duration;
use panweave::types::{Endpoint, ExtendedAddress};
use panweave::{Coordinator, EndDevice, Event, Node};

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

fn outcome(w: &World, i: usize, f: impl Fn(&Outcome) -> bool) -> bool {
    w.nodes[i]
        .2
        .iter()
        .any(|e| matches!(e, Event::Commissioning(o) if f(o)))
}

#[test]
fn builders_form_join_and_bind() {
    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };

    let mut coord = Coordinator::new(ExtendedAddress(0x00DD_0000_0000_0001))
        .identity(b"Panweave", b"Bridge")
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    let (d, ep) = endpoints::on_off_light(Endpoint(1)).unwrap();
    coord.add_endpoint(d, ep).unwrap();
    let c = w.add(coord);

    let mut switch = EndDevice::new(ExtendedAddress(0x00DD_0000_0000_0002))
        .identity(b"Panweave", b"Switch")
        .build::<SoftwareAes, _, _>(TestRng::seed(2), MemoryStorage::new());
    let (d, ep) = endpoints::on_off_light_switch(Endpoint(2)).unwrap();
    switch.add_endpoint(d, ep).unwrap();
    let s = w.add(switch);

    w.nodes[c].0.form_network().unwrap();
    assert!(
        w.run_until(Duration::from_secs(30), |w| outcome(w, c, |o| *o
            == Outcome::Formation(Ok(()))))
    );
    w.nodes[c].0.open_network().unwrap();

    w.nodes[s].0.steer().unwrap();
    assert!(
        w.run_until(Duration::from_secs(120), |w| outcome(w, s, |o| *o
            == Outcome::Steering(Ok(())))),
        "{:?}",
        w.nodes[s].2
    );
    assert!(w.nodes[s].0.bdb.is_on_network());
    assert!(
        w.nodes[s]
            .2
            .iter()
            .any(|e| matches!(e, Event::Stack(StackEvent::Joined { rejoin: false, .. })))
    );

    // The coordinator's light identifies; the switch binds to it.
    w.nodes[c].0.find_and_bind_target(Endpoint(1)).unwrap();
    w.nodes[s]
        .0
        .find_and_bind_initiator(Endpoint(2), None, &[])
        .unwrap();
    assert!(
        w.run_until(Duration::from_secs(30), |w| outcome(w, s, |o| matches!(
            o,
            Outcome::FindingBindingInitiator {
                bindings: 1,
                result: Ok(()),
                ..
            }
        ))),
        "{:?}",
        w.nodes[s].2
    );
    assert_eq!(w.nodes[s].0.stack.aps.bindings.len(), 1);

    // Reboot the switch from its storage: the initialization procedure
    // rejoins without commissioning.
    let storage = w.nodes[s].0.stack.storage.clone();
    let mut again = EndDevice::new(ExtendedAddress(0x00DD_0000_0000_0002))
        .build::<SoftwareAes, _, _>(TestRng::seed(3), MemoryStorage::new());
    again.stack.storage = storage;
    let (d, ep) = endpoints::on_off_light_switch(Endpoint(2)).unwrap();
    again.add_endpoint(d, ep).unwrap();
    again.poll(w.clock.now());
    assert_eq!(
        again.initialize().unwrap(),
        panweave::runtime::Restored::OnNetwork
    );
    let old_short = w.nodes[s].0.stack.short_address();
    let r = w.nodes[s].1;
    for j in 0..w.nodes.len() {
        w.medium.block(r, w.nodes[j].1);
    }
    let s2 = w.add(again);
    assert!(
        w.run_until(Duration::from_secs(60), |w| outcome(w, s2, |o| *o
            == Outcome::Rejoin(Ok(())))),
        "{:?}",
        w.nodes[s2].2
    );
    assert_eq!(w.nodes[s2].0.stack.short_address(), old_short);
    assert_eq!(w.nodes[s2].0.stack.aps.bindings.len(), 1);
}
