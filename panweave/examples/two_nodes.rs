//! Two nodes on the testkit's virtual medium, driven by the sans-I/O
//! loop an integrator writes: radio actions out, frames in, `poll` at
//! deadlines. Run with `cargo run -p panweave --example two_nodes`.
//!
//! On real hardware the same loop feeds a radio driver instead of the
//! virtual medium; see `docs/radio-hal.md`.
#![allow(clippy::expect_used, clippy::indexing_slicing, missing_docs)]

use panweave::endpoints;
use panweave::mac::radio::{RxMetadata, TxResult};
use panweave::mac::service::MacAction;
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

fn main() {
    let mut w = World {
        medium: VirtualMedium::new(),
        clock: VirtualClock::new(),
        nodes: Vec::new(),
    };
    let mut coord = Coordinator::new(ExtendedAddress(0x00EE_0000_0000_0001))
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::<64, 128>::new());
    coord.stack.config.trust_center_policy.allow_joins = true;
    let (d, ep) = endpoints::on_off_light(Endpoint(1)).expect("light endpoint");
    coord.add_endpoint(d, ep).expect("endpoint");
    let c = w.add(coord);

    let mut switch = EndDevice::new(ExtendedAddress(0x00EE_0000_0000_0002))
        .build::<SoftwareAes, _, _>(TestRng::seed(2), MemoryStorage::<64, 128>::new());
    let (d, ep) = endpoints::on_off_light_switch(Endpoint(2)).expect("switch endpoint");
    switch.add_endpoint(d, ep).expect("endpoint");
    let s = w.add(switch);

    w.nodes[c].0.form_network().expect("formation started");
    w.run_until(Duration::from_secs(30), |w| !w.nodes[c].2.is_empty());
    w.nodes[c].0.open_network().expect("network opened");
    w.nodes[s].0.steer().expect("steering started");
    w.run_until(Duration::from_secs(120), |w| {
        w.nodes[s]
            .2
            .iter()
            .any(|e| matches!(e, Event::Commissioning(_)))
    });
    w.nodes[c]
        .0
        .find_and_bind_target(Endpoint(1))
        .expect("target");
    w.nodes[s]
        .0
        .find_and_bind_initiator(Endpoint(2), None, &[])
        .expect("initiator");
    w.run_until(Duration::from_secs(30), |w| {
        w.nodes[s]
            .2
            .iter()
            .filter(|e| matches!(e, Event::Commissioning(_)))
            .count()
            >= 2
    });
    for (name, i) in [("coordinator", c), ("switch", s)] {
        println!(
            "{name}: short address {}",
            w.nodes[i].0.stack.short_address()
        );
        for e in &w.nodes[i].2 {
            if let Event::Commissioning(o) = e {
                println!("  {o:?}");
            }
        }
    }
    println!("switch bindings: {}", w.nodes[s].0.stack.aps.bindings.len());
}
