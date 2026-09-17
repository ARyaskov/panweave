//! Shared virtual-network harness for the runtime tests.

#![allow(
    dead_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use panweave_mac::radio::{RxMetadata, TxResult};
use panweave_mac::service::MacAction;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_storage::MemoryStorage;
use panweave_testkit::{TestRng, VirtualClock, VirtualMedium};
use panweave_types::time::Duration;
use panweave_types::{ExtendedAddress, Key128};
use panweave_zcl::Role;
use panweave_zcl::clusters::on_off;
use panweave_zcl::frame::ZclStatus;

pub type Node = Stack<SoftwareAes, TestRng, MemoryStorage<32, 64>>;

pub const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
pub const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
pub const ED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
pub const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
pub const SED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0004);

pub struct Sim {
    pub medium: VirtualMedium,
    pub clock: VirtualClock,
    pub nodes: Vec<(Node, usize)>,
    pub events: Vec<Vec<StackEvent>>,
    /// Application state: the end device applies On/Off commands.
    pub on_off_state: Vec<bool>,
}

impl Sim {
    pub fn new() -> Self {
        Sim {
            medium: VirtualMedium::new(),
            clock: VirtualClock::new(),
            nodes: Vec::new(),
            events: Vec::new(),
            on_off_state: Vec::new(),
        }
    }

    pub fn add(&mut self, mut stack: Node) -> usize {
        let radio = self.medium.add_radio();
        stack.poll(self.clock.now());
        self.nodes.push((stack, radio));
        self.events.push(Vec::new());
        self.on_off_state.push(false);
        self.nodes.len() - 1
    }

    /// Drains radio actions and events of every node until nothing moves.
    pub fn settle(&mut self) {
        loop {
            let mut progressed = false;
            for i in 0..self.nodes.len() {
                while let Some(a) = self.nodes[i].0.next_radio_action() {
                    progressed = true;
                    match a {
                        MacAction::Transmit { frame, .. } => {
                            let radio = self.nodes[i].1;
                            if std::env::var("PW_TRACE").is_ok() {
                                eprintln!(
                                    "t={} node{i} tx {:02x?}",
                                    self.clock.now().as_millis(),
                                    &frame[..]
                                );
                            }
                            let (air, targets) = self.medium.transmit(radio, &frame);
                            if let Some(air) = air {
                                for t in targets {
                                    let j = self.nodes.iter().position(|(_, r)| *r == t).unwrap();
                                    let meta = RxMetadata {
                                        lqi: 200,
                                        rssi_dbm: -40,
                                        timestamp_us: None,
                                        acked_by_hardware: false,
                                        channel: Some(air.channel),
                                    };
                                    self.nodes[j].0.on_radio_frame(&air.bytes, meta);
                                }
                            }
                            self.nodes[i].0.on_tx_complete(Ok(TxResult {
                                acked: false,
                                frame_pending: false,
                                timestamp_us: None,
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
                    progressed = true;
                    self.handle_app_event(i, &e);
                    self.events[i].push(e);
                }
            }
            if !progressed {
                break;
            }
        }
    }

    /// Minimal application: execute On/Off commands on endpoint 1.
    fn handle_app_event(&mut self, i: usize, e: &StackEvent) {
        if let StackEvent::ZclCommand(f) = e
            && f.origin.cluster == on_off::ID
        {
            let stack = &mut self.nodes[i].0;
            let status = match stack
                .zcl
                .cluster_mut(f.origin.endpoint, on_off::ID, Role::Server)
            {
                Some(c) => match on_off::apply(c, f.origin.header.command) {
                    Some(state) => {
                        self.on_off_state[i] = state;
                        ZclStatus::Success
                    }
                    None => ZclStatus::UnsupportedClusterCommand,
                },
                None => ZclStatus::UnsupportedCluster,
            };
            let _ = stack.zcl.default_response(&f.origin, status);
            stack.flush();
        }
    }

    /// Advances virtual time to the next deadline (at most `max`) and
    /// polls everything.
    pub fn step(&mut self, max: Duration) {
        self.settle();
        let now = self.clock.now();
        let next = self
            .nodes
            .iter()
            .filter_map(|(n, _)| n.next_deadline())
            .min_by_key(|t| t.as_millis())
            .map_or(now.saturating_add(max), |t| {
                if t.as_millis() <= now.as_millis() {
                    now.saturating_add(Duration::from_millis(1))
                } else {
                    t
                }
            });
        let limit = now.saturating_add(max);
        let target = if next.as_millis() > limit.as_millis() {
            limit
        } else {
            next
        };
        self.clock.advance_to(target);
        for (n, _) in &mut self.nodes {
            n.poll(target);
        }
        self.settle();
    }

    /// Runs until `pred` holds on the accumulated events or `timeout`
    /// elapses.
    pub fn run_until(&mut self, timeout: Duration, mut pred: impl FnMut(&Sim) -> bool) -> bool {
        let end = self.clock.now().saturating_add(timeout);
        loop {
            if pred(self) {
                return true;
            }
            if self.clock.now().as_millis() >= end.as_millis() {
                return false;
            }
            self.step(Duration::from_millis(250));
        }
    }

    pub fn events(&self, i: usize) -> &[StackEvent] {
        &self.events[i]
    }

    pub fn take_events(&mut self, i: usize) -> Vec<StackEvent> {
        std::mem::take(&mut self.events[i])
    }
}
