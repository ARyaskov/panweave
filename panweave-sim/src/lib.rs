//! Deterministic multi-node simulator: full [`Stack`]s on a virtual
//! radio medium with virtual time, optional PCAP capture and scripted
//! link failures. Used by the milestone tests and the `panweave-cli`
//! `sim` command.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

use std::any::Any;
use std::io::Write;

use panweave_bdb::{Bdb, Config as BdbConfig, Outcome};
use panweave_mac::radio::{RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacServiceConfig};
use panweave_pcap::PcapWriter;
use panweave_runtime::{Stack, StackConfig, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_storage::MemoryStorage;
use panweave_testkit::{TestRng, VirtualClock, VirtualMedium};
use panweave_types::Channel;
use panweave_types::time::{Duration, Instant};
use panweave_zcl::frame::ZclStatus;

/// The stack type simulated.
pub type SimStack = Stack<SoftwareAes, TestRng, MemoryStorage<64, 128>>;

/// Application behaviour attached to a simulated node.
pub trait App: Any {
    /// Called for every stack event before it is recorded.
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent);
    /// Called after the stack was polled at `now`.
    fn on_poll(&mut self, _stack: &mut SimStack, _now: Instant) {}
    /// Earliest time the application wants to be polled.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }
}

/// Default application: mirrors the On/Off servers executed by the
/// stack (a lamp driver would switch the load here) and answers any
/// other cluster-specific command with UNSUPPORTED_CLUSTER_COMMAND.
#[derive(Debug, Default)]
pub struct OnOffApp {
    /// Last state per endpoint number.
    pub state: Vec<(u8, bool)>,
}

impl App for OnOffApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        match event {
            StackEvent::OnOff { endpoint, on } => {
                match self.state.iter_mut().find(|(e, _)| *e == endpoint.0) {
                    Some(e) => e.1 = *on,
                    None => self.state.push((endpoint.0, *on)),
                }
            }
            StackEvent::ZclCommand(f) => {
                let _ = stack
                    .zcl
                    .default_response(&f.origin, ZclStatus::UnsupportedClusterCommand);
                stack.flush();
            }
            _ => {}
        }
    }
}

/// [`OnOffApp`] plus a BDB 3.1 commissioning machine: stack events are
/// translated for the machine and every finished procedure is recorded
/// in `outcomes`.
pub struct BdbApp {
    /// The On/Off behaviour.
    pub on_off: OnOffApp,
    /// The commissioning machine.
    pub bdb: Bdb,
    /// Finished procedures, in order.
    pub outcomes: Vec<Outcome>,
}

impl BdbApp {
    /// New application with `config`, not on a network.
    pub fn new(config: BdbConfig) -> Self {
        BdbApp {
            on_off: OnOffApp::default(),
            bdb: Bdb::new(config, false),
            outcomes: Vec::new(),
        }
    }
}

impl App for BdbApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        self.on_off.on_event(stack, event);
        if let Some(e) = SimStack::bdb_event(event)
            && let Some(o) = self.bdb.on_event(stack, &e)
        {
            self.outcomes.push(o);
        }
        stack.flush();
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some(o) = self.bdb.poll(stack, now) {
            self.outcomes.push(o);
        }
        stack.flush();
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.bdb.next_deadline()
    }
}

/// A simulated node.
pub struct SimNode {
    /// The stack.
    pub stack: SimStack,
    /// Radio index on the medium.
    pub radio: usize,
    /// Recorded events.
    pub events: Vec<StackEvent>,
    /// Application.
    pub app: Box<dyn App>,
    /// Human-readable name for traces.
    pub name: String,
}

/// One trace line.
#[derive(Clone, Debug)]
pub struct TraceEntry {
    /// Virtual time.
    pub at: Instant,
    /// Transmitting node index.
    pub node: usize,
    /// Frame bytes.
    pub frame: Vec<u8>,
    /// Receiving node indices.
    pub delivered_to: Vec<usize>,
}

/// The simulator.
pub struct Simulator {
    /// The medium.
    pub medium: VirtualMedium,
    /// The clock.
    pub clock: VirtualClock,
    nodes: Vec<SimNode>,
    pcap: Option<PcapWriter<Box<dyn Write>>>,
    /// Keep an in-memory trace of transmitted frames.
    pub trace_enabled: bool,
    /// The trace.
    pub trace: Vec<TraceEntry>,
    /// Frames transmitted.
    pub frames: u64,
    /// Energy detect level reported per channel (index = channel number).
    pub channel_energy: [u8; 27],
    /// Radio used by [`Simulator::inject`] (a device without a stack,
    /// e.g. a Green Power Device).
    phantom: Option<usize>,
}

impl Default for Simulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Simulator {
    /// Empty simulator.
    pub fn new() -> Self {
        Simulator {
            medium: VirtualMedium::new(),
            clock: VirtualClock::new(),
            nodes: Vec::new(),
            pcap: None,
            trace_enabled: false,
            trace: Vec::new(),
            frames: 0,
            channel_energy: [0; 27],
            phantom: None,
        }
    }

    /// Transmits a raw PHY frame (without FCS) from a stack-less radio on
    /// the current channel, e.g. a Green Power Device's GPDF; returns the
    /// nodes that received it.
    pub fn inject(&mut self, bytes: &[u8]) -> Vec<usize> {
        let radio = match self.phantom {
            Some(r) => r,
            None => {
                let r = self.medium.add_radio();
                self.phantom = Some(r);
                r
            }
        };
        let now = self.clock.now();
        self.frames += 1;
        let (air, targets) = self.medium.transmit(radio, bytes);
        let mut delivered = Vec::new();
        if let Some(air) = air {
            for t in targets {
                if let Some(j) = self.nodes.iter().position(|n| n.radio == t) {
                    let meta = RxMetadata {
                        lqi: 180,
                        rssi_dbm: -55,
                        timestamp_us: Some(now.as_millis() * 1000),
                        acked_by_hardware: false,
                        channel: Some(air.channel),
                    };
                    self.nodes[j].stack.on_radio_frame(&air.bytes, meta);
                    delivered.push(j);
                }
            }
        }
        self.settle();
        delivered
    }

    /// Captures every transmitted frame into a pcap stream.
    pub fn capture(&mut self, out: Box<dyn Write>) -> std::io::Result<()> {
        self.pcap = Some(PcapWriter::new(out)?);
        Ok(())
    }

    /// Adds a node built from `config` with a deterministic seed and the
    /// default On/Off application.
    pub fn add_node(&mut self, name: &str, config: StackConfig, seed: u64) -> usize {
        self.add_node_with_app(name, config, seed, Box::new(OnOffApp::default()))
    }

    /// Adds a node with a custom application.
    pub fn add_node_with_app(
        &mut self,
        name: &str,
        config: StackConfig,
        seed: u64,
        app: Box<dyn App>,
    ) -> usize {
        let stack = SimStack::new(
            config,
            MacServiceConfig::default(),
            TestRng::seed(seed),
            MemoryStorage::new(),
        );
        self.add_stack(name, stack, app)
    }

    /// Adds a prepared stack.
    pub fn add_stack(&mut self, name: &str, mut stack: SimStack, app: Box<dyn App>) -> usize {
        let radio = self.medium.add_radio();
        stack.poll(self.clock.now());
        self.nodes.push(SimNode {
            stack,
            radio,
            events: Vec::new(),
            app,
            name: name.to_string(),
        });
        self.nodes.len() - 1
    }

    /// The node.
    pub fn node(&self, i: usize) -> &SimNode {
        &self.nodes[i]
    }

    /// The node, mutably.
    pub fn node_mut(&mut self, i: usize) -> &mut SimNode {
        &mut self.nodes[i]
    }

    /// Read access to the stack of node `i`.
    pub fn stack_ref(&self, i: usize) -> &SimStack {
        &self.nodes[i].stack
    }

    /// The stack of node `i`.
    pub fn stack(&mut self, i: usize) -> &mut SimStack {
        &mut self.nodes[i].stack
    }

    /// The application of node `i` as its concrete type.
    pub fn app<T: App>(&self, i: usize) -> Option<&T> {
        let any: &dyn Any = &*self.nodes[i].app;
        any.downcast_ref::<T>()
    }

    /// The stack and application of node `i` (application as its
    /// concrete type).
    pub fn stack_and_app<T: App>(&mut self, i: usize) -> Option<(&mut SimStack, &mut T)> {
        let node = &mut self.nodes[i];
        let any: &mut dyn Any = &mut *node.app;
        any.downcast_mut::<T>().map(|a| (&mut node.stack, a))
    }

    /// Recorded events of node `i`.
    pub fn events(&self, i: usize) -> &[StackEvent] {
        &self.nodes[i].events
    }

    /// Takes the recorded events of node `i`.
    pub fn take_events(&mut self, i: usize) -> Vec<StackEvent> {
        std::mem::take(&mut self.nodes[i].events)
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True when no nodes exist.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Disconnects node `i` from every other node (crash / power loss).
    pub fn isolate(&mut self, i: usize) {
        let r = self.nodes[i].radio;
        for j in 0..self.nodes.len() {
            if j != i {
                self.medium.block(r, self.nodes[j].radio);
            }
        }
    }

    /// Blocks the link between two nodes.
    pub fn block(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.nodes[a].radio, self.nodes[b].radio);
        self.medium.block(ra, rb);
    }

    /// Restores the link between two nodes.
    pub fn unblock(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.nodes[a].radio, self.nodes[b].radio);
        self.medium.unblock(ra, rb);
    }

    /// Drains radio actions and events of every node until nothing moves.
    pub fn settle(&mut self) {
        loop {
            let mut progressed = false;
            for i in 0..self.nodes.len() {
                while let Some(a) = self.nodes[i].stack.next_radio_action() {
                    progressed = true;
                    self.perform(i, a);
                }
                while let Some(e) = self.nodes[i].stack.next_event() {
                    progressed = true;
                    let node = &mut self.nodes[i];
                    node.app.on_event(&mut node.stack, &e);
                    node.events.push(e);
                }
            }
            if !progressed {
                break;
            }
        }
    }

    fn perform(&mut self, i: usize, action: MacAction) {
        match action {
            MacAction::Transmit { frame, .. } => {
                let radio = self.nodes[i].radio;
                let now = self.clock.now();
                self.frames += 1;
                if let Some(p) = self.pcap.as_mut() {
                    let _ = p.write_frame(now.as_millis() * 1000, &frame);
                }
                let (air, targets) = self.medium.transmit(radio, &frame);
                let mut delivered = Vec::new();
                if let Some(air) = air {
                    for t in targets {
                        if let Some(j) = self.nodes.iter().position(|n| n.radio == t) {
                            let meta = RxMetadata {
                                lqi: self.medium.radio(t).map_or(200, |r| r.lqi),
                                rssi_dbm: -40,
                                timestamp_us: Some(now.as_millis() * 1000),
                                acked_by_hardware: false,
                                channel: Some(air.channel),
                            };
                            self.nodes[j].stack.on_radio_frame(&air.bytes, meta);
                            delivered.push(j);
                        }
                    }
                }
                if self.trace_enabled {
                    self.trace.push(TraceEntry {
                        at: now,
                        node: i,
                        frame: frame.to_vec(),
                        delivered_to: delivered,
                    });
                }
                self.nodes[i].stack.on_tx_complete(Ok(TxResult {
                    acked: false,
                    frame_pending: false,
                    timestamp_us: Some(now.as_millis() * 1000),
                }));
            }
            MacAction::SetChannel { channel, .. } => {
                let radio = self.nodes[i].radio;
                self.medium.set_channel(radio, channel);
            }
            MacAction::EnergyDetect { .. } => {
                // The channel's configured energy (0 unless the test set
                // `channel_energy`).
                let radio = self.nodes[i].radio;
                let channel = self
                    .medium
                    .radio(radio)
                    .map_or(Channel::DEFAULT_2_4GHZ, |r| r.channel);
                let level = self
                    .channel_energy
                    .get(usize::from(channel.raw()))
                    .copied()
                    .unwrap_or(0);
                self.nodes[i].stack.on_energy_result(level);
            }
            MacAction::Configure(_) | MacAction::SetPending { .. } => {}
        }
    }

    /// Advances virtual time to the earliest deadline (at most `max`) and
    /// polls every node.
    pub fn step(&mut self, max: Duration) {
        self.settle();
        let now = self.clock.now();
        let next = self
            .nodes
            .iter()
            .flat_map(|n| [n.stack.next_deadline(), n.app.next_deadline()])
            .flatten()
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
        for n in &mut self.nodes {
            n.stack.poll(target);
            n.app.on_poll(&mut n.stack, target);
        }
        self.settle();
    }

    /// Runs for `d` of virtual time.
    pub fn run_for(&mut self, d: Duration) {
        let end = self.clock.now().saturating_add(d);
        while self.clock.now().as_millis() < end.as_millis() {
            let remaining = end.saturating_duration_since(self.clock.now());
            self.step(remaining.min(Duration::from_millis(250)));
        }
    }

    /// Runs until `pred` holds or `timeout` elapses; returns whether it
    /// held.
    pub fn run_until(
        &mut self,
        timeout: Duration,
        mut pred: impl FnMut(&Simulator) -> bool,
    ) -> bool {
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

    /// Finishes the pcap capture, if any.
    pub fn finish_capture(&mut self) -> std::io::Result<()> {
        if let Some(p) = self.pcap.take() {
            p.finish()?;
        }
        Ok(())
    }

    /// Prints the trace with frame summaries.
    pub fn dump_trace(&self, out: &mut dyn Write) -> std::io::Result<()> {
        for t in &self.trace {
            writeln!(
                out,
                "{:>8} ms {:<12} -> {:?}: {}",
                t.at.as_millis(),
                self.nodes[t.node].name,
                t.delivered_to
                    .iter()
                    .map(|j| self.nodes[*j].name.as_str())
                    .collect::<Vec<_>>(),
                panweave_pcap::summarize(&t.frame)
            )?;
        }
        Ok(())
    }
}
