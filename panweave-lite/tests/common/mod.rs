//! Lite sensors on the simulator's medium with the full Panweave hub or
//! coordinator. The hub harness follows `panweave-hub/tests/common`.

#![allow(
    dead_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use panweave_hub::protocol::{Event, Request, Response};
use panweave_hub::{Hub, HubConfig, hub_endpoint};
use panweave_lite::sensor::{Inputs, SensorKind};
use panweave_lite::{LiteConfig, LiteDevice, LiteEvent};
use panweave_mac::radio::{RadioError, RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacServiceConfig};
use panweave_runtime::{StackConfig, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_sim::{App, Device, SimStack, Simulator};
use panweave_storage::{Key, Kind, MemoryStorage, Storage, StorageError};
use panweave_testkit::TestRng;
use panweave_types::time::{Duration, Instant};
use panweave_types::{Endpoint, ExtendedAddress, LogicalDeviceType};

pub const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x3C; 16]);
pub const HUB: u64 = 0x00AA_0000_0000_0001;
pub const LEAK: u64 = 0x00AA_0000_0000_0102;
pub const DOOR: u64 = 0x00AA_0000_0000_0103;

pub type Lite = LiteDevice<SoftwareAes, TestRng, LiteStore>;

/// Write faults of a [`LiteStore`].
pub const FAULT_NONE: u8 = 0;
/// Every write fails with an I/O error.
pub const FAULT_IO: u8 = 1;
/// The next write is cut by a power loss: nothing of it reaches the
/// medium and every later write fails until the fault is cleared.
pub const FAULT_POWER_CUT: u8 = 2;

/// The sensor's flash, shared across "reboots": a power cycle builds a
/// new device over the same records.
#[derive(Clone, Debug, Default)]
pub struct LiteStore {
    inner: Arc<Mutex<MemoryStorage<24, 160>>>,
    fault: Arc<AtomicU8>,
}

impl LiteStore {
    pub fn set_fault(&self, f: u8) {
        self.fault.store(f, Ordering::SeqCst);
    }

    pub fn writes(&self) -> u32 {
        self.inner.lock().unwrap().writes
    }

    pub fn has(&self, key: Key) -> bool {
        let mut buf = [0u8; 160];
        self.inner
            .lock()
            .unwrap()
            .load(key, &mut buf)
            .unwrap()
            .is_some()
    }

    fn check(&self) -> Result<(), StorageError> {
        match self.fault.load(Ordering::SeqCst) {
            FAULT_NONE => Ok(()),
            _ => Err(StorageError::Io),
        }
    }
}

impl Storage for LiteStore {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        self.check()?;
        self.inner.lock().unwrap().store(key, data)
    }

    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        self.inner.lock().unwrap().load(key, buf)
    }

    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        self.check()?;
        self.inner.lock().unwrap().erase(key)
    }

    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        self.check()?;
        self.inner.lock().unwrap().erase_kind(kind)
    }
}

/// A Lite device on the simulator, with its events recorded.
pub struct LiteNode {
    pub dev: Box<Lite>,
    pub events: Vec<LiteEvent>,
    pub config: LiteConfig,
    pub store: LiteStore,
    /// Unpowered: frames are ignored and nothing is sent.
    pub powered: bool,
    seed: u64,
}

impl LiteNode {
    pub fn new(config: LiteConfig, store: LiteStore, seed: u64) -> Self {
        let dev = Box::new(Lite::new(&config, TestRng::seed(seed), store.clone()).unwrap());
        LiteNode {
            dev,
            events: Vec::new(),
            config,
            store,
            powered: true,
            seed,
        }
    }

    /// Power loss and restart: RAM is gone, the flash stays.
    pub fn power_cycle(&mut self, inputs: Inputs, now: Instant) {
        self.seed += 1000;
        *self.dev = Lite::new(&self.config, TestRng::seed(self.seed), self.store.clone()).unwrap();
        self.dev.poll(now);
        self.powered = true;
        self.dev.initialize(inputs).unwrap();
    }
}

impl Device for LiteNode {
    fn next_radio_action(&mut self) -> Option<MacAction> {
        if !self.powered {
            return None;
        }
        self.dev.next_radio_action()
    }

    fn on_radio_frame(&mut self, bytes: &[u8], meta: RxMetadata) {
        if self.powered {
            self.dev.on_radio_frame(bytes, meta);
        }
    }

    fn on_tx_complete(&mut self, result: Result<TxResult, RadioError>) {
        self.dev.on_tx_complete(result);
    }

    fn on_energy_result(&mut self, level: u8) {
        self.dev.on_energy_result(level);
    }

    fn poll(&mut self, now: Instant) {
        if self.powered {
            self.dev.poll(now);
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        if self.powered {
            self.dev.next_deadline()
        } else {
            None
        }
    }

    fn drain_events(&mut self) -> bool {
        let mut any = false;
        while let Some(e) = self.dev.next_event() {
            any = true;
            self.events.push(e);
        }
        any
    }
}

/// A Lite sensor configuration polling every second (fast tests).
pub fn sensor_config(ieee: u64, kind: SensorKind, model: &'static [u8]) -> LiteConfig {
    let mut c = LiteConfig::new(ExtendedAddress(ieee), kind);
    c.poll_interval = Duration::from_millis(1000);
    c.manufacturer = b"Lite Sim";
    c.model = model;
    c.sensor.retry_first = Duration::from_millis(500);
    c.sensor.retry_max = Duration::from_secs(8);
    c
}

pub fn lite(sim: &Simulator, d: usize) -> &LiteNode {
    sim.device::<LiteNode>(d).unwrap()
}

pub fn lite_mut(sim: &mut Simulator, d: usize) -> &mut LiteNode {
    sim.device_mut::<LiteNode>(d).unwrap()
}

/// Sets the sensor inputs and moves the frames.
pub fn set_inputs(sim: &mut Simulator, d: usize, inputs: Inputs) {
    lite_mut(sim, d).dev.set_inputs(inputs);
    sim.settle();
}

pub fn wet() -> Inputs {
    Inputs {
        alarm: true,
        ..Inputs::default()
    }
}

pub fn dry() -> Inputs {
    Inputs::default()
}

// ---------------------------------------------------------------------
// The hub.
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct HubStore {
    inner: MemoryStorage<40, 512>,
}

impl Storage for HubStore {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        self.inner.store(key, data)
    }

    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        self.inner.load(key, buf)
    }

    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        self.inner.erase(key)
    }

    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        self.inner.erase_kind(kind)
    }
}

pub struct HubApp {
    pub hub: Hub<HubStore>,
    pub events: Vec<Event>,
}

impl HubApp {
    fn drain(&mut self) {
        while let Some(e) = self.hub.next_event() {
            self.events.push(e);
        }
    }
}

impl App for HubApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        self.hub.on_stack_event(stack, event);
        stack.flush();
        self.drain();
    }

    fn on_poll(&mut self, stack: &mut SimStack, _now: Instant) {
        self.hub.poll(stack);
        stack.flush();
        self.drain();
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.hub.next_deadline()
    }
}

/// A simulator with the hub on a formed network open for joining.
pub fn hub_network() -> (Simulator, usize) {
    let mut sim = Simulator::new();
    let cfg = StackConfig::new(LogicalDeviceType::Coordinator, ExtendedAddress(HUB));
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(1),
        MemoryStorage::new(),
    );
    let (d, ep) = hub_endpoint(Endpoint(1)).unwrap();
    s.add_endpoint(d, ep).unwrap();
    let app = HubApp {
        hub: Hub::new(
            HubConfig {
                firmware: "test",
                ..HubConfig::default()
            },
            HubStore::default(),
        ),
        events: Vec::new(),
    };
    let c = sim.add_stack("hub", s, Box::new(app));
    {
        let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.attach(stack);
    }
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    assert_eq!(
        request(&mut sim, c, &Request::PermitJoin { seconds: 240 }),
        Response::Done
    );
    (sim, c)
}

pub fn hub_events(sim: &Simulator, c: usize) -> &[Event] {
    &sim.app::<HubApp>(c).unwrap().events
}

pub fn take_hub_events(sim: &mut Simulator, c: usize) -> Vec<Event> {
    let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    core::mem::take(&mut app.events)
}

pub fn request(sim: &mut Simulator, c: usize, r: &Request) -> Response {
    let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
    let response = app.hub.handle(stack, r);
    stack.flush();
    app.drain();
    response
}

/// Runs until a hub event matching `pred` arrives.
pub fn wait_hub(sim: &mut Simulator, c: usize, secs: u64, pred: impl Fn(&Event) -> bool) {
    assert!(
        sim.run_until(Duration::from_secs(secs), |x| hub_events(x, c)
            .iter()
            .any(&pred)),
        "hub event not seen: {:?}",
        hub_events(sim, c)
    );
}

/// Adds a Lite sensor, starts commissioning and waits for the hub's
/// interview; returns the device index.
pub fn join_hub(sim: &mut Simulator, c: usize, name: &str, config: LiteConfig) -> usize {
    let ieee = config.ieee.0;
    let store = LiteStore::default();
    let mut node = LiteNode::new(config, store, ieee);
    node.dev.initialize(Inputs::default()).unwrap();
    let d = sim.add_device(name, Box::new(node));
    lite_mut(sim, d).dev.start_commissioning().unwrap();
    assert!(
        sim.run_until(Duration::from_secs(240), |x| {
            hub_events(x, c)
                .iter()
                .any(|e| matches!(e, Event::DeviceInterviewCompleted { ieee: i, .. } if *i == ieee))
        }),
        "interview of {name} did not complete: hub {:?} lite {:?}",
        hub_events(sim, c),
        lite(sim, d).events
    );
    d
}

/// Runs until the sensor's zone status is acknowledged by the CIE.
pub fn wait_confirmed(sim: &mut Simulator, d: usize, secs: u64) {
    assert!(
        sim.run_until(Duration::from_secs(secs), |x| {
            lite(x, d).dev.delivery() == panweave_lite::Delivery::Confirmed
        }),
        "not confirmed: {:?}",
        lite(sim, d).events
    );
}
