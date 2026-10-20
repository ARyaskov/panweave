//! Simulated hub and devices for the hub's integration tests.

#![allow(
    dead_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_hub::protocol::{Event, Request, Response};
use panweave_hub::{Hub, HubConfig, hub_endpoint};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{App, OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
};
use panweave_zcl::clusters::ias_zone::{self, EnrollMode};
use panweave_zcl::clusters::{identify, level, on_off, power_configuration};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

pub const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x3C; 16]);
pub const HUB: u64 = 0x00AA_0000_0000_0001;
pub const LEAK: u64 = 0x00AA_0000_0000_0002;
pub const CONTACT: u64 = 0x00AA_0000_0000_0003;
pub const BULB: u64 = 0x00AA_0000_0000_0004;

/// Registry storage of the tests: enough records of the NOR flash
/// store's maximum size.
pub type HubStore = MemoryStorage<40, 512>;

/// The hub as a simulator application: stack events in, hub events
/// collected for the test to inspect.
pub struct HubApp {
    pub hub: Hub<HubStore>,
    pub events: Vec<Event>,
}

impl HubApp {
    pub fn new(storage: HubStore) -> Self {
        HubApp {
            hub: Hub::new(
                HubConfig {
                    firmware: "test",
                    ..HubConfig::default()
                },
                storage,
            ),
            events: Vec::new(),
        }
    }

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

/// The coordinator with the hub's endpoint.
pub fn hub_stack() -> SimStack {
    let cfg = StackConfig::new(LogicalDeviceType::Coordinator, ExtendedAddress(HUB));
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(1),
        MemoryStorage::new(),
    );
    let (d, ep) = hub_endpoint(Endpoint(1)).unwrap();
    s.add_endpoint(d, ep).unwrap();
    s
}

fn device_stack(
    ieee: u64,
    role: LogicalDeviceType,
    sleepy: bool,
    model: &'static [u8],
    seed: u64,
) -> SimStack {
    let mut cfg = StackConfig::new(role, ExtendedAddress(ieee));
    cfg.sleepy = sleepy;
    cfg.poll_interval = Duration::from_millis(1000);
    cfg.manufacturer_name = b"Sim Devices";
    cfg.model = model;
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    )
}

/// A battery IAS zone sensor (sleepy end device) of `zone_type`.
pub fn zone_sensor(
    ieee: u64,
    zone_type: u16,
    enroll: EnrollMode,
    model: &'static [u8],
) -> SimStack {
    let mut s = device_stack(ieee, LogicalDeviceType::EndDevice, true, model, ieee);
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(power_configuration::battery_server(30).unwrap())
        .unwrap();
    ep.add_instance(ias_zone::server(zone_type, 0x1234, enroll, None).unwrap())
        .unwrap();
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0402),
        0,
        &[
            ClusterId(0),
            power_configuration::ID,
            identify::ID,
            ias_zone::ID,
        ],
        &[],
    )
    .unwrap();
    s.add_endpoint(desc, ep).unwrap();
    s
}

/// A dimmable bulb (router).
pub fn bulb() -> SimStack {
    let mut s = device_stack(BULB, LogicalDeviceType::Router, false, b"bulb-sim", 4);
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    ep.add_instance(level::server(1, 254).unwrap()).unwrap();
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0101),
        1,
        &[ClusterId(0), identify::ID, on_off::ID, level::ID],
        &[],
    )
    .unwrap();
    s.add_endpoint(desc, ep).unwrap();
    s
}

/// A simulator with the hub on a formed, open network. Returns the hub's
/// node index.
pub fn network() -> (Simulator, usize) {
    let mut sim = Simulator::new();
    let c = sim.add_stack("hub", hub_stack(), Box::new(HubApp::new(HubStore::new())));
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
    assert!(
        hub_events(&sim, c)
            .iter()
            .any(|e| matches!(e, Event::NetworkStarted(_)))
    );
    let r = request(&mut sim, c, &Request::PermitJoin { seconds: 180 });
    assert_eq!(r, Response::Done);
    (sim, c)
}

/// Adds a device, joins it and waits for its interview to finish.
pub fn join(sim: &mut Simulator, c: usize, name: &str, stack: SimStack, ieee: u64) -> usize {
    let d = sim.add_stack(name, stack, Box::new(OnOffApp::default()));
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(180), |x| {
            hub_events(x, c)
                .iter()
                .any(|e| matches!(e, Event::DeviceInterviewCompleted { ieee: i, .. } if *i == ieee))
        }),
        "interview of {name} did not complete: {:?}",
        hub_events(sim, c)
    );
    d
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

/// Runs until an event matching `pred` arrives; returns it.
pub fn wait_event(
    sim: &mut Simulator,
    c: usize,
    secs: u64,
    pred: impl Fn(&Event) -> bool,
) -> Event {
    assert!(
        sim.run_until(Duration::from_secs(secs), |x| hub_events(x, c)
            .iter()
            .any(&pred)),
        "event not seen: {:?}",
        hub_events(sim, c)
    );
    hub_events(sim, c)
        .iter()
        .find(|e| pred(e))
        .cloned()
        .unwrap()
}
