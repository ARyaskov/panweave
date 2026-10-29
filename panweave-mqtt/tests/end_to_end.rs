//! The bridge on the hub engine: a simulated hub with a dimmable bulb and
//! a contact sensor, the bridge's requests answered by the hub and its
//! events fed back, MQTT publications collected.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

#[path = "../../panweave-hub/tests/common/mod.rs"]
mod common;

use common::*;
use panweave_hub::protocol::{Event, LightCommand, Request};
use panweave_hub::registry::zone_type;
use panweave_mqtt::bridge::device_id;
use panweave_mqtt::{Action, Bridge, Config, Publication};
use panweave_sim::Simulator;
use panweave_types::time::Duration;
use panweave_zcl::clusters::ias_zone::EnrollMode;
use serde_json::Value;

/// The bridge's host: requests go to the simulated hub, publications
/// are collected.
struct Host {
    sim: Simulator,
    c: usize,
    bridge: Bridge,
    now: u64,
    published: Vec<Publication>,
    requests: Vec<Request>,
    /// The bulb's simulator node.
    bulb: usize,
}

impl Host {
    fn new(sim: Simulator, c: usize, cfg: Config) -> Self {
        Host {
            sim,
            c,
            bridge: Bridge::new(cfg),
            now: 1,
            published: Vec::new(),
            requests: Vec::new(),
            bulb: usize::MAX,
        }
    }

    /// Carries out actions until none are left, feeding the hub's events.
    fn run(&mut self, mut actions: Vec<Action>) {
        loop {
            for e in take_hub_events(&mut self.sim, self.c) {
                actions.extend(self.bridge.on_event(e, self.now));
            }
            if actions.is_empty() {
                return;
            }
            for a in core::mem::take(&mut actions) {
                match a {
                    Action::Publish(p) => self.published.push(p),
                    Action::Request(r) => {
                        self.requests.push(r.clone());
                        let response = request(&mut self.sim, self.c, &r);
                        actions.extend(self.bridge.on_response(&r, response, self.now));
                    }
                }
            }
        }
    }

    fn start(&mut self) {
        let a = self.bridge.start(self.now);
        self.run(a);
    }

    fn mqtt(&mut self, topic: &str, payload: &str) {
        let a = self.bridge.on_mqtt(topic, payload.as_bytes(), self.now);
        self.run(a);
    }

    fn sim_for(&mut self, secs: u64) {
        self.sim.run_for(Duration::from_secs(secs));
        self.run(Vec::new());
    }

    fn tick(&mut self, now: u64) {
        self.now = now;
        let a = self.bridge.tick(now);
        self.run(a);
    }

    /// The last retained payload of `topic`, if any was published.
    fn retained(&self, topic: &str) -> Option<&[u8]> {
        self.published
            .iter()
            .rev()
            .find(|p| p.topic == topic && p.retain)
            .map(|p| p.payload.as_slice())
    }

    fn json(&self, topic: &str) -> Value {
        let body = self
            .retained(topic)
            .unwrap_or_else(|| panic!("nothing retained on {topic}"));
        serde_json::from_slice(body).unwrap()
    }
}

fn contact_sensor() -> panweave_sim::SimStack {
    zone_sensor(
        CONTACT,
        zone_type::CONTACT_SWITCH,
        EnrollMode::AutoRequest,
        b"contact-sim",
    )
}

/// A hub with the bulb and the contact sensor, interviewed.
fn host(cfg: Config) -> Host {
    let (mut sim, c) = network();
    let b = join(&mut sim, c, "bulb", bulb(), BULB);
    join(&mut sim, c, "contact", contact_sensor(), CONTACT);
    let mut h = Host::new(sim, c, cfg);
    h.bulb = b;
    h.start();
    h
}

fn config_topic(component: &str, ieee: u64, object: &str) -> String {
    format!(
        "homeassistant/{component}/panweave_{}/{object}/config",
        device_id(ieee)
    )
}

#[test]
fn devices_are_announced_to_home_assistant() {
    let h = host(Config::default());
    assert_eq!(h.retained("panweave/bridge/state"), Some(&b"online"[..]));
    assert_eq!(h.retained("panweave/bridge/permit_join"), Some(&b"ON"[..]));

    let light = h.json(&config_topic("light", BULB, "light"));
    assert_eq!(light["schema"], "json");
    assert_eq!(light["brightness"], true);
    assert_eq!(light["brightness_scale"], 100);
    assert_eq!(
        light["command_topic"],
        format!("panweave/{}/set", device_id(BULB))
    );
    assert_eq!(light["device"]["model"], "bulb-sim");
    assert_eq!(light["device"]["manufacturer"], "Sim Devices");
    assert_eq!(
        light["device"]["via_device"],
        format!("panweave_bridge_{}", device_id(HUB))
    );
    assert_eq!(light["availability_mode"], "all");

    let door = h.json(&config_topic("binary_sensor", CONTACT, "contact"));
    assert_eq!(door["device_class"], "door");
    assert_eq!(
        door["state_topic"],
        format!("panweave/{}", device_id(CONTACT))
    );
    let tamper = h.json(&config_topic("binary_sensor", CONTACT, "tamper"));
    assert_eq!(tamper["entity_category"], "diagnostic");
    // No light or switch for the sensor, no door for the bulb.
    assert!(
        h.retained(&config_topic("light", CONTACT, "light"))
            .is_none()
    );
    assert!(
        h.retained(&config_topic("switch", CONTACT, "switch"))
            .is_none()
    );
    assert!(
        h.retained(&config_topic("binary_sensor", BULB, "contact"))
            .is_none()
    );

    // Every state field is present; the sensor's door state was read in
    // the interview.
    let state = h.json(&format!("panweave/{}", device_id(CONTACT)));
    for field in [
        "state",
        "brightness",
        "open",
        "water_leak",
        "occupancy",
        "tamper",
        "battery_low",
        "battery",
        "temperature",
    ] {
        assert!(state.get(field).is_some(), "{field} missing: {state}");
    }
    assert!(state["open"].is_boolean(), "{state}");
    assert!(state["state"].is_null());
    for ieee in [BULB, CONTACT] {
        assert_eq!(
            h.retained(&format!("panweave/{}/availability", device_id(ieee))),
            Some(&b"online"[..])
        );
    }
    // The permit-join switch belongs to the hub's device.
    let permit = h.json(&format!(
        "homeassistant/switch/panweave_{}/permit_join/config",
        device_id(HUB)
    ));
    assert_eq!(
        permit["command_topic"],
        "panweave/bridge/request/permit_join"
    );
}

#[test]
fn a_light_command_reaches_the_bulb_and_its_state_comes_back() {
    let mut h = host(Config::default());
    let set = format!("panweave/{}/set", device_id(BULB));
    h.mqtt(&set, r#"{"state":"ON","brightness":40,"transition":0.5}"#);
    assert!(h.requests.contains(&Request::Light {
        ieee: BULB,
        endpoint: 0,
        command: LightCommand::SetBrightness {
            percent: 40,
            transition_ds: 5
        }
    }));
    h.sim_for(10);
    let state = h.json(&format!("panweave/{}", device_id(BULB)));
    assert_eq!(state["state"], "ON", "{state}");
    assert_eq!(state["brightness"], 40, "{state}");

    h.mqtt(&set, "OFF");
    h.sim_for(10);
    let state = h.json(&format!("panweave/{}", device_id(BULB)));
    assert_eq!(state["state"], "OFF", "{state}");

    // A command for a device the hub does not have is not forwarded.
    let before = h.requests.len();
    h.mqtt("panweave/0x00000000000000ff/set", "ON");
    assert_eq!(h.requests.len(), before);
    let log = h.published.last().unwrap();
    assert_eq!(log.topic, "panweave/bridge/log");
}

#[test]
fn home_assistant_restart_gets_everything_again() {
    let mut h = host(Config::default());
    let door = config_topic("binary_sensor", CONTACT, "contact");
    h.published.clear();
    h.mqtt("homeassistant/status", "online");
    assert!(h.retained(&door).is_some());
    assert!(h.retained(&config_topic("light", BULB, "light")).is_some());
    assert!(
        h.retained(&format!("panweave/{}", device_id(BULB)))
            .is_some()
    );
    // `offline` (Home Assistant stopping) changes nothing.
    h.published.clear();
    h.mqtt("homeassistant/status", "offline");
    assert!(h.published.is_empty());
}

#[test]
fn bridge_requests_open_the_network_and_remove_devices() {
    let mut h = host(Config::default());
    h.mqtt("panweave/bridge/request/permit_join", "OFF");
    assert!(h.requests.contains(&Request::CloseNetwork));
    assert_eq!(h.retained("panweave/bridge/permit_join"), Some(&b"OFF"[..]));
    h.mqtt("panweave/bridge/request/permit_join", r#"{"time": 60}"#);
    assert!(h.requests.contains(&Request::PermitJoin { seconds: 60 }));
    assert_eq!(h.retained("panweave/bridge/permit_join"), Some(&b"ON"[..]));

    let door = config_topic("binary_sensor", CONTACT, "contact");
    h.mqtt(
        "panweave/bridge/request/remove",
        &format!(r#"{{"id":"{}","force":true}}"#, device_id(CONTACT)),
    );
    assert!(h.requests.contains(&Request::RemoveDevice {
        ieee: CONTACT,
        leave: false
    }));
    // Its retained discovery, state and availability are cleared.
    assert_eq!(h.retained(&door), Some(&[][..]));
    assert_eq!(
        h.retained(&format!("panweave/{}", device_id(CONTACT))),
        Some(&[][..])
    );
    assert!(!h.bridge.devices().any(|i| i == CONTACT));
    assert!(h.bridge.devices().any(|i| i == BULB));
}

#[test]
fn without_admin_the_network_requests_are_ignored() {
    let mut h = host(Config {
        admin: false,
        ..Config::default()
    });
    assert!(
        !h.bridge
            .subscriptions()
            .iter()
            .any(|s| s.contains("bridge/request"))
    );
    let before = h.requests.len();
    h.mqtt("panweave/bridge/request/permit_join", "ON");
    h.mqtt("panweave/bridge/request/remove", &device_id(CONTACT));
    assert_eq!(h.requests.len(), before);
    // No permit-join switch is offered (an empty retained config).
    assert_eq!(
        h.retained(&format!(
            "homeassistant/switch/panweave_{}/permit_join/config",
            device_id(HUB)
        )),
        Some(&[][..])
    );
}

#[test]
fn silent_devices_are_checked_or_marked_offline() {
    let mut h = host(Config::default());
    let bulb_avail = format!("panweave/{}/availability", device_id(BULB));
    let contact_avail = format!("panweave/{}/availability", device_id(CONTACT));

    // A quiet mains device is read; it answers and stays online.
    h.tick(11 * 60);
    assert!(h.requests.iter().any(|r| matches!(
        r,
        Request::ReadAttribute { ieee, cluster: 0, .. } if *ieee == BULB
    )));
    h.sim_for(10);
    assert_eq!(h.bridge.online(BULB), Some(true));

    // Out of radio range it fails the next check and goes offline.
    let bulb = h.bulb;
    h.sim.isolate(bulb);
    h.tick(23 * 60);
    h.sim_for(120);
    assert_eq!(h.bridge.online(BULB), Some(false));
    assert_eq!(h.retained(&bulb_avail), Some(&b"offline"[..]));

    // A battery device silent for 25 hours is offline, without a check.
    let reads = h
        .requests
        .iter()
        .filter(|r| matches!(r, Request::ReadAttribute { ieee, .. } if *ieee == CONTACT))
        .count();
    h.tick(26 * 3600);
    assert_eq!(h.retained(&contact_avail), Some(&b"offline"[..]));
    assert_eq!(
        h.requests
            .iter()
            .filter(|r| matches!(r, Request::ReadAttribute { ieee, .. } if *ieee == CONTACT))
            .count(),
        reads
    );
    // Hearing it again brings it back.
    let a = h.bridge.on_event(
        Event::CommandCompleted {
            command: 999,
            ieee: CONTACT,
            stage: panweave_hub::protocol::CommandStage::Responded,
            value: None,
        },
        h.now,
    );
    h.run(a);
    assert_eq!(h.retained(&contact_avail), Some(&b"online"[..]));
}

#[test]
fn a_device_that_leaves_is_withdrawn() {
    let mut h = host(Config::default());
    let light = config_topic("light", BULB, "light");
    let a = h.bridge.on_event(Event::DeviceLeft { ieee: BULB }, h.now);
    h.run(a);
    assert_eq!(h.retained(&light), Some(&[][..]));
    assert!(!h.bridge.devices().any(|i| i == BULB));
}
