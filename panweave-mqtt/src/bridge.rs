//! The bridge between the Panweave Hub Protocol and MQTT, sans-I/O.
//!
//! [`Bridge`] turns what the hub reports (responses and events) into MQTT
//! publications — Home Assistant discovery configurations, device state,
//! availability — and MQTT commands into hub requests. The caller owns
//! both connections: it sends the [`Action`]s, hands every hub response
//! back with the request it answers, every event, every message received
//! on [`Bridge::subscriptions`], and calls [`Bridge::tick`] about once a
//! second. Time is a monotonic count of seconds chosen by the caller.
//!
//! Topics (`<base>` is [`Config::base_topic`], `<id>` a device's IEEE
//! address as `0x` and 16 hex digits):
//!
//! | Topic | Direction | Payload |
//! |---|---|---|
//! | `<base>/bridge/state` | out, retained | `online` / `offline` (last will) |
//! | `<base>/bridge/permit_join` | out, retained | `ON` / `OFF` |
//! | `<base>/bridge/log` | out | `{"level", "message"}` |
//! | `<base>/bridge/request/permit_join` | in | seconds, `ON` (254 s) or `OFF` |
//! | `<base>/bridge/request/remove` | in | device id; `{"id", "force"}` |
//! | `<base>/bridge/request/interview` | in | device id |
//! | `<base>/bridge/request/group_add`, `group_remove` | in | `{"id", "group"}` |
//! | `<base>/bridge/request/scene_store` | in | `{"id", "group", "scene"}` |
//! | `<base>/bridge/request/scene_recall` | in | `{"group", "scene", "transition"}` |
//! | `<base>/group/<n>/set` | in | as `<base>/<id>/set`, to group `n` |
//! | `<base>/<id>` | out, retained | state object (below) |
//! | `<base>/<id>/availability` | out, retained | `online` / `offline` |
//! | `<base>/<id>/set` | in | `{"state", "brightness", "color_temp", "color", "transition"}` or `ON` / `OFF` / `TOGGLE` |
//! | `<base>/<id>/event` | out | `{"event"}`: a sensor event |
//! | `<base>/<id>/attribute` | out | an attribute report outside the state model |
//! | `<base>/<id>/ota` | out | `{"state": "downloading", "progress"}`, then `upgrading` or `failed` with the `status` |
//! | `<discovery>/status` | in | `online`: Home Assistant restarted |
//!
//! The state object always carries every field, `null` when unknown:
//! `state` (`ON`/`OFF`), `brightness` (percent), `open`, `water_leak`,
//! `occupancy`, `tamper`, `battery_low`, `trouble` (booleans), `battery`
//! (percent), `voltage` (mV), `temperature` (°C), `humidity` (%),
//! `zone_status`; colour lights add `color_mode` (`xy`, `hs`,
//! `color_temp`), `color_temp` (mireds) and `color` (`x`, `y`, `h`, `s`).

use std::collections::{BTreeMap, BTreeSet};

use panweave_hub::model::{
    Capabilities, ColorMode, ColorState, ContactState, DeviceCategory, DeviceState, Flag,
    LeakState, PowerSource, level_to_brightness,
};
use panweave_hub::protocol::{
    DeviceInfo, ErrorCode, Event, LightCommand, MAX_PERMIT_JOIN_SECONDS, Request, Response,
};
use serde_json::{Value, json};

/// ZCL Basic cluster, read to check that a mains-powered device is
/// still there.
const BASIC: u16 = 0x0000;

/// Bridge settings.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    /// Prefix of every bridge topic.
    pub base_topic: String,
    /// Home Assistant's discovery prefix.
    pub discovery_prefix: String,
    /// Accept the network requests (`<base>/bridge/request/…`). Without
    /// them the bridge only reports and controls devices.
    pub admin: bool,
    /// Seconds of silence after which a mains-powered device is checked
    /// with an attribute read; a failed read marks it offline.
    pub mains_check_s: u64,
    /// Seconds of silence after which a battery device is marked
    /// offline.
    pub battery_timeout_s: u64,
    /// Groups offered to Home Assistant as lights: group address and
    /// name. Group commands are not confirmed (the lights are
    /// optimistic).
    pub groups: Vec<(u16, String)>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            base_topic: "panweave".into(),
            discovery_prefix: "homeassistant".into(),
            admin: true,
            mains_check_s: 10 * 60,
            battery_timeout_s: 25 * 3600,
            groups: Vec::new(),
        }
    }
}

/// An MQTT message to publish.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Publication {
    /// Topic.
    pub topic: String,
    /// Payload (empty with `retain` clears a retained message).
    pub payload: Vec<u8>,
    /// Retained.
    pub retain: bool,
}

/// What the bridge asks its caller to do.
// `Request` is large (its alert configuration); actions are short-lived.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug)]
pub enum Action {
    /// Publish on MQTT.
    Publish(Publication),
    /// Send a request to the hub; hand the response to
    /// [`Bridge::on_response`] with this request.
    Request(Request),
}

/// A Home Assistant entity of a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Entity {
    component: &'static str,
    object: &'static str,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Light {
        brightness: bool,
        color: bool,
    },
    Switch,
    Binary {
        field: &'static str,
        class: &'static str,
        diagnostic: bool,
    },
    Sensor {
        field: &'static str,
        class: &'static str,
        unit: &'static str,
        diagnostic: bool,
    },
}

/// The entities a device's interview results call for.
fn entities(info: &DeviceInfo) -> Vec<Entity> {
    let caps = info.summary.capabilities;
    let category = info.summary.category;
    let mut out = Vec::new();
    let light = matches!(
        category,
        DeviceCategory::OnOffLight | DeviceCategory::DimmableLight | DeviceCategory::ColorLight
    );
    if light || (caps.contains(Capabilities::LEVEL) && caps.contains(Capabilities::ON_OFF)) {
        out.push(Entity {
            component: "light",
            object: "light",
            kind: Kind::Light {
                brightness: caps.contains(Capabilities::LEVEL),
                color: caps.contains(Capabilities::COLOR),
            },
        });
    } else if caps.contains(Capabilities::ON_OFF) && category != DeviceCategory::Controller {
        out.push(Entity {
            component: "switch",
            object: "switch",
            kind: Kind::Switch,
        });
    }
    let binary = |object, field, class, diagnostic| Entity {
        component: "binary_sensor",
        object,
        kind: Kind::Binary {
            field,
            class,
            diagnostic,
        },
    };
    if caps.contains(Capabilities::CONTACT) || category == DeviceCategory::ContactSensor {
        out.push(binary("contact", "open", "door", false));
    }
    if caps.contains(Capabilities::WATER_LEAK) || category == DeviceCategory::WaterLeakSensor {
        out.push(binary("water_leak", "water_leak", "moisture", false));
    }
    if caps.contains(Capabilities::OCCUPANCY) || category == DeviceCategory::MotionSensor {
        out.push(binary("occupancy", "occupancy", "motion", false));
    }
    if caps.contains(Capabilities::IAS_ZONE) {
        out.push(binary("tamper", "tamper", "tamper", true));
        out.push(binary("battery_low", "battery_low", "battery", true));
    }
    let sensor = |object, field, class, unit, diagnostic| Entity {
        component: "sensor",
        object,
        kind: Kind::Sensor {
            field,
            class,
            unit,
            diagnostic,
        },
    };
    if caps.contains(Capabilities::TEMPERATURE) {
        out.push(sensor(
            "temperature",
            "temperature",
            "temperature",
            "°C",
            false,
        ));
    }
    if caps.contains(Capabilities::HUMIDITY) {
        out.push(sensor("humidity", "humidity", "humidity", "%", false));
    }
    if caps.contains(Capabilities::BATTERY_PERCENTAGE) {
        out.push(sensor("battery", "battery", "battery", "%", true));
    }
    if caps.contains(Capabilities::BATTERY_VOLTAGE) {
        out.push(sensor("voltage", "voltage", "voltage", "mV", true));
    }
    out
}

/// Home Assistant colour modes of a colour light: xy (else hs) and
/// colour temperature as supported; both when the capabilities are not
/// known yet.
fn color_modes(color: Option<&ColorState>) -> Vec<&'static str> {
    let Some(c) = color.filter(|c| c.capabilities.is_some()) else {
        return vec!["color_temp", "xy"];
    };
    let mut m = Vec::new();
    if c.supports(ColorState::TEMPERATURE) {
        m.push("color_temp");
    }
    if c.supports(ColorState::XY) {
        m.push("xy");
    } else if c.supports(ColorState::HUE_SATURATION) {
        m.push("hs");
    }
    if m.is_empty() {
        m.push("brightness");
    }
    m
}

/// The colour fields of the state object.
fn color_json(c: &ColorState, modes: &[&str], out: &mut Value) {
    let xy =
        c.x.zip(c.y)
            .map(|(x, y)| (f64::from(x) / 65536.0, f64::from(y) / 65536.0));
    let hs = c
        .hue
        .zip(c.saturation)
        .map(|(h, s)| (f64::from(h) * 360.0 / 254.0, f64::from(s) * 100.0 / 254.0));
    let round = |v: f64, d: f64| (v * d).round() / d;
    let mut color = serde_json::Map::new();
    if let Some((x, y)) = xy {
        color.insert("x".into(), json!(round(x, 10_000.0)));
        color.insert("y".into(), json!(round(y, 10_000.0)));
    }
    if let Some((h, s)) = hs {
        color.insert("h".into(), json!(round(h, 10.0)));
        color.insert("s".into(), json!(round(s, 10.0)));
    }
    // The mode as Home Assistant knows it: a light in hue/saturation mode
    // that was offered as xy reports its xy.
    let mode = match c.mode {
        Some(ColorMode::Temperature) => Some("color_temp"),
        Some(ColorMode::Xy) => Some("xy"),
        Some(ColorMode::HueSaturation) if modes.contains(&"hs") => Some("hs"),
        Some(ColorMode::HueSaturation) => Some("xy"),
        None => None,
    }
    .filter(|m| modes.contains(m));
    out["color_mode"] = json!(mode);
    out["color_temp"] = json!(c.mireds);
    out["color"] = if color.is_empty() {
        Value::Null
    } else {
        Value::Object(color)
    };
}

/// Seconds as tenths of a second, 0 for anything unusable.
fn tenths(seconds: f64) -> u16 {
    if seconds.is_finite() && seconds > 0.0 {
        scale(seconds, 10.0, u16::MAX)
    } else {
        0
    }
}

/// `v × factor`, rounded and clamped to `0..=max`.
fn scale(v: f64, factor: f64, max: u16) -> u16 {
    let x = (v * factor).round().clamp(0.0, f64::from(max));
    // Clamped to 0..=max above.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let x = x as u16;
    x
}

/// `0x` and 16 hex digits.
pub fn device_id(ieee: u64) -> String {
    format!("0x{ieee:016x}")
}

/// The IEEE address of a device id: `0x` and hex digits, or the
/// colon-separated form.
pub fn parse_device_id(text: &str) -> Option<u64> {
    panweave_hub::model::Ieee::parse(text.trim().trim_matches('"')).map(|i| i.0)
}

fn flag(f: Flag) -> Value {
    match f {
        Flag::Unknown => Value::Null,
        Flag::Clear => Value::Bool(false),
        Flag::Set => Value::Bool(true),
    }
}

/// The state object of a device.
pub fn state_json(s: &DeviceState) -> Value {
    json!({
        "state": s.on.map(|on| if on { "ON" } else { "OFF" }),
        "brightness": s.level.and_then(level_to_brightness),
        "open": match s.contact {
            ContactState::Unknown => Value::Null,
            ContactState::Open => Value::Bool(true),
            ContactState::Closed => Value::Bool(false),
        },
        "water_leak": match s.water_leak {
            LeakState::Unknown => Value::Null,
            LeakState::Leak => Value::Bool(true),
            LeakState::Dry => Value::Bool(false),
        },
        "occupancy": flag(s.motion),
        "tamper": flag(s.tamper),
        "battery_low": flag(s.battery_low),
        "trouble": flag(s.trouble),
        "battery": s.battery_percent,
        "voltage": s.battery_mv,
        "temperature": s.temperature_centi.map(|t| f64::from(t) / 100.0),
        "humidity": s.humidity_centi.map(|h| f64::from(h) / 100.0),
        "zone_status": s.zone_status,
    })
}

/// A Jinja template turning a nullable boolean field into `ON` / `OFF`,
/// or `None` (unknown) for Home Assistant.
fn bool_template(field: &str) -> String {
    format!(
        "{{% if value_json.{field} is none %}}None{{% elif value_json.{field} %}}ON{{% else %}}OFF{{% endif %}}"
    )
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

#[derive(Debug)]
struct Device {
    info: Option<DeviceInfo>,
    state: DeviceState,
    /// Color Control state, for colour lights once read.
    color: Option<ColorState>,
    /// Discovery topics published for it.
    configs: BTreeSet<String>,
    /// When it was last heard (bridge clock), if known.
    heard: Option<u64>,
    online: Option<bool>,
    /// The attribute read checking that it is there, once accepted.
    check: Option<u16>,
    /// A check was requested and not yet accepted.
    check_requested: bool,
    /// When the last check started.
    checked_at: Option<u64>,
}

impl Device {
    fn new() -> Self {
        Device {
            info: None,
            state: DeviceState::default(),
            color: None,
            configs: BTreeSet::new(),
            heard: None,
            online: None,
            check: None,
            check_requested: false,
            checked_at: None,
        }
    }

    fn mains(&self) -> bool {
        self.info
            .as_ref()
            .is_some_and(|i| matches!(i.power_source, PowerSource::Mains | PowerSource::Dc))
            || self
                .info
                .as_ref()
                .is_some_and(|i| i.rx_on_when_idle == Some(true))
    }
}

/// The bridge state.
#[derive(Debug)]
pub struct Bridge {
    cfg: Config,
    hub_ieee: Option<u64>,
    hub_firmware: String,
    /// Seconds since the hub started, at bridge time `hub_clock.1`.
    hub_clock: Option<(u32, u64)>,
    permit_join: Option<bool>,
    devices: BTreeMap<u64, Device>,
    /// Devices listed in the registry walk in progress.
    listed: Option<BTreeSet<u64>>,
    now: u64,
    out: Vec<Action>,
}

impl Bridge {
    /// A bridge that has heard nothing from the hub yet.
    pub fn new(cfg: Config) -> Self {
        Bridge {
            cfg,
            hub_ieee: None,
            hub_firmware: String::new(),
            hub_clock: None,
            permit_join: None,
            devices: BTreeMap::new(),
            listed: None,
            now: 0,
            out: Vec::new(),
        }
    }

    /// The settings.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The topic of the bridge's availability (the MQTT last will:
    /// `offline`, retained).
    pub fn state_topic(&self) -> String {
        format!("{}/bridge/state", self.cfg.base_topic)
    }

    /// The topic filters to subscribe to.
    pub fn subscriptions(&self) -> Vec<String> {
        let mut v = vec![
            format!("{}/+/set", self.cfg.base_topic),
            format!("{}/status", self.cfg.discovery_prefix),
        ];
        if !self.cfg.groups.is_empty() {
            v.push(format!("{}/group/+/set", self.cfg.base_topic));
        }
        if self.cfg.admin {
            v.push(format!("{}/bridge/request/+", self.cfg.base_topic));
        }
        v
    }

    /// The devices known, by IEEE address.
    pub fn devices(&self) -> impl Iterator<Item = u64> + '_ {
        self.devices.keys().copied()
    }

    /// Whether a device is considered online (`None`: not yet decided).
    pub fn online(&self, ieee: u64) -> Option<bool> {
        self.devices.get(&ieee).and_then(|d| d.online)
    }

    fn publish(&mut self, topic: String, payload: impl Into<Vec<u8>>, retain: bool) {
        self.out.push(Action::Publish(Publication {
            topic,
            payload: payload.into(),
            retain,
        }));
    }

    fn request(&mut self, r: Request) {
        self.out.push(Action::Request(r));
    }

    fn log(&mut self, level: &str, message: String) {
        let topic = format!("{}/bridge/log", self.cfg.base_topic);
        let body = json!({ "level": level, "message": message }).to_string();
        self.publish(topic, body, false);
    }

    fn take(&mut self) -> Vec<Action> {
        core::mem::take(&mut self.out)
    }

    /// Starts (or restarts, after a reconnection of either side): the
    /// bridge announces itself and reads the hub's registry. Call after
    /// the MQTT connection is up and subscribed.
    pub fn start(&mut self, now: u64) -> Vec<Action> {
        self.now = now;
        self.publish(self.state_topic(), "online", true);
        self.request(Request::GetHubInfo);
        self.request(Request::GetNetworkStatus);
        self.resync();
        self.take()
    }

    /// Re-reads the registry from its start.
    fn resync(&mut self) {
        self.listed = Some(BTreeSet::new());
        self.request(Request::ListDevices { start: 0 });
    }

    /// Republishes every discovery configuration, state and availability
    /// (Home Assistant restarted and lost what was not retained).
    pub fn republish(&mut self, now: u64) -> Vec<Action> {
        self.now = now;
        self.publish(self.state_topic(), "online", true);
        self.publish_bridge_discovery();
        let ids: Vec<u64> = self.devices.keys().copied().collect();
        for ieee in ids {
            self.publish_device(ieee);
        }
        self.take()
    }

    /// What the caller publishes when it stops on purpose (the last will
    /// covers a lost connection).
    pub fn stop(&mut self) -> Vec<Action> {
        self.publish(self.state_topic(), "offline", true);
        self.take()
    }

    fn bridge_device(&self) -> Value {
        let hub = self.hub_ieee.unwrap_or_default();
        json!({
            "identifiers": [format!("panweave_bridge_{}", device_id(hub))],
            "name": "Panweave hub",
            "manufacturer": "Panweave",
            "model": "Zigbee coordinator",
            "sw_version": self.hub_firmware,
        })
    }

    fn publish_bridge_discovery(&mut self) {
        let Some(hub) = self.hub_ieee else {
            return;
        };
        let base = &self.cfg.base_topic;
        let id = format!("panweave_{}_permit_join", device_id(hub));
        let config = json!({
            "name": "Permit join",
            "unique_id": id,
            "object_id": id,
            "icon": "mdi:zigbee",
            "entity_category": "config",
            "device": self.bridge_device(),
            "availability_topic": format!("{base}/bridge/state"),
            "state_topic": format!("{base}/bridge/permit_join"),
            "command_topic": format!("{base}/bridge/request/permit_join"),
            "payload_on": "ON",
            "payload_off": "OFF",
        });
        let topic = format!(
            "{}/switch/panweave_{}/permit_join/config",
            self.cfg.discovery_prefix,
            device_id(hub)
        );
        if self.cfg.admin {
            self.publish(topic, config.to_string(), true);
        } else {
            self.publish(topic, Vec::new(), true);
        }
        if let Some(on) = self.permit_join {
            self.publish_permit_join(on);
        }
        self.publish_group_discovery();
    }

    fn publish_permit_join(&mut self, on: bool) {
        let topic = format!("{}/bridge/permit_join", self.cfg.base_topic);
        self.publish(topic, if on { "ON" } else { "OFF" }, true);
    }

    fn entity_config(
        &self,
        ieee: u64,
        info: &DeviceInfo,
        color: Option<&ColorState>,
        e: Entity,
    ) -> Value {
        let base = &self.cfg.base_topic;
        let id = device_id(ieee);
        let state_topic = format!("{base}/{id}");
        let unique = format!("panweave_{id}_{}", e.object);
        let model = text(&info.summary.model);
        let manufacturer = text(&info.manufacturer);
        let name = if model.is_empty() {
            id.clone()
        } else {
            model.clone()
        };
        let mut device = json!({
            "identifiers": [format!("panweave_{id}")],
            "name": name,
        });
        if !manufacturer.is_empty() {
            device["manufacturer"] = json!(manufacturer);
        }
        if !model.is_empty() {
            device["model"] = json!(model);
        }
        let build = text(&info.sw_build);
        if !build.is_empty() {
            device["sw_version"] = json!(build);
        }
        if let Some(hub) = self.hub_ieee {
            device["via_device"] = json!(format!("panweave_bridge_{}", device_id(hub)));
        }
        let mut c = json!({
            "unique_id": unique,
            "object_id": unique,
            "device": device,
            "state_topic": state_topic,
            "availability_mode": "all",
            "availability": [
                { "topic": format!("{base}/bridge/state") },
                { "topic": format!("{base}/{id}/availability") },
            ],
        });
        let command_topic = format!("{base}/{id}/set");
        match e.kind {
            Kind::Light {
                brightness,
                color: has_color,
            } => {
                c["name"] = Value::Null;
                c["schema"] = json!("json");
                c["command_topic"] = json!(command_topic);
                if brightness || has_color {
                    c["brightness"] = json!(true);
                    c["brightness_scale"] = json!(100);
                }
                if has_color {
                    c["supported_color_modes"] = json!(color_modes(color));
                    if let Some(min) = color.and_then(|c| c.mireds_min) {
                        c["min_mireds"] = json!(min);
                    }
                    if let Some(max) = color.and_then(|c| c.mireds_max) {
                        c["max_mireds"] = json!(max);
                    }
                } else if brightness {
                    c["supported_color_modes"] = json!(["brightness"]);
                } else {
                    c["supported_color_modes"] = json!(["onoff"]);
                }
            }
            Kind::Switch => {
                c["name"] = Value::Null;
                c["command_topic"] = json!(command_topic);
                c["value_template"] = json!("{{ value_json.state }}");
                c["state_on"] = json!("ON");
                c["state_off"] = json!("OFF");
                c["payload_on"] = json!(r#"{"state":"ON"}"#);
                c["payload_off"] = json!(r#"{"state":"OFF"}"#);
            }
            Kind::Binary {
                field,
                class,
                diagnostic,
            } => {
                c["name"] = Value::Null;
                c["device_class"] = json!(class);
                c["value_template"] = json!(bool_template(field));
                c["payload_on"] = json!("ON");
                c["payload_off"] = json!("OFF");
                if diagnostic {
                    c["entity_category"] = json!("diagnostic");
                }
            }
            Kind::Sensor {
                field,
                class,
                unit,
                diagnostic,
            } => {
                c["name"] = Value::Null;
                c["device_class"] = json!(class);
                c["unit_of_measurement"] = json!(unit);
                c["state_class"] = json!("measurement");
                c["value_template"] = json!(format!("{{{{ value_json.{field} }}}}"));
                if diagnostic {
                    c["entity_category"] = json!("diagnostic");
                }
            }
        }
        c
    }

    fn config_topic(&self, ieee: u64, e: Entity) -> String {
        format!(
            "{}/{}/panweave_{}/{}/config",
            self.cfg.discovery_prefix,
            e.component,
            device_id(ieee),
            e.object
        )
    }

    /// Publishes a device's discovery configurations (clearing those it
    /// no longer has), state and availability.
    fn publish_device(&mut self, ieee: u64) {
        let Some(d) = self.devices.get(&ieee) else {
            return;
        };
        let mut configs = BTreeSet::new();
        let mut pubs = Vec::new();
        if let Some(info) = &d.info {
            for e in entities(info) {
                let topic = self.config_topic(ieee, e);
                pubs.push((
                    topic.clone(),
                    self.entity_config(ieee, info, d.color.as_ref(), e)
                        .to_string()
                        .into_bytes(),
                ));
                configs.insert(topic);
            }
        }
        let stale: Vec<String> = d.configs.difference(&configs).cloned().collect();
        let online = d.online;
        for topic in stale {
            self.publish(topic, Vec::new(), true);
        }
        for (topic, body) in pubs {
            self.publish(topic, body, true);
        }
        if let Some(d) = self.devices.get_mut(&ieee) {
            d.configs = configs;
        }
        if let Some(online) = online {
            self.publish_availability(ieee, online);
        }
        self.publish_state(ieee);
    }

    fn publish_state(&mut self, ieee: u64) {
        let Some(d) = self.devices.get(&ieee) else {
            return;
        };
        let mut body = state_json(&d.state);
        let colour = d
            .info
            .as_ref()
            .is_some_and(|i| i.summary.capabilities.contains(Capabilities::COLOR));
        if colour {
            let modes = color_modes(d.color.as_ref());
            color_json(&d.color.unwrap_or_default(), &modes, &mut body);
        }
        let topic = format!("{}/{}", self.cfg.base_topic, device_id(ieee));
        self.publish(topic, body.to_string(), true);
    }

    fn publish_group_discovery(&mut self) {
        let base = self.cfg.base_topic.clone();
        let groups = self.cfg.groups.clone();
        for (group, name) in groups {
            let id = format!("panweave_group_{group}");
            let mut config = json!({
                "name": name,
                "unique_id": id,
                "object_id": id,
                "schema": "json",
                "optimistic": true,
                "command_topic": format!("{base}/group/{group}/set"),
                "availability_topic": format!("{base}/bridge/state"),
                "brightness": true,
                "brightness_scale": 100,
                "supported_color_modes": ["color_temp", "xy"],
            });
            if self.hub_ieee.is_some() {
                config["device"] = self.bridge_device();
            }
            let topic = format!(
                "{}/light/panweave_group_{group}/light/config",
                self.cfg.discovery_prefix
            );
            self.publish(topic, config.to_string(), true);
        }
    }

    fn publish_availability(&mut self, ieee: u64, online: bool) {
        let topic = format!("{}/{}/availability", self.cfg.base_topic, device_id(ieee));
        self.publish(topic, if online { "online" } else { "offline" }, true);
    }

    fn set_online(&mut self, ieee: u64, online: bool) {
        let Some(d) = self.devices.get_mut(&ieee) else {
            return;
        };
        if d.online != Some(online) {
            d.online = Some(online);
            self.publish_availability(ieee, online);
        }
    }

    /// The device was heard: it is online.
    fn heard(&mut self, ieee: u64) {
        let now = self.now;
        if let Some(d) = self.devices.get_mut(&ieee) {
            d.heard = Some(now);
            d.check = None;
            d.check_requested = false;
            d.checked_at = None;
        }
        self.set_online(ieee, true);
    }

    /// Forgets a device: its retained messages are cleared.
    fn remove_device(&mut self, ieee: u64) {
        let Some(d) = self.devices.remove(&ieee) else {
            return;
        };
        for topic in d.configs {
            self.publish(topic, Vec::new(), true);
        }
        let base = format!("{}/{}", self.cfg.base_topic, device_id(ieee));
        self.publish(format!("{base}/availability"), Vec::new(), true);
        self.publish(base, Vec::new(), true);
    }

    /// The hub answered `request` with `response`.
    pub fn on_response(&mut self, request: &Request, response: Response, now: u64) -> Vec<Action> {
        self.now = now;
        match (request, response) {
            (Request::GetHubInfo, Response::HubInfo(info)) => {
                self.hub_ieee = Some(info.ieee);
                self.hub_firmware = text(&info.firmware);
                self.hub_clock = Some((info.uptime_s, now));
                self.publish_bridge_discovery();
            }
            (Request::GetNetworkStatus, Response::NetworkStatus(s)) => {
                let on = s.permit_join_s > 0;
                self.permit_join = Some(on);
                self.publish_permit_join(on);
            }
            (Request::ListDevices { .. }, Response::DeviceList(list)) => {
                for d in &list.devices {
                    if let Some(l) = self.listed.as_mut() {
                        l.insert(d.ieee);
                    }
                    let entry = self.devices.entry(d.ieee).or_insert_with(Device::new);
                    if !d.present {
                        entry.online = None;
                    }
                    self.request(Request::GetDevice { ieee: d.ieee });
                }
                let next = usize::from(list.start) + list.devices.len();
                if next < usize::from(list.total) && !list.devices.is_empty() {
                    self.request(Request::ListDevices {
                        start: u8::try_from(next).unwrap_or(u8::MAX),
                    });
                } else if let Some(listed) = self.listed.take() {
                    let gone: Vec<u64> = self
                        .devices
                        .keys()
                        .copied()
                        .filter(|i| !listed.contains(i))
                        .collect();
                    for ieee in gone {
                        self.remove_device(ieee);
                    }
                }
            }
            (Request::GetDevice { ieee }, Response::Device(info)) => {
                let ieee = *ieee;
                let heard = self.hub_heard(info.summary.last_seen_s);
                let present = info.summary.present;
                let d = self.devices.entry(ieee).or_insert_with(Device::new);
                d.state = info.state;
                let colour = info.summary.capabilities.contains(Capabilities::COLOR);
                d.info = Some(info);
                if d.heard.is_none() {
                    d.heard = heard;
                }
                if d.online.is_none() {
                    let timeout = if d.mains() {
                        self.cfg.mains_check_s
                    } else {
                        self.cfg.battery_timeout_s
                    };
                    // A mains device not heard lately is checked by the
                    // next tick; until then it counts as there.
                    d.online = Some(
                        present
                            && (d.mains()
                                || heard.is_some_and(|h| now.saturating_sub(h) < timeout)),
                    );
                }
                self.publish_device(ieee);
                if colour {
                    self.request(Request::GetLightColor { ieee });
                }
            }
            (Request::GetLightColor { .. }, Response::LightColor { ieee, color }) => {
                self.color_changed(ieee, color);
            }
            (Request::RemoveDevice { ieee, .. }, Response::Done) => {
                self.remove_device(*ieee);
            }
            (Request::GetDevice { ieee }, Response::Error(ErrorCode::UnknownDevice)) => {
                self.remove_device(*ieee);
            }
            (Request::ReadAttribute { ieee, cluster, .. }, Response::Accepted { command })
                if *cluster == BASIC =>
            {
                if let Some(d) = self.devices.get_mut(ieee)
                    && d.check_requested
                {
                    d.check = Some(command);
                    d.check_requested = false;
                }
            }
            (Request::ReadAttribute { ieee, cluster, .. }, Response::Error(e))
                if *cluster == BASIC =>
            {
                if let Some(d) = self.devices.get_mut(ieee) {
                    d.check_requested = false;
                }
                if matches!(e, ErrorCode::Unreachable | ErrorCode::Timeout) {
                    self.set_online(*ieee, false);
                }
            }
            (r, Response::Error(e)) => {
                self.log("error", format!("{r:?}: {}", e.name()));
            }
            _ => {}
        }
        self.take()
    }

    /// A colour light's colour: new capabilities change its discovery
    /// configuration, anything else only its state.
    fn color_changed(&mut self, ieee: u64, color: ColorState) {
        let Some(d) = self.devices.get_mut(&ieee) else {
            return;
        };
        let before = d.color;
        d.color = Some(color);
        let identity =
            |c: Option<ColorState>| c.map(|c| (c.capabilities, c.mireds_min, c.mireds_max));
        if identity(before) != identity(Some(color)) {
            self.publish_device(ieee);
        } else {
            self.publish_state(ieee);
        }
    }

    /// Bridge time of a hub `last_seen_s` (seconds since the hub's boot).
    fn hub_heard(&self, last_seen_s: Option<u32>) -> Option<u64> {
        let (uptime, at) = self.hub_clock?;
        let ago = u64::from(uptime.saturating_sub(last_seen_s?));
        Some(at.saturating_sub(ago))
    }

    /// The hub reported `event`.
    pub fn on_event(&mut self, event: Event, now: u64) -> Vec<Action> {
        self.now = now;
        match event {
            Event::NetworkStarted(_) | Event::NetworkRestored(_) | Event::EventsDropped { .. } => {
                self.request(Request::GetHubInfo);
                self.request(Request::GetNetworkStatus);
                self.resync();
            }
            Event::PermitJoinChanged { seconds } => {
                self.permit_join = Some(seconds > 0);
                self.publish_permit_join(seconds > 0);
            }
            Event::DeviceJoined { ieee, .. } => {
                self.devices.entry(ieee).or_insert_with(Device::new);
                self.heard(ieee);
                self.request(Request::GetDevice { ieee });
            }
            Event::DeviceInterviewCompleted { ieee, .. } => {
                self.heard(ieee);
                self.request(Request::GetDevice { ieee });
            }
            Event::DeviceLeft { ieee } => {
                self.remove_device(ieee);
            }
            Event::DeviceStateChanged { ieee, state } => {
                if let Some(d) = self.devices.get_mut(&ieee) {
                    d.state = state;
                    self.heard(ieee);
                    self.publish_state(ieee);
                } else {
                    self.devices.insert(ieee, Device::new());
                    self.request(Request::GetDevice { ieee });
                }
            }
            Event::Sensor { ieee, event } => {
                self.heard(ieee);
                let topic = format!("{}/{}/event", self.cfg.base_topic, device_id(ieee));
                self.publish(topic, json!({ "event": event.name() }).to_string(), false);
            }
            Event::AttributeReport {
                ieee,
                endpoint,
                cluster,
                attribute,
                value,
            } => {
                self.heard(ieee);
                let topic = format!("{}/{}/attribute", self.cfg.base_topic, device_id(ieee));
                let body = json!({
                    "endpoint": endpoint,
                    "cluster": cluster,
                    "attribute": attribute,
                    "type": value.data_type,
                    "value": value.to_string(),
                });
                self.publish(topic, body.to_string(), false);
            }
            Event::CommandCompleted { ieee, .. } => self.heard(ieee),
            Event::CommandFailed {
                command,
                ieee,
                error,
                ..
            } => {
                let check = self
                    .devices
                    .get(&ieee)
                    .is_some_and(|d| d.check == Some(command));
                if check {
                    if let Some(d) = self.devices.get_mut(&ieee) {
                        d.check = None;
                    }
                    self.set_online(ieee, false);
                } else {
                    self.log(
                        "warning",
                        format!(
                            "command {command} to {} failed: {}",
                            device_id(ieee),
                            error.name()
                        ),
                    );
                }
            }
            Event::DeviceInterviewFailed { ieee, stage, error } => {
                self.log(
                    "warning",
                    format!(
                        "interview of {} stopped at {}: {}",
                        device_id(ieee),
                        stage.name(),
                        error.name()
                    ),
                );
            }
            Event::HubError { error, detail } => {
                self.log("error", format!("hub: {} ({detail})", error.name()));
            }
            Event::LightColorChanged { ieee, color } => {
                self.heard(ieee);
                self.color_changed(ieee, color);
            }
            // The OTA image is served by the host that offered it
            // (`panweave-hub-cli ota update`); the bridge reports progress.
            Event::OtaDataWanted { .. } => {}
            Event::OtaProgress { ieee, offset, size } => {
                self.heard(ieee);
                let topic = format!("{}/{}/ota", self.cfg.base_topic, device_id(ieee));
                let body = json!({
                    "state": "downloading",
                    "progress": u64::from(offset) * 100 / u64::from(size.max(1)),
                });
                self.publish(topic, body.to_string(), false);
            }
            Event::OtaFinished { ieee, status } => {
                let topic = format!("{}/{}/ota", self.cfg.base_topic, device_id(ieee));
                let state = if status == 0 { "upgrading" } else { "failed" };
                let body = json!({ "state": state, "status": status });
                self.publish(topic, body.to_string(), false);
            }
        }
        self.take()
    }

    /// A message arrived on a subscribed topic.
    pub fn on_mqtt(&mut self, topic: &str, payload: &[u8], now: u64) -> Vec<Action> {
        self.now = now;
        let payload = String::from_utf8_lossy(payload);
        let payload = payload.trim();
        let base = self.cfg.base_topic.clone();
        if topic == format!("{}/status", self.cfg.discovery_prefix) {
            if payload.eq_ignore_ascii_case("online") {
                return self.republish(now);
            }
        } else if let Some(name) = topic.strip_prefix(&format!("{base}/bridge/request/")) {
            if self.cfg.admin {
                self.bridge_request(name, payload);
            }
        } else if let Some(n) = topic
            .strip_prefix(&format!("{base}/group/"))
            .and_then(|r| r.strip_suffix("/set"))
        {
            match n.parse::<u16>() {
                Ok(group) if self.cfg.groups.iter().any(|(g, _)| *g == group) => {
                    for command in self.light_commands(payload, None) {
                        self.request(Request::GroupLight { group, command });
                    }
                }
                _ => self.log("warning", format!("{topic}: unknown group")),
            }
        } else if let Some(rest) = topic.strip_prefix(&format!("{base}/"))
            && let Some(id) = rest.strip_suffix("/set")
        {
            match parse_device_id(id) {
                Some(ieee) if self.devices.contains_key(&ieee) => self.set(ieee, payload),
                _ => self.log("warning", format!("{topic}: unknown device")),
            }
        }
        self.take()
    }

    fn bridge_request(&mut self, name: &str, payload: &str) {
        let value: Option<Value> = serde_json::from_str(payload).ok();
        match name {
            "permit_join" => {
                let seconds = match payload.to_ascii_uppercase().as_str() {
                    "ON" | "TRUE" => Some(u64::from(MAX_PERMIT_JOIN_SECONDS)),
                    "OFF" | "FALSE" => Some(0),
                    _ => value
                        .as_ref()
                        .and_then(|v| v.get("time").or(Some(v)))
                        .and_then(Value::as_u64),
                };
                match seconds {
                    Some(0) => self.request(Request::CloseNetwork),
                    Some(s) => self.request(Request::PermitJoin {
                        seconds: u8::try_from(s.min(u64::from(MAX_PERMIT_JOIN_SECONDS)))
                            .unwrap_or(MAX_PERMIT_JOIN_SECONDS),
                    }),
                    None => self.log("warning", format!("permit_join: bad payload {payload:?}")),
                }
            }
            "remove" | "interview" => {
                let (id, force) = match &value {
                    Some(Value::Object(o)) => (
                        o.get("id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        o.get("force").and_then(Value::as_bool).unwrap_or(false),
                    ),
                    _ => (payload.to_string(), false),
                };
                match parse_device_id(&id) {
                    Some(ieee) if name == "remove" => self.request(Request::RemoveDevice {
                        ieee,
                        leave: !force,
                    }),
                    Some(ieee) => self.request(Request::InterviewDevice { ieee }),
                    None => self.log("warning", format!("{name}: bad device id {id:?}")),
                }
            }
            "group_add" | "group_remove" | "scene_store" | "scene_recall" => {
                let o = value.as_ref().and_then(Value::as_object);
                let field = |k: &str| o.and_then(|o| o.get(k));
                let id = field("id")
                    .and_then(Value::as_str)
                    .and_then(parse_device_id);
                let group = field("group")
                    .and_then(Value::as_u64)
                    .and_then(|g| u16::try_from(g).ok());
                let scene = field("scene")
                    .and_then(Value::as_u64)
                    .and_then(|s| u8::try_from(s).ok());
                let transition_ds = field("transition")
                    .and_then(Value::as_f64)
                    .map_or(0, tenths);
                let r = match (name, id, group, scene) {
                    ("group_add", Some(ieee), Some(group), _) => Some(Request::AddGroup {
                        ieee,
                        endpoint: 0,
                        group,
                    }),
                    ("group_remove", Some(ieee), Some(group), _) => Some(Request::RemoveGroup {
                        ieee,
                        endpoint: 0,
                        group,
                    }),
                    ("scene_store", Some(ieee), Some(group), Some(scene)) => {
                        Some(Request::StoreScene {
                            ieee,
                            endpoint: 0,
                            group,
                            scene,
                        })
                    }
                    ("scene_recall", _, Some(group), Some(scene)) => Some(Request::RecallScene {
                        group,
                        scene,
                        transition_ds,
                    }),
                    _ => None,
                };
                match r {
                    Some(r) => self.request(r),
                    None => self.log("warning", format!("{name}: bad payload {payload:?}")),
                }
            }
            other => self.log("warning", format!("unknown bridge request {other:?}")),
        }
    }

    /// A `<base>/<id>/set` command.
    fn set(&mut self, ieee: u64, payload: &str) {
        let commands = self.light_commands(payload, Some(ieee));
        for command in commands {
            self.request(Request::Light {
                ieee,
                endpoint: 0,
                command,
            });
        }
    }

    /// The light commands of a `set` payload: on/off or brightness first,
    /// then the colour. Logs and returns nothing for an unusable payload.
    fn light_commands(&mut self, payload: &str, ieee: Option<u64>) -> Vec<LightCommand> {
        let mut out = Vec::new();
        let (state, brightness, transition, mireds, color) =
            match serde_json::from_str::<Value>(payload) {
                Ok(Value::Object(o)) => (
                    o.get("state")
                        .and_then(Value::as_str)
                        .map(str::to_ascii_uppercase),
                    o.get("brightness").and_then(Value::as_u64),
                    o.get("transition").and_then(Value::as_f64),
                    o.get("color_temp").and_then(Value::as_u64),
                    o.get("color").cloned(),
                ),
                _ => (Some(payload.to_ascii_uppercase()), None, None, None, None),
            };
        let transition_ds = transition.map_or(0, tenths);
        match (state.as_deref(), brightness) {
            (Some("OFF"), _) => out.push(LightCommand::TurnOff),
            (_, Some(b)) => out.push(LightCommand::SetBrightness {
                percent: u8::try_from(b.min(100)).unwrap_or(100),
                transition_ds,
            }),
            (Some("ON"), None) => out.push(LightCommand::TurnOn),
            (Some("TOGGLE"), None) => out.push(LightCommand::Toggle),
            _ => {}
        }
        if state.as_deref() != Some("OFF") {
            if let Some(m) = mireds {
                out.push(LightCommand::SetColorTemperature {
                    mireds: u16::try_from(m.clamp(1, 0xfeff)).unwrap_or(0xfeff),
                    transition_ds,
                });
            }
            if let Some(Value::Object(c)) = color {
                let get = |k: &str| c.get(k).and_then(Value::as_f64).filter(|v| v.is_finite());
                if let (Some(x), Some(y)) = (get("x"), get("y")) {
                    out.push(LightCommand::SetColorXy {
                        x: scale(x, 65536.0, 0xfeff),
                        y: scale(y, 65536.0, 0xfeff),
                        transition_ds,
                    });
                } else if let (Some(h), Some(sat)) = (get("h"), get("s")) {
                    out.push(LightCommand::SetHueSaturation {
                        hue: u8::try_from(scale(h.rem_euclid(360.0), 254.0 / 360.0, 254))
                            .unwrap_or(254),
                        saturation: u8::try_from(scale(sat, 254.0 / 100.0, 254)).unwrap_or(254),
                        transition_ds,
                    });
                }
            }
        }
        if out.is_empty() {
            let target = ieee.map_or_else(|| "group".to_string(), device_id);
            self.log(
                "warning",
                format!("{target}/set: unsupported payload {payload:?}"),
            );
        }
        out
    }

    /// Time passed: devices not heard for too long are checked or marked
    /// offline. Call about once a second.
    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        self.now = now;
        let mut checks = Vec::new();
        let mut offline = Vec::new();
        for (&ieee, d) in &self.devices {
            if d.online != Some(true) && !d.mains() {
                continue;
            }
            let silent = now.saturating_sub(d.heard.unwrap_or(0));
            if d.mains() {
                let pending = d.check.is_some() || d.check_requested;
                let recently = d
                    .checked_at
                    .is_some_and(|t| now.saturating_sub(t) < self.cfg.mains_check_s);
                if silent >= self.cfg.mains_check_s && !pending && !recently {
                    checks.push(ieee);
                }
            } else if silent >= self.cfg.battery_timeout_s {
                offline.push(ieee);
            }
        }
        for ieee in checks {
            let endpoint = self
                .devices
                .get(&ieee)
                .and_then(|d| d.info.as_ref())
                .and_then(|i| i.endpoints.first())
                .map_or(1, |e| e.endpoint);
            if let Some(d) = self.devices.get_mut(&ieee) {
                d.check_requested = true;
                d.checked_at = Some(now);
            }
            self.request(Request::ReadAttribute {
                ieee,
                endpoint,
                cluster: BASIC,
                attribute: 0x0000,
            });
        }
        for ieee in offline {
            self.set_online(ieee, false);
        }
        self.take()
    }
}
