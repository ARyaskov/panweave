//! Panweave MQTT bridge: the Panweave hub's devices on an MQTT broker,
//! announced to Home Assistant through MQTT discovery.
//!
//! The bridge runs on a host next to the hub (a PC, a Raspberry Pi), talks
//! to it over USB serial with the Panweave Hub Protocol and to a broker
//! with MQTT 3.1.1. Both halves are sans-I/O and tested without either
//! connection:
//!
//! * [`mqtt`] — the MQTT packets the bridge needs, and a stream decoder;
//! * [`bridge`] — hub responses and events to discovery configurations,
//!   state and availability; MQTT commands to hub requests.
//!
//! The `panweave-mqtt` binary connects them. The topics and the state
//! object are documented in [`bridge`] and in `docs/mqtt.md`.
#![forbid(unsafe_code)]

pub mod bridge;
pub mod mqtt;

pub use bridge::{Action, Bridge, Config, Publication};
