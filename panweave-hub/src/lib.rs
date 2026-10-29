//! Panweave hub: a Zigbee coordinator and Trust Center that manages
//! third-party devices directly, without a vendor cloud.
//!
//! The crate has two halves:
//!
//! * [`protocol`] and [`model`] — the *Panweave Hub Protocol v1*: typed
//!   requests, responses and events, their compact binary encoding and
//!   the COBS + CRC framing that carries them over a byte stream (USB
//!   serial today). These compile without the Zigbee stack (default
//!   features off), so a host application shares the exact definitions
//!   the firmware uses.
//! * the engine (feature `engine`, on by default) — the application on
//!   top of `panweave-runtime`: a bounded device registry keyed by IEEE
//!   address, the device interview (descriptors, Basic attributes, IAS
//!   Zone enrolment, bindings, reporting, initial state), IAS Zone and
//!   lighting state normalization, host commands with timeouts and
//!   state confirmation, persistence of the registry through any
//!   [`panweave_storage::Storage`], and a transport-independent
//!   [`Session`] that turns protocol frames into hub calls.
//!
//! The engine is sans-I/O like the stack: the firmware feeds it the
//! stack's events and calls [`Hub::poll`]; the simulator tests do the
//! same with `panweave-sim`. `docs/esp32c6-hub.md` in the repository is
//! the guide.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
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

#[cfg(feature = "alerts")]
pub mod alert;
pub mod boot;
pub mod capture;
pub mod compat;
pub mod diag;
pub mod esp32c6;
pub mod model;
pub mod partitions;
pub mod protocol;
pub mod supervisor;

#[cfg(feature = "engine")]
mod endpoint;
#[cfg(feature = "engine")]
mod hub;
#[cfg(feature = "alerts")]
mod hub_alerts;
#[cfg(feature = "engine")]
mod hub_diag;
/// The Green Power sink.
#[cfg(feature = "green-power")]
mod hub_gp;
/// The OTA upgrade server.
#[cfg(feature = "engine")]
mod hub_ota;
#[cfg(feature = "engine")]
mod hub_security;
#[cfg(feature = "engine")]
pub mod ias;
#[cfg(feature = "engine")]
mod interview;
#[cfg(feature = "engine")]
mod persist;
#[cfg(feature = "engine")]
pub mod registry;
#[cfg(feature = "engine")]
mod session;
#[cfg(feature = "engine")]
mod zcl;

#[cfg(feature = "engine")]
pub use endpoint::{hub_endpoint, hub_endpoint_into};
#[cfg(feature = "engine")]
pub use hub::{Hub, HubConfig, HubCounters, PlatformCounters};
#[cfg(feature = "alerts")]
pub use hub_alerts::PreparedAlert;
#[cfg(feature = "engine")]
pub use session::{Access, LinkStats, Session};
