//! Panweave Lite: the Panweave Zigbee stack dimensioned for battery IAS
//! Zone sensors (door / window contacts, water leak sensors) on
//! microcontrollers with 32 KiB of RAM, such as the Silicon Labs
//! EFR32MG22.
//!
//! Lite is not a second Zigbee stack. It is the same MAC, NWK, APS, ZDO,
//! ZCL, BDB, security and storage code as the full Panweave stack,
//! instantiated with the [`SleepySensor`] [`StackProfile`]: tables sized
//! for an end device without children, the compact
//! [`panweave_zcl::Sensor`] ZCL storage (no scene tables, no cluster
//! states but IAS Zone and Poll Control, `'static` Basic strings in
//! program memory, four reporting slots per cluster) and one application
//! endpoint. A full coordinator and a Lite sensor are different types of
//! the same generic stack and run side by side in one test binary.
//!
//! On top of the stack this crate adds what a sensor product needs:
//!
//! * [`sensor`]: the IAS Zone sensor endpoint ([`sensor::SensorKind`]:
//!   contact switch, water sensor, any zone type) built in place, and the
//!   [`sensor::ZoneReporter`] that turns sensor inputs into Zone Status
//!   Change Notifications, tracks their delivery and retries the ones
//!   that were not acknowledged — an alarm is never reported cleared
//!   before the alarm itself was delivered;
//! * [`device`]: [`LiteDevice`], the stack plus the BDB commissioning
//!   machine, persistence of the IAS enrolment, and a compact event
//!   queue;
//! * [`power`]: the sleep planner ([`power::plan`]) that tells the
//!   platform how long and how deeply it may sleep, the platform
//!   interface, and an energy model for battery-life estimates.
//!
//! Memory figures, measurement method and what has (not) been verified
//! on hardware are in `docs/lite.md`.
#![cfg_attr(not(feature = "std"), no_std)]
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

pub mod device;
pub mod footprint;
pub mod power;
pub mod sensor;

pub use device::{LiteConfig, LiteDevice, LiteEvent};
pub use panweave_runtime::{SleepySensor, StackProfile};
pub use sensor::{Delivery, SensorConfig, SensorKind, ZoneReporter};

use panweave_runtime::Stack;
use panweave_types::Endpoint;

/// Application endpoints of a Lite device.
pub const ENDPOINTS: usize = 1;

/// Cluster instances on the sensor endpoint: Basic, Identify, Power
/// Configuration, IAS Zone and Poll Control.
pub const ENDPOINT_CLUSTERS: usize = 5;

/// Attributes per cluster instance (the largest Lite cluster, Poll
/// Control, has eight with `ClusterRevision`).
pub const CLUSTER_ATTRIBUTES: usize = 8;

/// The endpoint of the sensor.
pub const SENSOR_ENDPOINT: Endpoint = Endpoint(1);

/// The stack of a Lite device: the Panweave runtime with the
/// [`SleepySensor`] profile and one endpoint of [`ENDPOINT_CLUSTERS`]
/// clusters of [`CLUSTER_ATTRIBUTES`] attributes.
pub type LiteStack<C, R, S> =
    Stack<C, R, S, SleepySensor, ENDPOINTS, ENDPOINT_CLUSTERS, CLUSTER_ATTRIBUTES>;

/// The sensor endpoint's instance type.
pub type LiteEndpoint =
    panweave_runtime::ProfileEndpoint<SleepySensor, ENDPOINT_CLUSTERS, CLUSTER_ATTRIBUTES>;
