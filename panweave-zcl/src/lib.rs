//! Panweave Zigbee Cluster Library foundation (ZCL revision 8, chapter 2).
//!
//! * [`types`]: data types and wire values (§2.6.2).
//! * [`frame`]: ZCL header and status codes (§2.4, §2.6.3).
//! * [`global`]: general command frames (§2.5).
//! * [`attribute`], [`cluster`]: attribute storage, global command
//!   server processing and reporting state (§2.3.4, §2.5.7, §2.5.11).
//! * [`layer`]: endpoint dispatch, Default Responses and reporting.
//! * [`clusters`]: Basic, Identify and On/Off definitions (chapter 3).
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod attribute;
pub mod cluster;
pub mod clusters;
pub mod frame;
pub mod global;
pub mod layer;
pub mod structured;
pub mod types;

pub use attribute::{Access, AttributeDef, AttributeTable};
pub use cluster::{ClusterDef, ClusterInstance, Role};
pub use frame::{Direction, Frame, FrameType, Header, ZclStatus};
pub use layer::{EndpointInstance, Origin, Zcl, ZclAction, ZclError, ZclIndication};
pub use types::{DataType, Value};
