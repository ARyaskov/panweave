//! Panweave application support sub-layer (APS): R23.2 §2.2 and §4.4.
//!
//! * [`frame`]: APS frame format and extended header (§2.2.5).
//! * [`command`]: APS command frames (§4.4.11).
//! * [`aib`]: constants and scalar AIB attributes (§2.2.7, §4.4.12).
//! * [`tables`]: binding, group and duplicate rejection tables.
//! * [`security`]: APS frame security over the key-pair set (§4.4.1).
//! * [`layer`]: the sans-I/O [`Aps`] state machine (APSDE/APSME).
//!
//! See `docs/architecture.md` and `docs/security-model.md`.
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

pub mod aib;
pub mod command;
pub mod frame;
pub mod interpan;
pub mod layer;
pub mod security;
pub mod tables;

pub use layer::{
    Aps, ApsAction, ApsConfig, ApsError, ApsEvent, ApsStats, DataIndication, DataRequest, Delivery,
    Destination, DeviceState, Loopback, MAX_ASDU, NwkHandle, NwkView, PersistItem, RequestId,
    SecurityStatus, TransportedKey, TxOptions,
};
