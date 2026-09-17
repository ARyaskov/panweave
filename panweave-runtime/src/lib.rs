//! Sans-I/O stack driver: composes the MAC service, NWK, APS, ZDO and ZCL
//! layers into one [`Stack`] that a runtime (RTOS task, async executor or
//! the simulator) drives with a radio, a clock and a storage backend.
//!
//! The stack owns no I/O: the runtime feeds received frames through
//! [`Stack::on_radio_frame`], reports transmissions with
//! [`Stack::on_tx_complete`], drains [`Stack::next_radio_action`] and
//! calls [`Stack::poll`] whenever [`Stack::next_deadline`] passes or any
//! input arrived. Application-level results are delivered as
//! [`StackEvent`]s.
//!
//! Layer wiring follows the primitives of R23.2: NLDE/NLME ↔ MAC (§3.2,
//! Annex D), APSDE/APSME ↔ NWK (§2.2), ZDO ↔ APS (§2.4, §2.5), and the
//! Trust Center authorization procedure (§4.6.3.2, §4.7.3).
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

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod agility;
mod bdb;
mod context;
mod dlk;
pub mod fragment_cache;
#[cfg(feature = "green-power")]
pub mod green_power;
pub mod interpan;
mod keep_alive;
pub mod ota;
mod persist;
mod provision;
mod pump;
mod stack;
pub mod swap_out;
pub mod touchlink;

pub use persist::Restored;
pub use provision::{AdoptParams, FormationParams};
pub use stack::{
    EndpointError, JoinMode, Stack, StackAps, StackConfig, StackEvent, StackNwk, StackZcl,
    StackZdo, ZclFrame, ZdpData,
};
