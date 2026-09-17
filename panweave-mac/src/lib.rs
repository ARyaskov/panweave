//! IEEE 802.15.4 frame codec, radio abstraction and MAC service for
//! Panweave.
//!
//! Zigbee uses a small, well-defined subset of IEEE 802.15.4: non-beacon
//! (beacon order 15) PANs, data frames with acknowledgements, association,
//! data-request polling, beacon requests/beacons for discovery, and no MAC
//! security (R23.2 Annex D). This crate implements exactly that subset in a
//! hardware-independent way:
//!
//! * [`frame`] — panic-free codec for MAC headers, beacons and MAC commands.
//! * [`radio`] — the [`radio::Radio`] trait a vendor backend or RCP
//!   adapter implements, plus radio configuration types.
//! * [`service`] — [`service::MacService`], a sans-I/O state machine that
//!   provides the MLME/MCPS behaviour Zigbee needs (sequence numbers,
//!   acknowledged transmission with retries, indirect transmission,
//!   polling, association, scanning, beacon responses).
//! * [`constants`] — PHY/MAC constants for the 2.4 GHz O-QPSK PHY.
//!
//! See `docs/radio-hal.md` for the integration model.

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

pub mod constants;
pub mod frame;
pub mod radio;
pub mod service;

pub use frame::{
    AddressMode, Frame, FrameControl, FrameType, FrameVersion, Header, MacAddress, MacCommand,
    MacCommandId,
};
pub use radio::{
    Radio, RadioCapabilities, RadioConfig, RadioError, RxMetadata, TxOptions, TxResult,
};
pub use service::{MacAction, MacEvent, MacRequest, MacService, MacServiceConfig};
