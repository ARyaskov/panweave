//! Zigbee Direct 1.1 (CSA 20-27688-041): secure session establishment over
//! the Authenticate characteristics, secured characteristic payloads,
//! authorization keys, the BLE advertisement extension, the GATT
//! service identifiers, the Commissioning Service payloads and ZDD
//! handler, and the Tunnel Service NPDU messages. The BLE transport
//! itself is the host's: this crate only produces and consumes
//! characteristic values. See `docs/architecture.md`.
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

pub mod advertisement;
pub mod auth;
pub mod commissioning;
pub mod gatt;
pub mod legacy;
pub mod rotation;
pub mod secure;
pub mod session;
pub mod tlv;
pub mod tunnel;
pub mod zvd;
