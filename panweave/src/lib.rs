//! Panweave: an independent Rust implementation of IEEE 802.15.4-based
//! Zigbee protocol functionality. See `docs/architecture.md`.
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

pub use panweave_types as types;
