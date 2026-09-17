//! Green Power Basic 1.1.2 (CSA 14-0563-19): the GPDF codec, the GP stub
//! security operations, the Green Power cluster (0x0021) command codecs,
//! the GPD commissioning command payloads, the proxy and sink tables and
//! the sans-I/O Basic Proxy machine. See `docs/architecture.md`.
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

pub mod cluster;
pub mod command;
pub mod commissioning;
pub mod description;
pub mod gpdf;
pub mod proxy;
pub mod proxy_table;
pub mod security;
pub mod sink;
pub mod sink_table;
pub mod translation;
pub mod tx_queue;
