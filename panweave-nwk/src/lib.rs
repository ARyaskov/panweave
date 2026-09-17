//! Zigbee network layer (R23.2 chapter 3) for Panweave.
//!
//! * [`frame`] — NPDU header/frame codec (§3.3).
//! * [`command`] — NWK command codecs (§3.4).
//! * [`tlv`] — global TLVs (Annex I.4).
//! * [`beacon`] — beacon payload and appendix (§3.6.8).
//! * [`nib`] — constants and the NWK information base (§3.5).
//! * [`neighbor`], [`routing`], [`broadcast`], [`discovery`],
//!   [`address_map`] — the NIB tables.
//! * [`security`] — NWK frame protection using `panweave-security`
//!   (§4.3).
//! * [`layer`] — the sans-I/O [`layer::Nwk`] state machine: discovery,
//!   formation, joining, rejoining, leaving, routing, broadcast, child
//!   aging and link status (§3.6).

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

pub mod address_map;
pub mod beacon;
pub mod broadcast;
pub mod command;
pub mod discovery;
pub mod frame;
pub mod interface;
pub mod joining_list;
pub mod layer;
pub mod neighbor;
pub mod nib;
pub mod routing;
pub mod security;
pub mod tlv;

pub use frame::{DiscoverRoute, Frame, FrameControl, FrameType, Header};
pub use layer::{Nwk, NwkAction, NwkConfig, NwkError, NwkEvent, NwkRequest, RxOutcome};
pub use nib::Nib;
