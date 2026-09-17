//! Security services for Panweave (R23.2 chapter 4 and Annexes A–C, J).
//!
//! Layers of this crate:
//!
//! * [`cipher`] — the [`cipher::BlockCipher`] abstraction (AES-128) with a
//!   software back-end behind the `crypto-software` feature.
//! * [`ccm`] — CCM* mode per Annex A (L = 2, M ∈ {0, 4, 8, 16}).
//! * [`mmo`] — AES-MMO hash and HMAC per Annex B.4 / B.1.4.
//! * [`key_hierarchy`] — key-transport / key-load key derivation
//!   (§4.5.3), install-code key derivation (BDB3.1 §6.11).
//! * [`aux_header`] — the auxiliary security header (§4.5.1) and CCM
//!   nonce (§4.5.2.2).
//! * [`frame_counter`] — outgoing counters with persistence reservation
//!   windows and incoming freshness tables (§4.3.4, §4.3.1.2).
//! * [`material`] — network security material set and link key table
//!   (§4.3.3, §4.4.12).
//! * [`frame`] — NWK and APS frame protection / unprotection (§4.3.1,
//!   §4.4.1).
//! * [`trust_center`] — Trust Center policy evaluation (§4.7.1).
//! * [`dlk`] — dynamic link key negotiation (§4.4.9, Annex J), behind the
//!   `dlk` feature.
//!
//! Secret-bearing types never print key material. See
//! `docs/security-model.md`.

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

pub mod aux_header;
pub mod ccm;
pub mod challenge;
pub mod cipher;
#[cfg(feature = "dlk")]
pub mod dlk;
pub mod frame;
pub mod frame_counter;
pub mod key_hierarchy;
pub mod material;
pub mod mmo;
pub mod touchlink;
pub mod trust_center;

pub use aux_header::{AuxHeader, KeyIdentifier, SecurityControl, SecurityLevel};
pub use cipher::BlockCipher;
#[cfg(feature = "crypto-software")]
pub use cipher::SoftwareAes;
pub use frame::{SecurityError, SecurityResult};
pub use frame_counter::{IncomingCounters, OutgoingCounter, Reservation};
pub use material::{LinkKeyEntry, LinkKeyTable, NetworkKeySlot, NetworkKeys};
pub use trust_center::{JoinDecision, TrustCenterPolicy};
