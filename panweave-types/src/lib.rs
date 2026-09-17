//! Core strongly typed values shared by every Panweave crate.
//!
//! This crate is `no_std`, allocation-free, and has no I/O. It defines the
//! vocabulary of the protocol — addresses, identifiers, keys, status codes,
//! time — so that higher layers never pass raw integers around.
//!
//! Design rules (see `docs/architecture.md`):
//!
//! * every wire value space is an explicit type;
//! * enumerations with reserved or future values carry an `Unknown(u8)`
//!   style variant so that a conforming future value is never rejected by
//!   accident;
//! * conversions from wire integers are checked and never panic;
//! * secret-bearing types redact `Debug` and zeroize on drop.

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

pub mod address;
pub mod capability;
pub mod channel;
pub mod device;
pub mod ids;
pub mod key;
pub mod rng;
pub mod status;
pub mod time;

pub use address::{Address, ExtendedAddress, GroupAddress, PanId, ShortAddress, ShortAddressKind};
pub use capability::MacCapability;
pub use channel::{Channel, ChannelMask, ChannelPage};
pub use device::{LogicalDeviceType, Role};
pub use ids::{
    AttributeId, ClusterId, CommandId, DeviceId, Endpoint, FrameCounter, KeySequenceNumber,
    ManufacturerCode, ProfileId, TransactionSequence,
};
pub use key::{InstallCode, Key128, KeyAttributes, KeyType};
pub use rng::{CryptoRng, Rng};
pub use status::{ApsStatus, MacStatus, NwkStatus};
pub use time::{Duration, Instant};

/// Helper macro to implement `defmt::Format` only when the feature is on.
#[doc(hidden)]
#[macro_export]
macro_rules! impl_defmt_via_debug {
    ($t:ty) => {
        #[cfg(feature = "defmt")]
        impl defmt::Format for $t {
            fn format(&self, fmt: defmt::Formatter) {
                defmt::write!(fmt, "{}", defmt::Debug2Format(self));
            }
        }
    };
}
