//! Panweave Zigbee Device Objects and Device Profile (R23.2 §2.3.2,
//! §2.4, §2.5).
//!
//! * [`descriptor`]: node, power and simple descriptors.
//! * [`zdp`]: ZDP cluster identifiers, status codes and frame codecs.
//! * [`layer`]: the sans-I/O [`Zdo`] with server processing and client
//!   request tracking.
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

pub mod descriptor;
pub mod layer;
pub mod zdp;

pub use descriptor::{NodeDescriptor, PowerDescriptor, ServerMask, SimpleDescriptor};
pub use layer::{Zdo, ZdoAction, ZdoContext, ZdoError, ZdoEvent, ZdoIndication};
pub use zdp::{ZdpStatus, cluster};

use panweave_codec::Writer;
use panweave_types::ShortAddress;

/// Writes the Fragmentation Parameters global TLV advertising this node's
/// `apsMaxSizeASDU` (§2.4.2.8.3) into `buf`; returns the length.
pub fn fragmentation_parameters_tlv(
    buf: &mut [u8],
    node: ShortAddress,
    desc: NodeDescriptor,
) -> usize {
    let mut w = Writer::new(buf);
    let p = panweave_nwk::tlv::FragmentationParameters {
        node,
        options: u8::from(desc.fragmentation_supported),
        max_incoming_transfer_unit: desc.max_incoming_transfer_size,
    };
    match p.write(&mut w) {
        Ok(()) => w.position(),
        Err(_) => 0,
    }
}
