//! Smart Energy 1.4a (CSA 07-5356-22): the profile's parameters and
//! security policy, the Key Establishment cluster (Annex C) with the
//! certificate-based key establishment machine, and the Smart Energy
//! clusters. See `docs/architecture.md`.
//!
//! The elliptic-curve arithmetic of the CBKE suites (ECMQV over
//! sect163k1 / sect283k1) is not implemented in this workspace: it enters
//! through the [`key_establishment::Ecmqv`] trait so that a validated
//! library can be plugged in (ADR-0012).
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

pub mod clusters;
pub mod commissioning;
pub mod devices;
pub mod interpan;
pub mod key_establishment;
pub mod profile;
pub mod security;

use panweave_types::{ClusterId, ProfileId};

/// The Smart Energy profile identifier.
pub const PROFILE_ID: ProfileId = ProfileId(0x0109);

/// Cluster identifiers used by the profile (Table 5-14).
pub mod cluster {
    use panweave_types::ClusterId;

    /// Key Establishment.
    pub const KEY_ESTABLISHMENT: ClusterId = ClusterId(0x0800);
    /// Price.
    pub const PRICE: ClusterId = ClusterId(0x0700);
    /// Demand Response and Load Control.
    pub const DEMAND_RESPONSE_LOAD_CONTROL: ClusterId = ClusterId(0x0701);
    /// Metering.
    pub const METERING: ClusterId = ClusterId(0x0702);
    /// Messaging.
    pub const MESSAGING: ClusterId = ClusterId(0x0703);
    /// Smart Energy Tunneling.
    pub const TUNNELING: ClusterId = ClusterId(0x0704);
    /// Prepayment.
    pub const PREPAYMENT: ClusterId = ClusterId(0x0705);
    /// Energy Management.
    pub const ENERGY_MANAGEMENT: ClusterId = ClusterId(0x0706);
    /// Calendar.
    pub const CALENDAR: ClusterId = ClusterId(0x0707);
    /// Device Management.
    pub const DEVICE_MANAGEMENT: ClusterId = ClusterId(0x0708);
    /// Events.
    pub const EVENTS: ClusterId = ClusterId(0x0709);
    /// MDU Pairing.
    pub const MDU_PAIRING: ClusterId = ClusterId(0x070A);
    /// Sub-GHz.
    pub const SUB_GHZ: ClusterId = ClusterId(0x070B);
    /// Over-the-Air Bootload (general).
    pub const OTA_UPGRADE: ClusterId = ClusterId(0x0019);
    /// Keep-Alive (general, Annex A.3).
    pub const KEEP_ALIVE: ClusterId = ClusterId(0x0025);
    /// Time (general).
    pub const TIME: ClusterId = ClusterId(0x000A);
    /// Alarms (general).
    pub const ALARMS: ClusterId = ClusterId(0x0009);
    /// Commissioning (general).
    pub const COMMISSIONING: ClusterId = ClusterId(0x0015);
    /// Power Configuration (general).
    pub const POWER_CONFIGURATION: ClusterId = ClusterId(0x0001);
    /// Basic (general).
    pub const BASIC: ClusterId = ClusterId(0x0000);
    /// Identify (general).
    pub const IDENTIFY: ClusterId = ClusterId(0x0003);
}

/// Whether frames of `cluster` on a Smart Energy endpoint must carry
/// APS link-key security (§5.4.6, Table 5-12). Clusters the table does
/// not list, including manufacturer-specific ones, require it too
/// (§5.4.6: any cluster added to a Smart Energy endpoint is APS
/// encrypted). A receiver answers an unsecured frame of a cluster that
/// requires it with a Default Response of status FAILURE.
pub const fn link_key_required(cluster: ClusterId) -> bool {
    !matches!(
        cluster.0,
        // Basic, Identify and Time are exempt; Key Establishment must be
        // exempt since it creates the key (its Annex C.5.2 frames carry
        // no APS security). Power Configuration and Keep-Alive follow
        // ADR-0012 (table rows unreadable in the source, treated as
        // exempt like the other network-key-only general clusters).
        0x0000 | 0x0003 | 0x000A | 0x0800 | 0x0001 | 0x0025
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_policy() {
        assert!(!link_key_required(cluster::BASIC));
        assert!(!link_key_required(cluster::KEY_ESTABLISHMENT));
        assert!(link_key_required(cluster::ALARMS));
        assert!(link_key_required(cluster::COMMISSIONING));
        assert!(link_key_required(cluster::PRICE));
        assert!(link_key_required(cluster::SUB_GHZ));
        assert!(link_key_required(cluster::OTA_UPGRADE));
        assert!(link_key_required(ClusterId(0xFC00)));
    }
}
