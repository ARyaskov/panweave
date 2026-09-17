//! Device Type Library (document 23-02016-002): device identifiers, their
//! device class and mandatory clusters, cluster classification for
//! finding & binding, and endpoint validation.
//!
//! The device table is generated from `metadata/devices.toml` by
//! `cargo xtask codegen` (`generated.rs`). Only identifiers are recorded:
//! the mandatory server and client clusters of each device as listed in
//! its PICS table. Optional clusters, attribute lists and command
//! requirements are not modelled.
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

use panweave_types::{ClusterId, DeviceId};

// Generated output is rustfmt-stable by construction; keep the
// generator's layout so `cargo xtask codegen --check` stays exact.
#[rustfmt::skip]
mod generated;

pub use generated::DEVICES;

/// Device class (DTL §1.10, Application Architecture §5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DeviceClass {
    /// A fixed set of clusters; finding & binding is mandatory for its
    /// application clusters.
    Simple,
    /// Clusters chosen at commissioning time (gateways, tools).
    Dynamic,
    /// A node-level device without application clusters (range extender).
    Node,
}

/// One device type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceType {
    /// Device identifier (Table 3).
    pub id: DeviceId,
    /// Name as listed in Table 3.
    pub name: &'static str,
    /// Device class.
    pub class: DeviceClass,
    /// Section of the library defining the device.
    pub section: &'static str,
    /// Mandatory server (input) clusters.
    pub servers: &'static [ClusterId],
    /// Mandatory client (output) clusters.
    pub clients: &'static [ClusterId],
}

impl DeviceType {
    /// Looks a device type up by identifier.
    pub fn lookup(id: DeviceId) -> Option<&'static DeviceType> {
        DEVICES
            .binary_search_by_key(&id.0, |d| d.id.0)
            .ok()
            .and_then(|i| DEVICES.get(i))
    }

    /// Mandatory clusters missing from an endpoint that declares
    /// `servers` / `clients` (a simple descriptor's input / output lists).
    /// Returns the number written to `missing` (server clusters first).
    pub fn missing(
        &self,
        servers: &[ClusterId],
        clients: &[ClusterId],
        missing: &mut [(ClusterId, Side)],
    ) -> usize {
        let mut n = 0;
        for c in self.servers {
            if !servers.contains(c) {
                if let Some(slot) = missing.get_mut(n) {
                    *slot = (*c, Side::Server);
                }
                n += 1;
            }
        }
        for c in self.clients {
            if !clients.contains(c) {
                if let Some(slot) = missing.get_mut(n) {
                    *slot = (*c, Side::Client);
                }
                n += 1;
            }
        }
        n
    }

    /// True when the endpoint declares every mandatory cluster.
    pub fn conforms(&self, servers: &[ClusterId], clients: &[ClusterId]) -> bool {
        self.missing(servers, clients, &mut []) == 0
    }
}

/// Which side of a cluster.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Side {
    /// Server (input cluster).
    Server,
    /// Client (output cluster).
    Client,
}

/// Cluster classification (ZCL8 chapter 3 "Classification" tables, DTL
/// §1.6 definitions).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClusterClass {
    /// Not part of the application function (commissioning,
    /// configuration, discovery, diagnostics, …).
    Utility,
    /// Application cluster whose transactions go client → server.
    Type1,
    /// Application cluster whose transactions go server → client.
    Type2,
    /// Application cluster without a primary transaction direction.
    Application,
}

/// Classification of the general, lighting, measurement, HVAC, closure,
/// security, smart energy and commissioning clusters of ZCL8.
pub const fn classify(cluster: ClusterId) -> ClusterClass {
    match cluster.0 {
        0x0000..=0x0004
        | 0x000B
        | 0x0015
        | 0x0019..=0x001A
        | 0x0020
        | 0x0022..=0x0025
        | 0x0B05
        | 0x1000 => ClusterClass::Utility,
        0x0005
        | 0x0006
        | 0x0008
        | 0x0016
        | 0x001C
        | 0x0102
        | 0x0103
        | 0x0202..=0x0204
        | 0x0300
        | 0x0301
        | 0x0501
        | 0x0600
        | 0x0615
        | 0x0617
        | 0x0700..=0x0703
        | 0x0705
        | 0x0707
        | 0x0709
        | 0x070B
        | 0x0904
        | 0x0905
        | 0x0B04 => ClusterClass::Type1,
        0x0007
        | 0x0009
        | 0x000C..=0x0014
        | 0x001B
        | 0x0100
        | 0x0101
        | 0x0200
        | 0x0201
        | 0x0400..=0x0407
        | 0x040A
        | 0x040B
        | 0x0500
        | 0x0502
        | 0x0602..=0x0613
        | 0x0900
        | 0x0B00..=0x0B03 => ClusterClass::Type2,
        _ => ClusterClass::Application,
    }
}

/// Whether an endpoint acts as finding & binding *initiator* for a
/// cluster instance (BDB 3.1 §11: type 1 client or type 2 server) or as
/// *target* (type 1 server or type 2 client). `None` for utility and
/// unclassified clusters.
pub const fn finding_binding_role(cluster: ClusterId, server: bool) -> Option<FbRole> {
    match (classify(cluster), server) {
        (ClusterClass::Type1, false) | (ClusterClass::Type2, true) => Some(FbRole::Initiator),
        (ClusterClass::Type1, true) | (ClusterClass::Type2, false) => Some(FbRole::Target),
        _ => None,
    }
}

/// Finding & binding role of a cluster instance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FbRole {
    /// Broadcasts Identify Query and creates bindings.
    Initiator,
    /// Identifies and answers Identify Query.
    Target,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_lookup_works() {
        assert!(DEVICES.windows(2).all(|w| w[0].id.0 < w[1].id.0));
        let light = DeviceType::lookup(DeviceId(0x0100)).unwrap();
        assert_eq!(light.name, "On/Off Light");
        assert_eq!(light.class, DeviceClass::Simple);
        assert!(light.servers.contains(&ClusterId(0x0006)));
        assert!(light.servers.contains(&ClusterId(0x0004)));
        assert!(light.clients.is_empty());
        let switch = DeviceType::lookup(DeviceId(0x0103)).unwrap();
        assert!(switch.clients.contains(&ClusterId(0x0006)));
        assert!(DeviceType::lookup(DeviceId(0xFFFF)).is_none());
    }

    #[test]
    fn missing_clusters_are_reported() {
        let light = DeviceType::lookup(DeviceId(0x0100)).unwrap();
        let mut missing = [(ClusterId(0), Side::Server); 8];
        let n = light.missing(
            &[ClusterId(0x0000), ClusterId(0x0003), ClusterId(0x0006)],
            &[],
            &mut missing,
        );
        assert_eq!(n, 2);
        assert!(missing[..n].contains(&(ClusterId(0x0004), Side::Server)));
        assert!(missing[..n].contains(&(ClusterId(0x0005), Side::Server)));
        assert!(!light.conforms(&[ClusterId(0)], &[]));
        assert!(light.conforms(light.servers, light.clients));
    }

    #[test]
    fn classification_and_finding_binding_roles() {
        assert_eq!(classify(ClusterId(0x0003)), ClusterClass::Utility);
        assert_eq!(classify(ClusterId(0x0006)), ClusterClass::Type1);
        assert_eq!(classify(ClusterId(0x0402)), ClusterClass::Type2);
        assert_eq!(
            finding_binding_role(ClusterId(0x0006), false),
            Some(FbRole::Initiator)
        );
        assert_eq!(
            finding_binding_role(ClusterId(0x0006), true),
            Some(FbRole::Target)
        );
        assert_eq!(
            finding_binding_role(ClusterId(0x0402), true),
            Some(FbRole::Initiator)
        );
        assert_eq!(finding_binding_role(ClusterId(0x0004), true), None);
    }
}
