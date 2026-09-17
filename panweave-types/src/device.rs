//! Logical device types and stack roles.

use core::fmt;

/// The Zigbee logical device type (R23.2 §1.1.4, §2.3.2.3.1 node
/// descriptor logical type field).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LogicalDeviceType {
    /// Zigbee coordinator: forms a centralized network, address `0x0000`.
    Coordinator,
    /// Zigbee router: routes frames and accepts children.
    Router,
    /// Zigbee end device: communicates only through its parent.
    EndDevice,
}

impl LogicalDeviceType {
    /// Node descriptor logical type field value (3 bits).
    #[inline]
    pub const fn descriptor_value(self) -> u8 {
        match self {
            LogicalDeviceType::Coordinator => 0,
            LogicalDeviceType::Router => 1,
            LogicalDeviceType::EndDevice => 2,
        }
    }

    /// Parses the node descriptor logical type field.
    #[inline]
    pub const fn from_descriptor_value(v: u8) -> Option<Self> {
        match v {
            0 => Some(LogicalDeviceType::Coordinator),
            1 => Some(LogicalDeviceType::Router),
            2 => Some(LogicalDeviceType::EndDevice),
            _ => None,
        }
    }

    /// True for coordinator and router.
    #[inline]
    pub const fn is_routing_capable(self) -> bool {
        !matches!(self, LogicalDeviceType::EndDevice)
    }
}

impl fmt::Display for LogicalDeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LogicalDeviceType::Coordinator => "coordinator",
            LogicalDeviceType::Router => "router",
            LogicalDeviceType::EndDevice => "end-device",
        })
    }
}

crate::impl_defmt_via_debug!(LogicalDeviceType);

/// The role a Panweave stack instance plays, refining the logical device
/// type with power behaviour.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Role {
    /// Coordinator and Trust Center of a centralized network.
    Coordinator,
    /// Router (may also form a distributed network).
    Router,
    /// End device with the receiver on when idle.
    EndDevice,
    /// Sleepy end device polling its parent for indirect frames.
    SleepyEndDevice,
}

impl Role {
    /// The logical device type reported in descriptors and beacons.
    #[inline]
    pub const fn logical_type(self) -> LogicalDeviceType {
        match self {
            Role::Coordinator => LogicalDeviceType::Coordinator,
            Role::Router => LogicalDeviceType::Router,
            Role::EndDevice | Role::SleepyEndDevice => LogicalDeviceType::EndDevice,
        }
    }

    /// True when the MAC receiver stays on while idle.
    #[inline]
    pub const fn rx_on_when_idle(self) -> bool {
        !matches!(self, Role::SleepyEndDevice)
    }
}

crate::impl_defmt_via_debug!(Role);
