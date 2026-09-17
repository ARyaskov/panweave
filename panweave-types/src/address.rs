//! Addressing types: PAN identifiers, 16-bit network addresses, 64-bit
//! IEEE addresses and group addresses.
//!
//! Spec: R23.2 §3.3.1.2, §3.6.1.7 (address assignment), Table 3-80
//! (broadcast addresses), §2.2.4.1 (APS addressing modes).

use core::fmt;

/// A 16-bit IEEE 802.15.4 PAN identifier.
///
/// `0xFFFF` is the broadcast PAN identifier and is never a valid operational
/// PAN ID for a Zigbee network (R23.2 §3.6.1.2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PanId(pub u16);

impl PanId {
    /// The broadcast PAN identifier (`0xFFFF`).
    pub const BROADCAST: PanId = PanId(0xFFFF);

    /// Returns the raw value.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// True when this PAN ID may be used to form a network (not broadcast).
    #[inline]
    pub const fn is_valid_for_formation(self) -> bool {
        self.0 != 0xFFFF
    }
}

impl fmt::Debug for PanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PanId(0x{:04x})", self.0)
    }
}

impl fmt::Display for PanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

impl From<u16> for PanId {
    fn from(v: u16) -> Self {
        PanId(v)
    }
}

crate::impl_defmt_via_debug!(PanId);

/// Classification of a 16-bit network address value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ShortAddressKind {
    /// A unicast device address (`0x0000..=0xFFF7`).
    Unicast,
    /// Reserved range (`0xFFF8..=0xFFFA`).
    Reserved,
    /// Broadcast to low-power routers only (`0xFFFB`).
    BroadcastLowPowerRouters,
    /// Broadcast to all routers and the coordinator (`0xFFFC`).
    BroadcastRouters,
    /// Broadcast to all devices with `macRxOnWhenIdle = TRUE` (`0xFFFD`).
    BroadcastRxOnWhenIdle,
    /// Reserved value `0xFFFE`, also used by the MAC as "no short address".
    NoShortAddress,
    /// Broadcast to all devices (`0xFFFF`).
    BroadcastAll,
}

/// A 16-bit Zigbee network (short) address.
///
/// Spec: R23.2 §3.3.1.2, Table 3-80.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShortAddress(pub u16);

impl ShortAddress {
    /// The coordinator address on a centralized network.
    pub const COORDINATOR: ShortAddress = ShortAddress(0x0000);
    /// Broadcast to every device in the PAN.
    pub const BROADCAST_ALL: ShortAddress = ShortAddress(0xFFFF);
    /// Broadcast to every device that keeps its receiver on when idle.
    pub const BROADCAST_RX_ON: ShortAddress = ShortAddress(0xFFFD);
    /// Broadcast to all routers and the coordinator.
    pub const BROADCAST_ROUTERS: ShortAddress = ShortAddress(0xFFFC);
    /// Broadcast to low-power routers only.
    pub const BROADCAST_LOW_POWER_ROUTERS: ShortAddress = ShortAddress(0xFFFB);
    /// The MAC "no short address" / unknown marker (`0xFFFE`).
    pub const NO_SHORT_ADDRESS: ShortAddress = ShortAddress(0xFFFE);
    /// Highest unicast address.
    pub const MAX_UNICAST: ShortAddress = ShortAddress(0xFFF7);

    /// Returns the raw value.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Classifies the address value.
    #[inline]
    pub const fn kind(self) -> ShortAddressKind {
        match self.0 {
            0x0000..=0xFFF7 => ShortAddressKind::Unicast,
            0xFFF8..=0xFFFA => ShortAddressKind::Reserved,
            0xFFFB => ShortAddressKind::BroadcastLowPowerRouters,
            0xFFFC => ShortAddressKind::BroadcastRouters,
            0xFFFD => ShortAddressKind::BroadcastRxOnWhenIdle,
            0xFFFE => ShortAddressKind::NoShortAddress,
            0xFFFF => ShortAddressKind::BroadcastAll,
        }
    }

    /// True for any of the defined broadcast addresses.
    #[inline]
    pub const fn is_broadcast(self) -> bool {
        matches!(
            self.kind(),
            ShortAddressKind::BroadcastAll
                | ShortAddressKind::BroadcastRxOnWhenIdle
                | ShortAddressKind::BroadcastRouters
                | ShortAddressKind::BroadcastLowPowerRouters
        )
    }

    /// True for a unicast address.
    #[inline]
    pub const fn is_unicast(self) -> bool {
        matches!(self.kind(), ShortAddressKind::Unicast)
    }

    /// True when the address is in the range a stochastic address
    /// allocator may hand out (R23.2 §3.6.1.7): unicast and not the
    /// coordinator address.
    #[inline]
    pub const fn is_assignable(self) -> bool {
        self.0 != 0x0000 && self.is_unicast()
    }
}

impl fmt::Debug for ShortAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShortAddress(0x{:04x})", self.0)
    }
}

impl fmt::Display for ShortAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

impl From<u16> for ShortAddress {
    fn from(v: u16) -> Self {
        ShortAddress(v)
    }
}

crate::impl_defmt_via_debug!(ShortAddress);

/// A 64-bit IEEE (extended / EUI-64) address.
///
/// Stored in host order; the wire encoding is little-endian
/// (R23.2 §1.2.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedAddress(pub u64);

impl ExtendedAddress {
    /// All-zero address; used as the "not present / unknown" marker in
    /// several tables.
    pub const ZERO: ExtendedAddress = ExtendedAddress(0);
    /// All-ones address; the Trust Center address of a distributed
    /// security network (R23.2 §4.8.1) and the "any device" marker.
    pub const BROADCAST: ExtendedAddress = ExtendedAddress(u64::MAX);

    /// Returns the raw value.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Little-endian wire bytes.
    #[inline]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Builds from little-endian wire bytes.
    #[inline]
    pub const fn from_le_bytes(b: [u8; 8]) -> Self {
        ExtendedAddress(u64::from_le_bytes(b))
    }

    /// True when the address is neither all-zero nor all-ones.
    #[inline]
    pub const fn is_valid_device_address(self) -> bool {
        self.0 != 0 && self.0 != u64::MAX
    }
}

impl fmt::Debug for ExtendedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtendedAddress({self})")
    }
}

impl fmt::Display for ExtendedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0.to_be_bytes();
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
        )
    }
}

impl From<u64> for ExtendedAddress {
    fn from(v: u64) -> Self {
        ExtendedAddress(v)
    }
}

crate::impl_defmt_via_debug!(ExtendedAddress);

/// A 16-bit APS group address (R23.2 §2.2.4.1, §2.2.8.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupAddress(pub u16);

impl GroupAddress {
    /// Returns the raw value.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for GroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupAddress(0x{:04x})", self.0)
    }
}

impl fmt::Display for GroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

impl From<u16> for GroupAddress {
    fn from(v: u16) -> Self {
        GroupAddress(v)
    }
}

crate::impl_defmt_via_debug!(GroupAddress);

/// A device address in either short or extended form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Address {
    /// 16-bit network address.
    Short(ShortAddress),
    /// 64-bit IEEE address.
    Extended(ExtendedAddress),
}

impl Address {
    /// Returns the short address when this is a short address.
    #[inline]
    pub const fn short(self) -> Option<ShortAddress> {
        match self {
            Address::Short(s) => Some(s),
            Address::Extended(_) => None,
        }
    }

    /// Returns the extended address when this is an extended address.
    #[inline]
    pub const fn extended(self) -> Option<ExtendedAddress> {
        match self {
            Address::Extended(e) => Some(e),
            Address::Short(_) => None,
        }
    }
}

impl From<ShortAddress> for Address {
    fn from(v: ShortAddress) -> Self {
        Address::Short(v)
    }
}

impl From<ExtendedAddress> for Address {
    fn from(v: ExtendedAddress) -> Self {
        Address::Extended(v)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Short(s) => write!(f, "{s}"),
            Address::Extended(e) => write!(f, "{e}"),
        }
    }
}

crate::impl_defmt_via_debug!(Address);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_address_classification_matches_table_3_80() {
        assert_eq!(ShortAddress(0x0000).kind(), ShortAddressKind::Unicast);
        assert_eq!(ShortAddress(0xFFF7).kind(), ShortAddressKind::Unicast);
        assert_eq!(ShortAddress(0xFFF8).kind(), ShortAddressKind::Reserved);
        assert_eq!(ShortAddress(0xFFFA).kind(), ShortAddressKind::Reserved);
        assert_eq!(
            ShortAddress(0xFFFB).kind(),
            ShortAddressKind::BroadcastLowPowerRouters
        );
        assert_eq!(
            ShortAddress(0xFFFC).kind(),
            ShortAddressKind::BroadcastRouters
        );
        assert_eq!(
            ShortAddress(0xFFFD).kind(),
            ShortAddressKind::BroadcastRxOnWhenIdle
        );
        assert_eq!(
            ShortAddress(0xFFFE).kind(),
            ShortAddressKind::NoShortAddress
        );
        assert_eq!(ShortAddress(0xFFFF).kind(), ShortAddressKind::BroadcastAll);
        assert!(ShortAddress::BROADCAST_ALL.is_broadcast());
        assert!(!ShortAddress::NO_SHORT_ADDRESS.is_broadcast());
        assert!(!ShortAddress::COORDINATOR.is_assignable());
        assert!(ShortAddress(0x1234).is_assignable());
    }

    #[test]
    fn extended_address_formatting_and_bytes() {
        let a = ExtendedAddress(0x0011_2233_4455_6677);
        assert_eq!(
            a.to_le_bytes(),
            [0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]
        );
        assert_eq!(ExtendedAddress::from_le_bytes(a.to_le_bytes()), a);
        assert!(a.is_valid_device_address());
        assert!(!ExtendedAddress::ZERO.is_valid_device_address());
        assert!(!ExtendedAddress::BROADCAST.is_valid_device_address());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn extended_address_display_is_colon_separated_big_endian() {
        use alloc::string::ToString;
        let a = ExtendedAddress(0x0011_2233_4455_6677);
        assert_eq!(a.to_string(), "00:11:22:33:44:55:66:77");
    }
}
