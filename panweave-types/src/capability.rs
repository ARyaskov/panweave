//! IEEE 802.15.4 capability information as used by Zigbee joining
//! (R23.2 Annex D.4, §3.4.6 Rejoin Request, §2.4.3.1.11 Device_annce).

use core::fmt;

/// The 8-bit MAC capability information field.
///
/// Bit layout (least significant first): alternate PAN coordinator, device
/// type (1 = full-function device / router), power source (1 = mains),
/// receiver on when idle, two reserved bits, security capability,
/// allocate address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacCapability(pub u8);

impl MacCapability {
    const ALTERNATE_PAN_COORDINATOR: u8 = 1 << 0;
    const DEVICE_TYPE_FFD: u8 = 1 << 1;
    const POWER_SOURCE_MAINS: u8 = 1 << 2;
    const RX_ON_WHEN_IDLE: u8 = 1 << 3;
    const RESERVED_MASK: u8 = 0b0011_0000;
    const SECURITY_CAPABLE: u8 = 1 << 6;
    const ALLOCATE_ADDRESS: u8 = 1 << 7;

    /// Capability value typical for a mains-powered router: FFD, mains
    /// power, receiver on when idle, allocate address.
    pub const ROUTER: MacCapability = MacCapability(
        Self::DEVICE_TYPE_FFD
            | Self::POWER_SOURCE_MAINS
            | Self::RX_ON_WHEN_IDLE
            | Self::ALLOCATE_ADDRESS,
    );

    /// Capability value typical for a non-sleepy end device.
    pub const END_DEVICE_RX_ON: MacCapability =
        MacCapability(Self::RX_ON_WHEN_IDLE | Self::ALLOCATE_ADDRESS);

    /// Capability value typical for a sleepy (battery) end device.
    pub const SLEEPY_END_DEVICE: MacCapability = MacCapability(Self::ALLOCATE_ADDRESS);

    /// Builds from the raw wire octet, preserving reserved bits.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        MacCapability(v)
    }

    /// Raw wire octet.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// True when the reserved bits are zero.
    #[inline]
    pub const fn reserved_bits_clear(self) -> bool {
        self.0 & Self::RESERVED_MASK == 0
    }

    /// Alternate PAN coordinator bit (always zero for Zigbee).
    #[inline]
    pub const fn alternate_pan_coordinator(self) -> bool {
        self.0 & Self::ALTERNATE_PAN_COORDINATOR != 0
    }

    /// True when the device is a full-function device (router capable).
    #[inline]
    pub const fn is_full_function_device(self) -> bool {
        self.0 & Self::DEVICE_TYPE_FFD != 0
    }

    /// True when mains powered.
    #[inline]
    pub const fn is_mains_powered(self) -> bool {
        self.0 & Self::POWER_SOURCE_MAINS != 0
    }

    /// True when the receiver stays on while idle.
    #[inline]
    pub const fn rx_on_when_idle(self) -> bool {
        self.0 & Self::RX_ON_WHEN_IDLE != 0
    }

    /// True when the device is security capable (MAC security; unused by
    /// Zigbee but carried on the wire).
    #[inline]
    pub const fn security_capable(self) -> bool {
        self.0 & Self::SECURITY_CAPABLE != 0
    }

    /// True when the joiner asks the parent to allocate a short address.
    #[inline]
    pub const fn allocate_address(self) -> bool {
        self.0 & Self::ALLOCATE_ADDRESS != 0
    }

    /// Returns a copy with the FFD bit set as given.
    #[inline]
    pub const fn with_full_function_device(self, v: bool) -> Self {
        self.with_bit(Self::DEVICE_TYPE_FFD, v)
    }

    /// Returns a copy with the mains-powered bit set as given.
    #[inline]
    pub const fn with_mains_powered(self, v: bool) -> Self {
        self.with_bit(Self::POWER_SOURCE_MAINS, v)
    }

    /// Returns a copy with the receiver-on-when-idle bit set as given.
    #[inline]
    pub const fn with_rx_on_when_idle(self, v: bool) -> Self {
        self.with_bit(Self::RX_ON_WHEN_IDLE, v)
    }

    /// Returns a copy with the allocate-address bit set as given.
    #[inline]
    pub const fn with_allocate_address(self, v: bool) -> Self {
        self.with_bit(Self::ALLOCATE_ADDRESS, v)
    }

    /// Returns a copy with the security-capable bit set as given.
    #[inline]
    pub const fn with_security_capable(self, v: bool) -> Self {
        self.with_bit(Self::SECURITY_CAPABLE, v)
    }

    #[inline]
    const fn with_bit(self, bit: u8, v: bool) -> Self {
        if v {
            MacCapability(self.0 | bit)
        } else {
            MacCapability(self.0 & !bit)
        }
    }
}

impl fmt::Debug for MacCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacCapability")
            .field("raw", &format_args!("0x{:02x}", self.0))
            .field("ffd", &self.is_full_function_device())
            .field("mains", &self.is_mains_powered())
            .field("rx_on_when_idle", &self.rx_on_when_idle())
            .field("security", &self.security_capable())
            .field("allocate_address", &self.allocate_address())
            .finish()
    }
}

crate::impl_defmt_via_debug!(MacCapability);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_capability_bits() {
        let c = MacCapability::ROUTER;
        assert_eq!(c.raw(), 0x8E);
        assert!(c.is_full_function_device());
        assert!(c.is_mains_powered());
        assert!(c.rx_on_when_idle());
        assert!(c.allocate_address());
        assert!(!c.security_capable());
        assert!(c.reserved_bits_clear());
    }

    #[test]
    fn sleepy_end_device_capability_bits() {
        let c = MacCapability::SLEEPY_END_DEVICE;
        assert_eq!(c.raw(), 0x80);
        assert!(!c.is_full_function_device());
        assert!(!c.rx_on_when_idle());
        let c2 = c.with_rx_on_when_idle(true);
        assert_eq!(c2.raw(), 0x88);
        assert!(!MacCapability::from_raw(0x30).reserved_bits_clear());
    }
}
