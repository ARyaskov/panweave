//! Protocol identifiers: endpoints, profiles, clusters, attributes,
//! commands, manufacturer codes, counters and sequence numbers.

use core::fmt;

macro_rules! id_newtype {
    ($(#[$m:meta])* $name:ident($inner:ty), $fmt:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(pub $inner);

        impl $name {
            /// Returns the raw wire value.
            #[inline]
            pub const fn raw(self) -> $inner {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "(", $fmt, ")"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, $fmt, self.0)
            }
        }

        impl From<$inner> for $name {
            fn from(v: $inner) -> Self {
                $name(v)
            }
        }

        impl From<$name> for $inner {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        crate::impl_defmt_via_debug!($name);
    };
}

id_newtype!(
    /// A 16-bit application profile identifier (R23.2 §2.3.1).
    ProfileId(u16),
    "0x{:04x}"
);

impl ProfileId {
    /// The Zigbee Device Profile (endpoint 0).
    pub const ZDP: ProfileId = ProfileId(0x0000);
    /// Home Automation profile identifier, used by ZCL-based Zigbee 3.0
    /// application endpoints.
    pub const HOME_AUTOMATION: ProfileId = ProfileId(0x0104);
    /// Smart Energy profile identifier.
    pub const SMART_ENERGY: ProfileId = ProfileId(0x0109);
    /// Green Power profile identifier (GP1.1.2 A.2.4).
    pub const GREEN_POWER: ProfileId = ProfileId(0xA1E0);
    /// Wildcard profile used by Match_Desc_req (R23.2 §2.4.3.1.7).
    pub const WILDCARD: ProfileId = ProfileId(0xFFFF);
}

id_newtype!(
    /// A 16-bit cluster identifier (ZCL8 §2.2.1).
    ClusterId(u16),
    "0x{:04x}"
);

impl ClusterId {
    /// True for manufacturer-specific cluster identifiers (`0xFC00..=0xFFFF`).
    #[inline]
    pub const fn is_manufacturer_specific(self) -> bool {
        self.0 >= 0xFC00
    }
}

id_newtype!(
    /// A 16-bit ZCL attribute identifier (ZCL8 §2.2.1.2).
    AttributeId(u16),
    "0x{:04x}"
);

impl AttributeId {
    /// The global `ClusterRevision` attribute (ZCL8 §2.3.2).
    pub const CLUSTER_REVISION: AttributeId = AttributeId(0xFFFD);
    /// The global `AttributeReportingStatus` attribute (ZCL8 §2.3.2).
    pub const ATTRIBUTE_REPORTING_STATUS: AttributeId = AttributeId(0xFFFE);

    /// True for manufacturer-specific attribute identifiers.
    #[inline]
    pub const fn is_manufacturer_specific(self) -> bool {
        self.0 >= 0xFC00
    }
}

id_newtype!(
    /// An 8-bit ZCL command identifier.
    CommandId(u8),
    "0x{:02x}"
);

id_newtype!(
    /// A 16-bit manufacturer code (ZCL8 §2.4.1.1.2).
    ManufacturerCode(u16),
    "0x{:04x}"
);

id_newtype!(
    /// A 16-bit device identifier from the Device Type Library (DTL2 §1.10).
    DeviceId(u16),
    "0x{:04x}"
);

id_newtype!(
    /// A 32-bit security frame counter (R23.2 §4.5.1.2).
    FrameCounter(u32),
    "{}"
);

impl FrameCounter {
    /// The largest representable value; a counter that reaches it MUST NOT
    /// be used for further transmissions (R23.2 §4.3.4).
    pub const MAX: FrameCounter = FrameCounter(u32::MAX);

    /// Returns the next counter value, or `None` on exhaustion.
    #[inline]
    pub const fn next(self) -> Option<FrameCounter> {
        match self.0.checked_add(1) {
            Some(v) => Some(FrameCounter(v)),
            None => None,
        }
    }
}

id_newtype!(
    /// An 8-bit network key sequence number (R23.2 §4.3.3).
    KeySequenceNumber(u8),
    "{}"
);

impl KeySequenceNumber {
    /// Wrapping increment used when the Trust Center rotates the key.
    #[inline]
    pub const fn wrapping_next(self) -> KeySequenceNumber {
        KeySequenceNumber(self.0.wrapping_add(1))
    }
}

id_newtype!(
    /// An 8-bit transaction sequence number (ZDP and ZCL).
    TransactionSequence(u8),
    "{}"
);

impl TransactionSequence {
    /// Wrapping increment.
    #[inline]
    pub const fn wrapping_next(self) -> TransactionSequence {
        TransactionSequence(self.0.wrapping_add(1))
    }
}

/// An application endpoint number (R23.2 §2.1.2, §2.2.4.1).
///
/// * `0` is the Zigbee Device Object endpoint.
/// * `1..=240` are application endpoints.
/// * `241..=254` are reserved; `242` is assigned to Green Power.
/// * `255` is the broadcast endpoint.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Endpoint(pub u8);

impl Endpoint {
    /// The ZDO endpoint.
    pub const ZDO: Endpoint = Endpoint(0);
    /// The Green Power endpoint (GP1.1.2 A.2.4).
    pub const GREEN_POWER: Endpoint = Endpoint(242);
    /// The broadcast endpoint.
    pub const BROADCAST: Endpoint = Endpoint(255);

    /// Returns the raw value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// True for application endpoints `1..=240`.
    #[inline]
    pub const fn is_application(self) -> bool {
        self.0 >= 1 && self.0 <= 240
    }

    /// True for endpoints that an application may register: `1..=240`
    /// plus the Green Power endpoint.
    #[inline]
    pub const fn is_registrable(self) -> bool {
        self.is_application() || self.0 == 242
    }

    /// True when the value is in the reserved range `241..=254` and not
    /// the Green Power endpoint.
    #[inline]
    pub const fn is_reserved(self) -> bool {
        self.0 >= 241 && self.0 <= 254 && self.0 != 242
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Endpoint({})", self.0)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u8> for Endpoint {
    fn from(v: u8) -> Self {
        Endpoint(v)
    }
}

crate::impl_defmt_via_debug!(Endpoint);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_ranges() {
        assert!(!Endpoint::ZDO.is_application());
        assert!(Endpoint(1).is_application());
        assert!(Endpoint(240).is_application());
        assert!(!Endpoint(241).is_application());
        assert!(Endpoint(241).is_reserved());
        assert!(!Endpoint::GREEN_POWER.is_reserved());
        assert!(Endpoint::GREEN_POWER.is_registrable());
        assert!(!Endpoint::BROADCAST.is_registrable());
    }

    #[test]
    fn frame_counter_exhaustion() {
        assert_eq!(FrameCounter(5).next(), Some(FrameCounter(6)));
        assert_eq!(FrameCounter::MAX.next(), None);
    }

    #[test]
    fn manufacturer_specific_ranges() {
        assert!(ClusterId(0xFC00).is_manufacturer_specific());
        assert!(!ClusterId(0xFBFF).is_manufacturer_specific());
        assert!(AttributeId(0xFFFD).is_manufacturer_specific());
    }
}
