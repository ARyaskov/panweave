//! Layer status enumerations that appear on the wire or in confirmations.
//!
//! * [`NwkStatus`]: R23.2 §3.7, Table 3-84.
//! * [`ApsStatus`]: R23.2 §2.2.9, Table 2-29.
//! * [`MacStatus`]: IEEE 802.15.4-2006 numeric values, as required by
//!   R23.2 Annex D.2 for values carried over the air.

macro_rules! status_enum {
    (
        $(#[$m:meta])*
        $name:ident {
            $( $(#[$vm:meta])* $variant:ident = $value:literal ),* $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub enum $name {
            $( $(#[$vm])* $variant, )*
            /// A value not defined by the implemented revision.
            Unknown(u8),
        }

        impl $name {
            /// Wire value.
            #[inline]
            pub const fn raw(self) -> u8 {
                match self {
                    $( $name::$variant => $value, )*
                    $name::Unknown(v) => v,
                }
            }

            /// Parses a wire value; unknown values are preserved.
            #[inline]
            pub const fn from_raw(v: u8) -> Self {
                match v {
                    $( $value => $name::$variant, )*
                    other => $name::Unknown(other),
                }
            }

            /// True for `Success`.
            #[inline]
            pub const fn is_success(self) -> bool {
                matches!(self, $name::Success)
            }
        }

        impl From<u8> for $name {
            fn from(v: u8) -> Self { $name::from_raw(v) }
        }

        impl From<$name> for u8 {
            fn from(v: $name) -> u8 { v.raw() }
        }

        crate::impl_defmt_via_debug!($name);
    };
}

status_enum! {
    /// NWK layer status values (R23.2 §3.7).
    NwkStatus {
        /// The request completed successfully.
        Success = 0x00,
        /// A parameter was invalid or out of range.
        InvalidParameter = 0xC1,
        /// The request is invalid in the current NWK state.
        InvalidRequest = 0xC2,
        /// A join request was disallowed.
        NotPermitted = 0xC3,
        /// Network formation failed.
        StartupFailure = 0xC4,
        /// The neighbor already exists.
        AlreadyPresent = 0xC5,
        /// A sync request failed at the MAC.
        SyncFailure = 0xC6,
        /// The neighbor table is full.
        NeighborTableFull = 0xC7,
        /// The addressed device is not in the neighbor table.
        UnknownDevice = 0xC8,
        /// Unknown NIB attribute.
        UnsupportedAttribute = 0xC9,
        /// No networks were found.
        NoNetworks = 0xCA,
        /// Outgoing frame counter exhausted.
        MaxFrameCounter = 0xCC,
        /// No key available for security processing.
        NoKey = 0xCD,
        /// The security engine produced bad output.
        BadCcmOutput = 0xCE,
        /// Route discovery failed for a non-capacity reason.
        RouteDiscoveryFailed = 0xD0,
        /// A routing failure occurred.
        RouteError = 0xD1,
        /// Broadcast transaction table full.
        BtTableFull = 0xD2,
        /// Insufficient buffering.
        FrameNotBuffered = 0xD3,
        /// The MAC interface is disabled or unknown.
        InvalidInterface = 0xD5,
        /// A required TLV was missing.
        MissingTlv = 0xD6,
        /// A TLV was malformed.
        InvalidTlv = 0xD7,
    }
}

status_enum! {
    /// APS sub-layer status values (R23.2 §2.2.9).
    ApsStatus {
        /// The request completed successfully.
        Success = 0x00,
        /// The ASDU is too long and fragmentation is unavailable.
        AsduTooLong = 0xA0,
        /// Defragmentation deferred.
        DefragDeferred = 0xA1,
        /// Fragmentation unsupported.
        DefragUnsupported = 0xA2,
        /// A parameter was out of range.
        IllegalRequest = 0xA3,
        /// The binding does not exist.
        InvalidBinding = 0xA4,
        /// The group does not exist.
        InvalidGroup = 0xA5,
        /// A parameter was invalid.
        InvalidParameter = 0xA6,
        /// No acknowledgement was received.
        NoAck = 0xA7,
        /// No bound device.
        NoBoundDevice = 0xA8,
        /// No short address known for the extended address.
        NoShortAddress = 0xA9,
        /// Binding is not supported.
        NotSupported = 0xAA,
        /// The received ASDU was secured with a link key.
        SecuredLinkKey = 0xAB,
        /// The received ASDU was secured with a network key.
        SecuredNwkKey = 0xAC,
        /// Security processing failed.
        SecurityFail = 0xAD,
        /// Binding or group table full.
        TableFull = 0xAE,
        /// The received ASDU was unsecured.
        Unsecured = 0xAF,
        /// Unknown AIB attribute.
        UnsupportedAttribute = 0xB0,
        /// The peer cannot receive fragmented transmissions.
        PeerCannotFragment = 0xB1,
        /// The peer did not respond to fragmentation discovery.
        UnknownFragmentSupport = 0xB2,
    }
}

status_enum! {
    /// IEEE 802.15.4-2006 MAC status values (numeric values per
    /// R23.2 Annex D.2).
    MacStatus {
        /// Success.
        Success = 0x00,
        /// Association denied: PAN at capacity (association status).
        PanAtCapacity = 0x01,
        /// Association denied: access denied (association status).
        PanAccessDenied = 0x02,
        /// Frame counter error.
        CounterError = 0xDB,
        /// Improper key type.
        ImproperKeyType = 0xDC,
        /// Improper security level.
        ImproperSecurityLevel = 0xDD,
        /// Unsupported legacy security.
        UnsupportedLegacy = 0xDE,
        /// Unsupported security.
        UnsupportedSecurity = 0xDF,
        /// Beacon loss.
        BeaconLoss = 0xE0,
        /// Channel access failure (CSMA-CA).
        ChannelAccessFailure = 0xE1,
        /// Denied.
        Denied = 0xE2,
        /// Transceiver disable failure.
        DisableTrxFailure = 0xE3,
        /// Security error.
        SecurityError = 0xE4,
        /// Frame too long.
        FrameTooLong = 0xE5,
        /// Invalid GTS.
        InvalidGts = 0xE6,
        /// Invalid handle.
        InvalidHandle = 0xE7,
        /// Invalid parameter.
        InvalidParameter = 0xE8,
        /// No acknowledgement.
        NoAck = 0xE9,
        /// No beacon.
        NoBeacon = 0xEA,
        /// No data pending.
        NoData = 0xEB,
        /// No short address.
        NoShortAddress = 0xEC,
        /// Out of CAP.
        OutOfCap = 0xED,
        /// PAN identifier conflict.
        PanIdConflict = 0xEE,
        /// Coordinator realignment.
        Realignment = 0xEF,
        /// Transaction expired.
        TransactionExpired = 0xF0,
        /// Transaction overflow.
        TransactionOverflow = 0xF1,
        /// Transmitter active.
        TxActive = 0xF2,
        /// Unavailable key.
        UnavailableKey = 0xF3,
        /// Unsupported attribute.
        UnsupportedAttribute = 0xF4,
        /// Invalid address.
        InvalidAddress = 0xF5,
        /// On time too long.
        OnTimeTooLong = 0xF6,
        /// Past time.
        PastTime = 0xF7,
        /// Tracking off.
        TrackingOff = 0xF8,
        /// Invalid index.
        InvalidIndex = 0xF9,
        /// Limit reached.
        LimitReached = 0xFA,
        /// Read only.
        ReadOnly = 0xFB,
        /// Scan in progress.
        ScanInProgress = 0xFC,
        /// Superframe overlap.
        SuperframeOverlap = 0xFD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nwk_status_round_trip_and_unknown_preservation() {
        for v in 0u8..=255 {
            assert_eq!(NwkStatus::from_raw(v).raw(), v);
            assert_eq!(ApsStatus::from_raw(v).raw(), v);
            assert_eq!(MacStatus::from_raw(v).raw(), v);
        }
        assert_eq!(NwkStatus::from_raw(0xCB), NwkStatus::Unknown(0xCB));
        assert_eq!(NwkStatus::from_raw(0xD7), NwkStatus::InvalidTlv);
        assert_eq!(ApsStatus::from_raw(0xB2), ApsStatus::UnknownFragmentSupport);
        assert!(NwkStatus::Success.is_success());
        assert!(!ApsStatus::NoAck.is_success());
    }
}
