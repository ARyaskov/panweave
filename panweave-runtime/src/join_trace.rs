//! Join milestones a parent or Trust Center observes, for diagnostics.
//!
//! The stack records each milestone of a device joining through this
//! node — the MAC association request, the NWK join, the Trust Center's
//! decision, the network key transport and its delivery, the Trust Center
//! link key exchange — in a small bounded queue the application drains
//! with [`crate::Stack::next_join_record`]. Records carry identities,
//! stages and status codes, never key material. An application that never
//! drains the queue loses only the oldest records (counted in
//! [`crate::Stack::join_trace_dropped`]); the stack's behaviour does not
//! depend on it.

use panweave_types::time::Instant;
use panweave_types::{ExtendedAddress, ShortAddress};

/// Records kept until the application drains them.
pub const JOIN_TRACE_CAPACITY: usize = 12;

/// A join milestone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinStage {
    /// A device asked this node for MAC association (`detail`: its MAC
    /// capability octet). No [`JoinStage::ChildJoined`] following means
    /// the association was refused (network closed, table full).
    AssociationRequest,
    /// The NWK layer accepted a child (`detail`: the Update Device status
    /// it implies — 0 secured rejoin, 1 unsecured join, 3 Trust Center
    /// rejoin).
    ChildJoined,
    /// A router reported a device through APS Update Device (`detail`: its
    /// status, as for [`JoinStage::ChildJoined`]; 2 = the device left).
    UpdateDevice,
    /// The Trust Center decided (`detail`: one of [`decision`]).
    Decision,
    /// The network key was sent to the device (directly or tunnelled).
    KeyTransportSent,
    /// The key transport was acknowledged: the device is authorized.
    KeyDelivered,
    /// The key transport failed (`detail`: the APS status).
    KeyDeliveryFailed,
    /// The device requested a unique Trust Center link key (`detail`: 1
    /// granted, 0 refused by policy).
    TclkRequested,
    /// The device verified its Trust Center link key.
    TclkVerified,
    /// The device holds the network key and has
    /// `bdbTrustCenterNodeJoinTimeout` to complete the required key
    /// exchange ([`crate::authorization`]).
    KeyExchangePending,
    /// The key-exchange window passed: the device was removed.
    KeyExchangeTimedOut,
    /// The device is authorized (`detail`: 1 when only through an
    /// administrator exemption).
    Authorized,
    /// The device joined again through the unauthenticated path: its
    /// earlier admission without the key exchange no longer applies.
    ExemptionWithdrawn,
}

impl JoinStage {
    /// A stable code for the stage.
    pub const fn code(self) -> u8 {
        match self {
            JoinStage::AssociationRequest => 1,
            JoinStage::ChildJoined => 2,
            JoinStage::UpdateDevice => 3,
            JoinStage::Decision => 4,
            JoinStage::KeyTransportSent => 5,
            JoinStage::KeyDelivered => 6,
            JoinStage::KeyDeliveryFailed => 7,
            JoinStage::TclkRequested => 8,
            JoinStage::TclkVerified => 9,
            JoinStage::KeyExchangePending => 10,
            JoinStage::KeyExchangeTimedOut => 11,
            JoinStage::Authorized => 12,
            JoinStage::ExemptionWithdrawn => 13,
        }
    }
}

/// Trust Center decisions ([`JoinStage::Decision`] detail).
pub mod decision {
    /// Negotiate a dynamic link key first.
    pub const NEGOTIATE_KEY: u8 = 0;
    /// Transport the network key.
    pub const TRANSPORT_NETWORK_KEY: u8 = 1;
    /// Allow without transport (secured rejoin).
    pub const ALLOW: u8 = 2;
    /// Ignore the device (policy refused it).
    pub const IGNORE: u8 = 3;
    /// Remove the device.
    pub const REMOVE: u8 = 4;
}

/// One milestone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct JoinRecord {
    /// When it happened (stack time).
    pub at: Instant,
    /// The device.
    pub device: ExtendedAddress,
    /// Its network address, when known at this stage.
    pub short: Option<ShortAddress>,
    /// The milestone.
    pub stage: JoinStage,
    /// Stage-specific detail (see [`JoinStage`]).
    pub detail: u8,
}
