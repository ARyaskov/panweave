//! Compile-time dimensions of a [`crate::Stack`].
//!
//! A [`StackProfile`] chooses the table capacities of every layer (MAC,
//! NWK, APS, ZDO, the ZCL storage profile) and of the runtime's own
//! bookkeeping. [`FullStack`] is what every role needs at once and the
//! default of [`crate::Stack`]; [`SleepySensor`] is a battery end device
//! with one application endpoint (Panweave Lite). Profiles are types, so
//! stacks of different profiles coexist in one binary, and none of them
//! changes protocol behaviour: a table that is full answers the way the
//! specification prescribes for a full table.

use panweave_aps::layer::ApsDims;
use panweave_mac::service::{EndDeviceMac, FullMac, MacDims};
use panweave_nwk::layer::{NwkDims, SleepyEndDevice};
use panweave_types::capacity::{Cap, Capacity};
use panweave_zcl::ZclProfile;
use panweave_zdo::layer::ZdoDims;

use crate::touchlink::Touchlink;

/// Where a stack keeps its touchlink state ([`Option`] of it, or
/// [`NoTouchlink`] for a profile without touchlink).
pub trait TouchlinkSlot: Default + 'static {
    /// The state, when touchlink is enabled.
    fn as_ref(&self) -> Option<&Touchlink>;
    /// The state, mutably.
    fn as_mut(&mut self) -> Option<&mut Touchlink>;
    /// Enables touchlink with `state`; `false` when the profile has no
    /// touchlink.
    fn put(&mut self, state: Touchlink) -> bool;
}

impl TouchlinkSlot for Option<Touchlink> {
    fn as_ref(&self) -> Option<&Touchlink> {
        Option::as_ref(self)
    }

    fn as_mut(&mut self) -> Option<&mut Touchlink> {
        Option::as_mut(self)
    }

    fn put(&mut self, state: Touchlink) -> bool {
        *self = Some(state);
        true
    }
}

/// A profile without touchlink: [`crate::Stack::enable_touchlink`]
/// fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NoTouchlink;

impl TouchlinkSlot for NoTouchlink {
    fn as_ref(&self) -> Option<&Touchlink> {
        None
    }

    fn as_mut(&mut self) -> Option<&mut Touchlink> {
        None
    }

    fn put(&mut self, _: Touchlink) -> bool {
        false
    }
}

/// The dimensions of a stack.
pub trait StackProfile: 'static {
    /// MAC queues and tables.
    type Mac: MacDims;
    /// NWK tables and queues.
    type Nwk: NwkDims;
    /// APS tables and queues.
    type Aps: ApsDims;
    /// ZDO tables and queues.
    type Zdo: ZdoDims;
    /// ZCL storage (cluster states, attribute pools, reporting slots,
    /// scene tables, queues).
    type Zcl: ZclProfile;
    /// Application events queued ([`crate::StackEvent`]).
    type Events: Capacity;
    /// Transmissions in flight between the layers (MAC ↔ NWK and
    /// APS ↔ NWK handle pairs, each).
    type Handles: Capacity;
    /// Children whose network key is in flight (Trust Center).
    type PendingChildren: Capacity;
    /// Joined Zigbee Direct Virtual Devices (Trust Center).
    type VirtualDevices: Capacity;
    /// `applicationKeyRequestList` entries (Trust Center).
    type KeyRequests: Capacity;
    /// Join milestones kept for diagnostics (at least one).
    type JoinTrace: Capacity;
    /// `apsFragmentationCacheTable` entries.
    type FragmentationCache: Capacity;
    /// Fragmented messages held while the peer's parameters are
    /// discovered.
    type FragmentationHeld: Capacity;
    /// Joiners the Trust Center negotiates a dynamic link key with.
    type NegotiatingJoiners: Capacity;
    /// Devices inside their key-exchange window (Trust Center).
    type KeyExchanges: Capacity;
    /// Key-exchange exemptions (Trust Center).
    type Exemptions: Capacity;
    /// Devices restored from a swap-out backup that still have to renew
    /// their link key (Trust Center).
    type SwapOutRenewals: Capacity;
    /// Application frames held until their originator is resolved
    /// (Trust Center authorization).
    type HeldFrames: Capacity;
    /// Address resolutions in progress for held frames.
    type Resolutions: Capacity;
    /// Touchlink state.
    type Touchlink: TouchlinkSlot;
    /// Octets of the largest persisted record (the binding, group and
    /// children tables are the long ones); the buffer a record is
    /// encoded into and loaded from.
    type Record: Capacity;
}

/// Every role at once: the default of [`crate::Stack`], with the tables
/// the runtime has always used ([`crate::StackNwk`], [`crate::StackAps`],
/// [`crate::StackZdo`], the [`panweave_zcl::Full`] ZCL storage and the
/// runtime constants).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FullStack;

impl StackProfile for FullStack {
    type Mac = FullMac;
    type Nwk = panweave_nwk::layer::Dims<16, 16, 4, 16>;
    type Aps = panweave_aps::layer::Dims<{ crate::stack::LINK_KEYS }, 8, 8, 8>;
    type Zdo = panweave_zdo::layer::Dims<4>;
    type Zcl = panweave_zcl::Full;
    type Events = Cap<{ crate::stack::EVENT_CAPACITY }>;
    type Handles = Cap<8>;
    type PendingChildren = Cap<4>;
    type VirtualDevices = Cap<8>;
    type KeyRequests = Cap<8>;
    type JoinTrace = Cap<{ crate::join_trace::JOIN_TRACE_CAPACITY }>;
    type FragmentationCache = Cap<{ crate::fragment_cache::CACHE_SIZE }>;
    type FragmentationHeld = Cap<{ crate::fragment_cache::PENDING }>;
    type NegotiatingJoiners = Cap<{ crate::dlk::MAX_PENDING_JOINS }>;
    type KeyExchanges = Cap<{ crate::authorization::KEY_EXCHANGE_PENDING_CAPACITY }>;
    type Exemptions = Cap<{ crate::authorization::KEY_EXCHANGE_EXEMPTIONS }>;
    type SwapOutRenewals = Cap<{ crate::stack::LINK_KEYS }>;
    type HeldFrames = Cap<{ crate::authorization::RESOLUTION_HOLD }>;
    type Resolutions = Cap<{ crate::authorization::RESOLUTIONS }>;
    type Touchlink = Option<Touchlink>;
    type Record = Cap<512>;
}

/// A battery end device with one application endpoint (Panweave Lite):
/// the end-device NWK, APS, ZDO and MAC dimensions, the
/// [`panweave_zcl::Sensor`] ZCL storage, no Trust Center or router
/// bookkeeping (it is neither), no touchlink, and small queues.
///
/// It keeps everything an end device uses: discovery and association,
/// secured and Trust Center rejoins, the Trust Center link key update
/// and dynamic link key negotiation as the initiator, frame counter
/// challenges, APS acknowledgements and duplicate rejection, MAC data
/// polling and fragmentation towards its Trust Center.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SleepySensor;

impl StackProfile for SleepySensor {
    type Mac = EndDeviceMac;
    type Nwk = SleepyEndDevice;
    type Aps = panweave_aps::layer::EndDevice;
    type Zdo = panweave_zdo::layer::EndDevice;
    type Zcl = panweave_zcl::Sensor;
    type Events = Cap<4>;
    type Handles = Cap<3>;
    type PendingChildren = Cap<0>;
    type VirtualDevices = Cap<0>;
    type KeyRequests = Cap<0>;
    type JoinTrace = Cap<1>;
    type FragmentationCache = Cap<2>;
    type FragmentationHeld = Cap<0>;
    type NegotiatingJoiners = Cap<0>;
    type KeyExchanges = Cap<0>;
    type Exemptions = Cap<0>;
    type SwapOutRenewals = Cap<0>;
    type HeldFrames = Cap<0>;
    type Resolutions = Cap<0>;
    type Touchlink = NoTouchlink;
    // Two bindings, two groups, two link keys: every record is far
    // shorter.
    type Record = Cap<128>;
}
