//! NWK constants (R23.2 §3.5.1, Table 3-65) and the network information
//! base (§3.5.2, Table 3-66).
//!
//! Timing constants defined in OctetDurations are given here as the
//! millisecond values the table lists for the 2.4 GHz PHY.

use panweave_security::aux_header::SecurityLevel;
use panweave_types::{
    Channel, ChannelPage, Duration, ExtendedAddress, LogicalDeviceType, MacCapability, PanId,
    ShortAddress,
};

use crate::command::{ParentInformation, TimeoutIndex};

/// NWK layer constants.
pub mod constants {
    use panweave_types::Duration;

    /// `nwkcMinHeaderOverhead`.
    pub const MIN_HEADER_OVERHEAD: usize = 8;
    /// `nwkcProtocolVersion`.
    pub const PROTOCOL_VERSION: u8 = 0x02;
    /// `nwkcRouteDiscoveryTime` (0x2710 ms).
    pub const ROUTE_DISCOVERY_TIME: Duration = Duration::from_millis(0x2710);
    /// `nwkcMaxBroadcastJitter` (0x40 ms).
    pub const MAX_BROADCAST_JITTER: Duration = Duration::from_millis(0x40);
    /// `nwkcInitialRREQRetries`.
    pub const INITIAL_RREQ_RETRIES: u8 = 3;
    /// `nwkcRREQRetries`.
    pub const RREQ_RETRIES: u8 = 2;
    /// `nwkcRREQRetryInterval` (0xfe ms).
    pub const RREQ_RETRY_INTERVAL: Duration = Duration::from_millis(0xFE);
    /// `nwkcMinRREQJitter` (2 ms).
    pub const MIN_RREQ_JITTER: Duration = Duration::from_millis(2);
    /// `nwkcMaxRREQJitter` (128 ms).
    pub const MAX_RREQ_JITTER: Duration = Duration::from_millis(128);
    /// `nwkcMACFrameOverhead`.
    pub const MAC_FRAME_OVERHEAD: usize = 0x0B;
    /// `nwkcMaxDepth`.
    pub const MAX_DEPTH: u8 = 15;
    /// `nwkcUnicastRetries`.
    pub const UNICAST_RETRIES: u8 = 3;
    /// `nwkcUnicastRetryDelay`.
    pub const UNICAST_RETRY_DELAY: Duration = Duration::from_millis(50);
    /// `nwkcMinRouterBootstrapJitter` (500 ms).
    pub const MIN_ROUTER_BOOTSTRAP_JITTER: Duration = Duration::from_millis(500);
    /// `nwkcMaxRouterBootstrapJitter` (1 s).
    pub const MAX_ROUTER_BOOTSTRAP_JITTER: Duration = Duration::from_millis(1000);
    /// `nwkcBroadcastDeliveryTime` (9 s).
    pub const BROADCAST_DELIVERY_TIME: Duration = Duration::from_secs(9);
    /// Default radius for transmissions: `2 * nwkcMaxDepth`.
    pub const DEFAULT_RADIUS: u8 = 2 * MAX_DEPTH;
    /// `apsSecurityTimeOutPeriod` default (10 s), used for the neighbor
    /// table `SecurityTimer` (§3.6.1.6.1.1, Table 4-35).
    pub const SECURITY_TIMEOUT: Duration = Duration::from_secs(10);
}

/// Network information base attributes that the NWK layer owns.
///
/// Table attributes (neighbor, route, discovery, BTT, address map) live in
/// their own modules; this struct holds the scalar attributes.
#[derive(Clone, Debug)]
pub struct Nib {
    /// `nwkSequenceNumber`.
    pub sequence_number: u8,
    /// `nwkPassiveAckTimeout` (default 500 ms).
    pub passive_ack_timeout: Duration,
    /// `nwkMaxBroadcastRetries` (default 2).
    pub max_broadcast_retries: u8,
    /// `nwkMaxChildren` (implementation specific).
    pub max_children: u8,
    /// `nwkMaxRouters`: router children accepted.
    pub max_routers: u8,
    /// `nwkNetworkBroadcastDeliveryTime` (default 9 s).
    pub network_broadcast_delivery_time: Duration,
    /// `nwkCapabilityInformation`.
    pub capability_information: MacCapability,
    /// `nwkManagerAddr` (default 0x0000).
    pub manager_addr: ShortAddress,
    /// `nwkMaxSourceRoute` (default 12).
    pub max_source_route: u8,
    /// `nwkUpdateId`.
    pub update_id: u8,
    /// `nwkNetworkAddress` (0xFFFF when not joined).
    pub network_address: ShortAddress,
    /// `nwkStackProfile` (2).
    pub stack_profile: u8,
    /// `nwkExtendedPANId` (0 when not joined).
    pub extended_pan_id: ExtendedAddress,
    /// `nwkPANId` (0xFFFF when not joined).
    pub pan_id: PanId,
    /// Current channel page.
    pub channel_page: ChannelPage,
    /// Current channel.
    pub channel: Channel,
    /// `nwkIsConcentrator`.
    pub is_concentrator: bool,
    /// `nwkConcentratorRadius`.
    pub concentrator_radius: u8,
    /// `nwkConcentratorDiscoveryTime` in seconds (0 = never).
    pub concentrator_discovery_time_secs: u32,
    /// `nwkSecurityLevel` (default 5).
    pub security_level: SecurityLevel,
    /// `nwkAllFresh` (default TRUE).
    pub all_fresh: bool,
    /// `nwkLinkStatusPeriod` (default 15 s).
    pub link_status_period: Duration,
    /// `nwkRouterAgeLimit` (default 3).
    pub router_age_limit: u8,
    /// `nwkLeaveRequestAllowed` (default TRUE).
    pub leave_request_allowed: bool,
    /// `nwkLeaveRequestWithoutRejoinAllowed` (default TRUE).
    pub leave_request_without_rejoin_allowed: bool,
    /// `nwkParentInformation`.
    pub parent_information: ParentInformation,
    /// `nwkEndDeviceTimeoutDefault` (default 8 → 256 minutes).
    pub end_device_timeout_default: TimeoutIndex,
    /// `nwkEndDeviceTimeout`: the value this end device negotiates.
    pub end_device_timeout: TimeoutIndex,
    /// `nwkIeeeAddress`.
    pub ieee_address: ExtendedAddress,
    /// `nwkGoodParentLQA` (default 75).
    pub good_parent_lqa: u8,
    /// `nwkMaxInitialJoinParentAttempts` (default 3).
    pub max_initial_join_parent_attempts: u8,
    /// `nwkMaxRejoinParentAttempts` (default 3).
    pub max_rejoin_parent_attempts: u8,
    /// `nwkHubConnectivity`.
    pub hub_connectivity: bool,
    /// `nwkPreferredParent`.
    pub preferred_parent: bool,
    /// `nwkNextPanId` (0xFFFF = none).
    pub next_pan_id: PanId,
    /// `nwkPanIdConflictCount`.
    pub pan_id_conflict_count: u16,
    /// `nwkRoutingSequenceNumber`.
    pub routing_sequence_number: u16,
    /// `nwkTxTotal`.
    pub tx_total: u16,
    /// Logical device type of this node.
    pub device_type: LogicalDeviceType,
    /// True once the node is joined and authenticated on a network.
    pub joined: bool,
    /// True once the node holds the network key (authenticated).
    pub authenticated: bool,
    /// Whether this device has invoked NLME-START-ROUTER (routers only).
    pub router_started: bool,
    /// `macRxOnWhenIdle` as configured for this node.
    pub rx_on_when_idle: bool,
    /// `nwkParentInformation` companion: this node's parent short address
    /// (end devices).
    pub parent_address: ShortAddress,
    /// Parent extended address (end devices).
    pub parent_ieee: ExtendedAddress,
    /// Depth in the tree (informational; deprecated in beacons).
    pub depth: u8,
}

impl Nib {
    /// Default NIB for a device of `device_type` with `ieee_address`.
    pub fn new(device_type: LogicalDeviceType, ieee_address: ExtendedAddress) -> Self {
        let rx_on_when_idle = device_type.is_routing_capable();
        Nib {
            sequence_number: 0,
            passive_ack_timeout: Duration::from_millis(500),
            max_broadcast_retries: 2,
            max_children: 16,
            max_routers: 16,
            network_broadcast_delivery_time: constants::BROADCAST_DELIVERY_TIME,
            capability_information: match device_type {
                LogicalDeviceType::Coordinator | LogicalDeviceType::Router => MacCapability::ROUTER,
                LogicalDeviceType::EndDevice => MacCapability::END_DEVICE_RX_ON,
            },
            manager_addr: ShortAddress::COORDINATOR,
            max_source_route: 12,
            update_id: 0,
            network_address: ShortAddress::NO_SHORT_ADDRESS,
            stack_profile: 2,
            extended_pan_id: ExtendedAddress::ZERO,
            pan_id: PanId::BROADCAST,
            channel_page: ChannelPage::PAGE_0,
            channel: Channel::DEFAULT_2_4GHZ,
            is_concentrator: false,
            concentrator_radius: 0,
            concentrator_discovery_time_secs: 0,
            security_level: SecurityLevel::EncMic32,
            all_fresh: true,
            link_status_period: Duration::from_secs(15),
            router_age_limit: 3,
            leave_request_allowed: true,
            leave_request_without_rejoin_allowed: true,
            parent_information: ParentInformation(0),
            end_device_timeout_default: TimeoutIndex::DEFAULT,
            end_device_timeout: TimeoutIndex::DEFAULT,
            ieee_address,
            good_parent_lqa: 75,
            max_initial_join_parent_attempts: 3,
            max_rejoin_parent_attempts: 3,
            hub_connectivity: false,
            preferred_parent: false,
            next_pan_id: PanId::BROADCAST,
            pan_id_conflict_count: 0,
            routing_sequence_number: 0,
            tx_total: 0,
            device_type,
            joined: false,
            authenticated: false,
            router_started: false,
            rx_on_when_idle,
            parent_address: ShortAddress::NO_SHORT_ADDRESS,
            parent_ieee: ExtendedAddress::ZERO,
            depth: 0,
        }
    }

    /// Next NWK sequence number (§3.6.2.1).
    pub fn next_sequence(&mut self) -> u8 {
        let v = self.sequence_number;
        self.sequence_number = self.sequence_number.wrapping_add(1);
        v
    }

    /// Increments `nwkRoutingSequenceNumber`.
    pub fn next_routing_sequence(&mut self) -> u16 {
        self.routing_sequence_number = self.routing_sequence_number.wrapping_add(1);
        self.routing_sequence_number
    }

    /// True for coordinator and router.
    #[inline]
    pub const fn is_router_or_coordinator(&self) -> bool {
        self.device_type.is_routing_capable()
    }

    /// True for the coordinator.
    #[inline]
    pub const fn is_coordinator(&self) -> bool {
        matches!(self.device_type, LogicalDeviceType::Coordinator)
    }

    /// True for end devices.
    #[inline]
    pub const fn is_end_device(&self) -> bool {
        matches!(self.device_type, LogicalDeviceType::EndDevice)
    }

    /// Clears the attributes listed in §3.6.1.11.4 step 2 (leave without
    /// rejoin). Table attributes are cleared by their owners.
    pub fn clear_for_leave(&mut self) {
        self.manager_addr = ShortAddress::COORDINATOR;
        self.update_id = 0;
        self.network_address = ShortAddress::NO_SHORT_ADDRESS;
        self.extended_pan_id = ExtendedAddress::ZERO;
        self.is_concentrator = false;
        self.concentrator_radius = 0;
        self.pan_id = PanId::BROADCAST;
        self.tx_total = 0;
        self.parent_information = ParentInformation(0);
        self.parent_address = ShortAddress::NO_SHORT_ADDRESS;
        self.parent_ieee = ExtendedAddress::ZERO;
        self.joined = false;
        self.authenticated = false;
        self.router_started = false;
        self.depth = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_sequence() {
        let mut nib = Nib::new(LogicalDeviceType::Router, ExtendedAddress(1));
        assert_eq!(nib.security_level, SecurityLevel::EncMic32);
        assert_eq!(nib.link_status_period, Duration::from_secs(15));
        assert_eq!(nib.router_age_limit, 3);
        assert!(nib.all_fresh);
        assert!(nib.rx_on_when_idle);
        nib.sequence_number = 255;
        assert_eq!(nib.next_sequence(), 255);
        assert_eq!(nib.next_sequence(), 0);
        assert_eq!(constants::DEFAULT_RADIUS, 30);
        let ed = Nib::new(LogicalDeviceType::EndDevice, ExtendedAddress(2));
        assert!(ed.is_end_device());
        assert!(!ed.capability_information.is_full_function_device());
    }

    #[test]
    fn clear_for_leave_resets_identity() {
        let mut nib = Nib::new(LogicalDeviceType::EndDevice, ExtendedAddress(2));
        nib.pan_id = PanId(1);
        nib.network_address = ShortAddress(5);
        nib.joined = true;
        nib.clear_for_leave();
        assert_eq!(nib.pan_id, PanId::BROADCAST);
        assert_eq!(nib.network_address, ShortAddress::NO_SHORT_ADDRESS);
        assert!(!nib.joined);
        assert_eq!(nib.ieee_address, ExtendedAddress(2), "IEEE address is kept");
    }
}
