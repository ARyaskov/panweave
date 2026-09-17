//! Adapters that expose NWK / APS state to the APS (`NwkView`) and the
//! ZDO (`ZdoContext`).

use panweave_aps::layer::NwkView;
use panweave_aps::tables::BindingEntry;
use panweave_nwk::neighbor::Relationship;
use panweave_nwk::routing::RouteStatus;
use panweave_security::cipher::BlockCipher;
use panweave_security::trust_center::TrustCenterPolicy;
use panweave_types::{
    ApsStatus, ExtendedAddress, LogicalDeviceType, MacCapability, Rng, ShortAddress,
};
use panweave_zdo::layer::ZdoContext;
use panweave_zdo::zdp::{
    BindReq, NeighborDeviceType, NeighborRecord, NeighborRelationship, RouteRecord,
    RouteRecordStatus, TriState, ZdpStatus,
};

use crate::stack::{StackAps, StackNwk};

/// Read-only address view over the NWK tables.
pub(crate) struct AddrView<'a, C: BlockCipher, R: Rng>(pub &'a StackNwk<C, R>);

impl<C: BlockCipher, R: Rng> NwkView for AddrView<'_, C, R> {
    fn ieee_of(&self, short: ShortAddress) -> Option<ExtendedAddress> {
        if short == self.0.nib.network_address {
            return Some(self.0.nib.ieee_address);
        }
        self.0
            .neighbors
            .by_short(short)
            .map(|n| n.extended)
            .or_else(|| self.0.address_map.extended_for(short))
    }

    fn short_of(&self, ieee: ExtendedAddress) -> Option<ShortAddress> {
        if ieee == self.0.nib.ieee_address {
            return Some(self.0.nib.network_address);
        }
        self.0
            .neighbors
            .by_extended(ieee)
            .map(|n| n.short)
            .or_else(|| self.0.address_map.short_for(ieee))
    }

    fn unauthenticated_child(&self, ieee: ExtendedAddress) -> Option<ShortAddress> {
        self.0
            .neighbors
            .by_extended(ieee)
            .filter(|n| {
                matches!(
                    n.relationship,
                    Relationship::UnauthenticatedChild
                        | Relationship::UnauthorizedChildRelayAllowed
                )
            })
            .map(|n| n.short)
    }
}

/// The ZDO's view of the stack.
pub(crate) struct ZdoCtx<'a, C: BlockCipher, R: Rng> {
    pub nwk: &'a mut StackNwk<C, R>,
    pub aps: &'a mut StackAps<C>,
    pub policy: &'a TrustCenterPolicy,
    pub is_trust_center: bool,
}

fn relationship_of(r: Relationship) -> NeighborRelationship {
    match r {
        Relationship::Parent => NeighborRelationship::Parent,
        Relationship::Child
        | Relationship::UnauthenticatedChild
        | Relationship::UnauthorizedChildRelayAllowed => NeighborRelationship::Child,
        Relationship::Sibling => NeighborRelationship::Sibling,
        _ => NeighborRelationship::None,
    }
}

impl<C: BlockCipher, R: Rng> ZdoContext for ZdoCtx<'_, C, R> {
    fn local_short(&self) -> ShortAddress {
        self.nwk.nib.network_address
    }

    fn local_ieee(&self) -> ExtendedAddress {
        self.nwk.nib.ieee_address
    }

    fn extended_pan_id(&self) -> ExtendedAddress {
        self.nwk.nib.extended_pan_id
    }

    fn trust_center(&self) -> ExtendedAddress {
        self.aps.aib.trust_center_address
    }

    fn is_trust_center(&self) -> bool {
        self.is_trust_center
    }

    fn logical_type(&self) -> LogicalDeviceType {
        self.nwk.nib.device_type
    }

    fn end_device_children(&self, f: &mut dyn FnMut(ExtendedAddress, ShortAddress)) {
        for n in self.nwk.neighbors.end_device_children() {
            f(n.extended, n.short);
        }
    }

    fn neighbor_count(&self) -> u8 {
        u8::try_from(self.nwk.neighbors.len()).unwrap_or(u8::MAX)
    }

    fn neighbor_record(&self, index: u8) -> Option<NeighborRecord> {
        let n = self.nwk.neighbors.iter().nth(usize::from(index))?;
        let my_depth = self.nwk.nib.depth;
        let depth = match n.relationship {
            Relationship::Parent => my_depth.saturating_sub(1),
            Relationship::Child
            | Relationship::UnauthenticatedChild
            | Relationship::UnauthorizedChildRelayAllowed => my_depth.saturating_add(1),
            _ => my_depth,
        };
        Some(NeighborRecord {
            extended_pan_id: self.nwk.nib.extended_pan_id,
            ieee: n.extended,
            short: n.short,
            device_type: match n.device_type {
                LogicalDeviceType::Coordinator => NeighborDeviceType::Coordinator,
                LogicalDeviceType::Router => NeighborDeviceType::Router,
                LogicalDeviceType::EndDevice => NeighborDeviceType::EndDevice,
            },
            rx_on_when_idle: if n.rx_on_when_idle {
                TriState::Yes
            } else {
                TriState::No
            },
            relationship: relationship_of(n.relationship),
            permit_joining: TriState::Unknown,
            depth,
            lqa: n.lqa.value(),
        })
    }

    fn route_count(&self) -> u8 {
        u8::try_from(self.nwk.routes.len()).unwrap_or(u8::MAX)
    }

    fn route_record(&self, index: u8) -> Option<RouteRecord> {
        let r = self.nwk.routes.iter().nth(usize::from(index))?;
        Some(RouteRecord {
            destination: r.destination,
            status: match r.status {
                RouteStatus::Active => RouteRecordStatus::Active,
                RouteStatus::DiscoveryUnderway | RouteStatus::ValidationUnderway => {
                    RouteRecordStatus::DiscoveryUnderway
                }
                RouteStatus::DiscoveryFailed => RouteRecordStatus::DiscoveryFailed,
                RouteStatus::Inactive => RouteRecordStatus::Inactive,
            },
            memory_constrained: false,
            many_to_one: r.many_to_one,
            route_record_required: r.route_record_required,
            next_hop: r.next_hop,
        })
    }

    fn binding_count(&self) -> u8 {
        u8::try_from(self.aps.bindings.len()).unwrap_or(u8::MAX)
    }

    fn binding_record(&self, index: u8) -> Option<BindReq> {
        let b = self.aps.bindings.iter().nth(usize::from(index))?;
        Some(BindReq {
            src: self.nwk.nib.ieee_address,
            src_endpoint: b.src_endpoint,
            cluster: b.cluster,
            destination: b.destination,
        })
    }

    fn bind(&mut self, req: &BindReq) -> ZdpStatus {
        match self.aps.bindings.bind(BindingEntry {
            src_endpoint: req.src_endpoint,
            cluster: req.cluster,
            destination: req.destination,
        }) {
            Ok(()) => ZdpStatus::Success,
            Err(ApsStatus::TableFull) => ZdpStatus::InsufficientSpace,
            Err(_) => ZdpStatus::InvalidRequestType,
        }
    }

    fn unbind(&mut self, req: &BindReq) -> ZdpStatus {
        match self.aps.bindings.unbind(&BindingEntry {
            src_endpoint: req.src_endpoint,
            cluster: req.cluster,
            destination: req.destination,
        }) {
            Ok(()) => ZdpStatus::Success,
            Err(ApsStatus::InvalidBinding) => ZdpStatus::NoEntry,
            Err(_) => ZdpStatus::InvalidRequestType,
        }
    }

    fn clear_bindings(&mut self, device: ExtendedAddress) {
        if device == ExtendedAddress::BROADCAST {
            self.aps.bindings.clear();
        } else {
            let _ = self.aps.bindings.remove_device(device);
        }
    }

    fn permit_joining(&mut self, duration: u8, from_trust_center: bool) -> ZdpStatus {
        if self.is_trust_center && !from_trust_center && !self.policy.allow_remote_policy_change {
            // §4.7.3.4: remote changes of the joining policy are refused.
            return ZdpStatus::InvalidRequestType;
        }
        match self.nwk.permit_joining(duration) {
            Ok(()) => ZdpStatus::Success,
            Err(_) => ZdpStatus::NotSupported,
        }
    }

    fn set_beacon_appendix(&mut self, _tlvs: &[u8]) {
        // TODO(PW-NWK-BEACON-APPENDIX): store nwkNetworkWideBeaconAppendixTLVs
        // from Mgmt_Permit_Joining_req. Spec: R23.2 §2.4.3.3.7.2.
    }

    fn leave(&mut self, device: ExtendedAddress, remove_children: bool, rejoin: bool) -> ZdpStatus {
        let target = if device == self.nwk.nib.ieee_address {
            None
        } else {
            Some(device)
        };
        match self.nwk.leave(target, rejoin, remove_children) {
            Ok(()) => ZdpStatus::Success,
            Err(_) => ZdpStatus::NotSupported,
        }
    }

    fn device_announced(
        &mut self,
        ieee: ExtendedAddress,
        short: ShortAddress,
        _capability: MacCapability,
    ) {
        if ieee != ExtendedAddress::BROADCAST && ieee != self.nwk.nib.ieee_address {
            let _ = self.nwk.address_map.record(ieee, short);
        }
    }

    fn claims_child(&self, child: ExtendedAddress) -> bool {
        self.nwk.neighbors.by_extended(child).is_some_and(|n| {
            n.device_type == LogicalDeviceType::EndDevice
                && n.relationship == Relationship::Child
                && n.keepalive_received
        })
    }

    fn child_claimed_elsewhere(&mut self, child: ExtendedAddress, _router: ShortAddress) {
        let _ = self.nwk.neighbors.remove_extended(child);
    }
}
