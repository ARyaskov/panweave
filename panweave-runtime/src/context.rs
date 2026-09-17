//! Adapters that expose NWK / APS state to the APS (`NwkView`) and the
//! ZDO (`ZdoContext`).

use panweave_aps::layer::NwkView;
use panweave_aps::layer::RelayInfo;
use panweave_aps::tables::BindingEntry;
use panweave_codec::Writer;
use panweave_codec::tlv::{Tlv, TlvSet};
use panweave_nwk::neighbor::Relationship;
use panweave_nwk::routing::RouteStatus;
use panweave_nwk::tlv::tag as tlv_tag;
use panweave_nwk::tlv::{
    ConfigurationParameters, FragmentationParameters, NextChannelChange, NextPanIdChange,
    PanIdConflictReport, RouterInformation, SupportedKeyNegotiationMethods,
};
use panweave_security::cipher::BlockCipher;
use panweave_security::trust_center::TrustCenterPolicy;
#[cfg(feature = "dlk")]
use panweave_types::KeyAttributes;
use panweave_types::{
    ApsStatus, ChannelMask, CryptoRng, ExtendedAddress, Key128, LogicalDeviceType, MacCapability,
    Rng, ShortAddress,
};
use panweave_zdo::security::SelectedKeyNegotiationMethod;

use crate::dlk::DlkState;
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
pub(crate) struct ZdoCtx<'a, C: BlockCipher, R: CryptoRng> {
    pub nwk: &'a mut StackNwk<C, R>,
    pub aps: &'a mut StackAps<C>,
    pub policy: &'a TrustCenterPolicy,
    pub is_trust_center: bool,
    /// Set when the binding table changed (runtime persists it).
    pub bindings_changed: bool,
    /// Key negotiation state.
    pub dlk: &'a mut DlkState,
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

impl<C: BlockCipher, R: CryptoRng> ZdoContext for ZdoCtx<'_, C, R> {
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

    fn awaiting_authorization(&self) -> bool {
        self.aps.state() == panweave_aps::layer::DeviceState::JoinedUnauthorized
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
            Ok(()) => {
                self.bindings_changed = true;
                ZdpStatus::Success
            }
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
            Ok(()) => {
                self.bindings_changed = true;
                ZdpStatus::Success
            }
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
        self.bindings_changed = true;
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

    fn set_beacon_appendix(&mut self, tlvs: &[u8]) {
        // §2.4.3.3.7.2: the Beacon Appendix Encapsulation Global TLV sets
        // nwkNetworkWideBeaconAppendixTLVs in its entirety.
        if let Ok(set) = TlvSet::validate(tlvs, |_| false)
            && let Some(inner) = set.value(tlv_tag::BEACON_APPENDIX_ENCAPSULATION)
        {
            self.nwk.set_network_wide_beacon_appendix(inner);
        }
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

    // ---- Security services (§2.4.3.4) --------------------------------

    fn key_negotiation(
        &mut self,
        partner: ExtendedAddress,
        point: &[u8; 32],
        aps_encrypted: bool,
    ) -> Result<[u8; 32], ZdpStatus> {
        #[cfg(not(feature = "dlk"))]
        {
            let _ = (partner, point, aps_encrypted);
            Err(ZdpStatus::NotSupported)
        }
        #[cfg(feature = "dlk")]
        {
            use panweave_security::dlk::Ephemeral;
            use panweave_security::material::{KeyNegotiationState, LinkKeyKind};
            use panweave_zdo::security::SelectedKeyNegotiationMethod;

            // §2.4.3.4.1.4: a unique, non-provisional entry requires an
            // APS-encrypted request unless the authentication token is
            // the pre-shared secret.
            let entry = self.aps.security.entry(partner);
            let Some(e) = entry else {
                // No key-pair entry (§4.7.3.3 step 2a / §4.4.9): refuse.
                return Err(ZdpStatus::NotAuthorized);
            };
            let secret = self
                .dlk
                .joins
                .iter()
                .find(|j| j.device == partner)
                .map_or_else(
                    || {
                        if e.passphrase.is_some() {
                            SelectedKeyNegotiationMethod::SECRET_AUTH_TOKEN
                        } else {
                            SelectedKeyNegotiationMethod::SECRET_ANONYMOUS
                        }
                    },
                    |j| j.secret,
                );
            let token_secret = secret == SelectedKeyNegotiationMethod::SECRET_AUTH_TOKEN;
            if e.kind == LinkKeyKind::Unique
                && e.attributes != KeyAttributes::ProvisionalKey
                && !aps_encrypted
                && !token_secret
            {
                return Err(ZdpStatus::NotAuthorized);
            }
            let Some(psk) = crate::dlk::passphrase_for(Some(e), secret) else {
                return Err(ZdpStatus::NotAuthorized);
            };
            let ephemeral = Ephemeral::generate::<C, _>(self.nwk.rng(), psk.as_bytes());
            let key = ephemeral
                .derive::<C>(self.nwk.nib.ieee_address, partner, point)
                .map_err(|_| ZdpStatus::InvalidTlv)?;
            let mine = *ephemeral.public();
            if !self.aps.set_negotiated_key(
                partner,
                &key,
                LinkKeyKind::Unique,
                KeyAttributes::UnverifiedKey,
            ) {
                return Err(ZdpStatus::TemporaryFailure);
            }
            if let Some(e) = self.aps.security.keys_mut().get_mut(partner) {
                e.negotiation_state = KeyNegotiationState::Complete;
                e.negotiation_method = SelectedKeyNegotiationMethod::PROTOCOL_SPEKE_AES_MMO;
                e.post_join_key_update = crate::dlk::update_method(secret);
            }
            Ok(mine)
        }
    }

    fn authentication_token(&mut self, requester: ExtendedAddress) -> Result<[u8; 16], ZdpStatus> {
        let Some(e) = self.aps.security.keys_mut().get_mut(requester) else {
            return Err(ZdpStatus::NotPermitted);
        };
        if !e.passphrase_update_allowed {
            return Err(ZdpStatus::NotPermitted);
        }
        // Step 6: an existing passphrase is returned, otherwise a fresh
        // random token is generated. Step 10 (lock after the APS
        // acknowledgement) is applied immediately: the token is stored
        // and the entry locked once handed out.
        let token = match &e.passphrase {
            Some(p) => {
                let mut t = [0u8; 16];
                t.copy_from_slice(p.as_bytes());
                t
            }
            None => {
                let mut t = [0u8; 16];
                self.nwk.rng().fill_bytes(&mut t);
                t
            }
        };
        let Some(e) = self.aps.security.keys_mut().get_mut(requester) else {
            return Err(ZdpStatus::NotPermitted);
        };
        e.passphrase = Some(Key128::from_bytes(token));
        e.passphrase_update_allowed = false;
        self.aps.request_link_key_persistence();
        Ok(token)
    }

    fn authentication_level(&self, target: ExtendedAddress) -> Result<(u8, u8), ZdpStatus> {
        let e = self.aps.security.entry(target).ok_or(ZdpStatus::NoMatch)?;
        Ok((
            e.initial_join_authentication.raw(),
            e.post_join_key_update.raw(),
        ))
    }

    fn start_key_update(
        &mut self,
        method: &SelectedKeyNegotiationMethod,
        via: Option<RelayInfo>,
    ) -> ZdpStatus {
        if !cfg!(feature = "dlk")
            || method.protocol != SelectedKeyNegotiationMethod::PROTOCOL_SPEKE_AES_MMO
        {
            return ZdpStatus::NoMatch;
        }
        let placeholder = self.aps.aib.trust_center_address;
        if placeholder == ExtendedAddress::BROADCAST && self.awaiting_authorization() {
            // Step 3: learn the Trust Center; the pre-configured entry
            // was installed under the placeholder (§4.6.3.1).
            self.aps.security.rename(placeholder, method.sender);
            self.aps.aib.trust_center_address = method.sender;
        }
        self.dlk.start_requested = Some((*method, via));
        ZdpStatus::Success
    }

    fn decommission(&mut self, devices: &[ExtendedAddress]) -> bool {
        let mut changed = false;
        for d in devices {
            if self.aps.security.remove(*d) {
                changed = true;
                self.aps.request_link_key_persistence();
            }
            if self.aps.bindings.remove_device(*d) > 0 {
                changed = true;
                self.bindings_changed = true;
            }
            let _ = self.nwk.neighbors.remove_extended(*d);
        }
        changed
    }

    fn set_configuration(&mut self, t: &Tlv<'_>) -> ZdpStatus {
        match t.tag {
            tlv_tag::CONFIGURATION_PARAMETERS => match ConfigurationParameters::parse(t) {
                Ok(p) => {
                    self.aps.aib.zdo_restricted_mode =
                        p.0 & ConfigurationParameters::ZDO_RESTRICTED_MODE != 0;
                    self.aps
                        .config
                        .require_link_key_encryption_for_transport_key =
                        p.0 & ConfigurationParameters::REQUIRE_LINK_KEY_FOR_TRANSPORT_KEY != 0;
                    self.nwk.nib.leave_request_allowed =
                        p.0 & ConfigurationParameters::LEAVE_REQUEST_ALLOWED != 0;
                    ZdpStatus::Success
                }
                Err(_) => ZdpStatus::InvalidRequestType,
            },
            tlv_tag::NEXT_PAN_ID_CHANGE => match NextPanIdChange::parse(t) {
                Ok(p) => {
                    self.nwk.nib.next_pan_id = p.pan_id;
                    ZdpStatus::Success
                }
                Err(_) => ZdpStatus::InvalidRequestType,
            },
            tlv_tag::NEXT_CHANNEL_CHANGE => match NextChannelChange::parse(t) {
                Ok(c) => {
                    let mask = c.mask.channels_only();
                    if mask.is_empty() || mask.and(ChannelMask::ALL_2_4GHZ) != mask {
                        // Not a supported channel of the interface.
                        ZdpStatus::InvalidRequestType
                    } else {
                        self.nwk.nib.next_channel_change = c.mask;
                        ZdpStatus::Success
                    }
                }
                Err(_) => ZdpStatus::InvalidRequestType,
            },
            _ => ZdpStatus::NotSupported,
        }
    }

    fn answer_frame_counter_challenge(
        &mut self,
        sender: ExtendedAddress,
        challenge: u64,
    ) -> Option<(u32, u32, [u8; 8])> {
        let local = self.nwk.nib.ieee_address;
        self.aps.security.answer_challenge(local, sender, challenge)
    }

    fn get_configuration(&mut self, tag: u8, w: &mut Writer<'_>) -> bool {
        match tag {
            tlv_tag::CONFIGURATION_PARAMETERS => {
                let mut bits = 0u16;
                if self.aps.aib.zdo_restricted_mode {
                    bits |= ConfigurationParameters::ZDO_RESTRICTED_MODE;
                }
                if self
                    .aps
                    .config
                    .require_link_key_encryption_for_transport_key
                {
                    bits |= ConfigurationParameters::REQUIRE_LINK_KEY_FOR_TRANSPORT_KEY;
                }
                if self.nwk.nib.leave_request_allowed {
                    bits |= ConfigurationParameters::LEAVE_REQUEST_ALLOWED;
                }
                ConfigurationParameters(bits).write(w).is_ok()
            }
            tlv_tag::NEXT_PAN_ID_CHANGE => NextPanIdChange {
                pan_id: self.nwk.nib.next_pan_id,
            }
            .write(w)
            .is_ok(),
            tlv_tag::NEXT_CHANNEL_CHANGE => {
                if self.nwk.nib.next_channel_change.is_empty() {
                    return false;
                }
                NextChannelChange {
                    mask: self.nwk.nib.next_channel_change,
                }
                .write(w)
                .is_ok()
            }
            tlv_tag::PAN_ID_CONFLICT_REPORT => {
                // §2.4.3.4.5.2 step 3: report and reset the count.
                let count = self.nwk.nib.pan_id_conflict_count;
                self.nwk.nib.pan_id_conflict_count = 0;
                PanIdConflictReport { count }.write(w).is_ok()
            }
            tlv_tag::SUPPORTED_KEY_NEGOTIATION_METHODS => SupportedKeyNegotiationMethods {
                protocols: self.aps.aib.supported_key_negotiation_methods,
                secrets: SupportedKeyNegotiationMethods::SECRET_AUTH_TOKEN
                    | SupportedKeyNegotiationMethods::SECRET_INSTALL_CODE,
                source: Some(self.nwk.nib.ieee_address),
            }
            .write(w)
            .is_ok(),
            tlv_tag::ROUTER_INFORMATION => {
                if !self.nwk.nib.is_router_or_coordinator() {
                    return false;
                }
                let mut info = RouterInformation(0);
                if self.nwk.nib.hub_connectivity {
                    info.0 |= RouterInformation::HUB_CONNECTIVITY;
                }
                if self.nwk.nib.preferred_parent {
                    info.0 |= RouterInformation::PREFERRED_PARENT;
                }
                info.write(w).is_ok()
            }
            tlv_tag::FRAGMENTATION_PARAMETERS => FragmentationParameters {
                node: self.nwk.nib.network_address,
                options: 0,
                max_incoming_transfer_unit: self.aps.aib.max_size_asdu,
            }
            .write(w)
            .is_ok(),
            _ => false,
        }
    }
}
