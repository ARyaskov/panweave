//! Out-of-band provisioning of the stack: formation and network
//! adoption with caller-supplied parameters, and the network-state
//! queries a commissioning front end (Zigbee Direct, a serial host
//! protocol, tests) needs. Nothing here bypasses the security model:
//! keys still enter through the NWK/APS key stores and the Trust
//! Center policy stays in force.

use panweave_aps::layer::DeviceState;
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_storage::Storage;
use panweave_types::{
    Channel, ChannelMask, CryptoRng, Endpoint, ExtendedAddress, Key128, KeyAttributes,
    KeySequenceNumber, LogicalDeviceType, NwkStatus, PanId, ShortAddress,
};

use crate::stack::{Phase, Stack};

/// Parameters of a provisioned network formation; `None` means "choose
/// as NLME-NETWORK-FORMATION.request does".
#[derive(Clone, Debug, Default)]
pub struct FormationParams {
    /// Network key (random when `None`).
    pub key: Option<Key128>,
    /// Extended PAN ID.
    pub extended_pan_id: Option<ExtendedAddress>,
    /// PAN ID.
    pub pan_id: Option<PanId>,
    /// Channels to consider (the configured primary channels when `None`);
    /// a single channel skips the energy scan.
    pub channels: Option<ChannelMask>,
    /// Network address (distributed networks only).
    pub network_address: Option<ShortAddress>,
    /// `nwkUpdateId` to start with.
    pub update_id: u8,
}

/// Parameters of an out-of-band network adoption: the device joins
/// without any over-the-air exchange (ZD 1.1 §7.7.2.7.4).
#[derive(Clone, Debug)]
pub struct AdoptParams {
    /// Extended PAN ID.
    pub extended_pan_id: ExtendedAddress,
    /// PAN ID.
    pub pan_id: PanId,
    /// Operating channel.
    pub channel: Channel,
    /// Network address (random when `None`).
    pub network_address: Option<ShortAddress>,
    /// Network key.
    pub key: Key128,
    /// Active key sequence number.
    pub key_sequence: KeySequenceNumber,
    /// `nwkUpdateId`.
    pub update_id: u8,
    /// Trust Center address (all ones for distributed networks).
    pub trust_center: ExtendedAddress,
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Extended PAN ID of the current network.
    pub const fn extended_pan_id(&self) -> ExtendedAddress {
        self.nwk.nib.extended_pan_id
    }

    /// Operating channel.
    pub const fn channel(&self) -> Channel {
        self.nwk.nib.channel
    }

    /// `nwkUpdateId`.
    pub const fn update_id(&self) -> u8 {
        self.nwk.nib.update_id
    }

    /// Active network key sequence number.
    pub const fn network_key_sequence(&self) -> KeySequenceNumber {
        self.network_key_sequence
    }

    /// Trust Center address (`apsTrustCenterAddress`).
    pub const fn trust_center_address(&self) -> ExtendedAddress {
        self.aps.aib.trust_center_address
    }

    /// Whether joining is currently permitted on this device.
    pub fn permit_joining_active(&self) -> bool {
        self.nwk.permit_joining_active()
    }

    /// Whether the stack is idle (not on a network and not commissioning).
    pub fn is_idle(&self) -> bool {
        self.phase == Phase::Idle
    }

    /// Forms a network from explicit parameters (ZD 1.1 §7.7.2.5.1).
    /// Centralized networks need the coordinator role, distributed ones
    /// a router configured for distributed security.
    pub fn form_network_params(&mut self, p: &FormationParams) -> Result<(), NwkStatus> {
        if self.phase != Phase::Idle {
            return Err(NwkStatus::InvalidRequest);
        }
        let key = match &p.key {
            Some(k) => k.clone(),
            None => {
                let mut k = [0u8; 16];
                self.nwk.rng().fill_bytes(&mut k);
                Key128::from_bytes(k)
            }
        };
        self.network_key_sequence = KeySequenceNumber(0);
        self.nwk.set_network_key(KeySequenceNumber(0), key, true);
        if let Some(e) = p.extended_pan_id {
            self.nwk.nib.extended_pan_id = e;
        }
        self.nwk.nib.update_id = p.update_id;
        let channels = p.channels.unwrap_or(self.config.channels);
        let distributed = self.config.distributed;
        self.nwk
            .network_formation_with(
                channels,
                self.config.scan_duration,
                distributed,
                p.pan_id,
                p.network_address,
            )
            .map_err(|_| NwkStatus::InvalidRequest)?;
        self.phase = Phase::Forming;
        Ok(())
    }

    /// Adopts a network out of band and resumes on it: routers start
    /// routing and announce themselves, end devices perform a secured
    /// rejoin to find a parent. Returns `InvalidRequest` when the stack
    /// is not idle.
    pub fn adopt_network(&mut self, p: &AdoptParams) -> Result<(), NwkStatus> {
        if self.phase != Phase::Idle {
            return Err(NwkStatus::InvalidRequest);
        }
        let short = match (self.config.role, p.network_address) {
            (LogicalDeviceType::Coordinator, _) => ShortAddress::COORDINATOR,
            (_, Some(a)) if a.is_unicast() => a,
            (_, Some(_)) => return Err(NwkStatus::InvalidParameter),
            (_, None) => loop {
                let a = ShortAddress(self.nwk.rng().next_u16());
                if a.is_unicast() && a != ShortAddress::COORDINATOR {
                    break a;
                }
            },
        };
        let depth = u8::from(self.config.role != LogicalDeviceType::Coordinator);
        let nib = &mut self.nwk.nib;
        nib.extended_pan_id = p.extended_pan_id;
        nib.pan_id = p.pan_id;
        nib.channel = p.channel;
        nib.network_address = short;
        nib.update_id = p.update_id;
        nib.depth = depth;
        self.network_key_sequence = p.key_sequence;
        self.nwk
            .set_network_key(p.key_sequence, p.key.clone(), true);
        self.aps.aib.trust_center_address = p.trust_center;
        self.config.distributed = p.trust_center == ExtendedAddress::BROADCAST;
        self.nwk.warm_start();
        self.aps
            .set_network_state(short, DeviceState::JoinedAuthorized);
        self.phase = Phase::Operating;
        let _ = self.persist_nib();
        let _ = self.persist_network_keys();
        self.resume()
    }

    /// Leaves the network, optionally taking the children along
    /// (NLME-LEAVE.request with RemoveChildren).
    pub fn leave_with(&mut self, rejoin: bool, remove_children: bool) -> Result<(), NwkStatus> {
        self.nwk
            .leave(None, rejoin, remove_children)
            .map_err(|_| NwkStatus::InvalidRequest)
    }

    /// Installs (or replaces) the link key used with `partner` (the
    /// Trust Center for a joiner, a joiner for the Trust Center) as a
    /// provisional or verified entry (ZD 1.1 Table 35 flags). A
    /// provisional Trust Center key is replaced through the usual key
    /// update once on the network.
    pub fn install_link_key(
        &mut self,
        partner: ExtendedAddress,
        key: Key128,
        kind: LinkKeyKind,
        provisional: bool,
    ) {
        let is_tc = self.config.role == LogicalDeviceType::Coordinator && !self.config.distributed;
        if !is_tc {
            self.config.preconfigured_link_key = (partner, key.clone(), kind);
            if !self.config.distributed {
                self.aps.aib.trust_center_address = partner;
            }
        }
        self.aps.security.remove(partner);
        let mut e = LinkKeyEntry::provisional(partner, key, kind);
        e.attributes = if provisional {
            KeyAttributes::ProvisionalKey
        } else {
            KeyAttributes::VerifiedKey
        };
        let _ = self.aps.security.install(e);
        let _ = self.persist_link_keys();
    }

    /// Refreshes the Diagnostics server on `endpoint` (ZCL8 §3.15) from
    /// the stack's counters: MAC unicast transmissions and failures, APS
    /// retries and failures, NWK / APS security drops, replays, relayed
    /// unicasts, queue overflows and the last frame's LQI / RSSI.
    /// Counters the stack does not keep are left untouched.
    pub fn refresh_diagnostics(&mut self, endpoint: Endpoint) -> bool {
        use panweave_zcl::clusters::diagnostics::{self, Counters, wrap16};
        let nwk = self.nwk.stats;
        let aps = self.aps.stats;
        let counters = Counters {
            mac_tx_ucast: Some(u32::from(self.nwk.nib.tx_total)),
            mac_tx_ucast_fail: Some(self.nwk.nib.tx_failures),
            aps_tx_ucast_retry: Some(wrap16(aps.retries)),
            aps_tx_ucast_fail: Some(wrap16(aps.ack_failures)),
            nwk_fc_failure: Some(wrap16(nwk.replays)),
            aps_unauthorized_key: Some(wrap16(aps.policy_dropped)),
            nwk_decrypt_failures: Some(wrap16(nwk.security_failures)),
            aps_decrypt_failures: Some(wrap16(aps.security_dropped)),
            packet_buffer_allocate_failures: Some(wrap16(
                aps.events_dropped.saturating_add(aps.actions_dropped),
            )),
            relayed_ucast: Some(wrap16(nwk.relayed)),
            packet_validate_drop_count: Some(wrap16(nwk.malformed.saturating_add(aps.malformed))),
            last_lqi: self.last_rx.map(|(l, _)| l),
            last_rssi: self.last_rx.map(|(_, r)| r),
            ..Counters::default()
        };
        match self
            .zcl
            .cluster_mut(endpoint, diagnostics::ID, panweave_zcl::Role::Server)
        {
            Some(c) => {
                diagnostics::update(c, &counters);
                true
            }
            None => false,
        }
    }

    /// Removes the link key held for `partner`.
    pub fn remove_link_key(&mut self, partner: ExtendedAddress) -> bool {
        let removed = self.aps.security.remove(partner);
        if removed {
            let _ = self.persist_link_keys();
        }
        removed
    }
}
