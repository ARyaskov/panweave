//! Out-of-band provisioning of the stack: formation and network
//! adoption with caller-supplied parameters, and the network-state
//! queries a commissioning front end (Zigbee Direct, a serial host
//! protocol, tests) needs. Nothing here bypasses the security model:
//! keys still enter through the NWK/APS key stores and the Trust
//! Center policy stays in force.

use panweave_aps::layer::{DeviceState, NwkView};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_storage::Storage;
use panweave_types::{
    Channel, ChannelMask, CryptoRng, Duration, Endpoint, ExtendedAddress, Instant, Key128,
    KeyAttributes, KeySequenceNumber, LogicalDeviceType, NwkStatus, PanId, ShortAddress,
};

use panweave_zcl::Role;
use panweave_zcl::clusters::commissioning::{self, StartupSet};

use crate::stack::{JoinMode, Phase, Stack};

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

    /// A fresh random 128-bit key from the stack's RNG (for network key
    /// updates and application link keys).
    pub fn random_key(&mut self) -> Key128 {
        let mut bytes = [0u8; 16];
        self.nwk.rng().fill_bytes(&mut bytes);
        Key128::from_bytes(bytes)
    }

    /// Trust Center network key update (§4.6.3.4.1): `key` becomes the
    /// alternate network key with the next sequence number, is broadcast
    /// to all rx-on devices under the current key (sleepy children get
    /// their copies when they poll), and after
    /// `nwkNetworkBroadcastDeliveryTime` a Switch Key broadcast makes it
    /// active everywhere, this device included. Returns the new sequence
    /// number. One update at a time.
    pub fn update_network_key(&mut self, key: Key128) -> Result<KeySequenceNumber, NwkStatus> {
        if !self.aps.config.is_trust_center
            || self.aps.aib.is_distributed()
            || self.phase != Phase::Operating
        {
            return Err(NwkStatus::InvalidRequest);
        }
        if self.key_update.is_some() {
            return Err(NwkStatus::InvalidRequest);
        }
        let sequence = KeySequenceNumber(self.network_key_sequence.0.wrapping_add(1));
        self.nwk.set_network_key(sequence, key.clone(), false);
        self.aps
            .transport_network_key(
                ExtendedAddress::ZERO,
                &key,
                sequence,
                panweave_aps::layer::KeyRoute::Broadcast,
            )
            .map_err(|_| NwkStatus::InvalidRequest)?;
        // The Trust Center's own rx-off children never hear the
        // broadcast (§4.4.2.3 last paragraph).
        let tc = self.aps.aib.trust_center_address;
        self.relay_network_key_to_sleepy_children(&key, sequence, tc);
        let at = self
            .now
            .saturating_add(self.nwk.nib.network_broadcast_delivery_time);
        self.key_update = Some((sequence, at));
        self.update_virtual_devices_keys(sequence);
        self.pump();
        Ok(sequence)
    }

    /// Second half of [`Stack::update_network_key`]: the Switch Key
    /// broadcast and the local switch (§4.6.3.4.1 / §4.6.3.4.2).
    pub(crate) fn poll_key_update(&mut self, now: Instant) {
        let Some((sequence, at)) = self.key_update else {
            return;
        };
        if !now.has_reached(at) {
            return;
        }
        self.key_update = None;
        let _ = self.aps.switch_key(sequence);
        if self.nwk.switch_network_key(sequence) {
            self.network_key_sequence = sequence;
        }
    }

    /// Asks the Trust Center for an application link key shared with
    /// `partner` (APSME-REQUEST-KEY.request, §4.4.6.1, BDB 3.1 §7.4).
    /// The key arrives as [`StackEvent::ApplicationLinkKey`] on both
    /// devices once the Trust Center's policy allows it.
    pub fn request_application_link_key(
        &mut self,
        partner: ExtendedAddress,
    ) -> Result<(), NwkStatus> {
        let tc = self.aps.aib.trust_center_address;
        let tc_short = crate::context::AddrView(&self.nwk)
            .short_of(tc)
            .unwrap_or(ShortAddress::COORDINATOR);
        self.aps
            .request_key(
                tc_short,
                panweave_aps::command::RequestKeyType::ApplicationLinkKey,
                Some(partner),
            )
            .map(|_| ())
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

    /// The current startup set of the Commissioning server on
    /// `endpoint` (ZCL8 §13.2), when present.
    pub fn startup_set(&self, endpoint: Endpoint) -> Option<StartupSet> {
        self.zcl
            .cluster(endpoint, commissioning::ID, Role::Server)
            .map(commissioning::load)
    }

    /// Seeds the Commissioning server on `endpoint` with the stack's
    /// live network parameters (short address, extended PAN ID, PAN ID,
    /// channel, Trust Center, key sequence; the keys stay unspecified).
    pub fn seed_startup_set(&mut self, endpoint: Endpoint) -> bool {
        let short = self.nwk.nib.network_address.0;
        let epid = self.nwk.nib.extended_pan_id.0;
        let pan = self.nwk.nib.pan_id.0;
        let channel = self.nwk.nib.channel;
        let tc = self.aps.aib.trust_center_address.0;
        let seq = self.network_key_sequence.0;
        let joined = self.phase == Phase::Operating;
        let Some(c) = self
            .zcl
            .cluster_mut(endpoint, commissioning::ID, Role::Server)
        else {
            return false;
        };
        let mut set = commissioning::load(c);
        if joined {
            set.short_address = short;
            set.extended_pan_id = epid;
            set.pan_id = pan;
            set.channel_mask = ChannelMask(0).with(channel).0;
            set.trust_center_address = tc;
            set.network_key_seq_num = seq;
            set.startup_control = commissioning::startup_control::SILENT_JOIN;
        }
        commissioning::store(c, &set);
        true
    }

    /// Runs the startup procedure of a Commissioning startup set
    /// (ZCL8 Table 13-5): leaves the current network first when on one
    /// (the set is applied once the leave completes, `StackEvent::Left`),
    /// installs the preconfigured link key when given, then forms,
    /// silently adopts, rejoins or associates per `StartupControl`.
    pub fn restart_from_startup_set(&mut self, set: &StartupSet) -> Result<(), NwkStatus> {
        if !set.is_consistent() {
            return Err(NwkStatus::InvalidParameter);
        }
        if self.phase != Phase::Idle {
            self.pending_startup = Some(set.clone());
            return self.leave_with(false, false);
        }
        self.apply_startup_set(set)
    }

    /// Runs a Restart Device whose delay elapsed (ZCL8 §13.2.2.3.1).
    pub(crate) fn poll_pending_restart(&mut self, now: Instant) {
        let Some((at, endpoint, install)) = self.pending_restart else {
            return;
        };
        if !now.has_reached(at) {
            return;
        }
        self.pending_restart = None;
        if install {
            if let Some(set) = self.startup_set(endpoint) {
                let _ = self.restart_from_startup_set(&set);
            }
        } else if self.phase == Phase::Operating {
            let _ = self.resume();
        }
    }

    /// Applies a startup set deferred by [`Self::restart_from_startup_set`].
    pub(crate) fn apply_pending_startup(&mut self) {
        if let Some(set) = self.pending_startup.take() {
            let _ = self.apply_startup_set(&set);
        }
    }

    fn apply_startup_set(&mut self, set: &StartupSet) -> Result<(), NwkStatus> {
        let channels = ChannelMask(set.channel_mask & ChannelMask::ALL_2_4GHZ.0);
        // The join, end-device and concentrator parameter sets (Tables
        // 13-7 – 13-9) become the stack's ZDO configuration attributes,
        // poll rate and concentrator settings.
        self.config.zdo.scan_attempts = set.scan_attempts.max(1);
        // TimeBetweenScans is in milliseconds; the ZDO attribute counts
        // octet durations (16 µs).
        self.config.zdo.time_between_scans_octets =
            u16::try_from(u32::from(set.time_between_scans) * 1000 / 16).unwrap_or(u16::MAX);
        self.config.zdo.rejoin_interval_secs = set.rejoin_interval;
        self.config.zdo.max_rejoin_interval_secs = set.max_rejoin_interval;
        if set.parent_retry_threshold != 0xff {
            self.config.zdo.parent_link_retry_threshold = set.parent_retry_threshold;
        }
        if set.indirect_poll_rate != 0 {
            self.config.poll_interval = Duration::from_millis(u64::from(set.indirect_poll_rate));
        }
        self.nwk.config.concentrator = set.concentrator;
        self.nwk.config.concentrator_radius = set.concentrator_radius;
        self.nwk.config.concentrator_discovery_time_secs =
            u32::from(set.concentrator_discovery_time);
        let key_given = set.network_key.as_bytes().iter().any(|b| *b != 0);
        let link_key_given = set
            .preconfigured_link_key
            .as_bytes()
            .iter()
            .any(|b| *b != 0);
        if link_key_given && set.trust_center_address != 0 {
            self.install_link_key(
                ExtendedAddress(set.trust_center_address),
                set.preconfigured_link_key.clone(),
                LinkKeyKind::Global,
                true,
            );
        }
        match set.startup_control {
            commissioning::startup_control::FORM => self.form_network_params(&FormationParams {
                key: key_given.then(|| set.network_key.clone()),
                extended_pan_id: Some(ExtendedAddress(set.extended_pan_id)),
                pan_id: (set.pan_id != 0xffff).then_some(PanId(set.pan_id)),
                channels: Some(channels),
                network_address: None,
                update_id: 0,
            }),
            commissioning::startup_control::SILENT_JOIN => {
                let channel = channels.first().ok_or(NwkStatus::InvalidParameter)?;
                self.adopt_network(&AdoptParams {
                    extended_pan_id: ExtendedAddress(set.extended_pan_id),
                    pan_id: PanId(set.pan_id),
                    channel,
                    network_address: Some(ShortAddress(set.short_address)),
                    key: set.network_key.clone(),
                    key_sequence: KeySequenceNumber(set.network_key_seq_num),
                    update_id: 0,
                    trust_center: ExtendedAddress(set.trust_center_address),
                })
            }
            commissioning::startup_control::REJOIN => {
                self.nwk.nib.extended_pan_id = ExtendedAddress(set.extended_pan_id);
                let mode = if key_given {
                    self.network_key_sequence = KeySequenceNumber(set.network_key_seq_num);
                    self.nwk.set_network_key(
                        KeySequenceNumber(set.network_key_seq_num),
                        set.network_key.clone(),
                        true,
                    );
                    JoinMode::SecuredRejoin
                } else {
                    JoinMode::TrustCenterRejoin
                };
                self.join_on(mode, channels, self.config.scan_duration)
            }
            _ => self.join_on(JoinMode::Association, channels, self.config.scan_duration),
        }
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
        let mac = self.mac.stats;
        let neighbors = &self.nwk.neighbors;
        let aps_sent = aps.tx_ucast_success.saturating_add(aps.ack_failures);
        let counters = Counters {
            mac_rx_bcast: Some(mac.rx_bcast),
            mac_tx_bcast: Some(mac.tx_bcast),
            mac_rx_ucast: Some(mac.rx_ucast),
            mac_tx_ucast: Some(mac.tx_ucast),
            mac_tx_ucast_retry: Some(wrap16(mac.tx_ucast_retry)),
            mac_tx_ucast_fail: Some(wrap16(mac.tx_ucast_fail)),
            aps_rx_bcast: Some(wrap16(aps.rx_bcast)),
            aps_tx_bcast: Some(wrap16(aps.tx_bcast)),
            aps_rx_ucast: Some(wrap16(aps.rx_ucast)),
            aps_tx_ucast_success: Some(wrap16(aps.tx_ucast_success)),
            aps_tx_ucast_retry: Some(wrap16(aps.retries)),
            aps_tx_ucast_fail: Some(wrap16(aps.ack_failures)),
            route_disc_initiated: Some(wrap16(nwk.route_discoveries)),
            neighbor_added: Some(wrap16(neighbors.added)),
            neighbor_removed: Some(wrap16(neighbors.removed)),
            neighbor_stale: Some(wrap16(neighbors.stale)),
            join_indication: Some(wrap16(nwk.join_indications)),
            child_moved: Some(wrap16(nwk.children_moved)),
            phy_to_mac_queue_limit_reached: Some(wrap16(mac.queue_limit_reached)),
            average_mac_retry_per_aps_message_sent: Some(wrap16(
                mac.tx_ucast_retry.checked_div(aps_sent).unwrap_or(0),
            )),
            nwk_fc_failure: Some(wrap16(nwk.replays)),
            aps_fc_failure: Some(wrap16(aps.fc_failures)),
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
            .cluster_mut(endpoint, diagnostics::ID, Role::Server)
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
