//! Zigbee Direct device (ZDD) binding: [`Node`] implements the
//! Commissioning Service's [`Zdd`] trait so a host's BLE transport can
//! hand decrypted characteristic writes to
//! `panweave_direct::commissioning::Commissioning` and drive the stack
//! with them (ZD 1.1 §7.7.2). Operation results surface as
//! [`Event::Direct`], which the host forwards to
//! `Commissioning::report` to notify the ZVD. The Tunnel Service (§7.7.3)
//! is bound by [`Node::open_tunnel`] / [`Node::on_tunnel_write`] /
//! [`Node::close_tunnel`] and [`Event::DirectTunnel`]: the ZVD is a NWK
//! neighbour behind a Trusted Link of the stack.

use panweave_aps::command::KeyDescriptor;
use panweave_bdb::Outcome;
use panweave_codec::Decode;
use panweave_direct::commissioning::{
    DeviceType, Domain, FindingBinding, FormNetwork, JoinNetwork, JoinedStatus, JoiningMethod,
    LeaveNetwork, ManageJoiners, NetworkInfo, NetworkStatus, STATUS_FAILURE, STATUS_SUCCESS,
    StatusReport, Zdd,
};
use panweave_direct::legacy::{self, Direction, EphemeralSession, Observation};
use panweave_direct::rotation::{Forwarding, PastNetworkKeys, forwarding_decision};
use panweave_direct::tunnel::{self, NpduMessage, SessionKind, TunnelError};
use panweave_nwk::command::{CommissioningRequest, CommissioningType, NwkCommandId};
use panweave_nwk::frame::{FrameType as NwkFrameType, Header as NwkHeader};
use panweave_nwk::tlv::{DeviceCapabilityExtension, GlobalTlvs};
use panweave_runtime::EndpointError;
use panweave_runtime::{AdoptParams, FormationParams, JoinMode, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::LinkKeyKind;
use panweave_storage::{Key, Kind, Storage, StorageError};
use panweave_types::{
    ChannelMask, CryptoRng, Endpoint, ExtendedAddress, Key128, KeyAttributes, KeySequenceNumber,
    LogicalDeviceType,
};
use panweave_types::{ProfileId, ShortAddress};
use panweave_zcl::cluster::Role;
use panweave_zcl::clusters::{direct_configuration, identify};

use crate::{Event, Node};

/// Zigbee Direct state a [`Node`] keeps between characteristic writes.
#[derive(Clone, Debug)]
pub struct DirectState {
    /// The operation whose completion is awaited.
    pending: Option<Domain>,
    /// Endpoint used for Identify when the ZVD does not name one (the
    /// first endpoint with an Identify server otherwise).
    pub identify_endpoint: Option<Endpoint>,
    /// Admin key handed over by the ZVD (Table 36 / §7.7.2.7.1); when
    /// `None` the host derives it from the Trust Center link key with
    /// `panweave_direct::auth::admin_key`.
    pub admin_key: Option<Key128>,
    /// The network keys this device switched away from (ZD §9.1): a ZVD
    /// whose Basic authorization key was derived from one of them may
    /// open a Limited Authorization session and Trust Center rejoin.
    /// Recorded on every key switch and persisted.
    pub past_network_keys: PastNetworkKeys<PAST_NETWORK_KEYS>,
    /// Open tunnels: the Trusted Link index and the ZVD behind it.
    pub tunnels: heapless::Vec<(u8, ExtendedAddress), 4>,
    /// Per tunnel, the kind of the last Network Commissioning Request
    /// the ZVD sent through it (an initial join or a rejoin) with the
    /// session it came on: tells a provisioning session from a Limited
    /// Authorization one when a legacy Trust Center's network key
    /// arrives (§10).
    last_join: heapless::Vec<(u8, CommissioningType, SessionKind), 4>,
    /// Ephemeral authorization sessions of ZVDs on a legacy network
    /// (§10.1), per tunnel, with whether the ZVD is router-capable (it
    /// is routed on behalf of like an end device while ephemeral,
    /// §10.1.1).
    pub legacy: heapless::Vec<(u8, EphemeralSession, bool), 4>,
    /// Whether the last declined Transport Key was secured with the
    /// well-known key (§10 step 2.1: the global ephemeral key applies).
    legacy_probe_global: bool,
    /// The Zigbee Direct interface is enabled (ZD 1.1 §11.3.5.4.3);
    /// persistent.
    pub interface_enabled: bool,
    /// The Anonymous Join Timeout in seconds (§11.3.5.4.4; 0 never,
    /// 0xFFFFFF always while the network is open); persistent.
    pub anonymous_join_timeout: u32,
    /// The Anonymous Join Countdown Timer: until when the anonymous
    /// secret is accepted (restarted on power-up and reconfiguration).
    pub anonymous_join_until: Option<panweave_types::time::Instant>,
    /// Whether the Trust Center is Zigbee Direct aware (§6.2.3), once
    /// checked with [`Node::check_direct_aware`].
    pub trust_center_aware: Option<bool>,
    /// The ZDP transaction of the awareness check in flight.
    aware_seq: Option<panweave_types::TransactionSequence>,
    /// A Trust Center link key update owed after an out-of-band join
    /// with a provisional key (§7.7.2.7.4): retried at this time until
    /// the key is verified; the ZDD never leaves over it.
    tclk_update_retry: Option<panweave_types::time::Instant>,
}

impl Default for DirectState {
    /// The interface enabled and the recommended Anonymous Join Timeout
    /// of 3600 s (ZD 1.1 §11.3.5.3.2).
    fn default() -> Self {
        DirectState {
            pending: None,
            identify_endpoint: None,
            admin_key: None,
            past_network_keys: PastNetworkKeys::default(),
            tunnels: heapless::Vec::new(),
            last_join: heapless::Vec::new(),
            legacy: heapless::Vec::new(),
            legacy_probe_global: false,
            interface_enabled: true,
            anonymous_join_timeout: direct_configuration::ANONYMOUS_JOIN_DEFAULT,
            anonymous_join_until: None,
            trust_center_aware: None,
            aware_seq: None,
            tclk_update_retry: None,
        }
    }
}

/// How long the ZDD waits before retrying the Trust Center link key
/// update owed after an out-of-band join (§7.7.2.7.4 asks for a retry
/// "when a connection with the TC is available"; the interval is an
/// implementation choice).
pub const TCLK_UPDATE_RETRY: panweave_types::time::Duration =
    panweave_types::time::Duration::from_secs(60);

/// Format octet of the `Kind::DirectAdminKey` record.
const DIRECT_ADMIN_KEY_FORMAT: u8 = 1;

/// Past network keys kept for Limited Authorization sessions.
pub const PAST_NETWORK_KEYS: usize = 4;

/// Format octet of the `Kind::DirectConfig` record.
const DIRECT_CONFIG_FORMAT: u8 = 1;

impl<C: BlockCipher, R: CryptoRng, S: Storage> Node<C, R, S> {
    /// Keeps the network key a key switch retires (ZD §9.1) and
    /// persists the set.
    pub(crate) fn direct_on_key_switched(&mut self, previous: Option<KeySequenceNumber>) {
        let Some(p) = previous else {
            return;
        };
        let Some(slot) = self.stack.nwk.security.keys.get(p) else {
            return;
        };
        self.direct.past_network_keys.record(p, slot.key.clone());
        let _ = self.persist_direct_past_keys();
    }

    /// Adds the Zigbee Direct Configuration server (ZD 1.1 §11.3) to
    /// `endpoint` with the current interface state and timeout; the
    /// Trust Center configures it from there. Fails when the endpoint is
    /// unknown or full.
    pub fn enable_direct_configuration(&mut self, endpoint: Endpoint) -> Result<(), EndpointError> {
        let centralized = !self.stack.config.distributed;
        let c = direct_configuration::server(
            self.direct.interface_enabled,
            self.direct.anonymous_join_timeout,
            centralized,
        )
        .map_err(|_| EndpointError)?;
        let ep = self.stack.zcl.endpoint_mut(endpoint).ok_or(EndpointError)?;
        ep.add_instance(c).map_err(|_| EndpointError)
    }

    /// Whether Zigbee Direct requests are processed (§11.3.5.4.3): the
    /// host stops advertising and drops service requests when not.
    pub fn direct_interface_enabled(&self) -> bool {
        self.direct.interface_enabled
    }

    /// Whether a provisioning session with the Anonymous Well-Known
    /// Secret may be established now (§11.3.5.4.4): only while the
    /// network is open to new devices and the Anonymous Join Countdown
    /// Timer has not expired.
    pub fn anonymous_join_allowed(&self) -> bool {
        if !self.stack.permit_joining_active() {
            return false;
        }
        match self.direct.anonymous_join_timeout {
            0 => false,
            direct_configuration::ANONYMOUS_JOIN_ALWAYS => true,
            _ => self
                .direct
                .anonymous_join_until
                .is_some_and(|t| !self.stack.now().has_reached(t)),
        }
    }

    /// (Re)starts the Anonymous Join Countdown Timer (power-up or a
    /// local stimulus, §11.3.5.4.4).
    pub fn restart_anonymous_join_countdown(&mut self) {
        let now = self.stack.now();
        self.direct.anonymous_join_until = match self.direct.anonymous_join_timeout {
            0 | direct_configuration::ANONYMOUS_JOIN_ALWAYS => None,
            secs => Some(now + panweave_types::time::Duration::from_secs(u64::from(secs))),
        };
    }

    /// Applies a Trust Center's configuration (the stack events of the
    /// Zigbee Direct Configuration server): persists it and restarts
    /// the countdown.
    pub(crate) fn direct_on_configured(&mut self, event: &StackEvent) {
        match event {
            StackEvent::DirectInterface { enabled, .. } => {
                self.direct.interface_enabled = *enabled;
                let _ = self.persist_direct_config();
            }
            StackEvent::DirectAnonymousJoinTimeout { seconds, .. } => {
                self.direct.anonymous_join_timeout = *seconds;
                self.restart_anonymous_join_countdown();
                let _ = self.persist_direct_config();
            }
            _ => {}
        }
    }

    /// Writes the interface configuration to storage.
    pub fn persist_direct_config(&mut self) -> Result<(), StorageError> {
        let t = self.direct.anonymous_join_timeout.to_le_bytes();
        let buf = [
            DIRECT_CONFIG_FORMAT,
            u8::from(self.direct.interface_enabled),
            t[0],
            t[1],
            t[2],
        ];
        self.stack
            .storage
            .store(Key::single(Kind::DirectConfig), &buf)
    }

    /// Restores the interface configuration (part of warm start) and
    /// starts the Anonymous Join Countdown Timer as after a power-cycle.
    pub fn restore_direct_config(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; 8];
        if let Some(n) = self
            .stack
            .storage
            .load(Key::single(Kind::DirectConfig), &mut buf)?
            && n >= 5
            && buf[0] == DIRECT_CONFIG_FORMAT
        {
            self.direct.interface_enabled = buf[1] & 0x01 != 0;
            self.direct.anonymous_join_timeout = u32::from_le_bytes([buf[2], buf[3], buf[4], 0]);
        }
        self.restart_anonymous_join_countdown();
        Ok(())
    }

    /// Checks whether the Trust Center is Zigbee Direct aware (§6.2.3):
    /// a Match_Desc_req for the Zigbee Direct Configuration client
    /// cluster on all its endpoints; the answer lands in
    /// `DirectState::trust_center_aware`. Distributed networks are
    /// aware by definition.
    pub fn check_direct_aware(&mut self) -> bool {
        if self.stack.config.distributed {
            self.direct.trust_center_aware = Some(true);
            return true;
        }
        let mut req = [0u8; 8];
        req[..2].copy_from_slice(&ShortAddress::COORDINATOR.0.to_le_bytes());
        req[2..4].copy_from_slice(&ProfileId::HOME_AUTOMATION.0.to_le_bytes());
        req[4] = 0;
        req[5] = 1;
        req[6..8].copy_from_slice(&direct_configuration::ID.0.to_le_bytes());
        match self.stack.zdo.request(
            ShortAddress::COORDINATOR,
            panweave_zdo::zdp::cluster::MATCH_DESC_REQ,
            &req,
        ) {
            Ok(seq) => {
                self.direct.aware_seq = Some(seq);
                self.stack.flush();
                true
            }
            Err(_) => false,
        }
    }

    /// The Match_Desc response of the awareness check.
    pub(crate) fn direct_on_aware_answer(&mut self, event: &StackEvent) {
        match event {
            StackEvent::Zdp(z) if Some(z.seq) == self.direct.aware_seq => {
                self.direct.aware_seq = None;
                // Match_Desc_rsp: status, address, match length, endpoints.
                let matched = z.data.first() == Some(&0) && z.data.get(3).is_some_and(|n| *n > 0);
                self.direct.trust_center_aware = Some(matched);
            }
            StackEvent::ZdpTimeout { seq, .. } if Some(*seq) == self.direct.aware_seq => {
                self.direct.aware_seq = None;
                self.direct.trust_center_aware = Some(false);
            }
            _ => {}
        }
    }

    /// The Admin authorization key of `zvd` (§6.3.2.1): the key a ZVD
    /// provisioned with the network parameters when there is one,
    /// otherwise the key derived from the active Trust Center link key
    /// on a centralized network; `None` on a distributed network without
    /// a provisioned key (no admin access, §7.7.2.7.1).
    pub fn admin_key_for(&self, zvd: ExtendedAddress) -> Option<Key128> {
        if let Some(k) = &self.direct.admin_key {
            return Some(k.clone());
        }
        if self.stack.config.distributed || !self.stack.is_operating() {
            return None;
        }
        let tc = self.stack.aps.aib.trust_center_address;
        self.stack
            .aps
            .security
            .entry(tc)
            .map(|e| panweave_direct::auth::admin_key::<C>(zvd, &e.key))
    }

    /// Keeps the Admin key of a Form / Join Network write: a provided
    /// key is stored until a factory reset (§6.3.2.1); a write without
    /// one leaves an earlier key alone.
    fn store_admin_key(&mut self, key: Option<&Key128>) {
        if let Some(k) = key {
            self.direct.admin_key = Some(k.clone());
            let mut buf = [0u8; 17];
            buf[0] = DIRECT_ADMIN_KEY_FORMAT;
            buf[1..].copy_from_slice(k.as_bytes());
            let _ = self
                .stack
                .storage
                .store(Key::single(Kind::DirectAdminKey), &buf);
        }
    }

    /// Restores the provisioned Admin key (part of warm start).
    pub fn restore_direct_admin_key(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; 17];
        if let Some(n) = self
            .stack
            .storage
            .load(Key::single(Kind::DirectAdminKey), &mut buf)?
            && n == 17
            && buf[0] == DIRECT_ADMIN_KEY_FORMAT
        {
            let mut k = [0u8; 16];
            k.copy_from_slice(&buf[1..]);
            self.direct.admin_key = Some(Key128::from_bytes(k));
        }
        Ok(())
    }

    /// Starts (or retries) the Trust Center link key update owed after
    /// an out-of-band join with a provisional key (§7.7.2.7.4).
    fn direct_start_tclk_update(&mut self) {
        let now = self.stack.now();
        self.direct.tclk_update_retry = Some(now + TCLK_UPDATE_RETRY);
        let _ = self.stack.update_trust_center_link_key();
    }

    /// Whether a Trust Center link key update is still owed.
    pub fn direct_tclk_update_pending(&self) -> bool {
        self.direct.tclk_update_retry.is_some()
    }

    /// The outcome of the owed link key update: verified or skipped
    /// closes it; a failure keeps the retry; leaving drops it.
    pub(crate) fn direct_on_tclk_update(&mut self, event: &StackEvent) {
        match event {
            StackEvent::LinkKeyUpdated
            | StackEvent::LinkKeyUpdateSkipped { .. }
            | StackEvent::Left { .. } => self.direct.tclk_update_retry = None,
            _ => {}
        }
    }

    /// Retries the owed link key update when its time has come and the
    /// key is still provisional.
    pub(crate) fn direct_poll(&mut self, now: panweave_types::time::Instant) {
        self.legacy_poll(now);
        if let Some(at) = self.direct.tclk_update_retry
            && now.has_reached(at)
        {
            if self.stack.is_operating() && self.stack.trust_center_link_key_is_provisional() {
                self.direct_start_tclk_update();
            } else {
                self.direct.tclk_update_retry = None;
            }
        }
    }

    /// Writes the past network keys to storage.
    pub fn persist_direct_past_keys(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; PAST_NETWORK_KEYS * PastNetworkKeys::<PAST_NETWORK_KEYS>::ENTRY_LEN];
        let n = self.direct.past_network_keys.encode(&mut buf).unwrap_or(0);
        self.stack.storage.store(
            Key::single(Kind::DirectPastKeys),
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Restores the past network keys from storage (part of warm start).
    pub fn restore_direct_past_keys(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; PAST_NETWORK_KEYS * PastNetworkKeys::<PAST_NETWORK_KEYS>::ENTRY_LEN];
        if let Some(n) = self
            .stack
            .storage
            .load(Key::single(Kind::DirectPastKeys), &mut buf)?
        {
            self.direct.past_network_keys = PastNetworkKeys::decode(buf.get(..n).unwrap_or(&[]));
        }
        Ok(())
    }

    /// Opens the Tunnel Service for the ZVD `peer` connected over BLE
    /// connection `handle`: Trusted Link `link` is registered with the
    /// stack (§7.7.4). Fails when the interface table is full.
    pub fn open_tunnel(&mut self, link: u8, handle: u16, peer: ExtendedAddress) -> bool {
        if !self.stack.add_trusted_link(link, handle) {
            return false;
        }
        self.direct.tunnels.retain(|(l, _)| *l != link);
        self.direct.tunnels.push((link, peer)).is_ok()
    }

    /// Closes a tunnel: the link and the ZVD's neighbour entry go.
    pub fn close_tunnel(&mut self, link: u8) {
        self.stack.remove_trusted_link(link);
        self.direct.tunnels.retain(|(l, _)| *l != link);
        self.direct.last_join.retain(|(l, _, _)| *l != link);
        self.direct.legacy.retain(|(l, _, _)| *l != link);
    }

    /// The legacy-network authorization session of the ZVD on `link`
    /// (ZD 1.1 §10.1), when the Trust Center predates Zigbee Direct.
    pub fn direct_legacy_session(&self, link: u8) -> Option<EphemeralSession> {
        self.direct
            .legacy
            .iter()
            .find(|(l, _, _)| *l == link)
            .map(|(_, s, _)| *s)
    }

    fn tunnel_peer(&self, link: u8) -> Option<ExtendedAddress> {
        self.direct
            .tunnels
            .iter()
            .find(|(l, _)| *l == link)
            .map(|(_, p)| *p)
    }

    /// Remembers the kind of Network Commissioning Request the ZVD
    /// sent on `link`.
    fn note_join_request(&mut self, link: u8, session: SessionKind, npdu: &[u8]) {
        let Ok((header, n)) = NwkHeader::decode_prefix(npdu) else {
            return;
        };
        if header.frame_control.frame_type() != NwkFrameType::Command {
            return;
        }
        let payload = npdu.get(n..).unwrap_or(&[]);
        if payload.first().copied().map(NwkCommandId::from_raw)
            != Some(NwkCommandId::CommissioningRequest)
        {
            return;
        }
        let Ok(req) = CommissioningRequest::decode_exact(payload.get(1..).unwrap_or(&[])) else {
            return;
        };
        self.direct.last_join.retain(|(l, _, _)| *l != link);
        let _ = self.direct.last_join.push((link, req.kind, session));
    }

    /// §10.1: whether an NPDU from the ZVD on `link` may enter the
    /// network during an ephemeral authorization session.
    fn legacy_allows_in(&self, link: u8, npdu: &[u8]) -> bool {
        let Some(session) = self.direct_legacy_session(link) else {
            return true;
        };
        let Ok((header, n)) = NwkHeader::decode_prefix(npdu) else {
            return false;
        };
        session.allows(
            Direction::FromZvd,
            header.frame_control.frame_type() == NwkFrameType::Command,
            header.dst == ShortAddress::COORDINATOR,
            npdu.get(n..).unwrap_or(&[]),
        )
    }

    /// §10: a legacy Trust Center's network key (a Transport Key the
    /// APSME declined) never reaches the ZVD on `link`; the ZDD proves
    /// the ZVD's authorization itself. An initial join gets an ephemeral
    /// authorization key (global when the Trust Center secured the key
    /// with the well-known key, unique otherwise) and opens an ephemeral
    /// session; a Trust Center rejoin gets a Basic key derived from the
    /// active network key (§9.1). Returns whether the frame was handled.
    fn legacy_on_declined(&mut self, link: u8) -> bool {
        if self.direct.trust_center_aware != Some(false) {
            return false;
        }
        let Some(zvd) = self.tunnel_peer(link) else {
            return false;
        };
        let Some(short) = self.stack.nwk.neighbors.by_extended(zvd).map(|n| n.short) else {
            return false;
        };
        let join = self
            .direct
            .last_join
            .iter()
            .find(|(l, _, _)| *l == link)
            .map(|(_, kind, session)| (*kind, *session));
        match join {
            Some((CommissioningType::InitialJoin, SessionKind::ZvdProvisioning)) => {
                if self.direct_legacy_session(link).is_some() {
                    // Already in an ephemeral session: a repeat of the
                    // network key changes nothing.
                    return true;
                }
                let global = self.direct.legacy_probe_global;
                self.legacy_install_well_known_entry(zvd);
                let seq = self.stack.nwk.nib.next_sequence();
                let _ = self.stack.aps.transport_authorization_key_as_trust_center(
                    zvd,
                    short,
                    KeyDescriptor::EphemeralAuthorization { global },
                    seq,
                );
                let deadline = self.stack.now() + self.stack.aps.aib.security_timeout_period;
                // §10.1.1: routed on behalf of like an end device child
                // while ephemeral.
                let mut router = false;
                if let Some(n) = self.stack.nwk.neighbors.by_extended_mut(zvd) {
                    router = n.is_router();
                    n.device_type = LogicalDeviceType::EndDevice;
                }
                let _ = self
                    .direct
                    .legacy
                    .push((link, EphemeralSession::new(deadline), router));
                self.stack.nwk.refresh_child_security_timer(zvd);
                self.stack.flush();
                true
            }
            Some((CommissioningType::Rejoin, SessionKind::ZvdProvisioning)) => {
                self.legacy_send_basic_key(zvd, short);
                self.stack.nwk.authenticate_child(zvd);
                self.stack.flush();
                true
            }
            _ => false,
        }
    }

    /// The ZDD's own key-pair entry for the ZVD under the well-known
    /// key, which secures the authorization keys it sends (§10).
    fn legacy_install_well_known_entry(&mut self, zvd: ExtendedAddress) {
        if self.stack.aps.security.entry(zvd).is_none() {
            let e = panweave_security::material::LinkKeyEntry::provisional(
                zvd,
                Key128::WELL_KNOWN_GLOBAL_TCLK,
                LinkKeyKind::Global,
            );
            let _ = self.stack.aps.install_link_key(e);
        }
    }

    /// Sends the ZVD its Basic authorization key derived from the active
    /// network key, on the Trust Center's behalf (§10, §10.1).
    fn legacy_send_basic_key(&mut self, zvd: ExtendedAddress, short: ShortAddress) {
        let sequence = self.stack.network_key_sequence();
        let Some(nwk_key) = self
            .stack
            .nwk
            .security
            .keys
            .get(sequence)
            .map(|s| s.key.clone())
        else {
            return;
        };
        let key = panweave_security::authorization::basic_key::<C>(zvd, &nwk_key);
        self.legacy_install_well_known_entry(zvd);
        let seq = self.stack.nwk.nib.next_sequence();
        let _ = self.stack.aps.transport_authorization_key_as_trust_center(
            zvd,
            short,
            KeyDescriptor::BasicAuthorizationKey {
                key,
                sequence,
                destination: zvd,
                source: self.stack.aps.aib.trust_center_address,
            },
            seq,
        );
    }

    /// §10.1 on the way out: the ephemeral filter for NPDUs to the ZVD
    /// and the watch for the Trust Center's key-load and data-key
    /// secured messages that end the ephemeral session with the Basic
    /// key. Returns whether the NPDU may be tunnelled.
    fn legacy_allows_out(&mut self, link: u8, npdu: &[u8]) -> bool {
        let Some(i) = self.direct.legacy.iter().position(|(l, _, _)| *l == link) else {
            return true;
        };
        let Ok((header, n)) = NwkHeader::decode_prefix(npdu) else {
            return false;
        };
        let nwk_command = header.frame_control.frame_type() == NwkFrameType::Command;
        let from_tc = header.src == ShortAddress::COORDINATOR;
        let aps = npdu.get(n..).unwrap_or(&[]);
        let Some((_, session, router)) = self.direct.legacy.get_mut(i) else {
            return true;
        };
        let router = *router;
        if !session.allows(Direction::ToZvd, nwk_command, from_tc, aps) {
            return false;
        }
        if !from_tc || nwk_command || legacy::aux_source(aps) == Some(self.stack.config.ieee) {
            // Not the Trust Center's (the ZDD's own aliased Transport
            // Keys carry its address in the auxiliary header).
            return true;
        }
        if session.observe_from_trust_center(aps) == Observation::DataKey {
            // The authentication sequence completed: the Basic key
            // follows this frame, and the ZVD is a child (or sibling
            // router) from now on.
            if let Some(zvd) = self.tunnel_peer(link) {
                let short = self.stack.nwk.neighbors.by_extended(zvd).map(|n| n.short);
                if let Some(short) = short {
                    self.legacy_send_basic_key(zvd, short);
                }
                self.stack.nwk.authenticate_child(zvd);
                if router && let Some(n) = self.stack.nwk.neighbors.by_extended_mut(zvd) {
                    n.device_type = LogicalDeviceType::Router;
                }
                self.stack.flush();
            }
        }
        true
    }

    /// §10.1 timekeeping: an ephemeral session keeps the ZVD's
    /// unauthenticated-child entry alive, and expires when the Trust
    /// Center gave no proof of end-to-end authentication in time.
    fn legacy_poll(&mut self, now: panweave_types::time::Instant) {
        let mut expired: heapless::Vec<u8, 4> = heapless::Vec::new();
        for (link, session, _) in self.direct.legacy.iter() {
            if session.is_ephemeral() {
                if session.timed_out(now) {
                    let _ = expired.push(*link);
                } else if let Some(peer) = self
                    .direct
                    .tunnels
                    .iter()
                    .find(|(l, _)| l == link)
                    .map(|(_, p)| *p)
                {
                    self.stack.nwk.refresh_child_security_timer(peer);
                }
            }
        }
        for link in expired {
            self.close_tunnel(link);
            self.push(Event::DirectAuthorizationTimeout { link });
        }
    }

    /// A decrypted write to the tunnel NPDU characteristic on `link`
    /// (§7.7.4.2, §7.7.3.6.2): every NPDU Message TLV is handed to the
    /// stack as received from the ZVD over the link; `session` applies
    /// the provisioning-session rule. Returns the first tunnel error.
    pub fn on_tunnel_write(
        &mut self,
        link: u8,
        session: SessionKind,
        payload: &[u8],
    ) -> Result<(), TunnelError> {
        let peer = self
            .direct
            .tunnels
            .iter()
            .find(|(l, _)| *l == link)
            .map(|(_, p)| *p)
            .ok_or(TunnelError::Malformed)?;
        // §10.1: an ephemeral authorization session elevates the
        // provisioning session; its own filter governs.
        let session = if self.direct_legacy_session(link).is_some() {
            SessionKind::Authorized
        } else {
            session
        };
        let mut first_error = None;
        for item in tunnel::preprocess(payload, session) {
            match item {
                Ok(m) => {
                    if !Self::declares_virtual_device(m.npdu) {
                        // §7.7.4.8: a Network Commissioning Request that
                        // does not declare a ZVD is dropped, or the
                        // Trust Center would send the network key.
                        first_error.get_or_insert(TunnelError::Dropped);
                        continue;
                    }
                    if !self.legacy_allows_in(link, m.npdu) {
                        // §10.1: an ephemeral session passes only the
                        // exchange with the Trust Center.
                        first_error.get_or_insert(TunnelError::Dropped);
                        continue;
                    }
                    self.note_join_request(link, session, m.npdu);
                    self.stack
                        .on_trusted_link_npdu(link, peer, m.npdu, m.assume_security);
                }
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        self.collect();
        first_error.map_or(Ok(()), Err)
    }

    /// Whether `npdu` is anything but a Network Commissioning Request
    /// lacking the Device Capability Extension Global TLV with the
    /// Zigbee Direct Virtual Device flag (§7.7.4.8).
    fn declares_virtual_device(npdu: &[u8]) -> bool {
        let Ok((header, n)) = NwkHeader::decode_prefix(npdu) else {
            return true;
        };
        if header.frame_control.frame_type() != NwkFrameType::Command {
            return true;
        }
        let Some(payload) = npdu.get(n..) else {
            return true;
        };
        if payload.first().copied().map(NwkCommandId::from_raw)
            != Some(NwkCommandId::CommissioningRequest)
        {
            return true;
        }
        let Ok(req) = CommissioningRequest::decode_exact(payload.get(1..).unwrap_or(&[])) else {
            return false;
        };
        req.tlv_set()
            .ok()
            .and_then(|set| {
                set.joiner_encapsulation()
                    .and_then(|inner| inner.device_capability_extension())
                    .or_else(|| set.device_capability_extension())
            })
            .is_some_and(|d| d.0 & DeviceCapabilityExtension::ZIGBEE_DIRECT_VIRTUAL_DEVICE != 0)
    }

    /// Turns a stack NPDU for a Trusted Link into the tunnel TLV
    /// (§7.7.4.1).
    pub(crate) fn direct_tunnel_out(&mut self, event: &StackEvent) -> Option<Event> {
        let StackEvent::TrustedLinkNpdu {
            link,
            npdu,
            assume_security,
        } = event
        else {
            return None;
        };
        if !self.direct.tunnels.iter().any(|(l, _)| l == link) {
            return None;
        }
        // §9: a data frame conveying an active or prospective network
        // key never reaches the ZVD; on a legacy network the ZDD answers
        // in the Trust Center's stead (§10), otherwise the connection is
        // closed.
        if let Ok((header, n)) = NwkHeader::decode_prefix(npdu)
            && header.frame_control.frame_type() == NwkFrameType::Data
            && forwarding_decision(npdu.get(n..).unwrap_or(&[])) == Forwarding::Decline
        {
            let aps = npdu.get(n..).unwrap_or(&[]);
            self.direct.legacy_probe_global =
                legacy::secured_with_well_known_key::<C>(aps, self.stack.aps.config.security_level);
            if self.legacy_on_declined(*link) {
                return None;
            }
            return Some(Event::DirectTunnelDeclined { link: *link });
        }
        if !self.legacy_allows_out(*link, npdu) {
            return None;
        }
        let mut buf = [0u8; tunnel::MAX_VALUE_LEN + 2];
        let n = NpduMessage {
            assume_security: *assume_security,
            npdu,
        }
        .encode(&mut buf)
        .ok()?;
        let tlv = heapless::Vec::from_slice(buf.get(..n)?).ok()?;
        Some(Event::DirectTunnel { link: *link, tlv })
    }

    /// Maps a stack event onto the completion of a pending Zigbee
    /// Direct operation.
    pub(crate) fn direct_outcome(&mut self, event: &StackEvent) -> Option<Event> {
        let pending = self.direct.pending?;
        let status = match (pending, event) {
            (Domain::FormNetwork, StackEvent::NetworkFormed { .. }) => STATUS_SUCCESS,
            (Domain::FormNetwork, StackEvent::FormationFailed(_)) => STATUS_FAILURE,
            (Domain::JoinNetwork, StackEvent::Joined { .. }) => STATUS_SUCCESS,
            (Domain::JoinNetwork, StackEvent::JoinFailed(_)) => STATUS_FAILURE,
            (Domain::LeaveNetwork, StackEvent::Left { .. }) => STATUS_SUCCESS,
            _ => return None,
        };
        self.direct.pending = None;
        Some(Event::Direct {
            domain: pending,
            status,
        })
    }

    /// Maps a commissioning outcome onto a pending Finding & Binding.
    pub(crate) fn direct_bdb_outcome(&mut self, outcome: Outcome) -> Option<Event> {
        if self.direct.pending != Some(Domain::FindingBinding) {
            return None;
        }
        let status = match outcome {
            Outcome::FindingBindingTarget { .. } => STATUS_SUCCESS,
            Outcome::FindingBindingInitiator { result, .. } => {
                if result.is_ok() {
                    STATUS_SUCCESS
                } else {
                    STATUS_FAILURE
                }
            }
            _ => return None,
        };
        self.direct.pending = None;
        Some(Event::Direct {
            domain: Domain::FindingBinding,
            status,
        })
    }

    fn identify_endpoint(&self) -> Option<Endpoint> {
        self.direct.identify_endpoint.or_else(|| {
            self.stack
                .zcl
                .endpoints()
                .iter()
                .find(|e| e.cluster(identify::ID, Role::Server).is_some())
                .map(|e| e.endpoint)
        })
    }

    fn install_direct_link_key(
        &mut self,
        partner: Option<ExtendedAddress>,
        lk: &panweave_direct::commissioning::LinkKey,
    ) {
        let partner = partner.unwrap_or(self.stack.config.preconfigured_link_key.0);
        let kind = if lk.unique {
            LinkKeyKind::Unique
        } else {
            LinkKeyKind::Global
        };
        self.stack
            .install_link_key(partner, lk.key.clone(), kind, lk.provisional);
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Zdd for Node<C, R, S> {
    fn status(&self) -> StatusReport {
        let stack = &self.stack;
        let joined = if stack.is_operating() {
            JoinedStatus::Commissioned
        } else if stack.is_idle() {
            JoinedStatus::NotCommissioned
        } else {
            JoinedStatus::InProgress
        };
        let network = (joined == JoinedStatus::Commissioned).then(|| NetworkInfo {
            channel: ChannelMask::EMPTY.with(stack.channel()),
            extended_pan_id: stack.extended_pan_id(),
            pan_id: stack.pan_id(),
            nwk_address: stack.short_address(),
            trust_center: stack.trust_center_address(),
            device_type: match stack.config.role {
                LogicalDeviceType::Coordinator => DeviceType::Coordinator,
                LogicalDeviceType::Router => DeviceType::Router,
                LogicalDeviceType::EndDevice => DeviceType::EndDevice,
            },
            update_id: stack.update_id(),
            key_sequence: stack.network_key_sequence().0,
        });
        StatusReport {
            status: NetworkStatus {
                joined,
                open: stack.permit_joining_active(),
                centralized: !stack.config.distributed,
            },
            ieee: stack.config.ieee,
            network,
        }
    }

    fn can_be_coordinator(&self) -> bool {
        self.stack.config.role == LogicalDeviceType::Coordinator
    }

    fn form_network(&mut self, p: &FormNetwork) -> u8 {
        // The ZVD chooses the security model (§7.7.2.5, Table 36); a
        // centralized network needs a coordinator-capable ZDD.
        if self.stack.set_security_model(p.distributed).is_err() {
            return STATUS_FAILURE;
        }
        if let Some(lk) = &p.link_key {
            self.install_direct_link_key(None, lk);
        }
        self.store_admin_key(p.admin_key.as_ref());
        let params = FormationParams {
            key: p.network_key.clone(),
            extended_pan_id: p.extended_pan_id,
            pan_id: p.pan_id,
            channels: p.channels,
            network_address: p.nwk_address,
            update_id: p.update_id.unwrap_or(0),
        };
        match self.stack.form_network_params(&params) {
            Ok(()) => {
                self.direct.pending = Some(Domain::FormNetwork);
                self.collect();
                STATUS_SUCCESS
            }
            Err(_) => STATUS_FAILURE,
        }
    }

    fn join_network(&mut self, p: &JoinNetwork) -> u8 {
        if let Some(lk) = &p.link_key {
            self.install_direct_link_key(p.trust_center, lk);
        }
        self.store_admin_key(p.admin_key.as_ref());
        let channels = p.channels.unwrap_or(self.stack.config.channels);
        let duration = self.stack.config.scan_duration;
        let attempts = self.stack.config.zdo.scan_attempts;
        let result = match p.method {
            JoiningMethod::Association => {
                if let Some(e) = p.extended_pan_id {
                    self.stack.nwk.nib.extended_pan_id = e;
                }
                self.stack
                    .join_with(JoinMode::Association, channels, duration, attempts)
            }
            JoiningMethod::Rejoin => {
                let Some(e) = p.extended_pan_id else {
                    return STATUS_FAILURE;
                };
                self.stack.nwk.nib.extended_pan_id = e;
                let mode = match &p.network_key {
                    Some(k) => {
                        self.stack
                            .nwk
                            .set_network_key(KeySequenceNumber(0), k.clone(), true);
                        JoinMode::SecuredRejoin
                    }
                    None => JoinMode::TrustCenterRejoin,
                };
                self.stack.join_with(mode, channels, duration, attempts)
            }
            JoiningMethod::OutOfBand => {
                let (Some(e), Some(pan), Some(c), Some(k)) =
                    (p.extended_pan_id, p.pan_id, p.channels, &p.network_key)
                else {
                    return STATUS_FAILURE;
                };
                // §7.7.2.7.4: exactly one channel.
                let (Some(channel), 1) = (c.first(), c.len()) else {
                    return STATUS_FAILURE;
                };
                let params = AdoptParams {
                    extended_pan_id: e,
                    pan_id: pan,
                    channel,
                    network_address: p.nwk_address,
                    key: k.clone(),
                    key_sequence: KeySequenceNumber(p.key_sequence.unwrap_or(0)),
                    update_id: p.update_id.unwrap_or(0),
                    trust_center: p.trust_center.unwrap_or(ExtendedAddress::BROADCAST),
                };
                let r = self.stack.adopt_network(&params);
                // §7.7.2.7.4: a provisional Trust Center link key is
                // updated once on the network, retried while the Trust
                // Center is out of reach, never a reason to leave.
                if r.is_ok()
                    && !self.stack.config.distributed
                    && self.stack.trust_center_link_key_is_provisional()
                {
                    self.direct_start_tclk_update();
                }
                if r.is_ok() && self.stack.is_operating() {
                    // Routers are on the network at once; end devices
                    // report once their rejoin completes.
                    self.bdb.set_on_network(true);
                    self.direct.pending = Some(Domain::JoinNetwork);
                    self.collect();
                    if self.direct.pending.take().is_some() {
                        self.push(Event::Direct {
                            domain: Domain::JoinNetwork,
                            status: STATUS_SUCCESS,
                        });
                    }
                    return STATUS_SUCCESS;
                }
                r
            }
        };
        match result {
            Ok(()) => {
                self.direct.pending = Some(Domain::JoinNetwork);
                self.collect();
                STATUS_SUCCESS
            }
            Err(_) => STATUS_FAILURE,
        }
    }

    fn permit_joining(&mut self, seconds: u8) -> u8 {
        if self.stack.config.role == LogicalDeviceType::EndDevice {
            return STATUS_FAILURE;
        }
        let r = self.stack.permit_join_network(seconds);
        self.collect();
        if r.is_ok() {
            STATUS_SUCCESS
        } else {
            STATUS_FAILURE
        }
    }

    fn leave_network(&mut self, p: LeaveNetwork) -> u8 {
        match self.stack.leave_with(p.rejoin, p.remove_children) {
            Ok(()) => {
                self.direct.pending = Some(Domain::LeaveNetwork);
                self.collect();
                STATUS_SUCCESS
            }
            Err(_) => STATUS_FAILURE,
        }
    }

    fn manage_joiners(&mut self, cmd: &ManageJoiners) -> u8 {
        if !self.can_be_coordinator() {
            return STATUS_FAILURE;
        }
        match cmd {
            ManageJoiners::DropAll => {
                let mut partners: heapless::Vec<ExtendedAddress, 32> = heapless::Vec::new();
                for e in self.stack.aps.security.keys_mut().iter() {
                    if e.attributes == KeyAttributes::ProvisionalKey
                        && e.partner != self.stack.config.preconfigured_link_key.0
                        && partners.push(e.partner).is_err()
                    {
                        break;
                    }
                }
                for p in partners {
                    self.stack.remove_link_key(p);
                }
                STATUS_SUCCESS
            }
            ManageJoiners::Add { ieee, key } => {
                self.stack
                    .install_link_key(*ieee, key.clone(), LinkKeyKind::Unique, true);
                STATUS_SUCCESS
            }
            ManageJoiners::Remove { ieee } => {
                if self.stack.remove_link_key(*ieee) {
                    STATUS_SUCCESS
                } else {
                    STATUS_FAILURE
                }
            }
        }
    }

    fn identify(&mut self, seconds: u16) -> u8 {
        let Some(ep) = self.identify_endpoint() else {
            return STATUS_FAILURE;
        };
        match self.stack.zcl.set_identify_time(ep, seconds) {
            Ok(()) => {
                self.collect();
                STATUS_SUCCESS
            }
            Err(_) => STATUS_FAILURE,
        }
    }

    fn identify_time(&self) -> u16 {
        self.identify_endpoint()
            .and_then(|ep| self.stack.zcl.cluster(ep, identify::ID, Role::Server))
            .map_or(0, identify::identify_time)
    }

    fn finding_binding(&mut self, p: FindingBinding) -> u8 {
        let r = if p.initiator {
            self.bdb
                .find_and_bind_initiator(&mut self.stack, p.endpoint, None, &[])
        } else {
            self.bdb.find_and_bind_target(&mut self.stack, p.endpoint)
        };
        match r {
            Ok(()) => {
                self.direct.pending = Some(Domain::FindingBinding);
                self.collect();
                STATUS_SUCCESS
            }
            Err(_) => STATUS_FAILURE,
        }
    }
}
