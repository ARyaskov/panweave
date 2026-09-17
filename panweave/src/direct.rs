//! Zigbee Direct device (ZDD) binding: [`Node`] implements the
//! Commissioning Service's [`Zdd`] trait so a host's BLE transport can
//! hand decrypted characteristic writes to
//! `panweave_direct::commissioning::Commissioning` and drive the stack
//! with them (ZD 1.1 §7.7.2). Operation results surface as
//! [`Event::Direct`], which the host forwards to
//! `Commissioning::report` to notify the ZVD.

use panweave_bdb::Outcome;
use panweave_direct::commissioning::{
    DeviceType, Domain, FindingBinding, FormNetwork, JoinNetwork, JoinedStatus, JoiningMethod,
    LeaveNetwork, ManageJoiners, NetworkInfo, NetworkStatus, STATUS_FAILURE, STATUS_SUCCESS,
    StatusReport, Zdd,
};
use panweave_runtime::{AdoptParams, FormationParams, JoinMode, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::LinkKeyKind;
use panweave_storage::Storage;
use panweave_types::{
    ChannelMask, CryptoRng, Endpoint, ExtendedAddress, Key128, KeyAttributes, KeySequenceNumber,
    LogicalDeviceType,
};
use panweave_zcl::cluster::Role;
use panweave_zcl::clusters::identify;

use crate::{Event, Node};

/// Zigbee Direct state a [`Node`] keeps between characteristic writes.
#[derive(Clone, Debug, Default)]
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
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Node<C, R, S> {
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
        self.stack.config.role == LogicalDeviceType::Coordinator && !self.stack.config.distributed
    }

    fn form_network(&mut self, p: &FormNetwork) -> u8 {
        // The security model (centralized or distributed) is fixed by the
        // node's role; a mismatch is a Form Network error.
        if p.distributed != self.stack.config.distributed {
            return STATUS_FAILURE;
        }
        if let Some(lk) = &p.link_key {
            self.install_direct_link_key(None, lk);
        }
        self.direct.admin_key.clone_from(&p.admin_key);
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
        self.direct.admin_key.clone_from(&p.admin_key);
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
