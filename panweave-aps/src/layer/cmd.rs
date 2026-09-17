//! APSME security services: Transport Key, Update Device, Remove Device,
//! Request Key, Switch Key, Tunnel, Verify Key, Confirm Key and Relay
//! Message (R23.2 §4.4.2–§4.4.8, §4.4.11, §4.6.3.7) with the acceptance
//! policy of §4.4.1.3 (Tables 4-6 and 4-7).

use heapless::Vec;
use panweave_codec::{Decode, Encode};
use panweave_security::aux_header::KeyIdentifier;
use panweave_security::cipher::BlockCipher;
use panweave_security::key_hierarchy;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_types::{
    ApsStatus, ExtendedAddress, Key128, KeyAttributes, KeySequenceNumber, KeyType, ShortAddress,
};
use subtle::ConstantTimeEq;

use super::rx::{DataIndication, FrameSecurity, RelayInfo, RxContext};
use super::tx::{PostAction, TxKind, TxParams, Wrap};
use super::{
    Aps, ApsAction, ApsError, ApsEvent, AsduBuf, DeviceState, NwkView, PersistItem, RequestId,
    TransportedKey,
};
use crate::command::{
    ApsCommand, ApsCommandId, ConfirmKey, KeyDescriptor, RelayMessage, RemoveDevice, RequestKey,
    RequestKeyType, SwitchKey, TransportKey, UpdateDevice, UpdateDeviceStatus, VerifyKey,
};
use crate::frame::Header;

/// How a Transport Key with the network key reaches the joiner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyRoute {
    /// Direct unicast to the device.
    Direct {
        /// Network address of the device.
        short: ShortAddress,
        /// Apply NWK security: false for a joined-but-unauthorized
        /// neighbour (§4.6.3.2.1), true for a key update to an
        /// authorized device.
        nwk_secure: bool,
    },
    /// Embedded in a Tunnel command to the device's parent (§4.6.3.7.1).
    Tunnel {
        /// The parent router.
        parent: ShortAddress,
    },
    /// NWK broadcast to all rx-on devices (network key updates,
    /// §4.6.3.4.1); APS security is not applied.
    Broadcast,
}

impl<
    C: BlockCipher,
    const KEYS: usize,
    const BINDINGS: usize,
    const GROUPS: usize,
    const DUPS: usize,
> Aps<C, KEYS, BINDINGS, GROUPS, DUPS>
{
    fn encode_command(cmd: &ApsCommand<'_>) -> Result<AsduBuf, ApsError> {
        let mut payload = AsduBuf::new();
        payload
            .resize(super::MAX_ASDU, 0)
            .map_err(|_| ApsError::AsduTooLong)?;
        let n = cmd
            .encode_to_slice(payload.as_mut_slice())
            .map_err(|_| ApsError::AsduTooLong)?;
        payload.truncate(n);
        Ok(payload)
    }

    /// Queues an APS command. `partner` selects APS security (with the
    /// key identifier appropriate to the command); `ack` requests an APS
    /// acknowledgement (unicast only, §4.4.11).
    #[allow(clippy::too_many_arguments)]
    fn send_command(
        &mut self,
        id: RequestId,
        dst: ShortAddress,
        cmd: &ApsCommand<'_>,
        partner: Option<ExtendedAddress>,
        key_type: KeyType,
        ack: bool,
        nwk_secure: bool,
        post: Option<PostAction>,
    ) -> Result<(), ApsError> {
        self.send_command_wrapped(id, dst, cmd, partner, key_type, ack, nwk_secure, post, None)
    }

    /// [`Self::send_command`] with an optional wrapper built at
    /// transmission time; with a wrapper `cmd` is the inner command.
    #[allow(clippy::too_many_arguments)]
    fn send_command_wrapped(
        &mut self,
        id: RequestId,
        dst: ShortAddress,
        cmd: &ApsCommand<'_>,
        partner: Option<ExtendedAddress>,
        key_type: KeyType,
        ack: bool,
        nwk_secure: bool,
        post: Option<PostAction>,
        wrap: Option<Wrap>,
    ) -> Result<(), ApsError> {
        let payload = Self::encode_command(cmd)?;
        let broadcast = dst.is_broadcast();
        let ack = ack && !broadcast;
        let counter = self.next_counter();
        let header = Header::command(counter, broadcast)
            .with_ack_request(ack)
            .secured(partner.is_some());
        let kind = match wrap {
            Some(Wrap::Tunnel { .. }) => ApsCommandId::Tunnel,
            Some(Wrap::Relay { downstream, .. }) => {
                if downstream {
                    ApsCommandId::RelayMessageDownstream
                } else {
                    ApsCommandId::RelayMessageUpstream
                }
            }
            None => cmd.id(),
        };
        self.queue_tx(
            TxParams {
                request: id,
                kind: TxKind::Command(kind),
                dst,
                partner,
                key_id: Self::key_id_for_command(cmd.id(), key_type),
                extended_nonce: true,
                header,
                nwk_secure,
                radius: None,
                alias: None,
                ack,
                post,
                wrap,
            },
            &payload,
            false,
        )
    }

    /// Requests persistence of the key-pair set after a direct change.
    pub fn request_link_key_persistence(&mut self) {
        self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
    }

    /// Replaces the key of `partner`'s entry with a negotiated or
    /// transported key (counters reset), persisting the key-pair set and
    /// the new outgoing counter reservation (§4.4.9, §4.7.3.3 step 5).
    pub fn set_negotiated_key(
        &mut self,
        partner: ExtendedAddress,
        key: &Key128,
        kind: LinkKeyKind,
        attributes: KeyAttributes,
    ) -> bool {
        if !self
            .security
            .replace_key(partner, key.clone(), attributes, kind)
        {
            return false;
        }
        self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
        self.request_counter_reservations();
        true
    }

    /// Installs a link-key entry and requests persistence of its first
    /// outgoing counter reservation.
    pub fn install_link_key(&mut self, entry: LinkKeyEntry) -> Result<(), LinkKeyEntry> {
        self.security.install(entry)?;
        self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
        self.request_counter_reservations();
        Ok(())
    }

    fn finish_command(&mut self, id: RequestId, cmd: ApsCommandId) -> Result<RequestId, ApsError> {
        self.track_request(id, 1, Some(cmd))?;
        self.service_pending();
        Ok(id)
    }

    /// APSME-TRANSPORT-KEY.request with the standard network key
    /// (§4.4.2.1.3, §4.6.3.2.2.3, §4.6.3.4.1). `device` is the recipient
    /// (`ExtendedAddress::ZERO` for broadcasts); with
    /// [`KeyRoute::Direct`] or [`KeyRoute::Tunnel`] the command is APS
    /// secured with the key-transport key derived from `device`'s link
    /// key, with [`KeyRoute::Broadcast`] it relies on NWK security.
    pub fn transport_network_key(
        &mut self,
        device: ExtendedAddress,
        key: &Key128,
        sequence: KeySequenceNumber,
        route: KeyRoute,
    ) -> Result<RequestId, ApsError> {
        if self.state == DeviceState::NotJoined {
            return Err(ApsError::NotJoined);
        }
        let source = if self.aib.is_distributed() {
            ExtendedAddress::BROADCAST
        } else {
            self.local_ieee
        };
        let id = self.alloc_request();
        let cmd = ApsCommand::TransportKey(TransportKey {
            descriptor: KeyDescriptor::NetworkKey {
                key: key.clone(),
                sequence,
                destination: if route == KeyRoute::Broadcast {
                    ExtendedAddress::ZERO
                } else {
                    device
                },
                source,
            },
        });
        match route {
            KeyRoute::Broadcast => {
                self.send_command(
                    id,
                    ShortAddress::BROADCAST_RX_ON,
                    &cmd,
                    None,
                    KeyType::StandardNetworkKey,
                    false,
                    true,
                    None,
                )?;
            }
            KeyRoute::Direct { short, nwk_secure } => {
                let partner = self.link_key_for(device).ok_or(ApsError::NoKey)?;
                self.send_command(
                    id,
                    short,
                    &cmd,
                    Some(partner),
                    KeyType::StandardNetworkKey,
                    nwk_secure,
                    nwk_secure,
                    None,
                )?;
            }
            KeyRoute::Tunnel { parent } => {
                let partner = self.link_key_for(device).ok_or(ApsError::NoKey)?;
                // The inner Transport Key is secured with the joiner's
                // key-transport key at transmission time and wrapped in a
                // Tunnel command to the parent (§4.6.3.7.1).
                let inner_counter = self.next_counter();
                let inner_header = Header::command(inner_counter, false)
                    .with_ack_request(false)
                    .secured(true);
                self.send_command_wrapped(
                    id,
                    parent,
                    &cmd,
                    None,
                    KeyType::StandardNetworkKey,
                    true,
                    true,
                    None,
                    Some(Wrap::Tunnel {
                        joiner: device,
                        inner_header,
                        inner_partner: partner,
                    }),
                )?;
                return self.finish_command(id, ApsCommandId::Tunnel);
            }
        }
        self.finish_command(id, ApsCommandId::TransportKey)
    }

    /// APSME-TRANSPORT-KEY.request with a Trust Center link key
    /// (§4.4.2.1.3): the new key is sent APS-secured with the key-load
    /// key derived from the current link key and, once confirmed,
    /// replaces it as UNVERIFIED until the device verifies it.
    pub fn transport_trust_center_link_key(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        key: &Key128,
        features_tlv: &[u8],
    ) -> Result<RequestId, ApsError> {
        if !self.config.is_trust_center {
            return Err(ApsError::IllegalRequest);
        }
        let partner = self.link_key_for(device).ok_or(ApsError::NoKey)?;
        let id = self.alloc_request();
        let cmd = ApsCommand::TransportKey(TransportKey {
            descriptor: KeyDescriptor::TrustCenterLinkKey {
                key: key.clone(),
                destination: device,
                source: self.local_ieee,
                tlvs: features_tlv,
            },
        });
        self.send_command(
            id,
            short,
            &cmd,
            Some(partner),
            KeyType::TrustCenterLinkKey,
            true,
            true,
            Some(PostAction::ReplaceKey {
                partner,
                key: key.clone(),
            }),
        )?;
        self.finish_command(id, ApsCommandId::TransportKey)
    }

    /// APSME-TRANSPORT-KEY.request with an application link key
    /// (§4.4.2.1.3), APS-secured with the key-load key of `device`.
    pub fn transport_application_link_key(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        partner_of_key: ExtendedAddress,
        key: &Key128,
        initiator: bool,
    ) -> Result<RequestId, ApsError> {
        let partner = self.link_key_for(device).ok_or(ApsError::NoKey)?;
        let id = self.alloc_request();
        let cmd = ApsCommand::TransportKey(TransportKey {
            descriptor: KeyDescriptor::ApplicationLinkKey {
                key: key.clone(),
                partner: partner_of_key,
                initiator,
                tlvs: &[],
            },
        });
        self.send_command(
            id,
            short,
            &cmd,
            Some(partner),
            KeyType::ApplicationLinkKey,
            true,
            true,
            None,
        )?;
        self.finish_command(id, ApsCommandId::TransportKey)
    }

    /// APSME-UPDATE-DEVICE.request (§4.4.3.1, §4.6.3.2.1): informs the
    /// Trust Center at `tc_short` about `device`. With a unique Trust
    /// Center link key one APS-encrypted copy is sent; with a global key
    /// an encrypted and an unencrypted copy are sent.
    pub fn update_device(
        &mut self,
        tc_short: ShortAddress,
        device: ExtendedAddress,
        short: ShortAddress,
        status: UpdateDeviceStatus,
        joiner_tlvs: &[u8],
    ) -> Result<RequestId, ApsError> {
        if self.state != DeviceState::JoinedAuthorized || self.aib.is_distributed() {
            return Err(ApsError::IllegalRequest);
        }
        if joiner_tlvs.len() > super::MAX_JOINER_TLVS {
            return Err(ApsError::InvalidParameter);
        }
        let tc = self.aib.trust_center_address;
        let (partner, kind) = match self.security.entry(tc) {
            Some(e) => (tc, e.kind),
            None => return Err(ApsError::NoKey),
        };
        let id = self.alloc_request();
        let cmd = ApsCommand::UpdateDevice(UpdateDevice {
            device,
            short,
            status,
            joiner_tlvs,
        });
        self.send_command(
            id,
            tc_short,
            &cmd,
            Some(partner),
            KeyType::TrustCenterLinkKey,
            true,
            true,
            None,
        )?;
        let mut copies = 1;
        if kind == LinkKeyKind::Global {
            self.send_command(
                id,
                tc_short,
                &cmd,
                None,
                KeyType::TrustCenterLinkKey,
                true,
                true,
                None,
            )?;
            copies = 2;
        }
        self.track_request(id, copies, Some(ApsCommandId::UpdateDevice))?;
        self.service_pending();
        Ok(id)
    }

    /// APSME-REMOVE-DEVICE.request (§4.4.4.1): asks `parent` to remove
    /// `target`; always APS-encrypted (Table 4-7).
    pub fn remove_device(
        &mut self,
        parent: ExtendedAddress,
        parent_short: ShortAddress,
        target: ExtendedAddress,
    ) -> Result<RequestId, ApsError> {
        if !self.config.is_trust_center {
            return Err(ApsError::IllegalRequest);
        }
        let partner = self.link_key_for(parent).ok_or(ApsError::NoKey)?;
        let id = self.alloc_request();
        let cmd = ApsCommand::RemoveDevice(RemoveDevice { target });
        self.send_command(
            id,
            parent_short,
            &cmd,
            Some(partner),
            KeyType::TrustCenterLinkKey,
            true,
            true,
            None,
        )?;
        self.finish_command(id, ApsCommandId::RemoveDevice)
    }

    /// APSME-REQUEST-KEY.request (§4.4.5.1) to the Trust Center at
    /// `tc_short`; always APS-encrypted (Table 4-7).
    pub fn request_key(
        &mut self,
        tc_short: ShortAddress,
        key_type: RequestKeyType,
        partner_device: Option<ExtendedAddress>,
    ) -> Result<RequestId, ApsError> {
        if self.state != DeviceState::JoinedAuthorized || self.aib.is_distributed() {
            return Err(ApsError::IllegalRequest);
        }
        if key_type == RequestKeyType::ApplicationLinkKey && partner_device.is_none() {
            return Err(ApsError::InvalidParameter);
        }
        let tc = self.aib.trust_center_address;
        let partner = self.link_key_for(tc).ok_or(ApsError::NoKey)?;
        let id = self.alloc_request();
        let cmd = ApsCommand::RequestKey(RequestKey {
            key_type,
            partner: partner_device,
        });
        self.send_command(
            id,
            tc_short,
            &cmd,
            Some(partner),
            KeyType::TrustCenterLinkKey,
            true,
            true,
            None,
        )?;
        self.finish_command(id, ApsCommandId::RequestKey)
    }

    /// A router's unicast of the Trust Center's broadcast network key
    /// update to an rx-off child (§4.4.2.3 last paragraph): the same
    /// command, NWK-secured, APS-unsecured, naming the Trust Center as
    /// its source and the child as its destination.
    pub fn relay_network_key_to_child(
        &mut self,
        child: ExtendedAddress,
        child_short: ShortAddress,
        key: &Key128,
        sequence: KeySequenceNumber,
        trust_center: ExtendedAddress,
    ) -> Result<RequestId, ApsError> {
        if self.state != DeviceState::JoinedAuthorized {
            return Err(ApsError::NotJoined);
        }
        let id = self.alloc_request();
        let cmd = ApsCommand::TransportKey(TransportKey {
            descriptor: KeyDescriptor::NetworkKey {
                key: key.clone(),
                sequence,
                destination: child,
                source: trust_center,
            },
        });
        self.send_command(
            id,
            child_short,
            &cmd,
            None,
            KeyType::StandardNetworkKey,
            true,
            true,
            None,
        )?;
        self.finish_command(id, ApsCommandId::TransportKey)
    }

    /// APSME-SWITCH-KEY.request (§4.4.6.1.3, §4.6.3.4.1): broadcast to
    /// all rx-on devices, NWK-secured only.
    pub fn switch_key(&mut self, sequence: KeySequenceNumber) -> Result<RequestId, ApsError> {
        if !self.config.is_trust_center {
            return Err(ApsError::IllegalRequest);
        }
        let id = self.alloc_request();
        let cmd = ApsCommand::SwitchKey(SwitchKey { sequence });
        self.send_command(
            id,
            ShortAddress::BROADCAST_RX_ON,
            &cmd,
            None,
            KeyType::StandardNetworkKey,
            false,
            true,
            None,
        )?;
        self.finish_command(id, ApsCommandId::SwitchKey)
    }

    /// APSME-VERIFY-KEY.request (§4.4.7.1.3): sends the keyed hash of the
    /// link key shared with `device` (the Trust Center for
    /// `KeyType::TrustCenterLinkKey`). Never APS-encrypted.
    pub fn verify_key(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        key_type: KeyType,
    ) -> Result<RequestId, ApsError> {
        if self.config.is_trust_center {
            return Err(ApsError::IllegalRequest);
        }
        let distributed = self.aib.is_distributed();
        if key_type != KeyType::TrustCenterLinkKey && distributed {
            return Err(ApsError::IllegalRequest);
        }
        if key_type == KeyType::ApplicationLinkKey && device == self.aib.trust_center_address {
            return Err(ApsError::IllegalRequest);
        }
        if !matches!(
            key_type,
            KeyType::TrustCenterLinkKey | KeyType::ApplicationLinkKey
        ) {
            return Err(ApsError::InvalidParameter);
        }
        let hash = {
            let e = self.security.entry(device).ok_or(ApsError::NoKey)?;
            key_hierarchy::verify_key_hash::<C>(&e.key)
        };
        let id = self.alloc_request();
        let cmd = ApsCommand::VerifyKey(VerifyKey {
            key_type,
            source: self.local_ieee,
            hash,
        });
        self.send_command(id, short, &cmd, None, key_type, true, true, None)?;
        self.finish_command(id, ApsCommandId::VerifyKey)
    }

    /// APSME-VERIFY-KEY.request from a joined-but-unauthorized device,
    /// relayed upstream through `parent` (§4.6.3.5, §4.6.3.2.3.1).
    pub fn verify_key_via(
        &mut self,
        device: ExtendedAddress,
        parent: ShortAddress,
        key_type: KeyType,
    ) -> Result<RequestId, ApsError> {
        if self.config.is_trust_center || key_type != KeyType::TrustCenterLinkKey {
            return Err(ApsError::IllegalRequest);
        }
        let hash = {
            let e = self.security.entry(device).ok_or(ApsError::NoKey)?;
            key_hierarchy::verify_key_hash::<C>(&e.key)
        };
        let id = self.alloc_request();
        let cmd = ApsCommand::VerifyKey(VerifyKey {
            key_type,
            source: self.local_ieee,
            hash,
        });
        let inner_counter = self.next_counter();
        let inner_header = Header::command(inner_counter, false).with_ack_request(false);
        self.send_command_wrapped(
            id,
            parent,
            &cmd,
            None,
            key_type,
            true,
            false,
            None,
            Some(Wrap::Relay {
                joiner: self.local_ieee,
                downstream: false,
                inner_header,
                inner_partner: None,
            }),
        )?;
        self.finish_command(id, ApsCommandId::RelayMessageUpstream)
    }

    /// APSME-CONFIRM-KEY.request from the Trust Center to a
    /// joined-but-unauthorized device, relayed downstream through
    /// `parent` (§4.6.3.5).
    pub fn confirm_key_via(
        &mut self,
        device: ExtendedAddress,
        parent: ShortAddress,
        key_type: KeyType,
        status: ApsStatus,
    ) -> Result<RequestId, ApsError> {
        if !self.config.is_trust_center || self.aib.is_distributed() {
            return Err(ApsError::IllegalRequest);
        }
        let (partner, status) = match self.link_key_for(device) {
            Some(p) => (Some(p).filter(|_| status.is_success()), status),
            None => (None, ApsStatus::SecurityFail),
        };
        let id = self.alloc_request();
        let cmd = ApsCommand::ConfirmKey(ConfirmKey {
            status,
            key_type,
            destination: device,
        });
        let inner_counter = self.next_counter();
        let inner_header = Header::command(inner_counter, false)
            .with_ack_request(false)
            .secured(partner.is_some());
        self.send_command_wrapped(
            id,
            parent,
            &cmd,
            None,
            key_type,
            true,
            true,
            None,
            Some(Wrap::Relay {
                joiner: device,
                downstream: true,
                inner_header,
                inner_partner: partner,
            }),
        )?;
        if partner.is_some() {
            self.security.reset_incoming(device);
        }
        self.finish_command(id, ApsCommandId::RelayMessageDownstream)
    }

    /// APSME-CONFIRM-KEY.request (§4.4.8.1.3): APS-encrypted only on
    /// SUCCESS.
    pub fn confirm_key(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        key_type: KeyType,
        status: ApsStatus,
    ) -> Result<RequestId, ApsError> {
        self.confirm_key_with(device, short, key_type, status, true)
    }

    /// [`Self::confirm_key`] with explicit NWK security: a Trust Center
    /// that is the parent of a joined-but-unauthorized device confirms
    /// its negotiated key NWK-unsecured (§4.6.3.5).
    fn confirm_key_with(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        key_type: KeyType,
        status: ApsStatus,
        nwk_secure: bool,
    ) -> Result<RequestId, ApsError> {
        if key_type == KeyType::TrustCenterLinkKey
            && (!self.config.is_trust_center || self.aib.is_distributed())
        {
            return Err(ApsError::IllegalRequest);
        }
        if !matches!(
            key_type,
            KeyType::TrustCenterLinkKey | KeyType::ApplicationLinkKey
        ) {
            return Err(ApsError::InvalidParameter);
        }
        let (partner, status) = match self.link_key_for(device) {
            Some(p) => (Some(p).filter(|_| status.is_success()), status),
            None => (None, ApsStatus::SecurityFail),
        };
        let id = self.alloc_request();
        let cmd = ApsCommand::ConfirmKey(ConfirmKey {
            status,
            key_type,
            destination: device,
        });
        self.send_command(
            id, short, &cmd, partner, key_type, nwk_secure, nwk_secure, None,
        )?;
        if partner.is_some() {
            self.security.reset_incoming(device);
        }
        self.finish_command(id, ApsCommandId::ConfirmKey)
    }

    /// Sends a Relay Message command carrying `frame` to `parent`
    /// (downstream from the Trust Center when `downstream`, upstream from
    /// a joiner otherwise).
    pub(crate) fn send_relay_command(
        &mut self,
        parent: ShortAddress,
        joiner: ExtendedAddress,
        frame: &[u8],
        downstream: bool,
        nwk_secure: bool,
    ) {
        let relay = RelayMessage {
            joiner,
            message: frame,
        };
        let cmd = if downstream {
            ApsCommand::RelayDownstream(relay)
        } else {
            ApsCommand::RelayUpstream(relay)
        };
        let id = self.alloc_request();
        if self
            .send_command(
                id,
                parent,
                &cmd,
                None,
                KeyType::StandardNetworkKey,
                true,
                nwk_secure,
                None,
            )
            .is_ok()
        {
            let _ = self.track_request(id, 1, Some(cmd.id()));
            self.service_pending();
        }
    }

    /// Sends a raw APS frame (extracted from a Tunnel or Relay Downstream
    /// command) to an unauthenticated child without NWK security
    /// (§4.6.3.7.2).
    fn forward_to_child(&mut self, child: ShortAddress, frame: &[u8]) {
        let Ok(frame) = super::FrameBuf::from_slice(frame) else {
            return;
        };
        let handle = self.alloc_handle();
        self.push_action(ApsAction::NwkData {
            handle,
            dst: child,
            radius: Some(1),
            discover_route: false,
            secure: false,
            alias: None,
            frame,
        });
    }

    /// Whether an APS command may be processed (§4.4.1.3, Table 4-6).
    fn command_allowed(
        &self,
        id: ApsCommandId,
        ctx: &RxContext,
        sec: &FrameSecurity,
        view: &impl NwkView,
    ) -> bool {
        let aps_secured = sec.partner.is_some();
        let from_unauthenticated_child = !ctx.nwk_secured
            && !aps_secured
            && ctx
                .src_ieee
                .is_some_and(|i| view.unauthenticated_child(i) == Some(ctx.src));
        if self.config.is_trust_center {
            return match id {
                ApsCommandId::UpdateDevice => {
                    // Unique key: encryption required; global: optional.
                    let unique = ctx
                        .src_ieee
                        .and_then(|i| self.security.entry(i))
                        .is_some_and(|e| e.kind == LinkKeyKind::Unique);
                    ctx.nwk_secured && (aps_secured || !unique)
                }
                ApsCommandId::RequestKey => aps_secured && ctx.nwk_secured,
                // A joiner negotiating a link key verifies it through its
                // parent's relay before holding the network key
                // (§4.6.3.2.2.2).
                ApsCommandId::VerifyKey => ctx.nwk_secured || ctx.relayed.is_some(),
                ApsCommandId::RelayMessageUpstream => ctx.nwk_secured || from_unauthenticated_child,
                _ => false,
            };
        }
        if self.aib.is_distributed() {
            return match id {
                ApsCommandId::TransportKey => true,
                ApsCommandId::RelayMessageUpstream => from_unauthenticated_child,
                ApsCommandId::Tunnel | ApsCommandId::RelayMessageDownstream => ctx.nwk_secured,
                _ => false,
            };
        }
        // Centralized network, not the Trust Center: Relay Upstream comes
        // from an unauthenticated child; everything else from the Trust
        // Center.
        if id == ApsCommandId::RelayMessageUpstream {
            return from_unauthenticated_child;
        }
        if self.state == DeviceState::JoinedUnauthorized {
            // Joining: the parent forwards the Trust Center's frames
            // unsecured; the handlers validate the contents. A Confirm
            // Key reaches the joiner inside a Relay Message Downstream
            // during key negotiation (§4.6.3.2.3.1).
            return matches!(
                id,
                ApsCommandId::TransportKey | ApsCommandId::RelayMessageDownstream
            ) || (id == ApsCommandId::ConfirmKey && aps_secured);
        }
        let tc = self.aib.trust_center_address;
        let from_tc = if let Some(p) = sec.partner {
            p == tc
        } else {
            match ctx.src_ieee {
                Some(i) => i == tc,
                None => ctx.src == ShortAddress::COORDINATOR,
            }
        };
        if !from_tc {
            return false;
        }
        let unique = self
            .security
            .entry(tc)
            .is_some_and(|e| e.kind == LinkKeyKind::Unique);
        match id {
            ApsCommandId::TransportKey => true,
            ApsCommandId::UpdateDevice => aps_secured || !unique,
            ApsCommandId::RemoveDevice | ApsCommandId::RequestKey | ApsCommandId::ConfirmKey => {
                aps_secured && ctx.nwk_secured
            }
            ApsCommandId::SwitchKey
            | ApsCommandId::Tunnel
            | ApsCommandId::VerifyKey
            | ApsCommandId::RelayMessageDownstream => ctx.nwk_secured,
            ApsCommandId::RelayMessageUpstream | ApsCommandId::Unknown(_) => false,
        }
    }

    /// Dispatches a received APS command.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_command<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        start: usize,
        end: usize,
        header: &Header,
        ctx: RxContext,
        sec: FrameSecurity,
        view: &impl NwkView,
        depth: u8,
    ) -> Option<DataIndication<'a>> {
        let id = buf.get(start).map(|b| ApsCommandId::from_raw(*b))?;
        if !self.command_allowed(id, &ctx, &sec, view) {
            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
            return None;
        }
        if header.control.ack_request && ctx.dst.is_unicast() && ctx.relayed.is_none() {
            self.send_ack(header, None, ctx, sec);
        }
        let cmd = match ApsCommand::decode_exact(buf.get(start..end)?) {
            Ok(c) => c,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return None;
            }
        };
        match cmd {
            ApsCommand::TransportKey(tk) => self.on_transport_key(&tk, &ctx, &sec),
            ApsCommand::UpdateDevice(ud) => self.on_update_device(&ud, &ctx, &sec),
            ApsCommand::RemoveDevice(rd) => {
                if let Some(src) = sec.partner {
                    self.push_event(ApsEvent::RemoveDevice {
                        src,
                        target: rd.target,
                    });
                }
            }
            ApsCommand::RequestKey(rk) => self.on_request_key(&rk, &ctx, &sec),
            ApsCommand::SwitchKey(sk) => self.on_switch_key(sk, &ctx),
            ApsCommand::Tunnel(t) => {
                if let Some(child) = view.unauthenticated_child(t.destination) {
                    self.forward_to_child(child, t.tunneled);
                }
            }
            ApsCommand::VerifyKey(vk) => self.on_verify_key(&vk, &ctx, view),
            ApsCommand::ConfirmKey(ck) => self.on_confirm_key(&ck, &ctx, &sec),
            ApsCommand::RelayDownstream(rm) => {
                if self.state == DeviceState::JoinedUnauthorized && rm.joiner == self.local_ieee {
                    // We are the joiner: process the relayed frame.
                    let (s, e) = relayed_range(buf, start, end, rm.message)?;
                    if depth > 0 {
                        return None;
                    }
                    let inner_ctx = RxContext {
                        src: ctx.src,
                        dst: self.local_short,
                        src_ieee: Some(self.aib.trust_center_address),
                        nwk_secured: false,
                        lqi: ctx.lqi,
                        relayed: Some(RelayInfo {
                            parent: ctx.src,
                            joiner: self.local_ieee,
                        }),
                    };
                    let inner = buf.get_mut(s..e)?;
                    return self.process_frame(inner, inner_ctx, view, depth + 1);
                }
                if let Some(child) = view.unauthenticated_child(rm.joiner) {
                    self.forward_to_child(child, rm.message);
                }
            }
            ApsCommand::RelayUpstream(rm) => {
                if self.config.is_trust_center {
                    if depth > 0 {
                        return None;
                    }
                    let (s, e) = relayed_range(buf, start, end, rm.message)?;
                    let inner_ctx = RxContext {
                        src: ctx.src,
                        dst: self.local_short,
                        src_ieee: Some(rm.joiner),
                        nwk_secured: false,
                        lqi: ctx.lqi,
                        relayed: Some(RelayInfo {
                            parent: ctx.src,
                            joiner: rm.joiner,
                        }),
                    };
                    let inner = buf.get_mut(s..e)?;
                    return self.process_frame(inner, inner_ctx, view, depth + 1);
                }
                // Parent router: only relay for our unauthenticated child
                // and only towards the Trust Center (§4.6.3.2.1).
                let child_ok = ctx.src_ieee.is_some_and(|i| {
                    i == rm.joiner && view.unauthenticated_child(i) == Some(ctx.src)
                });
                if child_ok {
                    let tc_short = view
                        .short_of(self.aib.trust_center_address)
                        .unwrap_or(ShortAddress::COORDINATOR);
                    self.send_relay_command(tc_short, rm.joiner, rm.message, false, true);
                }
            }
        }
        None
    }

    fn on_transport_key(&mut self, tk: &TransportKey<'_>, ctx: &RxContext, sec: &FrameSecurity) {
        let aps_secured = sec.partner.is_some();
        match &tk.descriptor {
            KeyDescriptor::NetworkKey {
                key,
                sequence,
                destination,
                source,
            } => {
                let distributed_src = *source == ExtendedAddress::BROADCAST;
                if *destination != ExtendedAddress::ZERO && *destination != self.local_ieee {
                    // Not for us and the UseParent-without-tunnel path is
                    // not supported: the frame cannot be decrypted here.
                    self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                    return;
                }
                match self.state {
                    DeviceState::JoinedUnauthorized => {
                        if !aps_secured && self.config.require_link_key_encryption_for_transport_key
                        {
                            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                            return;
                        }
                        if aps_secured && sec.key_id != KeyIdentifier::KeyTransport {
                            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                            return;
                        }
                        if distributed_src && !self.aib.is_distributed() {
                            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                            return;
                        }
                        // Learn the Trust Center (§4.6.3.1).
                        let placeholder = self.trust_center_partner();
                        if !distributed_src {
                            if placeholder != *source {
                                self.security.rename(placeholder, *source);
                            }
                            self.aib.trust_center_address = *source;
                        }
                        self.state = DeviceState::JoinedAuthorized;
                        self.push_action(ApsAction::Persist(PersistItem::Aib));
                        self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
                        self.push_event(ApsEvent::TransportKey {
                            src: *source,
                            key: TransportedKey::Network {
                                key: key.clone(),
                                sequence: *sequence,
                                source: *source,
                                broadcast: *destination == ExtendedAddress::ZERO,
                            },
                            authorizes: true,
                        });
                    }
                    DeviceState::JoinedAuthorized => {
                        // Key updates come only from the Trust Center,
                        // NWK-secured (§4.4.1.5, §4.6.3.4.2).
                        if self.aib.is_distributed() || !ctx.nwk_secured {
                            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                            return;
                        }
                        let from_tc = if aps_secured {
                            sec.partner == Some(self.aib.trust_center_address)
                        } else {
                            *source == self.aib.trust_center_address
                        };
                        if !from_tc {
                            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                            return;
                        }
                        self.push_event(ApsEvent::TransportKey {
                            src: *source,
                            key: TransportedKey::Network {
                                key: key.clone(),
                                sequence: *sequence,
                                source: *source,
                                broadcast: *destination == ExtendedAddress::ZERO,
                            },
                            authorizes: false,
                        });
                    }
                    DeviceState::NotJoined => {}
                }
            }
            KeyDescriptor::TrustCenterLinkKey {
                key,
                destination,
                source,
                tlvs,
            } => {
                if !aps_secured
                    || sec.key_id != KeyIdentifier::KeyLoad
                    || *destination != self.local_ieee
                    || self.state != DeviceState::JoinedAuthorized
                    || sec.partner != Some(self.aib.trust_center_address)
                    || *source != self.aib.trust_center_address
                {
                    self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                    return;
                }
                let sync = panweave_codec::tlv::TlvSet::validate(tlvs, |_| false)
                    .ok()
                    .and_then(|s| s.value(crate::command::TLV_LINK_KEY_FEATURES))
                    .and_then(|v| v.first().copied())
                    .is_some_and(|f| f & crate::command::LINK_KEY_FEATURE_FRAME_COUNTER_SYNC != 0);
                self.security.replace_key(
                    *source,
                    key.clone(),
                    KeyAttributes::UnverifiedKey,
                    LinkKeyKind::Unique,
                );
                if let Some(e) = self.security.keys_mut().get_mut(*source) {
                    e.frame_counter_sync = sync;
                }
                self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
                self.push_event(ApsEvent::TransportKey {
                    src: *source,
                    key: TransportedKey::TrustCenterLink { source: *source },
                    authorizes: false,
                });
            }
            KeyDescriptor::ApplicationLinkKey {
                key,
                partner,
                initiator,
                ..
            } => {
                if !aps_secured
                    || sec.key_id != KeyIdentifier::KeyLoad
                    || self.state != DeviceState::JoinedAuthorized
                    || sec.partner != Some(self.aib.trust_center_address)
                {
                    self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                    return;
                }
                let mut e = LinkKeyEntry::provisional(*partner, key.clone(), LinkKeyKind::Unique);
                e.attributes = KeyAttributes::VerifiedKey;
                if self.security.install(e).is_err() {
                    self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
                    return;
                }
                self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
                self.push_event(ApsEvent::TransportKey {
                    src: ctx.src_ieee.unwrap_or(self.aib.trust_center_address),
                    key: TransportedKey::ApplicationLink {
                        partner: *partner,
                        initiator: *initiator,
                    },
                    authorizes: false,
                });
            }
        }
    }

    fn on_update_device(&mut self, ud: &UpdateDevice<'_>, ctx: &RxContext, sec: &FrameSecurity) {
        if !self.config.is_trust_center {
            return;
        }
        let Ok(joiner_tlvs) = Vec::from_slice(ud.joiner_tlvs) else {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            return;
        };
        self.push_event(ApsEvent::UpdateDevice {
            src: ctx.src,
            src_ieee: ctx.src_ieee,
            device: ud.device,
            short: ud.short,
            status: ud.status,
            joiner_tlvs,
            aps_secured: sec.partner.is_some(),
        });
    }

    fn on_request_key(&mut self, rk: &RequestKey, ctx: &RxContext, sec: &FrameSecurity) {
        // §4.4.5.2.3: Trust Center only, centralized only, APS-secured.
        if !self.config.is_trust_center || self.aib.is_distributed() {
            return;
        }
        let Some(src) = sec.partner else { return };
        match rk.key_type {
            RequestKeyType::TrustCenterLinkKey | RequestKeyType::ApplicationLinkKey => {}
            RequestKeyType::Unknown(_) => return,
        }
        if let Some(e) = self.security.entry(src)
            && e.negotiation_method != 0
        {
            // Key negotiation was selected for this device; the APS
            // Request Key method is not allowed (step 3b).
            return;
        }
        self.push_event(ApsEvent::RequestKey {
            src,
            src_short: ctx.src,
            key_type: rk.key_type,
            partner: rk.partner,
        });
    }

    fn on_switch_key(&mut self, sk: SwitchKey, ctx: &RxContext) {
        if self.state != DeviceState::JoinedAuthorized || !ctx.nwk_secured {
            return;
        }
        // Only the Trust Center may switch keys (§4.6.3.4.2).
        let tc = self.aib.trust_center_address;
        let from_tc = match ctx.src_ieee {
            Some(i) => i == tc,
            None => ctx.src == ShortAddress::COORDINATOR,
        };
        if !from_tc {
            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
            return;
        }
        self.push_event(ApsEvent::SwitchKey {
            src: tc,
            sequence: sk.sequence,
        });
    }

    /// APSME-VERIFY-KEY.indication processing (§4.4.7.2.3).
    fn on_verify_key(&mut self, vk: &VerifyKey, ctx: &RxContext, view: &impl NwkView) {
        if ctx.dst.is_broadcast() {
            return;
        }
        let src = vk.source;
        let short = view.short_of(src).unwrap_or(ctx.src);
        let is_tc = self.config.is_trust_center;
        let status = match vk.key_type {
            KeyType::TrustCenterLinkKey if !is_tc => ApsStatus::IllegalRequest,
            KeyType::ApplicationLinkKey if is_tc => ApsStatus::IllegalRequest,
            KeyType::TrustCenterLinkKey if self.aib.is_distributed() => ApsStatus::NotSupported,
            KeyType::TrustCenterLinkKey | KeyType::ApplicationLinkKey => {
                match self.security.entry(src) {
                    Some(e)
                        if matches!(
                            e.attributes,
                            KeyAttributes::UnverifiedKey | KeyAttributes::VerifiedKey
                        ) =>
                    {
                        let expected = key_hierarchy::verify_key_hash::<C>(&e.key);
                        if bool::from(expected.ct_eq(&vk.hash)) {
                            ApsStatus::Success
                        } else {
                            ApsStatus::SecurityFail
                        }
                    }
                    _ => ApsStatus::SecurityFail,
                }
            }
            _ => ApsStatus::NotSupported,
        };
        if status.is_success() {
            self.security
                .set_attributes(src, KeyAttributes::VerifiedKey);
            self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
            self.push_event(ApsEvent::KeyVerified {
                partner: src,
                key_type: vk.key_type,
                relayed: ctx.relayed,
            });
        }
        let _ = match ctx.relayed {
            // We are the joiner's parent: no relay, NWK-unsecured.
            Some(r) if view.unauthenticated_child(src) == Some(r.parent) => {
                self.confirm_key_with(src, r.parent, vk.key_type, status, false)
            }
            Some(r) => self.confirm_key_via(src, r.parent, vk.key_type, status),
            None => self.confirm_key(src, short, vk.key_type, status),
        };
    }

    /// APSME-CONFIRM-KEY.indication processing (§4.4.8.2.3).
    fn on_confirm_key(&mut self, ck: &ConfirmKey, ctx: &RxContext, sec: &FrameSecurity) {
        if ctx.dst.is_broadcast() || self.config.is_trust_center {
            return;
        }
        let tc = self.aib.trust_center_address;
        let src = sec.partner.or(ctx.src_ieee).unwrap_or(tc);
        if !ck.status.is_success() {
            self.push_event(ApsEvent::ConfirmKey {
                src,
                key_type: ck.key_type,
                status: ck.status,
            });
            return;
        }
        match ck.key_type {
            KeyType::TrustCenterLinkKey | KeyType::ApplicationLinkKey
                if self.aib.is_distributed() =>
            {
                return;
            }
            KeyType::TrustCenterLinkKey if src != tc => return,
            KeyType::ApplicationLinkKey if src == tc => return,
            KeyType::TrustCenterLinkKey | KeyType::ApplicationLinkKey => {}
            _ => return,
        }
        if sec.partner != Some(src) {
            // A successful confirm is APS-encrypted (§4.4.8.1.3 step 5).
            self.stats.policy_dropped = self.stats.policy_dropped.saturating_add(1);
            return;
        }
        if self
            .security
            .set_attributes(src, KeyAttributes::VerifiedKey)
        {
            self.push_action(ApsAction::Persist(PersistItem::LinkKeys));
        }
        self.push_event(ApsEvent::ConfirmKey {
            src,
            key_type: ck.key_type,
            status: ck.status,
        });
    }
}

/// Byte range of a relayed message inside the command buffer.
fn relayed_range(buf: &[u8], start: usize, end: usize, message: &[u8]) -> Option<(usize, usize)> {
    let base = buf.as_ptr() as usize;
    let m = message.as_ptr() as usize;
    if m < base + start || m + message.len() > base + end {
        return None;
    }
    Some((m - base, m - base + message.len()))
}
