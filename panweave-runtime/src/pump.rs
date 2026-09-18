//! Action / event pumping between the layers, the receive path and the
//! join / authorization logic.

use heapless::Vec;
use panweave_aps::command::{RequestKeyType, UpdateDeviceStatus};
use panweave_aps::layer::NwkView;
use panweave_aps::layer::{
    ApsAction, ApsEvent, DataIndication, DataRequest, Delivery, Destination, DeviceState, KeyRoute,
    PersistItem, TransportedKey, TxOptions,
};
use panweave_aps::layer::{RelayInfo, SecurityStatus};
use panweave_codec::Decode;
use panweave_codec::Encode;
use panweave_codec::tlv::TlvSet;
use panweave_mac::frame::{FrameType as MacFrameType, MacAddress};
use panweave_mac::radio::RxMetadata;
use panweave_mac::service::{MacEvent, RxDisposition, TxStatus};
use panweave_nwk::interface::{InterfaceType, MacInterfaceEntry};
use panweave_nwk::layer::{JoinMethod, JoinParams};
use panweave_nwk::layer::{NwkAction, NwkEvent, RxOutcome};
use panweave_nwk::tlv::{DeviceCapabilityExtension, GlobalTlvs, SupportedKeyNegotiationMethods};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{InitialJoinAuthentication, LinkKeyEntry, LinkKeyKind};
use panweave_security::trust_center::{JoinDecision, JoinKind, TclkRequestPolicy};
use panweave_storage::{Key, Kind, Storage};
use panweave_types::time::Duration;
use panweave_types::{
    ApsStatus, CryptoRng, Endpoint, ExtendedAddress, Key128, KeySequenceNumber, KeyType,
    LogicalDeviceType, NwkStatus, ProfileId, ShortAddress,
};
use panweave_types::{ChannelMask, Instant, TransactionSequence};
use panweave_zcl::layer::{ZclAction, ZclEvent, ZclIndication};
use panweave_zdo::layer::{ZdoAction, ZdoEvent, ZdoIndication};
use panweave_zdo::security::{
    ChallengeReq, ChallengeRsp, FrameCounterChallenge, FrameCounterResponse,
    RetrieveAuthenticationTokenRsp, SelectedKeyNegotiationMethod, StartKeyNegotiationRsp,
    StartKeyUpdateReq,
};
use panweave_zdo::zdp::{
    BeaconSurveyResults, MgmtNwkBeaconSurveyReq, MgmtNwkBeaconSurveyRsp, MgmtNwkEnhancedUpdateReq,
    MgmtNwkUpdateNotify, MgmtNwkUpdateReq, NodeDescReq, NodeDescRsp, ParentAnnceRsp,
    PotentialParents,
};

/// `apsParentAnnounceBaseTimer` (R23.2 Table 2-134).
const PARENT_ANNOUNCE_BASE_TIMER: Duration = Duration::from_secs(10);
/// `apsParentAnnounceJitterMax`.
const PARENT_ANNOUNCE_JITTER_MAX: Duration = Duration::from_secs(10);
use panweave_zdo::{ZdpStatus, cluster};

use crate::context::{AddrView, ZdoCtx};
use crate::stack::{
    BeaconSurveyRequest, Challenge, EnergyScanRequest, PendingChild, Phase, Stack, StackEvent,
    ZclFrame, ZdpData,
};

/// Largest NWK payload copied out of a MAC frame.
const NPDU_BUF: usize = 116;
/// Largest APS frame copied out of an NWK data indication.
const APDU_BUF: usize = 108;
/// Largest ASDU copied out of an APS data indication.
const ASDU_BUF: usize = panweave_aps::MAX_ASDU;

/// An owned copy of an APS data indication (the APS layer borrows itself
/// while an indication is alive; copying lets the ZDO/ZCL handlers
/// reach the APS again).
struct OwnedIndication {
    src: ShortAddress,
    src_ieee: Option<ExtendedAddress>,
    src_endpoint: Endpoint,
    delivery: Delivery,
    profile: ProfileId,
    cluster: panweave_types::ClusterId,
    asdu: Vec<u8, ASDU_BUF>,
    security: SecurityStatus,
    lqi: u8,
    relayed: Option<RelayInfo>,
    counter: u8,
    nwk_broadcast: bool,
}

impl OwnedIndication {
    fn from(ind: &DataIndication<'_>) -> Option<Self> {
        Some(OwnedIndication {
            src: ind.src,
            src_ieee: ind.src_ieee,
            src_endpoint: ind.src_endpoint,
            delivery: ind.delivery,
            profile: ind.profile,
            cluster: ind.cluster,
            asdu: Vec::from_slice(ind.asdu).ok()?,
            security: ind.security,
            lqi: ind.lqi,
            relayed: ind.relayed,
            counter: ind.counter,
            nwk_broadcast: ind.nwk_broadcast,
        })
    }

    fn borrow(&self) -> DataIndication<'_> {
        DataIndication {
            src: self.src,
            src_ieee: self.src_ieee,
            src_endpoint: self.src_endpoint,
            delivery: self.delivery,
            profile: self.profile,
            cluster: self.cluster,
            asdu: &self.asdu,
            security: self.security,
            lqi: self.lqi,
            relayed: self.relayed,
            counter: self.counter,
            nwk_broadcast: self.nwk_broadcast,
        }
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Runs the inter-layer pump until nothing moves.
    pub(crate) fn pump(&mut self) {
        for _ in 0..64 {
            let mut progressed = false;
            progressed |= self.pump_mac_events();
            progressed |= self.pump_nwk_actions();
            progressed |= self.pump_nwk_events();
            progressed |= self.pump_aps_actions();
            progressed |= self.pump_aps_events();
            progressed |= self.pump_zdo();
            progressed |= self.pump_zcl_actions();
            if !progressed {
                break;
            }
        }
    }

    // ---------------------------------------------------------------
    // Receive path
    // ---------------------------------------------------------------

    pub(crate) fn handle_radio_frame(&mut self, bytes: &[u8], meta: RxMetadata) {
        let channel = meta.channel.unwrap_or(self.nwk.nib.channel);
        let lqi = meta.lqi;
        self.last_rx = Some((meta.lqi, meta.rssi_dbm));
        let rssi = meta.rssi_dbm;
        match self.mac.on_receive(bytes, meta) {
            RxDisposition::Handled | RxDisposition::Other { .. } => {}
            RxDisposition::Beacon { header, beacon, .. } => {
                self.nwk.on_mac_beacon(
                    header
                        .src_pan
                        .or(header.dst_pan)
                        .unwrap_or(self.nwk.nib.pan_id),
                    header.src,
                    &beacon,
                    channel,
                    self.nwk.nib.channel_page,
                    lqi,
                );
            }
            RxDisposition::Data { frame, .. } => {
                if frame.header.frame_control.frame_type() != MacFrameType::Data {
                    return;
                }
                #[cfg(feature = "green-power")]
                if crate::green_power::is_gpdf(frame.payload) {
                    // GPDFs (Zigbee Protocol Version 3) go to the GP stub.
                    self.on_gpdf(&frame, lqi, rssi);
                    return;
                }
                if panweave_aps::interpan::InterPanHeader::is_inter_pan(frame.payload) {
                    // Touchlink inter-PAN frames never enter the NWK layer.
                    self.on_inter_pan(&frame, meta.rssi_dbm, channel);
                    return;
                }
                let Some(mac_src) = frame.header.src.short() else {
                    return;
                };
                let Ok(mut npdu) = Vec::<u8, NPDU_BUF>::from_slice(frame.payload) else {
                    return;
                };
                let outcome = self.nwk.on_mac_data(&mut npdu, mac_src, lqi, rssi);
                self.deliver_rx_outcome(outcome);
            }
        }
    }

    /// Hands a NWK data outcome to the APS layer and the application.
    fn deliver_rx_outcome(&mut self, outcome: RxOutcome<'_>) {
        let owned = match outcome {
            RxOutcome::Data {
                src,
                dst,
                src_ieee,
                secured,
                lqi,
                payload,
                ..
            } => {
                let Ok(mut apdu) = Vec::<u8, APDU_BUF>::from_slice(payload) else {
                    return;
                };
                let view = AddrView(&self.nwk);
                self.aps
                    .on_nwk_data(&mut apdu, src, dst, src_ieee, secured, lqi, &view)
                    .as_ref()
                    .and_then(OwnedIndication::from)
            }
            RxOutcome::None | RxOutcome::InterPan { .. } => None,
        };
        if let Some(ind) = owned {
            self.dispatch_indication(&ind);
        }
    }

    /// An NPDU received over Trusted Link `link` from `peer` (the
    /// pre-processed NPDU Message of a Zigbee Direct tunnel, R23.2
    /// §3.2.2.43): processed as if received from that neighbour,
    /// treated as NWK-secured when `assume_security`. The link must be
    /// registered with [`Stack::add_trusted_link`].
    pub fn on_trusted_link_npdu(
        &mut self,
        link: u8,
        peer: ExtendedAddress,
        npdu: &[u8],
        assume_security: bool,
    ) {
        if !self
            .nwk
            .interfaces
            .get(link)
            .is_some_and(|e| e.kind == InterfaceType::TrustedLink && e.state)
        {
            return;
        }
        let Ok(mut buf) = Vec::<u8, NPDU_BUF>::from_slice(npdu) else {
            return;
        };
        let outcome = self
            .nwk
            .on_trusted_link_data(link, peer, &mut buf, assume_security);
        self.deliver_rx_outcome(outcome);
        self.pump();
    }

    /// Registers a Trusted Link interface (nwkMacInterfaceTable entry
    /// of type Trusted Link, R23.2 Table 3-69) carrying `handle` (for
    /// Zigbee Direct the BLE connection handle). NPDUs for neighbours
    /// behind it are reported as [`StackEvent::TrustedLinkNpdu`].
    pub fn add_trusted_link(&mut self, link: u8, handle: u16) -> bool {
        self.nwk
            .interfaces
            .insert(MacInterfaceEntry::trusted_link(link, handle))
            .is_ok()
    }

    /// Removes a Trusted Link: its neighbours are forgotten.
    pub fn remove_trusted_link(&mut self, link: u8) {
        self.nwk.interfaces.remove(link);
        self.nwk.neighbors.retain(|n| n.link != Some(link));
    }

    fn dispatch_indication(&mut self, ind: &OwnedIndication) {
        let borrowed = ind.borrow();
        let to_zdo = ind.profile == ProfileId::ZDP
            || matches!(ind.delivery, Delivery::Endpoint(Endpoint(0)));
        if to_zdo {
            let Stack {
                zdo,
                nwk,
                aps,
                config,
                dlk,
                ..
            } = self;
            let is_tc = aps.config.is_trust_center;
            let mut ctx = ZdoCtx {
                nwk,
                aps,
                policy: &config.trust_center_policy,
                is_trust_center: is_tc,
                bindings_changed: false,
                joining_list_changed: false,
                max_bind: config.zdo.max_bind,
                dlk,
            };
            let out = zdo.on_data(&borrowed, &mut ctx);
            let (bindings_changed, joining_list_changed) =
                (ctx.bindings_changed, ctx.joining_list_changed);
            if bindings_changed {
                let _ = self.persist_bindings();
            }
            if joining_list_changed {
                self.sync_joining_filter();
            }
            self.zdo.restricted_mode = self.aps.aib.zdo_restricted_mode;
            if let Some((method, via)) = self.dlk.start_requested.take() {
                // Security_Start_Key_Update_req accepted: negotiate with
                // the Trust Center (§4.6.3.5 step 1).
                let _ = self.start_key_negotiation(method.sender, method, via);
            }
            match out {
                Some(ZdoIndication::Response {
                    src,
                    seq,
                    cluster,
                    data,
                    matched,
                    src_ieee,
                    security,
                    relayed,
                }) => {
                    if cluster == cluster::response_of(cluster::SECURITY_START_KEY_NEGOTIATION_REQ)
                        && let Ok(rsp) = StartKeyNegotiationRsp::decode_exact(data)
                    {
                        self.on_key_negotiation_response(src_ieee, rsp.status, rsp.tlvs, relayed);
                    }
                    if cluster
                        == cluster::response_of(cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ)
                    {
                        self.on_authentication_token(src_ieee, security, data);
                    }
                    if cluster == cluster::response_of(cluster::SECURITY_CHALLENGE_REQ) {
                        self.on_challenge_response(data);
                    }
                    if cluster == cluster::response_of(cluster::PARENT_ANNCE) {
                        self.on_parent_annce_rsp(src, data);
                    }
                    let keep_alive_desc = cluster == cluster::response_of(cluster::NODE_DESC_REQ)
                        && self.on_keep_alive_node_desc(src, seq);
                    let fragmentation_desc = cluster
                        == cluster::response_of(cluster::NODE_DESC_REQ)
                        && self.on_fragmentation_node_desc(src, seq, data);
                    if cluster == cluster::response_of(cluster::NODE_DESC_REQ)
                        && self.tclk_update.is_some()
                        && src_ieee.is_none_or(|s| s == self.aps.aib.trust_center_address)
                    {
                        self.on_tclk_update_descriptor(data);
                    }
                    let keep_alive_match = cluster == cluster::response_of(cluster::MATCH_DESC_REQ)
                        && self.on_keep_alive_match(seq, data);
                    let ota = self.on_ota_discovery_response(src, seq, cluster, data);
                    if !keep_alive_match
                        && !keep_alive_desc
                        && !fragmentation_desc
                        && !ota
                        && let Ok(data) = Vec::from_slice(data)
                    {
                        self.push_event(StackEvent::Zdp(ZdpData {
                            src,
                            seq,
                            cluster,
                            data,
                            matched,
                        }));
                    }
                }
                Some(ZdoIndication::DeviceAnnounce {
                    ieee,
                    short,
                    capability,
                    ..
                }) => {
                    #[cfg(feature = "green-power")]
                    self.on_green_power_announce(ieee, short);
                    self.push_event(StackEvent::DeviceAnnounce {
                        ieee,
                        short,
                        capability,
                    });
                }
                None => {}
            }
            return;
        }
        let out = self.zcl.on_data(&borrowed, &mut self.aps.groups);
        if ind.cluster == panweave_zcl::clusters::groups::ID {
            // A Groups server command may have changed apsGroupTable.
            let _ = self.persist_groups();
        }
        #[cfg(feature = "green-power")]
        if let Some(ZclIndication::Command { origin, payload }) = out
            && self.on_green_power_command(&origin, payload)
        {
            return;
        }
        let event = match out {
            Some(ZclIndication::Command { origin, payload }) => Vec::from_slice(payload)
                .ok()
                .map(|payload| StackEvent::ZclCommand(ZclFrame { origin, payload })),
            Some(ZclIndication::Response { origin, payload })
                if origin.cluster == crate::keep_alive::CLUSTER
                    && origin.header.command
                        == panweave_zcl::global::command::READ_ATTRIBUTES_RESPONSE
                    && self.on_keep_alive_response(
                        origin.src,
                        origin.header.seq,
                        ind.security == SecurityStatus::LinkKey,
                        payload,
                    ) =>
            {
                None
            }
            Some(ZclIndication::Response { origin, payload }) => Vec::from_slice(payload)
                .ok()
                .map(|payload| StackEvent::ZclResponse(ZclFrame { origin, payload })),
            Some(ZclIndication::Report { origin, payload }) => Vec::from_slice(payload)
                .ok()
                .map(|payload| StackEvent::ZclReport(ZclFrame { origin, payload })),
            None => None,
        };
        if let Some(e) = event {
            self.push_event(e);
        }
    }

    // ---------------------------------------------------------------
    // MAC → NWK
    // ---------------------------------------------------------------

    fn pump_mac_events(&mut self) -> bool {
        let mut any = false;
        while let Some(e) = self.mac.next_event() {
            any = true;
            match e {
                MacEvent::DataConfirm { handle, status, .. } => {
                    if let Some(i) = self.mac_handles.iter().position(|(m, _)| *m == handle) {
                        let (_, nwk_handle) = self.mac_handles.swap_remove(i);
                        self.nwk.on_mac_data_confirm(nwk_handle, status);
                    }
                }
                MacEvent::ScanConfirm { kind, .. } => {
                    let energy = *self.mac.energy_results();
                    self.nwk.on_mac_scan_confirm(kind, &energy);
                }
                MacEvent::AssociateIndication {
                    device,
                    capability,
                    lqi,
                } => self
                    .nwk
                    .on_mac_associate_indication(device, capability, lqi),
                MacEvent::AssociateConfirm {
                    short_address,
                    status,
                } => self.nwk.on_mac_associate_confirm(short_address, status),
                MacEvent::CommStatus { device, status } => {
                    self.nwk.on_mac_comm_status(device, status);
                }
                MacEvent::PollConfirm {
                    frame_pending,
                    status,
                } => self
                    .nwk
                    .on_mac_poll_confirm(status == TxStatus::Success, frame_pending),
                MacEvent::PollIndication { device } => self.nwk.on_mac_poll_indication(device),
                MacEvent::IndirectReady { handle } => {
                    // The deferred transaction is consumed; the direct
                    // transmission that follows registers a new mapping.
                    if let Some(i) = self.mac_handles.iter().position(|(m, _)| *m == handle) {
                        let (_, nwk_handle) = self.mac_handles.swap_remove(i);
                        self.nwk.on_mac_indirect_ready(nwk_handle);
                    }
                }
                MacEvent::PanIdConflict { .. } => {
                    // The NWK detects conflicts from beacons (§3.6.1.10);
                    // nothing further to do here.
                }
            }
        }
        any
    }

    // ---------------------------------------------------------------
    // NWK → MAC / storage
    // ---------------------------------------------------------------

    fn pump_nwk_actions(&mut self) -> bool {
        let mut any = false;
        while let Some(a) = self.nwk.next_action() {
            any = true;
            match a {
                NwkAction::MacData {
                    handle,
                    dst,
                    frame,
                    ack,
                    indirect,
                } => {
                    let pan = self.nwk.nib.pan_id;
                    match self
                        .mac
                        .data_request(pan, MacAddress::Short(dst), &frame, ack, indirect)
                    {
                        Ok(mac_handle) => {
                            if self.mac_handles.push((mac_handle, handle)).is_err() {
                                let _ = self.mac.purge(mac_handle);
                                self.nwk
                                    .on_mac_data_confirm(handle, TxStatus::ChannelAccessFailure);
                            }
                        }
                        Err(_) => self
                            .nwk
                            .on_mac_data_confirm(handle, TxStatus::ChannelAccessFailure),
                    }
                }
                NwkAction::TrustedLinkData {
                    handle,
                    link,
                    frame,
                    assume_security,
                } => {
                    // The Trusted Link transport is the host's (a BLE
                    // connection for Zigbee Direct): the NPDU is handed
                    // out as an event and counted as delivered.
                    self.push_event(StackEvent::TrustedLinkNpdu {
                        link,
                        npdu: frame,
                        assume_security,
                    });
                    self.nwk.on_mac_data_confirm(handle, TxStatus::Success);
                }
                NwkAction::MacDataDeferred { handle, dst } => {
                    match self.mac.data_request_deferred(MacAddress::Short(dst)) {
                        Ok(mac_handle) => {
                            if self.mac_handles.push((mac_handle, handle)).is_err() {
                                let _ = self.mac.purge(mac_handle);
                                self.nwk
                                    .on_mac_data_confirm(handle, TxStatus::TransactionExpired);
                            }
                        }
                        Err(_) => self
                            .nwk
                            .on_mac_data_confirm(handle, TxStatus::TransactionExpired),
                    }
                }
                NwkAction::MacScan {
                    kind,
                    channels,
                    duration,
                    enhanced,
                } => {
                    let started = match enhanced {
                        Some(e) => self.mac.scan_enhanced(channels, duration, e),
                        None => self.mac.scan(kind, channels, duration),
                    };
                    if started.is_err() {
                        self.nwk.on_mac_scan_confirm(kind, &[0; 27]);
                    }
                }
                NwkAction::MacAssociate {
                    pan_id,
                    coordinator,
                    page,
                    channel,
                    capability,
                } => {
                    self.mac.set_channel(page, channel);
                    if self
                        .mac
                        .associate(pan_id, MacAddress::Short(coordinator), capability)
                        .is_err()
                    {
                        self.nwk.on_mac_associate_confirm(
                            ShortAddress::NO_SHORT_ADDRESS,
                            panweave_types::MacStatus::ChannelAccessFailure,
                        );
                    }
                }
                NwkAction::MacAssociateResponse {
                    device,
                    short,
                    status,
                } => {
                    if self.mac.associate_response(device, short, status).is_err() {
                        self.nwk
                            .on_mac_comm_status(device, TxStatus::ChannelAccessFailure);
                    }
                }
                NwkAction::MacStart {
                    pan_id,
                    page,
                    channel,
                    short,
                    coordinator,
                    beacon_capable,
                } => self
                    .mac
                    .start(pan_id, page, channel, short, coordinator, beacon_capable),
                NwkAction::MacSetPermit(p) => self.mac.set_association_permit(p),
                NwkAction::MacSetBeaconPayload(v) => {
                    let _ = self.mac.set_beacon_payload(&v);
                }
                NwkAction::MacSetShortAddress(s) => {
                    self.mac.set_short_address(s);
                    self.aps.set_network_state(s, self.aps.state());
                }
                NwkAction::MacSetPanId(p) => self.mac.set_pan_id(p),
                NwkAction::MacSetChannel { page, channel } => self.mac.set_channel(page, channel),
                NwkAction::MacSetCoordinator { short, extended } => {
                    self.mac.set_coordinator(short, extended);
                    // The link to the parent is confirmed (Annex D.11.2.3).
                    self.mac
                        .power_table_mut()
                        .mark_negotiated(Some(short), Some(extended));
                }
                NwkAction::MacSetRxOnWhenIdle(on) => self.mac.set_rx_on_when_idle(on),
                NwkAction::MacPoll => {
                    if self.mac.poll().is_err() {
                        self.nwk.on_mac_poll_confirm(false, false);
                    }
                }
                NwkAction::MacAdjustTxPower {
                    short,
                    extended,
                    delta_db,
                    rssi_dbm,
                } => {
                    let now = self.now;
                    let _ = self
                        .mac
                        .power_table_mut()
                        .adjust(short, extended, delta_db, rssi_dbm, now);
                }
                NwkAction::MacResetTxPower => self.mac.power_table_mut().reset(),
                NwkAction::Persist => {
                    // R23.2 §3.6.9 / §4.3.4: NIB items, end-device
                    // children and network keys are committed whenever
                    // the NWK layer flags a change.
                    let _ = self.persist_nib();
                    let _ = self.persist_children();
                    let _ = self.persist_network_keys();
                }
                NwkAction::CounterReservation(r) => {
                    let ok = self
                        .storage
                        .store(
                            Key::single(Kind::NwkFrameCounter),
                            &r.reserved_until.to_le_bytes(),
                        )
                        .is_ok();
                    if ok {
                        self.nwk.commit_counter_reservation(r);
                    }
                }
            }
        }
        any
    }

    // ---------------------------------------------------------------
    // NWK events → stack logic
    // ---------------------------------------------------------------

    fn pump_nwk_events(&mut self) -> bool {
        let mut any = false;
        while let Some(e) = self.nwk.next_event() {
            any = true;
            match e {
                NwkEvent::DataConfirm { id, status } => {
                    if let Some(i) = self.aps_handles.iter().position(|(t, _)| *t == id) {
                        let (_, h) = self.aps_handles.swap_remove(i);
                        self.aps.on_nwk_data_confirm(h, status);
                    }
                }
                NwkEvent::FormationConfirm { status } => {
                    if status.is_success() {
                        let short = self.nwk.nib.network_address;
                        self.aps
                            .set_network_state(short, DeviceState::JoinedAuthorized);
                        self.phase = Phase::Operating;
                        self.aps.aib.use_extended_pan_id = self.nwk.nib.extended_pan_id;
                        let _ = self.persist_link_keys();
                        self.push_event(StackEvent::NetworkFormed {
                            pan_id: self.nwk.nib.pan_id,
                            extended_pan_id: self.nwk.nib.extended_pan_id,
                        });
                    } else {
                        self.phase = Phase::Idle;
                        self.push_event(StackEvent::FormationFailed(status));
                    }
                }
                NwkEvent::DiscoveryConfirm { status } => {
                    if self.beacon_survey.is_some() {
                        self.on_beacon_survey_confirm();
                    }
                    if let Phase::Discovering(mode) = self.phase {
                        if status.is_success() {
                            // apsUseExtendedPANID (§2.2.5): when set, only
                            // that network is joined.
                            let wanted = self.aps.aib.use_extended_pan_id;
                            let params = JoinParams {
                                extended_pan_id: (wanted != ExtendedAddress::ZERO
                                    && wanted != ExtendedAddress::BROADCAST)
                                    .then_some(wanted),
                                rejoin: mode != crate::JoinMode::Association,
                                as_router: self.config.role == LogicalDeviceType::Router,
                                secure: mode == crate::JoinMode::SecuredRejoin,
                                capability: self.config.capability(),
                                require_permit: mode == crate::JoinMode::Association,
                            };
                            match self.nwk.join(params) {
                                Ok(()) => self.phase = Phase::Joining(mode),
                                Err(_) => {
                                    self.phase = Phase::Idle;
                                    self.note_parent_loss_rejoin(false);
                                    self.push_event(StackEvent::JoinFailed(
                                        NwkStatus::InvalidRequest,
                                    ));
                                }
                            }
                        } else if self.scan_attempts_left > 0 {
                            // Another :Config_NWK_Scan_Attempts round after
                            // :Config_NWK_Time_btwn_Scans (§2.5.4.5.1).
                            self.scan_attempts_left -= 1;
                            let at = self
                                .now
                                .saturating_add(self.config.zdo.time_between_scans());
                            self.next_scan = Some((at, self.last_scan.0, self.last_scan.1));
                        } else {
                            self.phase = Phase::Idle;
                            self.note_parent_loss_rejoin(false);
                            self.push_event(StackEvent::JoinFailed(status));
                        }
                    }
                }
                NwkEvent::JoinConfirm {
                    status,
                    network_address,
                    secured,
                    rejoin,
                    ..
                } => {
                    if status.is_success() {
                        self.aps
                            .set_network_state(network_address, Self::aps_state(secured));
                        if secured {
                            self.complete_join(rejoin);
                        } else {
                            self.phase = Phase::AwaitingKey;
                            self.awaiting_key_rejoin = rejoin;
                            // A sleepy joiner polls its parent for the
                            // tunnelled network key (§4.6.3.2.3).
                            self.next_poll = Some(self.now);
                            self.schedule_fast_polls();
                        }
                    } else {
                        self.phase = Phase::Idle;
                        self.note_parent_loss_rejoin(false);
                        self.push_event(StackEvent::JoinFailed(status));
                    }
                }
                NwkEvent::JoinIndication {
                    device,
                    network_address,
                    capability: _,
                    method,
                    joiner_tlvs,
                } => {
                    // The link to the child is confirmed (Annex D.11.2.3).
                    self.mac
                        .power_table_mut()
                        .mark_negotiated(Some(network_address), Some(device));
                    self.on_child_joined(device, network_address, method, &joiner_tlvs);
                }
                NwkEvent::AuthenticationTimeout => {
                    self.phase = Phase::Idle;
                    self.aps
                        .set_network_state(ShortAddress::NO_SHORT_ADDRESS, DeviceState::NotJoined);
                    self.note_parent_loss_rejoin(false);
                    self.push_event(StackEvent::JoinFailed(NwkStatus::NoKey));
                }
                NwkEvent::LeaveIndication {
                    device,
                    short,
                    child,
                    rejoin,
                } => match device {
                    None => {
                        self.phase = Phase::Idle;
                        self.aps.set_network_state(
                            ShortAddress::NO_SHORT_ADDRESS,
                            DeviceState::NotJoined,
                        );
                        self.stop_keep_alive();
                        self.fast_poll_mode = None;
                        self.push_event(StackEvent::Left { rejoin });
                        self.finish_factory_reset();
                        self.apply_pending_startup();
                        self.apply_pending_touchlink();
                    }
                    Some(ieee) => {
                        if child {
                            self.report_child_left(ieee, short, rejoin);
                        }
                    }
                },
                NwkEvent::LeaveConfirm {
                    device,
                    short,
                    status,
                } => match device {
                    None if status.is_success() => {
                        self.phase = Phase::Idle;
                        self.aps.set_network_state(
                            ShortAddress::NO_SHORT_ADDRESS,
                            DeviceState::NotJoined,
                        );
                        self.push_event(StackEvent::Left { rejoin: false });
                        self.finish_factory_reset();
                        self.apply_pending_startup();
                        self.apply_pending_touchlink();
                    }
                    Some(child) if status.is_success() => {
                        // A child this router made leave (Remove Device or
                        // Mgmt_Leave): tell the Trust Center (§4.6.3.6.2).
                        self.report_child_left(child, short, false);
                    }
                    _ => {}
                },
                NwkEvent::NetworkStatus { code, address } => {
                    if code == panweave_nwk::command::NetworkStatusCode::ParentLinkFailure
                        && self.config.role == LogicalDeviceType::EndDevice
                        && self.phase == Phase::Operating
                    {
                        // §2.5.5.5.6.x: count failures against
                        // :Config_Parent_Link_Retry_Threshold, then rejoin
                        // (§3.6.1.4.2 / BDB 3.1 §10.1) no sooner than
                        // :Config_Rejoin_Interval after the previous
                        // attempt.
                        self.parent_link_failures = self.parent_link_failures.saturating_add(1);
                        if self.parent_link_failures > self.config.zdo.parent_link_retry_threshold {
                            self.parent_link_failures = 0;
                            self.start_parent_loss_rejoin();
                        }
                    }
                    if code == panweave_nwk::command::NetworkStatusCode::NetworkAddressUpdate
                        && address == self.nwk.nib.network_address
                    {
                        // §3.6.1.10.2: re-addressed after an address
                        // conflict; announce the new address.
                        let _ = self.zdo.device_announce(
                            address,
                            self.config.ieee,
                            self.config.capability(),
                        );
                        self.push_event(StackEvent::AddressChanged { short: address });
                    }
                    if code == panweave_nwk::command::NetworkStatusCode::PanIdConflictReport {
                        // §2.3.4.2: a legacy device reported a conflict;
                        // the application decides (Stack::change_pan_id).
                        self.push_event(StackEvent::PanIdConflictReport { from: address });
                    }
                }
                NwkEvent::PanIdChanged { pan_id } => {
                    self.push_event(StackEvent::PanIdChanged { pan_id });
                }
                NwkEvent::EnergyScanConfirm { channels, energy } => {
                    let now = self.now;
                    if !self.on_interference_scan(&energy, now) {
                        self.on_energy_scan_confirm(channels, &energy);
                    }
                }
                NwkEvent::LinkPowerDelta {
                    src,
                    kind,
                    delta_db,
                } => {
                    self.push_event(StackEvent::LinkPowerDelta {
                        src,
                        kind,
                        delta_db,
                    });
                }
                NwkEvent::StartRouterConfirm { .. }
                | NwkEvent::RouteDiscoveryConfirm { .. }
                | NwkEvent::PermitJoining(_)
                | NwkEvent::ChildRemoved { .. }
                | NwkEvent::LostChild { .. }
                | NwkEvent::ParentInformationUpdated => {
                    #[cfg(feature = "green-power")]
                    self.sync_green_power_keys();
                }
                NwkEvent::KeySwitched { previous, sequence } => {
                    #[cfg(feature = "green-power")]
                    self.sync_green_power_keys();
                    self.push_event(StackEvent::NetworkKeySwitched { previous, sequence });
                }
            }
        }
        any
    }

    /// Finishes joining once the network key is active (§4.6.3.2.3.2).
    fn complete_join(&mut self, rejoin: bool) {
        self.phase = Phase::Operating;
        self.parent_link_failures = 0;
        self.note_parent_loss_rejoin(true);
        self.aps.set_authorized();
        self.next_poll = Some(self.now);
        self.fast_polls_left = self.config.fast_polls;
        if self.config.role == LogicalDeviceType::Router {
            let _ = self.nwk.start_router();
        }
        let short = self.nwk.nib.network_address;
        let _ = self
            .zdo
            .device_announce(short, self.config.ieee, self.config.capability());
        // On a centralized network the Trust Center is the coordinator
        // (network address 0x0000, §4.6.3.1): make the pair addressable.
        let tc = self.aps.aib.trust_center_address;
        if !self.aps.aib.is_distributed() && AddrView(&self.nwk).short_of(tc).is_none() {
            let _ = self.nwk.address_map.record(tc, ShortAddress::COORDINATOR);
        }
        // §2.4.3.4.2: a device that negotiated its link key obtains its
        // authentication token (passphrase) once, for later re-negotiation.
        let negotiated = self.aps.security.entry(tc).is_some_and(|e| {
            e.negotiation_state == panweave_security::material::KeyNegotiationState::Complete
                && e.passphrase_update_allowed
        });
        if !rejoin && !self.aps.aib.is_distributed() && negotiated {
            let tc_short = AddrView(&self.nwk)
                .short_of(tc)
                .unwrap_or(ShortAddress::COORDINATOR);
            let mut tlv = [0u8; 3];
            let mut w = panweave_codec::Writer::new(&mut tlv);
            let _ = panweave_zdo::security::AuthenticationTokenId(
                panweave_nwk::tlv::tag::SYMMETRIC_PASSPHRASE,
            )
            .write(&mut w);
            let req = panweave_zdo::security::RetrieveAuthenticationTokenReq { tlvs: &tlv };
            let _ = self.zdo.request_secured(
                tc_short,
                cluster::SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ,
                &req,
            );
        }
        // BDB 3.1 §10.2.4: request a unique Trust Center link key after a
        // join with a global key on a centralized network.
        let global = self
            .aps
            .security
            .entry(tc)
            .is_some_and(|e| e.kind == LinkKeyKind::Global);
        // §4.7.4.1.2.6 step 8: after a swap-out the hashed key must be
        // replaced before any APS-secured messaging.
        let swapped = core::mem::take(&mut self.swap_out_pending);
        if (!rejoin && !self.aps.aib.is_distributed() && global) || swapped {
            self.start_tclk_update(tc);
        }
        // apsUseExtendedPANID remembers the network for later rejoins
        // (§2.2.5) and is stored with the AIB.
        if self.aps.aib.use_extended_pan_id != self.nwk.nib.extended_pan_id {
            self.aps.aib.use_extended_pan_id = self.nwk.nib.extended_pan_id;
            let _ = self.persist_link_keys();
        }
        self.push_event(StackEvent::Joined {
            short,
            pan_id: self.nwk.nib.pan_id,
            rejoin,
        });
        self.start_keep_alive();
        #[cfg(feature = "green-power")]
        self.sync_green_power_keys();
    }

    /// NLME-JOIN.indication at a parent (§4.6.3.2.1).
    fn on_child_joined(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        method: JoinMethod,
        joiner_tlvs: &[u8],
    ) {
        let status = match method {
            JoinMethod::MacAssociation | JoinMethod::CommissioningJoin => {
                UpdateDeviceStatus::UnsecuredJoin
            }
            JoinMethod::RejoinUnsecured | JoinMethod::CommissioningRejoinUnsecured => {
                UpdateDeviceStatus::TrustCenterRejoin
            }
            JoinMethod::RejoinSecured | JoinMethod::CommissioningRejoinSecured => {
                UpdateDeviceStatus::SecuredRejoin
            }
        };
        if self.aps.config.is_trust_center {
            self.trust_center_authorize(device, short, status, None, joiner_tlvs);
        } else if self.aps.aib.is_distributed() {
            // Distributed network: the router hands out the network key
            // itself (§4.6.3.2.1), under the distributed security global
            // link key every joiner holds (BDB 3.1 §6.2.4): the key of the
            // preconfigured global entry, else the development key.
            if status != UpdateDeviceStatus::SecuredRejoin {
                if self.aps.security.entry(device).is_none() {
                    let key = self
                        .aps
                        .security
                        .keys()
                        .iter()
                        .find(|e| e.kind == LinkKeyKind::Global)
                        .map_or(Key128::DISTRIBUTED_GLOBAL_DEVELOPMENT, |e| e.key.clone());
                    let e = LinkKeyEntry::provisional(device, key, LinkKeyKind::Global);
                    let _ = self.aps.install_link_key(e);
                }
                let route = KeyRoute::Direct {
                    short,
                    nwk_secure: false,
                };
                // A Zigbee Direct Virtual Device on a distributed network
                // gets its Basic authorization key from the ZDD, under
                // the distributed global link key (ZD 1.1 §7.7.4.5).
                if Self::joiner_is_virtual_device(joiner_tlvs) {
                    self.virtual_devices.retain(|(d, _)| *d != device);
                    let _ = self.virtual_devices.push((device, None));
                    let seq = self.network_key_sequence;
                    self.send_basic_authorization_key(device, short, seq, route, true);
                } else {
                    self.send_network_key(device, short, route);
                }
            }
        } else {
            let tc_short = AddrView(&self.nwk)
                .short_of(self.aps.aib.trust_center_address)
                .unwrap_or(ShortAddress::COORDINATOR);
            let _ = self
                .aps
                .update_device(tc_short, device, short, status, joiner_tlvs);
        }
    }

    /// Trust Center authorization (§4.6.3.2.2, §4.7.3). `parent` is the
    /// router that reported the join (None when we are the parent).
    #[allow(clippy::too_many_lines)]
    fn trust_center_authorize(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        status: UpdateDeviceStatus,
        parent: Option<ShortAddress>,
        joiner_tlvs: &[u8],
    ) {
        if status == UpdateDeviceStatus::DeviceLeft {
            // §4.6.3.6.1: the device left through its parent; drop the
            // network-layer bookkeeping and inform the application. The
            // key-pair entry stays (a Trust Center policy decision).
            if let Some(s) = AddrView(&self.nwk).short_of(device) {
                self.fragmentation.forget(s);
            }
            let _ = self.nwk.neighbors.remove_extended(device);
            self.nwk.address_map.remove_extended(device);
            self.push_event(StackEvent::DeviceLeft {
                ieee: device,
                rejoin: false,
            });
            return;
        }
        let kind = match status {
            UpdateDeviceStatus::SecuredRejoin => JoinKind::SecuredRejoin,
            UpdateDeviceStatus::UnsecuredJoin => JoinKind::UnsecuredJoin,
            UpdateDeviceStatus::DeviceLeft => JoinKind::Left,
            UpdateDeviceStatus::TrustCenterRejoin | UpdateDeviceStatus::Reserved(_) => {
                JoinKind::TrustCenterRejoin
            }
        };
        // Supported Key Negotiation Methods inside the Joiner
        // Encapsulation (§4.7.3.3): the joiner offers SPEKE.
        let offers_dlk = cfg!(feature = "dlk")
            && TlvSet::validate(joiner_tlvs, |_| false)
                .ok()
                .and_then(|set| {
                    set.joiner_encapsulation()
                        .and_then(|inner| inner.key_negotiation_methods())
                        .or_else(|| set.key_negotiation_methods())
                })
                .is_some_and(|m| {
                    m.protocols & SupportedKeyNegotiationMethods::PROTO_SPEKE_CURVE25519_AES_MMO
                        != 0
                });
        // A Zigbee Direct Virtual Device (Device Capability Extension
        // Global TLV, bit 0): never the network key (§4.6.3.2.2.4).
        let virtual_device = Self::joiner_is_virtual_device(joiner_tlvs);
        let decision = self.config.trust_center_policy.evaluate_join(
            kind,
            self.aps.security.entry(device),
            offers_dlk,
            None,
        );
        if virtual_device {
            self.admit_virtual_device(device, short, parent, decision);
            return;
        }
        match decision {
            JoinDecision::NegotiateKey { create_entry } => {
                self.start_joiner_negotiation(device, short, parent, create_entry);
            }
            JoinDecision::TransportNetworkKey { create_entry } => {
                if create_entry {
                    let e = LinkKeyEntry::provisional(
                        device,
                        Key128::WELL_KNOWN_GLOBAL_TCLK,
                        LinkKeyKind::Global,
                    );
                    let _ = self.aps.install_link_key(e);
                }
                let route = match parent {
                    Some(p) => KeyRoute::Tunnel { parent: p },
                    None => KeyRoute::Direct {
                        short,
                        nwk_secure: false,
                    },
                };
                self.send_network_key(device, short, route);
            }
            JoinDecision::Allow => {
                self.nwk.authenticate_child(device);
                self.push_event(StackEvent::DeviceAuthorized {
                    ieee: device,
                    short,
                });
            }
            JoinDecision::Ignore => {}
            JoinDecision::Remove => {
                let _ = self.nwk.leave(Some(device), false, false);
            }
        }
    }

    /// Whether a joiner's TLVs carry the Device Capability Extension
    /// Global TLV with the Zigbee Direct Virtual Device flag.
    fn joiner_is_virtual_device(joiner_tlvs: &[u8]) -> bool {
        TlvSet::validate(joiner_tlvs, |_| false)
            .ok()
            .and_then(|set| {
                set.joiner_encapsulation()
                    .and_then(|inner| inner.device_capability_extension())
                    .or_else(|| set.device_capability_extension())
            })
            .is_some_and(|d| d.0 & DeviceCapabilityExtension::ZIGBEE_DIRECT_VIRTUAL_DEVICE != 0)
    }

    /// Network admittance of a Zigbee Direct Virtual Device
    /// (§4.6.3.2.2.4): with `allowVirtualDevices` the joiner gets a
    /// Basic authorization key derived from the active network key,
    /// APS-secured with the key-load key of its Trust Center link key,
    /// through its parent (the ZDD); without, it is not admitted and the
    /// parent is told to remove it. The stack remembers the device as
    /// virtual so that a network key update sends it a fresh Basic key
    /// instead of the new network key.
    fn admit_virtual_device(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        parent: Option<ShortAddress>,
        decision: JoinDecision,
    ) {
        let admitted = self.config.trust_center_policy.allow_virtual_devices
            && matches!(
                decision,
                JoinDecision::TransportNetworkKey { .. } | JoinDecision::NegotiateKey { .. }
            );
        if !admitted {
            let _ = self.nwk.leave(Some(device), false, false);
            return;
        }
        if self.aps.security.entry(device).is_none() {
            let e = LinkKeyEntry::provisional(
                device,
                Key128::WELL_KNOWN_GLOBAL_TCLK,
                LinkKeyKind::Global,
            );
            let _ = self.aps.install_link_key(e);
        }
        self.virtual_devices.retain(|(d, _)| *d != device);
        let _ = self.virtual_devices.push((device, parent));
        let route = match parent {
            Some(p) => KeyRoute::Tunnel { parent: p },
            None => KeyRoute::Direct {
                short,
                nwk_secure: false,
            },
        };
        let seq = self.network_key_sequence;
        self.send_basic_authorization_key(device, short, seq, route, true);
    }

    /// Transports the Basic authorization key of `device` derived from
    /// network key `seq` (ZD 1.1 §6.3.2.1); `joining` tracks the request
    /// as the joiner's authorization.
    fn send_basic_authorization_key(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        seq: KeySequenceNumber,
        route: KeyRoute,
        joining: bool,
    ) {
        let Some(nwk_key) = self.nwk.security.keys.get(seq).map(|s| s.key.clone()) else {
            return;
        };
        let key = panweave_security::authorization::basic_key::<C>(device, &nwk_key);
        if let Ok(request) = self
            .aps
            .transport_basic_authorization_key(device, &key, seq, route)
            && joining
        {
            let _ = self.pending_children.push(PendingChild {
                ieee: device,
                short,
                request,
            });
        }
    }

    /// A network key update: every joined Zigbee Direct Virtual Device
    /// gets a Basic authorization key derived from the prospective key
    /// instead of the key itself (§4.6.3.2.2.4), NWK-secured, through
    /// its parent when it joined through one.
    pub(crate) fn update_virtual_devices_keys(&mut self, sequence: KeySequenceNumber) {
        let devices = self.virtual_devices.clone();
        for (device, parent) in devices {
            let Some(short) = AddrView(&self.nwk).short_of(device) else {
                continue;
            };
            let route = match parent {
                Some(p) => KeyRoute::Tunnel { parent: p },
                None => KeyRoute::Direct {
                    short,
                    nwk_secure: true,
                },
            };
            self.send_basic_authorization_key(device, short, sequence, route, false);
        }
    }

    /// Trust Center side of Dynamic Key Negotiation Joining (§4.7.3.3
    /// steps 2–3): prepares the key-pair entry with its passphrase and
    /// asks the joiner to start negotiating through its parent.
    fn start_joiner_negotiation(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        parent: Option<ShortAddress>,
        create_entry: bool,
    ) {
        let secret = if create_entry {
            // Step 2c: anonymous negotiation with the well-known
            // passphrase (policy 0x03).
            let mut e = LinkKeyEntry::provisional(
                device,
                Key128::WELL_KNOWN_GLOBAL_TCLK,
                LinkKeyKind::Unique,
            );
            // The well-known passphrase is implied by the selected secret
            // and is not stored: the entry receives a real token later
            // (§2.4.3.4.2).
            e.initial_join_authentication = InitialJoinAuthentication::AnonymousKeyNegotiation;
            let _ = self.aps.install_link_key(e);
            SelectedKeyNegotiationMethod::SECRET_ANONYMOUS
        } else {
            // A pre-installed install-code entry: its passphrase is the
            // install-code derived key (§4.7.3.3).
            // The install-code derived key serves as the passphrase until
            // a token replaces it (§4.7.3.3, `passphrase_for`).
            match self.aps.security.keys_mut().get_mut(device) {
                Some(e) => {
                    e.initial_join_authentication =
                        InitialJoinAuthentication::KeyNegotiationWithAuthentication;
                    if e.passphrase.is_some() {
                        SelectedKeyNegotiationMethod::SECRET_AUTH_TOKEN
                    } else {
                        SelectedKeyNegotiationMethod::SECRET_INSTALL_CODE
                    }
                }
                None => return,
            }
        };
        let method = SelectedKeyNegotiationMethod {
            protocol: SelectedKeyNegotiationMethod::PROTOCOL_SPEKE_AES_MMO,
            secret,
            sender: self.config.ieee,
        };
        let mut tlvs = [0u8; 12 + 8];
        let mut w = panweave_codec::Writer::new(&mut tlvs);
        if method.write(&mut w).is_err() {
            return;
        }
        let _ = panweave_nwk::tlv::FragmentationParameters {
            node: self.nwk.nib.network_address,
            options: 0,
            max_incoming_transfer_unit: self.aps.aib.max_size_asdu,
        }
        .write(&mut w);
        let n = w.position();
        let req = StartKeyUpdateReq {
            tlvs: tlvs.get(..n).unwrap_or(&[]),
        };
        let relay = RelayInfo {
            parent: parent.unwrap_or(self.nwk.nib.network_address),
            joiner: device,
        };
        if self
            .zdo
            .request_via(short, cluster::SECURITY_START_KEY_UPDATE_REQ, &req, relay)
            .is_err()
        {
            return;
        }
        let deadline = self.now + self.aps.aib.security_timeout_period;
        let _ = self.dlk.joins.push(crate::dlk::PendingJoin {
            device,
            short,
            parent,
            secret,
            deadline,
        });
    }

    /// Mgmt_NWK_Update_req server processing (§2.4.3.3.9.2): channel
    /// change (0xfe), channel mask / network manager update (0xff) or an
    /// energy scan (0x00–0x05) answered with Mgmt_NWK_Update_notify.
    fn on_nwk_update_request(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        req: &MgmtNwkUpdateReq,
        broadcast: bool,
    ) {
        self.on_nwk_update_request_inner(src, seq, req, broadcast, false);
    }

    /// Mgmt_NWK_Enhanced_Update_req (§2.4.3.3.10): the single-page form
    /// follows the Mgmt_NWK_Update_req procedure; a multi-page list or
    /// an enhanced scan (no enhanced beacons on this MAC) is refused
    /// with INV_REQUESTTYPE.
    fn on_nwk_enhanced_update_request(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        req: &MgmtNwkEnhancedUpdateReq,
        broadcast: bool,
    ) {
        // §2.4.3.3.9.2 over a Channel List Structure: this device has a
        // single 2.4 GHz interface, so only the page 0 entry can be acted
        // on; the multi-page rules of steps 3b, 4c and 5c apply.
        let page0 = req
            .channels
            .pages
            .iter()
            .find(|m| m.page().0 == 0)
            .copied()
            .unwrap_or(ChannelMask(0));
        let refuse = |me: &mut Self| {
            if !broadcast {
                let notify = MgmtNwkUpdateNotify {
                    status: ZdpStatus::InvalidRequestType,
                    scanned_channels: req.channels.first().unwrap_or(ChannelMask(0)),
                    total_transmissions: 0,
                    transmission_failures: 0,
                    energy: &[],
                };
                me.zdo.nwk_enhanced_update_notify(src, seq, &notify);
            }
        };
        let total_channels: u32 = req
            .channels
            .pages
            .iter()
            .map(|m| m.channels_only().len())
            .sum();
        match req.scan_duration {
            MgmtNwkUpdateReq::CHANNEL_CHANGE => {
                // Step 3b: exactly one channel across the pages, on a
                // supported page (3c).
                if total_channels != 1 || page0.channels_only().is_empty() {
                    refuse(self);
                    return;
                }
            }
            MgmtNwkUpdateReq::ATTRIBUTE_CHANGE => {
                // Step 4c: the whole list becomes apsChannelMaskList.
                let Some(manager) = req.manager else {
                    refuse(self);
                    return;
                };
                if !self.aps.aib.is_distributed() && manager != ShortAddress::COORDINATOR {
                    return;
                }
                self.aps.aib.set_channel_mask_list(&req.channels.pages);
                self.nwk.nib.manager_addr = manager;
                let _ = self.persist_nib();
                let _ = self.persist_link_keys();
                return;
            }
            0x00..=0x05 => {
                // Step 5c: a single page; 5b: one this device supports.
                if req.channels.pages.len() != 1 || page0.channels_only().is_empty() {
                    if !broadcast {
                        refuse(self);
                    }
                    return;
                }
            }
            _ => {
                refuse(self);
                return;
            }
        }
        let update = MgmtNwkUpdateReq {
            scan_channels: page0,
            scan_duration: req.scan_duration,
            scan_count: req.scan_count,
            update_id: req.update_id,
            manager: req.manager,
        };
        self.on_nwk_update_request_inner(src, seq, &update, broadcast, true);
    }

    /// Mgmt_NWK_Beacon_Survey_req (§2.4.3.3.12.3): a coordinator refuses
    /// (NOT_PERMITTED), an enhanced scan is unsupported
    /// (INV_REQUESTTYPE), otherwise an active scan over the requested
    /// channels runs and the response follows the discovery confirm.
    fn on_beacon_survey_request(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        req: &MgmtNwkBeaconSurveyReq,
    ) {
        let fail = |me: &mut Self, status: ZdpStatus| {
            me.zdo
                .beacon_survey_rsp(src, seq, &MgmtNwkBeaconSurveyRsp::failure(status));
        };
        if self.config.role == LogicalDeviceType::Coordinator {
            fail(self, ZdpStatus::NotPermitted);
            return;
        }
        let channels = req
            .channels
            .first()
            .map(|m| m.channels_only().and(ChannelMask::ALL_2_4GHZ))
            .unwrap_or(ChannelMask(0));
        if channels.is_empty() || req.channels.pages.len() != 1 {
            fail(self, ZdpStatus::InvalidRequestType);
            return;
        }
        // The configuration bitmask picks an enhanced or a legacy
        // active scan (Annex D enhanced beacons either way).
        if self.beacon_survey.is_some()
            || !matches!(self.phase, Phase::Operating | Phase::Idle)
            || self
                .nwk
                .network_discovery_with(
                    channels,
                    self.config.scan_duration,
                    false,
                    Some(req.enhanced()),
                )
                .is_err()
        {
            fail(self, ZdpStatus::TemporaryFailure);
            return;
        }
        self.beacon_survey = Some(BeaconSurveyRequest { src, seq });
    }

    /// The discovery scan of a beacon survey finished: build the
    /// Beacon Survey Results, Potential Parents and PAN ID Conflict
    /// Report TLVs (§2.4.3.3.12.3 steps 9–11).
    fn on_beacon_survey_confirm(&mut self) {
        let Some(pending) = self.beacon_survey.take() else {
            return;
        };
        let counts = self.nwk.survey_counts();
        let is_end_device = self.config.role == LogicalDeviceType::EndDevice;
        let parent = if is_end_device {
            self.nwk.nib.parent_address
        } else {
            ShortAddress(0xFFFF)
        };
        let mut current_lqa = 0;
        let mut others: Vec<(ShortAddress, u8), 5> = Vec::new();
        // Potential parents: the on-network candidates with end device
        // capacity, best link first (§3.6.1.5.2 ordering by LQA).
        let mut candidates: Vec<(ShortAddress, u8), { panweave_nwk::layer::DISCOVERY_TABLE_SIZE }> =
            Vec::new();
        for c in self.nwk.discovery().iter() {
            if c.extended_pan_id != self.nwk.nib.extended_pan_id {
                continue;
            }
            if is_end_device && c.short == parent {
                current_lqa = c.lqa;
                continue;
            }
            if c.end_device_capacity {
                let _ = candidates.push((c.short, c.lqa));
            }
        }
        candidates.sort_unstable_by_key(|c| core::cmp::Reverse(c.1));
        for c in candidates.iter().take(5) {
            let _ = others.push(*c);
        }
        if is_end_device && current_lqa == 0 {
            current_lqa = self
                .nwk
                .neighbors
                .by_short(parent)
                .map_or(0, |n| n.lqa.value());
        }
        let rsp = MgmtNwkBeaconSurveyRsp {
            status: ZdpStatus::Success,
            results: BeaconSurveyResults {
                total: counts.total,
                on_network: counts.on_network,
                potential_parents: counts.potential_parents,
                other_networks: counts.other_networks,
            },
            parents: PotentialParents {
                current: parent,
                current_lqa,
                others,
            },
            pan_id_conflicts: (!is_end_device).then_some(self.nwk.nib.pan_id_conflict_count),
        };
        self.zdo.beacon_survey_rsp(pending.src, pending.seq, &rsp);
    }

    fn on_nwk_update_request_inner(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        req: &MgmtNwkUpdateReq,
        broadcast: bool,
        enhanced: bool,
    ) {
        let channels = req.scan_channels.channels_only();
        let supported = channels.and(ChannelMask::ALL_2_4GHZ);
        let error = |me: &mut Self, status: ZdpStatus| {
            // Error Response procedure (§2.4.3.3.9.3).
            if !broadcast {
                let notify = MgmtNwkUpdateNotify {
                    status,
                    scanned_channels: req.scan_channels,
                    total_transmissions: 0,
                    transmission_failures: 0,
                    energy: &[],
                };
                if enhanced {
                    me.zdo.nwk_enhanced_update_notify(src, seq, &notify);
                } else {
                    me.zdo.nwk_update_notify(src, seq, &notify);
                }
            }
        };
        match req.scan_duration {
            0xfe => {
                let next = self.nwk.nib.next_channel_change.channels_only();
                if !next.is_empty() && next != channels {
                    error(self, ZdpStatus::NotAuthorized);
                    return;
                }
                if channels.len() != 1 {
                    error(self, ZdpStatus::InvalidRequestType);
                    return;
                }
                let Some(channel) = supported.first() else {
                    error(self, ZdpStatus::InvalidRequestType);
                    return;
                };
                let update_id = req.update_id.unwrap_or(self.nwk.nib.update_id);
                self.nwk.change_channel(channel, update_id);
            }
            0xff => {
                let Some(manager) = req.manager else {
                    error(self, ZdpStatus::InvalidRequestType);
                    return;
                };
                // On a centralized network the network manager is the
                // coordinator (step 4a).
                if !self.aps.aib.is_distributed() && manager != ShortAddress::COORDINATOR {
                    return;
                }
                self.aps.aib.channel_mask = req.scan_channels;
                self.nwk.nib.manager_addr = manager;
                let _ = self.persist_nib();
            }
            0x00..=0x05 => {
                if broadcast {
                    return;
                }
                if supported.is_empty() {
                    error(self, ZdpStatus::InvalidRequestType);
                    return;
                }
                let count = req.scan_count.unwrap_or(1).max(1);
                if self.nwk.energy_scan(supported, req.scan_duration).is_err() {
                    error(self, ZdpStatus::TemporaryFailure);
                    return;
                }
                self.energy_scan = Some(EnergyScanRequest {
                    src,
                    seq,
                    channels: supported,
                    duration: req.scan_duration,
                    remaining: count - 1,
                    enhanced,
                });
            }
            _ => error(self, ZdpStatus::InvalidRequestType),
        }
    }

    /// NLME-ED-SCAN.confirm for a Mgmt_NWK_Update_req: report the energy
    /// values and run the remaining scans of the ScanCount.
    fn on_energy_scan_confirm(&mut self, channels: ChannelMask, energy: &[u8; 27]) {
        let Some(mut pending) = self.energy_scan.take() else {
            return;
        };
        let mut values: Vec<u8, 27> = Vec::new();
        for c in channels.iter() {
            let _ = values.push(*energy.get(usize::from(c.raw())).unwrap_or(&0xff));
        }
        let notify = MgmtNwkUpdateNotify {
            status: ZdpStatus::Success,
            scanned_channels: channels,
            total_transmissions: self.nwk.nib.tx_total,
            transmission_failures: self.nwk.nib.tx_failures,
            energy: &values,
        };
        if pending.enhanced {
            self.zdo
                .nwk_enhanced_update_notify(pending.src, pending.seq, &notify);
        } else {
            self.zdo
                .nwk_update_notify(pending.src, pending.seq, &notify);
        }
        if pending.remaining > 0
            && self
                .nwk
                .energy_scan(pending.channels, pending.duration)
                .is_ok()
        {
            pending.remaining -= 1;
            self.energy_scan = Some(pending);
        }
    }

    /// A child left this router (§4.6.3.6.2): a router on a centralized
    /// network reports a departure without rejoin to the Trust Center
    /// with Update Device (Device Left); the application is told.
    fn report_child_left(
        &mut self,
        ieee: ExtendedAddress,
        short: Option<ShortAddress>,
        rejoin: bool,
    ) {
        if !rejoin
            && !self.aps.config.is_trust_center
            && !self.aps.aib.is_distributed()
            && let Some(s) = short
        {
            let tc_short = AddrView(&self.nwk)
                .short_of(self.aps.aib.trust_center_address)
                .unwrap_or(ShortAddress::COORDINATOR);
            let _ = self
                .aps
                .update_device(tc_short, ieee, s, UpdateDeviceStatus::DeviceLeft, &[]);
        }
        if let Some(s) = short {
            self.fragmentation.forget(s);
        }
        self.push_event(StackEvent::DeviceLeft { ieee, rejoin });
    }

    /// Initiates an APS frame counter challenge to `partner`
    /// (§4.6.3.8.1), at most one per `apsChallengePeriodTimeoutSeconds`.
    fn issue_challenge(&mut self, partner: ExtendedAddress) {
        if let Some(c) = self.challenge
            && c.target == partner
            && !self.now.has_reached(c.deadline)
        {
            return;
        }
        let Some(short) = AddrView(&self.nwk).short_of(partner) else {
            return;
        };
        let mut v = [0u8; 8];
        self.nwk.rng().fill_bytes(&mut v);
        let value = u64::from_le_bytes(v);
        let mut tlvs = [0u8; 18];
        let mut w = panweave_codec::Writer::new(&mut tlvs);
        let ch = FrameCounterChallenge {
            sender: self.config.ieee,
            challenge: value,
        };
        if ch.write(&mut w).is_err() {
            return;
        }
        let req = ChallengeReq { tlvs: &tlvs };
        if self
            .zdo
            .request(short, cluster::SECURITY_CHALLENGE_REQ, &req)
            .is_err()
        {
            return;
        }
        let period = Duration::from_secs(u64::from(self.aps.aib.challenge_period_timeout_secs));
        self.challenge = Some(Challenge {
            target: partner,
            value,
            deadline: self.now + period,
        });
    }

    /// Security_Challenge_rsp (§4.6.3.8.5): validates the MIC and marks
    /// the partner's frame counter verified.
    fn on_challenge_response(&mut self, data: &[u8]) {
        let Some(c) = self.challenge else { return };
        let Ok(rsp) = ChallengeRsp::decode_exact(data) else {
            return;
        };
        if rsp.status != ZdpStatus::Success {
            return;
        }
        let Some(r) = panweave_zdo::security::validate(rsp.tlvs)
            .ok()
            .and_then(|set| FrameCounterResponse::find(&set))
        else {
            return;
        };
        if r.responder != c.target || r.challenge != c.value {
            return;
        }
        if self.aps.security.validate_challenge(
            c.target,
            c.value,
            r.aps_frame_counter,
            r.challenge_frame_counter,
            &r.mic,
        ) {
            self.challenge = None;
            self.aps.request_link_key_persistence();
            self.push_event(StackEvent::FrameCounterSynchronized { partner: c.target });
        }
    }

    /// Security_Retrieve_Authentication_Token_rsp (§2.4.4.4.2.2): store
    /// the passphrase handed out by the Trust Center once.
    fn on_authentication_token(
        &mut self,
        src_ieee: Option<ExtendedAddress>,
        security: SecurityStatus,
        data: &[u8],
    ) {
        let tc = self.aps.aib.trust_center_address;
        if security != SecurityStatus::LinkKey || src_ieee != Some(tc) {
            return;
        }
        let Ok(rsp) = RetrieveAuthenticationTokenRsp::decode_exact(data) else {
            return;
        };
        if rsp.status != ZdpStatus::Success {
            return;
        }
        let Some(token) = TlvSet::validate(rsp.tlvs, |_| false)
            .ok()
            .and_then(|set| set.symmetric_passphrase())
        else {
            return;
        };
        if let Some(e) = self.aps.security.keys_mut().get_mut(tc)
            && e.passphrase_update_allowed
        {
            e.passphrase = Some(Key128::from_bytes(token.value));
            e.passphrase_update_allowed = false;
            self.aps.request_link_key_persistence();
            self.push_event(StackEvent::AuthenticationTokenStored);
        }
    }

    pub(crate) fn send_network_key(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        route: KeyRoute,
    ) {
        let seq = self.network_key_sequence;
        let Some(key) = self.nwk.security.keys.get(seq).map(|s| s.key.clone()) else {
            return;
        };
        if let Ok(request) = self.aps.transport_network_key(device, &key, seq, route) {
            let _ = self.pending_children.push(PendingChild {
                ieee: device,
                short,
                request,
            });
        }
    }

    // ---------------------------------------------------------------
    // APS → NWK / storage
    // ---------------------------------------------------------------

    fn pump_aps_actions(&mut self) -> bool {
        let mut any = false;
        while let Some(a) = self.aps.next_action() {
            any = true;
            match a {
                ApsAction::NwkData {
                    handle,
                    dst,
                    radius,
                    discover_route,
                    secure,
                    alias,
                    frame,
                } => match self.nwk.data_request_aliased(
                    dst,
                    &frame,
                    radius,
                    discover_route,
                    secure,
                    alias,
                ) {
                    Ok(id) => {
                        self.schedule_fast_polls();
                        if self.aps_handles.push((id, handle)).is_err() {
                            self.aps
                                .on_nwk_data_confirm(handle, NwkStatus::FrameNotBuffered);
                        }
                    }
                    Err(_) => self
                        .aps
                        .on_nwk_data_confirm(handle, NwkStatus::InvalidRequest),
                },
                ApsAction::CounterReservation {
                    partner,
                    reservation,
                } => {
                    let ok = self
                        .storage
                        .store(
                            Key::with_id(Kind::ApsFrameCounter, partner.0),
                            &reservation.reserved_until.to_le_bytes(),
                        )
                        .is_ok();
                    if ok {
                        self.aps.commit_counter_reservation(partner, reservation);
                    }
                }
                ApsAction::Persist(item) => {
                    // R23.2 §2.2.8.1, §4.4.12.
                    let _ = match item {
                        PersistItem::LinkKeys | PersistItem::Aib => self.persist_link_keys(),
                        PersistItem::Bindings => self.persist_bindings(),
                        PersistItem::Groups => self.persist_groups(),
                    };
                }
            }
        }
        any
    }

    // ---------------------------------------------------------------
    // APS events → stack logic
    // ---------------------------------------------------------------

    fn pump_aps_events(&mut self) -> bool {
        let mut any = false;
        while let Some(e) = self.aps.next_event() {
            any = true;
            match e {
                ApsEvent::DataConfirm { .. } => {}
                ApsEvent::CommandConfirm { id, status, .. } => {
                    if let Some(i) = self.pending_children.iter().position(|p| p.request == id) {
                        let child = self.pending_children.swap_remove(i);
                        if status.is_success() {
                            self.nwk.authenticate_child(child.ieee);
                            self.push_event(StackEvent::DeviceAuthorized {
                                ieee: child.ieee,
                                short: child.short,
                            });
                        }
                    }
                }
                ApsEvent::TransportKey {
                    key, authorizes, ..
                } => match key {
                    TransportedKey::Network {
                        key,
                        sequence,
                        source,
                        broadcast,
                    } => {
                        if authorizes {
                            self.network_key_sequence = sequence;
                            self.nwk.set_network_key(sequence, key, true);
                            let rejoin = matches!(self.phase, Phase::Joining(m) if m != crate::JoinMode::Association)
                                || (self.phase == Phase::AwaitingKey && self.awaiting_key_rejoin);
                            self.awaiting_key_rejoin = false;
                            self.complete_join(rejoin);
                        } else {
                            self.nwk.set_network_key(sequence, key.clone(), false);
                            if broadcast && self.nwk.nib.is_router_or_coordinator() {
                                self.relay_network_key_to_sleepy_children(&key, sequence, source);
                            }
                        }
                    }
                    TransportedKey::TrustCenterLink { source } => {
                        let tc_short = AddrView(&self.nwk)
                            .short_of(source)
                            .unwrap_or(ShortAddress::COORDINATOR);
                        let _ = self
                            .aps
                            .verify_key(source, tc_short, KeyType::TrustCenterLinkKey);
                    }
                    TransportedKey::ApplicationLink { partner, initiator } => {
                        self.push_event(StackEvent::ApplicationLinkKey { partner, initiator });
                    }
                    TransportedKey::BasicAuthorization {
                        key,
                        sequence,
                        source,
                    } => {
                        // This stack is not a ZVD; a host running one on
                        // top of it gets the key for its session layer.
                        self.push_event(StackEvent::BasicAuthorizationKey {
                            key,
                            sequence,
                            source,
                        });
                    }
                },
                ApsEvent::SwitchKey { sequence, .. } => {
                    if self.nwk.switch_network_key(sequence) {
                        self.network_key_sequence = sequence;
                    }
                }
                ApsEvent::UpdateDevice {
                    src,
                    device,
                    short,
                    status,
                    joiner_tlvs,
                    ..
                } => {
                    #[cfg(feature = "green-power")]
                    self.on_green_power_announce(device, short);
                    self.trust_center_authorize(device, short, status, Some(src), &joiner_tlvs);
                }
                ApsEvent::RemoveDevice { target, .. } => {
                    // §4.6.3.6.2: ourselves, or one of our children;
                    // anything else is discarded by the NWK layer.
                    if target == self.config.ieee {
                        let _ = self.nwk.leave(None, false, false);
                    } else {
                        let _ = self.nwk.leave(Some(target), false, false);
                    }
                }
                ApsEvent::RequestKey {
                    src,
                    src_short,
                    key_type,
                    partner,
                } => {
                    if key_type == RequestKeyType::ApplicationLinkKey {
                        if let Some(partner) = partner {
                            self.on_application_key_request(src, src_short, partner);
                        }
                    } else if key_type == RequestKeyType::TrustCenterLinkKey
                        && self.config.trust_center_policy.tclk_requests != TclkRequestPolicy::Never
                    {
                        let mut k = [0u8; 16];
                        self.nwk.rng().fill_bytes(&mut k);
                        // Link-Key Features & Capabilities: this Trust
                        // Center synchronizes frame counters (§4.6.3.8).
                        let mut features = [0u8; 3];
                        let mut w = panweave_codec::Writer::new(&mut features);
                        let _ = panweave_aps::command::write_link_key_features(
                            &mut w,
                            panweave_aps::command::LINK_KEY_FEATURE_FRAME_COUNTER_SYNC,
                        );
                        let _ = self.aps.transport_trust_center_link_key(
                            src,
                            src_short,
                            &Key128::from_bytes(k),
                            &features,
                        );
                    }
                }
                ApsEvent::FrameCounterUnverified { partner } => {
                    self.issue_challenge(partner);
                }
                ApsEvent::StaleKeyUsed { partner } => {
                    self.push_event(StackEvent::StaleLinkKeyUsed { ieee: partner });
                }
                ApsEvent::TrustCenterSwapped { old, new } => {
                    // The new Trust Center answers at the coordinator
                    // address; the old identity is forgotten.
                    self.nwk.address_map.remove_extended(old);
                    let _ = self.nwk.address_map.record(new, ShortAddress::COORDINATOR);
                    self.swap_out_pending = true;
                    self.push_event(StackEvent::TrustCenterSwapped { old, new });
                }
                ApsEvent::KeyVerified {
                    partner, relayed, ..
                } => {
                    if self.aps.config.is_trust_center {
                        self.on_joiner_key_verified(partner, relayed);
                    }
                }
                ApsEvent::ConfirmKey { src, status, .. } => {
                    let ok = status == ApsStatus::Success;
                    if self.dlk.session.as_ref().is_some_and(|s| s.partner == src) {
                        self.on_key_negotiation_confirmed(src, ok);
                    } else if ok {
                        self.push_event(StackEvent::LinkKeyUpdated);
                    }
                }
            }
        }
        any
    }

    /// Rejoin after losing the parent, paced by `:Config_Rejoin_Interval`
    /// (§2.5.5.5.6.x): starts now when the interval since the last
    /// attempt has passed, otherwise when it will have.
    pub(crate) fn start_parent_loss_rejoin(&mut self) {
        let interval = Duration::from_secs(u64::from(self.rejoin_interval_secs.max(1)));
        let earliest = self
            .last_rejoin_attempt
            .map_or(self.now, |t| t.saturating_add(interval));
        if self.now.has_reached(earliest) {
            self.next_poll = None;
            self.last_rejoin_attempt = Some(self.now);
            self.parent_loss_rejoin = true;
            let _ = self.join(crate::JoinMode::SecuredRejoin);
        } else {
            self.rejoin_due = Some(earliest);
        }
    }

    /// The paced rejoin is due.
    pub(crate) fn poll_parent_loss_rejoin(&mut self, now: Instant) {
        if self.rejoin_due.is_some_and(|t| now.has_reached(t))
            && self.config.role == LogicalDeviceType::EndDevice
            && matches!(self.phase, Phase::Operating | Phase::Idle)
        {
            self.rejoin_due = None;
            self.start_parent_loss_rejoin();
        }
    }

    /// A parent-loss rejoin ended: on failure the interval grows (up to
    /// `:Config_Max_Rejoin_Interval`) and the next attempt is scheduled;
    /// on success it returns to `:Config_Rejoin_Interval`.
    pub(crate) fn note_parent_loss_rejoin(&mut self, success: bool) {
        if !core::mem::take(&mut self.parent_loss_rejoin) {
            return;
        }
        if success {
            self.rejoin_interval_secs = self.config.zdo.rejoin_interval_secs;
            self.rejoin_due = None;
        } else {
            self.rejoin_interval_secs = self
                .rejoin_interval_secs
                .saturating_mul(2)
                .min(self.config.zdo.max_rejoin_interval_secs)
                .max(self.config.zdo.rejoin_interval_secs);
            self.rejoin_due = self.last_rejoin_attempt.map(|t| {
                t.saturating_add(Duration::from_secs(u64::from(self.rejoin_interval_secs)))
            });
        }
    }

    /// Arms `apsParentAnnounceTimer` (§2.4.3.1.12.1): base timer plus a
    /// random jitter; `covered` end device children were already
    /// announced by earlier messages.
    pub(crate) fn schedule_parent_annce(&mut self, covered: usize) {
        let jitter_ms =
            u64::from(self.nwk.rng().below(
                u32::try_from(PARENT_ANNOUNCE_JITTER_MAX.as_millis() + 1).unwrap_or(u32::MAX),
            ));
        let at = self
            .now
            .saturating_add(PARENT_ANNOUNCE_BASE_TIMER)
            .saturating_add(Duration::from_millis(jitter_ms));
        self.parent_annce = Some((at, covered));
    }

    /// Sends the Parent_annce(s) due (§2.4.3.1.12.1): every end device
    /// child of the neighbor table, as many messages as needed with a
    /// fresh timer before each; nothing when there are no children.
    pub(crate) fn poll_parent_annce(&mut self, now: Instant) {
        let Some((at, covered)) = self.parent_annce else {
            return;
        };
        if !now.has_reached(at) {
            return;
        }
        self.parent_annce = None;
        let children: Vec<ExtendedAddress, 32> = self
            .nwk
            .neighbors
            .end_device_children()
            .map(|n| n.extended)
            .collect();
        let Some(rest) = children.get(covered..).filter(|r| !r.is_empty()) else {
            return;
        };
        match self.zdo.parent_announce(rest) {
            Ok(n) if covered + n < children.len() => self.schedule_parent_annce(covered + n),
            _ => {}
        }
    }

    /// Parent_annce_rsp (§2.4.4.2.12): the responding router has the
    /// listed end devices as its children now; they leave our neighbor
    /// table.
    fn on_parent_annce_rsp(&mut self, src: ShortAddress, data: &[u8]) {
        let Ok(rsp) = ParentAnnceRsp::decode_exact(data) else {
            return;
        };
        if !rsp.status.is_success() {
            return;
        }
        let mut removed = false;
        for child in rsp.children.iter() {
            if self.nwk.neighbors.remove_extended(child).is_some() {
                removed = true;
                self.nwk.stats.children_moved = self.nwk.stats.children_moved.saturating_add(1);
                self.push_event(StackEvent::ChildClaimed {
                    ieee: child,
                    by: src,
                });
            }
        }
        if removed {
            let _ = self.persist_children();
        }
    }

    /// On-Network TCLK Update procedure, step 1 (BDB 3.1 §10.2.4): ask
    /// the Trust Center for its node descriptor, offering our key
    /// negotiation methods, and wait `apsSecurityTimeOutPeriod` for the
    /// answer that says how (or whether) the link key is updated.
    pub(crate) fn start_tclk_update(&mut self, tc: ExtendedAddress) {
        let tc_short = AddrView(&self.nwk)
            .short_of(tc)
            .unwrap_or(ShortAddress::COORDINATOR);
        let mut tlvs = [0u8; 16];
        let n = {
            let mut w = panweave_codec::Writer::new(&mut tlvs);
            let ok = SupportedKeyNegotiationMethods {
                protocols: self.aps.aib.supported_key_negotiation_methods,
                secrets: SupportedKeyNegotiationMethods::SECRET_AUTH_TOKEN
                    | SupportedKeyNegotiationMethods::SECRET_INSTALL_CODE,
                source: Some(self.config.ieee),
            }
            .write(&mut w)
            .is_ok();
            if ok { w.position() } else { 0 }
        };
        let req = NodeDescReq {
            addr: tc_short,
            tlvs: tlvs.get(..n).unwrap_or(&[]),
        };
        if self
            .zdo
            .request(tc_short, cluster::NODE_DESC_REQ, &req)
            .is_ok()
        {
            self.tclk_update = Some(self.now + self.aps.aib.security_timeout_period);
        } else {
            // Cannot even ask: fall back to the symmetric exchange.
            let _ = self
                .aps
                .request_key(tc_short, RequestKeyType::TrustCenterLinkKey, None);
        }
    }

    /// On-Network TCLK Update procedure, steps 3–5 (BDB 3.1 §10.2.4):
    /// the Trust Center's node descriptor decides. Below revision 21
    /// there is no update; below 23, or when the Trust Center selected
    /// the Zigbee 3.0 mechanism (or nothing), the symmetric Request Key
    /// / Verify Key exchange runs; otherwise the selected key
    /// negotiation runs with the pre-shared secret it names, falling
    /// back to the symmetric exchange when this device holds no such
    /// secret.
    fn on_tclk_update_descriptor(&mut self, data: &[u8]) {
        let Ok(rsp) = NodeDescRsp::decode_exact(data) else {
            return;
        };
        let Some(descriptor) = rsp.descriptor.filter(|_| rsp.status.is_success()) else {
            return;
        };
        self.tclk_update = None;
        let tc = self.aps.aib.trust_center_address;
        let tc_short = AddrView(&self.nwk)
            .short_of(tc)
            .unwrap_or(ShortAddress::COORDINATOR);
        let revision = descriptor.server_mask.stack_compliance_revision();
        if revision < 21 {
            self.push_event(StackEvent::LinkKeyUpdateSkipped { revision });
            return;
        }
        let selected = panweave_zdo::security::validate(rsp.tlvs)
            .ok()
            .and_then(|set| SelectedKeyNegotiationMethod::find(&set))
            .filter(|m| m.protocol != SelectedKeyNegotiationMethod::PROTOCOL_ZIGBEE_3_0);
        if revision >= 23
            && let Some(method) = selected
            && crate::dlk::passphrase_for(self.aps.security.entry(tc), method.secret).is_some()
            && self.start_key_negotiation(tc, method, None).is_ok()
        {
            return;
        }
        let _ = self
            .aps
            .request_key(tc_short, RequestKeyType::TrustCenterLinkKey, None);
    }

    /// §4.4.2.3 last paragraph: a router that received the Trust
    /// Center's broadcast network key update unicasts it to each of its
    /// rx-off children (held by the MAC until they poll).
    pub(crate) fn relay_network_key_to_sleepy_children(
        &mut self,
        key: &Key128,
        sequence: KeySequenceNumber,
        trust_center: ExtendedAddress,
    ) {
        let children: Vec<(ExtendedAddress, ShortAddress), 16> = self
            .nwk
            .neighbors
            .end_device_children()
            .filter(|n| !n.rx_on_when_idle)
            .map(|n| (n.extended, n.short))
            .collect();
        for (ieee, short) in children {
            let _ = self
                .aps
                .relay_network_key_to_child(ieee, short, key, sequence, trust_center);
        }
    }

    /// A Request Key for an application link key at the Trust Center
    /// (§4.7.3.9, BDB 3.1 §7.4): when the policy allows it and both
    /// devices are known, a fresh key is transported to the initiator
    /// and the partner under their Trust Center link keys (initiator
    /// flag set for the requester).
    fn on_application_key_request(
        &mut self,
        initiator: ExtendedAddress,
        initiator_short: ShortAddress,
        partner: ExtendedAddress,
    ) {
        if !self.aps.config.is_trust_center {
            return;
        }
        let listed = self
            .application_key_request_list
            .iter()
            .any(|(a, b)| (*a == initiator && *b == partner) || (*a == partner && *b == initiator));
        let allowed = self.config.trust_center_policy.allow_app_key_request(
            initiator,
            partner,
            self.aps.security.entry(initiator),
            listed,
        );
        if !allowed {
            return;
        }
        // The partner must itself hold a verified Trust Center link key
        // and be reachable by network address.
        if self
            .aps
            .security
            .entry(partner)
            .is_none_or(|e| e.attributes != panweave_types::KeyAttributes::VerifiedKey)
        {
            return;
        }
        let Some(partner_short) = AddrView(&self.nwk).short_of(partner) else {
            return;
        };
        let mut k = [0u8; 16];
        self.nwk.rng().fill_bytes(&mut k);
        let key = Key128::from_bytes(k);
        let _ = self.aps.transport_application_link_key(
            initiator,
            initiator_short,
            partner,
            &key,
            true,
        );
        let _ =
            self.aps
                .transport_application_link_key(partner, partner_short, initiator, &key, false);
    }

    // ---------------------------------------------------------------
    // ZDO / ZCL → APS
    // ---------------------------------------------------------------

    fn send_aps(
        &mut self,
        destination: Destination,
        profile: ProfileId,
        cluster: panweave_types::ClusterId,
        src_endpoint: Endpoint,
        asdu: &[u8],
        options: TxOptions,
    ) {
        if self.send_with_fragmentation_check(
            destination,
            profile,
            cluster,
            src_endpoint,
            asdu,
            options,
        ) {
            return;
        }
        let req = DataRequest {
            destination,
            profile,
            cluster,
            src_endpoint,
            asdu,
            options,
            radius: None,
            alias: None,
        };
        let view = AddrView(&self.nwk);
        let _ = self.aps.data_request(&req, &view);
    }

    fn pump_zdo(&mut self) -> bool {
        let mut any = false;
        while let Some(a) = self.zdo.next_action() {
            any = true;
            let ZdoAction::Send {
                dst,
                cluster,
                frame,
                via,
                secure,
            } = a;
            let destination = match via {
                Some(r) => Destination::Relayed {
                    parent: r.parent,
                    joiner: if self.aps.config.is_trust_center {
                        Some(r.joiner)
                    } else {
                        None
                    },
                    endpoint: Endpoint(0),
                },
                None => Destination::Short {
                    address: dst,
                    endpoint: Endpoint(0),
                },
            };
            let options = TxOptions {
                ack: dst.is_unicast(),
                security: secure,
                ..TxOptions::ACKED
            };
            self.send_aps(
                destination,
                ProfileId::ZDP,
                cluster,
                Endpoint(0),
                &frame,
                options,
            );
        }
        while let Some(e) = self.zdo.next_event() {
            any = true;
            match e {
                ZdoEvent::Timeout { seq, cluster, dst } => {
                    self.push_event(StackEvent::ZdpTimeout { seq, cluster, dst });
                }
                ZdoEvent::NwkUpdateRequest {
                    src,
                    seq,
                    req,
                    broadcast,
                } => {
                    self.on_nwk_update_request(src, seq, &req, broadcast);
                }
                ZdoEvent::NwkEnhancedUpdateRequest {
                    src,
                    seq,
                    req,
                    broadcast,
                } => {
                    self.on_nwk_enhanced_update_request(src, seq, &req, broadcast);
                }
                ZdoEvent::BeaconSurveyRequest { src, seq, req } => {
                    self.on_beacon_survey_request(src, seq, &req);
                }
                ZdoEvent::InterferenceReport { src, notify } => {
                    let channel = notify
                        .channel_in_use
                        .channels_only()
                        .first()
                        .unwrap_or(self.nwk.nib.channel);
                    self.push_event(StackEvent::InterferenceReport {
                        src,
                        channel,
                        tx_total: notify.tx_total,
                        tx_failures: notify.tx_failures,
                        tx_retries: notify.tx_retries,
                        period_minutes: notify.period_minutes,
                    });
                }
                ZdoEvent::JoiningListUpdated => {
                    self.push_event(StackEvent::JoiningListUpdated);
                }
            }
        }
        any
    }

    fn pump_zcl_actions(&mut self) -> bool {
        let mut any = false;
        while let Some(a) = self.zcl.next_action() {
            any = true;
            let ZclAction::Send {
                destination,
                profile,
                cluster,
                src_endpoint,
                frame,
                options,
            } = a;
            self.send_aps(destination, profile, cluster, src_endpoint, &frame, options);
        }
        while let Some(e) = self.zcl.next_event() {
            any = true;
            if let ZclEvent::StartupSetsChanged { endpoint } = e {
                let _ = self.persist_startup_sets(endpoint);
                self.push_event(StackEvent::StartupSetsChanged { endpoint });
                continue;
            }
            if let ZclEvent::Restart {
                endpoint,
                install,
                delay,
                jitter,
                ..
            } = e
            {
                // §13.2.2.3.1: after the delay plus RAND(jitter × 80) ms
                // the stack restarts from the current startup set
                // (installing it) or with its running configuration.
                let jitter_ms = u64::from(self.nwk.rng().below(u32::from(jitter) * 80 + 1));
                let at = self.now
                    + Duration::from_secs(u64::from(delay))
                    + Duration::from_millis(jitter_ms);
                self.pending_restart = Some((at, endpoint, install));
            }
            self.push_event(match e {
                ZclEvent::Identify { endpoint, seconds } => {
                    StackEvent::Identify { endpoint, seconds }
                }
                ZclEvent::TriggerEffect {
                    endpoint,
                    effect,
                    variant,
                } => StackEvent::TriggerEffect {
                    endpoint,
                    effect,
                    variant,
                },
                ZclEvent::OnOff { endpoint, on } => StackEvent::OnOff { endpoint, on },
                ZclEvent::OffWithEffect {
                    endpoint,
                    effect,
                    variant,
                } => StackEvent::OffWithEffect {
                    endpoint,
                    effect,
                    variant,
                },
                ZclEvent::Level {
                    endpoint,
                    level,
                    done,
                } => StackEvent::Level {
                    endpoint,
                    level,
                    done,
                },
                ZclEvent::SceneRecalled {
                    endpoint,
                    group,
                    scene,
                } => StackEvent::SceneRecalled {
                    endpoint,
                    group,
                    scene,
                },
                ZclEvent::CheckIn {
                    endpoint,
                    src,
                    src_endpoint,
                } => StackEvent::CheckIn {
                    endpoint,
                    src,
                    src_endpoint,
                },
                ZclEvent::FactoryReset => StackEvent::FactoryReset,
                ZclEvent::AlarmReset { endpoint, alarm } => {
                    StackEvent::AlarmReset { endpoint, alarm }
                }
                ZclEvent::TimeSet { endpoint, utc } => StackEvent::TimeSet { endpoint, utc },
                ZclEvent::ZoneEnrolled { endpoint, zone_id } => {
                    StackEvent::ZoneEnrolled { endpoint, zone_id }
                }
                ZclEvent::ZoneTestMode { endpoint, seconds } => {
                    StackEvent::ZoneTestMode { endpoint, seconds }
                }
                ZclEvent::WindowCovering { endpoint, command } => {
                    StackEvent::WindowCovering { endpoint, command }
                }
                ZclEvent::DoorLock {
                    endpoint,
                    action,
                    user,
                } => StackEvent::DoorLock {
                    endpoint,
                    action,
                    user,
                },
                ZclEvent::Ace { endpoint, request } => StackEvent::Ace { endpoint, request },
                ZclEvent::Restart {
                    endpoint,
                    install,
                    immediate,
                    delay,
                    jitter,
                } => StackEvent::Restart {
                    endpoint,
                    install,
                    immediate,
                    delay,
                    jitter,
                },
                ZclEvent::Warning { endpoint, warning } => {
                    StackEvent::Warning { endpoint, warning }
                }
                ZclEvent::Squawk { endpoint, squawk } => StackEvent::Squawk { endpoint, squawk },
                ZclEvent::Setpoints {
                    endpoint,
                    heat,
                    cool,
                } => StackEvent::Setpoints {
                    endpoint,
                    heat,
                    cool,
                },
                ZclEvent::WeeklyScheduleChanged { endpoint } => {
                    StackEvent::WeeklyScheduleChanged { endpoint }
                }
                ZclEvent::Barrier { endpoint, percent } => {
                    StackEvent::Barrier { endpoint, percent }
                }
                ZclEvent::Frequency {
                    endpoint,
                    cluster,
                    frequency,
                } => StackEvent::Frequency {
                    endpoint,
                    cluster,
                    frequency,
                },
                ZclEvent::DutyCycle {
                    endpoint,
                    percent,
                    done,
                } => StackEvent::DutyCycle {
                    endpoint,
                    percent,
                    done,
                },
                ZclEvent::StartupSetsChanged { endpoint } => {
                    StackEvent::StartupSetsChanged { endpoint }
                }
                ZclEvent::Color {
                    endpoint,
                    mode,
                    a,
                    b,
                    done,
                } => StackEvent::Color {
                    endpoint,
                    mode,
                    a,
                    b,
                    done,
                },
                ZclEvent::ApplianceCommand { endpoint, command } => {
                    StackEvent::ApplianceCommand { endpoint, command }
                }
                ZclEvent::ApplianceOverload { endpoint, overload } => {
                    StackEvent::ApplianceOverload { endpoint, overload }
                }
                ZclEvent::PowerProfilePrice {
                    endpoint,
                    price,
                    extended,
                } => StackEvent::PowerProfilePrice {
                    endpoint,
                    price,
                    extended,
                },
                ZclEvent::PowerProfileOverallPrice { endpoint, price } => {
                    StackEvent::PowerProfileOverallPrice { endpoint, price }
                }
                ZclEvent::PowerProfileScheduled { endpoint, id } => {
                    StackEvent::PowerProfileScheduled { endpoint, id }
                }
                ZclEvent::LocationRecalculate { endpoint } => {
                    StackEvent::LocationRecalculate { endpoint }
                }
                ZclEvent::AnchorNode { endpoint, announce } => {
                    StackEvent::AnchorNode { endpoint, announce }
                }
                ZclEvent::FastPoll { fast, interval, .. } => {
                    // Poll Control server: switch the MAC poll rate.
                    self.fast_poll_mode = fast.then_some(interval);
                    if self.config.sleepy {
                        self.next_poll = Some(self.now);
                    }
                    continue;
                }
                ZclEvent::LongPollInterval { interval, .. } => {
                    self.config.poll_interval = interval;
                    continue;
                }
            });
        }
        any
    }

    /// Sends a ZCL frame built by the application through the ZCL layer.
    pub fn zcl_send(
        &mut self,
        destination: Destination,
        profile: ProfileId,
        cluster: panweave_types::ClusterId,
        src_endpoint: Endpoint,
        header: &panweave_zcl::Header,
        payload: &[u8],
    ) -> Result<(), panweave_zcl::ZclError> {
        let ack = matches!(destination, Destination::Short { address, .. } if address.is_unicast());
        self.zcl.send(
            destination,
            profile,
            cluster,
            src_endpoint,
            header,
            payload,
            TxOptions {
                ack,
                ..TxOptions::ACKED
            },
        )?;
        self.pump();
        Ok(())
    }

    /// Encodes and sends a ZDP request.
    pub fn zdp_request(
        &mut self,
        dst: ShortAddress,
        cluster: panweave_types::ClusterId,
        payload: &impl Encode,
    ) -> Result<TransactionSequence, panweave_zdo::ZdoError> {
        let seq = self.zdo.request(dst, cluster, payload)?;
        self.pump();
        Ok(seq)
    }

    /// Runs the pump after direct manipulation of a layer (e.g. after
    /// calling [`Stack::permit_join`] or ZCL helpers).
    pub fn flush(&mut self) {
        self.pump();
    }
}
