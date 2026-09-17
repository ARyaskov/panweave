//! Network and device maintenance (R23.2 §3.6.1): discovery, formation,
//! permit joining, joining/rejoining (child and parent procedures),
//! leaving, address and PAN-ID conflicts.

use heapless::Vec;
use panweave_codec::tlv::TlvSet;
use panweave_mac::frame::{Beacon, MacAddress};
use panweave_mac::ie::EnhancedBeaconRequest;
use panweave_mac::service::{ScanKind, TxStatus};
use panweave_security::cipher::BlockCipher;
use panweave_types::{
    Channel, ChannelMask, ChannelPage, Duration, ExtendedAddress, Instant, Key128,
    KeySequenceNumber, LogicalDeviceType, MacCapability, MacStatus, NwkStatus, PanId, Rng,
    ShortAddress,
};

use super::rx::CommandContext;
use super::{
    DISCOVERY_TABLE_SIZE, FormationState, MAX_JOINER_TLVS, Nwk, NwkAction, NwkError, NwkEvent,
    ScanPurpose, ScanState, TxKind,
};
use crate::address_map::allocate_stochastic;

use crate::beacon::BeaconPayload;
use crate::command::{
    CommissioningRequest, CommissioningResponse, CommissioningType, Leave, NetworkReport,
    NetworkStatusCode, NetworkUpdate, NwkCommand, RejoinRequest, RejoinResponse,
};
use crate::discovery::Candidate;
use crate::frame::{FrameType, Header};
use crate::neighbor::{NeighborEntry, Relationship};
use crate::nib::constants;
use crate::tlv::{self, GlobalTlvs, RouterInformation};

/// How a device attached (NLME-JOIN.indication `JoinerMethod`, Table
/// 3-73), which maps onto the APSME-UPDATE-DEVICE status.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinMethod {
    /// MAC association (Update Device status 0x01).
    MacAssociation,
    /// Network rejoin without security (0x03, Trust Center rejoin).
    RejoinUnsecured,
    /// Secured network rejoin (0x00).
    RejoinSecured,
    /// Network commissioning initial join without security (0x01).
    CommissioningJoin,
    /// Network commissioning rejoin without security (0x03).
    CommissioningRejoinUnsecured,
    /// Secured network commissioning rejoin (0x00).
    CommissioningRejoinSecured,
}

impl JoinMethod {
    /// APSME-UPDATE-DEVICE status value (Table 3-73).
    pub const fn update_device_status(self) -> u8 {
        match self {
            JoinMethod::MacAssociation | JoinMethod::CommissioningJoin => 0x01,
            JoinMethod::RejoinUnsecured | JoinMethod::CommissioningRejoinUnsecured => 0x03,
            JoinMethod::RejoinSecured | JoinMethod::CommissioningRejoinSecured => 0x00,
        }
    }

    /// True for secured (authenticated) attaches.
    pub const fn is_secured(self) -> bool {
        matches!(
            self,
            JoinMethod::RejoinSecured | JoinMethod::CommissioningRejoinSecured
        )
    }
}

/// NLME-JOIN.request parameters.
#[derive(Clone, Copy, Debug)]
pub struct JoinParams {
    /// Extended PAN ID to join; `None` lets any discovered network qualify
    /// (the higher layer normally selects one).
    pub extended_pan_id: Option<ExtendedAddress>,
    /// Rejoin (true) or initial join (false).
    pub rejoin: bool,
    /// Join as a router.
    pub as_router: bool,
    /// Secure the rejoin request with the network key.
    pub secure: bool,
    /// Capability information.
    pub capability: MacCapability,
    /// Only consider parents that permit joining (BDB steering sets true;
    /// rejoins may set false).
    pub require_permit: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum JoinPhase {
    SelectParent,
    /// MAC association in progress (MAC reports the outcome).
    Associating,
    /// Rejoin / commissioning request handed to the MAC.
    RequestSent,
    /// Waiting for the response frame.
    AwaitingResponse {
        deadline: Instant,
        polled: bool,
    },
    /// Joined; waiting for the network key (security timer).
    AwaitingKey {
        deadline: Instant,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ParentSnapshot {
    short: ShortAddress,
    extended: Option<ExtendedAddress>,
    pan_id: PanId,
    extended_pan_id: ExtendedAddress,
    page: ChannelPage,
    channel: Channel,
    r23: bool,
    update_id: u8,
    lqa: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct JoinState {
    pub params: JoinParams,
    pub secure: bool,
    candidates: Vec<usize, DISCOVERY_TABLE_SIZE>,
    next: usize,
    /// 0 = good-LQA pass, 1 = marginal pass.
    pass: u8,
    current: Option<ParentSnapshot>,
    phase: JoinPhase,
    attempts: u8,
    used_commissioning: bool,
}

impl<
    C: BlockCipher,
    R: Rng,
    const NEIGHBORS: usize,
    const ROUTES: usize,
    const RDT: usize,
    const BTT: usize,
> Nwk<C, R, NEIGHBORS, ROUTES, RDT, BTT>
{
    // ------------------------------------------------------------------
    // Discovery (§3.6.1.5)
    // ------------------------------------------------------------------

    /// NLME-NETWORK-AND-PARENT-DISCOVERY.request: active scan over
    /// `channels`; results accumulate in the discovery table and are
    /// reported via [`NwkEvent::DiscoveryConfirm`].
    ///
    /// May transmit (beacon requests); changes channel during the scan.
    pub fn network_discovery(
        &mut self,
        channels: ChannelMask,
        duration: u8,
        only_permit_join: bool,
    ) -> Result<(), NwkError> {
        if self.scan.is_some() {
            return Err(NwkError::Busy);
        }
        // Only channels an enabled interface supports (§3.2.2.3.3).
        let channels = self.interfaces.supported_subset(channels);
        if channels.is_empty() {
            return Err(NwkError::InvalidParameter);
        }
        self.discovery.clear();
        self.survey = super::SurveyCounts::default();
        // A (re)join starts at the maximum power (§3.4.13.1, §3.6.11.1);
        // the enhanced beacon exchange may negotiate it down again.
        self.push_action(NwkAction::MacResetTxPower);
        self.scan = Some(ScanState {
            purpose: ScanPurpose::Discovery,
            channels,
            duration,
            only_permit_join,
        });
        // Annex D.11.1: a joining device filters on permit joining, a
        // rejoining one on its extended PAN ID.
        let enhanced_scan = self.config.enhanced_beacon_requests
            || self
                .interfaces
                .enabled()
                .any(|i| i.scan_type == crate::interface::ScanType::EnhancedActive);
        let enhanced = if !enhanced_scan {
            None
        } else if self.nib.extended_pan_id != ExtendedAddress::ZERO && !only_permit_join {
            Some(EnhancedBeaconRequest::rejoining(
                self.nib.extended_pan_id,
                self.nib.network_address,
                None,
            ))
        } else {
            Some(EnhancedBeaconRequest::joining(None))
        };
        self.push_action(NwkAction::MacScan {
            kind: ScanKind::Active,
            channels,
            duration,
            enhanced,
        });
        Ok(())
    }

    /// Sets `nwkNetworkWideBeaconAppendixTLVs` from the Trust Center's
    /// Beacon Appendix Encapsulation (§2.4.3.3.7.2): replaces the whole
    /// value, keeps only well-formed global TLVs that fit the beacon.
    pub fn set_network_wide_beacon_appendix(&mut self, tlvs: &[u8]) {
        self.network_wide_beacon_appendix.clear();
        if let Ok(set) = TlvSet::validate(tlvs, |_| false) {
            let mut buf = [0u8; constants::MAX_BEACON_APPENDIX];
            let mut w = panweave_codec::Writer::new(&mut buf);
            for t in set.iter() {
                if !panweave_codec::tlv::is_global_tag(t.tag) {
                    continue;
                }
                if panweave_codec::tlv::write_tlv(&mut w, t.tag, t.value).is_err() {
                    break;
                }
            }
            let n = w.position();
            let _ = self
                .network_wide_beacon_appendix
                .extend_from_slice(buf.get(..n).unwrap_or(&[]));
        }
        self.update_beacon_payload();
    }

    /// NLME-ED-SCAN.request: an energy detect scan over `channels`
    /// (§3.2.2.5); completes with [`NwkEvent::EnergyScanConfirm`].
    pub fn energy_scan(&mut self, channels: ChannelMask, duration: u8) -> Result<(), NwkError> {
        if self.scan.is_some() {
            return Err(NwkError::Busy);
        }
        let channels = self.interfaces.supported_subset(channels);
        if channels.is_empty() || duration > 5 {
            return Err(NwkError::InvalidParameter);
        }
        self.scan = Some(ScanState {
            purpose: ScanPurpose::EnergyDetect,
            channels,
            duration,
            only_permit_join: false,
        });
        self.push_action(NwkAction::MacScan {
            kind: ScanKind::Energy,
            channels,
            duration,
            enhanced: None,
        });
        Ok(())
    }

    /// Changes the logical channel on the network manager's instruction
    /// (Mgmt_NWK_Update_req with ScanDuration 0xfe, §2.4.3.3.9.2 step 3):
    /// records `update_id`, switches the MAC and persists the NIB.
    pub fn change_channel(&mut self, channel: Channel, update_id: u8) {
        self.nib.channel = channel;
        self.note_channel_in_use();
        self.nib.update_id = update_id;
        self.nib.next_channel_change = ChannelMask::EMPTY;
        self.push_action(NwkAction::MacSetChannel {
            page: self.nib.channel_page,
            channel,
        });
        // Maximum power again on the new channel (§3.6.11.1).
        self.push_action(NwkAction::MacResetTxPower);
        if self.nib.is_router_or_coordinator() {
            self.update_beacon_payload();
        }
        self.push_action(NwkAction::Persist);
    }

    /// MLME-BEACON-NOTIFY: a beacon received during a scan (or during
    /// normal operation, for PAN ID conflict detection).
    pub fn on_mac_beacon(
        &mut self,
        src_pan: PanId,
        src: MacAddress,
        beacon: &Beacon<'_>,
        channel: Channel,
        page: ChannelPage,
        lqi: u8,
    ) {
        let surveying = self
            .scan
            .is_some_and(|s| s.purpose == ScanPurpose::Discovery);
        if surveying {
            self.survey.total = self.survey.total.saturating_add(1);
        }
        let Ok(payload) = BeaconPayload::decode_exact_lenient(beacon.payload) else {
            if surveying {
                self.survey.other_networks = self.survey.other_networks.saturating_add(1);
            }
            return;
        };
        // §3.6.1.5.1 steps 1–3.
        if beacon.payload.is_empty() || !payload.is_zigbee_pro() {
            if surveying {
                self.survey.other_networks = self.survey.other_networks.saturating_add(1);
            }
            return;
        }
        if surveying {
            if self.nib.joined && payload.extended_pan_id == self.nib.extended_pan_id {
                self.survey.on_network = self.survey.on_network.saturating_add(1);
                if payload.end_device_capacity {
                    self.survey.potential_parents = self.survey.potential_parents.saturating_add(1);
                }
            } else {
                self.survey.other_networks = self.survey.other_networks.saturating_add(1);
            }
        }
        let scan = self.scan;
        match scan.map(|s| s.purpose) {
            Some(ScanPurpose::Discovery) => {
                let only_permit = scan.is_some_and(|s| s.only_permit_join);
                if only_permit && !beacon.superframe.association_permit {
                    return;
                }
                if self.nib.extended_pan_id != ExtendedAddress::ZERO
                    && payload.extended_pan_id != self.nib.extended_pan_id
                {
                    return;
                }
                let short = match src {
                    MacAddress::Short(s) => s,
                    _ => return,
                };
                let appendix = payload.appendix_tlvs();
                let router_info = appendix.and_then(|a| a.router_information());
                let mut app: Vec<u8, { crate::discovery::MAX_APPENDIX }> = Vec::new();
                let _ = app.extend_from_slice(
                    payload
                        .appendix
                        .get(..payload.appendix.len().min(crate::discovery::MAX_APPENDIX))
                        .unwrap_or(&[]),
                );
                let c = Candidate {
                    extended_pan_id: payload.extended_pan_id,
                    pan_id: src_pan,
                    page,
                    channel,
                    short,
                    extended: src.extended(),
                    lqa: lqi,
                    update_id: payload.update_id,
                    router_capacity: payload.router_capacity,
                    end_device_capacity: payload.end_device_capacity,
                    permit_joining: beacon.superframe.association_permit,
                    pan_coordinator: beacon.superframe.pan_coordinator,
                    router_info,
                    r23: appendix.is_some() && router_info.is_some(),
                    appendix: app,
                    attempts: 0,
                };
                let parent = if self.nib.is_end_device() {
                    Some(self.nib.parent_address)
                } else {
                    None
                };
                let uid = self.nib.update_id;
                self.discovery.add(c, uid, parent);
            }
            Some(ScanPurpose::FormationActive | ScanPurpose::PanIdConflict) => {
                if let Some(f) = &mut self.formation {
                    if let Some(n) = f.networks_per_channel.get_mut(usize::from(channel.raw())) {
                        *n = n.saturating_add(1);
                    }
                    if !f.seen_pan_ids.contains(&src_pan) {
                        let _ = f.seen_pan_ids.push(src_pan);
                    }
                }
                if scan.is_some_and(|s| s.purpose == ScanPurpose::PanIdConflict)
                    && src_pan == self.nib.pan_id
                    && payload.extended_pan_id != self.nib.extended_pan_id
                {
                    self.report_pan_id_conflict(src_pan);
                }
            }
            Some(ScanPurpose::FormationEnergy | ScanPurpose::EnergyDetect) | None => {
                // Operating: PAN ID conflict detection (§3.6.1.13.1).
                if self.nib.joined
                    && src_pan == self.nib.pan_id
                    && payload.extended_pan_id != self.nib.extended_pan_id
                    && self.nib.is_router_or_coordinator()
                {
                    self.report_pan_id_conflict(src_pan);
                }
            }
        }
    }

    /// MLME-SCAN.confirm from the MAC.
    pub fn on_mac_scan_confirm(&mut self, kind: ScanKind, energy: &[u8; 27]) {
        let Some(scan) = self.scan.take() else { return };
        match (scan.purpose, kind) {
            (ScanPurpose::Discovery, ScanKind::Active) => {
                let status = if self.discovery.is_empty() {
                    NwkStatus::NoNetworks
                } else {
                    NwkStatus::Success
                };
                self.push_event(NwkEvent::DiscoveryConfirm { status });
                // A join may be waiting for discovery results.
                if self
                    .join
                    .as_ref()
                    .is_some_and(|j| j.phase == JoinPhase::SelectParent)
                {
                    self.try_next_parent();
                }
            }
            (ScanPurpose::FormationEnergy, ScanKind::Energy) => {
                let Some(f) = &mut self.formation else { return };
                f.energy = *energy;
                // Order channels by energy and keep the quieter half (at
                // least one), then active-scan them.
                let mut chans: Vec<(u8, Channel), 27> = Vec::new();
                for c in scan.channels.iter() {
                    let _ = chans.push((energy[usize::from(c.raw())], c));
                }
                chans.sort_unstable_by_key(|(e, _)| *e);
                let keep = chans.len().div_ceil(2).max(1);
                let mut mask = ChannelMask::EMPTY;
                for (_, c) in chans.iter().take(keep) {
                    mask = mask.with(*c);
                }
                f.channels = mask;
                self.scan = Some(ScanState {
                    purpose: ScanPurpose::FormationActive,
                    channels: mask,
                    duration: scan.duration,
                    only_permit_join: false,
                });
                self.push_action(NwkAction::MacScan {
                    kind: ScanKind::Active,
                    channels: mask,
                    duration: scan.duration,
                    enhanced: None,
                });
            }
            (ScanPurpose::FormationActive, ScanKind::Active) => self.finish_formation(),
            (ScanPurpose::PanIdConflict, ScanKind::Active) => {
                self.formation = None;
            }
            (ScanPurpose::EnergyDetect, ScanKind::Energy) => {
                self.push_event(NwkEvent::EnergyScanConfirm {
                    channels: scan.channels,
                    energy: *energy,
                });
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Formation (§3.6.1.1)
    // ------------------------------------------------------------------

    /// NLME-NETWORK-FORMATION.request. `distributed` forms a distributed
    /// security network from a router (random address); otherwise the
    /// device becomes the coordinator at `0x0000`.
    ///
    /// The network key must be installed via [`Nwk::set_network_key`]
    /// before or immediately after formation for a secured network.
    pub fn network_formation(
        &mut self,
        channels: ChannelMask,
        duration: u8,
        distributed: bool,
    ) -> Result<(), NwkError> {
        self.network_formation_with(channels, duration, distributed, None, None)
    }

    /// [`Nwk::network_formation`] with a caller-chosen PAN ID and (for
    /// distributed networks) network address, as out-of-band
    /// commissioning provides them (ZD 1.1 §7.7.2.5.1); `None` selects
    /// them as §3.6.1.1 does.
    pub fn network_formation_with(
        &mut self,
        channels: ChannelMask,
        duration: u8,
        distributed: bool,
        pan_id: Option<PanId>,
        short: Option<ShortAddress>,
    ) -> Result<(), NwkError> {
        if pan_id.is_some_and(|p| !p.is_valid_for_formation()) {
            return Err(NwkError::InvalidParameter);
        }
        if short.is_some_and(|s| !s.is_unicast()) {
            return Err(NwkError::InvalidParameter);
        }
        if self.nib.joined || self.scan.is_some() {
            return Err(NwkError::InvalidRequest);
        }
        // Only channels an enabled interface supports (§3.2.2.5.3).
        let channels = self.interfaces.supported_subset(channels);
        if channels.is_empty() {
            return Err(NwkError::InvalidParameter);
        }
        if !distributed && self.nib.device_type != LogicalDeviceType::Coordinator {
            return Err(NwkError::InvalidRequest);
        }
        if distributed && !self.nib.is_router_or_coordinator() {
            return Err(NwkError::InvalidRequest);
        }
        self.formation = Some(FormationState {
            channels,
            energy: [0; 27],
            networks_per_channel: [0; 27],
            seen_pan_ids: Vec::new(),
            distributed,
            pan_id,
            short,
        });
        let single = channels.len() == 1;
        let purpose = if single {
            ScanPurpose::FormationActive
        } else {
            ScanPurpose::FormationEnergy
        };
        self.scan = Some(ScanState {
            purpose,
            channels,
            duration,
            only_permit_join: false,
        });
        self.push_action(NwkAction::MacScan {
            kind: if single {
                ScanKind::Active
            } else {
                ScanKind::Energy
            },
            channels,
            duration,
            enhanced: None,
        });
        Ok(())
    }

    fn finish_formation(&mut self) {
        let Some(f) = self.formation.take() else {
            return;
        };
        // Channel with the fewest networks, lowest energy as tie-break.
        let mut best: Option<(Channel, u8, u8)> = None;
        for c in f.channels.iter() {
            let n = f.networks_per_channel[usize::from(c.raw())];
            let e = f.energy[usize::from(c.raw())];
            if best.is_none_or(|(_, bn, be)| n < bn || (n == bn && e < be)) {
                best = Some((c, n, e));
            }
        }
        let Some((channel, _, _)) = best else {
            self.push_event(NwkEvent::FormationConfirm {
                status: NwkStatus::StartupFailure,
            });
            return;
        };
        // The caller's PAN ID, else a random one not in use.
        let mut pan_id = f.pan_id;
        for _ in 0..16 {
            if pan_id.is_some() {
                break;
            }
            let p = PanId(self.rng.next_u16());
            if p.is_valid_for_formation() && !f.seen_pan_ids.contains(&p) {
                pan_id = Some(p);
                break;
            }
        }
        let Some(pan_id) = pan_id else {
            self.push_event(NwkEvent::FormationConfirm {
                status: NwkStatus::StartupFailure,
            });
            return;
        };
        let short = if f.distributed {
            f.short
                .or_else(|| allocate_stochastic(&mut self.rng, |_| false))
                .unwrap_or(ShortAddress(0x0001))
        } else {
            ShortAddress::COORDINATOR
        };
        if self.nib.extended_pan_id == ExtendedAddress::ZERO {
            self.nib.extended_pan_id = if f.distributed {
                ExtendedAddress(self.rng.next_u64() | 1)
            } else {
                self.nib.ieee_address
            };
        }
        self.nib.pan_id = pan_id;
        self.nib.channel = channel;
        self.note_channel_in_use();
        self.nib.network_address = short;
        self.nib.joined = true;
        self.nib.authenticated = true;
        self.nib.router_started = true;
        self.nib.depth = 0;
        self.operating_since = Some(self.now);
        self.link_status_due = Some(self.now + self.nib.link_status_period);
        self.refresh_power_delta_schedule();
        self.child_age_last = self.now;
        self.push_action(NwkAction::MacStart {
            pan_id,
            page: self.nib.channel_page,
            channel,
            short,
            coordinator: !f.distributed,
            beacon_capable: true,
        });
        self.update_beacon_payload();
        self.push_action(NwkAction::Persist);
        self.push_event(NwkEvent::FormationConfirm {
            status: NwkStatus::Success,
        });
    }

    /// Rebuilds the beacon payload from the NIB and pushes it to the MAC.
    pub(crate) fn update_beacon_payload(&mut self) {
        if !self.nib.is_router_or_coordinator() {
            return;
        }
        let router_capacity = self.neighbors.router_child_count()
            < usize::from(self.nib.max_routers)
            && self.neighbors.child_count() < usize::from(self.nib.max_children)
            && self.neighbors.len() < self.neighbors.capacity();
        let end_device_capacity = self.neighbors.child_count() < usize::from(self.nib.max_children)
            && self.neighbors.len() < self.neighbors.capacity();
        // §3.6.8.2 steps 3–4: network-wide TLVs first, then the device's
        // own TLVs whose tags were not already set network-wide.
        let mut appendix = [0u8; constants::MAX_BEACON_APPENDIX];
        let mut w = panweave_codec::Writer::new(&mut appendix);
        let _ = w.bytes(&self.network_wide_beacon_appendix);
        let has_router_info = TlvSet::validate(&self.network_wide_beacon_appendix, |_| false)
            .ok()
            .is_some_and(|set| set.find(tlv::tag::ROUTER_INFORMATION).is_some());
        let appendix_len = if self.config.r23_beacon_appendix && !has_router_info {
            let mut bits = 0u16;
            if self.nib.hub_connectivity {
                bits |= RouterInformation::HUB_CONNECTIVITY;
            }
            if self.nib.preferred_parent {
                bits |= RouterInformation::PREFERRED_PARENT;
            }
            if self
                .operating_since
                .is_some_and(|t| self.now.has_reached(t + Duration::from_secs(24 * 3600)))
            {
                bits |= RouterInformation::LONG_UPTIME;
            }
            if self.config.keepalive_methods & 0x01 != 0 {
                bits |= RouterInformation::MAC_DATA_POLL_KEEPALIVE;
            }
            if self.config.keepalive_methods & 0x02 != 0 {
                bits |= RouterInformation::END_DEVICE_KEEPALIVE;
            }
            let _ = RouterInformation(bits).write(&mut w);
            w.position()
        } else {
            w.position()
        };
        let payload = BeaconPayload::new(
            self.nib.extended_pan_id,
            router_capacity,
            end_device_capacity,
            self.nib.update_id,
            appendix.get(..appendix_len).unwrap_or(&[]),
        );
        let mut buf = [0u8; 52];
        let Ok(n) = panweave_codec::Encode::encode_to_slice(&payload, &mut buf) else {
            return;
        };
        let mut v: Vec<u8, 52> = Vec::new();
        let _ = v.extend_from_slice(buf.get(..n).unwrap_or(&[]));
        self.push_action(NwkAction::MacSetBeaconPayload(v));
    }

    // ------------------------------------------------------------------
    // Permit joining (§3.6.1.2)
    // ------------------------------------------------------------------

    /// Whether joining is currently permitted on this device.
    pub fn permit_joining_active(&self) -> bool {
        self.permit_until.is_some_and(|t| t > self.now)
    }

    /// NLME-PERMIT-JOINING.request. `0` disables, `1..=254` seconds,
    /// `255` unlimited.
    pub fn permit_joining(&mut self, duration_secs: u8) -> Result<(), NwkError> {
        if !self.nib.is_router_or_coordinator() {
            return Err(NwkError::InvalidRequest);
        }
        match duration_secs {
            0 => {
                self.permit_until = None;
                self.push_action(NwkAction::MacSetPermit(false));
                self.push_event(NwkEvent::PermitJoining(false));
            }
            255 => {
                self.permit_until = Some(Instant::FAR_FUTURE);
                self.push_action(NwkAction::MacSetPermit(true));
                self.push_event(NwkEvent::PermitJoining(true));
            }
            n => {
                self.permit_until = Some(self.now + Duration::from_secs(u64::from(n)));
                self.push_action(NwkAction::MacSetPermit(true));
                self.push_event(NwkEvent::PermitJoining(true));
            }
        }
        Ok(())
    }

    /// True while joining is permitted.
    pub fn is_permitting_joins(&self) -> bool {
        self.permit_until.is_some_and(|t| !self.now.has_reached(t))
    }

    /// Records the operating channel in the interface entry that carries
    /// it (Table 3-69 `ChannelInUse`).
    pub(crate) fn note_channel_in_use(&mut self) {
        let (page, channel) = (self.nib.channel_page, self.nib.channel);
        let index = self
            .interfaces
            .interface_for(page, channel)
            .map(|e| e.index);
        if let Some(i) = index
            && let Some(e) = self.interfaces.get_mut(i)
        {
            e.channel_in_use = Some((page, channel));
        }
    }

    /// Whether this parent can accept a new child of the given kind.
    fn has_child_capacity(&self, router: bool) -> bool {
        if self.neighbors.len() >= self.neighbors.capacity() {
            return false;
        }
        // Table 3-69 RoutersAllowed of the interface in use.
        if router
            && !self
                .interfaces
                .interface_for(self.nib.channel_page, self.nib.channel)
                .is_none_or(|e| e.routers_allowed)
        {
            return false;
        }
        if self.neighbors.child_count() >= usize::from(self.nib.max_children) {
            return false;
        }
        if router && self.neighbors.router_child_count() >= usize::from(self.nib.max_routers) {
            return false;
        }
        true
    }

    /// Allocates a fresh short address not known locally (§3.6.1.8).
    fn allocate_address(&mut self) -> Option<ShortAddress> {
        let neighbors = &self.neighbors;
        let map = &self.address_map;
        let my = self.nib.network_address;
        allocate_stochastic(&mut self.rng, |s| {
            s == my || neighbors.by_short(s).is_some() || map.contains_short(s)
        })
    }

    /// True when `short` is used by a device other than `ext`.
    fn address_conflicts(&self, short: ShortAddress, ext: ExtendedAddress) -> bool {
        if short == self.nib.network_address {
            return true;
        }
        if let Some(n) = self.neighbors.by_short(short)
            && n.extended != ext
        {
            return true;
        }
        matches!(self.address_map.extended_for(short), Some(e) if e != ext)
    }

    // ------------------------------------------------------------------
    // Joining: child side (§3.6.1.6.1.1)
    // ------------------------------------------------------------------

    /// NLME-JOIN.request. Requires a preceding discovery (the discovery
    /// table is consulted for parents).
    ///
    /// May transmit; persists on success.
    pub fn join(&mut self, params: JoinParams) -> Result<(), NwkError> {
        if self.join.is_some() {
            return Err(NwkError::Busy);
        }
        if !params.rejoin && self.nib.joined {
            return Err(NwkError::InvalidRequest);
        }
        if params.rejoin && params.secure && !self.security.has_key() {
            return Err(NwkError::InvalidRequest);
        }
        self.nib.capability_information = params.capability;
        self.nib.rx_on_when_idle = params.capability.rx_on_when_idle();
        self.nib.parent_information = crate::command::ParentInformation(0);
        self.join = Some(JoinState {
            params,
            secure: params.rejoin && params.secure,
            candidates: Vec::new(),
            next: 0,
            pass: 0,
            current: None,
            phase: JoinPhase::SelectParent,
            attempts: 0,
            used_commissioning: false,
        });
        if self.scan.is_none() {
            self.try_next_parent();
        }
        Ok(())
    }

    fn rank_candidates(&mut self, good_only: bool) {
        let Some(j) = &mut self.join else { return };
        let parent = if self.nib.is_end_device() && j.params.rejoin {
            Some(self.nib.parent_address)
        } else {
            None
        };
        let max_attempts = if j.params.rejoin {
            self.nib.max_rejoin_parent_attempts
        } else {
            self.nib.max_initial_join_parent_attempts
        };
        let mut out: Vec<usize, DISCOVERY_TABLE_SIZE> = Vec::new();
        self.discovery.ranked(
            j.params.extended_pan_id,
            j.params.as_router,
            j.params.require_permit,
            self.nib.good_parent_lqa,
            good_only,
            self.nib.update_id,
            parent,
            max_attempts,
            &mut out,
        );
        j.candidates = out;
        j.next = 0;
    }

    /// Picks the next candidate parent and starts the attach mechanism.
    pub(crate) fn try_next_parent(&mut self) {
        let Some(j) = &self.join else { return };
        let max_attempts = if j.params.rejoin {
            self.nib.max_rejoin_parent_attempts
        } else {
            self.nib.max_initial_join_parent_attempts
        };
        if j.attempts >= max_attempts {
            self.finish_join(NwkStatus::NoNetworks);
            return;
        }
        if j.candidates.is_empty() || j.next >= j.candidates.len() {
            let pass = j.pass;
            if pass == 0 && (j.candidates.is_empty() || j.next >= j.candidates.len()) {
                if j.next == 0 && j.candidates.is_empty() {
                    self.rank_candidates(true);
                }
                let exhausted = self
                    .join
                    .as_ref()
                    .is_some_and(|j| j.next >= j.candidates.len());
                if exhausted {
                    if let Some(j) = &mut self.join {
                        j.pass = 1;
                    }
                    self.rank_candidates(false);
                }
            }
            let Some(j) = &self.join else { return };
            if j.next >= j.candidates.len() {
                let status = if self.discovery.is_empty() {
                    NwkStatus::NoNetworks
                } else {
                    NwkStatus::NotPermitted
                };
                self.finish_join(status);
                return;
            }
        }
        let Some(j) = &mut self.join else { return };
        let idx = j.candidates[j.next];
        j.next += 1;
        j.attempts += 1;
        let Some(c) = self.discovery.get_mut(idx) else {
            return;
        };
        c.attempts = c.attempts.saturating_add(1);
        let snap = ParentSnapshot {
            short: c.short,
            extended: c.extended,
            pan_id: c.pan_id,
            extended_pan_id: c.extended_pan_id,
            page: c.page,
            channel: c.channel,
            r23: c.r23,
            update_id: c.update_id,
            lqa: c.lqa,
        };
        j.current = Some(snap);
        let rejoin = j.params.rejoin;
        let secure = j.secure;
        let capability = j.params.capability;
        // Attach mechanism selection (§3.6.1.6.1.1).
        self.push_action(NwkAction::MacSetChannel {
            page: snap.page,
            channel: snap.channel,
        });
        self.nib.channel = snap.channel;
        self.nib.channel_page = snap.page;
        if snap.r23 {
            if let Some(j) = &mut self.join {
                j.used_commissioning = true;
            }
            self.send_commissioning_request(snap, rejoin, secure, capability);
        } else if rejoin {
            self.send_rejoin_request(snap, secure, capability);
        } else {
            if let Some(j) = &mut self.join {
                j.phase = JoinPhase::Associating;
            }
            self.nib.pan_id = snap.pan_id;
            self.push_action(NwkAction::MacSetPanId(snap.pan_id));
            self.push_action(NwkAction::MacAssociate {
                pan_id: snap.pan_id,
                coordinator: snap.short,
                page: snap.page,
                channel: snap.channel,
                capability,
            });
        }
    }

    /// Ensures we have a short address for a NWK-level attach (rejoin /
    /// commissioning): keep the existing one or self-assign (§3.6.1.8).
    fn ensure_self_address(&mut self) -> ShortAddress {
        if self.nib.network_address.is_unicast() && self.nib.network_address.0 != 0 {
            return self.nib.network_address;
        }
        let a = allocate_stochastic(&mut self.rng, |_| false).unwrap_or(ShortAddress(0x1000));
        self.nib.network_address = a;
        a
    }

    fn send_rejoin_request(&mut self, p: ParentSnapshot, secure: bool, capability: MacCapability) {
        let my = self.ensure_self_address();
        self.nib.pan_id = p.pan_id;
        self.push_action(NwkAction::MacSetPanId(p.pan_id));
        self.push_action(NwkAction::MacSetShortAddress(my));
        let seq = self.nib.next_sequence();
        let mut header = Header::new(FrameType::Command, p.short, my, 1, seq)
            .with_src_ieee(self.nib.ieee_address)
            .secured(secure && self.config.security_enabled);
        if let Some(e) = p.extended {
            header = header.with_dst_ieee(e);
        }
        let cmd = NwkCommand::RejoinRequest(RejoinRequest { capability });
        if let Some(j) = &mut self.join {
            j.phase = JoinPhase::RequestSent;
        }
        if self
            .send_command_unicast(&header, &cmd, p.short, secure, false, TxKind::JoinRequest)
            .is_err()
        {
            self.on_join_request_sent(false);
        }
    }

    fn send_commissioning_request(
        &mut self,
        p: ParentSnapshot,
        rejoin: bool,
        secure: bool,
        capability: MacCapability,
    ) {
        let my = self.ensure_self_address();
        self.nib.pan_id = p.pan_id;
        self.push_action(NwkAction::MacSetPanId(p.pan_id));
        self.push_action(NwkAction::MacSetShortAddress(my));
        let seq = self.nib.next_sequence();
        let mut header = Header::new(FrameType::Command, p.short, my, 1, seq)
            .with_src_ieee(self.nib.ieee_address)
            .secured(rejoin && secure && self.config.security_enabled);
        if let Some(e) = p.extended {
            header = header.with_dst_ieee(e);
        }
        // Joiner Encapsulation with Fragmentation Parameters and, for initial
        // joins, Supported Key Negotiation Methods (§3.4.14.3.3).
        let mut tlvs = [0u8; 32];
        let mut w = panweave_codec::Writer::new(&mut tlvs);
        let _ = tlv::write_encapsulation(&mut w, tlv::tag::JOINER_ENCAPSULATION, |w| {
            tlv::FragmentationParameters {
                node: my,
                options: 0,
                max_incoming_transfer_unit: 0x80,
            }
            .write(w)?;
            if !rejoin {
                tlv::SupportedKeyNegotiationMethods {
                    protocols: tlv::SupportedKeyNegotiationMethods::PROTO_STATIC_KEY_REQUEST
                        | tlv::SupportedKeyNegotiationMethods::PROTO_SPEKE_CURVE25519_AES_MMO,
                    secrets: tlv::SupportedKeyNegotiationMethods::SECRET_INSTALL_CODE,
                    source: Some(self.nib.ieee_address),
                }
                .write(w)?;
            }
            Ok(())
        });
        let n = w.position();
        let cmd = NwkCommand::CommissioningRequest(CommissioningRequest {
            kind: if rejoin {
                CommissioningType::Rejoin
            } else {
                CommissioningType::InitialJoin
            },
            capability,
            tlvs: tlvs.get(..n).unwrap_or(&[]),
        });
        if let Some(j) = &mut self.join {
            j.phase = JoinPhase::RequestSent;
        }
        if self
            .send_command_unicast(
                &header,
                &cmd,
                p.short,
                rejoin && secure,
                false,
                TxKind::JoinRequest,
            )
            .is_err()
        {
            self.on_join_request_sent(false);
        }
    }

    /// Called when the rejoin/commissioning request transmission completes.
    pub(crate) fn on_join_request_sent(&mut self, ok: bool) {
        let Some(j) = &mut self.join else { return };
        if !matches!(j.phase, JoinPhase::RequestSent) {
            return;
        }
        if !ok {
            self.try_next_parent();
            return;
        }
        let deadline = self.now + panweave_mac::constants::response_wait_time();
        j.phase = JoinPhase::AwaitingResponse {
            deadline,
            polled: false,
        };
        let needs_poll = !j.params.capability.rx_on_when_idle();
        let parent_short = j
            .current
            .map_or(ShortAddress::NO_SHORT_ADDRESS, |c| c.short);
        let parent_ext = j
            .current
            .and_then(|c| c.extended)
            .unwrap_or(ExtendedAddress::ZERO);
        if needs_poll {
            // Poll the prospective parent for the response (§3.6.1.6.1.2).
            self.push_action(NwkAction::MacSetCoordinator {
                short: parent_short,
                extended: parent_ext,
            });
            self.push_action(NwkAction::MacPoll);
        }
    }

    /// MLME-ASSOCIATE.confirm from the MAC.
    pub fn on_mac_associate_confirm(&mut self, short: ShortAddress, status: MacStatus) {
        let Some(j) = &self.join else { return };
        if j.phase != JoinPhase::Associating {
            return;
        }
        let Some(p) = j.current else { return };
        if status == MacStatus::Success && short.is_unicast() {
            self.complete_join(p, short, false);
        } else {
            self.try_next_parent();
        }
    }

    /// Finalises a successful attach.
    fn complete_join(&mut self, p: ParentSnapshot, short: ShortAddress, secured: bool) {
        let Some(j) = &self.join else { return };
        let rejoin = j.params.rejoin;
        self.nib.network_address = short;
        self.nib.pan_id = p.pan_id;
        self.nib.extended_pan_id = p.extended_pan_id;
        self.nib.update_id = p.update_id;
        self.nib.channel = p.channel;
        self.nib.channel_page = p.page;
        self.note_channel_in_use();
        self.nib.parent_address = p.short;
        self.nib.parent_ieee = p.extended.unwrap_or(ExtendedAddress::ZERO);
        self.nib.joined = true;
        self.nib.authenticated = secured;
        self.nib.router_started = false;
        self.operating_since = Some(self.now);
        // Parent neighbor entry.
        let parent_ext = p.extended.unwrap_or(ExtendedAddress::ZERO);
        let mut e = NeighborEntry::new(
            parent_ext,
            p.short,
            if p.short == ShortAddress::COORDINATOR {
                LogicalDeviceType::Coordinator
            } else {
                LogicalDeviceType::Router
            },
            true,
            Relationship::Parent,
            p.lqa,
        );
        e.outgoing_cost = 1;
        if !secured {
            e.security_timer_secs =
                u16::try_from(constants::SECURITY_TIMEOUT.as_secs()).unwrap_or(10);
        }
        // The previous parent entry goes; so does a stale entry for
        // another device that held the parent's short address (a
        // replacement Trust Center at 0x0000 after a swap-out, §4.7.4).
        self.neighbors.retain(|n| {
            n.relationship != Relationship::Parent
                && (parent_ext == ExtendedAddress::ZERO
                    || n.short != p.short
                    || n.extended == parent_ext)
        });
        let _ = self.ensure_neighbor(e);
        self.push_action(NwkAction::MacSetPanId(p.pan_id));
        self.push_action(NwkAction::MacSetShortAddress(short));
        self.push_action(NwkAction::MacSetCoordinator {
            short: p.short,
            extended: parent_ext,
        });
        self.push_action(NwkAction::MacSetRxOnWhenIdle(self.nib.rx_on_when_idle));
        self.power_delta_due = None;
        self.power_request = None;
        if secured {
            self.finish_join_success(rejoin, true);
        } else if let Some(j) = &mut self.join {
            j.phase = JoinPhase::AwaitingKey {
                deadline: self.now + constants::SECURITY_TIMEOUT,
            };
            self.push_action(NwkAction::Persist);
            self.push_event(NwkEvent::JoinConfirm {
                status: NwkStatus::Success,
                network_address: short,
                extended_pan_id: p.extended_pan_id,
                rejoin,
                secured: false,
            });
        }
    }

    fn finish_join_success(&mut self, rejoin: bool, secured: bool) {
        self.join = None;
        self.discovery.clear();
        self.child_age_last = self.now;
        self.push_action(NwkAction::Persist);
        self.push_event(NwkEvent::JoinConfirm {
            status: NwkStatus::Success,
            network_address: self.nib.network_address,
            extended_pan_id: self.nib.extended_pan_id,
            rejoin,
            secured,
        });
        self.after_authenticated();
    }

    fn finish_join(&mut self, status: NwkStatus) {
        let rejoin = self.join.as_ref().is_some_and(|j| j.params.rejoin);
        self.join = None;
        if !rejoin {
            self.nib.pan_id = PanId::BROADCAST;
            self.nib.network_address = ShortAddress::NO_SHORT_ADDRESS;
            self.push_action(NwkAction::MacSetPanId(PanId::BROADCAST));
        }
        self.push_event(NwkEvent::JoinConfirm {
            status,
            network_address: self.nib.network_address,
            extended_pan_id: self.nib.extended_pan_id,
            rejoin,
            secured: false,
        });
    }

    /// Installs the network key delivered by the higher layer (APS
    /// Transport Key) and completes authentication. Also used by the
    /// coordinator before formation and for key updates (`active`
    /// false stores an alternate key).
    ///
    /// Persists state.
    pub fn set_network_key(&mut self, sequence: KeySequenceNumber, key: Key128, active: bool) {
        if active {
            self.security.install_active_key(sequence, key);
        } else {
            self.security.install_key(sequence, key);
            self.push_action(NwkAction::Persist);
            self.maybe_reserve_counter();
            return;
        }
        self.maybe_reserve_counter();
        self.push_action(NwkAction::Persist);
        if self.nib.joined && !self.nib.authenticated {
            self.nib.authenticated = true;
            if let Some(n) = self
                .neighbors
                .iter_mut()
                .find(|n| n.relationship == Relationship::Parent)
            {
                n.security_timer_secs = 0;
            }
            if self
                .join
                .as_ref()
                .is_some_and(|j| matches!(j.phase, JoinPhase::AwaitingKey { .. }))
            {
                let rejoin = self.join.as_ref().is_some_and(|j| j.params.rejoin);
                self.join = None;
                self.discovery.clear();
                let _ = rejoin;
            }
            self.after_authenticated();
        }
    }

    /// Switches the active network key (APSME-SWITCH-KEY).
    pub fn switch_network_key(&mut self, sequence: KeySequenceNumber) -> bool {
        let previous = self.security.keys.active().map(|s| s.sequence);
        let ok = self.security.switch_key(sequence);
        if ok {
            self.maybe_reserve_counter();
            self.push_action(NwkAction::Persist);
            self.push_event(NwkEvent::KeySwitched {
                previous: previous.filter(|p| *p != sequence),
                sequence,
            });
        }
        ok
    }

    /// Steps performed once the device holds the network key.
    fn after_authenticated(&mut self) {
        self.child_age_last = self.now;
        if self.nib.is_end_device() {
            // Negotiate the end device timeout (§3.6.10.2).
            self.send_end_device_timeout_request();
        }
        self.refresh_power_delta_schedule();
    }

    /// NLME-START-ROUTER.request: begin routing and beaconing after a
    /// successful join.
    pub fn start_router(&mut self) -> Result<(), NwkError> {
        if !self.nib.is_router_or_coordinator() || !self.nib.joined || !self.nib.authenticated {
            return Err(NwkError::InvalidRequest);
        }
        self.nib.router_started = true;
        self.push_action(NwkAction::MacStart {
            pan_id: self.nib.pan_id,
            page: self.nib.channel_page,
            channel: self.nib.channel,
            short: self.nib.network_address,
            coordinator: self.nib.is_coordinator(),
            beacon_capable: true,
        });
        self.update_beacon_payload();
        // The former parent becomes a sibling (§3.6.1.6).
        for n in self.neighbors.iter_mut() {
            if n.relationship == Relationship::Parent {
                n.relationship = Relationship::Sibling;
            }
        }
        let j = self.jitter(
            constants::MIN_ROUTER_BOOTSTRAP_JITTER,
            constants::MAX_ROUTER_BOOTSTRAP_JITTER,
        );
        self.link_status_due = Some(self.now + j);
        self.refresh_power_delta_schedule();
        self.push_event(NwkEvent::StartRouterConfirm {
            status: NwkStatus::Success,
        });
        Ok(())
    }

    /// Whether a join is in progress.
    pub fn is_joining(&self) -> bool {
        self.join.is_some()
    }

    /// Timer processing for the join state machine.
    pub(crate) fn service_join(&mut self, now: Instant) {
        let Some(j) = &mut self.join else { return };
        match j.phase {
            JoinPhase::AwaitingResponse { deadline, polled } => {
                if now.has_reached(deadline) {
                    self.try_next_parent();
                } else if !polled
                    && !j.params.capability.rx_on_when_idle()
                    && now.saturating_duration_until(deadline)
                        <= panweave_mac::constants::response_wait_time().div(2)
                {
                    j.phase = JoinPhase::AwaitingResponse {
                        deadline,
                        polled: true,
                    };
                    self.push_action(NwkAction::MacPoll);
                }
            }
            JoinPhase::AwaitingKey { deadline } => {
                if now.has_reached(deadline) {
                    // §3.6.1.6.1.1: NO_KEY → leave.
                    self.join = None;
                    self.push_event(NwkEvent::AuthenticationTimeout);
                    self.push_event(NwkEvent::JoinConfirm {
                        status: NwkStatus::NoKey,
                        network_address: self.nib.network_address,
                        extended_pan_id: self.nib.extended_pan_id,
                        rejoin: false,
                        secured: false,
                    });
                    self.local_leave(false);
                }
            }
            _ => {}
        }
    }

    /// Join-related deadline.
    pub(crate) fn join_deadline(&self) -> Option<Instant> {
        match self.join.as_ref()?.phase {
            JoinPhase::AwaitingResponse { deadline, .. } | JoinPhase::AwaitingKey { deadline } => {
                Some(deadline)
            }
            _ => None,
        }
    }

    fn accept_join_response(
        &mut self,
        ctx: &CommandContext,
        address: ShortAddress,
        status: MacStatus,
    ) {
        let Some(j) = &self.join else { return };
        let Some(p) = j.current else { return };
        if !matches!(j.phase, JoinPhase::AwaitingResponse { .. }) {
            return;
        }
        // §3.6.1.6.1.2: verify addresses.
        if ctx.dst_ieee.is_some_and(|d| d != self.nib.ieee_address) {
            return;
        }
        if let (Some(exp), Some(got)) = (p.extended, ctx.src_ieee)
            && exp != got
        {
            return;
        }
        if ctx.src != p.short {
            return;
        }
        // Unsecured responses only for unsecured requests (§3.6.1.10.6).
        if !ctx.secured && j.secure {
            return;
        }
        match status {
            MacStatus::Success => {
                let mut p = p;
                if p.extended.is_none() {
                    p.extended = ctx.src_ieee;
                }
                self.complete_join(p, address, ctx.secured);
            }
            s if s.raw() == CommissioningResponse::STATUS_ADDRESS_CONFLICT => {
                // Retry with the suggested address (§3.6.1.10.3).
                self.nib.network_address = address;
                if let Some(j) = &mut self.join {
                    j.next = j.next.saturating_sub(1);
                }
                self.try_next_parent();
            }
            _ => self.try_next_parent(),
        }
    }

    /// Rejoin Response destined to us.
    pub(crate) fn on_rejoin_response(&mut self, ctx: &CommandContext, rsp: RejoinResponse) {
        if self.join.is_some() {
            self.accept_join_response(ctx, rsp.address, rsp.status);
            return;
        }
        // Unsolicited: only from our parent, secured (address change,
        // §3.6.1.10.5).
        if !ctx.secured || ctx.src != self.nib.parent_address || !self.nib.is_end_device() {
            return;
        }
        if rsp.status == MacStatus::Success
            && rsp.address.is_unicast()
            && rsp.address != self.nib.network_address
        {
            self.nib.network_address = rsp.address;
            self.push_action(NwkAction::MacSetShortAddress(rsp.address));
            self.push_action(NwkAction::Persist);
            self.push_event(NwkEvent::NetworkStatus {
                address: rsp.address,
                code: NetworkStatusCode::NetworkAddressUpdate,
            });
        }
    }

    /// Commissioning Response destined to us.
    pub(crate) fn on_commissioning_response(
        &mut self,
        ctx: &CommandContext,
        rsp: &CommissioningResponse<'_>,
    ) {
        if self.join.is_some() {
            self.accept_join_response(ctx, rsp.address, rsp.status);
        }
    }

    // ------------------------------------------------------------------
    // Joining: parent side (§3.6.1.6.1.3)
    // ------------------------------------------------------------------

    /// MLME-ASSOCIATE.indication from the MAC.
    pub fn on_mac_associate_indication(
        &mut self,
        device: ExtendedAddress,
        capability: MacCapability,
        lqi: u8,
    ) {
        if !self.nib.is_router_or_coordinator() || !self.nib.router_started {
            return;
        }
        // Permit joining and the joining policy / IEEE list
        // (mibJoiningPolicy, §2.4.4.3.11) both gate association.
        if !self.is_permitting_joins() || !self.joining_list.allows(device) {
            self.push_action(NwkAction::MacAssociateResponse {
                device,
                short: ShortAddress::NO_SHORT_ADDRESS,
                status: MacStatus::PanAccessDenied,
            });
            return;
        }
        let router = capability.is_full_function_device();
        let existing = self.neighbors.by_extended(device).map(|n| n.short);
        let short = match existing {
            Some(s) => s,
            None => {
                if !self.has_child_capacity(router) {
                    self.push_action(NwkAction::MacAssociateResponse {
                        device,
                        short: ShortAddress::NO_SHORT_ADDRESS,
                        status: MacStatus::PanAtCapacity,
                    });
                    return;
                }
                match self.allocate_address() {
                    Some(a) => a,
                    None => {
                        self.push_action(NwkAction::MacAssociateResponse {
                            device,
                            short: ShortAddress::NO_SHORT_ADDRESS,
                            status: MacStatus::PanAtCapacity,
                        });
                        return;
                    }
                }
            }
        };
        self.add_unauthenticated_child(device, short, capability, lqi);
        self.push_action(NwkAction::MacAssociateResponse {
            device,
            short,
            status: MacStatus::Success,
        });
    }

    fn add_unauthenticated_child(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        capability: MacCapability,
        lqi: u8,
    ) {
        let mut e = NeighborEntry::new(
            device,
            short,
            if capability.is_full_function_device() {
                LogicalDeviceType::Router
            } else {
                LogicalDeviceType::EndDevice
            },
            capability.rx_on_when_idle(),
            Relationship::UnauthenticatedChild,
            lqi,
        );
        e.security_timer_secs = u16::try_from(constants::SECURITY_TIMEOUT.as_secs()).unwrap_or(10);
        e.set_timeout(self.nib.end_device_timeout_default);
        e.outgoing_cost = 1;
        let _ = self.ensure_neighbor(e);
        let _ = self.routes.remove(short);
        self.security.incoming.remove(device);
        let _ = self.address_map.record(device, short);
    }

    /// MLME-COMM-STATUS.indication for the indirect association response.
    pub fn on_mac_comm_status(&mut self, device: ExtendedAddress, status: TxStatus) {
        self.on_join_response_delivered_inner(
            device,
            status == TxStatus::Success,
            JoinMethod::MacAssociation,
        );
    }

    pub(crate) fn on_join_response_delivered(
        &mut self,
        device: ExtendedAddress,
        ok: bool,
        method: JoinMethod,
    ) {
        self.on_join_response_delivered_inner(device, ok, method);
    }

    fn on_join_response_delivered_inner(
        &mut self,
        device: ExtendedAddress,
        ok: bool,
        method: JoinMethod,
    ) {
        let Some(n) = self.neighbors.by_extended(device) else {
            return;
        };
        if !n.relationship.is_child() {
            return;
        }
        let short = n.short;
        let cap = MacCapability::from_raw(
            (u8::from(n.is_router()) << 1)
                | (u8::from(n.rx_on_when_idle) << 3)
                | (u8::from(n.rx_on_when_idle) << 2)
                | 0x80,
        );
        if !ok {
            if n.relationship == Relationship::UnauthenticatedChild {
                self.neighbors.remove_extended(device);
                self.address_map.remove_extended(device);
            }
            return;
        }
        let tlvs = self.pending_joiner_tlvs.take().unwrap_or_default();
        self.update_beacon_payload();
        self.push_action(NwkAction::Persist);
        self.stats.join_indications = self.stats.join_indications.saturating_add(1);
        self.push_event(NwkEvent::JoinIndication {
            device,
            network_address: short,
            capability: cap,
            method,
            joiner_tlvs: tlvs,
        });
    }

    /// Rejoin Request received (parent side).
    pub(crate) fn on_rejoin_request(&mut self, ctx: &CommandContext, req: RejoinRequest) {
        if !self.nib.is_router_or_coordinator() || !self.nib.router_started {
            return;
        }
        let Some(device) = ctx.src_ieee else { return };
        if ctx.dst != self.nib.network_address {
            return;
        }
        self.handle_attach_request(ctx, device, req.capability, false, ctx.secured, None);
    }

    /// Network Commissioning Request received (parent side).
    pub(crate) fn on_commissioning_request(
        &mut self,
        ctx: &CommandContext,
        req: &CommissioningRequest<'_>,
    ) {
        if !self.nib.is_router_or_coordinator() || !self.nib.router_started {
            return;
        }
        let Some(device) = ctx.src_ieee else { return };
        if ctx.dst != self.nib.network_address {
            return;
        }
        let initial = match req.kind {
            CommissioningType::InitialJoin => true,
            CommissioningType::Rejoin => false,
            _ => return,
        };
        if initial && ctx.secured {
            // §3.6.1.6.1.3: secured initial join is not allowed.
            return;
        }
        // Permit joining and the joining policy / IEEE list both gate
        // an initial join (mibJoiningPolicy, §2.4.4.3.11).
        if initial && (!self.is_permitting_joins() || !self.joining_list.allows(device)) {
            self.send_commissioning_response(
                ctx,
                device,
                ctx.src,
                MacStatus::PanAccessDenied,
                None,
            );
            return;
        }
        let Ok(set) = req.tlv_set() else { return };
        let joiner = set
            .joiner_encapsulation()
            .map(|s| s.as_bytes())
            .unwrap_or(&[]);
        let mut tlvs: Vec<u8, MAX_JOINER_TLVS> = Vec::new();
        let _ = tlvs.extend_from_slice(
            joiner
                .get(..joiner.len().min(MAX_JOINER_TLVS))
                .unwrap_or(&[]),
        );
        self.handle_attach_request(
            ctx,
            device,
            req.capability,
            true,
            ctx.secured,
            Some((initial, tlvs)),
        );
    }

    /// Shared parent-side processing for Rejoin and Commissioning
    /// requests (§3.6.1.6.1.3).
    fn handle_attach_request(
        &mut self,
        ctx: &CommandContext,
        device: ExtendedAddress,
        capability: MacCapability,
        commissioning: bool,
        secured: bool,
        commissioning_info: Option<(bool, Vec<u8, MAX_JOINER_TLVS>)>,
    ) {
        let initial = commissioning_info.as_ref().is_some_and(|(i, _)| *i);
        let method = match (commissioning, initial, secured) {
            (true, true, _) => JoinMethod::CommissioningJoin,
            (true, false, true) => JoinMethod::CommissioningRejoinSecured,
            (true, false, false) => JoinMethod::CommissioningRejoinUnsecured,
            (false, _, true) => JoinMethod::RejoinSecured,
            (false, _, false) => JoinMethod::RejoinUnsecured,
        };
        let requested = ctx.src;
        let router = capability.is_full_function_device();
        // Unsecured rejoins are rejected on distributed networks
        // (§3.6.1.6.1.3); the runtime flags this via `distributed`.
        if !secured && !initial && self.distributed_network {
            self.send_attach_response(
                ctx,
                device,
                requested,
                MacStatus::PanAccessDenied,
                commissioning,
            );
            return;
        }
        let existing = self.neighbors.by_extended(device).cloned();
        if let Some(e) = &existing {
            let differs = e.short != requested
                || e.is_router() != router
                || e.rx_on_when_idle != capability.rx_on_when_idle();
            if !secured && differs && e.relationship.is_child() {
                // §3.6.1.6.1.3 rule 3: unsecured attempts must not rewrite
                // legitimate neighbor data.
                self.send_attach_response(
                    ctx,
                    device,
                    requested,
                    MacStatus::PanAccessDenied,
                    commissioning,
                );
                return;
            }
        } else if !self.has_child_capacity(router) {
            self.send_attach_response(
                ctx,
                device,
                requested,
                MacStatus::PanAtCapacity,
                commissioning,
            );
            return;
        }
        // Address conflict handling (§3.6.1.10.3).
        let mut assigned = requested;
        let conflict = !requested.is_assignable() || self.address_conflicts(requested, device);
        if conflict {
            match self.allocate_address() {
                Some(a) => assigned = a,
                None => {
                    self.send_attach_response(
                        ctx,
                        device,
                        requested,
                        MacStatus::PanAtCapacity,
                        commissioning,
                    );
                    return;
                }
            }
            if commissioning {
                // Commissioning: tell the joiner to retry with the new
                // address (status 0xF0), no state change.
                self.send_commissioning_response(
                    ctx,
                    device,
                    assigned,
                    MacStatus::from_raw(CommissioningResponse::STATUS_ADDRESS_CONFLICT),
                    None,
                );
                return;
            }
        }
        // Accept: create/refresh the neighbor entry.
        let relationship = if secured {
            Relationship::Child
        } else {
            Relationship::UnauthenticatedChild
        };
        let mut e = NeighborEntry::new(
            device,
            assigned,
            if router {
                LogicalDeviceType::Router
            } else {
                LogicalDeviceType::EndDevice
            },
            capability.rx_on_when_idle(),
            relationship,
            ctx.lqi,
        );
        if let Some(old) = &existing {
            e.device_timeout_secs = old.device_timeout_secs;
            e.timeout_counter_secs = old.device_timeout_secs;
            e.end_device_configuration = old.end_device_configuration;
        }
        if e.device_timeout_secs == 0 {
            e.set_timeout(self.nib.end_device_timeout_default);
        }
        if !secured {
            e.security_timer_secs =
                u16::try_from(constants::SECURITY_TIMEOUT.as_secs()).unwrap_or(10);
        }
        e.outgoing_cost = 1;
        if !self.ensure_neighbor(e) {
            self.send_attach_response(
                ctx,
                device,
                requested,
                MacStatus::PanAtCapacity,
                commissioning,
            );
            return;
        }
        let _ = self.routes.remove(assigned);
        let _ = self.address_map.record(device, assigned);
        if let Some((_, tlvs)) = commissioning_info {
            self.pending_joiner_tlvs = Some(tlvs);
        }
        self.send_attach_success(ctx, device, assigned, method);
    }

    fn send_attach_response(
        &mut self,
        ctx: &CommandContext,
        device: ExtendedAddress,
        address: ShortAddress,
        status: MacStatus,
        commissioning: bool,
    ) {
        if commissioning {
            self.send_commissioning_response(ctx, device, address, status, None);
        } else {
            self.send_rejoin_response(ctx, device, address, status, None);
        }
    }

    /// Sends the successful attach response; the join indication follows
    /// once the response is delivered.
    fn send_attach_success(
        &mut self,
        ctx: &CommandContext,
        device: ExtendedAddress,
        address: ShortAddress,
        method: JoinMethod,
    ) {
        if matches!(
            method,
            JoinMethod::CommissioningJoin
                | JoinMethod::CommissioningRejoinSecured
                | JoinMethod::CommissioningRejoinUnsecured
        ) {
            self.send_commissioning_response(
                ctx,
                device,
                address,
                MacStatus::Success,
                Some(method),
            );
        } else {
            self.send_rejoin_response(ctx, device, address, MacStatus::Success, Some(method));
        }
    }

    fn attach_response_header(
        &mut self,
        ctx: &CommandContext,
        device: ExtendedAddress,
    ) -> Header<'static> {
        let seq = self.nib.next_sequence();
        Header::new(
            FrameType::Command,
            ctx.src,
            self.nib.network_address,
            1,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .with_dst_ieee(device)
        .secured(ctx.secured && self.config.security_enabled)
    }

    fn send_rejoin_response(
        &mut self,
        ctx: &CommandContext,
        device: ExtendedAddress,
        address: ShortAddress,
        status: MacStatus,
        method: Option<JoinMethod>,
    ) {
        let header = self.attach_response_header(ctx, device);
        let cmd = NwkCommand::RejoinResponse(RejoinResponse { address, status });
        let indirect = !self
            .neighbors
            .by_extended(device)
            .is_some_and(|n| n.rx_on_when_idle);
        let kind = match method {
            Some(method) if status == MacStatus::Success => TxKind::JoinResponse { device, method },
            _ => TxKind::Command,
        };
        let _ = self.send_command_unicast(&header, &cmd, ctx.src, ctx.secured, indirect, kind);
    }

    fn send_commissioning_response(
        &mut self,
        ctx: &CommandContext,
        device: ExtendedAddress,
        address: ShortAddress,
        status: MacStatus,
        method: Option<JoinMethod>,
    ) {
        let header = self.attach_response_header(ctx, device);
        let cmd = NwkCommand::CommissioningResponse(CommissioningResponse {
            address,
            status,
            tlvs: &[],
        });
        let indirect = !self
            .neighbors
            .by_extended(device)
            .is_some_and(|n| n.rx_on_when_idle);
        let kind = match method {
            Some(method) if status == MacStatus::Success => TxKind::JoinResponse { device, method },
            _ => TxKind::Command,
        };
        let _ = self.send_command_unicast(&header, &cmd, ctx.src, ctx.secured, indirect, kind);
    }

    /// Marks a child as authenticated once a secured frame from it is
    /// seen or the higher layer reports the key was delivered
    /// (§3.6.1.6.1.3).
    pub fn authenticate_child(&mut self, device: ExtendedAddress) {
        if let Some(n) = self.neighbors.by_extended_mut(device)
            && matches!(
                n.relationship,
                Relationship::UnauthenticatedChild | Relationship::UnauthorizedChildRelayAllowed
            )
        {
            n.relationship = Relationship::Child;
            n.security_timer_secs = 0;
            self.push_action(NwkAction::Persist);
        }
    }

    /// Extends the security timer of an unauthenticated child while the
    /// higher layer is still authorising it.
    pub fn refresh_child_security_timer(&mut self, device: ExtendedAddress) {
        if let Some(n) = self.neighbors.by_extended_mut(device)
            && n.relationship == Relationship::UnauthenticatedChild
        {
            n.security_timer_secs =
                u16::try_from(constants::SECURITY_TIMEOUT.as_secs()).unwrap_or(10);
        }
    }

    /// Records the joiner TLVs and neighbor for a child attached via a
    /// trusted link (Zigbee Direct); not used on plain radios.
    pub fn set_distributed(&mut self, distributed: bool) {
        self.distributed_network = distributed;
    }

    // ------------------------------------------------------------------
    // Leaving (§3.6.1.11)
    // ------------------------------------------------------------------

    /// NLME-LEAVE.request. `device == None` removes the local device; a
    /// child's extended address removes that child.
    ///
    /// May transmit; persists.
    pub fn leave(
        &mut self,
        device: Option<ExtendedAddress>,
        rejoin: bool,
        remove_children: bool,
    ) -> Result<(), NwkError> {
        if !self.nib.joined {
            return Err(NwkError::InvalidRequest);
        }
        let device = device.filter(|d| *d != self.nib.ieee_address);
        match device {
            None => {
                let seq = self.nib.next_sequence();
                let (dst, mac_dst) = if self.nib.is_end_device() {
                    (self.nib.parent_address, self.nib.parent_address)
                } else {
                    (ShortAddress::BROADCAST_ALL, ShortAddress::BROADCAST_ALL)
                };
                let header = Header::new(FrameType::Command, dst, self.nib.network_address, 1, seq)
                    .with_src_ieee(self.nib.ieee_address)
                    .secured(self.config.security_enabled);
                let cmd = NwkCommand::Leave(Leave {
                    rejoin,
                    request: false,
                    remove_children: remove_children && !self.nib.is_end_device(),
                });
                self.leaving_rejoin = Some(rejoin);
                if self.nib.is_end_device() {
                    if self
                        .send_command_unicast(
                            &header,
                            &cmd,
                            mac_dst,
                            true,
                            false,
                            TxKind::Leave { device: None },
                        )
                        .is_err()
                    {
                        self.on_leave_sent(None, NwkStatus::Success);
                    }
                } else {
                    let _ = self.send_command_broadcast_once(&header, &cmd, true);
                    self.on_leave_sent(None, NwkStatus::Success);
                }
                Ok(())
            }
            Some(child) => {
                if !self.nib.is_router_or_coordinator() {
                    return Err(NwkError::InvalidRequest);
                }
                let Some(n) = self.neighbors.by_extended(child) else {
                    return Err(NwkError::InvalidParameter);
                };
                if !n.relationship.is_child() {
                    return Err(NwkError::InvalidParameter);
                }
                if n.relationship == Relationship::UnauthenticatedChild {
                    let short = n.short;
                    self.remove_child(child);
                    self.push_event(NwkEvent::LeaveConfirm {
                        device: Some(child),
                        short: Some(short),
                        status: NwkStatus::Success,
                    });
                    return Ok(());
                }
                let short = n.short;
                let indirect = n.is_end_device() && !n.rx_on_when_idle;
                let seq = self.nib.next_sequence();
                let header =
                    Header::new(FrameType::Command, short, self.nib.network_address, 1, seq)
                        .with_src_ieee(self.nib.ieee_address)
                        .with_dst_ieee(child)
                        .secured(self.config.security_enabled);
                let cmd = NwkCommand::Leave(Leave {
                    rejoin,
                    request: true,
                    remove_children,
                });
                self.send_command_unicast(
                    &header,
                    &cmd,
                    short,
                    true,
                    indirect,
                    TxKind::Leave {
                        device: Some(child),
                    },
                )
            }
        }
    }

    pub(crate) fn on_leave_sent(&mut self, device: Option<ExtendedAddress>, status: NwkStatus) {
        match device {
            None => {
                let rejoin = self.leaving_rejoin.take().unwrap_or(false);
                self.push_event(NwkEvent::LeaveConfirm {
                    device: None,
                    short: None,
                    status,
                });
                self.local_leave(rejoin);
            }
            Some(child) => {
                let short = self.neighbors.by_extended(child).map(|n| n.short);
                self.remove_child(child);
                self.push_event(NwkEvent::LeaveConfirm {
                    device: Some(child),
                    short,
                    status,
                });
            }
        }
    }

    /// Removes a child and everything that refers to it.
    pub(crate) fn remove_child(&mut self, child: ExtendedAddress) {
        if let Some(n) = self.neighbors.remove_extended(child) {
            let _ = self.routes.remove(n.short);
            self.address_map.remove_extended(child);
            self.security.incoming.remove(child);
            self.update_beacon_payload();
            self.push_action(NwkAction::Persist);
            self.push_event(NwkEvent::ChildRemoved { device: child });
        }
    }

    /// Local process for leaving the network (§3.6.1.11.4).
    pub(crate) fn local_leave(&mut self, rejoin: bool) {
        self.join = None;
        self.pending.clear();
        self.bcast_bufs.clear();
        self.pending_rreq.clear();
        self.rdt.clear();
        self.btt.clear();
        self.routes.clear();
        self.source_routes.clear();
        self.permit_until = None;
        self.link_status_due = None;
        self.power_delta_due = None;
        self.power_request = None;
        self.operating_since = None;
        self.keepalive_due = None;
        if rejoin {
            // Keep identity and keys for the rejoin (§3.6.1.11.4 step 1).
            self.nib.joined = false;
            self.nib.authenticated = false;
            self.nib.router_started = false;
            self.neighbors
                .retain(|n| n.relationship == Relationship::Parent);
        } else {
            self.neighbors.clear();
            self.address_map.clear();
            self.security.clear_keys();
            self.nib.clear_for_leave();
            self.push_action(NwkAction::MacSetPanId(PanId::BROADCAST));
            self.push_action(NwkAction::MacSetShortAddress(
                ShortAddress::NO_SHORT_ADDRESS,
            ));
        }
        self.push_action(NwkAction::MacSetPermit(false));
        self.push_action(NwkAction::Persist);
    }

    /// Leave command received (§3.6.1.11.3).
    pub(crate) fn on_leave_command(&mut self, ctx: &CommandContext, leave: Leave) {
        if !ctx.secured {
            return;
        }
        if !leave.request {
            // Announcement: the sender left.
            if let Some(src_ieee) = ctx.src_ieee {
                if let Some(n) = self.neighbors.by_extended(src_ieee)
                    && n.relationship == Relationship::Parent
                    && leave.remove_children
                {
                    // Our parent left with remove-children: we leave too.
                    self.push_event(NwkEvent::LeaveIndication {
                        device: Some(src_ieee),
                        short: Some(ctx.src),
                        child: false,
                        rejoin: leave.rejoin,
                    });
                    if self.nib.is_router_or_coordinator() {
                        let _ = self.leave(None, leave.rejoin, leave.remove_children);
                    } else {
                        self.push_event(NwkEvent::LeaveIndication {
                            device: None,
                            short: None,
                            child: false,
                            rejoin: leave.rejoin,
                        });
                        self.local_leave(leave.rejoin);
                    }
                    return;
                }
                let child = self
                    .neighbors
                    .by_extended(src_ieee)
                    .is_some_and(|n| n.relationship.is_child());
                self.push_event(NwkEvent::LeaveIndication {
                    device: Some(src_ieee),
                    short: Some(ctx.src),
                    child,
                    rejoin: leave.rejoin,
                });
                if child {
                    self.remove_child(src_ieee);
                } else {
                    self.neighbors.remove_extended(src_ieee);
                    self.address_map.remove_extended(src_ieee);
                }
            }
            return;
        }
        // Request to leave (§3.6.1.11.3.1).
        if self.nib.is_coordinator() || ctx.dst.is_broadcast() {
            return;
        }
        if self.nib.is_router_or_coordinator() {
            if !self.nib.leave_request_allowed {
                return;
            }
            if !leave.rejoin && !self.nib.leave_request_without_rejoin_allowed {
                return;
            }
            self.push_event(NwkEvent::LeaveIndication {
                device: None,
                short: None,
                child: false,
                rejoin: leave.rejoin,
            });
            let _ = self.leave(None, leave.rejoin, leave.remove_children);
            return;
        }
        // End device: only from the parent.
        let from_parent = self
            .neighbors
            .by_short(ctx.mac_src)
            .is_some_and(|n| n.relationship == Relationship::Parent);
        if !from_parent {
            return;
        }
        self.push_event(NwkEvent::LeaveIndication {
            device: None,
            short: None,
            child: false,
            rejoin: leave.rejoin,
        });
        self.local_leave(leave.rejoin);
    }

    /// Sends a Leave (request, rejoin) to an end device that is not our
    /// child but addressed us as its parent (§3.6.2.2, §3.6.10.4).
    pub(crate) fn send_leave_to_unknown_child(&mut self, target: ShortAddress) {
        let seq = self.nib.next_sequence();
        let header = Header::new(FrameType::Command, target, self.nib.network_address, 1, seq)
            .with_src_ieee(self.nib.ieee_address)
            .secured(self.config.security_enabled);
        let cmd = NwkCommand::Leave(Leave {
            rejoin: true,
            request: true,
            remove_children: false,
        });
        let _ = self.send_command_unicast(&header, &cmd, target, true, false, TxKind::Command);
    }

    // ------------------------------------------------------------------
    // Address conflicts (§3.6.1.10)
    // ------------------------------------------------------------------

    /// Our own address is in use elsewhere.
    pub(crate) fn on_local_address_conflict(&mut self) {
        if self.nib.is_coordinator() || !self.nib.is_router_or_coordinator() {
            return;
        }
        let old = self.nib.network_address;
        let Some(new) = self.allocate_address() else {
            return;
        };
        self.nib.network_address = new;
        self.push_action(NwkAction::MacSetShortAddress(new));
        self.push_action(NwkAction::Persist);
        self.broadcast_address_conflict(old);
        self.push_event(NwkEvent::NetworkStatus {
            address: new,
            code: NetworkStatusCode::NetworkAddressUpdate,
        });
    }

    /// Another device's address is used twice.
    pub(crate) fn on_remote_address_conflict(&mut self, short: ShortAddress) {
        if !self.nib.is_router_or_coordinator() {
            return;
        }
        if let Some(n) = self.neighbors.by_short(short)
            && n.relationship.is_child()
            && n.is_end_device()
        {
            let child = n.extended;
            self.reassign_child_address(child);
            return;
        }
        self.broadcast_address_conflict(short);
    }

    /// Network Status (address conflict) received for `short`.
    pub(crate) fn on_address_conflict_reported(&mut self, short: ShortAddress) {
        if short == self.nib.network_address {
            self.on_local_address_conflict();
        } else if let Some(n) = self.neighbors.by_short(short)
            && n.relationship.is_child()
            && n.is_end_device()
        {
            let child = n.extended;
            self.reassign_child_address(child);
        }
    }

    fn broadcast_address_conflict(&mut self, about: ShortAddress) {
        let seq = self.nib.next_sequence();
        let header = Header::new(
            FrameType::Command,
            ShortAddress::BROADCAST_RX_ON,
            self.nib.network_address,
            constants::DEFAULT_RADIUS,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        let cmd = NwkCommand::NetworkStatus(crate::command::NetworkStatus {
            status: NetworkStatusCode::AddressConflict,
            dst: about,
            tlvs: &[],
        });
        if let Ok((frame, header_len)) = Self::build_command(&header, &cmd) {
            let _ = self.originate_broadcast(frame, header_len, self.config.security_enabled);
        }
    }

    /// Assigns a new address to an end device child and informs it with an
    /// unsolicited (secured) Rejoin Response (§3.6.1.10.5).
    fn reassign_child_address(&mut self, child: ExtendedAddress) {
        let Some(new) = self.allocate_address() else {
            return;
        };
        let Some(n) = self.neighbors.by_extended_mut(child) else {
            return;
        };
        let old = n.short;
        n.short = new;
        let sleepy = !n.rx_on_when_idle;
        let _ = self.address_map.record(child, new);
        let seq = self.nib.next_sequence();
        let header = Header::new(FrameType::Command, old, self.nib.network_address, 1, seq)
            .with_src_ieee(self.nib.ieee_address)
            .with_dst_ieee(child)
            .secured(self.config.security_enabled);
        let cmd = NwkCommand::RejoinResponse(RejoinResponse {
            address: new,
            status: MacStatus::Success,
        });
        let _ = self.send_command_unicast(&header, &cmd, old, true, sleepy, TxKind::Command);
        self.push_action(NwkAction::Persist);
    }

    // ------------------------------------------------------------------
    // PAN ID conflict (§3.6.1.13)
    // ------------------------------------------------------------------

    /// Reports a PAN ID conflict to the network manager (§3.6.1.13.1).
    /// A PAN ID conflict was detected (§3.6.1.13.1): Revision 23 devices
    /// only count conflicts in `nwkPanIdConflictCount` (reported through
    /// Security_Get_Configuration, §2.3.4.2) and never send an unsolicited
    /// Network Report.
    pub(crate) fn report_pan_id_conflict(&mut self, _conflicting: PanId) {
        if !self.nib.joined || !self.nib.is_router_or_coordinator() {
            return;
        }
        self.nib.pan_id_conflict_count = self.nib.pan_id_conflict_count.saturating_add(1);
    }

    /// Network Report received by the network manager (§3.6.1.13.2): a
    /// legacy (pre-R23) device reported a conflict. The application is
    /// told through NLME-NETWORK-STATUS.indication (0x14) and decides;
    /// the PAN ID is never changed automatically.
    pub(crate) fn on_network_report(&mut self, ctx: &CommandContext, report: &NetworkReport<'_>) {
        if !ctx.secured || report.epid != self.nib.extended_pan_id {
            return;
        }
        if self.nib.manager_addr != self.nib.network_address {
            return;
        }
        if report.report_id != NetworkReport::PAN_ID_CONFLICT {
            return;
        }
        self.push_event(NwkEvent::NetworkStatus {
            address: ctx.src,
            code: NetworkStatusCode::PanIdConflictReport,
        });
    }

    /// Changes the network's PAN ID on the application's decision
    /// (§3.6.1.13.3): `nwkNextPanId` is used when staged, otherwise a
    /// random unused identifier; a Network Update is broadcast and the
    /// switch happens after `nwkNetworkBroadcastDeliveryTime`. Only the
    /// network manager may do this.
    pub fn change_pan_id(&mut self) -> Result<(), NwkError> {
        if !self.nib.joined || self.nib.manager_addr != self.nib.network_address {
            return Err(NwkError::InvalidRequest);
        }
        if self.pan_id_update.is_some() {
            return Err(NwkError::Busy);
        }
        let staged = self.nib.next_pan_id;
        let mut new = if staged != PanId::BROADCAST && staged != self.nib.pan_id {
            Some(staged)
        } else {
            None
        };
        if new.is_none() {
            for _ in 0..16 {
                let p = PanId(self.rng.next_u16());
                if p.is_valid_for_formation() && p != self.nib.pan_id {
                    new = Some(p);
                    break;
                }
            }
        }
        let Some(new_pan) = new else {
            return Err(NwkError::Busy);
        };
        let update_id = self.nib.update_id.wrapping_add(1);
        let seq = self.nib.next_sequence();
        let header = Header::new(
            FrameType::Command,
            ShortAddress::BROADCAST_ALL,
            self.nib.network_address,
            constants::DEFAULT_RADIUS,
            seq,
        )
        .with_src_ieee(self.nib.ieee_address)
        .secured(self.config.security_enabled);
        let cmd = NwkCommand::NetworkUpdate(NetworkUpdate {
            update_id: NetworkUpdate::PAN_ID_UPDATE,
            epid: self.nib.extended_pan_id,
            nwk_update_id: update_id,
            new_pan_id: new_pan,
        });
        if let Ok((frame, header_len)) = Self::build_command(&header, &cmd) {
            let _ = self.originate_broadcast(frame, header_len, self.config.security_enabled);
        }
        self.nib.next_pan_id = new_pan;
        self.pan_id_update = Some((
            new_pan,
            update_id,
            self.now + self.nib.network_broadcast_delivery_time,
        ));
        Ok(())
    }

    /// Network Update received (§3.6.1.13.4).
    pub(crate) fn on_network_update(&mut self, ctx: &CommandContext, upd: NetworkUpdate) {
        if !ctx.secured || upd.epid != self.nib.extended_pan_id {
            return;
        }
        if ctx.src != self.nib.manager_addr {
            return;
        }
        // A staged nwkNextPanId gates the update: only 0xFFFF (nothing
        // staged) or the staged value is accepted.
        if self.nib.next_pan_id != PanId::BROADCAST && self.nib.next_pan_id != upd.new_pan_id {
            return;
        }
        // Newer update id (8-bit wrap).
        if upd.nwk_update_id.wrapping_sub(self.nib.update_id) >= 0x80
            || upd.nwk_update_id == self.nib.update_id
        {
            return;
        }
        self.nib.next_pan_id = upd.new_pan_id;
        self.pan_id_update = Some((
            upd.new_pan_id,
            upd.nwk_update_id,
            self.now + self.nib.network_broadcast_delivery_time,
        ));
    }

    /// Applies a scheduled PAN ID change.
    pub(crate) fn service_pan_id_update(&mut self, now: Instant) {
        if let Some((pan, uid, at)) = self.pan_id_update
            && now.has_reached(at)
        {
            self.pan_id_update = None;
            self.nib.pan_id = pan;
            self.nib.update_id = uid;
            self.nib.next_pan_id = PanId::BROADCAST;
            self.push_action(NwkAction::MacSetPanId(pan));
            self.update_beacon_payload();
            self.push_action(NwkAction::Persist);
            self.push_event(NwkEvent::PanIdChanged { pan_id: pan });
            self.push_event(NwkEvent::NetworkStatus {
                address: self.nib.network_address,
                code: NetworkStatusCode::PanIdUpdate,
            });
        }
    }

    /// Validates a raw TLV set from a received join request for tests.
    #[doc(hidden)]
    pub fn validate_tlvs(bytes: &[u8]) -> bool {
        TlvSet::validate(bytes, |_| false).is_ok()
    }
}

/// Lenient beacon payload decoding: accepts appendix bytes of any shape.
trait LenientDecode<'a>: Sized {
    fn decode_exact_lenient(bytes: &'a [u8]) -> Result<Self, ()>;
}

impl<'a> LenientDecode<'a> for BeaconPayload<'a> {
    fn decode_exact_lenient(bytes: &'a [u8]) -> Result<Self, ()> {
        panweave_codec::Decode::decode_exact(bytes).map_err(|_| ())
    }
}
