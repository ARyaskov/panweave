//! Frequency agility (R23.2 Annex E): interference reporting by routers
//! and the network channel manager's channel change.
//!
//! A router or coordinator tracks its unicast failures (`nwkTxTotal`,
//! `nwkTxFailures`). When the failure rate over the measurement window
//! passes the configured threshold it runs an energy scan over its
//! PHY's channels; if the channel in use is noisier than the quietest
//! alternative it sends a Mgmt_NWK_Unsolicited_Enhanced_Update_notify to
//! the network manager (at most four an hour) and restarts its
//! counters. The network manager receives such reports as
//! [`StackEvent::InterferenceReport`] and, when it decides to move the
//! network, [`Stack::change_network_channel`] broadcasts the channel
//! change (Mgmt_NWK_Update_req with ScanDuration 0xfe) and switches
//! itself after `nwkNetworkBroadcastDeliveryTime`; `apsChannelTimer`
//! then holds further changes back.

use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{Channel, ChannelMask, CryptoRng, LogicalDeviceType, NwkStatus, ShortAddress};
use panweave_zdo::zdp::{
    MgmtNwkUnsolicitedEnhancedUpdateNotify, MgmtNwkUpdateReq, ZdpStatus, cluster,
};

use crate::stack::{Phase, Stack, StackEvent};

/// How often the failure rate is examined.
const CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Reports allowed per hour (Annex E step 3).
const REPORTS_PER_HOUR: usize = 4;
/// Energy a channel must be quieter by, in energy-detect units, before
/// the channel in use counts as interfered.
const ENERGY_MARGIN: u8 = 10;
/// Energy detect scan duration exponent for the interference check.
const SCAN_DURATION: u8 = 3;

/// Interference reporting policy of a router or coordinator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InterferencePolicy {
    /// Report interference at all (an energy scan takes the device off
    /// the air for a moment).
    pub enabled: bool,
    /// Unicast transmissions needed before the rate is judged.
    pub min_transmissions: u16,
    /// Failure percentage that triggers the energy scan.
    pub failure_percent: u8,
}

impl Default for InterferencePolicy {
    fn default() -> Self {
        InterferencePolicy {
            enabled: true,
            min_transmissions: 20,
            failure_percent: 25,
        }
    }
}

/// Interference reporting state.
#[derive(Clone, Debug, Default)]
pub(crate) struct Interference {
    /// Next examination of the failure rate.
    pub next_check: Option<Instant>,
    /// An energy scan for the interference check is running.
    pub scanning: bool,
    /// When the current measurement window began.
    pub window_start: Option<Instant>,
    /// Instants of the reports sent within the last hour.
    pub reports: heapless::Vec<Instant, REPORTS_PER_HOUR>,
}

/// A channel change the network manager has broadcast, applied locally
/// after `nwkNetworkBroadcastDeliveryTime`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingChannelChange {
    pub at: Instant,
    pub channel: Channel,
    pub update_id: u8,
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Earliest timer of the frequency agility state.
    pub(crate) fn agility_deadline(&self) -> Option<Instant> {
        [
            self.interference.next_check,
            self.pending_channel_change.map(|p| p.at),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|t| t.as_millis())
    }

    /// Examines the failure rate (Annex E steps 1–3) and applies a
    /// pending channel change.
    pub(crate) fn poll_agility(&mut self, now: Instant) {
        if let Some(p) = self.pending_channel_change
            && now.has_reached(p.at)
        {
            self.pending_channel_change = None;
            self.nwk.change_channel(p.channel, p.update_id);
        }
        let policy = self.config.interference;
        let eligible = policy.enabled
            && self.phase == Phase::Operating
            && self.config.role != LogicalDeviceType::EndDevice;
        if !eligible {
            self.interference.next_check = None;
            return;
        }
        match self.interference.next_check {
            None => {
                self.interference.next_check = Some(now + CHECK_INTERVAL);
                self.interference.window_start.get_or_insert(now);
            }
            Some(t) if now.has_reached(t) => {
                self.interference.next_check = Some(now + CHECK_INTERVAL);
                self.check_interference(now);
            }
            Some(_) => {}
        }
    }

    fn check_interference(&mut self, now: Instant) {
        let policy = self.config.interference;
        let (total, failures) = (self.nwk.nib.tx_total, self.nwk.nib.tx_failures);
        let rate_high = total >= policy.min_transmissions
            && u32::from(failures) * 100 >= u32::from(policy.failure_percent) * u32::from(total);
        if !rate_high || self.interference.scanning || self.energy_scan.is_some() {
            return;
        }
        // Step 3: no more than four reports an hour.
        self.interference
            .reports
            .retain(|t| now.saturating_duration_since(*t) < Duration::from_secs(3600));
        if self.interference.reports.is_full() {
            return;
        }
        // Step 1: an energy scan across the PHY.
        if self
            .nwk
            .energy_scan(ChannelMask::ALL_2_4GHZ, SCAN_DURATION)
            .is_ok()
        {
            self.interference.scanning = true;
        }
    }

    /// The energy scan of an interference check finished: report when
    /// the channel in use is noisier than the quietest alternative
    /// (Annex E step 2); returns whether the confirm was consumed.
    pub(crate) fn on_interference_scan(&mut self, energy: &[u8; 27], now: Instant) -> bool {
        if !self.interference.scanning {
            return false;
        }
        self.interference.scanning = false;
        let current = self.nwk.nib.channel;
        let here = *energy.get(usize::from(current.raw())).unwrap_or(&0xff);
        let quietest = ChannelMask::ALL_2_4GHZ
            .iter()
            .filter(|c| *c != current)
            .map(|c| *energy.get(usize::from(c.raw())).unwrap_or(&0xff))
            .min()
            .unwrap_or(0xff);
        if here < quietest.saturating_add(ENERGY_MARGIN) {
            return true;
        }
        let window = self
            .interference
            .window_start
            .map_or(0, |s| now.saturating_duration_since(s).as_secs() / 60);
        let notify = MgmtNwkUnsolicitedEnhancedUpdateNotify {
            status: ZdpStatus::Success,
            channel_in_use: ChannelMask::EMPTY
                .with(current)
                .with_page(self.nwk.nib.channel_page),
            tx_total: self.nwk.nib.tx_total,
            tx_failures: self.nwk.nib.tx_failures,
            tx_retries: u16::try_from(self.mac.stats.tx_ucast_retry).unwrap_or(u16::MAX),
            period_minutes: u8::try_from(window).unwrap_or(u8::MAX),
        };
        let manager = self.nwk.nib.manager_addr;
        if self
            .zdo
            .unsolicited_enhanced_update_notify(manager, &notify)
            .is_ok()
        {
            let _ = self.interference.reports.push(now);
            // The counters restart with the report (Annex E step 2).
            self.nwk.nib.tx_total = 0;
            self.nwk.nib.tx_failures = 0;
            self.interference.window_start = Some(now);
            self.push_event(StackEvent::InterferenceReported {
                manager,
                energy: here,
            });
        }
        true
    }

    /// The network channel manager moves the network to `channel`
    /// (Annex E step 8): `nwkUpdateId` is incremented, Mgmt_NWK_Update_req
    /// (ScanDuration 0xfe) is broadcast to the rx-on devices and this
    /// device switches after `nwkNetworkBroadcastDeliveryTime`;
    /// `apsChannelTimer` (one hour by default) then refuses another
    /// change with `NotPermitted`. Only the network manager may call
    /// this (`InvalidRequest` otherwise).
    pub fn change_network_channel(&mut self, channel: Channel) -> Result<(), NwkStatus> {
        if self.phase != Phase::Operating
            || self.nwk.nib.manager_addr != self.nwk.nib.network_address
        {
            return Err(NwkStatus::InvalidRequest);
        }
        if !ChannelMask::ALL_2_4GHZ.contains(channel) {
            return Err(NwkStatus::InvalidParameter);
        }
        if self
            .channel_change_lockout
            .is_some_and(|t| !self.now.has_reached(t))
            || self.pending_channel_change.is_some()
        {
            return Err(NwkStatus::NotPermitted);
        }
        let update_id = self.nwk.nib.update_id.wrapping_add(1);
        let req = MgmtNwkUpdateReq {
            scan_channels: ChannelMask::EMPTY.with(channel),
            scan_duration: MgmtNwkUpdateReq::CHANNEL_CHANGE,
            scan_count: None,
            update_id: Some(update_id),
            manager: None,
        };
        self.zdo
            .request(
                ShortAddress::BROADCAST_RX_ON,
                cluster::MGMT_NWK_UPDATE_REQ,
                &req,
            )
            .map_err(|_| NwkStatus::InvalidRequest)?;
        let hours = u64::from(self.aps.aib.channel_timer_hours.unwrap_or(1).clamp(1, 24));
        self.channel_change_lockout = Some(self.now + Duration::from_secs(hours * 3600));
        self.pending_channel_change = Some(PendingChannelChange {
            at: self.now + self.nwk.nib.network_broadcast_delivery_time,
            channel,
            update_id,
        });
        self.pump();
        Ok(())
    }
}
