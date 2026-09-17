//! The MAC Interface Table (`nwkMacInterfaceTable`, R23.2 Table 3-69,
//! §3.6.12) and the NLME-SET-INTERFACE / NLME-GET-INTERFACE primitives
//! (§3.2.2.34 – §3.2.2.37): which radio interfaces the network layer
//! may use, their supported channels, the channel in use, whether
//! routers may join through them, and the per-interface counters the
//! application reads (and thereby resets).
//!
//! A single-radio device has one entry, index 0, covering its band;
//! a Zigbee Direct device adds a Trusted Link entry per authenticated
//! BLE connection. Enabling and disabling an interface here changes
//! what the layer scans, joins and forms on; the radio itself is the
//! runtime's to switch.

use heapless::Vec;
use panweave_types::{Channel, ChannelMask, ChannelPage};

/// Largest interface index (Table 3-39).
pub const MAX_INDEX: u8 = 31;
/// Largest link cost scalar (Table 3-69).
pub const MAX_LINK_COST_SCALAR: u8 = 34;

/// Interface type (Table 3-69 `Type`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterfaceType {
    /// An IEEE 802.15.4 radio.
    #[default]
    ZigbeeLink,
    /// A Zigbee Direct BLE connection (`SupportedChannels` and
    /// `ChannelInUse` are meaningless).
    TrustedLink,
}

/// Scan type used for NLME-NETWORK-AND-PARENT-DISCOVERY on the
/// interface (Table 3-69 `ScanType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ScanType {
    /// Beacon requests.
    #[default]
    Active,
    /// Enhanced beacon requests (Annex D.11.1).
    EnhancedActive,
}

/// Duty cycle thresholds in hundredths of a percent (Table 3-42); 0 =
/// no limit.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DutyCycleThresholds {
    /// Warning threshold.
    pub warning: u16,
    /// Critical threshold.
    pub critical: u16,
    /// Regulated threshold.
    pub regulated: u16,
}

/// The counters NLME-GET-INTERFACE.confirm returns and resets
/// (§3.2.2.37).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceCounters {
    /// `MacRxUcast`: unicast frames received.
    pub rx_ucast: u16,
    /// `MacTxUcastRetries`: MAC retries.
    pub tx_ucast_retries: u16,
    /// `MacTxUcastFailures`: failed transactions.
    pub tx_ucast_failures: u16,
    /// `MacTxUcastTotal`: transactions attempted (retries not counted).
    pub tx_ucast_total: u16,
}

/// One entry of the MAC Interface Table (Table 3-69).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MacInterfaceEntry {
    /// Unique index (0..=31).
    pub index: u8,
    /// Enabled for sending and receiving.
    pub state: bool,
    /// Supported channels, one mask per page (each with its page bits).
    pub supported_channels: Vec<ChannelMask, 4>,
    /// The channel in use (page and channel), when enabled.
    pub channel_in_use: Option<(ChannelPage, Channel)>,
    /// Routers may join through this interface.
    pub routers_allowed: bool,
    /// `nwkLinkPowerDeltaTransmitRate`, seconds (0 = never).
    pub link_power_delta_transmit_rate: u16,
    /// Beacons supported.
    pub beacons_supported: bool,
    /// Enhanced beacons supported.
    pub enhanced_beacons_supported: bool,
    /// Scan type for discovery.
    pub scan_type: ScanType,
    /// Scales every link cost on the interface (1..=34, default 1).
    pub link_cost_scalar: u8,
    /// Zigbee link or Trusted Link.
    pub kind: InterfaceType,
    /// The BLE connection handle of a Trusted Link.
    pub ble_connection_handle: u16,
    /// Power negotiation supported (Table 3-42).
    pub power_negotiation_supported: bool,
    /// Duty cycle thresholds.
    pub duty_cycle: DutyCycleThresholds,
    /// Counters since the last NLME-GET-INTERFACE.
    pub counters: InterfaceCounters,
}

impl MacInterfaceEntry {
    /// An enabled 802.15.4 interface with the given supported channels
    /// and defaults for everything else.
    pub fn radio(index: u8, supported: ChannelMask) -> Self {
        let mut supported_channels = Vec::new();
        let _ = supported_channels.push(supported);
        MacInterfaceEntry {
            index,
            state: true,
            supported_channels,
            channel_in_use: None,
            routers_allowed: true,
            link_power_delta_transmit_rate: 16,
            beacons_supported: true,
            enhanced_beacons_supported: false,
            scan_type: ScanType::Active,
            link_cost_scalar: 1,
            kind: InterfaceType::ZigbeeLink,
            ble_connection_handle: 0,
            power_negotiation_supported: false,
            duty_cycle: DutyCycleThresholds::default(),
            counters: InterfaceCounters::default(),
        }
    }

    /// A Trusted Link entry for a Zigbee Direct BLE connection.
    pub fn trusted_link(index: u8, ble_connection_handle: u16) -> Self {
        MacInterfaceEntry {
            supported_channels: Vec::new(),
            beacons_supported: false,
            kind: InterfaceType::TrustedLink,
            ble_connection_handle,
            ..Self::radio(index, ChannelMask::EMPTY)
        }
    }

    /// Whether the interface supports `channel` on `page`.
    pub fn supports(&self, page: ChannelPage, channel: Channel) -> bool {
        self.supported_channels
            .iter()
            .any(|m| m.page() == page && m.contains(channel))
    }

    /// The supported channels on `page`.
    pub fn supported_on(&self, page: ChannelPage) -> ChannelMask {
        self.supported_channels
            .iter()
            .find(|m| m.page() == page)
            .map_or(ChannelMask::EMPTY, |m| m.channels_only())
    }
}

/// NLME-SET-INTERFACE.request parameters (Table 3-39).
#[derive(Clone, Debug)]
pub struct SetInterface {
    /// The interface.
    pub index: u8,
    /// Enable or disable.
    pub state: bool,
    /// A single channel to use (page and channel); `None` = unspecified.
    pub channel_to_use: Option<(ChannelPage, Channel)>,
    /// The complete set of channels supported by the interface; `None`
    /// keeps the current set.
    pub supported_channels: Option<Vec<ChannelMask, 4>>,
    /// Routers may join through this interface.
    pub routers_allowed: bool,
    /// Duty cycle thresholds (tenths of a percent in the request, Table
    /// 3-39; stored in hundredths).
    pub duty_cycle: DutyCycleThresholds,
    /// Link cost scalar (1..=34).
    pub link_cost_scalar: u8,
}

/// NLME-GET-INTERFACE.confirm (Table 3-42): the entry as read; the
/// counters are reset by the read.
#[derive(Clone, Debug)]
pub struct InterfaceInfo {
    /// The entry.
    pub entry: MacInterfaceEntry,
}

/// Why a request was refused (`INV_REQUESTTYPE`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterfaceError {
    /// No entry with that index.
    UnknownInterface,
    /// Disabling would leave no enabled interface (§3.2.2.34.3 step
    /// 2a).
    LastInterface,
    /// The channel is not a single supported channel (step 3a/3b).
    InvalidChannel,
    /// The link cost scalar is out of range, or the table is full.
    InvalidParameter,
}

/// The table.
#[derive(Clone, Debug, Default)]
pub struct MacInterfaceTable<const N: usize> {
    entries: Vec<MacInterfaceEntry, N>,
}

impl<const N: usize> MacInterfaceTable<N> {
    /// A table with one enabled radio interface (index 0).
    pub fn single(supported: ChannelMask) -> Self {
        let mut t = MacInterfaceTable {
            entries: Vec::new(),
        };
        let _ = t.entries.push(MacInterfaceEntry::radio(0, supported));
        t
    }

    /// The entries.
    pub fn iter(&self) -> impl Iterator<Item = &MacInterfaceEntry> {
        self.entries.iter()
    }

    /// The enabled entries.
    pub fn enabled(&self) -> impl Iterator<Item = &MacInterfaceEntry> {
        self.entries.iter().filter(|e| e.state)
    }

    /// The entry with `index`.
    pub fn get(&self, index: u8) -> Option<&MacInterfaceEntry> {
        self.entries.iter().find(|e| e.index == index)
    }

    /// The entry with `index`, mutable.
    pub fn get_mut(&mut self, index: u8) -> Option<&mut MacInterfaceEntry> {
        self.entries.iter_mut().find(|e| e.index == index)
    }

    /// Adds an entry (replacing one with the same index).
    pub fn insert(&mut self, entry: MacInterfaceEntry) -> Result<(), InterfaceError> {
        if entry.index > MAX_INDEX {
            return Err(InterfaceError::InvalidParameter);
        }
        if let Some(e) = self.get_mut(entry.index) {
            *e = entry;
            return Ok(());
        }
        self.entries
            .push(entry)
            .map_err(|_| InterfaceError::InvalidParameter)
    }

    /// Removes an entry (a closed Trusted Link).
    pub fn remove(&mut self, index: u8) -> bool {
        match self.entries.iter().position(|e| e.index == index) {
            Some(i) => {
                let _ = self.entries.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// NLME-SET-INTERFACE.request (§3.2.2.34.3).
    pub fn set_interface(&mut self, req: &SetInterface) -> Result<(), InterfaceError> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.index == req.index)
            .ok_or(InterfaceError::UnknownInterface)?;
        if !req.state {
            // Step 2a: some other interface must stay enabled.
            if !self.entries.iter().any(|e| e.index != req.index && e.state) {
                return Err(InterfaceError::LastInterface);
            }
            let e = &mut self.entries[pos];
            e.state = false;
            e.channel_in_use = None;
            return Ok(());
        }
        if !(1..=MAX_LINK_COST_SCALAR).contains(&req.link_cost_scalar) {
            return Err(InterfaceError::InvalidParameter);
        }
        // Step 3a/3b: a single channel the interface supports.
        let supported = req
            .supported_channels
            .clone()
            .unwrap_or_else(|| self.entries[pos].supported_channels.clone());
        let e = &mut self.entries[pos];
        if e.kind == InterfaceType::ZigbeeLink {
            let Some((page, channel)) = req.channel_to_use else {
                return Err(InterfaceError::InvalidChannel);
            };
            if !supported
                .iter()
                .any(|m| m.page() == page && m.contains(channel))
            {
                return Err(InterfaceError::InvalidChannel);
            }
            e.channel_in_use = Some((page, channel));
        }
        // Step 3c.
        e.supported_channels = supported;
        e.state = true;
        e.routers_allowed = req.routers_allowed;
        e.link_cost_scalar = req.link_cost_scalar;
        e.duty_cycle = DutyCycleThresholds {
            warning: req.duty_cycle.warning.saturating_mul(10),
            critical: req.duty_cycle.critical.saturating_mul(10),
            regulated: req.duty_cycle.regulated.saturating_mul(10),
        };
        Ok(())
    }

    /// NLME-GET-INTERFACE.request (§3.2.2.36.3, §3.2.2.37): the entry,
    /// with its counters reset for the next read.
    pub fn get_interface(&mut self, index: u8) -> Result<InterfaceInfo, InterfaceError> {
        let e = self
            .get_mut(index)
            .ok_or(InterfaceError::UnknownInterface)?;
        let info = InterfaceInfo { entry: e.clone() };
        e.counters = InterfaceCounters::default();
        Ok(info)
    }

    /// The enabled radio interface that carries `channel` on `page`.
    pub fn interface_for(&self, page: ChannelPage, channel: Channel) -> Option<&MacInterfaceEntry> {
        self.enabled()
            .find(|e| e.kind == InterfaceType::ZigbeeLink && e.supports(page, channel))
    }

    /// The channels of `mask` (on its page) that some enabled radio
    /// interface supports (§3.2.2.3 / §3.2.2.5: the layer scans only
    /// those).
    pub fn supported_subset(&self, mask: ChannelMask) -> ChannelMask {
        let page = mask.page();
        let mut out = ChannelMask::EMPTY;
        for e in self.enabled() {
            if e.kind == InterfaceType::ZigbeeLink {
                out = ChannelMask(
                    out.raw() | (mask.channels_only().raw() & e.supported_on(page).raw()),
                );
            }
        }
        out.with_page(page)
    }

    /// A link cost scaled by the interface's `InterfaceLinkCostScalar`,
    /// capped at the maximum link cost 7 (§3.6.4.5.1.2).
    pub fn scaled_link_cost(&self, index: u8, cost: u8) -> u8 {
        let scalar = self.get(index).map_or(1, |e| e.link_cost_scalar.max(1));
        cost.saturating_mul(scalar).min(7)
    }

    /// Counts a unicast transmission on the interface.
    pub fn note_tx(&mut self, index: u8, retries: u16, failed: bool) {
        if let Some(e) = self.get_mut(index) {
            let c = &mut e.counters;
            c.tx_ucast_total = c.tx_ucast_total.saturating_add(1);
            c.tx_ucast_retries = c.tx_ucast_retries.saturating_add(retries);
            if failed {
                c.tx_ucast_failures = c.tx_ucast_failures.saturating_add(1);
            }
        }
    }

    /// Counts a unicast reception on the interface.
    pub fn note_rx(&mut self, index: u8) {
        if let Some(e) = self.get_mut(index) {
            e.counters.rx_ucast = e.counters.rx_ucast.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(n: u8) -> Channel {
        Channel::new_2_4ghz(n).unwrap()
    }

    #[test]
    fn set_and_get_interface_follow_3_2_2_34() {
        let mut t: MacInterfaceTable<4> = MacInterfaceTable::single(ChannelMask::ALL_2_4GHZ);
        assert_eq!(t.enabled().count(), 1);
        // Unknown index.
        let mut req = SetInterface {
            index: 5,
            state: true,
            channel_to_use: Some((ChannelPage::PAGE_0, ch(15))),
            supported_channels: None,
            routers_allowed: true,
            duty_cycle: DutyCycleThresholds {
                warning: 10,
                critical: 20,
                regulated: 30,
            },
            link_cost_scalar: 2,
        };
        assert_eq!(t.set_interface(&req), Err(InterfaceError::UnknownInterface));
        // The only interface cannot be disabled.
        req.index = 0;
        req.state = false;
        assert_eq!(t.set_interface(&req), Err(InterfaceError::LastInterface));
        // An unsupported channel is refused; a supported one is taken.
        req.state = true;
        req.channel_to_use = Some((ChannelPage(28), ch(15)));
        assert_eq!(t.set_interface(&req), Err(InterfaceError::InvalidChannel));
        req.channel_to_use = Some((ChannelPage::PAGE_0, ch(15)));
        t.set_interface(&req).unwrap();
        let e = t.get(0).unwrap();
        assert_eq!(e.channel_in_use, Some((ChannelPage::PAGE_0, ch(15))));
        assert_eq!(e.duty_cycle.warning, 100);
        assert_eq!(e.link_cost_scalar, 2);
        assert_eq!(t.scaled_link_cost(0, 3), 6);
        assert_eq!(t.scaled_link_cost(0, 5), 7);
        // Scalar range.
        req.link_cost_scalar = 40;
        assert_eq!(t.set_interface(&req), Err(InterfaceError::InvalidParameter));
        // A second interface lets the first be disabled.
        t.insert(MacInterfaceEntry::trusted_link(1, 0x0042))
            .unwrap();
        req.link_cost_scalar = 1;
        req.state = false;
        t.set_interface(&req).unwrap();
        assert!(!t.get(0).unwrap().state);
        assert!(t.get(0).unwrap().channel_in_use.is_none());
        assert_eq!(
            t.supported_subset(ChannelMask::ALL_2_4GHZ),
            ChannelMask::EMPTY
        );
        req.state = true;
        t.set_interface(&req).unwrap();
        assert_eq!(
            t.supported_subset(ChannelMask::BDB_PRIMARY),
            ChannelMask::BDB_PRIMARY
        );
        assert!(t.interface_for(ChannelPage::PAGE_0, ch(11)).is_some());
        assert!(t.interface_for(ChannelPage(28), ch(11)).is_none());
        // Counters are returned and reset by a read.
        t.note_tx(0, 2, true);
        t.note_tx(0, 0, false);
        t.note_rx(0);
        let info = t.get_interface(0).unwrap();
        assert_eq!(
            info.entry.counters,
            InterfaceCounters {
                rx_ucast: 1,
                tx_ucast_retries: 2,
                tx_ucast_failures: 1,
                tx_ucast_total: 2
            }
        );
        assert_eq!(t.get(0).unwrap().counters, InterfaceCounters::default());
        assert_eq!(
            t.get_interface(9).map(|_| ()),
            Err(InterfaceError::UnknownInterface)
        );
        assert!(t.remove(1));
        assert!(!t.remove(1));
    }
}
