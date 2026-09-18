//! Neighbor table (R23.2 §3.6.1.7, Table 3-75) and link cost estimation
//! (§3.6.3, §3.6.4.1, Table 3-76).
//!
//! The table is a fixed-capacity `heapless` vector. Eviction never removes
//! children or the parent; stale router neighbors (age beyond
//! `nwkRouterAgeLimit`) are the only candidates, in line with §3.6.4.4.4
//! and the safety rule in §3.6.4.4.3.1.

use heapless::Vec;
use panweave_types::{ExtendedAddress, LogicalDeviceType, ShortAddress};

use crate::command::TimeoutIndex;

/// Relationship between the local device and a neighbor (Table 3-75).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Relationship {
    /// The neighbor is the parent (0x00).
    Parent,
    /// The neighbor is a child (0x01).
    Child,
    /// Sibling router (0x02).
    Sibling,
    /// None of the above (0x03).
    None,
    /// Previous child (0x04).
    PreviousChild,
    /// Unauthenticated child (0x05).
    UnauthenticatedChild,
    /// Unauthorized child with relay allowed (0x06).
    UnauthorizedChildRelayAllowed,
    /// Lost child (0x07).
    LostChild,
    /// Child with address conflict (0x08).
    ChildAddressConflict,
    /// Backbone mesh sibling (0x09).
    BackboneMeshSibling,
}

impl Relationship {
    /// Wire/ZDP value.
    pub const fn raw(self) -> u8 {
        match self {
            Relationship::Parent => 0,
            Relationship::Child => 1,
            Relationship::Sibling => 2,
            Relationship::None => 3,
            Relationship::PreviousChild => 4,
            Relationship::UnauthenticatedChild => 5,
            Relationship::UnauthorizedChildRelayAllowed => 6,
            Relationship::LostChild => 7,
            Relationship::ChildAddressConflict => 8,
            Relationship::BackboneMeshSibling => 9,
        }
    }

    /// True for any child relationship (authenticated or not).
    pub const fn is_child(self) -> bool {
        matches!(
            self,
            Relationship::Child
                | Relationship::UnauthenticatedChild
                | Relationship::UnauthorizedChildRelayAllowed
                | Relationship::ChildAddressConflict
        )
    }

    /// True for an authenticated child.
    pub const fn is_authenticated_child(self) -> bool {
        matches!(self, Relationship::Child)
    }
}

/// Maps an LQA/LQI value to a link cost (Table 3-76).
#[inline]
pub const fn link_cost_from_lqa(lqa: u8) -> u8 {
    match lqa {
        193..=255 => 1,
        129..=192 => 2,
        97..=128 => 3,
        65..=96 => 4,
        33..=64 => 5,
        17..=32 => 6,
        _ => 7,
    }
}

/// Median-of-three LQA filter (§3.6.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LqaFilter {
    samples: [u8; 3],
    count: u8,
    next: u8,
}

impl LqaFilter {
    /// Filter with one initial sample.
    pub const fn new(first: u8) -> Self {
        LqaFilter {
            samples: [first, 0, 0],
            count: 1,
            next: 1,
        }
    }

    /// Adds a sample.
    pub fn push(&mut self, lqa: u8) {
        let idx = usize::from(self.next % 3);
        if let Some(s) = self.samples.get_mut(idx) {
            *s = lqa;
        }
        self.next = (self.next + 1) % 3;
        self.count = (self.count + 1).min(3);
    }

    /// The filtered value: the median of the available samples.
    pub fn value(&self) -> u8 {
        match self.count {
            0 => 0,
            1 => self.samples[0],
            2 => {
                let a = self.samples[0];
                let b = self.samples[1];
                // With two samples take the lower one (conservative).
                a.min(b)
            }
            _ => {
                let mut s = self.samples;
                s.sort_unstable();
                s[1]
            }
        }
    }

    /// Number of valid samples.
    pub const fn count(&self) -> u8 {
        self.count
    }
}

/// A neighbor table entry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NeighborEntry {
    /// Extended address.
    pub extended: ExtendedAddress,
    /// Network address.
    pub short: ShortAddress,
    /// Device type.
    pub device_type: LogicalDeviceType,
    /// Receiver on when idle.
    pub rx_on_when_idle: bool,
    /// End device configuration bitmask (§3.4.11.3.2).
    pub end_device_configuration: u8,
    /// Remaining time in seconds before an end device child ages out.
    pub timeout_counter_secs: u32,
    /// Negotiated device timeout in seconds (end device children).
    pub device_timeout_secs: u32,
    /// Relationship.
    pub relationship: Relationship,
    /// Transmit failure counter.
    pub transmit_failure: u8,
    /// Filtered LQA.
    pub lqa: LqaFilter,
    /// Outgoing cost reported by the neighbor (0 = unknown).
    pub outgoing_cost: u8,
    /// Link-status periods since the last link status from this router.
    pub age: u8,
    /// A keepalive has been received since reboot (end device children).
    pub keepalive_received: bool,
    /// Link-status periods since this router entry was added (saturating).
    pub router_age: u16,
    /// Seconds an unauthenticated child (or, on a joiner, the parent) may
    /// remain before the entry is dropped; 0 = not armed.
    pub security_timer_secs: u16,
    /// Router connectivity metric (§3.6.4.4.2).
    pub router_connectivity: u8,
    /// Router neighbor set diversity metric.
    pub router_neighbor_set_diversity: u8,
    /// Outbound activity counter.
    pub router_outbound_activity: u8,
    /// Inbound activity counter.
    pub router_inbound_activity: u8,
    /// The NWK key sequence number this neighbor last used (for
    /// diagnostics only).
    pub last_key_sequence: Option<u8>,
    /// RSSI of the last frame received from this neighbor, dBm (power
    /// negotiation, §3.4.13.7); volatile.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub last_rssi_dbm: Option<i8>,
    /// The Trusted Link (nwkMacInterfaceTable index) the neighbour is
    /// reached over instead of the radio (R23.2 §3.2.2.41, Zigbee Direct
    /// §7.7.4); volatile.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub link: Option<u8>,
}

impl NeighborEntry {
    /// Creates an entry with the given identity and relationship.
    pub fn new(
        extended: ExtendedAddress,
        short: ShortAddress,
        device_type: LogicalDeviceType,
        rx_on_when_idle: bool,
        relationship: Relationship,
        lqa: u8,
    ) -> Self {
        NeighborEntry {
            extended,
            short,
            device_type,
            rx_on_when_idle,
            end_device_configuration: 0,
            timeout_counter_secs: 0,
            device_timeout_secs: 0,
            relationship,
            transmit_failure: 0,
            lqa: LqaFilter::new(lqa),
            outgoing_cost: 0,
            age: 0,
            keepalive_received: false,
            router_age: 0,
            security_timer_secs: 0,
            router_connectivity: 0,
            router_neighbor_set_diversity: 0,
            router_outbound_activity: 0,
            router_inbound_activity: 0,
            last_key_sequence: None,
            last_rssi_dbm: None,
            link: None,
        }
    }

    /// Incoming link cost from the filtered LQA.
    #[inline]
    pub fn incoming_cost(&self) -> u8 {
        link_cost_from_lqa(self.lqa.value())
    }

    /// Cost used for path computations: the maximum of incoming and
    /// outgoing (§3.6.4.5.1.2), or 7 when the outgoing cost is unknown.
    #[inline]
    pub fn path_cost(&self) -> u8 {
        if self.outgoing_cost == 0 {
            7
        } else {
            self.incoming_cost().max(self.outgoing_cost)
        }
    }

    /// True for an end device.
    #[inline]
    pub const fn is_end_device(&self) -> bool {
        matches!(self.device_type, LogicalDeviceType::EndDevice)
    }

    /// True for a router or the coordinator.
    #[inline]
    pub const fn is_router(&self) -> bool {
        !self.is_end_device()
    }

    /// Sets the end device timeout from an enumeration value.
    pub fn set_timeout(&mut self, idx: TimeoutIndex) {
        if let Some(s) = idx.seconds() {
            self.device_timeout_secs = s;
            self.timeout_counter_secs = s;
        }
    }
}

/// Fixed-capacity neighbor table.
#[derive(Clone, Debug, Default)]
pub struct NeighborTable<const N: usize> {
    entries: Vec<NeighborEntry, N>,
    /// Entries added since start (Diagnostics `NeighborAdded`).
    pub added: u32,
    /// Entries removed since start (Diagnostics `NeighborRemoved`).
    pub removed: u32,
    /// Router entries that went stale (Diagnostics `NeighborStale`).
    pub stale: u32,
}

/// Why an insertion failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NeighborTableError {
    /// No free slot and nothing evictable.
    Full,
}

impl<const N: usize> NeighborTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        NeighborTable {
            entries: Vec::new(),
            added: 0,
            removed: 0,
            stale: 0,
        }
    }

    /// Capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates entries.
    pub fn iter(&self) -> impl Iterator<Item = &NeighborEntry> {
        self.entries.iter()
    }

    /// Mutable iteration.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut NeighborEntry> {
        self.entries.iter_mut()
    }

    /// Finds by extended address.
    pub fn by_extended(&self, addr: ExtendedAddress) -> Option<&NeighborEntry> {
        self.entries.iter().find(|e| e.extended == addr)
    }

    /// Finds by extended address (mutable).
    pub fn by_extended_mut(&mut self, addr: ExtendedAddress) -> Option<&mut NeighborEntry> {
        self.entries.iter_mut().find(|e| e.extended == addr)
    }

    /// Finds by short address.
    pub fn by_short(&self, addr: ShortAddress) -> Option<&NeighborEntry> {
        self.entries.iter().find(|e| e.short == addr)
    }

    /// Finds by short address (mutable).
    pub fn by_short_mut(&mut self, addr: ShortAddress) -> Option<&mut NeighborEntry> {
        self.entries.iter_mut().find(|e| e.short == addr)
    }

    /// The parent entry, if any.
    pub fn parent(&self) -> Option<&NeighborEntry> {
        self.entries
            .iter()
            .find(|e| e.relationship == Relationship::Parent)
    }

    /// Inserts or replaces the entry with the same extended address. When
    /// the table is full, a stale router entry (age > `router_age_limit`,
    /// not parent/child) is evicted; otherwise [`NeighborTableError::Full`].
    pub fn insert(
        &mut self,
        entry: NeighborEntry,
        router_age_limit: u8,
    ) -> Result<&mut NeighborEntry, NeighborTableError> {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.extended == entry.extended)
        {
            self.entries[pos] = entry;
            return Ok(&mut self.entries[pos]);
        }
        if self.entries.is_full() {
            let victim = self.entries.iter().position(|e| {
                e.is_router()
                    && e.age > router_age_limit
                    && !matches!(e.relationship, Relationship::Parent)
                    && !e.relationship.is_child()
            });
            match victim {
                Some(v) => {
                    let _ = self.entries.swap_remove(v);
                }
                None => return Err(NeighborTableError::Full),
            }
        }
        self.entries
            .push(entry)
            .map_err(|_| NeighborTableError::Full)?;
        self.added = self.added.saturating_add(1);
        let last = self.entries.len() - 1;
        Ok(&mut self.entries[last])
    }

    /// Removes the entry with `addr`.
    pub fn remove_extended(&mut self, addr: ExtendedAddress) -> Option<NeighborEntry> {
        let pos = self.entries.iter().position(|e| e.extended == addr)?;
        self.removed = self.removed.saturating_add(1);
        Some(self.entries.swap_remove(pos))
    }

    /// Removes the entry with `addr`.
    pub fn remove_short(&mut self, addr: ShortAddress) -> Option<NeighborEntry> {
        let pos = self.entries.iter().position(|e| e.short == addr)?;
        self.removed = self.removed.saturating_add(1);
        Some(self.entries.swap_remove(pos))
    }

    /// Removes entries matching `pred`.
    pub fn retain(&mut self, pred: impl FnMut(&NeighborEntry) -> bool) {
        let before = self.entries.len();
        self.entries.retain(pred);
        let gone = before.saturating_sub(self.entries.len());
        self.removed = self
            .removed
            .saturating_add(u32::try_from(gone).unwrap_or(u32::MAX));
    }

    /// Number of child entries (authenticated or not).
    pub fn child_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.relationship.is_child())
            .count()
    }

    /// Number of router children.
    pub fn router_child_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.relationship.is_child() && e.is_router())
            .count()
    }

    /// Iterates end device children.
    pub fn end_device_children(&self) -> impl Iterator<Item = &NeighborEntry> {
        self.entries
            .iter()
            .filter(|e| e.relationship.is_child() && e.is_end_device())
    }

    /// Iterates router neighbors (parent, siblings, router children).
    pub fn routers(&self) -> impl Iterator<Item = &NeighborEntry> {
        self.entries.iter().filter(|e| e.is_router())
    }

    /// Clears the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Applies one `nwkLinkStatusPeriod` tick (§3.6.4.4.4): increments
    /// ages of router neighbors, saturating; entries beyond the limit lose
    /// their outgoing cost. Returns the number of entries that became stale
    /// during this tick.
    pub fn link_status_tick(&mut self, router_age_limit: u8) -> usize {
        let mut newly_stale = 0;
        // A router behind a Trusted Link sends no Link Status; the link's
        // liveness is the host's (closing it removes the entry).
        for e in self
            .entries
            .iter_mut()
            .filter(|e| e.is_router() && e.link.is_none())
        {
            e.age = e.age.saturating_add(1);
            e.router_age = e.router_age.saturating_add(1);
            e.router_outbound_activity = e.router_outbound_activity.saturating_sub(1);
            e.router_inbound_activity = e.router_inbound_activity.saturating_sub(1);
            if e.age > router_age_limit && e.outgoing_cost != 0 {
                e.outgoing_cost = 0;
                newly_stale += 1;
            }
        }
        self.stale = self
            .stale
            .saturating_add(u32::try_from(newly_stale).unwrap_or(u32::MAX));
        newly_stale
    }

    /// Applies `elapsed_secs` to child timeout counters and security
    /// timers (§3.6.10.1). Returns the extended addresses of children that
    /// expired (removed from the table) in `expired`.
    pub fn age_children<const M: usize>(
        &mut self,
        elapsed_secs: u32,
        expired: &mut Vec<ExtendedAddress, M>,
    ) {
        if elapsed_secs == 0 {
            return;
        }
        let secs16 = u16::try_from(elapsed_secs).unwrap_or(u16::MAX);
        self.entries.retain(|e| {
            let mut keep = true;
            if e.security_timer_secs != 0 {
                let remaining = e.security_timer_secs.saturating_sub(secs16);
                if remaining == 0
                    && matches!(
                        e.relationship,
                        Relationship::UnauthenticatedChild
                            | Relationship::UnauthorizedChildRelayAllowed
                    )
                {
                    keep = false;
                }
            }
            if keep && e.relationship.is_authenticated_child() && e.is_end_device() {
                let remaining = e.timeout_counter_secs.saturating_sub(elapsed_secs);
                if remaining == 0 && e.device_timeout_secs != 0 {
                    keep = false;
                }
            }
            if !keep {
                let _ = expired.push(e.extended);
            }
            keep
        });
        self.removed = self
            .removed
            .saturating_add(u32::try_from(expired.len()).unwrap_or(u32::MAX));
        for e in self.entries.iter_mut() {
            if e.security_timer_secs != 0 {
                e.security_timer_secs = e.security_timer_secs.saturating_sub(secs16);
            }
            if e.relationship.is_authenticated_child() && e.is_end_device() {
                e.timeout_counter_secs = e.timeout_counter_secs.saturating_sub(elapsed_secs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u64, rel: Relationship, dt: LogicalDeviceType) -> NeighborEntry {
        NeighborEntry::new(
            ExtendedAddress(n),
            #[allow(clippy::cast_possible_truncation)]
            ShortAddress(n as u16),
            dt,
            true,
            rel,
            200,
        )
    }

    #[test]
    fn link_cost_table_3_76() {
        assert_eq!(link_cost_from_lqa(255), 1);
        assert_eq!(link_cost_from_lqa(193), 1);
        assert_eq!(link_cost_from_lqa(192), 2);
        assert_eq!(link_cost_from_lqa(129), 2);
        assert_eq!(link_cost_from_lqa(128), 3);
        assert_eq!(link_cost_from_lqa(97), 3);
        assert_eq!(link_cost_from_lqa(96), 4);
        assert_eq!(link_cost_from_lqa(65), 4);
        assert_eq!(link_cost_from_lqa(64), 5);
        assert_eq!(link_cost_from_lqa(33), 5);
        assert_eq!(link_cost_from_lqa(32), 6);
        assert_eq!(link_cost_from_lqa(17), 6);
        assert_eq!(link_cost_from_lqa(16), 7);
        assert_eq!(link_cost_from_lqa(0), 7);
    }

    #[test]
    fn lqa_median_filter() {
        let mut f = LqaFilter::new(200);
        assert_eq!(f.value(), 200);
        f.push(10);
        assert_eq!(f.value(), 10, "two samples: conservative");
        f.push(180);
        assert_eq!(f.value(), 180, "median of 200, 10, 180");
        f.push(190);
        assert_eq!(f.value(), 180, "median of 190, 10, 180");
        f.push(5);
        assert_eq!(
            f.value(),
            180,
            "median of 190, 5, 180: a single outlier is ignored"
        );
    }

    #[test]
    fn insert_evicts_only_stale_routers() {
        let mut t = NeighborTable::<2>::new();
        t.insert(
            entry(1, Relationship::Child, LogicalDeviceType::EndDevice),
            3,
        )
        .unwrap();
        t.insert(
            entry(2, Relationship::Sibling, LogicalDeviceType::Router),
            3,
        )
        .unwrap();
        assert!(
            t.insert(
                entry(3, Relationship::Sibling, LogicalDeviceType::Router),
                3
            )
            .is_err()
        );
        // Age the sibling beyond the limit.
        for _ in 0..4 {
            t.link_status_tick(3);
        }
        assert_eq!(t.by_extended(ExtendedAddress(2)).unwrap().outgoing_cost, 0);
        t.insert(
            entry(3, Relationship::Sibling, LogicalDeviceType::Router),
            3,
        )
        .unwrap();
        assert!(t.by_extended(ExtendedAddress(2)).is_none());
        assert!(
            t.by_extended(ExtendedAddress(1)).is_some(),
            "child never evicted"
        );
        assert_eq!(t.child_count(), 1);
    }

    #[test]
    fn child_aging_and_security_timer() {
        let mut t = NeighborTable::<4>::new();
        let mut child = entry(1, Relationship::Child, LogicalDeviceType::EndDevice);
        child.set_timeout(TimeoutIndex(0));
        t.insert(child, 3).unwrap();
        let mut unauth = entry(
            2,
            Relationship::UnauthenticatedChild,
            LogicalDeviceType::Router,
        );
        unauth.security_timer_secs = 10;
        t.insert(unauth, 3).unwrap();
        let mut expired = Vec::<ExtendedAddress, 4>::new();
        t.age_children(5, &mut expired);
        assert!(expired.is_empty());
        assert_eq!(
            t.by_extended(ExtendedAddress(1))
                .unwrap()
                .timeout_counter_secs,
            5
        );
        t.age_children(5, &mut expired);
        assert_eq!(expired.len(), 2);
        assert!(t.is_empty());
    }

    #[test]
    fn path_cost_uses_max_of_directions() {
        let mut e = entry(1, Relationship::Sibling, LogicalDeviceType::Router);
        assert_eq!(e.incoming_cost(), 1);
        assert_eq!(e.path_cost(), 7, "unknown outgoing cost");
        e.outgoing_cost = 3;
        assert_eq!(e.path_cost(), 3);
    }
}
