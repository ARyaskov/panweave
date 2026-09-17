//! Routing table (R23.2 §3.6.4.2, Table 3-77), route discovery table
//! (Table 3-79) and route record / source route table (Table 3-67).
//!
//! These are pure data structures; the routing algorithms live in
//! [`crate::layer`] and call into them.

use heapless::Vec;
use panweave_types::{Instant, ShortAddress};

use crate::frame::MAX_SOURCE_ROUTE_RELAYS;

/// Route status (Table 3-78).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RouteStatus {
    /// Active (0x0).
    Active,
    /// Discovery underway (0x1).
    DiscoveryUnderway,
    /// Discovery failed (0x2).
    DiscoveryFailed,
    /// Inactive (0x3).
    Inactive,
    /// Validation underway (0x4, legacy).
    ValidationUnderway,
}

impl RouteStatus {
    /// ZDP / wire value.
    pub const fn raw(self) -> u8 {
        match self {
            RouteStatus::Active => 0,
            RouteStatus::DiscoveryUnderway => 1,
            RouteStatus::DiscoveryFailed => 2,
            RouteStatus::Inactive => 3,
            RouteStatus::ValidationUnderway => 4,
        }
    }
}

/// A routing table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RouteEntry {
    /// Destination network address.
    pub destination: ShortAddress,
    /// Status.
    pub status: RouteStatus,
    /// The destination does not store source routes.
    pub no_route_cache: bool,
    /// The destination is a concentrator (many-to-one route).
    pub many_to_one: bool,
    /// A Route Record must precede the next data frame.
    pub route_record_required: bool,
    /// An expected periodic many-to-one route request was missed.
    pub expired: bool,
    /// Next hop.
    pub next_hop: ShortAddress,
    /// Routing sequence number (valid when `sequence_valid`).
    pub sequence: u16,
    /// `sequence` is valid.
    pub sequence_valid: bool,
    /// Path cost recorded when the route was learnt (used for the
    /// suitability comparison of §3.6.4.5.3).
    pub path_cost: u8,
    /// Total usage count (saturating).
    pub total_usage: u32,
    /// Recent activity counter (saturating; pre-loaded with the router age
    /// limit).
    pub recent_activity: u8,
    /// Deadline after which a many-to-one route is marked expired
    /// (§3.6.4.7); `None` when no concentrator discovery time applies.
    pub many_to_one_deadline: Option<Instant>,
}

impl RouteEntry {
    /// A fresh entry toward `destination` via `next_hop`.
    pub const fn new(
        destination: ShortAddress,
        next_hop: ShortAddress,
        status: RouteStatus,
        recent_activity: u8,
    ) -> Self {
        RouteEntry {
            destination,
            status,
            no_route_cache: false,
            many_to_one: false,
            route_record_required: false,
            expired: false,
            next_hop,
            sequence: 0,
            sequence_valid: false,
            path_cost: 0xFF,
            total_usage: 0,
            recent_activity,
            many_to_one_deadline: None,
        }
    }

    /// Records one use of the route for forwarding.
    pub fn touch(&mut self) {
        self.total_usage = self.total_usage.saturating_add(1);
        self.recent_activity = self.recent_activity.saturating_add(1);
    }
}

/// Fixed-capacity routing table.
#[derive(Clone, Debug, Default)]
pub struct RoutingTable<const N: usize> {
    entries: Vec<RouteEntry, N>,
}

impl<const N: usize> RoutingTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        RoutingTable {
            entries: Vec::new(),
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Iterates entries.
    pub fn iter(&self) -> impl Iterator<Item = &RouteEntry> {
        self.entries.iter()
    }

    /// Mutable iteration.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut RouteEntry> {
        self.entries.iter_mut()
    }

    /// Finds the entry for `destination`.
    pub fn get(&self, destination: ShortAddress) -> Option<&RouteEntry> {
        self.entries.iter().find(|e| e.destination == destination)
    }

    /// Finds the entry for `destination` (mutable).
    pub fn get_mut(&mut self, destination: ShortAddress) -> Option<&mut RouteEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.destination == destination)
    }

    /// True when a route can be established for `destination`: an entry
    /// exists or a slot is free (or reclaimable) — "routing table
    /// capacity" (§3.6.4.2).
    pub fn has_capacity_for(&self, destination: ShortAddress) -> bool {
        self.get(destination).is_some() || !self.entries.is_full() || self.evictable().is_some()
    }

    /// Index of the least valuable entry that may be overwritten
    /// (§3.6.4.8): lowest recent activity, then lowest total usage; never
    /// an entry with discovery underway.
    fn evictable(&self) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.status != RouteStatus::DiscoveryUnderway)
            .min_by_key(|(_, e)| (e.recent_activity, e.total_usage))
            .map(|(i, _)| i)
    }

    /// Inserts or replaces the entry for `entry.destination`, evicting per
    /// §3.6.4.8 when full. Returns `None` if no slot could be freed.
    pub fn insert(&mut self, entry: RouteEntry) -> Option<&mut RouteEntry> {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.destination == entry.destination)
        {
            self.entries[pos] = entry;
            return Some(&mut self.entries[pos]);
        }
        if self.entries.is_full() {
            let v = self.evictable()?;
            let _ = self.entries.swap_remove(v);
        }
        self.entries.push(entry).ok()?;
        let last = self.entries.len() - 1;
        Some(&mut self.entries[last])
    }

    /// Removes the entry for `destination`.
    pub fn remove(&mut self, destination: ShortAddress) -> Option<RouteEntry> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.destination == destination)?;
        Some(self.entries.swap_remove(pos))
    }

    /// Marks every route through `next_hop` inactive (§3.6.4.4.2,
    /// §3.6.4.5.2.1). Returns how many were affected.
    pub fn invalidate_via(&mut self, next_hop: ShortAddress) -> usize {
        let mut n = 0;
        for e in self
            .entries
            .iter_mut()
            .filter(|e| e.next_hop == next_hop && e.status == RouteStatus::Active)
        {
            e.status = RouteStatus::Inactive;
            n += 1;
        }
        n
    }

    /// Per `nwkLinkStatusPeriod` decay of recent activity (Table 3-77).
    pub fn link_status_tick(&mut self) {
        for e in &mut self.entries {
            e.recent_activity = e.recent_activity.saturating_sub(1);
        }
    }

    /// Marks many-to-one routes whose deadline passed as expired
    /// (§3.6.4.7).
    pub fn expire_many_to_one(&mut self, now: Instant) {
        for e in self.entries.iter_mut().filter(|e| e.many_to_one) {
            if let Some(d) = e.many_to_one_deadline
                && now.has_reached(d)
            {
                e.expired = true;
            }
        }
    }

    /// Clears the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Decides whether an advertised route may replace a local one
/// (§3.6.4.5.3 "Assessing Suitability of Incoming Route Information").
///
/// Returns true when the routing table should be updated with the
/// advertised route.
pub fn incoming_route_is_suitable(existing: Option<&RouteEntry>, advertised_cost: u8) -> bool {
    match existing {
        None => true,
        Some(e) => {
            // LoopFree: the advertised path cost must not exceed the local
            // route's cost (a strictly longer path could be a sub-section).
            if e.status == RouteStatus::Active {
                advertised_cost < e.path_cost
            } else {
                true
            }
        }
    }
}

/// A route discovery table entry (Table 3-79).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoveryEntry {
    /// Route request identifier.
    pub request_id: u8,
    /// Initiator of the route request.
    pub source: ShortAddress,
    /// Device that sent the lowest-cost route request so far.
    pub sender: ShortAddress,
    /// Accumulated cost from the source to this device.
    pub forward_cost: u8,
    /// Accumulated cost from this device to the destination (0xFF unknown).
    pub residual_cost: u8,
    /// Expiry.
    pub expires: Instant,
    /// Destination the discovery is for (kept so that expiry can clean the
    /// routing table, §3.6.4.5.1.7).
    pub destination: ShortAddress,
    /// The local device initiated this discovery.
    pub local: bool,
    /// Confirm already issued for a many-to-one entry.
    pub confirmed: bool,
}

/// Fixed-capacity route discovery table.
#[derive(Clone, Debug, Default)]
pub struct RouteDiscoveryTable<const N: usize> {
    entries: Vec<DiscoveryEntry, N>,
}

impl<const N: usize> RouteDiscoveryTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        RouteDiscoveryTable {
            entries: Vec::new(),
        }
    }

    /// Finds the entry for `(source, request_id)`.
    pub fn get(&self, source: ShortAddress, request_id: u8) -> Option<&DiscoveryEntry> {
        self.entries
            .iter()
            .find(|e| e.source == source && e.request_id == request_id)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, source: ShortAddress, request_id: u8) -> Option<&mut DiscoveryEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.source == source && e.request_id == request_id)
    }

    /// Inserts an entry, reusing an expired one when full ("route discovery
    /// table capacity", §3.6.4.2). Returns `None` when no capacity.
    pub fn insert(&mut self, entry: DiscoveryEntry, now: Instant) -> Option<&mut DiscoveryEntry> {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.source == entry.source && e.request_id == entry.request_id)
        {
            self.entries[pos] = entry;
            return Some(&mut self.entries[pos]);
        }
        if self.entries.is_full() {
            let pos = self
                .entries
                .iter()
                .position(|e| now.has_reached(e.expires))?;
            let _ = self.entries.swap_remove(pos);
        }
        self.entries.push(entry).ok()?;
        let last = self.entries.len() - 1;
        Some(&mut self.entries[last])
    }

    /// Removes and returns expired entries into `out`.
    pub fn expire<const M: usize>(&mut self, now: Instant, out: &mut Vec<DiscoveryEntry, M>) {
        self.entries.retain(|e| {
            if now.has_reached(e.expires) {
                let _ = out.push(*e);
                false
            } else {
                true
            }
        });
    }

    /// Removes the entry for `(source, request_id)`.
    pub fn remove(&mut self, source: ShortAddress, request_id: u8) -> Option<DiscoveryEntry> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.source == source && e.request_id == request_id)?;
        Some(self.entries.swap_remove(pos))
    }

    /// True when another discovery for `destination` is still pending.
    pub fn any_pending_for(&self, destination: ShortAddress) -> bool {
        self.entries.iter().any(|e| e.destination == destination)
    }

    /// Iterates entries.
    pub fn iter(&self) -> impl Iterator<Item = &DiscoveryEntry> {
        self.entries.iter()
    }

    /// Earliest expiry.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.entries.iter().map(|e| e.expires).min()
    }

    /// Clears the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A stored source route toward `destination` (Table 3-67).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SourceRouteEntry {
    /// Destination.
    pub destination: ShortAddress,
    /// Relays in the order they must appear in the source route subframe
    /// (nearest the destination first).
    pub relays: Vec<ShortAddress, MAX_SOURCE_ROUTE_RELAYS>,
}

/// Route record (source route) table maintained by concentrators.
#[derive(Clone, Debug, Default)]
pub struct SourceRouteTable<const N: usize> {
    entries: Vec<SourceRouteEntry, N>,
}

impl<const N: usize> SourceRouteTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        SourceRouteTable {
            entries: Vec::new(),
        }
    }

    /// Finds the route toward `destination`.
    pub fn get(&self, destination: ShortAddress) -> Option<&SourceRouteEntry> {
        self.entries.iter().find(|e| e.destination == destination)
    }

    /// Stores a route learnt from a Route Record whose relay list is in
    /// append order (first relay after the originator first). Existing
    /// routes to the destination are replaced (§3.6.4.5.5). When full, the
    /// oldest entry is dropped.
    pub fn store_from_record(
        &mut self,
        destination: ShortAddress,
        relays_in_record_order: impl Iterator<Item = ShortAddress>,
    ) -> bool {
        let mut relays: Vec<ShortAddress, MAX_SOURCE_ROUTE_RELAYS> = Vec::new();
        for r in relays_in_record_order {
            if relays.push(r).is_err() {
                return false;
            }
        }
        // The record lists relays from the originator outward; the source
        // route subframe wants nearest-destination first, which is the same
        // order (the relay adjacent to the originator/destination is first).
        let entry = SourceRouteEntry {
            destination,
            relays,
        };
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.destination == destination)
        {
            self.entries[pos] = entry;
            return true;
        }
        if self.entries.is_full() {
            let _ = self.entries.remove(0);
        }
        self.entries.push(entry).is_ok()
    }

    /// Removes the route toward `destination`.
    pub fn remove(&mut self, destination: ShortAddress) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.destination != destination);
        before != self.entries.len()
    }

    /// Clears the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_table_insert_and_eviction() {
        let mut t = RoutingTable::<2>::new();
        let mut a = RouteEntry::new(ShortAddress(1), ShortAddress(10), RouteStatus::Active, 3);
        a.touch();
        t.insert(a).unwrap();
        t.insert(RouteEntry::new(
            ShortAddress(2),
            ShortAddress(10),
            RouteStatus::Active,
            3,
        ))
        .unwrap();
        // Full: evict the least recently active (destination 2).
        t.insert(RouteEntry::new(
            ShortAddress(3),
            ShortAddress(11),
            RouteStatus::Active,
            3,
        ))
        .unwrap();
        assert!(t.get(ShortAddress(2)).is_none());
        assert!(t.get(ShortAddress(1)).is_some());
        assert_eq!(t.invalidate_via(ShortAddress(10)), 1);
        assert_eq!(
            t.get(ShortAddress(1)).unwrap().status,
            RouteStatus::Inactive
        );
        // Entries in discovery are never evicted.
        let mut u = RoutingTable::<1>::new();
        u.insert(RouteEntry::new(
            ShortAddress(1),
            ShortAddress(1),
            RouteStatus::DiscoveryUnderway,
            3,
        ))
        .unwrap();
        assert!(
            u.insert(RouteEntry::new(
                ShortAddress(2),
                ShortAddress(1),
                RouteStatus::Active,
                3
            ))
            .is_none()
        );
        assert!(!u.has_capacity_for(ShortAddress(2)));
        assert!(u.has_capacity_for(ShortAddress(1)));
    }

    #[test]
    fn suitability_rules() {
        assert!(incoming_route_is_suitable(None, 9));
        let mut e = RouteEntry::new(ShortAddress(1), ShortAddress(2), RouteStatus::Active, 3);
        e.path_cost = 5;
        assert!(incoming_route_is_suitable(Some(&e), 4));
        assert!(!incoming_route_is_suitable(Some(&e), 5));
        assert!(!incoming_route_is_suitable(Some(&e), 6));
        e.status = RouteStatus::Inactive;
        assert!(incoming_route_is_suitable(Some(&e), 9));
    }

    #[test]
    fn discovery_table_expiry_and_reuse() {
        let mut t = RouteDiscoveryTable::<1>::new();
        let now = Instant::from_millis(0);
        let e = DiscoveryEntry {
            request_id: 1,
            source: ShortAddress(1),
            sender: ShortAddress(1),
            forward_cost: 0,
            residual_cost: 0xFF,
            expires: now + panweave_types::Duration::from_secs(10),
            destination: ShortAddress(9),
            local: true,
            confirmed: false,
        };
        t.insert(e, now).unwrap();
        let e2 = DiscoveryEntry { request_id: 2, ..e };
        assert!(t.insert(e2, now).is_none(), "full and nothing expired");
        let later = now + panweave_types::Duration::from_secs(10);
        assert!(t.insert(e2, later).is_some(), "expired entry reused");
        assert!(t.get(ShortAddress(1), 1).is_none());
        let mut out = Vec::<DiscoveryEntry, 4>::new();
        t.expire(later + panweave_types::Duration::from_secs(10), &mut out);
        assert_eq!(out.len(), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn source_route_table() {
        let mut t = SourceRouteTable::<1>::new();
        assert!(t.store_from_record(
            ShortAddress(5),
            [ShortAddress(1), ShortAddress(2)].into_iter()
        ));
        assert_eq!(t.get(ShortAddress(5)).unwrap().relays.len(), 2);
        assert!(t.store_from_record(ShortAddress(6), [ShortAddress(3)].into_iter()));
        assert!(t.get(ShortAddress(5)).is_none(), "oldest dropped when full");
        assert!(t.remove(ShortAddress(6)));
        assert!(t.is_empty());
        let too_long = (0..13u16).map(ShortAddress);
        assert!(!t.store_from_record(ShortAddress(7), too_long));
    }
}
