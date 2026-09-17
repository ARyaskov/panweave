//! APS tables: binding table (R23.2 §2.2.8.2), group table (§2.2.8.3) and
//! the duplicate rejection table (§2.2.8.4.2).
//!
//! All tables are fixed-capacity and heap-free; the capacities are const
//! generics chosen by the integrator.

use heapless::Vec;
use panweave_types::time::Instant;
use panweave_types::{ApsStatus, ClusterId, Endpoint, ExtendedAddress, GroupAddress, ShortAddress};

/// Destination of a binding link (§2.2.8.2.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BindingDestination {
    /// A specific endpoint on a specific device.
    Unicast {
        /// Destination device.
        address: ExtendedAddress,
        /// Destination endpoint.
        endpoint: Endpoint,
    },
    /// A group address.
    Group(GroupAddress),
}

/// One binding table entry: (source endpoint, cluster) → destination.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BindingEntry {
    /// Source endpoint on this device.
    pub src_endpoint: Endpoint,
    /// Cluster of the link.
    pub cluster: ClusterId,
    /// Destination.
    pub destination: BindingDestination,
}

/// The binding table (`apsBindingTable`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BindingTable<const N: usize> {
    entries: Vec<BindingEntry, N>,
}

impl<const N: usize> Default for BindingTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> BindingTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        BindingTable {
            entries: Vec::new(),
        }
    }

    /// APSME-BIND.request: adds an entry. Duplicate entries succeed
    /// without change (the mapping is a set).
    pub fn bind(&mut self, entry: BindingEntry) -> Result<(), ApsStatus> {
        if entry.src_endpoint == Endpoint(0) || entry.src_endpoint == Endpoint::BROADCAST {
            return Err(ApsStatus::IllegalRequest);
        }
        if let BindingDestination::Unicast { endpoint, .. } = entry.destination
            && (endpoint == Endpoint(0) || endpoint == Endpoint::BROADCAST)
        {
            return Err(ApsStatus::IllegalRequest);
        }
        if self.entries.contains(&entry) {
            return Ok(());
        }
        self.entries.push(entry).map_err(|_| ApsStatus::TableFull)
    }

    /// APSME-UNBIND.request: removes an entry.
    pub fn unbind(&mut self, entry: &BindingEntry) -> Result<(), ApsStatus> {
        match self.entries.iter().position(|e| e == entry) {
            Some(i) => {
                self.entries.swap_remove(i);
                Ok(())
            }
            None => Err(ApsStatus::InvalidBinding),
        }
    }

    /// Destinations bound to `(src_endpoint, cluster)`.
    pub fn destinations(
        &self,
        src_endpoint: Endpoint,
        cluster: ClusterId,
    ) -> impl Iterator<Item = BindingDestination> + '_ {
        self.entries
            .iter()
            .filter(move |e| e.src_endpoint == src_endpoint && e.cluster == cluster)
            .map(|e| e.destination)
    }

    /// Removes every entry that targets `address` (device left).
    pub fn remove_device(&mut self, address: ExtendedAddress) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| {
            !matches!(e.destination, BindingDestination::Unicast { address: a, .. } if a == address)
        });
        before - self.entries.len()
    }

    /// All entries.
    pub fn iter(&self) -> impl Iterator<Item = &BindingEntry> {
        self.entries.iter()
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

    /// Removes all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Endpoint membership bitmap for one group (endpoints 0x01–0xfe).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EndpointSet([u32; 8]);

impl EndpointSet {
    /// Empty set.
    pub const EMPTY: EndpointSet = EndpointSet([0; 8]);

    #[inline]
    const fn slot(ep: Endpoint) -> (usize, u32) {
        ((ep.0 / 32) as usize, 1u32 << (ep.0 % 32))
    }

    /// Membership test.
    #[inline]
    pub fn contains(&self, ep: Endpoint) -> bool {
        let (i, bit) = Self::slot(ep);
        self.0.get(i).is_some_and(|w| w & bit != 0)
    }

    /// Adds an endpoint.
    #[inline]
    pub fn insert(&mut self, ep: Endpoint) {
        let (i, bit) = Self::slot(ep);
        if let Some(w) = self.0.get_mut(i) {
            *w |= bit;
        }
    }

    /// Removes an endpoint.
    #[inline]
    pub fn remove(&mut self, ep: Endpoint) {
        let (i, bit) = Self::slot(ep);
        if let Some(w) = self.0.get_mut(i) {
            *w &= !bit;
        }
    }

    /// True when no endpoint is a member.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }

    /// Iterates member endpoints in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = Endpoint> + '_ {
        (0u16..=255)
            .map(|v| {
                #[allow(clippy::cast_possible_truncation)]
                Endpoint(v as u8)
            })
            .filter(move |ep| self.contains(*ep))
    }
}

/// One group table entry (Table 2-25).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupEntry {
    /// The group.
    pub group: GroupAddress,
    /// Member endpoints.
    pub endpoints: EndpointSet,
}

/// The group table (`apsGroupTable`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupTable<const N: usize> {
    entries: Vec<GroupEntry, N>,
}

impl<const N: usize> Default for GroupTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> GroupTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        GroupTable {
            entries: Vec::new(),
        }
    }

    /// APSME-ADD-GROUP.request.
    pub fn add(&mut self, group: GroupAddress, endpoint: Endpoint) -> Result<(), ApsStatus> {
        if endpoint == Endpoint(0) || endpoint == Endpoint::BROADCAST {
            return Err(ApsStatus::InvalidParameter);
        }
        if let Some(e) = self.entries.iter_mut().find(|e| e.group == group) {
            e.endpoints.insert(endpoint);
            return Ok(());
        }
        let mut endpoints = EndpointSet::EMPTY;
        endpoints.insert(endpoint);
        self.entries
            .push(GroupEntry { group, endpoints })
            .map_err(|_| ApsStatus::TableFull)
    }

    /// APSME-REMOVE-GROUP.request.
    pub fn remove(&mut self, group: GroupAddress, endpoint: Endpoint) -> Result<(), ApsStatus> {
        let Some(i) = self.entries.iter().position(|e| e.group == group) else {
            return Err(ApsStatus::InvalidGroup);
        };
        let Some(entry) = self.entries.get_mut(i) else {
            return Err(ApsStatus::InvalidGroup);
        };
        if !entry.endpoints.contains(endpoint) {
            return Err(ApsStatus::InvalidGroup);
        }
        entry.endpoints.remove(endpoint);
        if entry.endpoints.is_empty() {
            self.entries.swap_remove(i);
        }
        Ok(())
    }

    /// APSME-REMOVE-ALL-GROUPS.request for one endpoint.
    pub fn remove_all(&mut self, endpoint: Endpoint) {
        for e in &mut self.entries {
            e.endpoints.remove(endpoint);
        }
        self.entries.retain(|e| !e.endpoints.is_empty());
    }

    /// Member endpoints of `group` (empty when the group is unknown).
    pub fn endpoints(&self, group: GroupAddress) -> EndpointSet {
        self.entries
            .iter()
            .find(|e| e.group == group)
            .map_or(EndpointSet::EMPTY, |e| e.endpoints)
    }

    /// True when any endpoint is a member of `group`.
    pub fn is_member(&self, group: GroupAddress) -> bool {
        self.entries.iter().any(|e| e.group == group)
    }

    /// True when `endpoint` is a member of `group`.
    pub fn contains(&self, group: GroupAddress, endpoint: Endpoint) -> bool {
        self.endpoints(group).contains(endpoint)
    }

    /// All entries.
    pub fn iter(&self) -> impl Iterator<Item = &GroupEntry> {
        self.entries.iter()
    }

    /// Number of groups.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Duplicate rejection record: source address, APS counter and expiry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DuplicateRecord {
    src: ShortAddress,
    counter: u8,
    expires: Instant,
}

/// The duplicate rejection table (§2.2.8.4.2). Frames whose (source,
/// APS counter) pair matches a live entry are duplicates.
#[derive(Clone, Debug)]
pub struct DuplicateRejectionTable<const N: usize> {
    entries: Vec<DuplicateRecord, N>,
}

impl<const N: usize> Default for DuplicateRejectionTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DuplicateRejectionTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        DuplicateRejectionTable {
            entries: Vec::new(),
        }
    }

    /// Records `(src, counter)` at `now`. Returns true when the pair was
    /// already present (a duplicate). Expired entries are reused first;
    /// when full, the entry closest to expiry is evicted.
    pub fn check_and_record(
        &mut self,
        src: ShortAddress,
        counter: u8,
        now: Instant,
        lifetime: panweave_types::time::Duration,
    ) -> bool {
        self.entries.retain(|e| !now.has_reached(e.expires));
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.src == src && e.counter == counter)
        {
            // Refresh so a slow retransmitting sender keeps being rejected.
            e.expires = now.saturating_add(lifetime);
            return true;
        }
        let rec = DuplicateRecord {
            src,
            counter,
            expires: now.saturating_add(lifetime),
        };
        if self.entries.push(rec).is_err() {
            if let Some((i, _)) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.expires)
            {
                self.entries.swap_remove(i);
            }
            let _ = self.entries.push(rec);
        }
        false
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::time::Duration;

    #[test]
    fn binding_table_bind_unbind() {
        let mut t = BindingTable::<2>::new();
        let e1 = BindingEntry {
            src_endpoint: Endpoint(1),
            cluster: ClusterId(6),
            destination: BindingDestination::Unicast {
                address: ExtendedAddress(0xA),
                endpoint: Endpoint(2),
            },
        };
        let e2 = BindingEntry {
            src_endpoint: Endpoint(1),
            cluster: ClusterId(6),
            destination: BindingDestination::Group(GroupAddress(7)),
        };
        assert_eq!(t.bind(e1), Ok(()));
        assert_eq!(t.bind(e1), Ok(()));
        assert_eq!(t.len(), 1);
        assert_eq!(t.bind(e2), Ok(()));
        let e3 = BindingEntry {
            cluster: ClusterId(8),
            ..e1
        };
        assert_eq!(t.bind(e3), Err(ApsStatus::TableFull));
        assert_eq!(t.destinations(Endpoint(1), ClusterId(6)).count(), 2);
        assert_eq!(t.destinations(Endpoint(2), ClusterId(6)).count(), 0);
        assert_eq!(t.unbind(&e3), Err(ApsStatus::InvalidBinding));
        assert_eq!(t.unbind(&e1), Ok(()));
        assert_eq!(t.remove_device(ExtendedAddress(0xA)), 0);
        assert_eq!(
            t.bind(BindingEntry {
                src_endpoint: Endpoint(0),
                ..e1
            }),
            Err(ApsStatus::IllegalRequest)
        );
    }

    #[test]
    fn group_table_membership() {
        let mut g = GroupTable::<2>::new();
        assert_eq!(g.add(GroupAddress(1), Endpoint(1)), Ok(()));
        assert_eq!(g.add(GroupAddress(1), Endpoint(5)), Ok(()));
        assert_eq!(g.add(GroupAddress(2), Endpoint(1)), Ok(()));
        assert_eq!(
            g.add(GroupAddress(3), Endpoint(1)),
            Err(ApsStatus::TableFull)
        );
        assert_eq!(
            g.add(GroupAddress(1), Endpoint(0)),
            Err(ApsStatus::InvalidParameter)
        );
        let eps: Vec<Endpoint, 4> = g.endpoints(GroupAddress(1)).iter().collect();
        assert_eq!(eps.as_slice(), &[Endpoint(1), Endpoint(5)]);
        assert!(g.contains(GroupAddress(2), Endpoint(1)));
        assert_eq!(
            g.remove(GroupAddress(2), Endpoint(3)),
            Err(ApsStatus::InvalidGroup)
        );
        assert_eq!(g.remove(GroupAddress(2), Endpoint(1)), Ok(()));
        assert!(!g.is_member(GroupAddress(2)));
        g.remove_all(Endpoint(1));
        assert!(g.is_member(GroupAddress(1)));
        g.remove_all(Endpoint(5));
        assert!(g.is_empty());
    }

    #[test]
    fn duplicate_rejection_expiry_and_eviction() {
        let mut d = DuplicateRejectionTable::<2>::new();
        let t0 = Instant::from_millis(0);
        let life = Duration::from_millis(100);
        assert!(!d.check_and_record(ShortAddress(1), 1, t0, life));
        assert!(d.check_and_record(ShortAddress(1), 1, t0, life));
        assert!(!d.check_and_record(ShortAddress(1), 2, t0, life));
        // Full: the oldest entry is evicted.
        assert!(!d.check_and_record(ShortAddress(2), 1, Instant::from_millis(10), life));
        assert_eq!(d.len(), 2);
        assert!(!d.check_and_record(ShortAddress(1), 1, Instant::from_millis(20), life));
        // Expiry.
        assert!(!d.check_and_record(ShortAddress(1), 1, Instant::from_millis(500), life));
        assert_eq!(d.len(), 1);
    }
}
