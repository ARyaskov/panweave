//! Network address map (`nwkAddressMap`, R23.2 Table 3-68) and stochastic
//! address assignment (§3.6.1.8).

use heapless::Vec;
use panweave_types::{ExtendedAddress, Rng, ShortAddress};

/// Fixed-capacity map between extended and network addresses.
#[derive(Clone, Debug, Default)]
pub struct AddressMap<const N: usize> {
    entries: Vec<(ExtendedAddress, ShortAddress), N>,
}

/// Outcome of recording an address pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddressMapUpdate {
    /// Nothing changed.
    Unchanged,
    /// A new pair was recorded.
    Added,
    /// The short address of an existing extended address changed
    /// (the device was re-addressed).
    ShortChanged {
        /// Previous short address.
        old: ShortAddress,
    },
    /// The short address is now claimed by a different extended address
    /// than before (address conflict candidate, §3.6.1.10.2).
    Conflict {
        /// The other extended address using the same short address.
        other: ExtendedAddress,
    },
    /// The map is full; the pair was not recorded.
    Full,
}

impl<const N: usize> AddressMap<N> {
    /// Empty map.
    pub const fn new() -> Self {
        AddressMap {
            entries: Vec::new(),
        }
    }

    /// Short address for `ext`.
    pub fn short_for(&self, ext: ExtendedAddress) -> Option<ShortAddress> {
        self.entries.iter().find(|e| e.0 == ext).map(|e| e.1)
    }

    /// Extended address for `short`.
    pub fn extended_for(&self, short: ShortAddress) -> Option<ExtendedAddress> {
        self.entries.iter().find(|e| e.1 == short).map(|e| e.0)
    }

    /// Records the pair and reports what changed. Conflicts are reported
    /// but the map keeps the previous binding of the short address so the
    /// caller can resolve per §3.6.1.10.
    pub fn record(&mut self, ext: ExtendedAddress, short: ShortAddress) -> AddressMapUpdate {
        if let Some(other) = self.extended_for(short)
            && other != ext
        {
            return AddressMapUpdate::Conflict { other };
        }
        if let Some(e) = self.entries.iter_mut().find(|e| e.0 == ext) {
            if e.1 == short {
                return AddressMapUpdate::Unchanged;
            }
            let old = e.1;
            e.1 = short;
            return AddressMapUpdate::ShortChanged { old };
        }
        match self.entries.push((ext, short)) {
            Ok(()) => AddressMapUpdate::Added,
            Err(_) => AddressMapUpdate::Full,
        }
    }

    /// Removes any pair for `ext`.
    pub fn remove_extended(&mut self, ext: ExtendedAddress) {
        self.entries.retain(|e| e.0 != ext);
    }

    /// Removes any pair for `short`.
    pub fn remove_short(&mut self, short: ShortAddress) {
        self.entries.retain(|e| e.1 != short);
    }

    /// True when `short` is recorded for any device.
    pub fn contains_short(&self, short: ShortAddress) -> bool {
        self.entries.iter().any(|e| e.1 == short)
    }

    /// Iterates pairs.
    pub fn iter(&self) -> impl Iterator<Item = (ExtendedAddress, ShortAddress)> + '_ {
        self.entries.iter().copied()
    }

    /// Number of pairs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clears the map.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Draws a random unicast network address that is not in use according
/// to `in_use` (§3.6.1.8): never `0x0000`, never a reserved/broadcast
/// value. Gives up after a bounded number of draws.
pub fn allocate_stochastic(
    rng: &mut impl Rng,
    mut in_use: impl FnMut(ShortAddress) -> bool,
) -> Option<ShortAddress> {
    for _ in 0..64 {
        let candidate = ShortAddress(rng.next_u16());
        if candidate.is_assignable() && !in_use(candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::rng::DeterministicRng;

    #[test]
    fn record_and_conflict() {
        let mut m = AddressMap::<2>::new();
        assert_eq!(
            m.record(ExtendedAddress(1), ShortAddress(10)),
            AddressMapUpdate::Added
        );
        assert_eq!(
            m.record(ExtendedAddress(1), ShortAddress(10)),
            AddressMapUpdate::Unchanged
        );
        assert_eq!(
            m.record(ExtendedAddress(1), ShortAddress(11)),
            AddressMapUpdate::ShortChanged {
                old: ShortAddress(10)
            }
        );
        assert_eq!(
            m.record(ExtendedAddress(2), ShortAddress(11)),
            AddressMapUpdate::Conflict {
                other: ExtendedAddress(1)
            }
        );
        assert_eq!(m.short_for(ExtendedAddress(1)), Some(ShortAddress(11)));
        assert_eq!(
            m.record(ExtendedAddress(2), ShortAddress(12)),
            AddressMapUpdate::Added
        );
        assert_eq!(
            m.record(ExtendedAddress(3), ShortAddress(13)),
            AddressMapUpdate::Full
        );
        m.remove_short(ShortAddress(12));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn stochastic_allocation_avoids_used_and_reserved() {
        let mut rng = DeterministicRng::seed(3);
        let used = [ShortAddress(0x1234)];
        for _ in 0..200 {
            let a = allocate_stochastic(&mut rng, |s| used.contains(&s)).unwrap();
            assert!(a.is_assignable());
            assert_ne!(a, ShortAddress(0x1234));
        }
        assert!(allocate_stochastic(&mut rng, |_| true).is_none());
    }
}
