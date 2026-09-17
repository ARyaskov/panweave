//! Power Control Information Table (R23.2 Annex D.11.2.3): the transmit
//! power negotiated per link, consulted for every unicast transmission
//! to that link (D.11.2.3: a device without an entry is sent to at the
//! maximum power for the channel, D.11.2.4.5). The table is volatile:
//! after a reset every link starts at maximum power and is negotiated
//! down again. Entries created while joining that the network layer
//! never confirms (`nwk_negotiated`) are dropped after
//! [`UNNEGOTIATED_LIFETIME`].
//!
//! The network layer drives the table through Link Power Delta
//! commands (§3.4.13); the MAC only stores and applies the result.

use heapless::Vec;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ExtendedAddress, ShortAddress};

use crate::frame::MacAddress;

/// How long an entry may stay without the network layer confirming the
/// link (D.11.2.3).
pub const UNNEGOTIATED_LIFETIME: Duration = Duration::from_secs(10);

/// Transmit power limits a negotiation may never exceed (D.11.2.4.4).
///
/// The spec fixes the limits per band (D.12.2.2.3 for GB 868); 2.4 GHz
/// radios differ, so the application configures them. The default is a
/// conservative range common to 2.4 GHz transceivers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PowerLimits {
    /// Minimum transmit power in dBm.
    pub min_dbm: i8,
    /// Maximum transmit power in dBm (the power used before any
    /// negotiation and for links not in the table).
    pub max_dbm: i8,
}

impl Default for PowerLimits {
    fn default() -> Self {
        PowerLimits {
            min_dbm: -20,
            max_dbm: 8,
        }
    }
}

impl PowerLimits {
    /// Clamps a power level to the limits.
    pub const fn clamp(&self, dbm: i8) -> i8 {
        if dbm < self.min_dbm {
            self.min_dbm
        } else if dbm > self.max_dbm {
            self.max_dbm
        } else {
            dbm
        }
    }
}

/// One link (Figure D-9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PowerEntry {
    /// Short address of the peer.
    pub short: ShortAddress,
    /// IEEE address of the peer (`ZERO` when unknown).
    pub extended: ExtendedAddress,
    /// Transmit power to use towards the peer, dBm.
    pub tx_power_dbm: i8,
    /// RSSI of the last frame received from the peer, dBm.
    pub last_rssi_dbm: i8,
    /// The network layer confirmed the link (NWK Negotiated).
    pub nwk_negotiated: bool,
    /// When the entry was created (for the un-negotiated timeout).
    pub created: Instant,
}

/// Why an entry could not be stored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PowerTableError {
    /// No room and nothing evictable.
    Full,
}

/// The table (D.11.2.3), at least one entry.
#[derive(Clone, Debug)]
pub struct PowerControlTable<const N: usize> {
    entries: Vec<PowerEntry, N>,
    /// The limits negotiations are clamped to.
    pub limits: PowerLimits,
}

impl<const N: usize> Default for PowerControlTable<N> {
    fn default() -> Self {
        Self::new(PowerLimits::default())
    }
}

impl<const N: usize> PowerControlTable<N> {
    /// Empty table with the given limits.
    pub const fn new(limits: PowerLimits) -> Self {
        PowerControlTable {
            entries: Vec::new(),
            limits,
        }
    }

    /// The entries.
    pub fn iter(&self) -> impl Iterator<Item = &PowerEntry> {
        self.entries.iter()
    }

    /// Number of links in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn position(
        &self,
        short: Option<ShortAddress>,
        extended: Option<ExtendedAddress>,
    ) -> Option<usize> {
        self.entries.iter().position(|e| {
            short.is_some_and(|s| s.is_unicast() && e.short == s)
                || extended.is_some_and(|x| x != ExtendedAddress::ZERO && e.extended == x)
        })
    }

    /// MLME-GET-POWER-INFORMATION-TABLE.request (D.11.2.3.1): the entry
    /// for the link pair, by short and/or IEEE address.
    pub fn get(
        &self,
        short: Option<ShortAddress>,
        extended: Option<ExtendedAddress>,
    ) -> Option<&PowerEntry> {
        self.position(short, extended)
            .and_then(|i| self.entries.get(i))
    }

    /// MLME-SET-POWER-INFORMATION-TABLE.request (D.11.2.3.3): stores or
    /// replaces the entry for the link pair, clamping the power. When
    /// full, the oldest un-negotiated entry is evicted.
    pub fn set(&mut self, mut entry: PowerEntry) -> Result<(), PowerTableError> {
        entry.tx_power_dbm = self.limits.clamp(entry.tx_power_dbm);
        if let Some(i) = self.position(Some(entry.short), Some(entry.extended)) {
            if let Some(e) = self.entries.get_mut(i) {
                if entry.extended == ExtendedAddress::ZERO {
                    entry.extended = e.extended;
                }
                *e = entry;
            }
            return Ok(());
        }
        if self.entries.is_full() {
            let victim = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| !e.nwk_negotiated)
                .min_by_key(|(_, e)| e.created.as_millis())
                .map(|(i, _)| i)
                .ok_or(PowerTableError::Full)?;
            let _ = self.entries.swap_remove(victim);
        }
        self.entries.push(entry).map_err(|_| PowerTableError::Full)
    }

    /// Applies a negotiated power delta for the link (§3.4.13.7 step 3):
    /// the peer asked for `delta_db` more (or less) power, so the link's
    /// transmit power becomes the current one (maximum when unknown) plus
    /// the delta, clamped; the last RSSI is recorded and the link is
    /// marked negotiated. Returns the resulting power.
    pub fn adjust(
        &mut self,
        short: ShortAddress,
        extended: ExtendedAddress,
        delta_db: i8,
        rssi_dbm: i8,
        now: Instant,
    ) -> Result<i8, PowerTableError> {
        let (current, created) = self
            .get(Some(short), Some(extended))
            .map_or((self.limits.max_dbm, now), |e| (e.tx_power_dbm, e.created));
        let power = self.limits.clamp(current.saturating_add(delta_db));
        self.set(PowerEntry {
            short,
            extended,
            tx_power_dbm: power,
            last_rssi_dbm: rssi_dbm,
            nwk_negotiated: true,
            created,
        })?;
        Ok(power)
    }

    /// Marks the link as confirmed by the network layer (the joiner is
    /// now in the neighbor table).
    pub fn mark_negotiated(
        &mut self,
        short: Option<ShortAddress>,
        extended: Option<ExtendedAddress>,
    ) {
        if let Some(i) = self.position(short, extended)
            && let Some(e) = self.entries.get_mut(i)
        {
            e.nwk_negotiated = true;
        }
    }

    /// Removes the link.
    pub fn remove(
        &mut self,
        short: Option<ShortAddress>,
        extended: Option<ExtendedAddress>,
    ) -> bool {
        match self.position(short, extended) {
            Some(i) => {
                let _ = self.entries.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Forgets every link: after a channel change, a rejoin or a reset
    /// all transmissions return to the maximum power (§3.4.13.1,
    /// §3.6.11.1).
    pub fn reset(&mut self) {
        self.entries.clear();
    }

    /// Drops entries the network layer never confirmed within
    /// [`UNNEGOTIATED_LIFETIME`] (D.11.2.3 housekeeping).
    pub fn expire(&mut self, now: Instant) {
        self.entries.retain(|e| {
            e.nwk_negotiated || now.saturating_duration_since(e.created) < UNNEGOTIATED_LIFETIME
        });
    }

    /// The transmit power for a frame to `dst`: the link's negotiated
    /// power, or `None` (the radio's maximum) for broadcasts and unknown
    /// links (D.11.2.4.5).
    pub fn tx_power_for(&self, dst: &MacAddress) -> Option<i8> {
        match dst {
            MacAddress::Short(s) if s.is_unicast() => self.get(Some(*s), None),
            MacAddress::Extended(x) => self.get(None, Some(*x)),
            _ => None,
        }
        .map(|e| e.tx_power_dbm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ShortAddress = ShortAddress(0x1234);
    const A_IEEE: ExtendedAddress = ExtendedAddress(0x1122_3344_5566_7788);

    #[test]
    fn adjusts_from_maximum_and_clamps() {
        let mut t: PowerControlTable<4> = PowerControlTable::default();
        assert_eq!(t.tx_power_for(&MacAddress::Short(A)), None);
        let p = t.adjust(A, A_IEEE, -5, -40, Instant::ZERO).unwrap();
        assert_eq!(p, 3);
        assert_eq!(t.tx_power_for(&MacAddress::Short(A)), Some(3));
        assert_eq!(t.tx_power_for(&MacAddress::Extended(A_IEEE)), Some(3));
        assert_eq!(t.get(Some(A), None).unwrap().last_rssi_dbm, -40);
        assert!(t.get(Some(A), None).unwrap().nwk_negotiated);
        // Cumulative, then clamped at the limits.
        assert_eq!(t.adjust(A, A_IEEE, -30, -30, Instant::ZERO).unwrap(), -20);
        assert_eq!(t.adjust(A, A_IEEE, 100, -90, Instant::ZERO).unwrap(), 8);
        assert_eq!(
            t.tx_power_for(&MacAddress::Short(ShortAddress::BROADCAST_ALL)),
            None
        );
        assert!(t.remove(Some(A), None));
        assert!(t.is_empty());
    }

    #[test]
    fn unnegotiated_entries_expire_and_are_evicted_first() {
        let mut t: PowerControlTable<2> = PowerControlTable::default();
        t.set(PowerEntry {
            short: A,
            extended: A_IEEE,
            tx_power_dbm: 0,
            last_rssi_dbm: -50,
            nwk_negotiated: false,
            created: Instant::ZERO,
        })
        .unwrap();
        t.set(PowerEntry {
            short: ShortAddress(0x0001),
            extended: ExtendedAddress::ZERO,
            tx_power_dbm: 2,
            last_rssi_dbm: -50,
            nwk_negotiated: true,
            created: Instant::ZERO,
        })
        .unwrap();
        // Full: the un-negotiated entry makes room.
        t.set(PowerEntry {
            short: ShortAddress(0x0002),
            extended: ExtendedAddress::ZERO,
            tx_power_dbm: 1,
            last_rssi_dbm: -50,
            nwk_negotiated: true,
            created: Instant::ZERO,
        })
        .unwrap();
        assert!(t.get(Some(A), None).is_none());
        assert_eq!(t.len(), 2);
        // Nothing evictable: full.
        assert_eq!(
            t.set(PowerEntry {
                short: ShortAddress(0x0003),
                extended: ExtendedAddress::ZERO,
                tx_power_dbm: 1,
                last_rssi_dbm: -50,
                nwk_negotiated: true,
                created: Instant::ZERO,
            }),
            Err(PowerTableError::Full)
        );
        t.reset();
        t.set(PowerEntry {
            short: A,
            extended: A_IEEE,
            tx_power_dbm: 0,
            last_rssi_dbm: -50,
            nwk_negotiated: false,
            created: Instant::ZERO,
        })
        .unwrap();
        t.expire(Instant::ZERO + Duration::from_secs(9));
        assert_eq!(t.len(), 1);
        t.mark_negotiated(None, Some(A_IEEE));
        t.expire(Instant::ZERO + Duration::from_secs(11));
        assert_eq!(t.len(), 1);
        t.get(Some(A), None).unwrap();
        t.remove(Some(A), None);
        t.set(PowerEntry {
            short: A,
            extended: A_IEEE,
            tx_power_dbm: 0,
            last_rssi_dbm: -50,
            nwk_negotiated: false,
            created: Instant::ZERO,
        })
        .unwrap();
        t.expire(Instant::ZERO + Duration::from_secs(11));
        assert!(t.is_empty());
    }
}
