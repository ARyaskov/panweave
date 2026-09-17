//! Broadcast transaction table (R23.2 §3.6.6, Table 3-81) with passive
//! acknowledgement tracking.

use heapless::Vec;
use panweave_types::{Instant, ShortAddress};

/// Maximum router neighbors tracked for passive acknowledgement per
/// broadcast record.
pub const PASSIVE_ACK_TRACKED: usize = 16;

/// A broadcast transaction record.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BroadcastRecord {
    /// Broadcast initiator.
    pub source: ShortAddress,
    /// NWK sequence number of the broadcast.
    pub sequence: u8,
    /// Expiry (`nwkNetworkBroadcastDeliveryTime` after creation).
    pub expires: Instant,
    /// Router neighbors that have not yet been heard relaying this
    /// broadcast (passive acknowledgement).
    pub awaiting: Vec<ShortAddress, PASSIVE_ACK_TRACKED>,
    /// Retransmissions performed so far by the local device.
    pub retries: u8,
    /// When the next (re)transmission is due, if the local device still
    /// needs to relay this broadcast.
    pub next_tx: Option<Instant>,
    /// True when the local device originated or must relay this frame and
    /// the buffered copy is held in the layer's broadcast buffer.
    pub relay_pending: bool,
}

impl BroadcastRecord {
    /// Marks `neighbor` as having relayed the broadcast.
    pub fn passive_ack(&mut self, neighbor: ShortAddress) {
        self.awaiting.retain(|n| *n != neighbor);
    }

    /// True when every tracked neighbor has relayed the broadcast.
    pub fn fully_acknowledged(&self) -> bool {
        self.awaiting.is_empty()
    }
}

/// Fixed-capacity broadcast transaction table.
#[derive(Clone, Debug, Default)]
pub struct BroadcastTransactionTable<const N: usize> {
    records: Vec<BroadcastRecord, N>,
}

impl<const N: usize> BroadcastTransactionTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        BroadcastTransactionTable {
            records: Vec::new(),
        }
    }

    /// Finds the record for `(source, sequence)`.
    pub fn get(&self, source: ShortAddress, sequence: u8) -> Option<&BroadcastRecord> {
        self.records
            .iter()
            .find(|r| r.source == source && r.sequence == sequence)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, source: ShortAddress, sequence: u8) -> Option<&mut BroadcastRecord> {
        self.records
            .iter_mut()
            .find(|r| r.source == source && r.sequence == sequence)
    }

    /// Inserts a new record, reusing an expired one when the table is
    /// full. Returns `None` when full with no expired entries (the frame
    /// is then dropped, §3.6.6).
    pub fn insert(
        &mut self,
        record: BroadcastRecord,
        now: Instant,
    ) -> Option<&mut BroadcastRecord> {
        if self.records.is_full() {
            let pos = self
                .records
                .iter()
                .position(|r| now.has_reached(r.expires))?;
            let _ = self.records.swap_remove(pos);
        }
        self.records.push(record).ok()?;
        let last = self.records.len() - 1;
        Some(&mut self.records[last])
    }

    /// Removes expired records.
    pub fn expire(&mut self, now: Instant) {
        self.records.retain(|r| !now.has_reached(r.expires));
    }

    /// Iterates records.
    pub fn iter(&self) -> impl Iterator<Item = &BroadcastRecord> {
        self.records.iter()
    }

    /// Mutable iteration.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut BroadcastRecord> {
        self.records.iter_mut()
    }

    /// The earliest pending retransmission or expiry time.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.records
            .iter()
            .flat_map(|r| core::iter::once(r.expires).chain(r.next_tx))
            .min()
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clears the table.
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::Duration;

    fn rec(seq: u8, expires: Instant) -> BroadcastRecord {
        BroadcastRecord {
            source: ShortAddress(1),
            sequence: seq,
            expires,
            awaiting: Vec::new(),
            retries: 0,
            next_tx: None,
            relay_pending: false,
        }
    }

    #[test]
    fn duplicate_detection_and_expiry_reuse() {
        let mut t = BroadcastTransactionTable::<1>::new();
        let now = Instant::ZERO;
        let exp = now + Duration::from_secs(9);
        t.insert(rec(1, exp), now).unwrap();
        assert!(t.get(ShortAddress(1), 1).is_some());
        assert!(
            t.insert(rec(2, exp), now).is_none(),
            "full, nothing expired"
        );
        assert!(
            t.insert(rec(2, exp), exp).is_some(),
            "expired record reused"
        );
        assert!(t.get(ShortAddress(1), 1).is_none());
        t.expire(exp + Duration::from_secs(9));
        assert!(t.is_empty());
    }

    #[test]
    fn passive_ack_tracking() {
        let mut r = rec(1, Instant::ZERO);
        r.awaiting.push(ShortAddress(2)).unwrap();
        r.awaiting.push(ShortAddress(3)).unwrap();
        assert!(!r.fully_acknowledged());
        r.passive_ack(ShortAddress(2));
        r.passive_ack(ShortAddress(9));
        assert!(!r.fully_acknowledged());
        r.passive_ack(ShortAddress(3));
        assert!(r.fully_acknowledged());
    }
}
