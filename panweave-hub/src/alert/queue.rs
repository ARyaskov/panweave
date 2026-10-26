//! The persistent, bounded queue of events waiting for delivery.
//!
//! Records live in the hub's own store (`Kind::Application`) under ids
//! whose most significant octet is 0xFF: as an EUI-64 that octet has the
//! group bit set, so no device record (keyed by its IEEE address) can
//! ever collide with them.
//!
//! * one record per slot ([`CAPACITY`] slots): the event, written
//!   before [`Queue::push`] returns — an event is never only in RAM
//!   unless the flash write itself failed, which is counted and
//!   reported;
//! * a meta record: the boot counter (incremented once per boot, so an
//!   event identifier `boot.seq` is unique across reboots) and the
//!   overflow accounting;
//! * an acknowledgement record: the `message_id` Telegram returned and
//!   the identifiers it covered. It is written *before* the delivered
//!   slots are erased; a reboot between the two erases the slots the
//!   record names, so a delivered event is never sent again because of
//!   an interruption.
//!
//! Overflow policy: nothing is ever evicted. An event that finds every
//! slot taken is counted, with the first and last identifiers lost, and
//! the next message says so. Flash wear: one small record per event, one
//! rewrite when an attempt ends ambiguously, one acknowledgement and the
//! slot erasures per delivery, one meta write per boot — the
//! log-structured store spreads them.

use heapless::Vec;
use panweave_codec::{Reader, Writer};
use panweave_storage::{Key, Kind, Storage};

use crate::protocol::AlertKind;

/// Queue capacity (events pending at once).
pub const CAPACITY: usize = 16;
/// Events one delivery acknowledgement can name.
pub const MAX_ACK: usize = CAPACITY;

const FORMAT: u8 = 1;
/// Configuration record id.
pub(crate) const CONFIG_ID: u64 = 0xFFFF_FFFF_FFFF_FF10;
const META_ID: u64 = 0xFFFF_FFFF_FFFF_FF11;
const ACK_ID: u64 = 0xFFFF_FFFF_FFFF_FF12;
const SLOT_BASE: u64 = 0xFFFF_FFFF_FFFF_FF20;

const fn key(id: u64) -> Key {
    Key::with_id(Kind::Application, id)
}

#[allow(clippy::cast_possible_truncation)]
const fn slot_key(slot: usize) -> Key {
    key(SLOT_BASE + slot as u64)
}

/// A stable event identifier: the boot it happened in and its sequence
/// number in that boot. Shown in every notification as `#boot.seq`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EventId {
    /// Boot counter.
    pub boot: u32,
    /// Sequence number in that boot.
    pub seq: u32,
}

/// A queued event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlertEvent {
    /// Its identifier.
    pub id: EventId,
    /// What happened.
    pub kind: AlertKind,
    /// The sensor (0 for a test notification).
    pub ieee: u64,
    /// The raw IAS ZoneStatus that reported it, when one did.
    pub zone_status: Option<u16>,
    /// Monotonic milliseconds since the start of boot `id.boot`. No wall
    /// clock time is invented.
    pub at_ms: u64,
    /// Delivery attempts that included it.
    pub attempts: u8,
    /// A previous attempt may already have published it.
    pub ambiguous: bool,
}

/// Events that found the queue full.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Overflow {
    /// How many.
    pub count: u32,
    /// The first one lost.
    pub first: Option<EventId>,
    /// The last one lost.
    pub last: Option<EventId>,
}

/// The last delivery acknowledgement.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ack {
    /// Telegram's `message_id`.
    pub message_id: i64,
    /// Events it covered.
    pub ids: Vec<EventId, MAX_ACK>,
    /// Overflow losses it reported (cleared from the accounting).
    pub overflow_reported: u32,
}

/// The queue (a RAM mirror of the persisted slots).
#[derive(Clone, Debug)]
pub struct Queue {
    slots: [Option<AlertEvent>; CAPACITY],
    boot: u32,
    next_seq: u32,
    overflow: Overflow,
    last_ack: Option<Ack>,
    /// Flash writes that failed (the event is then kept in RAM only).
    pub storage_errors: u32,
}

fn write_id(w: &mut Writer<'_>, id: EventId) -> Result<(), panweave_codec::CodecError> {
    w.u32_le(id.boot)?;
    w.u32_le(id.seq)
}

fn read_id(r: &mut Reader<'_>) -> Option<EventId> {
    Some(EventId {
        boot: r.u32_le().ok()?,
        seq: r.u32_le().ok()?,
    })
}

fn write_opt_id(w: &mut Writer<'_>, id: Option<EventId>) -> Result<(), panweave_codec::CodecError> {
    match id {
        Some(i) => {
            w.u8(1)?;
            write_id(w, i)
        }
        None => w.u8(0),
    }
}

/// An optional identifier; `None` when absent or unreadable (the meta
/// record is best effort: a damaged one only loses overflow details).
fn read_opt_id(r: &mut Reader<'_>) -> Option<EventId> {
    match r.u8().ok()? {
        1 => read_id(r),
        _ => None,
    }
}

fn encode_event(e: &AlertEvent, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(FORMAT).ok()?;
    write_id(&mut w, e.id).ok()?;
    w.u8(e.kind.code()).ok()?;
    w.u64_le(e.ieee).ok()?;
    match e.zone_status {
        Some(z) => {
            w.u8(1).ok()?;
            w.u16_le(z).ok()?;
        }
        None => w.u8(0).ok()?,
    }
    w.u64_le(e.at_ms).ok()?;
    w.u8(e.attempts).ok()?;
    w.u8(u8::from(e.ambiguous)).ok()?;
    Some(w.position())
}

fn decode_event(b: &[u8]) -> Option<AlertEvent> {
    let mut r = Reader::new(b);
    if r.u8().ok()? != FORMAT {
        return None;
    }
    let id = read_id(&mut r)?;
    let kind = AlertKind::from_code(r.u8().ok()?)?;
    let ieee = r.u64_le().ok()?;
    let zone_status = match r.u8().ok()? {
        0 => None,
        1 => Some(r.u16_le().ok()?),
        _ => return None,
    };
    Some(AlertEvent {
        id,
        kind,
        ieee,
        zone_status,
        at_ms: r.u64_le().ok()?,
        attempts: r.u8().ok()?,
        ambiguous: r.u8().ok()? != 0,
    })
}

impl Queue {
    /// Opens the queue: starts a new boot (one meta write), loads the
    /// pending events, and completes an interrupted acknowledgement.
    pub fn open<S: Storage>(storage: &mut S) -> Self {
        let mut q = Queue {
            slots: [None; CAPACITY],
            boot: 0,
            next_seq: 0,
            overflow: Overflow::default(),
            last_ack: None,
            storage_errors: 0,
        };
        let mut buf = [0u8; 64];
        if let Ok(Some(n)) = storage.load(key(META_ID), &mut buf) {
            let mut r = Reader::new(buf.get(..n).unwrap_or(&[]));
            if r.u8().ok() == Some(FORMAT) {
                q.boot = r.u32_le().unwrap_or(0);
                q.overflow.count = r.u32_le().unwrap_or(0);
                q.overflow.first = read_opt_id(&mut r);
                q.overflow.last = read_opt_id(&mut r);
            }
        }
        q.boot = q.boot.wrapping_add(1);
        q.store_meta(storage);
        for (i, slot) in q.slots.iter_mut().enumerate() {
            if let Ok(Some(n)) = storage.load(slot_key(i), &mut buf) {
                *slot = buf.get(..n).and_then(decode_event);
            }
        }
        let mut ack_buf = [0u8; 16 + 8 * MAX_ACK];
        if let Ok(Some(n)) = storage.load(key(ACK_ID), &mut ack_buf) {
            q.last_ack = decode_ack(ack_buf.get(..n).unwrap_or(&[]));
        }
        if let Some(ack) = q.last_ack.clone() {
            // An acknowledgement written before its slots were erased.
            for i in 0..CAPACITY {
                if q.slots[i].is_some_and(|e| ack.ids.contains(&e.id)) {
                    q.slots[i] = None;
                    let _ = storage.erase(slot_key(i));
                }
            }
        }
        q
    }

    fn store_meta<S: Storage>(&mut self, storage: &mut S) {
        let mut buf = [0u8; 40];
        let mut w = Writer::new(&mut buf);
        let ok = w.u8(FORMAT).is_ok()
            && w.u32_le(self.boot).is_ok()
            && w.u32_le(self.overflow.count).is_ok()
            && write_opt_id(&mut w, self.overflow.first).is_ok()
            && write_opt_id(&mut w, self.overflow.last).is_ok();
        let n = w.position();
        if !ok
            || storage
                .store(key(META_ID), buf.get(..n).unwrap_or(&[]))
                .is_err()
        {
            self.storage_errors = self.storage_errors.saturating_add(1);
        }
    }

    fn store_slot<S: Storage>(&mut self, storage: &mut S, slot: usize) {
        let Some(e) = self.slots[slot] else {
            return;
        };
        let mut buf = [0u8; 48];
        let written = encode_event(&e, &mut buf).is_some_and(|n| {
            storage
                .store(slot_key(slot), buf.get(..n).unwrap_or(&[]))
                .is_ok()
        });
        if !written {
            self.storage_errors = self.storage_errors.saturating_add(1);
        }
    }

    /// This boot's identifier.
    pub const fn boot(&self) -> u32 {
        self.boot
    }

    /// Events pending.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Nothing pending.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Overflow accounting not yet reported in a delivered message.
    pub const fn overflow(&self) -> Overflow {
        self.overflow
    }

    /// The last acknowledgement.
    pub const fn last_ack(&self) -> Option<&Ack> {
        self.last_ack.as_ref()
    }

    /// Pending events, oldest first.
    pub fn pending(&self) -> Vec<AlertEvent, CAPACITY> {
        let mut v: Vec<AlertEvent, CAPACITY> = self.slots.iter().flatten().copied().collect();
        v.sort_unstable_by_key(|e| e.id);
        v
    }

    /// Queues an event, persisting it first. `Err` with the identifier it
    /// would have had when every slot is taken (counted, never silent).
    pub fn push<S: Storage>(
        &mut self,
        storage: &mut S,
        kind: AlertKind,
        ieee: u64,
        zone_status: Option<u16>,
        now_ms: u64,
    ) -> Result<EventId, EventId> {
        let id = EventId {
            boot: self.boot,
            seq: self.next_seq,
        };
        self.next_seq = self.next_seq.wrapping_add(1);
        let Some(slot) = self.slots.iter().position(Option::is_none) else {
            self.overflow.count = self.overflow.count.saturating_add(1);
            self.overflow.first.get_or_insert(id);
            self.overflow.last = Some(id);
            self.store_meta(storage);
            return Err(id);
        };
        self.slots[slot] = Some(AlertEvent {
            id,
            kind,
            ieee,
            zone_status,
            at_ms: now_ms,
            attempts: 0,
            ambiguous: false,
        });
        self.store_slot(storage, slot);
        Ok(id)
    }

    /// The events of `ids` were part of an attempt; `ambiguous`: it may
    /// have published them.
    pub fn note_attempt<S: Storage>(&mut self, storage: &mut S, ids: &[EventId], ambiguous: bool) {
        for i in 0..CAPACITY {
            let Some(e) = self.slots[i].as_mut() else {
                continue;
            };
            if ids.contains(&e.id) {
                e.attempts = e.attempts.saturating_add(1);
                let was = e.ambiguous;
                e.ambiguous |= ambiguous;
                // Only a change of the duplicate marker is worth a flash
                // write; the attempt count is informational.
                if e.ambiguous != was {
                    self.store_slot(storage, i);
                }
            }
        }
    }

    /// Telegram accepted the message `message_id` covering `ids` (and,
    /// when `overflow_reported` is non-zero, the overflow note): the
    /// acknowledgement is persisted, then the slots are erased.
    pub fn acknowledge<S: Storage>(
        &mut self,
        storage: &mut S,
        message_id: i64,
        ids: &[EventId],
        overflow_reported: u32,
    ) {
        let mut ack = Ack {
            message_id,
            ids: Vec::new(),
            overflow_reported,
        };
        for id in ids.iter().take(MAX_ACK) {
            let _ = ack.ids.push(*id);
        }
        let mut buf = [0u8; 16 + 8 * MAX_ACK];
        let stored = encode_ack(&ack, &mut buf).is_some_and(|n| {
            storage
                .store(key(ACK_ID), buf.get(..n).unwrap_or(&[]))
                .is_ok()
        });
        if !stored {
            self.storage_errors = self.storage_errors.saturating_add(1);
        }
        for i in 0..CAPACITY {
            if self.slots[i].is_some_and(|e| ack.ids.contains(&e.id)) {
                self.slots[i] = None;
                if storage.erase(slot_key(i)).is_err() {
                    self.storage_errors = self.storage_errors.saturating_add(1);
                }
            }
        }
        if overflow_reported > 0 {
            self.overflow.count = self.overflow.count.saturating_sub(overflow_reported);
            if self.overflow.count == 0 {
                self.overflow = Overflow::default();
            }
            self.store_meta(storage);
        }
        self.last_ack = Some(ack);
    }
}

fn encode_ack(a: &Ack, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(FORMAT).ok()?;
    #[allow(clippy::cast_sign_loss)]
    w.u64_le(a.message_id as u64).ok()?;
    w.u32_le(a.overflow_reported).ok()?;
    #[allow(clippy::cast_possible_truncation)]
    w.u8(a.ids.len() as u8).ok()?;
    for id in &a.ids {
        write_id(&mut w, *id).ok()?;
    }
    Some(w.position())
}

fn decode_ack(b: &[u8]) -> Option<Ack> {
    let mut r = Reader::new(b);
    if r.u8().ok()? != FORMAT {
        return None;
    }
    #[allow(clippy::cast_possible_wrap)]
    let message_id = r.u64_le().ok()? as i64;
    let overflow_reported = r.u32_le().ok()?;
    let n = r.u8().ok()?;
    let mut ids = Vec::new();
    for _ in 0..n {
        ids.push(read_id(&mut r)?).ok()?;
    }
    Some(Ack {
        message_id,
        ids,
        overflow_reported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_storage::MemoryStorage;

    type Store = MemoryStorage<32, 512>;

    fn push(q: &mut Queue, s: &mut Store, kind: AlertKind, t: u64) -> EventId {
        q.push(s, kind, 0x54EF_4410_0000_0001, Some(1), t).unwrap()
    }

    #[test]
    fn events_are_persisted_before_push_returns_and_survive_a_reboot_in_order() {
        let mut s = Store::new();
        let mut q = Queue::open(&mut s);
        assert_eq!(q.boot(), 1);
        let a = push(&mut q, &mut s, AlertKind::WaterLeak, 10);
        let b = push(&mut q, &mut s, AlertKind::WaterLeakCleared, 20);
        assert!(a < b);
        // Power loss: nothing but the store survives.
        let q2 = Queue::open(&mut s);
        assert_eq!(q2.boot(), 2);
        let p = q2.pending();
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].id, p[0].kind), (a, AlertKind::WaterLeak));
        assert_eq!((p[1].id, p[1].kind), (b, AlertKind::WaterLeakCleared));
        // New events of the new boot sort after the old ones.
        let mut q2 = q2;
        let c = push(&mut q2, &mut s, AlertKind::WaterLeak, 5);
        assert_eq!(c, EventId { boot: 2, seq: 0 });
        assert_eq!(q2.pending().last().unwrap().id, c);
    }

    #[test]
    fn an_acknowledgement_survives_a_reboot_and_completes_an_interrupted_erase() {
        let mut s = Store::new();
        let mut q = Queue::open(&mut s);
        let a = push(&mut q, &mut s, AlertKind::WaterLeak, 10);
        let b = push(&mut q, &mut s, AlertKind::WaterLeakCleared, 20);
        q.acknowledge(&mut s, 777, &[a], 0);
        assert_eq!(
            q.pending()
                .iter()
                .map(|e| e.id)
                .collect::<std::vec::Vec<_>>(),
            [b]
        );
        let q2 = Queue::open(&mut s);
        assert_eq!(q2.last_ack().unwrap().message_id, 777);
        assert_eq!(q2.pending().len(), 1);

        // Interrupted: the acknowledgement was written, the slot not yet
        // erased (simulated by writing the slot back).
        let mut s = Store::new();
        let mut q = Queue::open(&mut s);
        let a = push(&mut q, &mut s, AlertKind::WaterLeak, 10);
        let saved = {
            let mut buf = [0u8; 64];
            let n = s.load(slot_key(0), &mut buf).unwrap().unwrap();
            buf[..n].to_vec()
        };
        q.acknowledge(&mut s, 5, &[a], 0);
        s.store(slot_key(0), &saved).unwrap();
        let q2 = Queue::open(&mut s);
        assert!(q2.is_empty(), "a delivered event is never sent again");
        assert_eq!(s.load(slot_key(0), &mut [0u8; 64]).unwrap(), None);
    }

    #[test]
    fn overflow_is_counted_never_evicts_and_is_cleared_once_reported() {
        let mut s = Store::new();
        let mut q = Queue::open(&mut s);
        let mut ids = std::vec::Vec::new();
        for t in 0..CAPACITY as u64 {
            ids.push(push(&mut q, &mut s, AlertKind::ContactOpened, t));
        }
        let lost1 = q
            .push(&mut s, AlertKind::WaterLeak, 1, None, 100)
            .unwrap_err();
        let lost2 = q
            .push(&mut s, AlertKind::WaterLeak, 1, None, 101)
            .unwrap_err();
        assert_eq!(q.len(), CAPACITY);
        assert_eq!(q.pending()[0].id, ids[0], "nothing evicted");
        let o = q.overflow();
        assert_eq!((o.count, o.first, o.last), (2, Some(lost1), Some(lost2)));
        // Survives a reboot.
        let mut q = Queue::open(&mut s);
        assert_eq!(q.overflow().count, 2);
        q.acknowledge(&mut s, 1, &ids, 2);
        assert_eq!(q.overflow(), Overflow::default());
        assert!(q.is_empty());
        assert_eq!(Queue::open(&mut s).overflow().count, 0);
    }

    #[test]
    fn an_ambiguous_attempt_is_remembered_across_reboots() {
        let mut s = Store::new();
        let mut q = Queue::open(&mut s);
        let a = push(&mut q, &mut s, AlertKind::WaterLeak, 10);
        q.note_attempt(&mut s, &[a], false);
        assert!(!q.pending()[0].ambiguous);
        q.note_attempt(&mut s, &[a], true);
        let q = Queue::open(&mut s);
        assert!(q.pending()[0].ambiguous);
    }

    #[test]
    fn a_failed_flash_write_is_counted() {
        // A store too small for the slots.
        let mut s = MemoryStorage::<1, 512>::new();
        let mut q = Queue::open(&mut s);
        assert_eq!(q.storage_errors, 0);
        q.push(&mut s, AlertKind::WaterLeak, 1, None, 1).unwrap();
        assert_eq!(q.storage_errors, 1);
        assert_eq!(q.len(), 1, "kept in RAM rather than dropped");
    }
}
