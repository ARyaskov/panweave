//! Persistent storage abstraction for the Panweave stack.
//!
//! The core layers never touch storage directly; they emit persistence
//! hints and counter reservations that the runtime turns into
//! [`Storage`] writes (`docs/storage-model.md`). Records are addressed by
//! a [`Key`] (kind + 64-bit identifier) so that per-partner records such
//! as link keys do not need a separate namespace scheme.
//!
//! Frame-counter reservations MUST be durably written before the runtime
//! commits them (`docs/security-model.md`); a storage implementation that
//! buffers writes must therefore complete [`Storage::store`] before
//! returning.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

use heapless::Vec;

/// Record kinds.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Kind {
    /// NWK outgoing frame counter reservation bound (4 octets, LE).
    NwkFrameCounter,
    /// Network keys and sequence numbers.
    NetworkKeys,
    /// Scalar NIB attributes needed to rejoin after a reset.
    Nib,
    /// End-device children of a router (R23.2 §3.6.9, §3.6.10.7).
    Children,
    /// A link-key entry; `id` is the partner IEEE address.
    LinkKey,
    /// Outgoing APS frame counter reservation of a link key; `id` is the
    /// partner IEEE address.
    ApsFrameCounter,
    /// Scalar AIB attributes (Trust Center address, …).
    Aib,
    /// Binding table.
    Bindings,
    /// Group table.
    Groups,
    /// Application-defined record.
    Application,
    /// Green Power Proxy Table entry; `id` is the entry index.
    GreenPower,
    /// Past network keys a Zigbee Direct device keeps for Limited
    /// Authorization sessions (ZD 1.1 §9.1).
    DirectPastKeys,
    /// Saved startup attribute sets of a Commissioning server (ZCL8
    /// §13.2.2.3.2); `id` is the endpoint.
    StartupSets,
    /// Zigbee Direct interface configuration (ZD 1.1 §11.3.5.4): the
    /// interface state and the Anonymous Join Timeout.
    DirectConfig,
}

/// A record key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Key {
    /// Record kind.
    pub kind: Kind,
    /// Identifier within the kind (0 for singletons).
    pub id: u64,
}

impl Key {
    /// A singleton record.
    pub const fn single(kind: Kind) -> Self {
        Key { kind, id: 0 }
    }

    /// A per-identifier record.
    pub const fn with_id(kind: Kind, id: u64) -> Self {
        Key { kind, id }
    }
}

/// Storage errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StorageError {
    /// No space for the record.
    Full,
    /// The record is larger than the caller's buffer.
    BufferTooSmall,
    /// The backing medium failed.
    Io,
}

/// Durable key/value storage.
pub trait Storage {
    /// Stores (creates or replaces) a record. Returns only after the data
    /// is durable.
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError>;
    /// Loads a record into `buf`; `Ok(None)` when absent, otherwise the
    /// record length.
    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError>;
    /// Removes a record (absent records are not an error).
    fn erase(&mut self, key: Key) -> Result<(), StorageError>;
    /// Removes every record of `kind`.
    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError>;
}

/// In-memory storage for tests and RAM-only deployments. `N` records of
/// up to `S` octets each.
#[derive(Clone, Debug)]
pub struct MemoryStorage<const N: usize, const S: usize> {
    records: Vec<(Key, Vec<u8, S>), N>,
    /// Number of `store` calls (for tests asserting persistence order).
    pub writes: u32,
}

impl<const N: usize, const S: usize> Default for MemoryStorage<N, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const S: usize> MemoryStorage<N, S> {
    /// Empty storage.
    pub const fn new() -> Self {
        MemoryStorage {
            records: Vec::new(),
            writes: 0,
        }
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl<const N: usize, const S: usize> Storage for MemoryStorage<N, S> {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        let value = Vec::from_slice(data).map_err(|_| StorageError::Full)?;
        self.writes = self.writes.saturating_add(1);
        if let Some(r) = self.records.iter_mut().find(|(k, _)| *k == key) {
            r.1 = value;
            return Ok(());
        }
        self.records
            .push((key, value))
            .map_err(|_| StorageError::Full)
    }

    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        let Some((_, v)) = self.records.iter().find(|(k, _)| *k == key) else {
            return Ok(None);
        };
        let dst = buf.get_mut(..v.len()).ok_or(StorageError::BufferTooSmall)?;
        dst.copy_from_slice(v);
        Ok(Some(v.len()))
    }

    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        self.records.retain(|(k, _)| *k != key);
        Ok(())
    }

    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        self.records.retain(|(k, _)| k.kind != kind);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_storage_round_trip() {
        let mut s = MemoryStorage::<4, 8>::new();
        let k = Key::with_id(Kind::LinkKey, 7);
        assert_eq!(s.load(k, &mut [0; 8]).unwrap(), None);
        s.store(k, &[1, 2, 3]).unwrap();
        s.store(Key::single(Kind::Nib), &[9]).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(s.load(k, &mut buf).unwrap(), Some(3));
        assert_eq!(&buf[..3], &[1, 2, 3]);
        assert_eq!(s.load(k, &mut [0; 2]), Err(StorageError::BufferTooSmall));
        s.store(k, &[4]).unwrap();
        assert_eq!(s.load(k, &mut buf).unwrap(), Some(1));
        assert_eq!(s.len(), 2);
        s.erase_kind(Kind::LinkKey).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.store(k, &[0; 9]), Err(StorageError::Full));
        assert_eq!(s.writes, 3);
    }
}
