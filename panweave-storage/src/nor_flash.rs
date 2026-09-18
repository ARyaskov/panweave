//! A log-structured [`Storage`] on any NOR flash of the `embedded-storage`
//! traits: the on-chip flash of an ESP32 or nRF, an external SPI flash.
//!
//! The region is split in two halves of whole sectors. Records are
//! appended to the active half, the newest record of a key being the
//! truth; a full half is compacted by copying the live records to the
//! other half and switching to it. The switch is atomic: the new half's
//! header — a magic and a sequence number — is written after its
//! records, so a power loss during compaction leaves the old half
//! active. Every record carries a CRC; a partially written record
//! (power loss mid-write) fails it and is skipped.
//!
//! [`Storage::store`] returns only once the record is in flash, as the
//! frame-counter contract requires (`docs/storage-model.md`). A store
//! costs one write of `16 + len` octets (rounded up to the flash's
//! alignment) and, when the half is full, a compaction: one sector erase
//! per sector of a half plus the live records rewritten.

use embedded_storage::nor_flash::NorFlash;

use crate::{Key, Kind, Storage, StorageError};

/// Largest record payload.
pub const MAX_RECORD: usize = 512;

const MAGIC: [u8; 4] = *b"PWS1";
const HEADER: usize = 16;
const TAG_RECORD: u8 = 0xA5;
const FLAG_SET: u8 = 0;
const FLAG_ERASED: u8 = 1;
const FLAG_KIND_ERASED: u8 = 2;

/// A [`Storage`] over the NOR flash `F`, in `len` octets at `base`.
pub struct NorFlashStore<F: NorFlash> {
    flash: F,
    base: u32,
    half: u32,
    /// 0 or 1: the half records are appended to.
    active: u32,
    /// Sequence number of the active half.
    seq: u32,
    /// Offset of the first free octet in the active half.
    tail: u32,
}

impl<F: NorFlash> core::fmt::Debug for NorFlashStore<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NorFlashStore")
            .field("base", &self.base)
            .field("half", &self.half)
            .field("active", &self.active)
            .field("seq", &self.seq)
            .field("tail", &self.tail)
            .finish_non_exhaustive()
    }
}

/// Header length as an offset.
const HEADER_LEN: u32 = 16;

/// Every offset and length in the log is a multiple of this: the
/// larger of the flash's read and write granules, at least four.
#[allow(clippy::cast_possible_truncation)]
const fn align<F: NorFlash>() -> u32 {
    let a = if F::READ_SIZE > F::WRITE_SIZE {
        F::READ_SIZE
    } else {
        F::WRITE_SIZE
    };
    let a = if a < 4 { 4 } else { a };
    a as u32
}

/// The flash's sector size as an offset.
#[allow(clippy::cast_possible_truncation)]
const fn sector<F: NorFlash>() -> u32 {
    F::ERASE_SIZE as u32
}

const fn round_up(n: u32, align: u32) -> u32 {
    n.div_ceil(align) * align
}

fn crc16(bytes: &[u8]) -> u16 {
    // CRC-16/CCITT-FALSE, bit by bit: the store writes a few records an
    // hour and has no use for a table.
    let mut crc: u16 = 0xffff;
    for &b in bytes {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// One decoded record header.
#[derive(Clone, Copy)]
struct Record {
    kind: u8,
    flags: u8,
    id: u64,
    len: u16,
    crc: u16,
}

impl Record {
    fn matches(&self, key: Key) -> bool {
        self.kind == key.kind.code() && self.id == key.id
    }

    /// Size of the record in the log.
    const fn size<F: NorFlash>(&self) -> u32 {
        round_up(HEADER_LEN + self.len as u32, align::<F>())
    }
}

impl<F: NorFlash> NorFlashStore<F> {
    /// Opens the store in `len` octets at `base` (both multiples of two
    /// sectors), formatting the region when no half carries a valid
    /// header.
    pub fn new(flash: F, base: u32, len: u32) -> Result<Self, StorageError> {
        let sector = sector::<F>();
        if len < 2 * sector || !len.is_multiple_of(2 * sector) || !base.is_multiple_of(sector) {
            return Err(StorageError::Io);
        }
        let mut s = NorFlashStore {
            flash,
            base,
            half: len / 2,
            active: 0,
            seq: 0,
            tail: HEADER_LEN,
        };
        let a = s.header(0)?;
        let b = s.header(1)?;
        match (a, b) {
            (None, None) => s.format()?,
            (Some(sa), Some(sb)) => {
                // Both valid only when a compaction's old half was not
                // erased yet: the newer sequence wins.
                s.active = u32::from(sb.wrapping_sub(sa) < u32::MAX / 2);
                s.seq = if s.active == 1 { sb } else { sa };
                s.scan_tail()?;
            }
            (Some(sa), None) => {
                s.active = 0;
                s.seq = sa;
                s.scan_tail()?;
            }
            (None, Some(sb)) => {
                s.active = 1;
                s.seq = sb;
                s.scan_tail()?;
            }
        }
        Ok(s)
    }

    /// Erases the whole region and starts an empty log.
    pub fn format(&mut self) -> Result<(), StorageError> {
        self.erase_half(0)?;
        self.erase_half(1)?;
        self.active = 0;
        self.seq = 1;
        self.write_header(0, 1)?;
        self.tail = HEADER_LEN;
        Ok(())
    }

    /// The flash, for the application's own use.
    pub fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }

    /// Octets left in the active half before a compaction.
    pub fn free(&self) -> u32 {
        self.half - self.tail
    }

    fn half_base(&self, half: u32) -> u32 {
        self.base + half * self.half
    }

    fn erase_half(&mut self, half: u32) -> Result<(), StorageError> {
        let from = self.half_base(half);
        self.flash
            .erase(from, from + self.half)
            .map_err(|_| StorageError::Io)
    }

    /// The sequence number of a half with a valid header.
    fn header(&mut self, half: u32) -> Result<Option<u32>, StorageError> {
        let mut buf = [0u8; HEADER];
        let at = self.half_base(half);
        self.flash
            .read(at, &mut buf)
            .map_err(|_| StorageError::Io)?;
        if buf[..4] != MAGIC {
            return Ok(None);
        }
        Ok(Some(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]])))
    }

    fn write_header(&mut self, half: u32, seq: u32) -> Result<(), StorageError> {
        let mut buf = [0xffu8; HEADER];
        buf[..4].copy_from_slice(&MAGIC);
        buf[4..8].copy_from_slice(&seq.to_le_bytes());
        let at = self.half_base(half);
        self.flash.write(at, &buf).map_err(|_| StorageError::Io)
    }

    fn read_record(&mut self, half: u32, at: u32) -> Result<Option<Record>, StorageError> {
        if at + HEADER_LEN > self.half {
            return Ok(None);
        }
        let mut buf = [0u8; HEADER];
        self.flash
            .read(self.half_base(half) + at, &mut buf)
            .map_err(|_| StorageError::Io)?;
        if buf[0] != TAG_RECORD {
            return Ok(None);
        }
        let len = u16::from_le_bytes([buf[4], buf[5]]);
        if usize::from(len) > MAX_RECORD {
            return Ok(None);
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&buf[8..16]);
        Ok(Some(Record {
            kind: buf[1],
            flags: buf[2],
            id: u64::from_le_bytes(id),
            len,
            crc: u16::from_le_bytes([buf[6], buf[7]]),
        }))
    }

    /// Reads a record's payload into `buf` and checks the CRC; `Ok(false)`
    /// when the record is corrupt.
    fn read_payload(
        &mut self,
        half: u32,
        at: u32,
        r: &Record,
        buf: &mut [u8],
    ) -> Result<bool, StorageError> {
        let n = usize::from(r.len);
        let Some(dst) = buf.get_mut(..n) else {
            return Err(StorageError::BufferTooSmall);
        };
        if n > 0 {
            // Read the aligned span the payload lies in.
            let padded = round_up(u32::from(r.len), align::<F>()) as usize;
            let mut tmp = [0u8; MAX_RECORD + 16];
            self.flash
                .read(self.half_base(half) + at + HEADER_LEN, &mut tmp[..padded])
                .map_err(|_| StorageError::Io)?;
            dst.copy_from_slice(&tmp[..n]);
        }
        Ok(crc16(dst) == r.crc)
    }

    /// Positions `tail` after the last record of the active half.
    fn scan_tail(&mut self) -> Result<(), StorageError> {
        let mut at = HEADER_LEN;
        while let Some(r) = self.read_record(self.active, at)? {
            at += r.size::<F>();
        }
        self.tail = at;
        Ok(())
    }

    /// Walks the records of `half` in order, calling `f(offset, record)`
    /// until it returns `false`.
    fn walk(
        &mut self,
        half: u32,
        mut f: impl FnMut(&mut Self, u32, Record) -> Result<bool, StorageError>,
    ) -> Result<(), StorageError> {
        let mut at = HEADER_LEN;
        while let Some(r) = self.read_record(half, at)? {
            if !f(self, at, r)? {
                break;
            }
            at += r.size::<F>();
        }
        Ok(())
    }

    /// The offset of the record that decides `key` in `half`, if any:
    /// its last `set` unless a later erase covers it.
    fn find(&mut self, half: u32, key: Key) -> Result<Option<(u32, Record)>, StorageError> {
        let mut found = None;
        self.walk(half, |_, at, r| {
            if r.flags == FLAG_KIND_ERASED && r.kind == key.kind.code() {
                found = None;
            } else if r.matches(key) {
                found = if r.flags == FLAG_SET {
                    Some((at, r))
                } else {
                    None
                };
            }
            Ok(true)
        })?;
        Ok(found)
    }

    /// Whether the record at `at` in `half` is the one that decides its
    /// key.
    fn is_live(&mut self, half: u32, at: u32, r: Record) -> Result<bool, StorageError> {
        if r.flags != FLAG_SET {
            return Ok(false);
        }
        let key = Key {
            kind: Kind::from_code(r.kind).unwrap_or(Kind::Application),
            id: r.id,
        };
        if Kind::from_code(r.kind).is_none() {
            return Ok(false);
        }
        Ok(self.find(half, key)?.is_some_and(|(live, _)| live == at))
    }

    fn append(&mut self, kind: u8, flags: u8, id: u64, data: &[u8]) -> Result<(), StorageError> {
        if data.len() > MAX_RECORD {
            return Err(StorageError::Full);
        }
        let len = u16::try_from(data.len()).map_err(|_| StorageError::Full)?;
        let size = round_up(HEADER_LEN + u32::from(len), align::<F>());
        if self.tail + size > self.half {
            self.compact()?;
            if self.tail + size > self.half {
                return Err(StorageError::Full);
            }
        }
        let mut buf = [0xffu8; HEADER + MAX_RECORD + 16];
        buf[0] = TAG_RECORD;
        buf[1] = kind;
        buf[2] = flags;
        buf[3] = 0;
        buf[4..6].copy_from_slice(&len.to_le_bytes());
        buf[6..8].copy_from_slice(&crc16(data).to_le_bytes());
        buf[8..16].copy_from_slice(&id.to_le_bytes());
        buf[HEADER..HEADER + data.len()].copy_from_slice(data);
        let at = self.half_base(self.active) + self.tail;
        self.flash
            .write(at, &buf[..size as usize])
            .map_err(|_| StorageError::Io)?;
        self.tail += size;
        Ok(())
    }

    /// Copies the live records to the other half and switches to it.
    fn compact(&mut self) -> Result<(), StorageError> {
        let old = self.active;
        let new = 1 - old;
        self.erase_half(new)?;
        let mut out = HEADER_LEN;
        let mut at = HEADER_LEN;
        let mut payload = [0u8; MAX_RECORD];
        while let Some(r) = self.read_record(old, at)? {
            if self.is_live(old, at, r)? && self.read_payload(old, at, &r, &mut payload)? {
                let size = r.size::<F>();
                let mut buf = [0xffu8; HEADER + MAX_RECORD + 16];
                buf[0] = TAG_RECORD;
                buf[1] = r.kind;
                buf[2] = r.flags;
                buf[3] = 0;
                buf[4..6].copy_from_slice(&r.len.to_le_bytes());
                buf[6..8].copy_from_slice(&r.crc.to_le_bytes());
                buf[8..16].copy_from_slice(&r.id.to_le_bytes());
                buf[HEADER..HEADER + usize::from(r.len)]
                    .copy_from_slice(&payload[..usize::from(r.len)]);
                self.flash
                    .write(self.half_base(new) + out, &buf[..size as usize])
                    .map_err(|_| StorageError::Io)?;
                out += size;
            }
            at += r.size::<F>();
        }
        // The header last: until now the new half was invalid and the
        // old one still the truth.
        let seq = self.seq.wrapping_add(1);
        self.write_header(new, seq)?;
        self.active = new;
        self.seq = seq;
        self.tail = out;
        self.erase_half(old)
    }
}

impl<F: NorFlash> Storage for NorFlashStore<F> {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        self.append(key.kind.code(), FLAG_SET, key.id, data)
    }

    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        let Some((at, r)) = self.find(self.active, key)? else {
            return Ok(None);
        };
        if usize::from(r.len) > buf.len() {
            return Err(StorageError::BufferTooSmall);
        }
        if self.read_payload(self.active, at, &r, buf)? {
            Ok(Some(usize::from(r.len)))
        } else {
            Ok(None)
        }
    }

    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        if self.find(self.active, key)?.is_none() {
            return Ok(());
        }
        self.append(key.kind.code(), FLAG_ERASED, key.id, &[])
    }

    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        let code = kind.code();
        let mut any = false;
        self.walk(self.active, |s, at, r| {
            if r.kind == code && s.is_live(s.active, at, r)? {
                any = true;
                return Ok(false);
            }
            Ok(true)
        })?;
        if !any {
            return Ok(());
        }
        self.append(code, FLAG_KIND_ERASED, 0, &[])
    }
}

#[cfg(test)]
mod tests {
    use embedded_storage::nor_flash::{ErrorType, NorFlashError, NorFlashErrorKind, ReadNorFlash};

    use super::*;

    const SECTOR: usize = 4096;
    const S: u32 = 4096;

    /// A NOR flash in RAM with the real rules: erase sets a whole sector
    /// to 0xFF, a write only clears bits, everything aligned.
    struct RamFlash {
        cells: Vec<u8>,
        erases: u32,
        /// Writes left before a simulated power loss.
        fuel: Option<u32>,
    }

    #[derive(Debug)]
    struct E;

    impl NorFlashError for E {
        fn kind(&self) -> NorFlashErrorKind {
            NorFlashErrorKind::Other
        }
    }

    impl ErrorType for RamFlash {
        type Error = E;
    }

    impl ReadNorFlash for RamFlash {
        const READ_SIZE: usize = 4;
        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), E> {
            assert_eq!(offset % 4, 0);
            assert_eq!(bytes.len() % 4, 0);
            let o = offset as usize;
            bytes.copy_from_slice(&self.cells[o..o + bytes.len()]);
            Ok(())
        }
        fn capacity(&self) -> usize {
            self.cells.len()
        }
    }

    impl NorFlash for RamFlash {
        const WRITE_SIZE: usize = 4;
        const ERASE_SIZE: usize = SECTOR;
        fn erase(&mut self, from: u32, to: u32) -> Result<(), E> {
            assert_eq!(from as usize % SECTOR, 0);
            assert_eq!(to as usize % SECTOR, 0);
            self.erases += 1;
            self.cells[from as usize..to as usize].fill(0xff);
            Ok(())
        }
        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), E> {
            assert_eq!(offset % 4, 0);
            assert_eq!(bytes.len() % 4, 0);
            if let Some(f) = &mut self.fuel {
                if *f == 0 {
                    return Err(E);
                }
                *f -= 1;
            }
            let o = offset as usize;
            for (c, b) in self.cells[o..o + bytes.len()].iter_mut().zip(bytes) {
                assert_eq!(*c & *b, *b, "write sets a bit at {offset:#x}");
                *c = *b;
            }
            Ok(())
        }
    }

    fn flash() -> RamFlash {
        RamFlash {
            cells: vec![0u8; 8 * SECTOR],
            erases: 0,
            fuel: None,
        }
    }

    #[test]
    fn records_round_trip_and_survive_reopening() {
        let mut s = NorFlashStore::new(flash(), S, 4 * S).unwrap();
        let k = Key::with_id(Kind::LinkKey, 0x1122);
        let mut buf = [0u8; 64];
        assert_eq!(s.load(k, &mut buf).unwrap(), None);
        s.store(k, &[1, 2, 3]).unwrap();
        s.store(Key::single(Kind::Nib), &[9; 33]).unwrap();
        assert_eq!(s.load(k, &mut buf).unwrap(), Some(3));
        assert_eq!(&buf[..3], &[1, 2, 3]);
        s.store(k, &[4]).unwrap();
        assert_eq!(s.load(k, &mut buf).unwrap(), Some(1));
        assert_eq!(buf[0], 4);
        assert_eq!(s.load(k, &mut [0; 0]), Err(StorageError::BufferTooSmall));
        // Reopen: the log is scanned again.
        let NorFlashStore { flash, .. } = s;
        let mut s = NorFlashStore::new(flash, S, 4 * S).unwrap();
        assert_eq!(s.load(k, &mut buf).unwrap(), Some(1));
        assert_eq!(s.load(Key::single(Kind::Nib), &mut buf).unwrap(), Some(33));
        s.erase(k).unwrap();
        assert_eq!(s.load(k, &mut buf).unwrap(), None);
        s.store(Key::with_id(Kind::LinkKey, 5), &[5]).unwrap();
        s.erase_kind(Kind::LinkKey).unwrap();
        assert_eq!(
            s.load(Key::with_id(Kind::LinkKey, 5), &mut buf).unwrap(),
            None
        );
        assert_eq!(s.load(Key::single(Kind::Nib), &mut buf).unwrap(), Some(33));
        // A set after an erase-kind is visible again.
        s.store(Key::with_id(Kind::LinkKey, 5), &[6]).unwrap();
        assert_eq!(
            s.load(Key::with_id(Kind::LinkKey, 5), &mut buf).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn a_full_half_is_compacted_to_the_live_records() {
        let mut s = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        let counter = Key::single(Kind::NwkFrameCounter);
        let nib = Key::single(Kind::Nib);
        s.store(nib, &[7; 100]).unwrap();
        // 4-octet counters: 20 octets each, ~200 fit in a half.
        for i in 0..1000u32 {
            s.store(counter, &i.to_le_bytes()).unwrap();
        }
        let mut buf = [0u8; 128];
        assert_eq!(s.load(counter, &mut buf).unwrap(), Some(4));
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 999);
        assert_eq!(s.load(nib, &mut buf).unwrap(), Some(100));
        assert!(s.flash.erases > 2, "compactions happened");
        // The last compaction left the half with the two live records
        // and the counters written since.
        assert!(s.free() > S / 2, "{}", s.free());
        // Over-long records are refused, not split.
        assert_eq!(s.store(nib, &[0; MAX_RECORD + 1]), Err(StorageError::Full));
    }

    #[test]
    fn power_loss_during_compaction_keeps_the_old_half() {
        let mut s = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        let nib = Key::single(Kind::Nib);
        s.store(nib, &[1; 200]).unwrap();
        let counter = Key::single(Kind::NwkFrameCounter);
        let mut i = 0u32;
        while s.free() >= 20 {
            s.store(counter, &i.to_le_bytes()).unwrap();
            i += 1;
        }
        // The next store compacts; the power fails after the first record
        // is copied.
        s.flash.fuel = Some(1);
        assert_eq!(s.store(counter, &i.to_le_bytes()), Err(StorageError::Io));
        s.flash.fuel = None;
        let NorFlashStore { flash, .. } = s;
        let mut s = NorFlashStore::new(flash, 0, 2 * S).unwrap();
        let mut buf = [0u8; 256];
        assert_eq!(s.load(nib, &mut buf).unwrap(), Some(200));
        assert_eq!(s.load(counter, &mut buf).unwrap(), Some(4));
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), i - 1);
        // And the store works on.
        s.store(counter, &i.to_le_bytes()).unwrap();
        assert_eq!(s.load(counter, &mut buf).unwrap(), Some(4));
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), i);
    }

    #[test]
    fn a_torn_record_is_skipped() {
        let mut s = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        let nib = Key::single(Kind::Nib);
        s.store(nib, &[1, 2, 3, 4]).unwrap();
        // Corrupt the payload of the record just written.
        let at = (s.tail - 4) as usize;
        s.flash.cells[at] &= 0xf0;
        let mut buf = [0u8; 8];
        assert_eq!(s.load(nib, &mut buf).unwrap(), None);
        s.store(nib, &[5]).unwrap();
        assert_eq!(s.load(nib, &mut buf).unwrap(), Some(1));
    }
}
