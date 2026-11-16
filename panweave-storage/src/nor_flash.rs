//! A log-structured [`Storage`] on any NOR flash of the `embedded-storage`
//! traits: the on-chip flash of an ESP32 or nRF, an external SPI flash.
//!
//! The region is split in two halves of whole sectors. Records are
//! appended to the active half, the newest record of a key being the
//! truth; a full half is compacted by copying the live records to the
//! other half and switching to it. The switch is atomic: the new half's
//! header — a magic and a sequence number — is written after its
//! records, so a power loss during compaction leaves the old half
//! active. Version 2 records commit only after their metadata and payload
//! are durable. Interrupted appends leave the previous value intact;
//! damage to a committed record is reported instead of hiding it as absent.
//!
//! [`Storage::store`] returns only once the record is in flash, as the
//! frame-counter contract requires (`docs/storage-model.md`). A store
//! costs an aligned metadata/payload write and a commit write and, when
//! the half is full, a compaction: one sector erase
//! per sector of a half plus the live records rewritten.

use core::cell::RefCell;
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};

use crate::{Key, Kind, Storage, StorageError};

/// A borrowed NOR driver shared by disjoint stores in a single execution
/// context. Each operation borrows the driver for its duration and forwards
/// explicitly to the NOR traits, even if the driver also has an inherent
/// `write` method with sector-erasing read/modify/write semantics.
pub struct SharedNorFlash<'a, F>(&'a RefCell<F>);

impl<'a, F> SharedNorFlash<'a, F> {
    /// Shares a driver. The caller keeps each store's region disjoint and
    /// must not access the cell recursively or concurrently from interrupts.
    pub const fn new(flash: &'a RefCell<F>) -> Self {
        Self(flash)
    }
}

impl<F> Copy for SharedNorFlash<'_, F> {}

impl<F> Clone for SharedNorFlash<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: ErrorType> ErrorType for SharedNorFlash<'_, F> {
    type Error = F::Error;
}

impl<F: ReadNorFlash> ReadNorFlash for SharedNorFlash<'_, F> {
    const READ_SIZE: usize = F::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        ReadNorFlash::read(&mut *self.0.borrow_mut(), offset, bytes)
    }

    fn capacity(&self) -> usize {
        ReadNorFlash::capacity(&*self.0.borrow())
    }
}

impl<F: NorFlash> NorFlash for SharedNorFlash<'_, F> {
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        NorFlash::write(&mut *self.0.borrow_mut(), offset, bytes)
    }

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        NorFlash::erase(&mut *self.0.borrow_mut(), from, to)
    }
}

/// Largest record payload.
pub const MAX_RECORD: usize = 512;

const LEGACY_MAGIC: [u8; 4] = *b"PWS1";
const MAGIC: [u8; 4] = *b"PWS2";
const HEADER: usize = 16;
const RECORD_HEADER: u32 = 20;
const TAG_RECORD: u8 = 0xA5;
const FLAG_SET: u8 = 0;
const FLAG_ERASED: u8 = 1;
const FLAG_KIND_ERASED: u8 = 2;

/// Counters of a [`NorFlashStore`], for diagnostics. They live in RAM
/// and restart at every boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreStats {
    /// The region was blank when opened and was formatted.
    pub formatted_at_open: bool,
    /// Committed records whose metadata or payload failed validation.
    pub corrupt_records: u32,
    /// Records appended.
    pub writes: u32,
    /// Compactions (half switches).
    pub compactions: u32,
    /// Operations that failed with an I/O error of the flash.
    pub io_errors: u32,
}

/// A [`Storage`] over the NOR flash `F`, in `len` octets at `base`.
pub struct NorFlashStore<F: NorFlash> {
    flash: F,
    /// Counters.
    pub stats: StoreStats,
    base: u32,
    half: u32,
    /// 0 or 1: the half records are appended to.
    active: u32,
    /// Sequence number of the active half.
    seq: u32,
    /// Offset of the first free octet in the active half.
    tail: u32,
    format: Format,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Legacy,
    Committed,
}

impl Format {
    const fn half_header<F: NorFlash>(self) -> u32 {
        match self {
            Self::Legacy => HEADER_LEN,
            Self::Committed => align::<F>() + round_up(HEADER_LEN, align::<F>()),
        }
    }

    const fn payload_offset<F: NorFlash>(self) -> u32 {
        match self {
            Self::Legacy => HEADER_LEN,
            Self::Committed => align::<F>() + round_up(RECORD_HEADER, align::<F>()),
        }
    }
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

/// Octets moved per flash access when a record is read, written or
/// copied: records stream through this much stack, not a whole record.
const CHUNK: usize = 64;

/// The largest multiple of the store's alignment within [`CHUNK`].
#[allow(clippy::cast_possible_truncation)]
const fn chunk<F: NorFlash>() -> usize {
    let a = align::<F>() as usize;
    CHUNK - CHUNK % a
}

fn crc16(bytes: &[u8]) -> u16 {
    crc16_update(0xffff, bytes)
}

fn crc16_update(mut crc: u16, bytes: &[u8]) -> u16 {
    // CRC-16/CCITT-FALSE, bit by bit: the store writes a few records an
    // hour and has no use for a table.
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

/// Streams a record into the log in aligned chunks of at most [`CHUNK`]
/// octets, padding the tail with 0xFF.
struct ChunkWriter {
    buf: [u8; CHUNK],
    fill: usize,
    at: u32,
}

impl ChunkWriter {
    const fn new(at: u32) -> Self {
        ChunkWriter {
            buf: [0xff; CHUNK],
            fill: 0,
            at,
        }
    }

    fn push<F: NorFlash>(&mut self, flash: &mut F, mut bytes: &[u8]) -> Result<(), StorageError> {
        let cap = chunk::<F>();
        while !bytes.is_empty() {
            let n = (cap - self.fill).min(bytes.len());
            self.buf[self.fill..self.fill + n].copy_from_slice(&bytes[..n]);
            self.fill += n;
            bytes = &bytes[n..];
            if self.fill == cap {
                self.flush(flash)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn flush<F: NorFlash>(&mut self, flash: &mut F) -> Result<(), StorageError> {
        if self.fill == 0 {
            return Ok(());
        }
        let n = round_up(self.fill as u32, align::<F>()) as usize;
        flash
            .write(self.at, &self.buf[..n])
            .map_err(|_| StorageError::Io)?;
        self.at += n as u32;
        self.buf = [0xff; CHUNK];
        self.fill = 0;
        Ok(())
    }
}

/// One decoded record header.
#[derive(Clone, Copy)]
struct Record {
    kind: u8,
    flags: u8,
    id: u64,
    len: u16,
    crc: u16,
    format: Format,
}

impl Record {
    fn matches(&self, key: Key) -> bool {
        self.kind == key.kind.code() && self.id == key.id
    }

    /// Size of the record in the log.
    const fn size<F: NorFlash>(&self) -> u32 {
        round_up(
            self.format.payload_offset::<F>() + self.len as u32,
            align::<F>(),
        )
    }
}

impl<F: NorFlash> NorFlashStore<F> {
    /// Opens the store in `len` octets at `base` (both multiples of two
    /// sectors), formatting only a fully erased region. Unknown or damaged
    /// committed state returns `Corrupt` and is left untouched. Version 1
    /// records remain readable and migrate on the first mutation.
    /// Fails with `Io` for an out-of-bounds region or a flash whose read or
    /// write granule exceeds 64 octets.
    pub fn new(flash: F, base: u32, len: u32) -> Result<Self, StorageError> {
        let sector = sector::<F>();
        // Records stream through CHUNK-octet buffers.
        if align::<F>() as usize > CHUNK || sector == 0 {
            return Err(StorageError::Io);
        }
        let region_end = base.checked_add(len).ok_or(StorageError::Io)?;
        if !usize::try_from(region_end).is_ok_and(|end| end <= flash.capacity())
            || len < 2 * sector
            || !len.is_multiple_of(2 * sector)
            || !base.is_multiple_of(sector)
        {
            return Err(StorageError::Io);
        }
        let mut s = NorFlashStore {
            flash,
            stats: StoreStats::default(),
            base,
            half: len / 2,
            active: 0,
            seq: 0,
            tail: Format::Committed.half_header::<F>(),
            format: Format::Committed,
        };
        let a = s.header(0)?;
        let b = s.header(1)?;
        match (a, b) {
            (None, None) => {
                if !s.erased_from(0, 0)? || !s.erased_from(1, 0)? {
                    return Err(StorageError::Corrupt);
                }
                s.stats.formatted_at_open = true;
                s.format()?;
            }
            (Some((sa, fa)), Some((sb, fb))) => {
                // Both valid only when a compaction's old half was not
                // erased yet: the newer sequence wins.
                s.active = u32::from(sb.wrapping_sub(sa) < u32::MAX / 2);
                s.seq = if s.active == 1 { sb } else { sa };
                s.format = if s.active == 1 { fb } else { fa };
                s.scan_tail()?;
            }
            (Some((sa, format)), None) => {
                s.active = 0;
                s.seq = sa;
                s.format = format;
                s.scan_tail()?;
            }
            (None, Some((sb, format))) => {
                s.active = 1;
                s.seq = sb;
                s.format = format;
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
        self.format = Format::Committed;
        self.write_header(0, 1)?;
        self.tail = self.format.half_header::<F>();
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

    /// Size of one half: the most the live records can occupy.
    pub fn capacity(&self) -> u32 {
        self.half
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
    fn header(&mut self, half: u32) -> Result<Option<(u32, Format)>, StorageError> {
        let mut buf = [0u8; CHUNK];
        let at = self.half_base(half);
        let n = round_up(HEADER_LEN, align::<F>()) as usize;
        self.flash
            .read(at, &mut buf[..n])
            .map_err(|_| StorageError::Io)?;
        if buf[..4] == LEGACY_MAGIC {
            return Ok(Some((
                u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
                Format::Legacy,
            )));
        }
        if buf[..4] != MAGIC {
            return Ok(None);
        }
        self.flash
            .read(at + align::<F>(), &mut buf[..n])
            .map_err(|_| StorageError::Io)?;
        if crc16(&buf[..4]) != u16::from_le_bytes([buf[4], buf[5]]) {
            return Err(StorageError::Corrupt);
        }
        Ok(Some((
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            Format::Committed,
        )))
    }

    fn write_header(&mut self, half: u32, seq: u32) -> Result<(), StorageError> {
        let mut buf = [0xffu8; CHUNK];
        buf[..4].copy_from_slice(&seq.to_le_bytes());
        let crc = crc16(&buf[..4]);
        buf[4..6].copy_from_slice(&crc.to_le_bytes());
        let at = self.half_base(half);
        let n = round_up(HEADER_LEN, align::<F>()) as usize;
        self.flash
            .write(at + align::<F>(), &buf[..n])
            .map_err(|_| StorageError::Io)?;
        // A separate write granule commits the fully copied half.
        buf.fill(0);
        buf[..4].copy_from_slice(&MAGIC);
        self.flash
            .write(at, &buf[..align::<F>() as usize])
            .map_err(|_| StorageError::Io)
    }

    fn read_record(&mut self, half: u32, at: u32) -> Result<Option<Record>, StorageError> {
        let offset = self.format.payload_offset::<F>();
        if at + offset > self.half {
            return Ok(None);
        }
        let mut buf = [0u8; CHUNK];
        let mut metadata = self.half_base(half) + at;
        let n = match self.format {
            Format::Legacy => HEADER,
            Format::Committed => {
                let a = align::<F>() as usize;
                self.flash
                    .read(metadata, &mut buf[..a])
                    .map_err(|_| StorageError::Io)?;
                if buf[..a].iter().all(|b| *b == 0xff) {
                    return Ok(None);
                }
                metadata += align::<F>();
                round_up(RECORD_HEADER, align::<F>()) as usize
            }
        };
        self.flash
            .read(metadata, &mut buf[..n])
            .map_err(|_| StorageError::Io)?;
        if self.format == Format::Legacy && buf[..n].iter().all(|b| *b == 0xff) {
            return Ok(None);
        }
        if buf[0] != TAG_RECORD
            || Kind::from_code(buf[1]).is_none()
            || !matches!(buf[2], FLAG_SET | FLAG_ERASED | FLAG_KIND_ERASED)
            || (self.format == Format::Committed
                && crc16(&buf[..16]) != u16::from_le_bytes([buf[16], buf[17]]))
        {
            self.stats.corrupt_records = self.stats.corrupt_records.saturating_add(1);
            return Err(StorageError::Corrupt);
        }
        let len = u16::from_le_bytes([buf[4], buf[5]]);
        if usize::from(len) > MAX_RECORD || at + offset + u32::from(len) > self.half {
            return Err(StorageError::Corrupt);
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&buf[8..16]);
        Ok(Some(Record {
            kind: buf[1],
            flags: buf[2],
            id: u64::from_le_bytes(id),
            len,
            crc: u16::from_le_bytes([buf[6], buf[7]]),
            format: self.format,
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
        // The aligned part straight into `dst`, the unaligned tail
        // through a chunk.
        let a = align::<F>() as usize;
        let body = n - n % a;
        let base = self.half_base(half) + at + r.format.payload_offset::<F>();
        if body > 0 {
            self.flash
                .read(base, &mut dst[..body])
                .map_err(|_| StorageError::Io)?;
        }
        if body < n {
            let mut tmp = [0u8; CHUNK];
            #[allow(clippy::cast_possible_truncation)]
            self.flash
                .read(base + body as u32, &mut tmp[..a])
                .map_err(|_| StorageError::Io)?;
            dst[body..].copy_from_slice(&tmp[..n - body]);
        }
        let ok = crc16(dst) == r.crc;
        if !ok {
            self.stats.corrupt_records = self.stats.corrupt_records.saturating_add(1);
        }
        Ok(ok)
    }

    /// Whether a record's payload matches its CRC, read chunk by chunk.
    fn payload_intact(&mut self, half: u32, at: u32, r: &Record) -> Result<bool, StorageError> {
        let src = self.half_base(half) + at + r.format.payload_offset::<F>();
        let len = usize::from(r.len);
        let cap = chunk::<F>();
        let mut crc = 0xffff;
        let mut done = 0usize;
        while done < len {
            let mut tmp = [0u8; CHUNK];
            let n = (len - done).min(cap);
            #[allow(clippy::cast_possible_truncation)]
            let padded = round_up(n as u32, align::<F>()) as usize;
            #[allow(clippy::cast_possible_truncation)]
            self.flash
                .read(src + done as u32, &mut tmp[..padded])
                .map_err(|_| StorageError::Io)?;
            crc = crc16_update(crc, &tmp[..n]);
            done += n;
        }
        let ok = crc == r.crc;
        if !ok {
            self.stats.corrupt_records = self.stats.corrupt_records.saturating_add(1);
        }
        Ok(ok)
    }

    /// Positions `tail` after the last record of the active half.
    fn scan_tail(&mut self) -> Result<(), StorageError> {
        let mut at = self.format.half_header::<F>();
        while let Some(r) = self.read_record(self.active, at)? {
            at += r.size::<F>();
        }
        // A failed append may have programmed its body without its commit
        // block. Compact before reusing that NOR region.
        self.tail = if self.erased_from(self.active, at)? {
            at
        } else {
            self.half
        };
        Ok(())
    }

    fn erased_from(&mut self, half: u32, mut at: u32) -> Result<bool, StorageError> {
        let mut buf = [0u8; CHUNK];
        let cap = u32::try_from(chunk::<F>()).map_err(|_| StorageError::Io)?;
        while at < self.half {
            let n = (self.half - at).min(cap) as usize;
            self.flash
                .read(self.half_base(half) + at, &mut buf[..n])
                .map_err(|_| StorageError::Io)?;
            if buf[..n].iter().any(|b| *b != 0xff) {
                return Ok(false);
            }
            at += u32::try_from(n).map_err(|_| StorageError::Io)?;
        }
        Ok(true)
    }

    /// Walks the records of `half` in order, calling `f(offset, record)`
    /// until it returns `false`.
    fn walk(
        &mut self,
        half: u32,
        mut f: impl FnMut(&mut Self, u32, Record) -> Result<bool, StorageError>,
    ) -> Result<(), StorageError> {
        let mut at = self.format.half_header::<F>();
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
        let size = round_up(
            Format::Committed.payload_offset::<F>() + u32::from(len),
            align::<F>(),
        );
        if self.format == Format::Legacy || self.tail + size > self.half {
            self.compact()?;
            if self.tail + size > self.half {
                return Err(StorageError::Full);
            }
        }
        let at = self.half_base(self.active) + self.tail;
        let mut w = ChunkWriter::new(at + align::<F>());
        let header = committed_record_header(kind, flags, id, len, crc16(data));
        let header_len = round_up(RECORD_HEADER, align::<F>()) as usize;
        let written = w
            .push(&mut self.flash, &header[..header_len])
            .and_then(|()| w.push(&mut self.flash, data))
            .and_then(|()| w.flush(&mut self.flash))
            .and_then(|()| {
                self.flash
                    .write(at, &[0u8; CHUNK][..align::<F>() as usize])
                    .map_err(|_| StorageError::Io)
            });
        if written.is_err() {
            self.tail = self.half;
            self.stats.io_errors = self.stats.io_errors.saturating_add(1);
            return Err(StorageError::Io);
        }
        self.tail += size;
        self.stats.writes = self.stats.writes.saturating_add(1);
        Ok(())
    }

    /// Copies the live records to the other half and switches to it.
    fn compact(&mut self) -> Result<(), StorageError> {
        let old = self.active;
        let new = 1 - old;
        self.erase_half(new)?;
        let mut out = Format::Committed.half_header::<F>();
        let mut at = self.format.half_header::<F>();
        while let Some(r) = self.read_record(old, at)? {
            if self.is_live(old, at, r)? {
                if !self.payload_intact(old, at, &r)? {
                    return Err(StorageError::Corrupt);
                }
                let size = round_up(
                    Format::Committed.payload_offset::<F>() + u32::from(r.len),
                    align::<F>(),
                );
                if out + size > self.half {
                    return Err(StorageError::Full);
                }
                let dst = self.half_base(new) + out;
                let mut w = ChunkWriter::new(dst + align::<F>());
                let header = committed_record_header(r.kind, r.flags, r.id, r.len, r.crc);
                w.push(
                    &mut self.flash,
                    &header[..round_up(RECORD_HEADER, align::<F>()) as usize],
                )?;
                // The payload, chunk by chunk.
                let src = self.half_base(old) + at + r.format.payload_offset::<F>();
                let mut done = 0usize;
                let len = usize::from(r.len);
                let cap = chunk::<F>();
                while done < len {
                    let mut tmp = [0u8; CHUNK];
                    let n = (len - done).min(cap);
                    // Both below MAX_RECORD + CHUNK.
                    #[allow(clippy::cast_possible_truncation)]
                    let padded = round_up(n as u32, align::<F>()) as usize;
                    #[allow(clippy::cast_possible_truncation)]
                    self.flash
                        .read(src + done as u32, &mut tmp[..padded])
                        .map_err(|_| StorageError::Io)?;
                    w.push(&mut self.flash, &tmp[..n])?;
                    done += n;
                }
                w.flush(&mut self.flash)?;
                self.flash
                    .write(dst, &[0u8; CHUNK][..align::<F>() as usize])
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
        self.format = Format::Committed;
        self.stats.compactions = self.stats.compactions.saturating_add(1);
        self.erase_half(old)
    }
}

/// The 16-octet header of a record.
fn record_header(kind: u8, flags: u8, id: u64, len: u16, crc: u16) -> [u8; HEADER] {
    let mut h = [0xffu8; HEADER];
    h[0] = TAG_RECORD;
    h[1] = kind;
    h[2] = flags;
    h[3] = 0;
    h[4..6].copy_from_slice(&len.to_le_bytes());
    h[6..8].copy_from_slice(&crc.to_le_bytes());
    h[8..16].copy_from_slice(&id.to_le_bytes());
    h
}

fn committed_record_header(kind: u8, flags: u8, id: u64, len: u16, crc: u16) -> [u8; CHUNK] {
    let mut h = [0xffu8; CHUNK];
    h[..HEADER].copy_from_slice(&record_header(kind, flags, id, len, crc));
    let metadata_crc = crc16(&h[..HEADER]);
    h[16..18].copy_from_slice(&metadata_crc.to_le_bytes());
    h
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
            Err(StorageError::Corrupt)
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
    #[derive(Clone)]
    struct RamFlash {
        cells: Vec<u8>,
        erases: u32,
        /// Writes left before a simulated power loss.
        fuel: Option<u32>,
        /// Four-octet programming units left, including partial write calls.
        word_fuel: Option<usize>,
    }

    impl RamFlash {
        // Match drivers such as esp-storage that expose both interfaces.
        #[allow(dead_code)]
        fn write(&mut self, _offset: u32, _bytes: &[u8]) -> Result<(), E> {
            panic!(
                "inherent write would erase a sector ({} erases so far); use NorFlash::write",
                self.erases
            );
        }
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
            for (dst, src) in self.cells[o..o + bytes.len()]
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(bytes.as_chunks::<4>().0.iter())
            {
                if let Some(fuel) = &mut self.word_fuel {
                    if *fuel == 0 {
                        return Err(E);
                    }
                    *fuel -= 1;
                }
                for (c, b) in dst.iter_mut().zip(src) {
                    assert_eq!(*c & *b, *b, "write sets a bit at {offset:#x}");
                    *c = *b;
                }
            }
            Ok(())
        }
    }

    fn flash() -> RamFlash {
        RamFlash {
            cells: vec![0xffu8; 8 * SECTOR],
            erases: 0,
            fuel: None,
            word_fuel: None,
        }
    }

    #[test]
    fn shared_stores_append_without_sector_erases_and_reopen() {
        let driver = RefCell::new(flash());
        let shared = SharedNorFlash::new(&driver);
        let mut first = NorFlashStore::new(shared, 0, 2 * S).unwrap();
        let mut second = NorFlashStore::new(shared, 2 * S, 2 * S).unwrap();
        let erases = driver.borrow().erases;
        for value in 0..16u8 {
            first.store(Key::single(Kind::Nib), &[value; 32]).unwrap();
            second
                .store(Key::single(Kind::Application), &[value; 12])
                .unwrap();
        }
        assert_eq!(
            driver.borrow().erases,
            erases,
            "appends only program erased space"
        );
        let mut first = NorFlashStore::new(shared, 0, 2 * S).unwrap();
        let mut second = NorFlashStore::new(shared, 2 * S, 2 * S).unwrap();
        let mut buf = [0; 32];
        assert_eq!(
            first.load(Key::single(Kind::Nib), &mut buf).unwrap(),
            Some(32)
        );
        assert_eq!(buf, [15; 32]);
        assert_eq!(
            second
                .load(Key::single(Kind::Application), &mut buf)
                .unwrap(),
            Some(12)
        );
        assert_eq!(&buf[..12], &[15; 12]);
        driver.borrow_mut().fuel = Some(0);
        assert_eq!(
            first.store(Key::single(Kind::Nib), &[99; 32]),
            Err(StorageError::Io)
        );
        assert_eq!(driver.borrow().erases, erases);
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
        // Repeated counter updates eventually require compaction.
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
    fn long_unaligned_records_stream_through_compaction() {
        let mut s = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        let big = Key::single(Kind::Bindings);
        let data: Vec<u8> = (0..MAX_RECORD - 3)
            .map(|i| u8::try_from((i * 7 + 3) % 256).unwrap())
            .collect();
        s.store(big, &data).unwrap();
        let counter = Key::single(Kind::NwkFrameCounter);
        for i in 0..600u32 {
            s.store(counter, &i.to_le_bytes()).unwrap();
        }
        assert!(s.stats.compactions > 0);
        let mut buf = [0u8; MAX_RECORD];
        assert_eq!(s.load(big, &mut buf).unwrap(), Some(data.len()));
        assert_eq!(&buf[..data.len()], &data[..]);
        // Reopened from the flash alone.
        let flash = s.flash;
        let mut s = NorFlashStore::new(flash, 0, 2 * S).unwrap();
        assert_eq!(s.load(big, &mut buf).unwrap(), Some(data.len()));
        assert_eq!(&buf[..data.len()], &data[..]);
    }

    #[test]
    fn power_loss_during_compaction_keeps_the_old_half() {
        let mut s = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        let nib = Key::single(Kind::Nib);
        s.store(nib, &[1; 200]).unwrap();
        let counter = Key::single(Kind::NwkFrameCounter);
        let mut i = 0u32;
        while s.free() >= 28 {
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
    fn a_corrupt_committed_record_is_reported() {
        let mut s = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        let nib = Key::single(Kind::Nib);
        s.store(nib, &[1, 2, 3, 4]).unwrap();
        // Corrupt the payload of the record just written.
        let at = (s.tail - 4) as usize;
        s.flash.cells[at] &= 0xf0;
        let mut buf = [0u8; 8];
        assert_eq!(s.load(nib, &mut buf), Err(StorageError::Corrupt));
        assert_eq!(s.stats.corrupt_records, 1, "the corrupt record is counted");
        s.store(nib, &[5]).unwrap();
        assert_eq!(s.load(nib, &mut buf).unwrap(), Some(1));
    }

    #[test]
    fn replacements_survive_a_cut_at_every_program_word() {
        for len in [4usize, 301] {
            let key = Key::single(Kind::NwkFrameCounter);
            let old = vec![0x11; len];
            let new = vec![0x33; len];
            let mut original = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
            original.store(key, &old).unwrap();
            let image = original.flash;
            let words = (20 + len).div_ceil(4) + 1;
            for cut in 0..=words {
                let mut store = NorFlashStore::new(image.clone(), 0, 2 * S).unwrap();
                store.flash.word_fuel = Some(cut);
                let result = store.store(key, &new);
                store.flash.word_fuel = None;
                let mut reopened = NorFlashStore::new(store.flash, 0, 2 * S).unwrap();
                let mut buf = vec![0; len];
                assert_eq!(reopened.load(key, &mut buf).unwrap(), Some(len));
                assert_eq!(buf, if result.is_ok() { &new } else { &old }.as_slice());
                // A dirty tail is compacted instead of programming over it.
                reopened.store(key, &new).unwrap();
                assert_eq!(reopened.load(key, &mut buf).unwrap(), Some(len));
                assert_eq!(buf, new);
            }
        }
    }

    #[test]
    fn compaction_survives_a_cut_at_every_program_word() {
        let key = Key::single(Kind::NwkFrameCounter);
        let nib = Key::single(Kind::Nib);
        let mut original = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        original.store(nib, &[0x33; 200]).unwrap();
        let mut bound = 0u32;
        while original.free() >= 28 {
            bound += 1024;
            original.store(key, &bound.to_le_bytes()).unwrap();
        }
        let image = original.flash;
        let next = bound + 1024;
        // Two live records, the new half header and the appended counter.
        for cut in 0..=80 {
            let mut store = NorFlashStore::new(image.clone(), 0, 2 * S).unwrap();
            store.flash.word_fuel = Some(cut);
            let result = store.store(key, &next.to_le_bytes());
            store.flash.word_fuel = None;
            let mut reopened = NorFlashStore::new(store.flash, 0, 2 * S).unwrap();
            let mut buf = [0u8; 200];
            assert_eq!(reopened.load(nib, &mut buf).unwrap(), Some(200));
            assert_eq!(buf, [0x33; 200]);
            assert_eq!(reopened.load(key, &mut buf).unwrap(), Some(4));
            let actual = u32::from_le_bytes(buf[..4].try_into().unwrap());
            assert_eq!(actual, if result.is_ok() { next } else { bound });
            reopened.store(key, &next.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn corrupt_latest_counter_never_falls_back_or_disappears_in_compaction() {
        let key = Key::single(Kind::NwkFrameCounter);
        let mut store = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        store.store(key, &1024u32.to_le_bytes()).unwrap();
        store.store(key, &3072u32.to_le_bytes()).unwrap();
        let at = store.tail as usize - 4;
        store.flash.cells[at + 1] &= 0xf7;
        let mut reopened = NorFlashStore::new(store.flash, 0, 2 * S).unwrap();
        assert_eq!(reopened.load(key, &mut [0; 4]), Err(StorageError::Corrupt));
        assert_eq!(reopened.compact(), Err(StorageError::Corrupt));
    }

    #[test]
    fn legacy_records_are_read_and_migrated_before_a_new_append() {
        let mut image = flash();
        image.cells[..4].copy_from_slice(&LEGACY_MAGIC);
        image.cells[4..8].copy_from_slice(&1u32.to_le_bytes());
        let key = Key::single(Kind::NwkFrameCounter);
        let data = 2048u32.to_le_bytes();
        image.cells[16..32].copy_from_slice(&record_header(
            key.kind.code(),
            FLAG_SET,
            0,
            4,
            crc16(&data),
        ));
        image.cells[32..36].copy_from_slice(&data);
        let mut store = NorFlashStore::new(image, 0, 2 * S).unwrap();
        let mut buf = [0; 4];
        assert_eq!(store.load(key, &mut buf).unwrap(), Some(4));
        assert_eq!(buf, data);
        store.store(Key::single(Kind::Nib), &[7]).unwrap();
        let mut store = NorFlashStore::new(store.flash, 0, 2 * S).unwrap();
        assert_eq!(store.load(key, &mut buf).unwrap(), Some(4));
        assert_eq!(buf, data);
        assert!(store.format == Format::Committed);
    }

    #[test]
    fn invalid_regions_are_rejected_before_any_flash_access() {
        let image = flash();
        assert!(matches!(
            NorFlashStore::new(image.clone(), 7 * S, 2 * S),
            Err(StorageError::Io)
        ));
        assert!(matches!(
            NorFlashStore::new(image, u32::MAX - S + 1, 2 * S),
            Err(StorageError::Io)
        ));
        let mut image = flash();
        image.cells[0] = 0;
        assert!(matches!(
            NorFlashStore::new(image, 0, 2 * S),
            Err(StorageError::Corrupt)
        ));
    }

    #[test]
    fn counters_report_formatting_writes_compactions_and_io_errors() {
        let mut s = NorFlashStore::new(flash(), 0, 2 * S).unwrap();
        assert!(s.stats.formatted_at_open, "blank flash is formatted");
        assert_eq!(s.capacity(), S);
        let counter = Key::single(Kind::NwkFrameCounter);
        for i in 0..400u32 {
            s.store(counter, &i.to_le_bytes()).unwrap();
        }
        assert_eq!(s.stats.writes, 400);
        assert!(s.stats.compactions >= 1);
        assert_eq!(s.stats.corrupt_records, 0);
        s.flash.fuel = Some(0);
        assert_eq!(s.store(counter, &[1]), Err(StorageError::Io));
        assert_eq!(s.stats.io_errors, 1);
        s.flash.fuel = None;
        let NorFlashStore { flash, .. } = s;
        let s = NorFlashStore::new(flash, 0, 2 * S).unwrap();
        assert!(!s.stats.formatted_at_open, "a valid log is reopened");
    }
}
