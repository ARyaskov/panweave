//! The Proxy Table (GP Basic 1.1.2 §A.3.4.2.2, Table 40) with the alias
//! derivation of §A.3.6.3.3.1 and the over-the-air entry format used by
//! the `ProxyTable` attribute, GP Proxy Table Response and persistence.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ExtendedAddress, Key128, ShortAddress};

use crate::cluster::{GroupList, SinkList};
use crate::gpdf::{ApplicationId, ENDPOINT_ALL, ENDPOINT_INDEPENDENT, GpdId, SecurityLevel};
use crate::security::KeyType;

/// Alias of a commissioned group that means "use the derived alias"
/// (Table 26).
pub const ALIAS_DERIVED: ShortAddress = ShortAddress(0xFFFF);

/// Security parameters of an entry (§A.3.3.2.2.2.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecurityOptions {
    /// SecurityLevel.
    pub level: SecurityLevel,
    /// SecurityKeyType.
    pub key_type: KeyType,
    /// The GPD key when stored (shared / derivable keys may be omitted).
    pub key: Option<Key128>,
}

/// One Proxy Table entry (Table 40).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProxyEntry {
    /// GPD identity (endpoint 0x00 / 0xff / specific for IEEE GPDs).
    pub gpd: GpdId,
    /// EntryActive.
    pub active: bool,
    /// EntryValid.
    pub valid: bool,
    /// Sequence number capabilities (incremental MAC sequence numbers).
    pub sequence_number_capable: bool,
    /// Lightweight unicast sinks.
    pub lightweight_sinks: SinkList,
    /// A sink requires derived groupcast.
    pub derived_group: bool,
    /// Commissioned groups with their aliases.
    pub groups: GroupList,
    /// GPD Fixed.
    pub gpd_fixed: bool,
    /// InRange.
    pub in_range: bool,
    /// Assigned alias.
    pub assigned_alias: Option<ShortAddress>,
    /// Security options (SecurityUse when present).
    pub security: Option<SecurityOptions>,
    /// GPD security frame counter (or MAC sequence number).
    pub frame_counter: u32,
    /// Groupcast radius (0 = unspecified).
    pub groupcast_radius: u8,
    /// Search counter of inactive / invalid entries.
    pub search_counter: u8,
}

impl ProxyEntry {
    /// A fresh active, valid entry for `gpd` without sinks.
    pub fn new(gpd: GpdId) -> Self {
        ProxyEntry {
            gpd,
            active: true,
            valid: true,
            sequence_number_capable: false,
            lightweight_sinks: Vec::new(),
            derived_group: false,
            groups: Vec::new(),
            gpd_fixed: false,
            in_range: false,
            assigned_alias: None,
            security: None,
            frame_counter: 0,
            groupcast_radius: 0,
            search_counter: 0,
        }
    }

    /// True when no sink is paired any more.
    pub fn is_empty(&self) -> bool {
        self.lightweight_sinks.is_empty() && !self.derived_group && self.groups.is_empty()
    }

    /// The alias used for derived groupcast: the assigned alias when
    /// set, otherwise the derived one (§A.3.4.2.2.2.3).
    pub fn alias(&self) -> ShortAddress {
        self.assigned_alias
            .unwrap_or_else(|| derived_alias(&self.gpd))
    }

    /// Security level of the entry (`None` when SecurityUse is clear).
    pub fn security_level(&self) -> SecurityLevel {
        self.security
            .as_ref()
            .map_or(SecurityLevel::None, |s| s.level)
    }

    /// Key type of the entry.
    pub fn key_type(&self) -> KeyType {
        self.security.as_ref().map_or(KeyType::None, |s| s.key_type)
    }

    /// True when this entry answers for `gpd` (§A.3.5.2.3): same SrcID,
    /// or same IEEE address with the exact endpoint, an entry endpoint of
    /// 0xff, or a frame endpoint of 0x00 / 0xff.
    pub fn matches(&self, gpd: &GpdId) -> bool {
        match (&self.gpd, gpd) {
            (GpdId::SrcId(a), GpdId::SrcId(b)) => a == b,
            (
                GpdId::Ieee {
                    address: a,
                    endpoint: ea,
                },
                GpdId::Ieee {
                    address: b,
                    endpoint: eb,
                },
            ) => {
                a == b
                    && (ea == eb
                        || *ea == ENDPOINT_ALL
                        || *eb == ENDPOINT_ALL
                        || *eb == ENDPOINT_INDEPENDENT)
            }
            _ => false,
        }
    }

    fn options(&self) -> u16 {
        u16::from(self.gpd.application_id().raw())
            | (u16::from(self.active) << 3)
            | (u16::from(self.valid) << 4)
            | (u16::from(self.sequence_number_capable) << 5)
            | (u16::from(!self.lightweight_sinks.is_empty()) << 6)
            | (u16::from(self.derived_group) << 7)
            | (u16::from(!self.groups.is_empty()) << 8)
            | (u16::from(self.in_range) << 10)
            | (u16::from(self.gpd_fixed) << 11)
            | (u16::from(self.assigned_alias.is_some()) << 13)
            | (u16::from(self.security.is_some()) << 14)
    }

    /// Writes the over-the-air form (§A.3.4.2.2.1.1).
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.options())?;
        self.gpd.write_with_endpoint(w)?;
        if let Some(a) = self.assigned_alias {
            w.u16_le(a.0)?;
        }
        if let Some(s) = &self.security {
            w.u8(s.level.raw() | (s.key_type.raw() << 2))?;
        }
        if self.security.is_some() || self.sequence_number_capable {
            w.u32_le(self.frame_counter)?;
        }
        if let Some(s) = &self.security {
            let zero = [0u8; 16];
            let key: &[u8] = s.key.as_ref().map_or(&zero, |k| k.as_bytes());
            w.bytes(key)?;
        }
        if !self.lightweight_sinks.is_empty() {
            w.u8(u8::try_from(self.lightweight_sinks.len()).unwrap_or(0))?;
            for (ieee, short) in &self.lightweight_sinks {
                w.u64_le(ieee.0)?;
                w.u16_le(short.0)?;
            }
        }
        if !self.groups.is_empty() {
            w.u8(u8::try_from(self.groups.len()).unwrap_or(0))?;
            for (group, alias) in &self.groups {
                w.u16_le(*group)?;
                w.u16_le(alias.0)?;
            }
        }
        w.u8(self.groupcast_radius)?;
        if !self.active || !self.valid {
            w.u8(self.search_counter)?;
        }
        Ok(())
    }

    /// Reads the over-the-air form.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let o = r.u16_le()?;
        let app = ApplicationId::from_raw((o & 0x07) as u8).ok_or(CodecError::InvalidField {
            field: "application id",
            value: u32::from(o & 0x07),
        })?;
        let gpd = GpdId::read_with_endpoint(r, app)?;
        let mut e = ProxyEntry::new(gpd);
        e.active = o & (1 << 3) != 0;
        e.valid = o & (1 << 4) != 0;
        e.sequence_number_capable = o & (1 << 5) != 0;
        e.derived_group = o & (1 << 7) != 0;
        e.in_range = o & (1 << 10) != 0;
        e.gpd_fixed = o & (1 << 11) != 0;
        if o & (1 << 13) != 0 {
            e.assigned_alias = Some(ShortAddress(r.u16_le()?));
        }
        let security_use = o & (1 << 14) != 0;
        let mut sec = None;
        if security_use {
            let so = r.u8()?;
            sec = Some(SecurityOptions {
                level: SecurityLevel::from_raw(so & 0x03).ok_or(CodecError::InvalidField {
                    field: "security level",
                    value: u32::from(so & 0x03),
                })?,
                key_type: KeyType::from_raw((so >> 2) & 0x07).ok_or(CodecError::InvalidField {
                    field: "key type",
                    value: u32::from((so >> 2) & 0x07),
                })?,
                key: None,
            });
        }
        if security_use || e.sequence_number_capable {
            e.frame_counter = r.u32_le()?;
        }
        if let Some(s) = sec.as_mut() {
            let mut k = [0u8; 16];
            k.copy_from_slice(r.bytes(16)?);
            let key = Key128::from_bytes(k);
            s.key = (!key.is_zero()).then_some(key);
        }
        e.security = sec;
        if o & (1 << 6) != 0 {
            let n = r.u8()?;
            for _ in 0..n {
                let ieee = ExtendedAddress(r.u64_le()?);
                let short = ShortAddress(r.u16_le()?);
                let _ = e.lightweight_sinks.push((ieee, short));
            }
        }
        if o & (1 << 8) != 0 {
            let n = r.u8()?;
            for _ in 0..n {
                let group = r.u16_le()?;
                let alias = ShortAddress(r.u16_le()?);
                let _ = e.groups.push((group, alias));
            }
        }
        e.groupcast_radius = r.u8()?;
        if !e.active || !e.valid {
            e.search_counter = r.u8()?;
        }
        Ok(e)
    }

    /// Encoded length of the over-the-air form.
    pub fn encoded_len(&self) -> usize {
        let mut n = 2 + self.gpd.encoded_len_with_endpoint() + 1;
        if self.assigned_alias.is_some() {
            n += 2;
        }
        if self.security.is_some() {
            n += 1 + 16;
        }
        if self.security.is_some() || self.sequence_number_capable {
            n += 4;
        }
        if !self.lightweight_sinks.is_empty() {
            n += 1 + 10 * self.lightweight_sinks.len();
        }
        if !self.groups.is_empty() {
            n += 1 + 4 * self.groups.len();
        }
        if !self.active || !self.valid {
            n += 1;
        }
        n
    }
}

/// The derived alias / DGroupID of a GPD (§A.3.6.3.3.1, §A.3.6.1.4).
pub fn derived_alias(gpd: &GpdId) -> ShortAddress {
    let id = gpd.id_bits();
    let low = (id & 0xFFFF) as u16;
    let reserved = |v: u16| v == 0x0000 || v > 0xFFF7;
    if !reserved(low) {
        return ShortAddress(low);
    }
    let xored = low ^ ((id >> 16) & 0xFFFF) as u16;
    if !reserved(xored) {
        return ShortAddress(xored);
    }
    if low == 0 {
        ShortAddress(0x0007)
    } else {
        ShortAddress(low.wrapping_sub(8))
    }
}

/// The Proxy Table.
#[derive(Clone, Debug)]
pub struct ProxyTable<const N: usize> {
    entries: Vec<ProxyEntry, N>,
}

impl<const N: usize> Default for ProxyTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ProxyTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        ProxyTable {
            entries: Vec::new(),
        }
    }

    /// Entries in index order (non-empty only, as the OTA index counts).
    pub fn iter(&self) -> impl Iterator<Item = &ProxyEntry> {
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

    /// Capacity (`gppMaxProxyTableEntries`).
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The entry matching `gpd` under the endpoint rules of §A.3.5.2.3,
    /// preferring an exact endpoint match.
    pub fn find(&self, gpd: &GpdId) -> Option<&ProxyEntry> {
        self.entries
            .iter()
            .find(|e| e.gpd == *gpd)
            .or_else(|| self.entries.iter().find(|e| e.matches(gpd)))
    }

    /// Mutable [`Self::find`].
    pub fn find_mut(&mut self, gpd: &GpdId) -> Option<&mut ProxyEntry> {
        let i = self
            .entries
            .iter()
            .position(|e| e.gpd == *gpd)
            .or_else(|| self.entries.iter().position(|e| e.matches(gpd)))?;
        self.entries.get_mut(i)
    }

    /// The entry with exactly this identity (endpoint included).
    pub fn get_exact_mut(&mut self, gpd: &GpdId) -> Option<&mut ProxyEntry> {
        self.entries.iter_mut().find(|e| e.gpd == *gpd)
    }

    /// Entries for the same device (any endpoint).
    pub fn for_device_mut(&mut self, gpd: &GpdId) -> impl Iterator<Item = &mut ProxyEntry> {
        self.entries
            .iter_mut()
            .filter(move |e| e.gpd.same_device(gpd))
    }

    /// Inserts an entry and returns its index; fails when full.
    pub fn insert(&mut self, entry: ProxyEntry) -> Result<usize, ProxyEntry> {
        self.entries.push(entry)?;
        Ok(self.entries.len() - 1)
    }

    /// Mutable entry at the index.
    pub fn at_mut(&mut self, index: usize) -> Option<&mut ProxyEntry> {
        self.entries.get_mut(index)
    }

    /// Removes the exact entry.
    pub fn remove(&mut self, gpd: &GpdId) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.gpd != *gpd);
        self.entries.len() != before
    }

    /// Removes every entry of the device (any endpoint).
    pub fn remove_device(&mut self, gpd: &GpdId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| !e.gpd.same_device(gpd));
        before - self.entries.len()
    }

    /// Removes the entry at `index`.
    pub fn remove_at(&mut self, index: usize) {
        if index < self.entries.len() {
            self.entries.remove(index);
        }
    }

    /// Entry at the OTA index.
    pub fn at(&self, index: usize) -> Option<&ProxyEntry> {
        self.entries.get(index)
    }

    /// Encodes entries from `start` that fit `out` completely; returns
    /// `(count, bytes)`.
    pub fn encode_from(&self, start: usize, out: &mut [u8]) -> (u8, usize) {
        let mut w = Writer::new(out);
        let mut count = 0u8;
        for e in self.entries.iter().skip(start) {
            if e.encoded_len() > w.remaining() || e.encode(&mut w).is_err() {
                break;
            }
            count = count.saturating_add(1);
        }
        (count, w.position())
    }

    /// Restores a table from concatenated OTA entries (persistence).
    pub fn decode_entries(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut t = ProxyTable::new();
        let mut r = Reader::new(bytes);
        while !r.is_empty() {
            let e = ProxyEntry::decode(&mut r)?;
            t.entries.push(e).map_err(|_| CodecError::LengthMismatch {
                field: "proxy table",
            })?;
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_derivation_rules() {
        assert_eq!(
            derived_alias(&GpdId::SrcId(0x8765_4321)),
            ShortAddress(0x4321)
        );
        // Reserved low half → XOR with the next half.
        assert_eq!(
            derived_alias(&GpdId::SrcId(0x1234_0000)),
            ShortAddress(0x1234)
        );
        // Low half reserved, XOR still reserved, low half non-zero → −8.
        assert_eq!(
            derived_alias(&GpdId::SrcId(0x0001_FFF8)),
            ShortAddress(0xFFF0)
        );
        // XOR also reserved and low half zero → 0x0007.
        assert_eq!(
            derived_alias(&GpdId::SrcId(0x0000_0000)),
            ShortAddress(0x0007)
        );
        // XOR reserved and low half non-zero → low − 8.
        assert_eq!(
            derived_alias(&GpdId::SrcId(0x0000_FFF8)),
            ShortAddress(0xFFF0)
        );
        let ieee = GpdId::Ieee {
            address: ExtendedAddress(0x00AA_BBCC_DDEE_1234),
            endpoint: 7,
        };
        assert_eq!(derived_alias(&ieee), ShortAddress(0x1234));
    }

    #[test]
    fn entry_ota_round_trip_and_matching() {
        let mut e = ProxyEntry::new(GpdId::SrcId(0x8765_4321));
        e.sequence_number_capable = true;
        e.derived_group = true;
        e.lightweight_sinks
            .push((ExtendedAddress(0x11), ShortAddress(0x22)))
            .unwrap();
        e.groups.push((0x0042, ALIAS_DERIVED)).unwrap();
        e.security = Some(SecurityOptions {
            level: SecurityLevel::Mic,
            key_type: KeyType::Individual,
            key: Some(Key128::from_bytes([0x33; 16])),
        });
        e.frame_counter = 99;
        e.assigned_alias = Some(ShortAddress(0x0100));
        let mut buf = [0u8; 96];
        let mut w = Writer::new(&mut buf);
        e.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, e.encoded_len());
        let mut r = Reader::new(&buf[..n]);
        let back = ProxyEntry::decode(&mut r).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.alias(), ShortAddress(0x0100));

        let mut t: ProxyTable<4> = ProxyTable::new();
        t.insert(e.clone()).unwrap();
        let ieee = ProxyEntry::new(GpdId::Ieee {
            address: ExtendedAddress(5),
            endpoint: ENDPOINT_ALL,
        });
        t.insert(ieee).unwrap();
        assert!(t.find(&GpdId::SrcId(0x8765_4321)).is_some());
        assert!(
            t.find(&GpdId::Ieee {
                address: ExtendedAddress(5),
                endpoint: 3
            })
            .is_some(),
            "entry for all endpoints matches"
        );
        assert!(t.find(&GpdId::SrcId(1)).is_none());
        let mut out = [0u8; 128];
        let (count, len) = t.encode_from(0, &mut out);
        assert_eq!(count, 2);
        let again: ProxyTable<4> = ProxyTable::decode_entries(&out[..len]).unwrap();
        assert_eq!(again.len(), 2);
        assert_eq!(again.at(0), Some(&e));
    }
}
