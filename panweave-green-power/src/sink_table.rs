//! The Sink Table (GP Basic 1.1.2 §A.3.3.2.2, Table 25): the pairings a
//! sink holds, with the over-the-air entry format used by the `SinkTable`
//! attribute, the GP Sink Table Response and persistence.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{Key128, ShortAddress};

use crate::cluster::{CommunicationMode, GroupList};
use crate::gpdf::{ApplicationId, ENDPOINT_ALL, ENDPOINT_INDEPENDENT, GpdId, SecurityLevel};
use crate::proxy_table::{ALIAS_DERIVED, SecurityOptions, derived_alias};
use crate::security::KeyType;

/// Groupcast radius meaning "undefined: twice nwkMaxDepth" (§A.3.3.2.2.2.5).
pub const RADIUS_DEFAULT: u8 = 0x00;

/// One Sink Table entry (Table 25).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SinkEntry {
    /// GPD identity (endpoint specific or 0xff for IEEE GPDs).
    pub gpd: GpdId,
    /// CommunicationMode of the pairing.
    pub mode: CommunicationMode,
    /// Sequence number capabilities (incremental MAC sequence numbers).
    pub sequence_number_capable: bool,
    /// RxOnCapability.
    pub rx_on_capable: bool,
    /// FixedLocation.
    pub fixed_location: bool,
    /// DeviceID of the GPD.
    pub device_id: u8,
    /// Pre-commissioned groups with their aliases (mode 0b10 only).
    pub groups: GroupList,
    /// Assigned alias.
    pub assigned_alias: Option<ShortAddress>,
    /// Groupcast radius.
    pub groupcast_radius: u8,
    /// Security options (SecurityUse when present).
    pub security: Option<SecurityOptions>,
    /// GPD security frame counter (or MAC sequence number).
    pub frame_counter: u32,
}

impl SinkEntry {
    /// A fresh unsecured entry for `gpd` in `mode`.
    pub fn new(gpd: GpdId, mode: CommunicationMode, device_id: u8) -> Self {
        SinkEntry {
            gpd,
            mode,
            sequence_number_capable: false,
            rx_on_capable: false,
            fixed_location: false,
            device_id,
            groups: Vec::new(),
            assigned_alias: None,
            groupcast_radius: RADIUS_DEFAULT,
            security: None,
            frame_counter: 0,
        }
    }

    /// The alias used for derived groupcast and full unicast: the
    /// assigned one when set, otherwise the derived one (§A.3.3.2.2.2.1).
    pub fn alias(&self) -> ShortAddress {
        self.assigned_alias
            .unwrap_or_else(|| derived_alias(&self.gpd))
    }

    /// The alias of a commissioned group entry (0xffff means derived).
    pub fn group_alias(&self, alias: ShortAddress) -> ShortAddress {
        if alias == ALIAS_DERIVED {
            derived_alias(&self.gpd)
        } else {
            alias
        }
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

    /// True when this entry is for `gpd` (§A.3.5.2.4): same SrcID, or
    /// same IEEE address with the exact endpoint, an entry endpoint of
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

    /// Keeps the larger of the stored and a newly received groupcast
    /// radius (§A.3.3.2.2.2.5).
    pub fn merge_radius(&mut self, radius: u8) {
        if self.groupcast_radius == RADIUS_DEFAULT || radius > self.groupcast_radius {
            self.groupcast_radius = radius;
        }
    }

    fn options(&self) -> u16 {
        u16::from(self.gpd.application_id().raw())
            | (u16::from(self.mode.raw()) << 3)
            | (u16::from(self.sequence_number_capable) << 5)
            | (u16::from(self.rx_on_capable) << 6)
            | (u16::from(self.fixed_location) << 7)
            | (u16::from(self.assigned_alias.is_some()) << 8)
            | (u16::from(self.security.is_some()) << 9)
    }

    /// Writes the over-the-air form (§A.3.3.2.2.1.1).
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.options())?;
        self.gpd.write_with_endpoint(w)?;
        w.u8(self.device_id)?;
        if self.mode == CommunicationMode::CommissionedGroupcast {
            w.u8(u8::try_from(self.groups.len()).unwrap_or(0))?;
            for (group, alias) in &self.groups {
                w.u16_le(*group)?;
                w.u16_le(alias.0)?;
            }
        }
        if let Some(a) = self.assigned_alias {
            w.u16_le(a.0)?;
        }
        w.u8(self.groupcast_radius)?;
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
        let mode = CommunicationMode::from_raw(((o >> 3) & 0x03) as u8);
        let device_id = r.u8()?;
        let mut e = SinkEntry::new(gpd, mode, device_id);
        e.sequence_number_capable = o & (1 << 5) != 0;
        e.rx_on_capable = o & (1 << 6) != 0;
        e.fixed_location = o & (1 << 7) != 0;
        if mode == CommunicationMode::CommissionedGroupcast {
            let n = r.u8()?;
            for _ in 0..n {
                let group = r.u16_le()?;
                let alias = ShortAddress(r.u16_le()?);
                let _ = e.groups.push((group, alias));
            }
        }
        if o & (1 << 8) != 0 {
            e.assigned_alias = Some(ShortAddress(r.u16_le()?));
        }
        e.groupcast_radius = r.u8()?;
        let security_use = o & (1 << 9) != 0;
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
            let key = Key128::from_bytes(r.array::<16>()?);
            s.key = (!key.is_zero()).then_some(key);
        }
        e.security = sec;
        Ok(e)
    }

    /// Encoded length of the over-the-air form.
    pub fn encoded_len(&self) -> usize {
        let mut n = 2 + self.gpd.encoded_len_with_endpoint() + 1 + 1;
        if self.mode == CommunicationMode::CommissionedGroupcast {
            n += 1 + 4 * self.groups.len();
        }
        if self.assigned_alias.is_some() {
            n += 2;
        }
        if self.security.is_some() {
            n += 1 + 16;
        }
        if self.security.is_some() || self.sequence_number_capable {
            n += 4;
        }
        n
    }
}

/// The Sink Table.
#[derive(Clone, Debug)]
pub struct SinkTable<const N: usize> {
    entries: Vec<SinkEntry, N>,
}

impl<const N: usize> Default for SinkTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SinkTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        SinkTable {
            entries: Vec::new(),
        }
    }

    /// Entries in index order.
    pub fn iter(&self) -> impl Iterator<Item = &SinkEntry> {
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

    /// Capacity (`gpsMaxSinkTableEntries`).
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The entry for `gpd` under the endpoint rules of §A.3.5.2.4,
    /// preferring an exact match.
    pub fn find(&self, gpd: &GpdId) -> Option<&SinkEntry> {
        self.entries
            .iter()
            .find(|e| e.gpd == *gpd)
            .or_else(|| self.entries.iter().find(|e| e.matches(gpd)))
    }

    /// Mutable [`Self::find`].
    pub fn find_mut(&mut self, gpd: &GpdId) -> Option<&mut SinkEntry> {
        let i = self
            .entries
            .iter()
            .position(|e| e.gpd == *gpd)
            .or_else(|| self.entries.iter().position(|e| e.matches(gpd)))?;
        self.entries.get_mut(i)
    }

    /// Inserts an entry and returns its index; fails when full.
    pub fn insert(&mut self, entry: SinkEntry) -> Result<usize, SinkEntry> {
        self.entries.push(entry)?;
        Ok(self.entries.len() - 1)
    }

    /// Removes the entries matching `gpd`; returns how many.
    pub fn remove(&mut self, gpd: &GpdId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| !e.matches(gpd));
        before - self.entries.len()
    }

    /// Entry at the OTA index.
    pub fn at(&self, index: usize) -> Option<&SinkEntry> {
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
        let mut t = SinkTable::new();
        let mut r = Reader::new(bytes);
        while !r.is_empty() {
            let e = SinkEntry::decode(&mut r)?;
            t.entries.push(e).map_err(|_| CodecError::LengthMismatch {
                field: "sink table",
            })?;
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::ExtendedAddress;

    #[test]
    fn sink_entry_round_trips_in_every_mode() {
        // Derived groupcast, sequence numbers, no security: counter
        // present, no group list.
        let mut e = SinkEntry::new(
            GpdId::SrcId(0x8765_4321),
            CommunicationMode::DerivedGroupcast,
            0x02,
        );
        e.sequence_number_capable = true;
        e.frame_counter = 0x0102_0304;
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        e.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, e.encoded_len());
        // Options: app 0, mode 0b01 (bits 3-4), seq caps (bit 5).
        assert_eq!(&buf[..2], &[0x28, 0x00]);
        assert_eq!(buf[6], 0x02, "device id");
        assert_eq!(buf[7], 0x00, "radius");
        assert_eq!(&buf[8..12], &[0x04, 0x03, 0x02, 0x01]);
        let back = SinkEntry::decode(&mut Reader::new(&buf[..n])).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.alias(), ShortAddress(0x4321));
        // Commissioned groupcast with two groups, an assigned alias and
        // an individual key.
        let mut g = SinkEntry::new(
            GpdId::Ieee {
                address: ExtendedAddress(0x1122_3344_5566_7788),
                endpoint: 3,
            },
            CommunicationMode::CommissionedGroupcast,
            0x07,
        );
        g.groups.push((0x0010, ShortAddress(0x1234))).unwrap();
        g.groups.push((0x0011, ALIAS_DERIVED)).unwrap();
        g.assigned_alias = Some(ShortAddress(0x2222));
        g.groupcast_radius = 5;
        g.security = Some(SecurityOptions {
            level: SecurityLevel::EncryptedMic,
            key_type: KeyType::Individual,
            key: Some(Key128::from_bytes([0x33; 16])),
        });
        g.frame_counter = 9;
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, g.encoded_len());
        assert_eq!(n, 2 + 9 + 1 + 9 + 2 + 1 + 1 + 4 + 16);
        let back = SinkEntry::decode(&mut Reader::new(&buf[..n])).unwrap();
        assert_eq!(back, g);
        assert_eq!(back.group_alias(ALIAS_DERIVED), ShortAddress(0x7788));
        assert_eq!(back.group_alias(ShortAddress(0x1234)), ShortAddress(0x1234));
        assert_eq!(back.security_level(), SecurityLevel::EncryptedMic);
        assert_eq!(back.key_type(), KeyType::Individual);
    }

    #[test]
    fn table_lookup_follows_the_endpoint_rules() {
        let mut t: SinkTable<4> = SinkTable::new();
        let ieee = ExtendedAddress(0x0A0B_0C0D_0E0F_1011);
        t.insert(SinkEntry::new(
            GpdId::Ieee {
                address: ieee,
                endpoint: 2,
            },
            CommunicationMode::LightweightUnicast,
            0x02,
        ))
        .unwrap();
        t.insert(SinkEntry::new(
            GpdId::SrcId(0x0000_0042),
            CommunicationMode::FullUnicast,
            0x02,
        ))
        .unwrap();
        let exact = GpdId::Ieee {
            address: ieee,
            endpoint: 2,
        };
        assert!(t.find(&exact).is_some());
        assert!(
            t.find(&GpdId::Ieee {
                address: ieee,
                endpoint: 0
            })
            .is_some()
        );
        assert!(
            t.find(&GpdId::Ieee {
                address: ieee,
                endpoint: 5
            })
            .is_none()
        );
        assert!(t.find(&GpdId::SrcId(0x43)).is_none());
        let mut buf = [0u8; 64];
        let (count, n) = t.encode_from(0, &mut buf);
        assert_eq!(count, 2);
        let back: SinkTable<4> = SinkTable::decode_entries(&buf[..n]).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.at(1).unwrap().gpd, GpdId::SrcId(0x42));
        assert_eq!(
            t.remove(&GpdId::Ieee {
                address: ieee,
                endpoint: 0xff
            }),
            1
        );
        assert_eq!(t.len(), 1);
        let mut e = SinkEntry::new(GpdId::SrcId(1), CommunicationMode::FullUnicast, 0);
        e.merge_radius(3);
        e.merge_radius(2);
        assert_eq!(e.groupcast_radius, 3);
    }
}
