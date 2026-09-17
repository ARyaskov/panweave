//! GPD Application Description (GP Basic 1.1.2 §A.4.2.1.6) and the
//! Compact Attribute Reporting command it describes (§A.4.2.3.6): the
//! report descriptors a multi-sensor GPD sends at commissioning time,
//! a per-GPD store assembling them, and the interpretation of a compact
//! report into ZCL attribute values through its descriptor.

use heapless::Vec;
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::ClusterId;

use crate::gpdf::GpdId;

/// Largest report descriptor kept.
pub const MAX_DESCRIPTOR: usize = 48;
/// Report descriptors kept per GPD (the MultiSensorCommissioningBufferSize
/// minimum, §A.3.5.2.4.1).
pub const MAX_REPORTS: usize = 4;

/// GPD Application Description command payload (Figure 122).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ApplicationDescription<'a> {
    /// Total number of reports the GPD describes.
    pub total_reports: u8,
    /// Number of report descriptors in this command.
    pub reports: u8,
    /// The report descriptors, concatenated.
    pub descriptors: &'a [u8],
}

impl<'a> ApplicationDescription<'a> {
    /// Iterates the report descriptors.
    pub fn reports(&self) -> ReportDescriptors<'a> {
        ReportDescriptors {
            rest: self.descriptors,
        }
    }
}

impl<'a> Decode<'a> for ApplicationDescription<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let total_reports = r.u8()?;
        let reports = r.u8()?;
        if total_reports == 0 || reports == 0 || reports > total_reports {
            return Err(CodecError::InvalidField {
                field: "number of reports",
                value: u32::from(reports),
            });
        }
        let descriptors = r.take_rest();
        // Every descriptor must be complete.
        let mut n = 0u8;
        let mut it = ReportDescriptors { rest: descriptors };
        while let Some(d) = it.next_checked()? {
            let _ = d;
            n = n.saturating_add(1);
        }
        if n != reports {
            return Err(CodecError::InvalidField {
                field: "number of reports",
                value: u32::from(n),
            });
        }
        Ok(ApplicationDescription {
            total_reports,
            reports,
            descriptors,
        })
    }
}

impl Encode for ApplicationDescription<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.descriptors.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.total_reports)?;
        w.u8(self.reports)?;
        w.bytes(self.descriptors)
    }
}

/// One report descriptor (Figure 123).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReportDescriptor<'a> {
    /// Report identifier.
    pub id: u8,
    /// Timeout period in seconds between reports, when fixed.
    pub timeout: Option<u16>,
    /// The data point descriptors, concatenated.
    pub data_points: &'a [u8],
    /// The whole descriptor as received (for storing).
    pub raw: &'a [u8],
}

impl<'a> ReportDescriptor<'a> {
    /// Encodes a descriptor from its parts.
    pub fn write(
        w: &mut Writer<'_>,
        id: u8,
        timeout: Option<u16>,
        data_points: &[u8],
    ) -> Result<(), CodecError> {
        w.u8(id)?;
        w.u8(u8::from(timeout.is_some()))?;
        if let Some(t) = timeout {
            w.u16_le(t)?;
        }
        w.u8(
            u8::try_from(data_points.len()).map_err(|_| CodecError::Unrepresentable {
                field: "data points",
            })?,
        )?;
        w.bytes(data_points)
    }

    /// Iterates the data point descriptors.
    pub fn data_points(&self) -> DataPoints<'a> {
        DataPoints {
            rest: self.data_points,
        }
    }
}

/// Iterator over report descriptors.
#[derive(Clone, Debug)]
pub struct ReportDescriptors<'a> {
    rest: &'a [u8],
}

impl<'a> ReportDescriptors<'a> {
    fn next_checked(&mut self) -> Result<Option<ReportDescriptor<'a>>, CodecError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let mut r = Reader::new(self.rest);
        let id = r.u8()?;
        let options = r.u8()?;
        let timeout = if options & 0x01 != 0 {
            Some(r.u16_le()?)
        } else {
            None
        };
        let len = usize::from(r.u8()?);
        let data_points = r.bytes(len)?;
        let used = r.consumed().len();
        let raw = self.rest.get(..used).ok_or(CodecError::Unrepresentable {
            field: "report descriptor",
        })?;
        self.rest = self.rest.get(used..).unwrap_or(&[]);
        Ok(Some(ReportDescriptor {
            id,
            timeout,
            data_points,
            raw,
        }))
    }
}

impl<'a> Iterator for ReportDescriptors<'a> {
    type Item = ReportDescriptor<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_checked().ok().flatten()
    }
}

/// One data point descriptor (Figure 125).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DataPoint<'a> {
    /// Cluster.
    pub cluster: ClusterId,
    /// The GPD implements the server side of the cluster.
    pub server: bool,
    /// Manufacturer code of a manufacturer-specific cluster / attribute.
    pub manufacturer: Option<u16>,
    /// Attribute records, concatenated.
    pub records: &'a [u8],
    /// Number of records.
    pub count: u8,
}

impl<'a> DataPoint<'a> {
    /// Iterates the attribute records.
    pub fn attributes(&self) -> AttributeRecords<'a> {
        AttributeRecords {
            rest: self.records,
            left: self.count,
        }
    }

    /// Encodes a data point from its parts (`records` are the encoded
    /// attribute records, `count` how many).
    pub fn write(
        w: &mut Writer<'_>,
        cluster: ClusterId,
        server: bool,
        manufacturer: Option<u16>,
        count: u8,
        records: &[u8],
    ) -> Result<(), CodecError> {
        if !(1..=8).contains(&count) {
            return Err(CodecError::Unrepresentable {
                field: "attribute records",
            });
        }
        w.u8((count - 1) | (u8::from(server) << 3) | (u8::from(manufacturer.is_some()) << 4))?;
        w.u16_le(cluster.0)?;
        if let Some(m) = manufacturer {
            w.u16_le(m)?;
        }
        w.bytes(records)
    }
}

/// Iterator over data point descriptors.
#[derive(Clone, Debug)]
pub struct DataPoints<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for DataPoints<'a> {
    type Item = DataPoint<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let mut r = Reader::new(self.rest);
        let options = r.u8().ok()?;
        let count = (options & 0x07) + 1;
        let cluster = ClusterId(r.u16_le().ok()?);
        let manufacturer = if options & 0x10 != 0 {
            Some(r.u16_le().ok()?)
        } else {
            None
        };
        // Walk the records to find where this data point ends.
        let records_start = r.consumed().len();
        for _ in 0..count {
            r.u16_le().ok()?;
            r.u8().ok()?;
            let o = r.u8().ok()?;
            r.bytes(usize::from(o & 0x0f) + 1).ok()?;
        }
        let end = r.consumed().len();
        let records = self.rest.get(records_start..end)?;
        self.rest = self.rest.get(end..).unwrap_or(&[]);
        Some(DataPoint {
            cluster,
            server: options & 0x08 != 0,
            manufacturer,
            records,
            count,
        })
    }
}

/// One attribute record (Figure 127).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttributeRecord<'a> {
    /// Attribute identifier.
    pub id: u16,
    /// ZCL data type.
    pub data_type: u8,
    /// Reported in operation (else background data).
    pub reported: bool,
    /// Offset of the value within a compact report, when reported.
    pub offset: Option<u8>,
    /// Fixed value conveyed at commissioning time.
    pub value: Option<&'a [u8]>,
}

impl AttributeRecord<'_> {
    /// Encodes a record from its parts.
    pub fn write(
        w: &mut Writer<'_>,
        id: u16,
        data_type: u8,
        offset: Option<u8>,
        value: Option<&[u8]>,
    ) -> Result<(), CodecError> {
        let remaining = usize::from(offset.is_some()) + value.map_or(0, <[u8]>::len);
        if remaining == 0 || remaining > 16 {
            return Err(CodecError::Unrepresentable {
                field: "attribute record",
            });
        }
        // Remaining length is "decremented by one".
        #[allow(clippy::cast_possible_truncation)]
        let rem = (remaining - 1) as u8;
        w.u16_le(id)?;
        w.u8(data_type)?;
        w.u8(rem | (u8::from(offset.is_some()) << 4) | (u8::from(value.is_some()) << 5))?;
        if let Some(o) = offset {
            w.u8(o)?;
        }
        if let Some(v) = value {
            w.bytes(v)?;
        }
        Ok(())
    }
}

/// Iterator over attribute records.
#[derive(Clone, Debug)]
pub struct AttributeRecords<'a> {
    rest: &'a [u8],
    left: u8,
}

impl<'a> Iterator for AttributeRecords<'a> {
    type Item = AttributeRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let mut r = Reader::new(self.rest);
        let id = r.u16_le().ok()?;
        let data_type = r.u8().ok()?;
        let options = r.u8().ok()?;
        let body = r.bytes(usize::from(options & 0x0f) + 1).ok()?;
        let reported = options & 0x10 != 0;
        let has_value = options & 0x20 != 0;
        let (offset, value) = match (reported, has_value) {
            (true, true) => (body.first().copied(), body.get(1..)),
            (true, false) => (body.first().copied(), None),
            (false, true) => (None, Some(body)),
            (false, false) => (None, None),
        };
        let used = r.consumed().len();
        self.rest = self.rest.get(used..).unwrap_or(&[]);
        self.left -= 1;
        Some(AttributeRecord {
            id,
            data_type,
            reported,
            offset,
            value,
        })
    }
}

/// Encoded length of a ZCL value of `data_type` at the start of
/// `bytes`, for the fixed-length types and the length-prefixed strings
/// (`None` for types the sink cannot size).
pub fn value_len(data_type: u8, bytes: &[u8]) -> Option<usize> {
    Some(match data_type {
        0x00 => 0,
        0x08..=0x0f => usize::from(data_type - 0x07),
        0x10 => 1,
        0x18..=0x1f => usize::from(data_type - 0x17),
        0x20..=0x27 => usize::from(data_type - 0x1f),
        0x28..=0x2f => usize::from(data_type - 0x27),
        0x30 => 1,
        0x31 => 2,
        0x38 => 2,
        0x39 => 4,
        0x3a => 8,
        0x41 | 0x42 => {
            let n = *bytes.first()?;
            if n == 0xff { 1 } else { 1 + usize::from(n) }
        }
        0x43 | 0x44 => {
            let n = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
            if n == 0xffff { 2 } else { 2 + usize::from(n) }
        }
        0xe0 | 0xe1 | 0xe2 | 0xe8 | 0xe9 | 0xea | 0xf0 => match data_type {
            0xe0 | 0xe1 | 0xe2 | 0xe8 | 0xe9 | 0xea => 4,
            _ => 8,
        },
        0xf1 => 16,
        _ => return None,
    })
}

/// One reported attribute of a compact report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReportedAttribute<'a> {
    /// Cluster.
    pub cluster: ClusterId,
    /// The GPD implements the server side.
    pub server: bool,
    /// Manufacturer code.
    pub manufacturer: Option<u16>,
    /// Attribute identifier.
    pub id: u16,
    /// ZCL data type.
    pub data_type: u8,
    /// The value octets.
    pub value: &'a [u8],
}

/// GPD Compact Attribute Reporting command payload (Figure 138).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompactReport<'a> {
    /// Report identifier.
    pub report_id: u8,
    /// The data points, laid out as the descriptor says.
    pub payload: &'a [u8],
}

impl<'a> CompactReport<'a> {
    /// Parses a Compact Attribute Reporting payload.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        Some(CompactReport {
            report_id: *bytes.first()?,
            payload: bytes.get(1..)?,
        })
    }

    /// Interprets the report through `descriptor` (the one with its
    /// report identifier): the reported attributes with their values.
    pub fn attributes(
        &self,
        descriptor: &ReportDescriptor<'a>,
    ) -> impl Iterator<Item = ReportedAttribute<'a>> + 'a {
        let payload = self.payload;
        descriptor.data_points().flat_map(move |dp| {
            dp.attributes().filter_map(move |rec| {
                let offset = usize::from(rec.offset?);
                let rest = payload.get(offset..)?;
                let len = value_len(rec.data_type, rest)?;
                Some(ReportedAttribute {
                    cluster: dp.cluster,
                    server: dp.server,
                    manufacturer: dp.manufacturer,
                    id: rec.id,
                    data_type: rec.data_type,
                    value: rest.get(..len)?,
                })
            })
        })
    }
}

/// The report descriptors of one GPD.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Description {
    /// GPD identity.
    pub gpd: GpdId,
    /// Total number of reports announced.
    pub total: u8,
    /// Descriptors received, by report identifier.
    reports: Vec<Vec<u8, MAX_DESCRIPTOR>, MAX_REPORTS>,
}

impl Description {
    /// Whether every announced report was received.
    pub fn is_complete(&self) -> bool {
        (0..self.total).all(|id| self.report(id).is_some())
    }

    /// The descriptor of report `id`.
    pub fn report(&self, id: u8) -> Option<ReportDescriptor<'_>> {
        self.reports
            .iter()
            .filter_map(|raw| ReportDescriptors { rest: raw }.next())
            .find(|d| d.id == id)
    }

    /// The descriptors received.
    pub fn reports(&self) -> impl Iterator<Item = ReportDescriptor<'_>> {
        self.reports
            .iter()
            .filter_map(|raw| ReportDescriptors { rest: raw }.next())
    }
}

/// Outcome of feeding an Application Description.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Fed {
    /// More reports are expected.
    Partial,
    /// Every report of the GPD is known.
    Complete,
    /// The store could not hold the descriptor.
    Full,
}

/// Application descriptions of the GPDs being commissioned or paired
/// (out-of-order and duplicate descriptors tolerated, §A.3.9.1 step
/// 13.i).
#[derive(Clone, Debug, Default)]
pub struct Descriptions<const N: usize> {
    entries: Vec<Description, N>,
}

impl<const N: usize> Descriptions<N> {
    /// An empty store.
    pub const fn new() -> Self {
        Descriptions {
            entries: Vec::new(),
        }
    }

    /// Feeds the descriptors of `gpd`'s Application Description.
    pub fn feed(&mut self, gpd: GpdId, d: &ApplicationDescription<'_>) -> Fed {
        let idx = match self.entries.iter().position(|e| e.gpd.same_device(&gpd)) {
            Some(i) => i,
            None => {
                let e = Description {
                    gpd,
                    total: d.total_reports,
                    reports: Vec::new(),
                };
                if self.entries.push(e).is_err() {
                    self.entries.remove(0);
                    let _ = self.entries.push(Description {
                        gpd,
                        total: d.total_reports,
                        reports: Vec::new(),
                    });
                }
                self.entries.len() - 1
            }
        };
        let Some(entry) = self.entries.get_mut(idx) else {
            return Fed::Full;
        };
        if entry.total != d.total_reports {
            entry.total = d.total_reports;
            entry.reports.clear();
        }
        for r in d.reports() {
            if entry.report(r.id).is_some() {
                continue;
            }
            let Ok(raw) = Vec::from_slice(r.raw) else {
                return Fed::Full;
            };
            if entry.reports.push(raw).is_err() {
                return Fed::Full;
            }
        }
        if entry.is_complete() {
            Fed::Complete
        } else {
            Fed::Partial
        }
    }

    /// The description of `gpd`.
    pub fn get(&self, gpd: &GpdId) -> Option<&Description> {
        self.entries.iter().find(|e| e.gpd.same_device(gpd))
    }

    /// Forgets `gpd`.
    pub fn remove(&mut self, gpd: &GpdId) {
        self.entries.retain(|e| !e.gpd.same_device(gpd));
    }

    /// The descriptions held.
    pub fn iter(&self) -> impl Iterator<Item = &Description> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temperature sensor: report 0 carries MeasuredValue (int16 at
    /// offset 0) and a fixed Tolerance; report 1 a humidity value.
    fn temperature_descriptor(buf: &mut [u8]) -> usize {
        let mut records = [0u8; 32];
        let mut rw = Writer::new(&mut records);
        AttributeRecord::write(&mut rw, 0x0000, 0x29, Some(0), None).unwrap();
        AttributeRecord::write(&mut rw, 0x0003, 0x21, None, Some(&[0x64, 0x00])).unwrap();
        let rn = rw.position();
        let mut points = [0u8; 40];
        let mut pw = Writer::new(&mut points);
        DataPoint::write(&mut pw, ClusterId(0x0402), true, None, 2, &records[..rn]).unwrap();
        let pn = pw.position();
        let mut w = Writer::new(buf);
        ReportDescriptor::write(&mut w, 0, Some(300), &points[..pn]).unwrap();
        w.position()
    }

    fn humidity_descriptor(buf: &mut [u8]) -> usize {
        let mut records = [0u8; 16];
        let mut rw = Writer::new(&mut records);
        AttributeRecord::write(&mut rw, 0x0000, 0x21, Some(0), None).unwrap();
        let rn = rw.position();
        let mut points = [0u8; 24];
        let mut pw = Writer::new(&mut points);
        DataPoint::write(&mut pw, ClusterId(0x0405), true, None, 1, &records[..rn]).unwrap();
        let pn = pw.position();
        let mut w = Writer::new(buf);
        ReportDescriptor::write(&mut w, 1, None, &points[..pn]).unwrap();
        w.position()
    }

    #[test]
    fn application_description_round_trips_and_interprets_reports() {
        let mut t = [0u8; 64];
        let tn = temperature_descriptor(&mut t);
        let mut h = [0u8; 64];
        let hn = humidity_descriptor(&mut h);
        let mut both = [0u8; 128];
        both[..tn].copy_from_slice(&t[..tn]);
        both[tn..tn + hn].copy_from_slice(&h[..hn]);
        let d = ApplicationDescription {
            total_reports: 2,
            reports: 2,
            descriptors: &both[..tn + hn],
        };
        let mut buf = [0u8; 128];
        let len = d.encode_to_slice(&mut buf).unwrap();
        let back = ApplicationDescription::decode_exact(&buf[..len]).unwrap();
        assert_eq!(back, d);
        let reports: Vec<ReportDescriptor<'_>, 4> = back.reports().collect();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].id, 0);
        assert_eq!(reports[0].timeout, Some(300));
        assert_eq!(reports[1].timeout, None);
        let points: Vec<DataPoint<'_>, 4> = reports[0].data_points().collect();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].cluster, ClusterId(0x0402));
        assert!(points[0].server);
        let recs: Vec<AttributeRecord<'_>, 4> = points[0].attributes().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(
            (recs[0].id, recs[0].data_type, recs[0].offset),
            (0, 0x29, Some(0))
        );
        assert!(recs[0].reported && recs[0].value.is_none());
        assert_eq!(recs[1].value, Some(&[0x64, 0x00][..]));
        assert!(!recs[1].reported);
        drop(recs);
        drop(points);
        drop(reports);
        // A mismatching count is malformed.
        buf[1] = 1;
        assert!(ApplicationDescription::decode_exact(&buf[..len]).is_err());
        // The store assembles the two reports whichever order they come
        // in, ignoring duplicates.
        let gpd = GpdId::SrcId(0x42);
        let mut store: Descriptions<2> = Descriptions::new();
        let second = ApplicationDescription {
            total_reports: 2,
            reports: 1,
            descriptors: &h[..hn],
        };
        assert_eq!(store.feed(gpd, &second), Fed::Partial);
        assert_eq!(store.feed(gpd, &second), Fed::Partial);
        let first = ApplicationDescription {
            total_reports: 2,
            reports: 1,
            descriptors: &t[..tn],
        };
        assert_eq!(store.feed(gpd, &first), Fed::Complete);
        let desc = store.get(&gpd).unwrap();
        assert!(desc.is_complete());
        // A compact report for report 0: MeasuredValue 21.50 °C.
        let report = CompactReport::parse(&[0x00, 0x66, 0x08]).unwrap();
        let attrs: Vec<ReportedAttribute<'_>, 4> =
            report.attributes(&desc.report(0).unwrap()).collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].cluster, ClusterId(0x0402));
        assert_eq!(attrs[0].id, 0);
        assert_eq!(attrs[0].data_type, 0x29);
        assert_eq!(attrs[0].value, &[0x66, 0x08]);
        // A short payload yields nothing; an unknown report id nothing.
        let short = CompactReport::parse(&[0x00, 0x66]).unwrap();
        assert_eq!(short.attributes(&desc.report(0).unwrap()).count(), 0);
        assert!(desc.report(5).is_none());
        drop(attrs);
        store.remove(&gpd);
        assert!(store.get(&gpd).is_none());
        assert_eq!(value_len(0x42, &[3, 1, 2, 3]), Some(4));
        assert_eq!(value_len(0x42, &[0xff]), Some(1));
        assert_eq!(value_len(0x39, &[]), Some(4));
        assert_eq!(value_len(0x48, &[]), None);
    }
}
