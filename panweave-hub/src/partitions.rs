//! Partition-table validation for the hub image.
//!
//! The same checks run in three places: the firmware's build script
//! (`partitions-hub.csv` must be valid to build), the CLI (`partitions
//! check`, optionally against a built image), and the firmware at boot on
//! the table actually flashed (reported in the boot report, never acted
//! upon destructively). [`parse_csv`] reads the ESP-IDF CSV format;
//! [`validate`] checks a table against the hub's expectations.

use heapless::{String, Vec};

/// Partitions kept from a table.
pub const MAX_PARTITIONS: usize = 16;

/// Findings kept from a validation.
pub const MAX_FINDINGS: usize = 16;

/// Flash sector size: every partition starts on one.
pub const SECTOR: u32 = 0x1000;

/// Alignment of application partitions (ESP-IDF).
pub const APP_ALIGN: u32 = 0x10000;

/// The partition table's own location (flash offset 0x8000, one sector).
pub const TABLE_OFFSET: u32 = 0x8000;

/// Where the stack's records live on every image of the crate.
pub const NVS_OFFSET: u32 = 0x9000;
/// Size of the stack's region.
pub const NVS_SIZE: u32 = 0x6000;

/// Label of the hub's registry partition.
pub const HUBDATA_LABEL: &str = "hubdata";

/// Smallest usable registry region: two halves of a sector each.
pub const HUBDATA_MIN: u32 = 2 * SECTOR;

/// Partition types.
pub mod kind {
    /// Application.
    pub const APP: u8 = 0x00;
    /// Data.
    pub const DATA: u8 = 0x01;
}

/// One partition.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Partition {
    /// Label (at most 16 characters).
    pub label: String<16>,
    /// Type ([`kind`]).
    pub kind: u8,
    /// Subtype.
    pub subtype: u8,
    /// Offset.
    pub offset: u32,
    /// Size.
    pub size: u32,
}

impl Partition {
    /// End offset (exclusive).
    pub const fn end(&self) -> u64 {
        self.offset as u64 + self.size as u64
    }
}

/// A problem found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Finding {
    /// Partitions `.0` and `.1` overlap.
    Overlap(u8, u8),
    /// Partition `.0` overlaps the bootloader or the table itself.
    OverlapsTable(u8),
    /// Partition `.0` ends beyond the flash.
    OutOfFlash(u8),
    /// Partition `.0` does not start on a sector.
    Misaligned(u8),
    /// Application partition `.0` does not start on a 64 KiB boundary.
    AppMisaligned(u8),
    /// Two partitions carry the label of partition `.0`.
    DuplicateLabel(u8),
    /// No `hubdata` partition: the registry would live in RAM only.
    HubdataMissing,
    /// `hubdata` (`.0`) is not a data partition.
    HubdataNotData(u8),
    /// `hubdata` (`.0`) is smaller than two sectors.
    HubdataTooSmall(u8),
    /// The stack's region 0x9000+0x6000 is not an `nvs` data partition
    /// exactly: existing networks would not be found.
    NvsMoved,
    /// No application partition.
    NoApp,
    /// The image (`.1` KiB) does not fit application partition `.0`.
    ImageTooLarge(u8, u16),
}

impl Finding {
    /// A stable code (for the boot report and diagnostics).
    pub const fn code(self) -> u8 {
        match self {
            Finding::Overlap(..) => 1,
            Finding::OverlapsTable(_) => 2,
            Finding::OutOfFlash(_) => 3,
            Finding::Misaligned(_) => 4,
            Finding::AppMisaligned(_) => 5,
            Finding::DuplicateLabel(_) => 6,
            Finding::HubdataMissing => 7,
            Finding::HubdataNotData(_) => 8,
            Finding::HubdataTooSmall(_) => 9,
            Finding::NvsMoved => 10,
            Finding::NoApp => 11,
            Finding::ImageTooLarge(..) => 12,
        }
    }

    /// The partition the finding is about, when one.
    pub const fn partition(self) -> Option<u8> {
        match self {
            Finding::Overlap(a, _)
            | Finding::OverlapsTable(a)
            | Finding::OutOfFlash(a)
            | Finding::Misaligned(a)
            | Finding::AppMisaligned(a)
            | Finding::DuplicateLabel(a)
            | Finding::HubdataNotData(a)
            | Finding::HubdataTooSmall(a)
            | Finding::ImageTooLarge(a, _) => Some(a),
            Finding::HubdataMissing | Finding::NvsMoved | Finding::NoApp => None,
        }
    }

    /// Whether the hub still works with this finding (the registry in RAM
    /// is a degraded but working state).
    pub const fn is_fatal(self) -> bool {
        !matches!(self, Finding::HubdataMissing)
    }

    /// A description.
    pub const fn describe(self) -> &'static str {
        match self {
            Finding::Overlap(..) => "partitions overlap",
            Finding::OverlapsTable(_) => "partition overlaps the bootloader or the partition table",
            Finding::OutOfFlash(_) => "partition ends beyond the flash",
            Finding::Misaligned(_) => "partition does not start on a 4 KiB sector",
            Finding::AppMisaligned(_) => "application partition not on a 64 KiB boundary",
            Finding::DuplicateLabel(_) => "duplicate partition label",
            Finding::HubdataMissing => "no hubdata partition: the registry is RAM-only",
            Finding::HubdataNotData(_) => "hubdata is not a data partition",
            Finding::HubdataTooSmall(_) => "hubdata is smaller than two sectors",
            Finding::NvsMoved => "the stack's region (nvs at 0x9000, 0x6000) is not where expected",
            Finding::NoApp => "no application partition",
            Finding::ImageTooLarge(..) => "the firmware image does not fit its partition",
        }
    }
}

/// Validates `table` for a flash of `flash_size` octets; with
/// `image_size`, also that the image fits the first application
/// partition.
pub fn validate(
    table: &[Partition],
    flash_size: u32,
    image_size: Option<u32>,
) -> Vec<Finding, MAX_FINDINGS> {
    let mut out: Vec<Finding, MAX_FINDINGS> = Vec::new();
    let mut add = |f: Finding| {
        let _ = out.push(f);
    };
    let idx = |i: usize| u8::try_from(i).unwrap_or(u8::MAX);
    for (i, p) in table.iter().enumerate() {
        if p.offset % SECTOR != 0 {
            add(Finding::Misaligned(idx(i)));
        }
        if p.kind == kind::APP && p.offset % APP_ALIGN != 0 {
            add(Finding::AppMisaligned(idx(i)));
        }
        if p.end() > u64::from(flash_size) {
            add(Finding::OutOfFlash(idx(i)));
        }
        if p.offset < TABLE_OFFSET + SECTOR {
            add(Finding::OverlapsTable(idx(i)));
        }
        for (j, q) in table.iter().enumerate().skip(i + 1) {
            if u64::from(p.offset) < q.end() && u64::from(q.offset) < p.end() {
                add(Finding::Overlap(idx(i), idx(j)));
            }
            if p.label == q.label {
                add(Finding::DuplicateLabel(idx(j)));
            }
        }
    }
    let nvs_ok = table.iter().any(|p| {
        p.kind == kind::DATA && p.subtype == 0x02 && p.offset == NVS_OFFSET && p.size == NVS_SIZE
    });
    if !nvs_ok {
        add(Finding::NvsMoved);
    }
    match table.iter().position(|p| p.label.as_str() == HUBDATA_LABEL) {
        None => add(Finding::HubdataMissing),
        Some(i) => {
            let p = &table[i];
            if p.kind != kind::DATA {
                add(Finding::HubdataNotData(idx(i)));
            }
            if p.size < HUBDATA_MIN {
                add(Finding::HubdataTooSmall(idx(i)));
            }
        }
    }
    match table.iter().position(|p| p.kind == kind::APP) {
        None => add(Finding::NoApp),
        Some(i) => {
            if let Some(n) = image_size
                && n > table[i].size
            {
                add(Finding::ImageTooLarge(
                    idx(i),
                    u16::try_from(n.div_ceil(1024)).unwrap_or(u16::MAX),
                ));
            }
        }
    }
    out
}

/// A CSV line that could not be read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CsvError {
    /// 1-based line number.
    pub line: usize,
    /// What is wrong.
    pub what: &'static str,
}

fn number(field: &str) -> Option<u32> {
    let f = field.trim();
    let (digits, radix) = match f.strip_prefix("0x").or_else(|| f.strip_prefix("0X")) {
        Some(h) => (h, 16),
        None => (f, 10),
    };
    let (digits, mult) = match digits.strip_suffix(['K', 'k']) {
        Some(d) if radix == 10 => (d, 1024),
        _ => match digits.strip_suffix(['M', 'm']) {
            Some(d) if radix == 10 => (d, 1024 * 1024),
            _ => (digits, 1),
        },
    };
    u32::from_str_radix(digits, radix).ok()?.checked_mul(mult)
}

fn subtype(kind: u8, name: &str) -> Option<u8> {
    let n = name.trim();
    if let Some(v) = number(n) {
        return u8::try_from(v).ok();
    }
    let v = match (kind, n) {
        (kind::APP, "factory") => 0x00,
        (kind::APP, "test") => 0x20,
        (kind::APP, s) if s.starts_with("ota_") => {
            0x10 + u8::try_from(number(s.get(4..)?)?).ok()?
        }
        (kind::DATA, "ota") => 0x00,
        (kind::DATA, "phy") => 0x01,
        (kind::DATA, "nvs") => 0x02,
        (kind::DATA, "coredump") => 0x03,
        (kind::DATA, "nvs_keys") => 0x04,
        (kind::DATA, "efuse") => 0x05,
        (kind::DATA, "undefined") => 0x06,
        (kind::DATA, "esphttpd") => 0x80,
        (kind::DATA, "fat") => 0x81,
        (kind::DATA, "spiffs") => 0x82,
        (kind::DATA, "littlefs") => 0x83,
        _ => return None,
    };
    Some(v)
}

/// Parses an ESP-IDF partition CSV (explicit offsets; comments and blank
/// lines ignored).
pub fn parse_csv(text: &str) -> Result<Vec<Partition, MAX_PARTITIONS>, CsvError> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = n + 1;
        let content = raw.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        let err = |what| CsvError { line, what };
        let mut fields = content.split(',').map(str::trim);
        let label = fields.next().ok_or(err("no label"))?;
        let ty = fields.next().ok_or(err("no type"))?;
        let sub = fields.next().ok_or(err("no subtype"))?;
        let offset = fields.next().ok_or(err("no offset"))?;
        let size = fields.next().ok_or(err("no size"))?;
        let kind = match ty {
            "app" => kind::APP,
            "data" => kind::DATA,
            t => number(t)
                .and_then(|v| u8::try_from(v).ok())
                .ok_or(err("unknown type"))?,
        };
        let p = Partition {
            label: String::try_from(label).map_err(|_| err("label longer than 16"))?,
            kind,
            subtype: subtype(kind, sub).ok_or(err("unknown subtype"))?,
            offset: number(offset).ok_or(err("offset must be explicit"))?,
            size: number(size).ok_or(err("bad size"))?,
        };
        out.push(p).map_err(|_| err("too many partitions"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUB_CSV: &str = include_str!("../../examples/esp32c6-super-mini/partitions-hub.csv");
    const FLASH: u32 = 0x40_0000;

    #[test]
    fn the_shipped_hub_table_is_valid() {
        let t = parse_csv(HUB_CSV).unwrap();
        assert_eq!(t.len(), 4);
        assert_eq!(t[3].label.as_str(), "hubdata");
        assert_eq!((t[3].kind, t[3].subtype), (kind::DATA, 0x06));
        assert_eq!((t[3].offset, t[3].size), (0x31_0000, 0x1_0000));
        assert_eq!((t[2].offset, t[2].size), (0x1_0000, 0x30_0000));
        assert!(validate(&t, FLASH, Some(1_100_000)).is_empty());
        // The 1.07 MiB image fits with room; a 3.1 MiB one does not.
        assert_eq!(
            validate(&t, FLASH, Some(0x31_0000)).as_slice(),
            &[Finding::ImageTooLarge(2, 3136)]
        );
        // On a 2 MiB flash the factory and hubdata partitions end beyond.
        let small = validate(&t, 0x20_0000, None);
        assert!(small.contains(&Finding::OutOfFlash(2)));
        assert!(small.contains(&Finding::OutOfFlash(3)));
    }

    #[test]
    fn layout_defects_are_found() {
        let p = |label: &str, kind: u8, sub: u8, offset: u32, size: u32| Partition {
            label: String::try_from(label).unwrap(),
            kind,
            subtype: sub,
            offset,
            size,
        };
        let table = [
            p("nvs", kind::DATA, 0x02, 0x9000, 0x6000),
            p("factory", kind::APP, 0x00, 0x18000, 0x10_0000),
            p("hubdata", kind::APP, 0x00, 0x10_8000, 0x800),
            p("nvs", kind::DATA, 0x02, 0x7000, 0x1000),
            p("odd", kind::DATA, 0x06, 0x20_0100, 0x1000),
        ];
        let f = validate(&table, FLASH, None);
        assert!(f.contains(&Finding::AppMisaligned(1)));
        assert!(f.contains(&Finding::Overlap(1, 2)));
        assert!(f.contains(&Finding::HubdataNotData(2)));
        assert!(f.contains(&Finding::HubdataTooSmall(2)));
        assert!(f.contains(&Finding::DuplicateLabel(3)));
        assert!(f.contains(&Finding::OverlapsTable(3)));
        assert!(f.contains(&Finding::Misaligned(4)));
        // espflash's default table: no hubdata, which is not fatal.
        let default = [
            p("nvs", kind::DATA, 0x02, 0x9000, 0x6000),
            p("phy_init", kind::DATA, 0x01, 0xf000, 0x1000),
            p("factory", kind::APP, 0x00, 0x10000, 0x3f_0000),
        ];
        let f = validate(&default, FLASH, None);
        assert_eq!(f.as_slice(), &[Finding::HubdataMissing]);
        assert!(!f[0].is_fatal());
        let moved = [p("nvs", kind::DATA, 0x02, 0xa000, 0x6000)];
        assert!(validate(&moved, FLASH, None).contains(&Finding::NvsMoved));
    }

    #[test]
    fn csv_syntax() {
        let t = parse_csv(
            "# comment\n\nnvs, data, nvs, 0x9000, 24K\nota_1, app, ota_1, 0x110000, 1M # c\nx, 0x40, 0x99, 0x200000, 4096\n",
        )
        .unwrap();
        assert_eq!(t[0].size, 0x6000);
        assert_eq!((t[1].subtype, t[1].size), (0x11, 0x10_0000));
        assert_eq!((t[2].kind, t[2].subtype), (0x40, 0x99));
        assert_eq!(
            parse_csv("a, app, factory, , 0x1000"),
            Err(CsvError {
                line: 1,
                what: "offset must be explicit"
            })
        );
        assert!(parse_csv("a, app, nonsense, 0x10000, 0x1000").is_err());
        assert!(parse_csv("a-label-that-is-too-long, app, factory, 0x10000, 0x1000").is_err());
    }
}
