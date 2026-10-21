//! Diagnostic messages of the Hub Protocol (added in firmware 0.2.1, still
//! protocol version 1: new request and response tags only, so older hosts
//! and older firmware keep working — an older hub answers these requests
//! with `UnknownRequest`).

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};

use super::{
    ProtocolError, Text, read_bool, read_opt_u8, read_opt_u16, read_text, write_opt_u8,
    write_opt_u16, write_text,
};
use crate::capture::{CaptureMode, CapturedFrame, MAX_FRAME};
use crate::diag::{Category, DiagRecord, Severity, present};

/// Records per [`TracePage`].
pub const MAX_TRACE_PAGE: usize = 12;
/// Frames per [`CapturePage`].
pub const MAX_CAPTURE_PAGE: usize = 3;
/// Partitions listed in a [`BootReport`].
pub const MAX_BOOT_PARTITIONS: usize = 8;
/// Partition findings listed in a [`BootReport`].
pub const MAX_BOOT_FINDINGS: usize = 8;
/// Longest capture a host may request, in seconds.
pub const MAX_CAPTURE_SECONDS: u16 = 3600;

/// How the chip came out of reset, classified from the reset reason the
/// ROM reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResetKind {
    /// Power-on reset.
    ColdBoot,
    /// Software reset (a restart requested by firmware).
    SoftwareReset,
    /// A watchdog fired (also the outcome of a panic: the firmware halts
    /// and the RTC watchdog resets it).
    WatchdogReset,
    /// Another known reason (brown-out, USB-JTAG reset by a flashing
    /// tool, JTAG, …): see the raw code.
    OtherReset,
    /// The reason could not be read.
    UnknownResetReason,
}

impl ResetKind {
    const fn code(self) -> u8 {
        match self {
            ResetKind::ColdBoot => 0,
            ResetKind::SoftwareReset => 1,
            ResetKind::WatchdogReset => 2,
            ResetKind::OtherReset => 3,
            ResetKind::UnknownResetReason => 4,
        }
    }

    const fn from_code(c: u8) -> Self {
        match c {
            0 => ResetKind::ColdBoot,
            1 => ResetKind::SoftwareReset,
            2 => ResetKind::WatchdogReset,
            3 => ResetKind::OtherReset,
            _ => ResetKind::UnknownResetReason,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            ResetKind::ColdBoot => "cold-boot",
            ResetKind::SoftwareReset => "software-reset",
            ResetKind::WatchdogReset => "watchdog-reset",
            ResetKind::OtherReset => "other-reset",
            ResetKind::UnknownResetReason => "unknown",
        }
    }
}

/// What happened to the Zigbee network at boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkRestore {
    /// Not attempted (yet).
    NotAttempted,
    /// The network was resumed from flash.
    Restored,
    /// No network was stored: a new one was formed.
    Formed,
    /// The stack's storage could not be read; no network was formed (an
    /// existing one is not replaced behind the user's back).
    ReadFailed,
    /// No network was found but the storage held corrupt records; no
    /// network was formed automatically.
    CorruptNotFormed,
    /// A network is stored but cannot be used — half written, in a format
    /// this firmware does not know, or undecodable; it was left untouched
    /// and no network was formed.
    StoredUnusable,
}

/// What reading the stack's storage found (the input of
/// [`NetworkRestore::decide`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoredNetwork {
    /// The storage could not be read.
    Unreadable,
    /// A network was restored.
    Present,
    /// Nothing is stored: factory new.
    Empty,
    /// Something is stored but cannot be used.
    Unusable,
}

impl NetworkRestore {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            NetworkRestore::NotAttempted => 0,
            NetworkRestore::Restored => 1,
            NetworkRestore::Formed => 2,
            NetworkRestore::ReadFailed => 3,
            NetworkRestore::CorruptNotFormed => 4,
            NetworkRestore::StoredUnusable => 5,
        }
    }

    /// The value of a wire code.
    pub const fn from_code(c: u8) -> Self {
        match c {
            1 => NetworkRestore::Restored,
            2 => NetworkRestore::Formed,
            3 => NetworkRestore::ReadFailed,
            4 => NetworkRestore::CorruptNotFormed,
            5 => NetworkRestore::StoredUnusable,
            _ => NetworkRestore::NotAttempted,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            NetworkRestore::NotAttempted => "not-attempted",
            NetworkRestore::Restored => "restored",
            NetworkRestore::Formed => "formed",
            NetworkRestore::ReadFailed => "read-failed",
            NetworkRestore::CorruptNotFormed => "corrupt-not-formed",
            NetworkRestore::StoredUnusable => "stored-unusable",
        }
    }

    /// Whether the hub is without a network because forming one could
    /// replace an existing one.
    pub const fn refused_to_form(self) -> bool {
        matches!(
            self,
            NetworkRestore::ReadFailed
                | NetworkRestore::CorruptNotFormed
                | NetworkRestore::StoredUnusable
        )
    }

    /// The boot policy: what to do with the network given what reading the
    /// stack's storage found and how many records the store skipped as
    /// damaged.
    ///
    /// Only [`NetworkRestore::Formed`] means "form a new network", and only
    /// a clean, genuinely empty store leads there: a read error, damaged
    /// records, or a stored network this firmware cannot use never lead
    /// to a new network silently replacing the one the paired devices
    /// know (and its keys are never overwritten).
    pub const fn decide(stored: StoredNetwork, corrupt_records: u32) -> Self {
        match stored {
            StoredNetwork::Unreadable => NetworkRestore::ReadFailed,
            StoredNetwork::Present => NetworkRestore::Restored,
            StoredNetwork::Unusable => NetworkRestore::StoredUnusable,
            StoredNetwork::Empty if corrupt_records > 0 => NetworkRestore::CorruptNotFormed,
            StoredNetwork::Empty => NetworkRestore::Formed,
        }
    }
}

/// A partition as the flashed table lists it.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PartitionEntry {
    /// Label.
    pub label: Text<16>,
    /// Type.
    pub kind: u8,
    /// Subtype.
    pub subtype: u8,
    /// Offset.
    pub offset: u32,
    /// Size.
    pub size: u32,
}

/// A partition-table finding (`crate::partitions::Finding` code and the
/// partition index, 0xff when none).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PartitionFinding {
    /// Finding code.
    pub code: u8,
    /// Partition index, 0xff when the finding is about none.
    pub partition: u8,
}

/// What the hub found at boot. Values the hardware or the drivers cannot
/// provide are absent, never guessed.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BootReport {
    /// Chip.
    pub chip: Text<16>,
    /// Chip revision (major × 100 + minor) from eFuse.
    pub chip_revision: Option<u16>,
    /// Firmware version.
    pub firmware: Text<16>,
    /// Build identifier (source revision when known).
    pub build: Text<24>,
    /// Reset classification.
    pub reset: Option<ResetKind>,
    /// Raw reset reason code of the ROM.
    pub reset_raw: Option<u8>,
    /// CPU clock in MHz.
    pub cpu_mhz: Option<u16>,
    /// Flash size the image header declares, in octets.
    pub flash_size: Option<u32>,
    /// The partition table could be read.
    pub partition_table_read: bool,
    /// The partitions.
    pub partitions: Vec<PartitionEntry, MAX_BOOT_PARTITIONS>,
    /// Problems found in the table.
    pub findings: Vec<PartitionFinding, MAX_BOOT_FINDINGS>,
    /// The registry region in use (offset, size).
    pub hubdata: Option<(u32, u32)>,
    /// The coordinator's IEEE address.
    pub ieee: u64,
    /// Radio channel after start-up.
    pub radio_channel: Option<u8>,
    /// Network restoration.
    pub network: Option<NetworkRestore>,
    /// Devices restored into the registry.
    pub registry_devices: Option<u8>,
    /// The registry is persistent.
    pub registry_persistent: bool,
    /// The USB link is up (the controller was taken over).
    pub usb_ready: bool,
    /// Watchdog timeout in seconds, when armed.
    pub watchdog_s: Option<u16>,
    /// Milliseconds from reset to the main loop.
    pub boot_ms: Option<u32>,
}

/// Counters of the radio driver adapter (absent when not running on the
/// radio, e.g. in simulation).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RadioDriverStats {
    /// Transmissions started.
    pub tx_attempts: u32,
    /// Acknowledged transmissions.
    pub tx_acked: u32,
    /// Transmissions that requested an acknowledgement and got none, or
    /// whose CCA failed (the driver does not tell which).
    pub tx_no_ack: u32,
    /// Unacknowledged transmissions whose CCA failed.
    pub tx_cca_failures: u32,
    /// Transmissions the driver refused or never completed.
    pub tx_faults: u32,
    /// Frames received.
    pub rx_frames: u32,
    /// Received buffers with an impossible length (dropped).
    pub rx_malformed: u32,
    /// Configuration changes refused (bad channel).
    pub config_errors: u32,
    /// Self-addressed frames sent to apply a configuration change.
    pub config_flushes: u32,
    /// RSSI of the last received frame, dBm.
    pub last_rssi: Option<i8>,
    /// LQI of the last received frame.
    pub last_lqi: Option<u8>,
}

/// Radio, MAC, NWK and APS counters.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RadioDiagnostics {
    /// Channel.
    pub channel: Option<u8>,
    /// Transmit power, dBm.
    pub tx_power_dbm: Option<i8>,
    /// Energy detection works (false on the ESP32-C6 driver: a forming
    /// coordinator cannot pick the quietest channel).
    pub energy_detection: bool,
    /// Driver adapter counters.
    pub driver: Option<RadioDriverStats>,
    /// MAC unicast transactions started.
    pub mac_tx_ucast: u32,
    /// MAC retransmissions (software retries of the MAC service).
    pub mac_tx_ucast_retry: u32,
    /// MAC unicasts that failed after all retries.
    pub mac_tx_ucast_fail: u32,
    /// MAC unicasts received.
    pub mac_rx_ucast: u32,
    /// MAC broadcasts sent.
    pub mac_tx_bcast: u32,
    /// MAC broadcasts received.
    pub mac_rx_bcast: u32,
    /// Frames refused: MAC transmit queue full.
    pub mac_queue_full: u32,
    /// NWK frames dropped as malformed.
    pub nwk_malformed: u32,
    /// NWK frames dropped by security processing.
    pub nwk_security_failures: u32,
    /// NWK frames dropped as replays.
    pub nwk_replays: u32,
    /// NWK frames dropped for lack of a route.
    pub nwk_no_route: u32,
    /// Unicasts refused: all NWK pending slots in use.
    pub nwk_pending_full: u32,
    /// Most NWK pending slots ever in use.
    pub nwk_pending_high_water: u8,
    /// NWK pending slots in use now.
    pub nwk_pending: u8,
    /// … of which held for sleepy children.
    pub nwk_pending_held: u8,
    /// NWK pending slots in all.
    pub nwk_pending_capacity: u8,
    /// APS unicasts acknowledged.
    pub aps_tx_success: u32,
    /// APS retransmissions.
    pub aps_retries: u32,
    /// APS unicasts never acknowledged.
    pub aps_ack_failures: u32,
    /// APS frames dropped by security processing.
    pub aps_security_dropped: u32,
    /// APS frames dropped as malformed.
    pub aps_malformed: u32,
}

/// A flash store's counters and room.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StoreUsage {
    /// Room for live records (one half of the region).
    pub capacity: u32,
    /// Octets left before the next compaction.
    pub free: u32,
    /// Records written since boot.
    pub writes: u32,
    /// Compactions since boot.
    pub compactions: u32,
    /// Records that failed their CRC when read since boot.
    pub corrupt_records: u32,
    /// Flash I/O errors since boot.
    pub io_errors: u32,
    /// The region was blank or unreadable at boot and was formatted.
    pub formatted_at_open: bool,
}

/// Persistence state.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StorageDiagnostics {
    /// The registry has persistent storage.
    pub registry_persistent: bool,
    /// Devices in the registry.
    pub registry_devices: u8,
    /// Registry records written.
    pub registry_writes: u32,
    /// Registry storage errors.
    pub registry_errors: u32,
    /// … of which "storage full".
    pub registry_full_errors: u32,
    /// Device records skipped at restore (unknown format, corrupt).
    pub records_skipped: u32,
    /// The last registry storage error (0 full, 1 I/O, 2 buffer).
    pub last_error: Option<u8>,
    /// What happened to the network at boot.
    pub network: Option<NetworkRestore>,
    /// The stack's store.
    pub stack_store: Option<StoreUsage>,
    /// The registry's store.
    pub hub_store: Option<StoreUsage>,
}

/// A bounded queue's use.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct QueueUsage {
    /// Entries now.
    pub len: u16,
    /// Capacity.
    pub capacity: u16,
    /// Most entries seen since boot.
    pub high_water: u16,
}

/// What only the target can measure about itself. Every field is absent
/// when it was not measured (in simulation, or where the firmware has no
/// way to): never an estimate.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TargetMetrics {
    /// Main stack size, octets (from the linker's stack region).
    pub stack_size: Option<u32>,
    /// Deepest main-stack use seen, octets (painted-stack watermark).
    pub stack_peak: Option<u32>,
    /// Heap size, octets.
    pub heap_size: Option<u32>,
    /// Heap in use now, octets.
    pub heap_used: Option<u32>,
    /// Most heap ever in use, octets.
    pub heap_peak: Option<u32>,
    /// Main-loop turns longer than 20 ms (a sleepy child that polled may
    /// stop listening for its frame before the loop serves it).
    pub loop_over_20ms: Option<u32>,
    /// Longest hub engine poll (registry flash writes included), µs.
    pub hub_poll_max_us: Option<u32>,
    /// Milliseconds since the radio last completed a transmission or
    /// received a frame (silence is not a fault).
    pub radio_idle_ms: Option<u32>,
    /// Radio steps cut short to serve the rest of the loop under a burst
    /// of received frames.
    pub rx_bursts_cut: Option<u32>,
    /// The watchdog supervisor's health (`supervisor::Health` code).
    pub health: Option<u8>,
    /// Radio recoveries attempted this boot.
    pub radio_recoveries: Option<u32>,
}

/// Runtime metrics.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RuntimeDiagnostics {
    /// Milliseconds since boot (64-bit: never wraps in practice).
    pub uptime_ms: u64,
    /// Main loop turns (firmware).
    pub loop_iterations: Option<u32>,
    /// Longest main loop turn, µs (excluding the idle wait).
    pub loop_max_us: Option<u32>,
    /// Turns longer than the overrun limit.
    pub loop_overruns: Option<u32>,
    /// Longest radio processing step, µs.
    pub radio_step_max_us: Option<u32>,
    /// Watchdog timeout, seconds (absent: no watchdog).
    pub watchdog_s: Option<u16>,
    /// Hub events for the host.
    pub hub_events: QueueUsage,
    /// Awaited Zigbee transactions.
    pub pending: QueueUsage,
    /// Host commands in flight.
    pub commands: QueueUsage,
    /// Diagnostic trace.
    pub trace: QueueUsage,
    /// Session transmit queue (octets).
    pub session_tx: QueueUsage,
    /// Capture queue (frames).
    pub capture: QueueUsage,
    /// Hub events dropped.
    pub hub_events_dropped: u32,
    /// Stack events dropped.
    pub stack_events_dropped: u32,
    /// Trace records dropped.
    pub trace_dropped: u32,
    /// Join milestones dropped by the stack.
    pub join_trace_dropped: u32,
    /// Captured frames dropped.
    pub capture_dropped: u32,
    /// Octets received from the host (firmware).
    pub usb_rx_bytes: Option<u32>,
    /// Octets sent to the host (firmware).
    pub usb_tx_bytes: Option<u32>,
    /// Times queued output was dropped for a host that took nothing.
    pub usb_discards: u32,
    /// Devices in the registry.
    pub devices: u8,
    /// Registry capacity.
    pub max_devices: u8,
    /// Interviews with a request outstanding.
    pub interviews_active: u8,
    /// Interviews waiting for their device.
    pub interviews_stalled: u8,
    /// Target measurements; absent where the platform cannot measure
    /// (always in simulation).
    pub target: TargetMetrics,
}

/// The trace configuration and fill.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TraceConfiguration {
    /// Records below this severity are not kept.
    pub min_severity: Severity,
    /// Categories kept (bit = category code).
    pub categories: u32,
    /// Capacity in records.
    pub capacity: u16,
    /// Records stored.
    pub stored: u16,
    /// Records dropped (log full).
    pub dropped: u32,
    /// Records filtered out by the configuration.
    pub filtered: u32,
}

/// A page of the diagnostic trace.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TracePage {
    /// Uptime when the page was read, ms (to unwrap `at_ms`).
    pub uptime_ms: u64,
    /// Sequence number to continue from.
    pub next: u32,
    /// Oldest sequence number still stored: anything older is gone.
    pub first_available: u32,
    /// Records dropped since boot.
    pub dropped: u32,
    /// The records.
    pub records: Vec<DiagRecord, MAX_TRACE_PAGE>,
}

/// A page of captured frames.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CapturePage {
    /// A capture is running.
    pub active: bool,
    /// What the capture keeps of each frame.
    pub mode: CaptureMode,
    /// Seconds left in the running capture.
    pub remaining_s: u16,
    /// Frames dropped in this capture (queue full).
    pub dropped: u32,
    /// Frames still queued after this page.
    pub queued: u16,
    /// Uptime when the page was read, ms.
    pub uptime_ms: u64,
    /// The frames.
    pub frames: Vec<CapturedFrame, MAX_CAPTURE_PAGE>,
}

fn write_opt_u32(w: &mut Writer<'_>, v: Option<u32>) -> Result<(), CodecError> {
    match v {
        Some(x) => {
            w.u8(1)?;
            w.u32_le(x)
        }
        None => w.u8(0),
    }
}

fn read_opt_u32(r: &mut Reader<'_>) -> Result<Option<u32>, ProtocolError> {
    Ok(if read_bool(r)? {
        Some(r.u32_le()?)
    } else {
        None
    })
}

fn write_opt_i8(w: &mut Writer<'_>, v: Option<i8>) -> Result<(), CodecError> {
    match v {
        Some(x) => {
            w.u8(1)?;
            w.i8(x)
        }
        None => w.u8(0),
    }
}

fn read_opt_i8(r: &mut Reader<'_>) -> Result<Option<i8>, ProtocolError> {
    Ok(if read_bool(r)? { Some(r.i8()?) } else { None })
}

fn count(n: usize) -> Result<u8, CodecError> {
    u8::try_from(n).map_err(|_| CodecError::Unrepresentable { field: "count" })
}

pub(crate) fn write_boot_report(w: &mut Writer<'_>, b: &BootReport) -> Result<(), CodecError> {
    write_text(w, &b.chip)?;
    write_opt_u16(w, b.chip_revision)?;
    write_text(w, &b.firmware)?;
    write_text(w, &b.build)?;
    write_opt_u8(w, b.reset.map(ResetKind::code))?;
    write_opt_u8(w, b.reset_raw)?;
    write_opt_u16(w, b.cpu_mhz)?;
    write_opt_u32(w, b.flash_size)?;
    w.u8(u8::from(b.partition_table_read))?;
    w.u8(count(b.partitions.len())?)?;
    for p in &b.partitions {
        write_text(w, &p.label)?;
        w.u8(p.kind)?;
        w.u8(p.subtype)?;
        w.u32_le(p.offset)?;
        w.u32_le(p.size)?;
    }
    w.u8(count(b.findings.len())?)?;
    for f in &b.findings {
        w.u8(f.code)?;
        w.u8(f.partition)?;
    }
    match b.hubdata {
        Some((o, s)) => {
            w.u8(1)?;
            w.u32_le(o)?;
            w.u32_le(s)?;
        }
        None => w.u8(0)?,
    }
    w.u64_le(b.ieee)?;
    write_opt_u8(w, b.radio_channel)?;
    write_opt_u8(w, b.network.map(NetworkRestore::code))?;
    write_opt_u8(w, b.registry_devices)?;
    w.u8(u8::from(b.registry_persistent))?;
    w.u8(u8::from(b.usb_ready))?;
    write_opt_u16(w, b.watchdog_s)?;
    write_opt_u32(w, b.boot_ms)
}

pub(crate) fn read_boot_report(r: &mut Reader<'_>) -> Result<BootReport, ProtocolError> {
    let chip = read_text(r)?;
    let chip_revision = read_opt_u16(r)?;
    let firmware = read_text(r)?;
    let build = read_text(r)?;
    let reset = read_opt_u8(r)?.map(ResetKind::from_code);
    let reset_raw = read_opt_u8(r)?;
    let cpu_mhz = read_opt_u16(r)?;
    let flash_size = read_opt_u32(r)?;
    let partition_table_read = read_bool(r)?;
    let mut partitions = Vec::new();
    for _ in 0..r.u8()? {
        let p = PartitionEntry {
            label: read_text(r)?,
            kind: r.u8()?,
            subtype: r.u8()?,
            offset: r.u32_le()?,
            size: r.u32_le()?,
        };
        partitions.push(p).map_err(|_| ProtocolError::Malformed)?;
    }
    let mut findings = Vec::new();
    for _ in 0..r.u8()? {
        let f = PartitionFinding {
            code: r.u8()?,
            partition: r.u8()?,
        };
        findings.push(f).map_err(|_| ProtocolError::Malformed)?;
    }
    let hubdata = if read_bool(r)? {
        Some((r.u32_le()?, r.u32_le()?))
    } else {
        None
    };
    Ok(BootReport {
        chip,
        chip_revision,
        firmware,
        build,
        reset,
        reset_raw,
        cpu_mhz,
        flash_size,
        partition_table_read,
        partitions,
        findings,
        hubdata,
        ieee: r.u64_le()?,
        radio_channel: read_opt_u8(r)?,
        network: read_opt_u8(r)?.map(NetworkRestore::from_code),
        registry_devices: read_opt_u8(r)?,
        registry_persistent: read_bool(r)?,
        usb_ready: read_bool(r)?,
        watchdog_s: read_opt_u16(r)?,
        boot_ms: read_opt_u32(r)?,
    })
}

pub(crate) fn write_radio(w: &mut Writer<'_>, d: &RadioDiagnostics) -> Result<(), CodecError> {
    write_opt_u8(w, d.channel)?;
    write_opt_i8(w, d.tx_power_dbm)?;
    w.u8(u8::from(d.energy_detection))?;
    match &d.driver {
        Some(s) => {
            w.u8(1)?;
            for v in [
                s.tx_attempts,
                s.tx_acked,
                s.tx_no_ack,
                s.tx_cca_failures,
                s.tx_faults,
                s.rx_frames,
                s.rx_malformed,
                s.config_errors,
                s.config_flushes,
            ] {
                w.u32_le(v)?;
            }
            write_opt_i8(w, s.last_rssi)?;
            write_opt_u8(w, s.last_lqi)?;
        }
        None => w.u8(0)?,
    }
    for v in [
        d.mac_tx_ucast,
        d.mac_tx_ucast_retry,
        d.mac_tx_ucast_fail,
        d.mac_rx_ucast,
        d.mac_tx_bcast,
        d.mac_rx_bcast,
        d.mac_queue_full,
        d.nwk_malformed,
        d.nwk_security_failures,
        d.nwk_replays,
        d.nwk_no_route,
        d.nwk_pending_full,
    ] {
        w.u32_le(v)?;
    }
    w.u8(d.nwk_pending_high_water)?;
    w.u8(d.nwk_pending)?;
    w.u8(d.nwk_pending_held)?;
    w.u8(d.nwk_pending_capacity)?;
    for v in [
        d.aps_tx_success,
        d.aps_retries,
        d.aps_ack_failures,
        d.aps_security_dropped,
        d.aps_malformed,
    ] {
        w.u32_le(v)?;
    }
    Ok(())
}

pub(crate) fn read_radio(r: &mut Reader<'_>) -> Result<RadioDiagnostics, ProtocolError> {
    let channel = read_opt_u8(r)?;
    let tx_power_dbm = read_opt_i8(r)?;
    let energy_detection = read_bool(r)?;
    let driver = if read_bool(r)? {
        Some(RadioDriverStats {
            tx_attempts: r.u32_le()?,
            tx_acked: r.u32_le()?,
            tx_no_ack: r.u32_le()?,
            tx_cca_failures: r.u32_le()?,
            tx_faults: r.u32_le()?,
            rx_frames: r.u32_le()?,
            rx_malformed: r.u32_le()?,
            config_errors: r.u32_le()?,
            config_flushes: r.u32_le()?,
            last_rssi: read_opt_i8(r)?,
            last_lqi: read_opt_u8(r)?,
        })
    } else {
        None
    };
    Ok(RadioDiagnostics {
        channel,
        tx_power_dbm,
        energy_detection,
        driver,
        mac_tx_ucast: r.u32_le()?,
        mac_tx_ucast_retry: r.u32_le()?,
        mac_tx_ucast_fail: r.u32_le()?,
        mac_rx_ucast: r.u32_le()?,
        mac_tx_bcast: r.u32_le()?,
        mac_rx_bcast: r.u32_le()?,
        mac_queue_full: r.u32_le()?,
        nwk_malformed: r.u32_le()?,
        nwk_security_failures: r.u32_le()?,
        nwk_replays: r.u32_le()?,
        nwk_no_route: r.u32_le()?,
        nwk_pending_full: r.u32_le()?,
        nwk_pending_high_water: r.u8()?,
        nwk_pending: r.u8()?,
        nwk_pending_held: r.u8()?,
        nwk_pending_capacity: r.u8()?,
        aps_tx_success: r.u32_le()?,
        aps_retries: r.u32_le()?,
        aps_ack_failures: r.u32_le()?,
        aps_security_dropped: r.u32_le()?,
        aps_malformed: r.u32_le()?,
    })
}

fn write_store(w: &mut Writer<'_>, s: Option<&StoreUsage>) -> Result<(), CodecError> {
    match s {
        Some(s) => {
            w.u8(1)?;
            for v in [
                s.capacity,
                s.free,
                s.writes,
                s.compactions,
                s.corrupt_records,
                s.io_errors,
            ] {
                w.u32_le(v)?;
            }
            w.u8(u8::from(s.formatted_at_open))
        }
        None => w.u8(0),
    }
}

fn read_store(r: &mut Reader<'_>) -> Result<Option<StoreUsage>, ProtocolError> {
    if !read_bool(r)? {
        return Ok(None);
    }
    Ok(Some(StoreUsage {
        capacity: r.u32_le()?,
        free: r.u32_le()?,
        writes: r.u32_le()?,
        compactions: r.u32_le()?,
        corrupt_records: r.u32_le()?,
        io_errors: r.u32_le()?,
        formatted_at_open: read_bool(r)?,
    }))
}

pub(crate) fn write_storage(w: &mut Writer<'_>, d: &StorageDiagnostics) -> Result<(), CodecError> {
    w.u8(u8::from(d.registry_persistent))?;
    w.u8(d.registry_devices)?;
    for v in [
        d.registry_writes,
        d.registry_errors,
        d.registry_full_errors,
        d.records_skipped,
    ] {
        w.u32_le(v)?;
    }
    write_opt_u8(w, d.last_error)?;
    write_opt_u8(w, d.network.map(NetworkRestore::code))?;
    write_store(w, d.stack_store.as_ref())?;
    write_store(w, d.hub_store.as_ref())
}

pub(crate) fn read_storage(r: &mut Reader<'_>) -> Result<StorageDiagnostics, ProtocolError> {
    Ok(StorageDiagnostics {
        registry_persistent: read_bool(r)?,
        registry_devices: r.u8()?,
        registry_writes: r.u32_le()?,
        registry_errors: r.u32_le()?,
        registry_full_errors: r.u32_le()?,
        records_skipped: r.u32_le()?,
        last_error: read_opt_u8(r)?,
        network: read_opt_u8(r)?.map(NetworkRestore::from_code),
        stack_store: read_store(r)?,
        hub_store: read_store(r)?,
    })
}

fn write_queue(w: &mut Writer<'_>, q: QueueUsage) -> Result<(), CodecError> {
    w.u16_le(q.len)?;
    w.u16_le(q.capacity)?;
    w.u16_le(q.high_water)
}

fn read_queue(r: &mut Reader<'_>) -> Result<QueueUsage, ProtocolError> {
    Ok(QueueUsage {
        len: r.u16_le()?,
        capacity: r.u16_le()?,
        high_water: r.u16_le()?,
    })
}

pub(crate) fn write_runtime(w: &mut Writer<'_>, d: &RuntimeDiagnostics) -> Result<(), CodecError> {
    w.u64_le(d.uptime_ms)?;
    write_opt_u32(w, d.loop_iterations)?;
    write_opt_u32(w, d.loop_max_us)?;
    write_opt_u32(w, d.loop_overruns)?;
    write_opt_u32(w, d.radio_step_max_us)?;
    write_opt_u16(w, d.watchdog_s)?;
    for q in [
        &d.hub_events,
        &d.pending,
        &d.commands,
        &d.trace,
        &d.session_tx,
        &d.capture,
    ] {
        write_queue(w, *q)?;
    }
    for v in [
        d.hub_events_dropped,
        d.stack_events_dropped,
        d.trace_dropped,
        d.join_trace_dropped,
        d.capture_dropped,
    ] {
        w.u32_le(v)?;
    }
    write_opt_u32(w, d.usb_rx_bytes)?;
    write_opt_u32(w, d.usb_tx_bytes)?;
    w.u32_le(d.usb_discards)?;
    w.u8(d.devices)?;
    w.u8(d.max_devices)?;
    w.u8(d.interviews_active)?;
    w.u8(d.interviews_stalled)?;
    let t = &d.target;
    for v in [
        t.stack_size,
        t.stack_peak,
        t.heap_size,
        t.heap_used,
        t.heap_peak,
        t.loop_over_20ms,
        t.hub_poll_max_us,
        t.radio_idle_ms,
        t.rx_bursts_cut,
        t.health.map(u32::from),
        t.radio_recoveries,
    ] {
        write_opt_u32(w, v)?;
    }
    Ok(())
}

pub(crate) fn read_runtime(r: &mut Reader<'_>) -> Result<RuntimeDiagnostics, ProtocolError> {
    Ok(RuntimeDiagnostics {
        uptime_ms: r.u64_le()?,
        loop_iterations: read_opt_u32(r)?,
        loop_max_us: read_opt_u32(r)?,
        loop_overruns: read_opt_u32(r)?,
        radio_step_max_us: read_opt_u32(r)?,
        watchdog_s: read_opt_u16(r)?,
        hub_events: read_queue(r)?,
        pending: read_queue(r)?,
        commands: read_queue(r)?,
        trace: read_queue(r)?,
        session_tx: read_queue(r)?,
        capture: read_queue(r)?,
        hub_events_dropped: r.u32_le()?,
        stack_events_dropped: r.u32_le()?,
        trace_dropped: r.u32_le()?,
        join_trace_dropped: r.u32_le()?,
        capture_dropped: r.u32_le()?,
        usb_rx_bytes: read_opt_u32(r)?,
        usb_tx_bytes: read_opt_u32(r)?,
        usb_discards: r.u32_le()?,
        devices: r.u8()?,
        max_devices: r.u8()?,
        interviews_active: r.u8()?,
        interviews_stalled: r.u8()?,
        target: TargetMetrics {
            stack_size: read_opt_u32(r)?,
            stack_peak: read_opt_u32(r)?,
            heap_size: read_opt_u32(r)?,
            heap_used: read_opt_u32(r)?,
            heap_peak: read_opt_u32(r)?,
            loop_over_20ms: read_opt_u32(r)?,
            hub_poll_max_us: read_opt_u32(r)?,
            radio_idle_ms: read_opt_u32(r)?,
            rx_bursts_cut: read_opt_u32(r)?,
            health: read_opt_u32(r)?
                .map(|v| u8::try_from(v).map_err(|_| ProtocolError::Malformed))
                .transpose()?,
            radio_recoveries: read_opt_u32(r)?,
        },
    })
}

pub(crate) fn write_trace_config(
    w: &mut Writer<'_>,
    c: &TraceConfiguration,
) -> Result<(), CodecError> {
    w.u8(c.min_severity.code())?;
    w.u32_le(c.categories)?;
    w.u16_le(c.capacity)?;
    w.u16_le(c.stored)?;
    w.u32_le(c.dropped)?;
    w.u32_le(c.filtered)
}

pub(crate) fn read_trace_config(r: &mut Reader<'_>) -> Result<TraceConfiguration, ProtocolError> {
    Ok(TraceConfiguration {
        min_severity: Severity::from_code(r.u8()?).ok_or(ProtocolError::Malformed)?,
        categories: r.u32_le()?,
        capacity: r.u16_le()?,
        stored: r.u16_le()?,
        dropped: r.u32_le()?,
        filtered: r.u32_le()?,
    })
}

/// Encodes one record: sequence, time, category, severity, code, the
/// presence bits, then the present fields in a fixed order.
pub(crate) fn write_record(w: &mut Writer<'_>, rec: &DiagRecord) -> Result<(), CodecError> {
    w.u32_le(rec.seq)?;
    w.u32_le(rec.at_ms)?;
    w.u8(rec.category.code())?;
    w.u8(rec.severity.code())?;
    w.u16_le(rec.code)?;
    let mut flags = 0;
    for (bit, on) in [
        (present::IEEE, rec.ieee.is_some()),
        (present::SHORT, rec.short.is_some()),
        (present::ENDPOINT, rec.endpoint.is_some()),
        (present::CLUSTER, rec.cluster.is_some()),
        (present::TSN, rec.tsn.is_some()),
        (present::STATUS, rec.status.is_some()),
        (present::ARG, rec.arg.is_some()),
    ] {
        if on {
            flags |= bit;
        }
    }
    w.u8(flags)?;
    if let Some(v) = rec.ieee {
        w.u64_le(v)?;
    }
    if let Some(v) = rec.short {
        w.u16_le(v)?;
    }
    if let Some(v) = rec.endpoint {
        w.u8(v)?;
    }
    if let Some(v) = rec.cluster {
        w.u16_le(v)?;
    }
    if let Some(v) = rec.tsn {
        w.u8(v)?;
    }
    if let Some(v) = rec.status {
        w.u8(v)?;
    }
    if let Some(v) = rec.arg {
        w.u32_le(v)?;
    }
    Ok(())
}

pub(crate) fn read_record(r: &mut Reader<'_>) -> Result<DiagRecord, ProtocolError> {
    let seq = r.u32_le()?;
    let at_ms = r.u32_le()?;
    let category = Category::from_code(r.u8()?).ok_or(ProtocolError::Malformed)?;
    let severity = Severity::from_code(r.u8()?).ok_or(ProtocolError::Malformed)?;
    let code = r.u16_le()?;
    let flags = r.u8()?;
    if flags & 0x80 != 0 {
        return Err(ProtocolError::Malformed);
    }
    let has = |bit: u8| flags & bit != 0;
    let ieee = if has(present::IEEE) {
        Some(r.u64_le()?)
    } else {
        None
    };
    let short = if has(present::SHORT) {
        Some(r.u16_le()?)
    } else {
        None
    };
    let endpoint = if has(present::ENDPOINT) {
        Some(r.u8()?)
    } else {
        None
    };
    let cluster = if has(present::CLUSTER) {
        Some(r.u16_le()?)
    } else {
        None
    };
    let tsn = if has(present::TSN) {
        Some(r.u8()?)
    } else {
        None
    };
    let status = if has(present::STATUS) {
        Some(r.u8()?)
    } else {
        None
    };
    let arg = if has(present::ARG) {
        Some(r.u32_le()?)
    } else {
        None
    };
    Ok(DiagRecord {
        seq,
        at_ms,
        category,
        severity,
        code,
        ieee,
        short,
        endpoint,
        cluster,
        tsn,
        status,
        arg,
    })
}

pub(crate) fn write_trace_page(w: &mut Writer<'_>, p: &TracePage) -> Result<(), CodecError> {
    w.u64_le(p.uptime_ms)?;
    w.u32_le(p.next)?;
    w.u32_le(p.first_available)?;
    w.u32_le(p.dropped)?;
    w.u8(count(p.records.len())?)?;
    for rec in &p.records {
        write_record(w, rec)?;
    }
    Ok(())
}

pub(crate) fn read_trace_page(r: &mut Reader<'_>) -> Result<TracePage, ProtocolError> {
    let uptime_ms = r.u64_le()?;
    let next = r.u32_le()?;
    let first_available = r.u32_le()?;
    let dropped = r.u32_le()?;
    let mut records = Vec::new();
    for _ in 0..r.u8()? {
        records
            .push(read_record(r)?)
            .map_err(|_| ProtocolError::Malformed)?;
    }
    Ok(TracePage {
        uptime_ms,
        next,
        first_available,
        dropped,
        records,
    })
}

pub(crate) fn write_capture_page(w: &mut Writer<'_>, p: &CapturePage) -> Result<(), CodecError> {
    w.u8(u8::from(p.active))?;
    w.u8(p.mode.code())?;
    w.u16_le(p.remaining_s)?;
    w.u32_le(p.dropped)?;
    w.u16_le(p.queued)?;
    w.u64_le(p.uptime_ms)?;
    w.u8(count(p.frames.len())?)?;
    for f in &p.frames {
        w.u32_le(f.seq)?;
        w.u32_le(f.at_ms)?;
        w.u8(f.channel)?;
        w.u8(f.flags)?;
        write_opt_i8(w, f.rssi)?;
        write_opt_u8(w, f.lqi)?;
        w.u8(f.original_len)?;
        w.u8(count(f.data.len())?)?;
        w.bytes(&f.data)?;
    }
    Ok(())
}

pub(crate) fn read_capture_page(r: &mut Reader<'_>) -> Result<CapturePage, ProtocolError> {
    let active = read_bool(r)?;
    let mode = CaptureMode::from_code(r.u8()?).ok_or(ProtocolError::Malformed)?;
    let remaining_s = r.u16_le()?;
    let dropped = r.u32_le()?;
    let queued = r.u16_le()?;
    let uptime_ms = r.u64_le()?;
    let mut frames = Vec::new();
    for _ in 0..r.u8()? {
        let seq = r.u32_le()?;
        let at_ms = r.u32_le()?;
        let channel = r.u8()?;
        let flags = r.u8()?;
        let rssi = read_opt_i8(r)?;
        let lqi = read_opt_u8(r)?;
        let original_len = r.u8()?;
        let n = usize::from(r.u8()?);
        if n > MAX_FRAME || n > usize::from(original_len) {
            return Err(ProtocolError::Malformed);
        }
        let data = Vec::from_slice(r.bytes(n)?).map_err(|_| ProtocolError::Malformed)?;
        frames
            .push(CapturedFrame {
                seq,
                at_ms,
                channel,
                flags,
                rssi,
                lqi,
                original_len,
                data,
            })
            .map_err(|_| ProtocolError::Malformed)?;
    }
    Ok(CapturePage {
        active,
        mode,
        remaining_s,
        dropped,
        queued,
        uptime_ms,
        frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_clean_empty_store_forms_a_network() {
        use StoredNetwork::*;
        assert_eq!(NetworkRestore::decide(Present, 0), NetworkRestore::Restored);
        // A network survives some damaged records elsewhere.
        assert_eq!(NetworkRestore::decide(Present, 3), NetworkRestore::Restored);
        assert_eq!(NetworkRestore::decide(Empty, 0), NetworkRestore::Formed);
        assert_eq!(
            NetworkRestore::decide(Empty, 1),
            NetworkRestore::CorruptNotFormed
        );
        assert_eq!(
            NetworkRestore::decide(Unreadable, 0),
            NetworkRestore::ReadFailed
        );
        assert_eq!(
            NetworkRestore::decide(Unusable, 0),
            NetworkRestore::StoredUnusable
        );
        for stored in [Unreadable, Present, Empty, Unusable] {
            for corrupt in [0, 1] {
                let d = NetworkRestore::decide(stored, corrupt);
                assert_eq!(
                    d == NetworkRestore::Formed,
                    stored == Empty && corrupt == 0,
                    "{stored:?} {corrupt}"
                );
            }
        }
        for c in 0..=5 {
            assert_eq!(NetworkRestore::from_code(c).code(), c);
        }
        assert!(NetworkRestore::StoredUnusable.refused_to_form());
        assert!(!NetworkRestore::Formed.refused_to_form());
    }
}
