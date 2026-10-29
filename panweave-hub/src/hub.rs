//! The hub engine: stack events in, protocol events out, host requests
//! executed over the radio with timeouts, the registry kept and
//! persisted.

use heapless::{Deque, Vec};
use panweave_aps::Destination;
use panweave_aps::tables::BindingDestination;
use panweave_codec::{Decode, Reader};
use panweave_runtime::{Stack, StackEvent, ZclFrame, ZdpData};
use panweave_security::cipher::BlockCipher;
use panweave_storage::{Storage, StorageError};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, CommandId, CryptoRng, Endpoint, ExtendedAddress, GroupAddress, MacCapability,
    ProfileId, ShortAddress, TransactionSequence,
};
use panweave_zcl::global::{
    AttributeValue, ConfigureReportingStatus, DefaultResponse, ReadAttributeStatus, Records,
    command as global,
};
use panweave_zcl::{Direction, FrameType, Header};
use panweave_zdo::zdp::{BindReq, MgmtLeaveReq, StatusRsp, cluster as zdp};

#[cfg(feature = "radio-capture")]
use crate::capture::CaptureBuffer;
use crate::diag::{Category, DiagLog, DiagRecord, Severity, code};
use crate::model::{
    ContactState, DeviceState, Flag, InterviewStatus, LeakState, PowerSource, brightness_to_level,
};
use crate::persist;
use crate::protocol::{
    AttributeData, CommandStage, DEVICE_PAGE, DeviceList, Diagnostics, ErrorCode, Event, HubInfo,
    LightCommand, MAX_FIRMWARE, MAX_PERMIT_JOIN_SECONDS, NetworkInfo, NetworkState, NetworkStatus,
    Request, Response, SensorEvent, TargetMetrics, VERSION,
};
use crate::protocol::{BootReport, NetworkRestore, RadioDriverStats, StoreUsage};
use crate::registry::{Device, MAX_DEVICES, NO_SHORT, Registry, cluster};
use crate::zcl::{self, Applied, Report, ias_cmd};

/// Hub events kept for the host.
pub(crate) const EVENT_CAPACITY: usize = 32;
/// Records the diagnostic trace keeps (32 octets each).
pub const DIAG_CAPACITY: usize = 128;
/// Frames the capture queue holds (about 150 octets each; only with the
/// `radio-capture` feature).
#[cfg(feature = "radio-capture")]
pub const CAPTURE_FRAMES: usize = 16;
/// Zigbee transactions awaited at once.
pub(crate) const MAX_PENDING: usize = 10;
/// ZDP transactions awaited at once (the stack's ZDO tracks four).
const MAX_PENDING_ZDP: usize = 3;
/// Host commands in flight.
pub(crate) const MAX_COMMANDS: usize = 8;
/// Device records written per poll (bounds the time a poll can take).
const WRITES_PER_POLL: usize = 2;
/// Pause between two hub-initiated frames to a sleepy device. Its parent
/// holds a frame until the device polls, and the stack keeps only four
/// unicasts in flight in all (`panweave_nwk::layer::PENDING_TX`): frames
/// sent back to back to a sleepy device can crowd each other out.
pub(crate) const SLEEPY_SPACING: Duration = Duration::from_secs(1);

/// Engine configuration.
#[derive(Clone, Debug)]
pub struct HubConfig {
    /// The hub's endpoint ([`crate::hub_endpoint`]).
    pub endpoint: Endpoint,
    /// Firmware version reported to hosts.
    pub firmware: &'static str,
    /// How long a device has to answer a request. Sleepy devices receive
    /// it at their next poll, so this is longer than a poll interval.
    pub response_timeout: Duration,
    /// Attempts per interview step before it is skipped (optional
    /// steps) or the interview stalls (mandatory steps).
    pub max_attempts: u8,
    /// Delay before a retry.
    pub retry_delay: Duration,
    /// How long the interview waits for a Zone Enroll Request after
    /// writing the CIE address before enrolling the zone unsolicited.
    pub enroll_wait: Duration,
    /// Delay between a registry change and its write (coalesces the
    /// steps of an interview into one write).
    pub persist_delay: Duration,
    /// How long the Trust Center keeps accepting new devices after the
    /// permit-join window closed (a device that associated at the last
    /// second still receives the network key).
    pub join_grace: Duration,
    /// Minimum time between two state synchronizations of a device.
    pub sync_interval: Duration,
    /// Devices interviewed at once.
    pub max_interviews: usize,
    /// Whether there is registry storage. When `false` the registry is
    /// kept in RAM only: the storage is never read or written, and hosts
    /// are told.
    pub persistent: bool,
    /// Fast-poll timeout asked of a device at a Check-in while the hub
    /// has work for it, in quarter seconds (Poll Control Check-in
    /// Response). The hub sends Fast Poll Stop as soon as the work is
    /// done.
    pub fast_poll_timeout_qs: u16,
}

impl Default for HubConfig {
    fn default() -> Self {
        HubConfig {
            endpoint: Endpoint(1),
            firmware: "",
            response_timeout: Duration::from_secs(10),
            max_attempts: 3,
            retry_delay: Duration::from_secs(2),
            enroll_wait: Duration::from_secs(5),
            persist_delay: Duration::from_secs(2),
            join_grace: Duration::from_secs(30),
            sync_interval: Duration::from_secs(60),
            max_interviews: 2,
            persistent: true,
            fast_poll_timeout_qs: 120,
        }
    }
}

/// Engine counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct HubCounters {
    /// Events dropped because the event queue was full.
    pub events_dropped: u32,
    /// Interview steps that exhausted their attempts.
    pub interview_failures: u32,
    /// Host commands that timed out.
    pub command_timeouts: u32,
    /// Registry records written.
    pub storage_writes: u32,
    /// Registry storage errors.
    pub storage_errors: u32,
    /// Devices refused because the registry was full.
    pub registry_full: u32,
    /// Registry writes refused because the storage was full.
    pub storage_full: u32,
    /// Device records skipped at restore.
    pub records_skipped: u32,
    /// The last storage error (0 full, 1 I/O, 2 buffer too small).
    pub last_storage_error: Option<u8>,
}

/// Counters and state of the platform (radio driver, stores, main loop,
/// USB) for diagnostics; the firmware updates them. Values a platform
/// does not have stay `None` (the simulator has no radio driver).
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformCounters {
    /// Radio frames received.
    pub radio_rx: u32,
    /// Radio frames transmitted.
    pub radio_tx: u32,
    /// Radio frames dropped by the driver adapter (malformed buffers).
    pub radio_dropped: u32,
    /// Stack events dropped.
    pub stack_events_dropped: u32,
    /// The radio driver adapter's counters.
    pub driver: Option<RadioDriverStats>,
    /// Transmit power, dBm.
    pub tx_power_dbm: Option<i8>,
    /// Energy detection works on this radio.
    pub energy_detection: bool,
    /// Main loop turns.
    pub loop_iterations: Option<u32>,
    /// Longest main loop turn, µs.
    pub loop_max_us: Option<u32>,
    /// Main loop turns over the overrun limit.
    pub loop_overruns: Option<u32>,
    /// Longest radio processing step, µs.
    pub radio_step_max_us: Option<u32>,
    /// Watchdog timeout, seconds.
    pub watchdog_s: Option<u16>,
    /// Octets received from the host.
    pub usb_rx_bytes: Option<u32>,
    /// Octets sent to the host.
    pub usb_tx_bytes: Option<u32>,
    /// The stack's flash store.
    pub stack_store: Option<StoreUsage>,
    /// The registry's flash store.
    pub hub_store: Option<StoreUsage>,
    /// Target memory and timing measurements.
    pub target: TargetMetrics,
}

/// Who awaits a transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Owner {
    /// A device's interview.
    Interview(u64),
    /// A device's state synchronization.
    Sync(u64),
    /// A host command.
    Command(u16),
}

/// What a transaction awaits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Wait {
    /// A ZDP response with this sequence number.
    Zdp(u8),
    /// A ZCL response with this sequence number.
    Zcl(u8),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Pending {
    pub owner: Owner,
    pub short: u16,
    pub wait: Wait,
    pub deadline: Instant,
}

/// The answer to an awaited transaction.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Reply<'a> {
    Zdp(&'a ZdpData),
    Zcl(&'a ZclFrame),
    Timeout,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CommandKind {
    Light(LightCommand),
    Read {
        cluster: u16,
        attribute: u16,
    },
    Configure {
        cluster: u16,
        report: Report,
    },
    Bind {
        cluster: u16,
    },
    /// Groups Add Group / Remove Group.
    Group {
        remove: bool,
        group: u16,
    },
    /// Scenes Store Scene.
    StoreScene {
        group: u16,
        scene: u8,
    },
}

/// Highest group address a host may use (0xfff8–0xffff are reserved,
/// ZCL8 §3.6.1.1).
const MAX_GROUP: u16 = 0xfff7;

/// Groups and Scenes response commands, and the statuses that mean the
/// request already holds (ZCL8 Table 2-12).
mod member_cmd {
    pub const ADD_GROUP_RESPONSE: u8 = 0x00;
    pub const REMOVE_GROUP_RESPONSE: u8 = 0x03;
    pub const STORE_SCENE_RESPONSE: u8 = 0x04;
    /// DUPLICATE_EXISTS: already a member.
    pub const DUPLICATE_EXISTS: u8 = 0x8a;
    /// NOT_FOUND: not a member.
    pub const NOT_FOUND: u8 = 0x8b;
}

#[derive(Clone, Copy, Debug)]
struct HostCommand {
    id: u16,
    ieee: u64,
    short: u16,
    endpoint: u8,
    kind: CommandKind,
    stage: CommandStage,
    attempts: u8,
}

/// The hub.
pub struct Hub<HS: Storage> {
    pub(crate) config: HubConfig,
    pub(crate) storage: HS,
    pub(crate) registry: Registry,
    pub(crate) pending: Vec<Pending, MAX_PENDING>,
    commands: Vec<HostCommand, MAX_COMMANDS>,
    events: Deque<Event, EVENT_CAPACITY>,
    unreported_drops: u16,
    next_command: u16,
    pub(crate) now: Instant,
    permit_until: Option<Instant>,
    joins_until: Option<Instant>,
    network: Option<NetworkInfo>,
    index_dirty: bool,
    erase_queue: Vec<u64, 4>,
    persist_due: Option<Instant>,
    storage_failing: bool,
    /// Engine counters.
    pub counters: HubCounters,
    /// Platform counters (updated by the firmware).
    pub platform: PlatformCounters,
    /// The diagnostic trace.
    pub(crate) diag: DiagLog<DIAG_CAPACITY>,
    /// Captured radio frames.
    #[cfg(feature = "radio-capture")]
    pub(crate) capture: CaptureBuffer<CAPTURE_FRAMES>,
    /// What the hub found at boot.
    pub(crate) boot: BootReport,
    /// What happened to the network at boot.
    pub(crate) network_restore: Option<NetworkRestore>,
    /// High-water marks: events, pending, commands.
    pub(crate) high_water: [u16; 3],
    /// Stack events dropped as last seen (to log new drops once).
    pub(crate) stack_drops_seen: u32,
    /// Join milestones the stack dropped, as last seen.
    pub(crate) join_drops_seen: u32,
    /// When the previous join milestone of each recent device happened.
    pub(crate) join_last: Vec<(u64, Instant), 4>,
    /// Key-exchange exemptions waiting for their device to join, with
    /// the end of their window.
    pub(crate) exemption_grants: Vec<(u64, Instant), { crate::protocol::MAX_EXEMPTIONS }>,
    /// The persisted exemptions were applied to the stack.
    pub(crate) exemptions_applied: bool,
    /// The OTA upgrade server.
    pub(crate) ota: crate::hub_ota::OtaServer,
    /// Experimental Wi-Fi notifications.
    #[cfg(feature = "alerts")]
    pub(crate) alerts: crate::hub_alerts::AlertEngine,
}

impl<HS: Storage> core::fmt::Debug for Hub<HS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hub")
            .field("devices", &self.registry.len())
            .field("pending", &self.pending.len())
            .field("commands", &self.commands.len())
            .field("events", &self.events.len())
            .finish_non_exhaustive()
    }
}

fn ieee_of<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &Stack<C, R, S>,
    short: u16,
) -> Option<u64> {
    let s = ShortAddress(short);
    stack
        .nwk
        .neighbors
        .by_short(s)
        .map(|n| n.extended.0)
        .or_else(|| stack.nwk.address_map.extended_for(s).map(|e| e.0))
}

impl<HS: Storage> Hub<HS> {
    /// A hub with an empty registry over `storage`.
    pub fn new(config: HubConfig, storage: HS) -> Self {
        Hub {
            config,
            storage,
            registry: Registry::new(),
            pending: Vec::new(),
            commands: Vec::new(),
            events: Deque::new(),
            unreported_drops: 0,
            next_command: 1,
            now: Instant::from_millis(0),
            permit_until: None,
            joins_until: None,
            network: None,
            index_dirty: false,
            erase_queue: Vec::new(),
            persist_due: None,
            storage_failing: false,
            counters: HubCounters::default(),
            platform: PlatformCounters::default(),
            diag: DiagLog::new(),
            #[cfg(feature = "radio-capture")]
            capture: CaptureBuffer::new(),
            boot: BootReport::default(),
            network_restore: None,
            high_water: [0; 3],
            stack_drops_seen: 0,
            join_drops_seen: 0,
            join_last: Vec::new(),
            exemption_grants: Vec::new(),
            exemptions_applied: false,
            ota: crate::hub_ota::OtaServer::default(),
            #[cfg(feature = "alerts")]
            alerts: crate::hub_alerts::AlertEngine::default(),
        }
    }

    /// The registry.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The registry storage.
    pub fn storage(&self) -> &HS {
        &self.storage
    }

    /// Loads the registry from storage; returns the number of devices
    /// restored. Their state is unknown and is read again when they are
    /// next heard; unfinished interviews resume.
    pub fn restore(&mut self) -> Result<usize, StorageError> {
        if !self.config.persistent {
            self.log(DiagRecord::new(
                Category::Boot,
                Severity::Warning,
                code::REGISTRY_RAM_ONLY,
            ));
            return Ok(0);
        }
        let mut buf = [0u8; persist::MAX_RECORD];
        let index = match self.storage.load(persist::index_key(), &mut buf) {
            Ok(Some(n)) => n,
            Ok(None) => {
                self.log(
                    DiagRecord::new(Category::Boot, Severity::Info, code::REGISTRY_RESTORED).arg(0),
                );
                return Ok(0);
            }
            Err(e) => {
                self.storage_error(e);
                return Err(e);
            }
        };
        let n = index;
        let Ok(index) = persist::decode_index(buf.get(..n).unwrap_or(&[])) else {
            self.counters.storage_errors += 1;
            self.log(DiagRecord::new(
                Category::Persistence,
                Severity::Error,
                code::INDEX_CORRUPT,
            ));
            self.emit(Event::HubError {
                error: ErrorCode::StorageFailure,
                detail: 0,
            });
            return Ok(0);
        };
        let mut skipped: u16 = 0;
        for ieee in index {
            let record = match self.storage.load(persist::device_key(ieee), &mut buf) {
                Ok(Some(n)) => persist::decode_device(buf.get(..n).unwrap_or(&[])).ok(),
                Ok(None) => None,
                Err(e) => {
                    self.storage_error(e);
                    return Err(e);
                }
            };
            match record {
                Some(mut d) if d.ieee == ieee => {
                    d.needs_sync = true;
                    if matches!(
                        d.interview.status,
                        InterviewStatus::NotStarted | InterviewStatus::InProgress
                    ) {
                        d.interview.status = InterviewStatus::InProgress;
                        d.interview.due = Some(self.now);
                    }
                    let _ = self.registry.restore(d);
                }
                _ => {
                    skipped = skipped.saturating_add(1);
                    self.log(
                        DiagRecord::new(
                            Category::Persistence,
                            Severity::Error,
                            code::RECORD_SKIPPED,
                        )
                        .ieee(ieee),
                    );
                }
            }
        }
        self.log(
            DiagRecord::new(Category::Boot, Severity::Info, code::REGISTRY_RESTORED)
                .arg(u32::try_from(self.registry.len()).unwrap_or(u32::MAX)),
        );
        if skipped > 0 {
            self.counters.storage_errors += u32::from(skipped);
            self.counters.records_skipped += u32::from(skipped);
            self.emit(Event::HubError {
                error: ErrorCode::StorageFailure,
                detail: skipped,
            });
        }
        self.take_previous_stall_reset();
        #[cfg(feature = "alerts")]
        self.restore_alerts();
        Ok(self.registry.len())
    }

    /// Applies the hub's settings to the stack: the ZDO response timeout
    /// for sleepy devices, and joining closed. Call once, before the
    /// network is formed or resumed.
    pub fn attach<C: BlockCipher, R: CryptoRng, S: Storage>(&mut self, stack: &mut Stack<C, R, S>) {
        stack.zdo.response_timeout = self.config.response_timeout;
        stack.config.trust_center_policy.allow_joins = false;
        self.now = stack.now();
    }

    /// The network was resumed from the stack's persistent data.
    pub fn network_restored<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
    ) {
        let info = Self::network_info(stack);
        self.network = Some(info);
        self.emit(Event::NetworkRestored(info));
    }

    fn network_info<C: BlockCipher, R: CryptoRng, S: Storage>(
        stack: &Stack<C, R, S>,
    ) -> NetworkInfo {
        NetworkInfo {
            pan_id: stack.pan_id().0,
            extended_pan_id: stack.nwk.nib.extended_pan_id.0,
            channel: stack.nwk.nib.channel.raw(),
        }
    }

    /// Erases the registry (memory and storage). The firmware calls it
    /// with `Node::factory_reset`.
    pub fn factory_reset(&mut self) -> Result<(), StorageError> {
        self.registry.clear();
        self.pending.clear();
        self.commands.clear();
        self.erase_queue.clear();
        self.index_dirty = false;
        self.persist_due = None;
        self.permit_until = None;
        self.joins_until = None;
        self.network = None;
        self.exemption_grants.clear();
        self.exemptions_applied = false;
        self.storage.erase_kind(panweave_storage::Kind::Application)
    }

    // ---------------------------------------------------------------
    // Events for the host
    // ---------------------------------------------------------------

    pub(crate) fn emit(&mut self, e: Event) {
        if self.unreported_drops > 0 && self.events.len() + 2 <= EVENT_CAPACITY {
            let count = core::mem::take(&mut self.unreported_drops);
            let _ = self.events.push_back(Event::EventsDropped { count });
        }
        if self.events.push_back(e).is_err() {
            if self.unreported_drops == 0 {
                self.log(
                    DiagRecord::new(Category::Resources, Severity::Warning, code::EVENTS_DROPPED)
                        .arg(1),
                );
            }
            self.unreported_drops = self.unreported_drops.saturating_add(1);
            self.counters.events_dropped = self.counters.events_dropped.saturating_add(1);
        }
        self.note_high_water();
    }

    /// The next event for the host.
    pub fn next_event(&mut self) -> Option<Event> {
        let e = self.events.pop_front();
        if self.unreported_drops > 0 && !self.events.is_full() {
            let count = core::mem::take(&mut self.unreported_drops);
            let _ = self.events.push_back(Event::EventsDropped { count });
        }
        e.or_else(|| self.events.pop_front())
    }

    /// The next event, without removing it.
    pub fn peek_event(&self) -> Option<&Event> {
        self.events.front()
    }

    /// Events waiting for the host.
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }

    /// Host commands in flight.
    pub(crate) fn commands_len(&self) -> usize {
        self.commands.len()
    }

    fn emit_state_events(&mut self, ieee: u64, before: &DeviceState, after: &DeviceState) {
        // Queued durably before the events go to the host.
        #[cfg(feature = "alerts")]
        self.alert_state_change(ieee, before, after);
        if before.water_leak != after.water_leak {
            let e = match after.water_leak {
                LeakState::Leak => SensorEvent::WaterLeakDetected,
                LeakState::Dry => SensorEvent::WaterLeakCleared,
                LeakState::Unknown => SensorEvent::WaterLeakStateUnknown,
            };
            self.emit(Event::Sensor { ieee, event: e });
        }
        if before.contact != after.contact {
            let e = match after.contact {
                ContactState::Open => SensorEvent::ContactOpened,
                ContactState::Closed => SensorEvent::ContactClosed,
                ContactState::Unknown => SensorEvent::ContactStateUnknown,
            };
            self.emit(Event::Sensor { ieee, event: e });
        }
        if before.battery_low != Flag::Set && after.battery_low == Flag::Set {
            self.emit(Event::Sensor {
                ieee,
                event: SensorEvent::BatteryLow,
            });
        }
        if before.tamper != Flag::Set && after.tamper == Flag::Set {
            self.emit(Event::Sensor {
                ieee,
                event: SensorEvent::TamperDetected,
            });
        }
        if before != after {
            self.emit(Event::DeviceStateChanged {
                ieee,
                state: *after,
            });
        }
    }

    // ---------------------------------------------------------------
    // Stack events
    // ---------------------------------------------------------------

    /// Feeds one stack event.
    pub fn on_stack_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) {
        self.now = stack.now();
        match event {
            StackEvent::NetworkFormed { .. } => {
                let info = Self::network_info(stack);
                self.network = Some(info);
                self.log(
                    DiagRecord::new(Category::Boot, Severity::Info, code::NETWORK_FORMED)
                        .arg(u32::from(info.channel)),
                );
                self.emit(Event::NetworkStarted(info));
            }
            StackEvent::FormationFailed(status) => {
                self.network = None;
                self.log(
                    DiagRecord::new(Category::Boot, Severity::Critical, code::FORMATION_FAILED)
                        .status(status.raw()),
                );
                self.emit(Event::HubError {
                    error: ErrorCode::NetworkDown,
                    detail: 0,
                });
            }
            StackEvent::DeviceAuthorized { ieee, short } => {
                self.log(
                    DiagRecord::new(
                        Category::Commissioning,
                        Severity::Info,
                        code::DEVICE_AUTHORIZED,
                    )
                    .ieee(ieee.0)
                    .short(short.0),
                );
                self.device_joined(ieee.0, short.0, None);
                self.after_authorized(stack, ieee.0);
            }
            StackEvent::KeyExchangePending { ieee, .. } => {
                self.on_key_exchange_pending(stack, ieee.0);
            }
            StackEvent::KeyExchangeTimedOut { ieee } => {
                // Removed by the Trust Center (logged with the join
                // milestones); a registered device is no longer present.
                self.device_left(ieee.0);
            }
            StackEvent::DeviceAnnounce {
                ieee,
                short,
                capability,
            } => {
                self.log(
                    DiagRecord::new(
                        Category::Commissioning,
                        Severity::Info,
                        code::DEVICE_ANNOUNCED,
                    )
                    .ieee(ieee.0)
                    .short(short.0)
                    .status(capability.raw()),
                );
                // A device still in (or past) its key-exchange window is
                // not the hub's to register or interview.
                if Self::may_serve(stack, ieee.0) {
                    self.device_joined(ieee.0, short.0, Some(*capability));
                } else {
                    self.log_not_authorized(stack, ieee.0, Some(short.0));
                }
            }
            StackEvent::DeviceLeft { ieee, rejoin } => {
                self.log(
                    DiagRecord::new(Category::Commissioning, Severity::Info, code::DEVICE_LEFT)
                        .ieee(ieee.0)
                        .status(u8::from(*rejoin)),
                );
                if !rejoin {
                    self.device_left(ieee.0);
                }
            }
            StackEvent::Zdp(z) => {
                self.heard(stack, z.src.0);
                self.on_reply(stack, z.src.0, Wait::Zdp(z.seq.0), Reply::Zdp(z));
            }
            StackEvent::ZdpTimeout { seq, dst, cluster } => {
                let ieee = self
                    .registry
                    .index_of_short(dst.0)
                    .and_then(|i| self.registry.at(i));
                let mut rec = DiagRecord::new(Category::Zdo, Severity::Warning, code::ZDP_TIMEOUT)
                    .short(dst.0)
                    .cluster(cluster.0)
                    .tsn(seq.0);
                if let Some(d) = ieee {
                    rec = rec.ieee(d.ieee);
                }
                self.log(rec);
                self.on_reply(stack, dst.0, Wait::Zdp(seq.0), Reply::Timeout);
            }
            // A Check-in to the hub's endpoint, which has no Poll Control
            // client: the ZCL hands it up as a server's response.
            StackEvent::ZclResponse(f) if Self::is_check_in(f) => {
                let i = self.heard(stack, f.origin.src.0);
                self.on_check_in(stack, i, f);
            }
            StackEvent::ZclResponse(f) => {
                let src = f.origin.src.0;
                if let Some(i) = self.heard(stack, src) {
                    self.ingest_response(i, f);
                }
                self.on_reply(stack, src, Wait::Zcl(f.origin.header.seq.0), Reply::Zcl(f));
            }
            StackEvent::ZclReport(f) => {
                if let Some(i) = self.heard(stack, f.origin.src.0) {
                    self.ingest_report(i, f);
                }
                let _ = stack
                    .zcl
                    .default_response(&f.origin, panweave_zcl::ZclStatus::Success);
                stack.flush();
            }
            StackEvent::ZclCommand(f) => {
                let i = self.heard(stack, f.origin.src.0);
                self.on_command(stack, i, f);
            }
            _ => {}
        }
    }

    /// A device joined (Trust Center view) or announced itself.
    fn device_joined(&mut self, ieee: u64, short: u16, capability: Option<MacCapability>) {
        if ieee == 0 || ieee == u64::MAX {
            return;
        }
        let now = self.now;
        let old_short = self.registry.get(ieee).map(|d| d.short);
        let (i, new) = match self.registry.upsert(ieee, short) {
            Ok(r) => r,
            Err(_) => {
                self.counters.registry_full += 1;
                self.log(
                    DiagRecord::new(
                        Category::Commissioning,
                        Severity::Error,
                        code::REGISTRY_FULL,
                    )
                    .ieee(ieee)
                    .short(short),
                );
                self.emit(Event::HubError {
                    error: ErrorCode::RegistryFull,
                    detail: u16::try_from(MAX_DEVICES).unwrap_or(u16::MAX),
                });
                return;
            }
        };
        let recent = self.config.join_grace;
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        if let Some(c) = capability {
            d.rx_on_when_idle = Some(c.rx_on_when_idle());
            if c.is_mains_powered()
                && d.power_source == PowerSource::Unknown
                && !d.ignores_mac_mains_claim()
            {
                d.power_source = PowerSource::Mains;
            }
        }
        let was_present = d.present;
        d.present = true;
        d.last_seen = Some(now);
        d.dirty = true;
        let report = d
            .joined_at
            .is_none_or(|t| now.saturating_duration_since(t).as_millis() > recent.as_millis());
        if report {
            d.joined_at = Some(now);
        }
        let rejoin = !new;
        if new {
            d.interview.status = InterviewStatus::InProgress;
            d.interview.due = Some(now.saturating_add(Duration::from_secs(1)));
            self.index_dirty = true;
        } else {
            // A known device came back: its state may have changed while
            // it was away, and a factory-reset device lost its IAS
            // enrolment — check both when it is next reachable.
            d.needs_sync = true;
            d.last_sync = None;
            if d.zone.is_some() && d.interview.status.is_finished() {
                d.enroll_answered = false;
            }
            if matches!(
                d.interview.status,
                InterviewStatus::Stalled | InterviewStatus::NotStarted
            ) {
                d.interview.status = InterviewStatus::InProgress;
                d.interview.attempts = 0;
                d.interview.due = Some(now);
            }
        }
        self.schedule_persist();
        if let Some(old) = old_short
            && old != short
        {
            self.log(
                DiagRecord::new(
                    Category::Commissioning,
                    Severity::Info,
                    code::ADDRESS_CHANGED,
                )
                .ieee(ieee)
                .short(short)
                .arg(u32::from(old)),
            );
        }
        if new {
            self.log(
                DiagRecord::new(Category::Interview, Severity::Info, code::INTERVIEW_STARTED)
                    .ieee(ieee)
                    .short(short),
            );
        } else if report {
            self.log(
                DiagRecord::new(
                    Category::Commissioning,
                    Severity::Info,
                    code::DEVICE_REJOINED,
                )
                .ieee(ieee)
                .short(short),
            );
        }
        if report || !was_present {
            self.emit(Event::DeviceJoined {
                ieee,
                short,
                rejoin,
            });
        }
    }

    /// A device left the network for good.
    fn device_left(&mut self, ieee: u64) {
        let Some(i) = self.registry.index_of(ieee) else {
            return;
        };
        self.cancel_device(ieee);
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        let before = d.state;
        d.present = false;
        d.dirty = true;
        d.interview.busy = false;
        d.sync_busy = false;
        // The device is gone: nothing it reported before can be trusted
        // to still hold.
        d.state = DeviceState::default();
        let after = d.state;
        self.schedule_persist();
        self.emit(Event::DeviceLeft { ieee });
        self.emit_state_events(ieee, &before, &after);
    }

    /// Notes that a frame came from `short`; returns the device's index.
    /// A device the registry does not know yet (its join predates the
    /// registry, or the registry was full) is added and interviewed.
    fn heard<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        short: u16,
    ) -> Option<usize> {
        let now = self.now;
        // Traffic from a device without application access neither
        // registers it nor resumes its interview.
        let known = self
            .registry
            .index_of_short(short)
            .and_then(|i| self.registry.at(i))
            .map(|d| d.ieee);
        if !Self::may_serve(stack, known.or_else(|| ieee_of(stack, short))?) {
            return None;
        }
        let i = match self.registry.index_of_short(short) {
            Some(i) => i,
            None => {
                let ieee = ieee_of(stack, short)?;
                let (i, new) = self.registry.upsert(ieee, short).ok()?;
                if new {
                    self.log(
                        DiagRecord::new(
                            Category::Commissioning,
                            Severity::Info,
                            code::DEVICE_DISCOVERED,
                        )
                        .ieee(ieee)
                        .short(short),
                    );
                    self.index_dirty = true;
                    if let Some(d) = self.registry.at_mut(i) {
                        d.interview.status = InterviewStatus::InProgress;
                        d.interview.due = Some(now);
                    }
                }
                self.schedule_persist();
                i
            }
        };
        let lqi = self
            .registry
            .at(i)
            .and_then(|d| stack.nwk.neighbors.by_extended(ExtendedAddress(d.ieee)))
            .map(|n| n.lqa.value());
        let d = self.registry.at_mut(i)?;
        d.last_seen = Some(now);
        if lqi.is_some() {
            d.lqi = lqi;
        }
        if !d.present {
            d.present = true;
            d.dirty = true;
        }
        // The device is awake: resume an interview waiting for it.
        match d.interview.status {
            InterviewStatus::Stalled => {
                d.interview.status = InterviewStatus::InProgress;
                d.interview.attempts = 0;
                d.interview.due = Some(now);
                let rec =
                    DiagRecord::new(Category::Interview, Severity::Info, code::INTERVIEW_RESUMED)
                        .ieee(d.ieee)
                        .short(short)
                        .arg(crate::interview::stage_arg(d));
                self.log(rec);
            }
            InterviewStatus::InProgress if d.interview.attempts > 0 && !d.interview.busy => {
                d.interview.due = Some(now);
            }
            _ => {}
        }
        Some(i)
    }

    /// Cancels everything in flight for a device.
    fn cancel_device(&mut self, ieee: u64) {
        self.pending.retain(|p| match p.owner {
            Owner::Interview(x) | Owner::Sync(x) => x != ieee,
            Owner::Command(_) => true,
        });
        let failed: Vec<HostCommand, MAX_COMMANDS> = self
            .commands
            .iter()
            .filter(|c| c.ieee == ieee)
            .copied()
            .collect();
        for c in failed {
            self.finish_command_failed(c.id, ErrorCode::Unreachable, 0);
        }
    }

    // ---------------------------------------------------------------
    // Attribute data from devices
    // ---------------------------------------------------------------

    /// Applies attribute values to device `i`, emitting the resulting
    /// events. `report` marks unsolicited reports (unmapped attributes
    /// are forwarded to the host).
    fn apply_attributes<'a>(
        &mut self,
        i: usize,
        origin_endpoint: u8,
        cluster_id: u16,
        values: impl Iterator<Item = (u16, panweave_zcl::Value<'a>)>,
        report: bool,
    ) {
        let Some(d) = self.registry.at(i) else {
            return;
        };
        let ieee = d.ieee;
        let before = d.state;
        let color_before = d.color;
        let was_enrolled = d.zone.is_some_and(|z| z.enrolled);
        let zone_type_before = d.zone.and_then(|z| z.zone_type);
        let mut identity = false;
        for (attribute, value) in values {
            let Some(d) = self.registry.at_mut(i) else {
                return;
            };
            match zcl::apply(d, cluster_id, attribute, &value) {
                Applied::Identity => identity = true,
                Applied::ZoneStatus(s) => self.ingest_zone_status(i, s),
                Applied::Unmapped if report => {
                    self.emit(Event::AttributeReport {
                        ieee,
                        endpoint: origin_endpoint,
                        cluster: cluster_id,
                        attribute,
                        value: zcl::attribute_data(&value),
                    });
                }
                Applied::State | Applied::Color | Applied::Unchanged | Applied::Unmapped => {}
            }
        }
        // A zone status that arrived before the zone type was known (an
        // early notification) is interpreted as soon as it is.
        if let Some(d) = self.registry.at(i)
            && zone_type_before.is_none()
            && d.zone.and_then(|z| z.zone_type).is_some()
            && let Some(status) = d.state.zone_status
        {
            self.ingest_zone_status(i, status);
        }
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        let caps = d.capabilities;
        let power = d.power_source;
        if identity {
            d.dirty = true;
        }
        d.classify();
        if d.power_source != power {
            identity = true;
            d.dirty = true;
        }
        if d.capabilities != caps {
            d.dirty = true;
            identity = true;
        }
        // A zone that was enrolled and says it no longer is (the device
        // was reset and rejoined) sends nothing to the hub any more:
        // enrol it again.
        if was_enrolled && !d.zone.is_some_and(|z| z.enrolled) && d.interview.status.is_finished() {
            d.interview.status = InterviewStatus::InProgress;
            d.interview.stage = crate::model::InterviewStage::IasZone;
            d.interview.step = 0;
            d.interview.attempts = 0;
            d.interview.due = Some(self.now);
            d.enroll_answered = false;
            d.enroll_retries = 0;
            d.cie_address = None;
            d.dirty = true;
            identity = true;
            let rec = DiagRecord::new(Category::IasZone, Severity::Warning, code::IAS_REENROLL)
                .ieee(ieee)
                .short(d.short);
            self.log(rec);
        }
        let Some(d) = self.registry.at(i) else {
            return;
        };
        let after = d.state;
        let color = d.color;
        if identity {
            self.schedule_persist();
        }
        self.emit_state_events(ieee, &before, &after);
        if color != color_before {
            self.emit(Event::LightColorChanged { ieee, color });
        }
    }

    fn ingest_report(&mut self, i: usize, f: &ZclFrame) {
        let values = Records::<AttributeValue>::new(&f.payload)
            .map_while(Result::ok)
            .map(|r| (r.id.0, r.value));
        self.apply_attributes(i, f.origin.src_endpoint.0, f.origin.cluster.0, values, true);
    }

    fn ingest_response(&mut self, i: usize, f: &ZclFrame) {
        if f.origin.header.control.frame_type != FrameType::Global
            || f.origin.header.command != global::READ_ATTRIBUTES_RESPONSE
        {
            return;
        }
        let ieee = self.registry.at(i).map_or(0, |d| d.ieee);
        for r in Records::<ReadAttributeStatus>::new(&f.payload).map_while(Result::ok) {
            if !r.status.is_success() {
                // UNSUPPORTED_ATTRIBUTE is an answer, not a failure.
                let severity = if r.status.raw() == 0x86 {
                    Severity::Debug
                } else {
                    Severity::Warning
                };
                self.log(
                    DiagRecord::new(Category::Zcl, severity, code::ZCL_ATTRIBUTE_ERROR)
                        .ieee(ieee)
                        .short(f.origin.src.0)
                        .endpoint(f.origin.src_endpoint.0)
                        .cluster(f.origin.cluster.0)
                        .tsn(f.origin.header.seq.0)
                        .status(r.status.raw())
                        .arg(u32::from(r.id.0)),
                );
            }
        }
        let values = Records::<ReadAttributeStatus>::new(&f.payload)
            .map_while(Result::ok)
            .filter_map(|r| r.value.map(|v| (r.id.0, v)));
        self.apply_attributes(
            i,
            f.origin.src_endpoint.0,
            f.origin.cluster.0,
            values,
            false,
        );
    }

    /// Interprets an IAS `ZoneStatus` for device `i`.
    pub(crate) fn ingest_zone_status(&mut self, i: usize, status: u16) {
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        let map = crate::ias::alarm_map(
            d.zone.and_then(|z| z.zone_type),
            &d.manufacturer,
            &d.model,
            crate::ias::OVERRIDES,
        );
        let r = crate::ias::interpret(map, status);
        {
            use crate::diag::ias_bits as b;
            let overridden = crate::ias::OVERRIDES.iter().any(|o| {
                o.manufacturer == d.manufacturer.as_slice() && o.model == d.model.as_slice()
            });
            let mut flags = 0;
            if let Some(c) = r.contact {
                flags |= b::CONTACT_KNOWN;
                if c == ContactState::Open {
                    flags |= b::CONTACT_OPEN;
                }
            }
            if let Some(w) = r.water_leak {
                flags |= b::LEAK_KNOWN;
                if w == LeakState::Leak {
                    flags |= b::LEAK;
                }
            }
            if r.test {
                flags |= b::TEST_MODE;
            }
            if overridden {
                flags |= b::OVERRIDE;
            }
            if map.is_none() {
                flags |= b::TYPE_UNKNOWN;
            }
            let mut rec = DiagRecord::new(Category::IasZone, Severity::Info, code::IAS_STATUS)
                .ieee(d.ieee)
                .short(d.short)
                .arg(crate::diag::zone_status_arg(status, flags));
            if let Some(z) = d.zone {
                rec = rec.endpoint(z.endpoint);
            }
            self.diag.record(
                rec,
                u32::try_from(self.now.as_millis() & u64::from(u32::MAX)).unwrap_or(0),
            );
        }
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        d.state.zone_status = Some(status);
        if let Some(c) = r.contact {
            d.state.contact = c;
        }
        if let Some(w) = r.water_leak {
            d.state.water_leak = w;
        }
        if let Some(m) = r.motion {
            d.state.motion = m;
        }
        d.state.tamper = r.tamper;
        d.state.battery_low = r.battery_low;
        d.state.trouble = r.trouble;
    }

    /// A cluster-specific command for the hub's client clusters.
    fn on_command<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        i: Option<usize>,
        f: &ZclFrame,
    ) {
        let o = &f.origin;
        let from_server = o.header.control.direction == Direction::ToClient;
        if Self::is_check_in(f) {
            return self.on_check_in(stack, i, f);
        }
        if o.cluster == panweave_zcl::clusters::ota::ID && !from_server {
            return self.on_ota_command(stack, i, f);
        }
        if o.cluster.0 == cluster::IAS_ZONE && from_server {
            match o.header.command.0 {
                ias_cmd::STATUS_CHANGE => {
                    if let (Some(i), Some(change)) = (
                        i,
                        panweave_zcl::clusters::ias_zone::StatusChange::parse(&f.payload),
                    ) {
                        let ieee = self.registry.at(i).map_or(0, |d| d.ieee);
                        let before = self.registry.at(i).map(|d| d.state).unwrap_or_default();
                        self.ingest_zone_status(i, change.zone_status);
                        let after = self.registry.at(i).map(|d| d.state).unwrap_or_default();
                        self.emit_state_events(ieee, &before, &after);
                    }
                    let _ = stack
                        .zcl
                        .default_response(o, panweave_zcl::ZclStatus::Success);
                }
                ias_cmd::ENROLL_REQUEST => self.on_enroll_request(stack, i, f),
                _ => {
                    self.log_unsupported(i, f);
                    let _ = stack
                        .zcl
                        .default_response(o, panweave_zcl::ZclStatus::UnsupportedClusterCommand);
                }
            }
        } else {
            self.log_unsupported(i, f);
            let _ = stack
                .zcl
                .default_response(o, panweave_zcl::ZclStatus::UnsupportedClusterCommand);
        }
        stack.flush();
    }

    fn log_unsupported(&mut self, i: Option<usize>, f: &ZclFrame) {
        let mut rec = DiagRecord::new(
            Category::Zcl,
            Severity::Debug,
            code::ZCL_UNSUPPORTED_COMMAND,
        )
        .short(f.origin.src.0)
        .endpoint(f.origin.src_endpoint.0)
        .cluster(f.origin.cluster.0)
        .tsn(f.origin.header.seq.0)
        .arg(u32::from(f.origin.header.command.0));
        if let Some(d) = i.and_then(|i| self.registry.at(i)) {
            rec = rec.ieee(d.ieee);
        }
        self.log(rec);
    }

    /// Zone Enroll Request (ZCL8 §8.2.2.4.2): the hub, as the CIE,
    /// enrols every zone of a device on its network with the zone
    /// identifier the registry allocated.
    fn on_enroll_request<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        i: Option<usize>,
        f: &ZclFrame,
    ) {
        let mut r = Reader::new(&f.payload);
        let zone_type = r.u16_le().ok();
        let src_endpoint = f.origin.src_endpoint.0;
        let (code, zone_id) = match i {
            Some(i) => {
                let free = self.registry.free_zone_id();
                match self.registry.at_mut(i) {
                    Some(d) => {
                        let zone = d.zone.get_or_insert(crate::protocol::ZoneInfo {
                            endpoint: src_endpoint,
                            zone_type: None,
                            zone_id: None,
                            enrolled: false,
                        });
                        if zone.zone_type.is_none() && zone_type.is_some() {
                            zone.zone_type = zone_type;
                        }
                        let id = zone.zone_id.or(free);
                        zone.zone_id = id;
                        d.enroll_answered = true;
                        d.dirty = true;
                        // An interview waiting for this request moves on,
                        // once the response had a chance to reach a
                        // sleepy device (its parent holds few frames).
                        if d.interview.status == InterviewStatus::InProgress
                            && d.interview.stage == crate::model::InterviewStage::IasZone
                            && d.interview.step == 3
                        {
                            d.interview.due = Some(self.now.saturating_add(SLEEPY_SPACING));
                        }
                        d.classify();
                        match id {
                            Some(id) => (0x00, id),
                            None => (0x03, 0xff),
                        }
                    }
                    None => (0x02, 0xff),
                }
            }
            // Not a device of this network's registry: no permit.
            None => (0x02, 0xff),
        };
        self.schedule_persist();
        let ieee = i.and_then(|i| self.registry.at(i)).map(|d| d.ieee);
        let mut req = DiagRecord::new(Category::IasZone, Severity::Info, code::IAS_ENROLL_REQUEST)
            .short(f.origin.src.0)
            .endpoint(src_endpoint)
            .tsn(f.origin.header.seq.0);
        let mut rsp = DiagRecord::new(Category::IasZone, Severity::Info, code::IAS_ENROLL_RESPONSE)
            .short(f.origin.src.0)
            .endpoint(src_endpoint)
            .tsn(f.origin.header.seq.0)
            .status(code)
            .arg(u32::from(zone_id));
        if let Some(t) = zone_type {
            req = req.arg(u32::from(t));
        }
        if let Some(ieee) = ieee {
            req = req.ieee(ieee);
            rsp = rsp.ieee(ieee);
        }
        if code != 0 {
            rsp.severity = Severity::Warning;
        }
        self.log(req);
        self.log(rsp);
        // A response command: same transaction sequence number.
        let _ = stack.zcl.respond(
            &f.origin,
            CommandId(ias_cmd::ENROLL_RESPONSE),
            FrameType::ClusterSpecific,
            &[code, zone_id],
        );
    }

    // ---------------------------------------------------------------
    // Awaited transactions
    // ---------------------------------------------------------------

    fn zdp_pending(&self) -> usize {
        self.pending
            .iter()
            .filter(|p| matches!(p.wait, Wait::Zdp(_)))
            .count()
    }

    /// Room for one more transaction of the kind.
    pub(crate) fn has_room(&self, zdp: bool) -> bool {
        !self.pending.is_full() && (!zdp || self.zdp_pending() < MAX_PENDING_ZDP)
    }

    pub(crate) fn track(&mut self, owner: Owner, short: u16, wait: Wait) -> bool {
        let slack = match wait {
            Wait::Zdp(_) => Duration::from_secs(2),
            Wait::Zcl(_) => Duration::from_millis(0),
        };
        let deadline = self
            .now
            .saturating_add(self.config.response_timeout)
            .saturating_add(slack);
        self.pending
            .push(Pending {
                owner,
                short,
                wait,
                deadline,
            })
            .is_ok()
    }

    fn on_reply<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        short: u16,
        wait: Wait,
        reply: Reply<'_>,
    ) {
        let Some(at) = self
            .pending
            .iter()
            .position(|p| p.short == short && p.wait == wait)
        else {
            return;
        };
        let p = self.pending.swap_remove(at);
        self.dispatch(stack, p.owner, reply);
    }

    fn dispatch<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        owner: Owner,
        reply: Reply<'_>,
    ) {
        match owner {
            Owner::Interview(ieee) => self.interview_reply(stack, ieee, reply),
            Owner::Sync(ieee) => self.sync_reply(ieee, reply),
            Owner::Command(id) => self.command_reply(stack, id, reply),
        }
    }

    fn expire<C: BlockCipher, R: CryptoRng, S: Storage>(&mut self, stack: &mut Stack<C, R, S>) {
        let now = self.now;
        while let Some(at) = self
            .pending
            .iter()
            .position(|p| now.has_reached(p.deadline))
        {
            let p = self.pending.swap_remove(at);
            self.dispatch(stack, p.owner, Reply::Timeout);
        }
    }

    // ---------------------------------------------------------------
    // Polling
    // ---------------------------------------------------------------

    /// Runs timers: transaction timeouts, the permit-join window,
    /// interviews, state synchronization and registry writes.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(&mut self, stack: &mut Stack<C, R, S>) {
        self.now = stack.now();
        let now = self.now;
        self.poll_diagnostics(stack);
        self.poll_security(stack);
        self.expire(stack);
        if self.permit_until.is_some_and(|t| now.has_reached(t)) {
            self.permit_until = None;
            self.log(DiagRecord::new(
                Category::Commissioning,
                Severity::Info,
                code::PERMIT_JOIN_CLOSED,
            ));
            self.emit(Event::PermitJoinChanged { seconds: 0 });
        }
        if self.joins_until.is_some_and(|t| now.has_reached(t)) {
            self.joins_until = None;
            stack.config.trust_center_policy.allow_joins = false;
            self.log(DiagRecord::new(
                Category::Commissioning,
                Severity::Info,
                code::JOINS_REFUSED_AGAIN,
            ));
        }
        if stack.is_operating() {
            self.run_interviews(stack);
            self.run_syncs(stack);
            self.stop_fast_polls(stack);
        }
        self.poll_ota();
        self.flush_storage();
    }

    // ---------------------------------------------------------------
    // Poll Control
    // ---------------------------------------------------------------

    /// A Poll Control Check-in (server to client, ZCL8 §3.16.5.3).
    fn is_check_in(f: &ZclFrame) -> bool {
        let h = &f.origin.header;
        f.origin.cluster.0 == cluster::POLL_CONTROL
            && h.control.frame_type == FrameType::ClusterSpecific
            && h.control.direction == Direction::ToClient
            && h.command.0 == 0x00
    }

    /// Whether the hub has something for the device: its interview, a
    /// state synchronization, a host command or an awaited answer.
    fn has_work(&self, d: &Device) -> bool {
        !d.interview.status.is_finished()
            || d.needs_sync
            || d.sync_busy
            || self.commands.iter().any(|c| c.ieee == d.ieee)
            || self.pending.iter().any(|p| p.short == d.short)
            || self.ota.serving(d.ieee)
    }

    /// Answers a Check-in: fast polling while the hub has work for the
    /// device, so its requests are not held until the next long poll
    /// (§3.16.5.4.1). Every Check-in is answered; a device that gets no
    /// answer keeps its normal polling after `CheckInResponseWait`.
    fn on_check_in<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        i: Option<usize>,
        f: &ZclFrame,
    ) {
        let work = i
            .and_then(|i| self.registry.at(i))
            .is_some_and(|d| self.has_work(d));
        let timeout = self.config.fast_poll_timeout_qs;
        let t = timeout.to_le_bytes();
        stack.zcl.reply_cluster_specific(
            &f.origin,
            CommandId(0x00), // Check-in Response
            &[u8::from(work), t[0], t[1]],
        );
        stack.flush();
        let mut rec = DiagRecord::new(Category::Zcl, Severity::Debug, code::POLL_CHECK_IN)
            .short(f.origin.src.0)
            .endpoint(f.origin.src_endpoint.0)
            .cluster(cluster::POLL_CONTROL)
            .tsn(f.origin.header.seq.0)
            .status(u8::from(work))
            .arg(u32::from(timeout));
        if let Some(d) = i.and_then(|i| self.registry.at_mut(i)) {
            rec = rec.ieee(d.ieee);
            d.fast_polling = work;
        }
        self.log(rec);
    }

    /// Sends Fast Poll Stop to devices asked to fast poll whose work is
    /// done (§3.16.5.4.2), so they return to long polling at once.
    fn stop_fast_polls<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
    ) {
        for i in 0..self.registry.len() {
            let Some(d) = self.registry.at(i) else {
                continue;
            };
            if !d.fast_polling || self.has_work(d) {
                continue;
            }
            let (ieee, short) = (d.ieee, d.short);
            let Some(ep) = d.endpoint_serving(cluster::POLL_CONTROL) else {
                if let Some(d) = self.registry.at_mut(i) {
                    d.fast_polling = false;
                }
                continue;
            };
            if self
                .send_cluster_command(stack, short, ep, cluster::POLL_CONTROL, 0x01, &[], false)
                .is_none()
            {
                // The stack is busy: try again at the next poll.
                continue;
            }
            if let Some(d) = self.registry.at_mut(i) {
                d.fast_polling = false;
            }
            self.log(
                DiagRecord::new(Category::Zcl, Severity::Debug, code::FAST_POLL_STOP)
                    .ieee(ieee)
                    .short(short)
                    .endpoint(ep)
                    .cluster(cluster::POLL_CONTROL),
            );
        }
    }

    /// The earliest time [`Hub::poll`] has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut consider = |t: Instant| {
            if next.is_none_or(|n| t.as_millis() < n.as_millis()) {
                next = Some(t);
            }
        };
        if let Some(t) = self.ota_deadline() {
            consider(t);
        }
        for p in &self.pending {
            consider(p.deadline);
        }
        if let Some(t) = self.permit_until {
            consider(t);
        }
        if let Some(t) = self.joins_until {
            consider(t);
        }
        if let Some(t) = self.persist_due {
            consider(t);
        }
        #[cfg(feature = "alerts")]
        if let Some(t) = self.alert_deadline() {
            consider(Instant::from_millis(t));
        }
        for d in self.registry.iter() {
            if d.interview.status == InterviewStatus::InProgress
                && !d.interview.busy
                && let Some(t) = d.interview.due
            {
                consider(t);
            }
        }
        next
    }

    // ---------------------------------------------------------------
    // State synchronization
    // ---------------------------------------------------------------

    /// The clusters read to synchronize a device's state, in order.
    fn sync_list(d: &Device) -> Vec<(u8, u16), 8> {
        let mut l = Vec::new();
        if let Some(z) = d.zone {
            let _ = l.push((z.endpoint, cluster::IAS_ZONE));
        }
        for c in zcl::TRACKED {
            if c == cluster::IAS_ZONE || zcl::state_attributes(c).is_empty() {
                continue;
            }
            if let Some(ep) = d.endpoint_serving(c) {
                let _ = l.push((ep, c));
            }
        }
        l
    }

    fn run_syncs<C: BlockCipher, R: CryptoRng, S: Storage>(&mut self, stack: &mut Stack<C, R, S>) {
        let now = self.now;
        let interval = self.config.sync_interval;
        for i in 0..self.registry.len() {
            if !self.has_room(false) {
                return;
            }
            let Some(d) = self.registry.at(i) else {
                continue;
            };
            // A sleepy device is only reachable right after it was
            // heard (it polls its parent then).
            let awake = d.rx_on_when_idle == Some(true)
                || d.last_seen
                    .is_some_and(|t| now.saturating_duration_since(t).as_millis() < 5000);
            let due = d.last_sync.is_none_or(|t| {
                now.saturating_duration_since(t).as_millis() >= interval.as_millis()
            });
            if !d.needs_sync
                || d.sync_busy
                || !d.present
                || d.short == NO_SHORT
                || !d.interview.status.is_finished()
                || !awake
                || (d.sync_step == 0 && !due)
            {
                continue;
            }
            let list = Self::sync_list(d);
            let Some(&(ep, c)) = list.get(usize::from(d.sync_step)) else {
                if let Some(d) = self.registry.at_mut(i) {
                    d.needs_sync = false;
                    d.sync_step = 0;
                }
                continue;
            };
            let (ieee, short) = (d.ieee, d.short);
            let sent = self.send_read(stack, short, ep, c, zcl::state_attributes(c));
            let Some(d) = self.registry.at_mut(i) else {
                continue;
            };
            if d.sync_step == 0 {
                d.last_sync = Some(now);
            }
            match sent {
                Some(seq) => {
                    d.sync_busy = true;
                    if !self.track(Owner::Sync(ieee), short, Wait::Zcl(seq))
                        && let Some(d) = self.registry.at_mut(i)
                    {
                        d.sync_busy = false;
                        d.sync_step = 0;
                    }
                }
                None => d.sync_step = 0,
            }
        }
    }

    fn sync_reply(&mut self, ieee: u64, reply: Reply<'_>) {
        let Some(d) = self.registry.get_mut(ieee) else {
            return;
        };
        d.sync_busy = false;
        match reply {
            Reply::Timeout => d.sync_step = 0,
            _ => d.sync_step = d.sync_step.saturating_add(1),
        }
    }

    // ---------------------------------------------------------------
    // Sending
    // ---------------------------------------------------------------

    /// Sends Read Attributes; returns the ZCL sequence number.
    pub(crate) fn send_read<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        short: u16,
        endpoint: u8,
        cluster_id: u16,
        attributes: &[u16],
    ) -> Option<u8> {
        let payload = zcl::read_payload(attributes);
        self.send_global(
            stack,
            short,
            endpoint,
            cluster_id,
            global::READ_ATTRIBUTES,
            &payload,
        )
    }

    /// Sends a global ZCL command (default response enabled).
    pub(crate) fn send_global<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        short: u16,
        endpoint: u8,
        cluster_id: u16,
        command: CommandId,
        payload: &[u8],
    ) -> Option<u8> {
        let seq = stack
            .zcl
            .send_global(
                Destination::Short {
                    address: ShortAddress(short),
                    endpoint: Endpoint(endpoint),
                },
                ProfileId::HOME_AUTOMATION,
                ClusterId(cluster_id),
                self.config.endpoint,
                command,
                Direction::ToServer,
                None,
                payload,
            )
            .ok()?;
        stack.flush();
        Some(seq.0)
    }

    /// Sends a cluster-specific command to a server; `want_response`
    /// clears Disable Default Response.
    pub(crate) fn send_cluster_command<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        short: u16,
        endpoint: u8,
        cluster_id: u16,
        command: u8,
        payload: &[u8],
        want_response: bool,
    ) -> Option<u8> {
        let seq: TransactionSequence = stack.zcl.next_seq();
        let mut header = Header::cluster_specific(seq, CommandId(command), Direction::ToServer);
        header.control.disable_default_response = !want_response;
        stack
            .zcl_send(
                Destination::Short {
                    address: ShortAddress(short),
                    endpoint: Endpoint(endpoint),
                },
                ProfileId::HOME_AUTOMATION,
                ClusterId(cluster_id),
                self.config.endpoint,
                &header,
                payload,
            )
            .ok()?;
        Some(seq.0)
    }

    /// Sends Bind_req binding `cluster_id` of the device to the hub.
    pub(crate) fn send_bind<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
        short: u16,
        endpoint: u8,
        cluster_id: u16,
    ) -> Option<u8> {
        let req = BindReq {
            src: ExtendedAddress(ieee),
            src_endpoint: Endpoint(endpoint),
            cluster: ClusterId(cluster_id),
            destination: BindingDestination::Unicast {
                address: stack.config.ieee,
                endpoint: self.config.endpoint,
            },
        };
        stack
            .zdp_request(ShortAddress(short), zdp::BIND_REQ, &req)
            .ok()
            .map(|s| s.0)
    }

    // ---------------------------------------------------------------
    // Persistence
    // ---------------------------------------------------------------

    pub(crate) fn schedule_persist(&mut self) {
        if self.persist_due.is_none() {
            self.persist_due = Some(self.now.saturating_add(self.config.persist_delay));
        }
    }

    /// Counts and logs a storage error (also used by the firmware for
    /// the stack's storage at boot).
    pub fn storage_error(&mut self, e: StorageError) {
        let code = match e {
            StorageError::Full => 0,
            StorageError::Io => 1,
            StorageError::BufferTooSmall => 2,
        };
        self.counters.storage_errors = self.counters.storage_errors.saturating_add(1);
        if e == StorageError::Full {
            self.counters.storage_full = self.counters.storage_full.saturating_add(1);
        }
        self.counters.last_storage_error = Some(code);
        self.log(
            DiagRecord::new(Category::Persistence, Severity::Error, code::STORE_FAILED)
                .status(code),
        );
    }

    fn storage_failed(&mut self, e: StorageError) {
        self.storage_error(e);
        if !self.storage_failing {
            self.storage_failing = true;
            self.emit(Event::HubError {
                error: ErrorCode::StorageFailure,
                detail: 0,
            });
        }
        // Try again later rather than in a tight loop.
        self.persist_due = Some(self.now.saturating_add(Duration::from_secs(30)));
    }

    /// Writes what changed: new device records first, then the index,
    /// then erases removed devices' records.
    fn flush_storage(&mut self) {
        if !self.persist_due.is_some_and(|t| self.now.has_reached(t)) {
            return;
        }
        self.persist_due = None;
        if !self.config.persistent {
            self.registry.iter_mut().for_each(|d| d.dirty = false);
            self.index_dirty = false;
            self.erase_queue.clear();
            return;
        }
        let mut buf = [0u8; persist::MAX_RECORD];
        let mut written = 0;
        for i in 0..self.registry.len() {
            let Some(d) = self.registry.at(i) else {
                continue;
            };
            if !d.dirty {
                continue;
            }
            if written == WRITES_PER_POLL {
                self.schedule_persist();
                return;
            }
            let Ok(n) = persist::encode_device(d, &mut buf) else {
                continue;
            };
            let key = persist::device_key(d.ieee);
            match self.storage.store(key, buf.get(..n).unwrap_or(&[])) {
                Ok(()) => {
                    self.counters.storage_writes += 1;
                    self.storage_failing = false;
                    written += 1;
                    self.log(
                        DiagRecord::new(
                            Category::Persistence,
                            Severity::Debug,
                            code::RECORD_WRITTEN,
                        )
                        .ieee(key.id),
                    );
                    if let Some(d) = self.registry.at_mut(i) {
                        d.dirty = false;
                    }
                }
                Err(e) => return self.storage_failed(e),
            }
        }
        if self.index_dirty {
            let Ok(n) = persist::encode_index(self.registry.iter(), &mut buf) else {
                return;
            };
            match self
                .storage
                .store(persist::index_key(), buf.get(..n).unwrap_or(&[]))
            {
                Ok(()) => {
                    self.counters.storage_writes += 1;
                    self.index_dirty = false;
                }
                Err(e) => return self.storage_failed(e),
            }
        }
        while let Some(&ieee) = self.erase_queue.first() {
            if let Err(e) = self.storage.erase(persist::device_key(ieee)) {
                return self.storage_failed(e);
            }
            self.erase_queue.remove(0);
        }
    }

    /// Writes everything that is pending now, whatever the delay (before
    /// a planned restart).
    pub fn flush(&mut self) {
        loop {
            self.persist_due = Some(self.now);
            self.flush_storage();
            let more = self.registry.iter().any(|d| d.dirty)
                || self.index_dirty
                || !self.erase_queue.is_empty();
            if !more || self.storage_failing {
                break;
            }
        }
        self.persist_due = None;
    }

    // ---------------------------------------------------------------
    // Requests
    // ---------------------------------------------------------------

    fn uptime_s(&self) -> u32 {
        u32::try_from(self.now.as_millis() / 1000).unwrap_or(u32::MAX)
    }

    /// Engine diagnostics (the session adds its link counters).
    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics {
            uptime_s: self.uptime_s(),
            radio_rx: self.platform.radio_rx,
            radio_tx: self.platform.radio_tx,
            radio_dropped: self.platform.radio_dropped,
            stack_events_dropped: self.platform.stack_events_dropped,
            devices: u8::try_from(self.registry.len()).unwrap_or(u8::MAX),
            max_devices: u8::try_from(MAX_DEVICES).unwrap_or(u8::MAX),
            pending: u8::try_from(self.pending.len()).unwrap_or(u8::MAX),
            commands: u8::try_from(self.commands.len()).unwrap_or(u8::MAX),
            events_dropped: self.counters.events_dropped,
            interview_failures: self.counters.interview_failures,
            command_timeouts: self.counters.command_timeouts,
            storage_writes: self.counters.storage_writes,
            storage_errors: self.counters.storage_errors,
            registry_full: self.counters.registry_full,
            ..Diagnostics::default()
        }
    }

    /// Opens (`seconds` > 0) or closes the network for joining: the
    /// permit-join flag network-wide (Mgmt_Permit_Joining_req to all
    /// routers) and the Trust Center's acceptance of new devices, which
    /// stays on for [`HubConfig::join_grace`] after the window.
    pub fn permit_join<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        seconds: u8,
    ) -> Result<(), ErrorCode> {
        self.now = stack.now();
        if seconds > MAX_PERMIT_JOIN_SECONDS {
            return Err(ErrorCode::InvalidArgument);
        }
        if !stack.is_operating() {
            return Err(ErrorCode::NetworkDown);
        }
        stack
            .permit_join_network(seconds)
            .map_err(|_| ErrorCode::SendFailed)?;
        if seconds == 0 {
            self.permit_until = None;
            self.joins_until = None;
            stack.config.trust_center_policy.allow_joins = false;
            self.log(DiagRecord::new(
                Category::Commissioning,
                Severity::Info,
                code::PERMIT_JOIN_CLOSED,
            ));
        } else {
            self.log(
                DiagRecord::new(
                    Category::Commissioning,
                    Severity::Info,
                    code::PERMIT_JOIN_OPENED,
                )
                .arg(u32::from(seconds)),
            );
            let window = Duration::from_secs(u64::from(seconds));
            let until = self.now.saturating_add(window);
            self.permit_until = Some(until);
            self.joins_until = Some(until.saturating_add(self.config.join_grace));
            stack.config.trust_center_policy.allow_joins = true;
        }
        self.emit(Event::PermitJoinChanged { seconds });
        Ok(())
    }

    /// Seconds left in the permit-join window.
    pub fn permit_join_remaining(&self) -> u8 {
        self.permit_until.map_or(0, |t| {
            let ms = self.now.saturating_duration_until(t).as_millis();
            u8::try_from(ms.div_ceil(1000)).unwrap_or(u8::MAX)
        })
    }

    /// Executes a host request. Requests that continue over the radio
    /// answer [`Response::Accepted`]; their outcome is an event.
    pub fn handle<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        request: &Request,
    ) -> Response {
        self.now = stack.now();
        if let Some(r) = self.handle_diagnostics(stack, request) {
            return r.unwrap_or_else(Response::Error);
        }
        if let Some(r) = self.handle_security(stack, request) {
            return r.unwrap_or_else(Response::Error);
        }
        if let Some(r) = self.handle_ota(stack, request) {
            return r.unwrap_or_else(Response::Error);
        }
        #[cfg(feature = "alerts")]
        if let Some(r) = self.handle_alerts(request) {
            return r.unwrap_or_else(Response::Error);
        }
        let r = match request {
            Request::GetHubInfo => Ok(Response::HubInfo(HubInfo {
                protocol_version: VERSION,
                firmware: Vec::from_slice(
                    self.config
                        .firmware
                        .as_bytes()
                        .get(..self.config.firmware.len().min(MAX_FIRMWARE))
                        .unwrap_or(&[]),
                )
                .unwrap_or_default(),
                ieee: stack.config.ieee.0,
                max_devices: u8::try_from(MAX_DEVICES).unwrap_or(u8::MAX),
                uptime_s: self.uptime_s(),
                persistent: self.config.persistent,
            })),
            Request::GetNetworkStatus => {
                let state = if stack.is_operating() {
                    NetworkState::Up
                } else if self.network.is_some() {
                    NetworkState::Forming
                } else {
                    NetworkState::Down
                };
                Ok(Response::NetworkStatus(NetworkStatus {
                    state,
                    network: Self::network_info(stack),
                    short: stack.short_address().0,
                    permit_join_s: self.permit_join_remaining(),
                    devices: u8::try_from(self.registry.len()).unwrap_or(u8::MAX),
                }))
            }
            Request::PermitJoin { seconds } => {
                if *seconds == 0 {
                    Err(ErrorCode::InvalidArgument)
                } else {
                    self.permit_join(stack, *seconds).map(|()| Response::Done)
                }
            }
            Request::CloseNetwork => self.permit_join(stack, 0).map(|()| Response::Done),
            Request::ListDevices { start } => {
                let boot = Instant::from_millis(0);
                let mut devices = Vec::new();
                for d in self
                    .registry
                    .iter()
                    .skip(usize::from(*start))
                    .take(DEVICE_PAGE)
                {
                    let _ = devices.push(d.summary(boot));
                }
                Ok(Response::DeviceList(DeviceList {
                    total: u8::try_from(self.registry.len()).unwrap_or(u8::MAX),
                    start: *start,
                    devices,
                }))
            }
            Request::GetDevice { ieee } => self
                .registry
                .get(*ieee)
                .map(|d| Response::Device(d.info(Instant::from_millis(0))))
                .ok_or(ErrorCode::UnknownDevice),
            Request::GetDeviceState { ieee } => self
                .registry
                .get(*ieee)
                .map(|d| Response::DeviceState {
                    ieee: d.ieee,
                    state: d.state,
                    last_seen_s: d.last_seen_s(Instant::from_millis(0)),
                })
                .ok_or(ErrorCode::UnknownDevice),
            Request::InterviewDevice { ieee } => {
                self.restart_interview(*ieee).map(|()| Response::Done)
            }
            Request::ReadAttribute {
                ieee,
                endpoint,
                cluster,
                attribute,
            } => self.start_command(
                stack,
                *ieee,
                *endpoint,
                CommandKind::Read {
                    cluster: *cluster,
                    attribute: *attribute,
                },
            ),
            Request::ConfigureReporting {
                ieee,
                endpoint,
                cluster,
                attribute,
                data_type,
                min_interval,
                max_interval,
                change,
            } => {
                if min_interval > max_interval && *max_interval != 0 {
                    Err(ErrorCode::InvalidArgument)
                } else {
                    let analog = zcl::analog_width(*data_type).is_some();
                    self.start_command(
                        stack,
                        *ieee,
                        *endpoint,
                        CommandKind::Configure {
                            cluster: *cluster,
                            report: Report {
                                attribute: *attribute,
                                data_type: *data_type,
                                min: *min_interval,
                                max: *max_interval,
                                change: analog.then_some(*change),
                            },
                        },
                    )
                }
            }
            Request::Bind {
                ieee,
                endpoint,
                cluster,
            } => self.start_command(
                stack,
                *ieee,
                *endpoint,
                CommandKind::Bind { cluster: *cluster },
            ),
            Request::Light {
                ieee,
                endpoint,
                command,
            } => self.start_light(stack, *ieee, *endpoint, *command),
            Request::GetLightColor { .. }
            | Request::AddGroup { .. }
            | Request::RemoveGroup { .. }
            | Request::StoreScene { .. }
            | Request::GroupLight { .. }
            | Request::RecallScene { .. } => self.handle_lighting(stack, request),
            Request::RemoveDevice { ieee, leave } => self
                .remove_device(stack, *ieee, *leave)
                .map(|()| Response::Done),
            Request::GetDiagnostics => Ok(Response::Diagnostics(self.diagnostics())),
            // Answered by `handle_diagnostics` above.
            Request::GetBootReport
            | Request::GetRadioDiagnostics
            | Request::GetStorageDiagnostics
            | Request::GetRuntimeDiagnostics
            | Request::GetTraceConfiguration
            | Request::SetTraceConfiguration { .. }
            | Request::ReadTrace { .. }
            | Request::ClearTrace
            | Request::StartCapture { .. }
            | Request::StopCapture
            | Request::ReadCapture { .. }
            | Request::SetKeyExchangeExemption { .. }
            | Request::GetSecurityStatus
            | Request::OtaOffer(_)
            | Request::OtaData { .. }
            | Request::OtaCancel
            | Request::GetOtaStatus => Err(ErrorCode::UnknownRequest),
            // Answered by `handle_alerts` with the `alerts` feature.
            Request::GetAlertStatus
            | Request::SetAlertConfig(_)
            | Request::QueueTestAlert
            | Request::RunRadioProbe
            | Request::GetWifiScan => Err(ErrorCode::NotSupported),
        };
        r.unwrap_or_else(Response::Error)
    }

    /// Removes a device from the registry, after asking it to leave the
    /// network when `leave`.
    fn remove_device<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
        leave: bool,
    ) -> Result<(), ErrorCode> {
        let d = self.registry.get(ieee).ok_or(ErrorCode::UnknownDevice)?;
        let short = d.short;
        self.drop_exemption(stack, ieee);
        if leave {
            if !stack.is_operating() {
                return Err(ErrorCode::NetworkDown);
            }
            // The Trust Center way first (NWK Leave to a child, APS
            // Remove Device to a parent); a device the stack's tables do
            // not hold gets a Mgmt_Leave_req at its last known address.
            if stack.remove_node(ExtendedAddress(ieee), None).is_err() {
                if short == NO_SHORT {
                    return Err(ErrorCode::Unreachable);
                }
                stack
                    .zdp_request(
                        ShortAddress(short),
                        zdp::MGMT_LEAVE_REQ,
                        &MgmtLeaveReq {
                            device: ExtendedAddress(ieee),
                            remove_children: false,
                            rejoin: false,
                        },
                    )
                    .map_err(|_| ErrorCode::SendFailed)?;
            }
        }
        self.cancel_device(ieee);
        self.registry.remove(ieee);
        self.index_dirty = true;
        if self.erase_queue.push(ieee).is_err() {
            // The queue only delays erasures: write now to make room.
            self.flush();
            let _ = self.erase_queue.push(ieee);
        }
        self.schedule_persist();
        Ok(())
    }

    // ---------------------------------------------------------------
    // Host commands
    // ---------------------------------------------------------------

    fn command_target(&self, ieee: u64) -> Result<&Device, ErrorCode> {
        let d = self.registry.get(ieee).ok_or(ErrorCode::UnknownDevice)?;
        if !d.present || d.short == NO_SHORT {
            return Err(ErrorCode::Unreachable);
        }
        Ok(d)
    }

    fn start_light<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
        endpoint: u8,
        command: LightCommand,
    ) -> Result<Response, ErrorCode> {
        let command = Self::normalize_light(command)?;
        let d = self.command_target(ieee)?;
        let needed = command.cluster();
        let endpoint = if endpoint == 0 {
            d.endpoint_serving(needed).ok_or(ErrorCode::NotSupported)?
        } else if d
            .endpoint(endpoint)
            .is_some_and(|e| e.inputs.contains(&needed))
        {
            endpoint
        } else {
            return Err(ErrorCode::NotSupported);
        };
        self.start_command(stack, ieee, endpoint, CommandKind::Light(command))
    }

    /// Colour, group and scene requests (0.4).
    fn handle_lighting<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        request: &Request,
    ) -> Result<Response, ErrorCode> {
        match request {
            Request::GetLightColor { ieee } => {
                let d = self.registry.get(*ieee).ok_or(ErrorCode::UnknownDevice)?;
                if !d.capabilities.contains(crate::model::Capabilities::COLOR) {
                    return Err(ErrorCode::NotSupported);
                }
                Ok(Response::LightColor {
                    ieee: *ieee,
                    color: d.color,
                })
            }
            Request::AddGroup {
                ieee,
                endpoint,
                group,
            }
            | Request::RemoveGroup {
                ieee,
                endpoint,
                group,
            } => {
                if *group == 0 || *group > MAX_GROUP {
                    return Err(ErrorCode::InvalidArgument);
                }
                let remove = matches!(request, Request::RemoveGroup { .. });
                let endpoint = self.member_endpoint(*ieee, *endpoint, cluster::GROUPS)?;
                self.start_command(
                    stack,
                    *ieee,
                    endpoint,
                    CommandKind::Group {
                        remove,
                        group: *group,
                    },
                )
            }
            Request::StoreScene {
                ieee,
                endpoint,
                group,
                scene,
            } => {
                if *group > MAX_GROUP {
                    return Err(ErrorCode::InvalidArgument);
                }
                let endpoint = self.member_endpoint(*ieee, *endpoint, cluster::SCENES)?;
                self.start_command(
                    stack,
                    *ieee,
                    endpoint,
                    CommandKind::StoreScene {
                        group: *group,
                        scene: *scene,
                    },
                )
            }
            Request::GroupLight { group, command } => {
                if *group == 0 || *group > MAX_GROUP {
                    return Err(ErrorCode::InvalidArgument);
                }
                let command = Self::normalize_light(*command)?;
                let (cluster_id, cmd, payload) =
                    Self::light_frame(command).ok_or(ErrorCode::InvalidArgument)?;
                self.send_group(stack, *group, cluster_id, cmd, &payload)
                    .map(|()| Response::Done)
            }
            Request::RecallScene {
                group,
                scene,
                transition_ds,
            } => {
                if *group > MAX_GROUP {
                    return Err(ErrorCode::InvalidArgument);
                }
                let g = group.to_le_bytes();
                let t = transition_ds.to_le_bytes();
                // Recall Scene: group, scene and, when given, a transition
                // time overriding the scene's (ZCL8 §3.7.2.4.5).
                let payload: Vec<u8, 5> = if *transition_ds == 0 {
                    Vec::from_slice(&[g[0], g[1], *scene]).unwrap_or_default()
                } else {
                    Vec::from_slice(&[g[0], g[1], *scene, t[0], t[1]]).unwrap_or_default()
                };
                self.send_group(stack, *group, cluster::SCENES, 0x05, &payload)
                    .map(|()| Response::Done)
            }
            _ => Err(ErrorCode::UnknownRequest),
        }
    }

    /// A light command as sent: brightness 0 is Off; out-of-range values
    /// are refused.
    fn normalize_light(command: LightCommand) -> Result<LightCommand, ErrorCode> {
        match command {
            LightCommand::SetBrightness { percent: 0, .. } => Ok(LightCommand::TurnOff),
            LightCommand::SetBrightness { percent, .. } if percent > 100 => {
                Err(ErrorCode::InvalidArgument)
            }
            // 0 is undefined and 0xffff invalid (ZCL8 §5.2.2.2.1.8).
            LightCommand::SetColorTemperature { mireds, .. } if mireds == 0 || mireds == 0xffff => {
                Err(ErrorCode::InvalidArgument)
            }
            // At most 0xfeff (§5.2.2.2.1.4).
            LightCommand::SetColorXy { x, y, .. } if x > 0xfeff || y > 0xfeff => {
                Err(ErrorCode::InvalidArgument)
            }
            // At most 0xfe (§5.2.2.2.1.1).
            LightCommand::SetHueSaturation {
                hue, saturation, ..
            } if hue > 0xfe || saturation > 0xfe => Err(ErrorCode::InvalidArgument),
            c => Ok(c),
        }
    }

    /// The cluster, command and payload of a light command.
    fn light_frame(l: LightCommand) -> Option<(u16, u8, Vec<u8, 8>)> {
        // Color commands execute even while the light is off
        // (OptionsMask / OptionsOverride bit 0, ExecuteIfOff, §5.2.2.2.1.29),
        // so a colour set before turning on is kept.
        const IF_OFF: [u8; 2] = [1, 1];
        Some(match l {
            LightCommand::TurnOn => (cluster::ON_OFF, 0x01, Vec::new()),
            LightCommand::TurnOff => (cluster::ON_OFF, 0x00, Vec::new()),
            LightCommand::Toggle => (cluster::ON_OFF, 0x02, Vec::new()),
            LightCommand::SetBrightness {
                percent,
                transition_ds,
            } => {
                let level = brightness_to_level(percent)?;
                let t = transition_ds.to_le_bytes();
                // Move to Level (with On/Off): level, transition time,
                // OptionsMask, OptionsOverride (ZCL8 §3.10.2.3.1).
                let p = Vec::from_slice(&[level, t[0], t[1], 0, 0]).ok()?;
                (cluster::LEVEL, 0x04, p)
            }
            LightCommand::SetColorTemperature {
                mireds,
                transition_ds,
            } => {
                let m = mireds.to_le_bytes();
                let t = transition_ds.to_le_bytes();
                let p = Vec::from_slice(&[m[0], m[1], t[0], t[1], IF_OFF[0], IF_OFF[1]]).ok()?;
                (cluster::COLOR, 0x0a, p)
            }
            LightCommand::SetColorXy {
                x,
                y,
                transition_ds,
            } => {
                let (x, y, t) = (
                    x.to_le_bytes(),
                    y.to_le_bytes(),
                    transition_ds.to_le_bytes(),
                );
                let p =
                    Vec::from_slice(&[x[0], x[1], y[0], y[1], t[0], t[1], IF_OFF[0], IF_OFF[1]])
                        .ok()?;
                (cluster::COLOR, 0x07, p)
            }
            LightCommand::SetHueSaturation {
                hue,
                saturation,
                transition_ds,
            } => {
                let t = transition_ds.to_le_bytes();
                let p =
                    Vec::from_slice(&[hue, saturation, t[0], t[1], IF_OFF[0], IF_OFF[1]]).ok()?;
                (cluster::COLOR, 0x06, p)
            }
        })
    }

    /// The endpoint of `ieee` serving `cluster_id`: `endpoint`, or the
    /// first one when 0.
    fn member_endpoint(&self, ieee: u64, endpoint: u8, cluster_id: u16) -> Result<u8, ErrorCode> {
        let d = self.command_target(ieee)?;
        if endpoint == 0 {
            d.endpoint_serving(cluster_id)
                .ok_or(ErrorCode::NotSupported)
        } else if d
            .endpoint(endpoint)
            .is_some_and(|e| e.inputs.contains(&cluster_id))
        {
            Ok(endpoint)
        } else {
            Err(ErrorCode::NotSupported)
        }
    }

    /// Sends a cluster command to a group: one group-addressed frame, no
    /// response asked for (ZCL8 §2.5.12.2: none comes for groupcasts).
    fn send_group<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        group: u16,
        cluster_id: u16,
        command: u8,
        payload: &[u8],
    ) -> Result<(), ErrorCode> {
        if !stack.is_operating() {
            return Err(ErrorCode::NetworkDown);
        }
        let seq: TransactionSequence = stack.zcl.next_seq();
        let mut header = Header::cluster_specific(seq, CommandId(command), Direction::ToServer);
        header.control.disable_default_response = true;
        stack
            .zcl_send(
                Destination::Group(GroupAddress(group)),
                ProfileId::HOME_AUTOMATION,
                ClusterId(cluster_id),
                self.config.endpoint,
                &header,
                payload,
            )
            .map_err(|_| ErrorCode::SendFailed)
    }

    fn start_command<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
        endpoint: u8,
        kind: CommandKind,
    ) -> Result<Response, ErrorCode> {
        if !stack.is_operating() {
            return Err(ErrorCode::NetworkDown);
        }
        let short = self.command_target(ieee)?.short;
        let zdp = matches!(kind, CommandKind::Bind { .. });
        if self.commands.is_full() || !self.has_room(zdp) {
            return Err(ErrorCode::Busy);
        }
        let id = self.next_command;
        self.next_command = self.next_command.checked_add(1).unwrap_or(1);
        let mut cmd = HostCommand {
            id,
            ieee,
            short,
            endpoint,
            kind,
            stage: CommandStage::Accepted,
            attempts: 1,
        };
        let wait = self.transmit(stack, &cmd).ok_or(ErrorCode::SendFailed)?;
        cmd.stage = CommandStage::Sent;
        self.log_command(&cmd, code::COMMAND_SENT, Severity::Debug, None);
        let _ = self.commands.push(cmd);
        if !self.track(Owner::Command(id), short, wait) {
            // Room was checked above; never leave a command untracked.
            self.commands.retain(|c| c.id != id);
            return Err(ErrorCode::Busy);
        }
        Ok(Response::Accepted { command: id })
    }

    /// Sends a command's request; returns what to await.
    fn transmit<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        c: &HostCommand,
    ) -> Option<Wait> {
        match c.kind {
            CommandKind::Light(l) => {
                let (cluster_id, command, payload) = Self::light_frame(l)?;
                self.send_cluster_command(
                    stack, c.short, c.endpoint, cluster_id, command, &payload, true,
                )
                .map(Wait::Zcl)
            }
            CommandKind::Read { cluster, attribute } => self
                .send_read(stack, c.short, c.endpoint, cluster, &[attribute])
                .map(Wait::Zcl),
            CommandKind::Configure { cluster, report } => {
                let payload = zcl::configure_payload(&[report]);
                self.send_global(
                    stack,
                    c.short,
                    c.endpoint,
                    cluster,
                    global::CONFIGURE_REPORTING,
                    &payload,
                )
                .map(Wait::Zcl)
            }
            CommandKind::Bind { cluster } => self
                .send_bind(stack, c.ieee, c.short, c.endpoint, cluster)
                .map(Wait::Zdp),
            CommandKind::Group { remove, group } => {
                let g = group.to_le_bytes();
                // Add Group: group and an empty name; Remove Group: the
                // group (ZCL8 §3.6.2.3).
                let (command, payload): (u8, &[u8]) = if remove {
                    (0x03, &g)
                } else {
                    (0x00, &[g[0], g[1], 0])
                };
                self.send_cluster_command(
                    stack,
                    c.short,
                    c.endpoint,
                    cluster::GROUPS,
                    command,
                    payload,
                    true,
                )
                .map(Wait::Zcl)
            }
            CommandKind::StoreScene { group, scene } => {
                let g = group.to_le_bytes();
                self.send_cluster_command(
                    stack,
                    c.short,
                    c.endpoint,
                    cluster::SCENES,
                    0x04,
                    &[g[0], g[1], scene],
                    true,
                )
                .map(Wait::Zcl)
            }
        }
    }

    fn log_command(&mut self, c: &HostCommand, which: u16, severity: Severity, status: Option<u8>) {
        let cluster_id = match c.kind {
            CommandKind::Light(l) => l.cluster(),
            CommandKind::Group { .. } => cluster::GROUPS,
            CommandKind::StoreScene { .. } => cluster::SCENES,
            CommandKind::Read { cluster, .. }
            | CommandKind::Configure { cluster, .. }
            | CommandKind::Bind { cluster } => cluster,
        };
        let mut rec = DiagRecord::new(Category::Zcl, severity, which)
            .ieee(c.ieee)
            .short(c.short)
            .endpoint(c.endpoint)
            .cluster(cluster_id)
            .arg(u32::from(c.id));
        if let Some(s) = status {
            rec = rec.status(s);
        }
        self.log(rec);
    }

    fn finish_command_ok(&mut self, id: u16, stage: CommandStage, value: Option<AttributeData>) {
        let Some(at) = self.commands.iter().position(|c| c.id == id) else {
            return;
        };
        let c = self.commands.swap_remove(at);
        let which = if stage == CommandStage::Confirmed {
            code::COMMAND_CONFIRMED
        } else {
            code::COMMAND_RESPONDED
        };
        self.log_command(&c, which, Severity::Info, None);
        self.emit(Event::CommandCompleted {
            command: id,
            ieee: c.ieee,
            stage,
            value,
        });
    }

    fn finish_command_failed(&mut self, id: u16, error: ErrorCode, status: u8) {
        let Some(at) = self.commands.iter().position(|c| c.id == id) else {
            return;
        };
        let c = self.commands.swap_remove(at);
        self.pending.retain(|p| p.owner != Owner::Command(id));
        let which = if error == ErrorCode::Timeout {
            code::COMMAND_TIMEOUT
        } else {
            code::COMMAND_FAILED
        };
        self.log_command(&c, which, Severity::Warning, Some(status));
        self.emit(Event::CommandFailed {
            command: id,
            ieee: c.ieee,
            stage: c.stage,
            error,
            status,
        });
    }

    fn command_reply<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        id: u16,
        reply: Reply<'_>,
    ) {
        let Some(c) = self.commands.iter().find(|c| c.id == id).copied() else {
            return;
        };
        match reply {
            Reply::Timeout => self.command_timeout(stack, c),
            Reply::Zdp(z) => {
                let status = StatusRsp::decode(&mut Reader::new(&z.data)).map(|s| s.status);
                match status {
                    Ok(s) if s.is_success() => {
                        self.finish_command_ok(id, CommandStage::Responded, None);
                    }
                    Ok(s) => self.finish_command_failed(id, ErrorCode::ZdoFailure, s.raw()),
                    Err(_) => self.finish_command_failed(id, ErrorCode::ZdoFailure, 0xff),
                }
            }
            Reply::Zcl(f) => self.command_zcl(stack, c, f),
        }
    }

    fn command_timeout<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        c: HostCommand,
    ) {
        if c.stage == CommandStage::Responded {
            // The device executed the command; only the read-back is
            // missing.
            self.finish_command_ok(c.id, CommandStage::Responded, None);
            return;
        }
        // Idempotent commands get a second chance; Toggle does not (a
        // lost response does not mean a lost command).
        let retry = c.attempts < 2 && !matches!(c.kind, CommandKind::Light(LightCommand::Toggle));
        if retry && let Some(wait) = self.transmit(stack, &c) {
            if let Some(cmd) = self.commands.iter_mut().find(|x| x.id == c.id) {
                cmd.attempts += 1;
            }
            self.log_command(&c, code::COMMAND_RETRY, Severity::Warning, None);
            if self.track(Owner::Command(c.id), c.short, wait) {
                return;
            }
        }
        self.counters.command_timeouts = self.counters.command_timeouts.saturating_add(1);
        self.finish_command_failed(c.id, ErrorCode::Timeout, 0);
    }

    fn command_zcl<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        c: HostCommand,
        f: &ZclFrame,
    ) {
        let h = &f.origin.header;
        if h.control.frame_type != FrameType::Global {
            // Groups / Scenes responses: a status first (ZCL8 §3.6.2.4,
            // §3.7.2.5).
            let expected = match c.kind {
                CommandKind::Group { remove: false, .. } => Some(member_cmd::ADD_GROUP_RESPONSE),
                CommandKind::Group { remove: true, .. } => Some(member_cmd::REMOVE_GROUP_RESPONSE),
                CommandKind::StoreScene { .. } => Some(member_cmd::STORE_SCENE_RESPONSE),
                _ => None,
            };
            if expected == Some(h.command.0) {
                let status = f.payload.first().copied().unwrap_or(0xff);
                let holds = match c.kind {
                    CommandKind::Group { remove: false, .. } => {
                        status == member_cmd::DUPLICATE_EXISTS
                    }
                    CommandKind::Group { remove: true, .. } => status == member_cmd::NOT_FOUND,
                    _ => false,
                };
                if status == 0 || holds {
                    self.finish_command_ok(c.id, CommandStage::Responded, None);
                } else {
                    self.finish_command_failed(c.id, ErrorCode::ZclFailure, status);
                }
            }
            return;
        }
        if h.command == global::DEFAULT_RESPONSE {
            let Ok(dr) = DefaultResponse::decode_exact(&f.payload) else {
                return self.finish_command_failed(c.id, ErrorCode::ZclFailure, 0xff);
            };
            if !dr.status.is_success() {
                self.log(
                    DiagRecord::new(
                        Category::Zcl,
                        Severity::Warning,
                        code::ZCL_DEFAULT_RESPONSE_ERROR,
                    )
                    .ieee(c.ieee)
                    .short(c.short)
                    .endpoint(f.origin.src_endpoint.0)
                    .cluster(f.origin.cluster.0)
                    .tsn(h.seq.0)
                    .status(dr.status.raw()),
                );
                return self.finish_command_failed(c.id, ErrorCode::ZclFailure, dr.status.raw());
            }
            match c.kind {
                CommandKind::Light(l) if c.stage == CommandStage::Sent => {
                    // Executed: read the result back.
                    if let Some(cmd) = self.commands.iter_mut().find(|x| x.id == c.id) {
                        cmd.stage = CommandStage::Responded;
                    }
                    let (cl, attrs): (u16, &[u16]) = match l {
                        LightCommand::SetBrightness { .. } => (cluster::LEVEL, &[0x0000]),
                        LightCommand::SetColorTemperature { .. } => (
                            cluster::COLOR,
                            &[zcl::color_attr::MIREDS, zcl::color_attr::MODE],
                        ),
                        LightCommand::SetColorXy { .. } => (
                            cluster::COLOR,
                            &[
                                zcl::color_attr::X,
                                zcl::color_attr::Y,
                                zcl::color_attr::MODE,
                            ],
                        ),
                        LightCommand::SetHueSaturation { .. } => (
                            cluster::COLOR,
                            &[
                                zcl::color_attr::HUE,
                                zcl::color_attr::SATURATION,
                                zcl::color_attr::MODE,
                            ],
                        ),
                        _ => (cluster::ON_OFF, &[0x0000]),
                    };
                    match self.send_read(stack, c.short, c.endpoint, cl, attrs) {
                        Some(seq) if self.track(Owner::Command(c.id), c.short, Wait::Zcl(seq)) => {}
                        Some(_) => self.finish_command_ok(c.id, CommandStage::Responded, None),
                        None => self.finish_command_ok(c.id, CommandStage::Responded, None),
                    }
                }
                _ => self.finish_command_ok(c.id, CommandStage::Responded, None),
            }
            return;
        }
        if h.command == global::READ_ATTRIBUTES_RESPONSE {
            let first = Records::<ReadAttributeStatus>::new(&f.payload)
                .map_while(Result::ok)
                .next();
            let Some(rec) = first else {
                return self.finish_command_failed(c.id, ErrorCode::ZclFailure, 0xff);
            };
            match rec.value {
                Some(v) if rec.status.is_success() => {
                    let stage = if matches!(c.kind, CommandKind::Light(_)) {
                        CommandStage::Confirmed
                    } else {
                        CommandStage::Responded
                    };
                    self.finish_command_ok(c.id, stage, Some(zcl::attribute_data(&v)));
                }
                _ => self.finish_command_failed(c.id, ErrorCode::ZclFailure, rec.status.raw()),
            }
            return;
        }
        if h.command == global::CONFIGURE_REPORTING_RESPONSE {
            let failed = Records::<ConfigureReportingStatus>::new(&f.payload)
                .map_while(Result::ok)
                .find(|s| !s.status.is_success());
            match failed {
                None => self.finish_command_ok(c.id, CommandStage::Responded, None),
                Some(s) => self.finish_command_failed(c.id, ErrorCode::ZclFailure, s.status.raw()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::protocol::ZoneInfo;
    use crate::registry::zone_type;
    use panweave_storage::MemoryStorage;

    type TestHub = Hub<MemoryStorage<8, 512>>;

    fn hub_with(model: &[u8], manufacturer: &[u8]) -> (TestHub, usize) {
        let mut hub = Hub::new(HubConfig::default(), MemoryStorage::new());
        let (i, _) = hub.registry.upsert(0x00AA_0000_0000_0042, 0x1234).unwrap();
        let d = hub.registry.at_mut(i).unwrap();
        d.manufacturer = Vec::from_slice(manufacturer).unwrap();
        d.model = Vec::from_slice(model).unwrap();
        d.zone = Some(ZoneInfo {
            endpoint: 1,
            zone_type: None,
            zone_id: None,
            enrolled: false,
        });
        while hub.next_event().is_some() {}
        (hub, i)
    }

    #[test]
    fn an_alarm_before_the_zone_type_is_interpreted_once_it_is_known() {
        let (mut hub, i) = hub_with(b"YNDX-00527", b"Yandex");
        // A Zone Status Change Notification arrives before the interview
        // read the zone type: kept raw, never read as "dry".
        hub.ingest_zone_status(i, crate::ias::status::ALARM1);
        let d = hub.registry.at(i).unwrap();
        assert_eq!(d.state.water_leak, LeakState::Unknown);
        assert_eq!(d.state.zone_status, Some(1));
        // The zone type arrives: the stored status is interpreted.
        hub.apply_attributes(
            i,
            1,
            cluster::IAS_ZONE,
            [(
                0x0001u16,
                panweave_zcl::Value::Enum16(zone_type::WATER_SENSOR),
            )]
            .into_iter(),
            false,
        );
        assert_eq!(
            hub.registry.at(i).unwrap().state.water_leak,
            LeakState::Leak
        );
        let mut leak_events = 0;
        while let Some(e) = hub.next_event() {
            if matches!(
                e,
                Event::Sensor {
                    event: SensorEvent::WaterLeakDetected,
                    ..
                }
            ) {
                leak_events += 1;
            }
        }
        assert_eq!(leak_events, 1);
    }

    #[test]
    fn the_aqara_profile_corrects_a_mains_claim_and_others_do_not() {
        for (model, manufacturer, expected) in [
            (&b"lumi.flood.agl02"[..], &b"LUMI"[..], PowerSource::Battery),
            (&b"other-sensor"[..], &b"LUMI"[..], PowerSource::Mains),
        ] {
            let (mut hub, i) = hub_with(model, manufacturer);
            let d = hub.registry.at_mut(i).unwrap();
            assert_eq!(
                d.ignores_mac_mains_claim(),
                expected == PowerSource::Battery
            );
            // What a MAC capability octet with the mains bit led to.
            d.power_source = PowerSource::Mains;
            hub.apply_attributes(i, 1, cluster::BASIC, core::iter::empty(), false);
            assert_eq!(hub.registry.at(i).unwrap().power_source, expected);
        }
    }
}
