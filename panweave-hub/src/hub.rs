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
    ClusterId, CommandId, CryptoRng, Endpoint, ExtendedAddress, MacCapability, ProfileId,
    ShortAddress, TransactionSequence,
};
use panweave_zcl::global::{
    AttributeValue, ConfigureReportingStatus, DefaultResponse, ReadAttributeStatus, Records,
    command as global,
};
use panweave_zcl::{Direction, FrameType, Header};
use panweave_zdo::zdp::{BindReq, MgmtLeaveReq, StatusRsp, cluster as zdp};

use crate::model::{
    ContactState, DeviceState, Flag, InterviewStatus, LeakState, PowerSource, brightness_to_level,
};
use crate::persist;
use crate::protocol::{
    AttributeData, CommandStage, DEVICE_PAGE, DeviceList, Diagnostics, ErrorCode, Event, HubInfo,
    LightCommand, MAX_FIRMWARE, MAX_PERMIT_JOIN_SECONDS, NetworkInfo, NetworkState, NetworkStatus,
    Request, Response, SensorEvent, VERSION,
};
use crate::registry::{Device, MAX_DEVICES, NO_SHORT, Registry, cluster};
use crate::zcl::{self, Applied, Report, ias_cmd};

/// Hub events kept for the host.
const EVENT_CAPACITY: usize = 32;
/// Zigbee transactions awaited at once.
const MAX_PENDING: usize = 10;
/// ZDP transactions awaited at once (the stack's ZDO tracks four).
const MAX_PENDING_ZDP: usize = 3;
/// Host commands in flight.
const MAX_COMMANDS: usize = 8;
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
}

/// Counters of the platform (radio driver, stack) for diagnostics; the
/// firmware updates them.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformCounters {
    /// Radio frames received.
    pub radio_rx: u32,
    /// Radio frames transmitted.
    pub radio_tx: u32,
    /// Radio frames dropped by the driver.
    pub radio_dropped: u32,
    /// Stack events dropped.
    pub stack_events_dropped: u32,
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
    Read { cluster: u16, attribute: u16 },
    Configure { cluster: u16, report: Report },
    Bind { cluster: u16 },
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
    storage: HS,
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
            return Ok(0);
        }
        let mut buf = [0u8; persist::MAX_RECORD];
        let Some(n) = self.storage.load(persist::index_key(), &mut buf)? else {
            return Ok(0);
        };
        let Ok(index) = persist::decode_index(buf.get(..n).unwrap_or(&[])) else {
            self.counters.storage_errors += 1;
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
                    self.counters.storage_errors += 1;
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
                _ => skipped = skipped.saturating_add(1),
            }
        }
        if skipped > 0 {
            self.counters.storage_errors += u32::from(skipped);
            self.emit(Event::HubError {
                error: ErrorCode::StorageFailure,
                detail: skipped,
            });
        }
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
            self.unreported_drops = self.unreported_drops.saturating_add(1);
            self.counters.events_dropped = self.counters.events_dropped.saturating_add(1);
        }
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

    fn emit_state_events(&mut self, ieee: u64, before: &DeviceState, after: &DeviceState) {
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
                self.emit(Event::NetworkStarted(info));
            }
            StackEvent::FormationFailed(_) => {
                self.network = None;
                self.emit(Event::HubError {
                    error: ErrorCode::NetworkDown,
                    detail: 0,
                });
            }
            StackEvent::DeviceAuthorized { ieee, short } => {
                self.device_joined(ieee.0, short.0, None);
            }
            StackEvent::DeviceAnnounce {
                ieee,
                short,
                capability,
            } => self.device_joined(ieee.0, short.0, Some(*capability)),
            StackEvent::DeviceLeft { ieee, rejoin } => {
                if !rejoin {
                    self.device_left(ieee.0);
                }
            }
            StackEvent::Zdp(z) => {
                self.heard(stack, z.src.0);
                self.on_reply(stack, z.src.0, Wait::Zdp(z.seq.0), Reply::Zdp(z));
            }
            StackEvent::ZdpTimeout { seq, dst, .. } => {
                self.on_reply(stack, dst.0, Wait::Zdp(seq.0), Reply::Timeout);
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
        let (i, new) = match self.registry.upsert(ieee, short) {
            Ok(r) => r,
            Err(_) => {
                self.counters.registry_full += 1;
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
            if c.is_mains_powered() && d.power_source == PowerSource::Unknown {
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
        let i = match self.registry.index_of_short(short) {
            Some(i) => i,
            None => {
                let ieee = ieee_of(stack, short)?;
                let (i, new) = self.registry.upsert(ieee, short).ok()?;
                if new {
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
        let was_enrolled = d.zone.is_some_and(|z| z.enrolled);
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
                Applied::State | Applied::Unchanged | Applied::Unmapped => {}
            }
        }
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        let caps = d.capabilities;
        if identity {
            d.dirty = true;
        }
        d.classify();
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
        }
        let after = d.state;
        if identity {
            self.schedule_persist();
        }
        self.emit_state_events(ieee, &before, &after);
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
                    let _ = stack
                        .zcl
                        .default_response(o, panweave_zcl::ZclStatus::UnsupportedClusterCommand);
                }
            }
        } else {
            let _ = stack
                .zcl
                .default_response(o, panweave_zcl::ZclStatus::UnsupportedClusterCommand);
        }
        stack.flush();
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
        self.expire(stack);
        if self.permit_until.is_some_and(|t| now.has_reached(t)) {
            self.permit_until = None;
            self.emit(Event::PermitJoinChanged { seconds: 0 });
        }
        if self.joins_until.is_some_and(|t| now.has_reached(t)) {
            self.joins_until = None;
            stack.config.trust_center_policy.allow_joins = false;
        }
        if stack.is_operating() {
            self.run_interviews(stack);
            self.run_syncs(stack);
        }
        self.flush_storage();
    }

    /// The earliest time [`Hub::poll`] has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut consider = |t: Instant| {
            if next.is_none_or(|n| t.as_millis() < n.as_millis()) {
                next = Some(t);
            }
        };
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

    fn storage_failed(&mut self) {
        self.counters.storage_errors = self.counters.storage_errors.saturating_add(1);
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
                    if let Some(d) = self.registry.at_mut(i) {
                        d.dirty = false;
                    }
                }
                Err(_) => return self.storage_failed(),
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
                Err(_) => return self.storage_failed(),
            }
        }
        while let Some(&ieee) = self.erase_queue.first() {
            if self.storage.erase(persist::device_key(ieee)).is_err() {
                return self.storage_failed();
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
        } else {
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
            Request::RemoveDevice { ieee, leave } => self
                .remove_device(stack, *ieee, *leave)
                .map(|()| Response::Done),
            Request::GetDiagnostics => Ok(Response::Diagnostics(self.diagnostics())),
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
        let command = match command {
            LightCommand::SetBrightness { percent: 0, .. } => LightCommand::TurnOff,
            LightCommand::SetBrightness { percent, .. } if percent > 100 => {
                return Err(ErrorCode::InvalidArgument);
            }
            c => c,
        };
        let d = self.command_target(ieee)?;
        let needed = match command {
            LightCommand::SetBrightness { .. } => cluster::LEVEL,
            _ => cluster::ON_OFF,
        };
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
                let (cluster_id, command, payload): (u16, u8, Vec<u8, 5>) = match l {
                    LightCommand::TurnOn => (cluster::ON_OFF, 0x01, Vec::new()),
                    LightCommand::TurnOff => (cluster::ON_OFF, 0x00, Vec::new()),
                    LightCommand::Toggle => (cluster::ON_OFF, 0x02, Vec::new()),
                    LightCommand::SetBrightness {
                        percent,
                        transition_ds,
                    } => {
                        let level = brightness_to_level(percent)?;
                        let t = transition_ds.to_le_bytes();
                        // Move to Level (with On/Off): level, transition
                        // time, OptionsMask, OptionsOverride (ZCL8
                        // §3.10.2.3.1).
                        let p = Vec::from_slice(&[level, t[0], t[1], 0, 0]).ok()?;
                        (cluster::LEVEL, 0x04, p)
                    }
                };
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
        }
    }

    fn finish_command_ok(&mut self, id: u16, stage: CommandStage, value: Option<AttributeData>) {
        let Some(at) = self.commands.iter().position(|c| c.id == id) else {
            return;
        };
        let c = self.commands.swap_remove(at);
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
            return;
        }
        if h.command == global::DEFAULT_RESPONSE {
            let Ok(dr) = DefaultResponse::decode_exact(&f.payload) else {
                return self.finish_command_failed(c.id, ErrorCode::ZclFailure, 0xff);
            };
            if !dr.status.is_success() {
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
