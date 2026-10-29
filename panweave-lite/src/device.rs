//! [`LiteDevice`]: a battery IAS Zone sensor on the Panweave stack.
//!
//! The device composes the [`crate::LiteStack`], the BDB 3.1
//! commissioning machine and the [`ZoneReporter`]. The firmware feeds
//! it radio frames, transmission results, sensor inputs and the time,
//! drains its radio actions and events, and sleeps as
//! [`LiteDevice::sleep_plan`] allows:
//!
//! ```text
//! loop {
//!     while let Some(a) = dev.next_radio_action() { radio.perform(a) }
//!     while let Some(e) = dev.next_event() { app.handle(e) }
//!     match platform.sleep(&dev.sleep_plan(platform.now())) {
//!         Wake::Input => dev.set_inputs(board.read_inputs()),
//!         Wake::Radio => radio.deliver(&mut dev),
//!         Wake::Deadline => {}
//!     }
//!     dev.poll(platform.now());
//! }
//! ```
//!
//! # Persistence
//!
//! The stack persists the network state, keys and frame counter
//! reservations (`docs/storage-model.md`). The device adds one record,
//! the IAS enrolment ([`ias_zone::Enrollment`], `Kind::Application` id
//! [`ENROLLMENT_RECORD`]): the CIE configures a zone once, and a sensor
//! that forgot its CIE after a power loss could never report again. A
//! failed write is reported ([`LiteEvent::StorageFailed`]) and retried.

use heapless::Deque;
use panweave_bdb::{Bdb, Config as BdbConfig, Failure, Outcome};
use panweave_mac::radio::{RadioError, RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacServiceConfig};
use panweave_runtime::{EndpointError, Restored, StackConfig, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::LinkKeyKind;
use panweave_storage::{Key, Kind, Storage, StorageError};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    CryptoRng, ExtendedAddress, Key128, LogicalDeviceType, ManufacturerCode, ProfileId,
    ShortAddress,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::{ias_zone, power_configuration};

use crate::power::{self, Activity, SleepPlan};
use crate::sensor::{self, Delivery, Inputs, Publish, SensorConfig, ZoneReporter};
use crate::{LiteStack, SENSOR_ENDPOINT};

/// `Kind::Application` id of the IAS enrolment record (the IAS Zone
/// cluster identifier).
pub const ENROLLMENT_RECORD: u64 = 0x0500;

/// Delay between attempts to write the IAS enrolment record while the
/// storage fails.
pub const SAVE_RETRY: Duration = Duration::from_secs(5);

/// Events queued for the application.
pub const EVENT_CAPACITY: usize = 4;

/// The configuration of a Lite device.
#[derive(Clone, Debug)]
pub struct LiteConfig {
    /// IEEE address.
    pub ieee: ExtendedAddress,
    /// The sensor.
    pub sensor: SensorConfig,
    /// `ManufacturerName` (kept in program memory).
    pub manufacturer: &'static [u8],
    /// `ModelIdentifier` (kept in program memory).
    pub model: &'static [u8],
    /// Manufacturer code of the node descriptor.
    pub manufacturer_code: ManufacturerCode,
    /// Data poll interval while idle (BDB 3.1 §6.5: at most 7.5 s while
    /// the parent must buffer for the device; longer between reports
    /// once commissioned, as the Poll Control long poll interval).
    pub poll_interval: Duration,
    /// The pre-configured Trust Center link key: the install-code
    /// derived key of this device (`LinkKeyKind::Unique`), or the
    /// well-known key (default).
    pub link_key: (ExtendedAddress, Key128, LinkKeyKind),
    /// Commissioning parameters.
    pub bdb: BdbConfig,
    /// MAC parameters.
    pub mac: MacServiceConfig,
}

impl LiteConfig {
    /// A sensor of `kind` with the defaults of [`SensorConfig::new`], a
    /// 7.5 s poll interval and the well-known Trust Center link key.
    pub fn new(ieee: ExtendedAddress, kind: sensor::SensorKind) -> Self {
        LiteConfig {
            ieee,
            sensor: SensorConfig::new(kind),
            manufacturer: b"Panweave",
            model: b"Lite sensor",
            manufacturer_code: ManufacturerCode(0x0000),
            poll_interval: Duration::from_millis(7_500),
            link_key: (
                ExtendedAddress::BROADCAST,
                Key128::WELL_KNOWN_GLOBAL_TCLK,
                LinkKeyKind::Global,
            ),
            bdb: BdbConfig::DEFAULT_2_4GHZ,
            mac: MacServiceConfig::default(),
        }
    }

    /// Joins with an install-code derived link key (BDB 3.1 §10.1).
    #[must_use]
    pub fn install_code_key(mut self, key: Key128) -> Self {
        self.link_key = (ExtendedAddress::BROADCAST, key, LinkKeyKind::Unique);
        self
    }

    /// The stack configuration.
    pub fn stack_config(&self) -> StackConfig {
        let mut c = StackConfig::new(LogicalDeviceType::EndDevice, self.ieee);
        c.sleepy = true;
        c.poll_interval = self.poll_interval;
        c.manufacturer_name = self.manufacturer;
        c.model = self.model;
        c.manufacturer_code = self.manufacturer_code;
        c.preconfigured_link_key = self.link_key.clone();
        c.channels = self.bdb.primary_channels;
        c.scan_duration = self.bdb.scan_duration;
        // The Trust Center keep-alive is a router procedure.
        c.keep_alive = false;
        c
    }
}

/// An event for the application.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LiteEvent {
    /// A commissioning procedure finished.
    Commissioning(Outcome),
    /// Joined (or rejoined) and authorized.
    Joined {
        /// Network address.
        short: ShortAddress,
        /// A rejoin.
        rejoin: bool,
    },
    /// Left the network.
    Left {
        /// The device rejoins.
        rejoin: bool,
    },
    /// The CIE enrolled the zone.
    Enrolled {
        /// `ZoneID`.
        zone_id: u8,
    },
    /// The delivery state of the zone status changed.
    Delivery(Delivery),
    /// Identify started (`seconds` > 0) or stopped.
    Identify {
        /// Remaining seconds.
        seconds: u16,
    },
    /// A Reset to Factory Defaults command restored the attributes.
    AttributesReset,
    /// Writing the IAS enrolment record failed; it is retried every
    /// [`SAVE_RETRY`] (one event per run of failures).
    StorageFailed(StorageError),
}

/// A battery IAS Zone sensor (see the module documentation).
pub struct LiteDevice<C: BlockCipher, R: CryptoRng, S: Storage> {
    /// The protocol stack.
    pub stack: LiteStack<C, R, S>,
    /// The BDB 3.1 commissioning machine.
    pub bdb: Bdb,
    reporter: ZoneReporter,
    inputs: Inputs,
    /// The enrolment last written to storage.
    saved: Option<ias_zone::Enrollment>,
    /// The enrolment record must be written.
    save_due: bool,
    /// A failed write is retried at this instant (one attempt per
    /// [`SAVE_RETRY`], one [`LiteEvent::StorageFailed`] per episode).
    save_retry_at: Option<Instant>,
    delivery: Delivery,
    events: Deque<LiteEvent, EVENT_CAPACITY>,
    /// Events dropped because the application did not drain them.
    pub dropped_events: u32,
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> LiteDevice<C, R, S> {
    /// Builds the device: the stack with the sensor endpoint (built in
    /// place in the stack's table). `rng` must be cryptographically
    /// secure. The device is returned by value: on a microcontroller use
    /// [`LiteDevice::new_in`], which builds it in its `static` instead of
    /// in a temporary of its own size.
    pub fn new(config: &LiteConfig, rng: R, storage: S) -> Result<Self, EndpointError> {
        let mut d = Self::unstarted(config, rng, storage);
        d.start_up(config)?;
        Ok(d)
    }

    /// [`LiteDevice::new`] into `slot`.
    pub fn new_in<'a>(
        slot: &'a mut core::mem::MaybeUninit<Self>,
        config: &LiteConfig,
        rng: R,
        storage: S,
    ) -> Result<&'a mut Self, EndpointError> {
        let d = slot.write(Self::unstarted(config, rng, storage));
        d.start_up(config)?;
        Ok(d)
    }

    fn unstarted(config: &LiteConfig, rng: R, storage: S) -> Self {
        LiteDevice {
            stack: LiteStack::unstarted(config.stack_config(), config.mac, rng, storage),
            bdb: Bdb::new(config.bdb, false),
            reporter: ZoneReporter::new(&config.sensor),
            inputs: Inputs::default(),
            saved: None,
            save_due: false,
            save_retry_at: None,
            delivery: Delivery::Confirmed,
            events: Deque::new(),
            dropped_events: 0,
        }
    }

    fn start_up(&mut self, config: &LiteConfig) -> Result<(), EndpointError> {
        self.stack.start_up();
        let sensor = config.sensor;
        self.stack
            .add_endpoint_with(SENSOR_ENDPOINT, ProfileId::HOME_AUTOMATION, |ep| {
                sensor::fill_endpoint(ep, &sensor)
            })
    }

    /// BDB 3.1 §7.1 initialization after a reset or power-up: restores the
    /// network state and the IAS enrolment, publishes the sensor inputs
    /// read at start-up and, when the device was on a network, starts
    /// the rejoin procedure.
    pub fn initialize(&mut self, inputs: Inputs) -> Result<Restored, StorageError> {
        let restored = self.restore()?;
        self.inputs = inputs;
        let now = self.stack.now();
        let p = self.reporter.start(inputs, now);
        self.apply(p);
        if restored == Restored::OnNetwork {
            self.bdb.set_on_network(true);
            let _ = self.bdb.rejoin(&mut self.stack, false);
        }
        self.collect();
        Ok(restored)
    }

    /// The stack's persistent state and the IAS enrolment.
    #[inline(never)]
    fn restore(&mut self) -> Result<Restored, StorageError> {
        let restored = self.stack.restore()?;
        let mut buf = [0u8; ias_zone::Enrollment::LEN];
        if let Some(n) = self
            .stack
            .storage
            .load(Key::with_id(Kind::Application, ENROLLMENT_RECORD), &mut buf)?
            && let Some(e) = buf.get(..n).and_then(ias_zone::Enrollment::decode)
            && let Some(c) = self.zone_mut()
        {
            ias_zone::restore_enrollment(c, &e);
            self.saved = Some(e);
        }
        Ok(restored)
    }

    /// Network steering (BDB 3.1 §9.8): finds an open network and joins
    /// it (the commissioning button of a factory-new sensor).
    pub fn start_commissioning(&mut self) -> Result<(), Failure> {
        let r = self.bdb.steer(&mut self.stack);
        self.collect();
        r
    }

    /// Rejoin procedure (BDB 3.1 §10.1), e.g. after the parent was lost.
    pub fn rejoin(&mut self) -> Result<(), Failure> {
        let r = self.bdb.rejoin(&mut self.stack, false);
        self.collect();
        r
    }

    /// Leaves the network and erases the persisted network state and the
    /// IAS enrolment (BDB 3.1 §13.3); the NWK frame counter is kept.
    pub fn factory_reset(&mut self) -> Result<(), StorageError> {
        let _ = self.stack.leave(false);
        self.stack.flush();
        self.bdb.set_on_network(false);
        self.stack.erase_persisted()?;
        self.stack
            .storage
            .erase(Key::with_id(Kind::Application, ENROLLMENT_RECORD))?;
        self.saved = None;
        self.save_due = false;
        self.save_retry_at = None;
        self.collect();
        Ok(())
    }

    /// New sensor inputs (a GPIO or comparator edge): a change is
    /// notified to the CIE now.
    pub fn set_inputs(&mut self, inputs: Inputs) {
        self.inputs = inputs;
        let now = self.stack.now();
        let p = self.reporter.set_inputs(inputs, now);
        self.apply(p);
        self.collect();
    }

    /// The current sensor inputs.
    pub const fn inputs(&self) -> Inputs {
        self.inputs
    }

    /// Records a battery reading (`voltage` in 100 mV, `percentage` in
    /// half percent); the reporting configuration decides when it is
    /// sent.
    pub fn set_battery(&mut self, voltage: Option<u8>, percentage: Option<u8>) {
        if let Some(c) =
            self.stack
                .zcl
                .cluster_mut(SENSOR_ENDPOINT, power_configuration::ID, Role::Server)
        {
            let _ = power_configuration::set_battery(c, voltage, percentage);
        }
        self.stack.flush();
        self.collect();
    }

    /// Whether the CIE has the current zone status.
    pub const fn delivery(&self) -> Delivery {
        self.reporter_delivery()
    }

    const fn reporter_delivery(&self) -> Delivery {
        self.delivery
    }

    /// The zone status delivery state machine.
    pub const fn reporter(&self) -> &ZoneReporter {
        &self.reporter
    }

    fn zone_mut(
        &mut self,
    ) -> Option<
        &mut panweave_runtime::ProfileCluster<crate::SleepySensor, { crate::CLUSTER_ATTRIBUTES }>,
    > {
        self.stack
            .zcl
            .cluster_mut(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
    }

    /// Whether the device can reach its CIE now.
    fn reachable(&self) -> bool {
        self.stack.is_operating()
            && self
                .stack
                .zcl
                .cluster(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
                .and_then(ias_zone::state_of)
                .is_some_and(|s| s.cie.is_some())
    }

    // Not inlined: its frame would otherwise add to every caller's.
    #[inline(never)]
    fn apply(&mut self, p: Option<Publish>) {
        match p {
            Some(Publish::Status(s)) => {
                let _ = self.stack.zcl.set_zone_status(SENSOR_ENDPOINT, s);
            }
            Some(Publish::Renotify) => {
                let _ = self.stack.zcl.notify_zone_status(SENSOR_ENDPOINT);
            }
            None => return,
        }
        // The notification is built by the ZCL timers.
        let now = self.stack.now();
        self.stack.poll(now);
        self.note_delivery();
    }

    fn note_delivery(&mut self) {
        let d = self.reporter.delivery();
        if d != self.delivery {
            self.delivery = d;
            self.push(LiteEvent::Delivery(d));
        }
    }

    fn push(&mut self, e: LiteEvent) {
        if self.events.push_back(e).is_err() {
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
    }

    /// Drains the stack events into the commissioning machine, the
    /// reporter and the application queue.
    // Not inlined: its frame would otherwise add to every caller's.
    #[inline(never)]
    fn collect(&mut self) {
        while let Some(e) = self.stack.next_event() {
            if let Some(b) = LiteStack::<C, R, S>::bdb_event(&e)
                && let Some(o) = self.bdb.on_event(&mut self.stack, &b)
            {
                self.push(LiteEvent::Commissioning(o));
            }
            let now = self.stack.now();
            match e {
                StackEvent::Joined { short, rejoin, .. } => {
                    self.bdb.set_on_network(true);
                    self.push(LiteEvent::Joined { short, rejoin });
                    let p = self.reporter.on_reachable(now);
                    self.apply(p);
                }
                StackEvent::Left { rejoin } => {
                    self.bdb.set_on_network(false);
                    self.push(LiteEvent::Left { rejoin });
                }
                StackEvent::ZoneEnrolled { zone_id, .. } => {
                    self.save_due = true;
                    self.push(LiteEvent::Enrolled { zone_id });
                    let p = self.reporter.on_reachable(now);
                    self.apply(p);
                }
                StackEvent::ZoneDelivery {
                    command,
                    zone_status,
                    status,
                    ..
                } if command == ias_zone::CMD_ZONE_STATUS_CHANGE_NOTIFICATION => {
                    let p = self
                        .reporter
                        .on_delivery(zone_status, status.is_success(), now);
                    self.apply(p);
                    self.note_delivery();
                }
                StackEvent::Identify { seconds, .. } => {
                    self.push(LiteEvent::Identify { seconds });
                }
                StackEvent::FactoryReset => self.push(LiteEvent::AttributesReset),
                _ => {}
            }
        }
        self.save_enrollment();
    }

    /// Writes the IAS enrolment when the CIE changed it.
    // Not inlined: its frame would otherwise add to every caller's.
    #[inline(never)]
    fn save_enrollment(&mut self) {
        let current = self
            .stack
            .zcl
            .cluster(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
            .and_then(ias_zone::enrollment);
        if current == self.saved && !self.save_due {
            return;
        }
        let now = self.stack.now();
        if self.save_retry_at.is_some_and(|t| !now.has_reached(t)) {
            return;
        }
        let key = Key::with_id(Kind::Application, ENROLLMENT_RECORD);
        let r = match current {
            Some(e) => self.stack.storage.store(key, &e.encode()),
            None => self.stack.storage.erase(key),
        };
        match r {
            Ok(()) => {
                self.saved = current;
                self.save_due = false;
                self.save_retry_at = None;
            }
            Err(err) => {
                self.save_due = true;
                if self.save_retry_at.is_none() {
                    self.push(LiteEvent::StorageFailed(err));
                }
                self.save_retry_at = Some(now.saturating_add(SAVE_RETRY));
            }
        }
    }

    /// Next event.
    pub fn next_event(&mut self) -> Option<LiteEvent> {
        self.collect();
        self.events.pop_front()
    }

    /// A frame received by the radio.
    pub fn on_radio_frame(&mut self, bytes: &[u8], meta: RxMetadata) {
        self.stack.on_radio_frame(bytes, meta);
        self.collect();
    }

    /// Completion of the last transmission.
    pub fn on_tx_complete(&mut self, result: Result<TxResult, RadioError>) {
        self.stack.on_tx_complete(result);
        self.collect();
    }

    /// Result of an energy-detect request.
    pub fn on_energy_result(&mut self, level: u8) {
        self.stack.on_energy_result(level);
        self.collect();
    }

    /// Next radio action to perform.
    pub fn next_radio_action(&mut self) -> Option<MacAction> {
        self.stack.next_radio_action()
    }

    /// Advances time: the stack and commissioning timers and the
    /// reporter's retransmissions.
    pub fn poll(&mut self, now: Instant) {
        // BDB 3.1 §6.6: poll fast while a commissioning procedure runs.
        self.stack.set_fast_polling(self.bdb.is_busy());
        self.stack.poll(now);
        if let Some(o) = self.bdb.poll(&mut self.stack, now) {
            self.push(LiteEvent::Commissioning(o));
        }
        let reachable = self.reachable();
        let p = self.reporter.poll(now, reachable);
        self.apply(p);
        self.collect();
    }

    /// Earliest time [`LiteDevice::poll`] must run again.
    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.stack.next_deadline(),
            self.bdb.next_deadline(),
            self.reporter.deadline(),
            self.save_retry_at,
        ]
        .into_iter()
        .flatten()
        .min_by_key(|t| t.as_millis())
    }

    /// Whether the receiver must stay on.
    pub fn needs_receiver(&self) -> bool {
        self.stack.needs_receiver()
    }

    /// What the device is doing, for [`power::plan`].
    pub fn activity(&self, now: Instant) -> Activity {
        Activity {
            now,
            deadline: self.next_deadline(),
            radio_busy: self.stack.mac.has_output(),
            receiver: self.needs_receiver(),
            on_network: self.bdb.is_on_network(),
            commissioning: self.bdb.is_busy(),
        }
    }

    /// How the platform may sleep until the next input.
    pub fn sleep_plan(&self, now: Instant) -> SleepPlan {
        power::plan(&self.activity(now))
    }
}
