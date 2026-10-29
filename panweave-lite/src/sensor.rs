//! The IAS Zone sensor: its endpoint and the delivery of its zone status.
//!
//! # Endpoint
//!
//! [`fill_endpoint`] builds the IAS Zone device (DTL device 0x0402, Home
//! Automation profile) in the stack's own endpoint table: Identify, IAS
//! Zone and, as configured, Power Configuration (a battery server with
//! the attributes a battery sensor reports) and Poll Control. The stack
//! adds the Basic server with the `'static` manufacturer name and model
//! identifier. Only clusters that are instantiated are listed in the
//! simple descriptor.
//!
//! # Delivery of the zone status
//!
//! [`ZoneReporter`] turns sensor inputs into the `ZoneStatus` the IAS
//! Zone server publishes (a change makes the server send a Zone Status
//! Change Notification to its CIE) and follows each notification's APS
//! outcome ([`panweave_runtime::StackEvent::ZoneDelivery`]):
//!
//! * an undelivered notification of the current status is retried with
//!   exponential back-off, and at once when the device is back on the
//!   network or enrolled;
//! * an alarm or tamper condition that has not been delivered is kept in
//!   the published status even when the input already cleared: the CIE
//!   learns that the leak happened before it learns that it is over, and
//!   a failed transmission is never turned into a "cleared" report;
//! * [`ZoneReporter::delivery`] tells the application whether the CIE
//!   has the current status ([`Delivery::Confirmed`]) or not.

use panweave_types::DeviceId;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, ProfileId};
use panweave_zcl::Role;
use panweave_zcl::clusters::ias_zone::{self, EnrollMode, zone_status};
use panweave_zcl::clusters::{identify, poll_control, power_configuration};
use panweave_zdo::descriptor::SimpleDescriptor;

use crate::LiteEndpoint;

/// What the sensor detects.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SensorKind {
    /// Door / window contact: `ZoneType` contact switch (0x0015); Alarm1
    /// is "open".
    Contact,
    /// Water leak sensor: `ZoneType` water sensor (0x002a); Alarm1 is
    /// "wet".
    WaterLeak,
    /// Any other zone type (ZCL8 Table 8-5).
    Custom {
        /// `ZoneType`.
        zone_type: u16,
    },
}

impl SensorKind {
    /// The `ZoneType` attribute value.
    pub const fn zone_type(self) -> u16 {
        match self {
            SensorKind::Contact => ias_zone::zone_type::CONTACT_SWITCH,
            SensorKind::WaterLeak => ias_zone::zone_type::WATER_SENSOR,
            SensorKind::Custom { zone_type } => zone_type,
        }
    }
}

/// The battery as the Power Configuration server describes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BatteryConfig {
    /// `BatteryRatedVoltage` in 100 mV (30 for a CR2032).
    pub rated_voltage: u8,
    /// `BatteryVoltageMinThreshold` in 100 mV (0 = disabled).
    pub min_threshold: u8,
}

/// The sensor endpoint's configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SensorConfig {
    /// What it detects.
    pub kind: SensorKind,
    /// How it enrols with its CIE (ZCL8 §8.2.2.1.3).
    pub enroll: EnrollMode,
    /// Manufacturer code in Zone Enroll Requests.
    pub manufacturer_code: u16,
    /// A Power Configuration battery server.
    pub battery: Option<BatteryConfig>,
    /// A Poll Control server (check-ins and fast poll on request,
    /// ZCL8 §3.16).
    pub poll_control: bool,
    /// Supervision: the status is notified again at least this often
    /// (`SupervisionNotify` is set in `ZoneStatus`); `None` for none.
    pub supervision: Option<Duration>,
    /// First retry delay of an undelivered notification; it doubles up
    /// to [`SensorConfig::retry_max`].
    pub retry_first: Duration,
    /// Longest retry delay.
    pub retry_max: Duration,
}

impl SensorConfig {
    /// A sensor of `kind` with a CR2032-class battery, Poll Control, no
    /// supervision, Auto-Enroll-Request enrolment and retries from 2 s
    /// up to 5 min.
    pub const fn new(kind: SensorKind) -> Self {
        SensorConfig {
            kind,
            enroll: EnrollMode::AutoRequest,
            manufacturer_code: 0,
            battery: Some(BatteryConfig {
                rated_voltage: 30,
                min_threshold: 24,
            }),
            poll_control: true,
            supervision: None,
            retry_first: Duration::from_secs(2),
            retry_max: Duration::from_secs(300),
        }
    }
}

/// The IAS Zone device type (DTL §45).
pub const DEVICE_ID: DeviceId = DeviceId(0x0402);

/// Device version in the simple descriptor.
pub const DEVICE_VERSION: u8 = 0;

/// Fills the stack's empty endpoint `ep` with the sensor clusters (for
/// [`panweave_runtime::Stack::add_endpoint_with`]); returns its simple
/// descriptor, or `None` when a cluster does not fit (the stack then
/// removes the endpoint).
pub fn fill_endpoint(ep: &mut LiteEndpoint, cfg: &SensorConfig) -> Option<SimpleDescriptor> {
    let mut servers: heapless::Vec<ClusterId, { crate::ENDPOINT_CLUSTERS }> = heapless::Vec::new();
    // Basic: added by the stack.
    servers.push(ClusterId(0x0000)).ok()?;
    let c = ep.add_cluster(identify::DEF, Role::Server).ok()?;
    identify::fill_server(c).ok()?;
    servers.push(identify::ID).ok()?;
    if let Some(b) = cfg.battery {
        let c = ep
            .add_cluster(power_configuration::DEF, Role::Server)
            .ok()?;
        power_configuration::fill_battery_server_basic(c, b.rated_voltage, b.min_threshold).ok()?;
        servers.push(power_configuration::ID).ok()?;
    }
    let c = ep.add_cluster(ias_zone::DEF, Role::Server).ok()?;
    ias_zone::fill_server(
        c,
        cfg.kind.zone_type(),
        cfg.manufacturer_code,
        cfg.enroll,
        None,
    )
    .ok()?;
    servers.push(ias_zone::ID).ok()?;
    if cfg.poll_control {
        let c = ep
            .add_cluster(poll_control::SERVER_DEF, Role::Server)
            .ok()?;
        // Battery protection: check-ins at least every 30 s, long polls
        // of at least 1 s, fast polling for at most 2 minutes.
        poll_control::fill_server(c, 120, 4, 480).ok()?;
        servers.push(poll_control::ID).ok()?;
    }
    SimpleDescriptor::new(
        ep.endpoint,
        ProfileId::HOME_AUTOMATION,
        DEVICE_ID,
        DEVICE_VERSION,
        &servers,
        &[],
    )
}

/// The sensor inputs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Inputs {
    /// The detected condition (contact open, water present): Alarm1.
    pub alarm: bool,
    /// The enclosure is open: Tamper.
    pub tamper: bool,
    /// The battery is low: Battery.
    pub low_battery: bool,
}

/// `ZoneStatus` bits that report an event the CIE must learn about even
/// when it is over by the time it can be delivered.
pub const EVENT_BITS: u16 = zone_status::ALARM1 | zone_status::ALARM2 | zone_status::TAMPER;

/// Whether the CIE has the published status.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Delivery {
    /// The CIE acknowledged the current status.
    Confirmed,
    /// The current status has not been acknowledged yet.
    Pending {
        /// The status being delivered.
        status: u16,
        /// Retransmissions so far.
        attempts: u8,
    },
}

/// What the device must do with the IAS Zone server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Publish {
    /// Set `ZoneStatus` (a change is notified).
    Status(u16),
    /// Notify the current status again.
    Renotify,
}

/// The zone status delivery state machine (see the module
/// documentation). It does no I/O: the device applies what it returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ZoneReporter {
    /// The status the inputs call for.
    physical: u16,
    /// The status set in the IAS Zone server.
    published: u16,
    /// The last status the CIE acknowledged.
    confirmed: Option<u16>,
    /// A notification of `published` is in flight or waits for a CIE.
    awaiting: bool,
    /// Next retransmission.
    retry_at: Option<Instant>,
    /// Retransmit as soon as the device is reachable again.
    retry_when_reachable: bool,
    attempts: u8,
    /// Bits always set (Restore / Supervision notify).
    flags: u16,
    retry_first: Duration,
    retry_max: Duration,
    supervision: Option<Duration>,
    next_supervision: Option<Instant>,
}

impl ZoneReporter {
    /// A reporter for `cfg`; nothing is published yet.
    pub const fn new(cfg: &SensorConfig) -> Self {
        let mut flags = zone_status::RESTORE_NOTIFY;
        if cfg.supervision.is_some() {
            flags |= zone_status::SUPERVISION_NOTIFY;
        }
        ZoneReporter {
            physical: flags,
            published: 0,
            confirmed: None,
            awaiting: false,
            retry_at: None,
            retry_when_reachable: false,
            attempts: 0,
            flags,
            retry_first: cfg.retry_first,
            retry_max: cfg.retry_max,
            supervision: cfg.supervision,
            next_supervision: None,
        }
    }

    /// The `ZoneStatus` bits of `inputs`.
    pub const fn status_of(&self, inputs: Inputs) -> u16 {
        let mut s = self.flags;
        if inputs.alarm {
            s |= zone_status::ALARM1;
        }
        if inputs.tamper {
            s |= zone_status::TAMPER;
        }
        if inputs.low_battery {
            s |= zone_status::BATTERY;
        }
        s
    }

    /// The status to publish: the inputs, plus the events published but
    /// not acknowledged.
    fn target(&self) -> u16 {
        let delivered = self.confirmed.unwrap_or(0);
        self.physical | (self.published & EVENT_BITS & !delivered)
    }

    fn publish(&mut self, now: Instant) -> Option<Publish> {
        let target = self.target();
        if target == self.published && self.confirmed == Some(target) {
            return None;
        }
        if target == self.published && self.awaiting {
            return None;
        }
        self.published = target;
        self.awaiting = true;
        self.retry_at = None;
        self.retry_when_reachable = false;
        self.attempts = 0;
        self.schedule_supervision(now);
        Some(Publish::Status(target))
    }

    fn schedule_supervision(&mut self, now: Instant) {
        self.next_supervision = self.supervision.map(|d| now.saturating_add(d));
    }

    /// The first status after start-up (the device publishes the inputs
    /// it read).
    pub fn start(&mut self, inputs: Inputs, now: Instant) -> Option<Publish> {
        self.physical = self.status_of(inputs);
        self.publish(now)
    }

    /// New sensor inputs.
    pub fn set_inputs(&mut self, inputs: Inputs, now: Instant) -> Option<Publish> {
        self.physical = self.status_of(inputs);
        let target = self.target();
        if target == self.published {
            return None;
        }
        self.publish(now)
    }

    /// The APS outcome of a notification that carried `zone_status`.
    pub fn on_delivery(
        &mut self,
        zone_status: u16,
        delivered: bool,
        now: Instant,
    ) -> Option<Publish> {
        if delivered {
            self.confirmed = Some(zone_status);
            if zone_status == self.published {
                self.awaiting = false;
                self.retry_at = None;
                self.retry_when_reachable = false;
                self.attempts = 0;
            }
            // A held clear may go out now.
            let target = self.target();
            return (target != self.published)
                .then(|| self.publish(now))
                .flatten();
        }
        if zone_status != self.published {
            // An older status: the current one has its own outcome.
            return None;
        }
        self.awaiting = false;
        let shift = u32::from(self.attempts.min(16));
        let delay = self
            .retry_first
            .as_millis()
            .saturating_mul(1u64 << shift)
            .min(self.retry_max.as_millis());
        self.retry_at = Some(now.saturating_add(Duration::from_millis(delay)));
        None
    }

    /// The device can reach its CIE again (joined, rejoined, enrolled):
    /// an unacknowledged status is notified at once.
    pub fn on_reachable(&mut self, now: Instant) -> Option<Publish> {
        if self.confirmed == Some(self.published) && !self.retry_when_reachable {
            return None;
        }
        if self.published == 0 && self.confirmed.is_none() && !self.awaiting {
            return None;
        }
        self.retry_at = None;
        self.retry_when_reachable = false;
        self.awaiting = true;
        self.attempts = self.attempts.saturating_add(1);
        self.schedule_supervision(now);
        Some(Publish::Renotify)
    }

    /// Timers: a due retransmission (when `reachable`; otherwise it waits
    /// for [`ZoneReporter::on_reachable`]) or supervision notification.
    pub fn poll(&mut self, now: Instant, reachable: bool) -> Option<Publish> {
        if let Some(t) = self.retry_at
            && now.has_reached(t)
        {
            self.retry_at = None;
            if !reachable {
                self.retry_when_reachable = true;
                return None;
            }
            self.awaiting = true;
            self.attempts = self.attempts.saturating_add(1);
            self.schedule_supervision(now);
            return Some(Publish::Renotify);
        }
        if let Some(t) = self.next_supervision
            && now.has_reached(t)
        {
            self.schedule_supervision(now);
            if reachable && !self.awaiting {
                self.awaiting = true;
                return Some(Publish::Renotify);
            }
        }
        None
    }

    /// The next timer.
    pub fn deadline(&self) -> Option<Instant> {
        match (self.retry_at, self.next_supervision) {
            (Some(a), Some(b)) => Some(if a.as_millis() <= b.as_millis() { a } else { b }),
            (a, b) => a.or(b),
        }
    }

    /// Whether the CIE has the current status.
    pub fn delivery(&self) -> Delivery {
        if self.confirmed == Some(self.published) && !self.retry_when_reachable {
            Delivery::Confirmed
        } else {
            Delivery::Pending {
                status: self.published,
                attempts: self.attempts,
            }
        }
    }

    /// The status the inputs call for.
    pub const fn physical(&self) -> u16 {
        self.physical
    }

    /// The status published in the IAS Zone server.
    pub const fn published(&self) -> u16 {
        self.published
    }

    /// Whether a notification is in flight (or waits for a CIE).
    pub const fn awaiting(&self) -> bool {
        self.awaiting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALARM: u16 = zone_status::ALARM1;
    const RESTORE: u16 = zone_status::RESTORE_NOTIFY;

    fn t(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn wet(alarm: bool) -> Inputs {
        Inputs {
            alarm,
            ..Inputs::default()
        }
    }

    #[test]
    fn a_change_is_published_and_confirmed() {
        let mut r = ZoneReporter::new(&SensorConfig::new(SensorKind::WaterLeak));
        assert_eq!(r.start(wet(false), t(0)), Some(Publish::Status(RESTORE)));
        assert!(r.on_delivery(RESTORE, true, t(10)).is_none());
        assert_eq!(r.delivery(), Delivery::Confirmed);
        assert_eq!(
            r.set_inputs(wet(true), t(20)),
            Some(Publish::Status(RESTORE | ALARM))
        );
        assert!(matches!(r.delivery(), Delivery::Pending { .. }));
        assert!(r.on_delivery(RESTORE | ALARM, true, t(30)).is_none());
        assert_eq!(r.delivery(), Delivery::Confirmed);
        // The same inputs again: nothing to send.
        assert!(r.set_inputs(wet(true), t(40)).is_none());
    }

    #[test]
    fn an_undelivered_alarm_is_retried_with_back_off() {
        let mut r = ZoneReporter::new(&SensorConfig::new(SensorKind::WaterLeak));
        r.start(wet(false), t(0));
        r.on_delivery(RESTORE, true, t(1));
        r.set_inputs(wet(true), t(10));
        assert!(r.on_delivery(RESTORE | ALARM, false, t(100)).is_none());
        assert_eq!(r.deadline(), Some(t(2_100)));
        assert!(r.poll(t(2_000), true).is_none());
        assert_eq!(r.poll(t(2_100), true), Some(Publish::Renotify));
        r.on_delivery(RESTORE | ALARM, false, t(2_200));
        assert_eq!(r.deadline(), Some(t(6_200)), "doubled");
        // Unreachable when due: it waits for the network.
        assert!(r.poll(t(6_200), false).is_none());
        assert!(r.deadline().is_none());
        assert_eq!(r.on_reachable(t(9_000)), Some(Publish::Renotify));
        r.on_delivery(RESTORE | ALARM, true, t(9_100));
        assert_eq!(r.delivery(), Delivery::Confirmed);
    }

    #[test]
    fn a_clear_is_held_until_the_alarm_was_delivered() {
        let mut r = ZoneReporter::new(&SensorConfig::new(SensorKind::WaterLeak));
        r.start(wet(false), t(0));
        r.on_delivery(RESTORE, true, t(1));
        assert_eq!(
            r.set_inputs(wet(true), t(10)),
            Some(Publish::Status(RESTORE | ALARM))
        );
        // Dry again before the alarm got through: the alarm stays.
        assert!(r.set_inputs(wet(false), t(20)).is_none());
        assert_eq!(r.published(), RESTORE | ALARM);
        // The failure does not turn into "dry".
        assert!(r.on_delivery(RESTORE | ALARM, false, t(30)).is_none());
        assert_eq!(r.published(), RESTORE | ALARM);
        assert_eq!(r.poll(t(2_030), true), Some(Publish::Renotify));
        // Delivered: now the clear goes out.
        assert_eq!(
            r.on_delivery(RESTORE | ALARM, true, t(2_040)),
            Some(Publish::Status(RESTORE))
        );
        r.on_delivery(RESTORE, true, t(2_050));
        assert_eq!(r.delivery(), Delivery::Confirmed);
    }

    #[test]
    fn a_new_event_keeps_the_undelivered_one() {
        let mut r = ZoneReporter::new(&SensorConfig::new(SensorKind::Contact));
        r.start(wet(false), t(0));
        r.on_delivery(RESTORE, true, t(1));
        r.set_inputs(wet(true), t(10));
        // Closed, but the enclosure opened meanwhile: tamper is sent with
        // the undelivered alarm.
        let out = r.set_inputs(
            Inputs {
                alarm: false,
                tamper: true,
                low_battery: false,
            },
            t(20),
        );
        assert_eq!(
            out,
            Some(Publish::Status(RESTORE | ALARM | zone_status::TAMPER))
        );
        // A stale failure is ignored.
        assert!(r.on_delivery(RESTORE | ALARM, false, t(30)).is_none());
        assert!(r.deadline().is_none());
        assert_eq!(
            r.on_delivery(RESTORE | ALARM | zone_status::TAMPER, true, t(40)),
            Some(Publish::Status(RESTORE | zone_status::TAMPER))
        );
    }

    #[test]
    fn supervision_renotifies_periodically() {
        let mut cfg = SensorConfig::new(SensorKind::Contact);
        cfg.supervision = Some(Duration::from_secs(60));
        let mut r = ZoneReporter::new(&cfg);
        let s = zone_status::SUPERVISION_NOTIFY | RESTORE;
        assert_eq!(r.start(Inputs::default(), t(0)), Some(Publish::Status(s)));
        r.on_delivery(s, true, t(5));
        assert_eq!(r.deadline(), Some(t(60_000)));
        assert_eq!(r.poll(t(60_000), true), Some(Publish::Renotify));
        assert_eq!(r.deadline(), Some(t(120_000)));
    }
}
