//! Demand Response and Load Control cluster (SE 1.4a Annex D.2): the
//! server commands Load Control Event / Cancel Load Control Event /
//! Cancel All Load Control Events, the client commands Report Event
//! Status / Get Scheduled Events, the client attributes of Table D-7 and
//! a client-side event scheduler applying the acceptance, supersede,
//! randomization and cancellation rules of D.2.2.3, D.2.3.2 and D.2.4.2.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::cluster::ClusterDef;
use panweave_zcl::types::DataType;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0701);

/// `UtilityEnrollmentGroup` (client).
pub const UTILITY_ENROLLMENT_GROUP: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(1), Access::RW);
/// `StartRandomizationMinutes` (client, default 0x1E).
pub const START_RANDOMIZATION_MINUTES: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(1), Access::RW);
/// `DurationRandomizationMinutes` (client, default 0).
pub const DURATION_RANDOMIZATION_MINUTES: AttributeDef =
    AttributeDef::new(0x0002, DataType::Uint(1), Access::RW);
/// `DeviceClassValue` (client).
pub const DEVICE_CLASS_VALUE: AttributeDef =
    AttributeDef::new(0x0003, DataType::Uint(2), Access::RW);

/// Default `StartRandomizationMinutes`.
pub const DEFAULT_START_RANDOMIZATION_MINUTES: u8 = 0x1E;
/// Largest randomization (minutes) either attribute accepts.
pub const MAX_RANDOMIZATION_MINUTES: u8 = 0x3C;

/// Server → client: Load Control Event.
pub const CMD_LOAD_CONTROL_EVENT: CommandId = CommandId(0x00);
/// Server → client: Cancel Load Control Event.
pub const CMD_CANCEL_LOAD_CONTROL_EVENT: CommandId = CommandId(0x01);
/// Server → client: Cancel All Load Control Events.
pub const CMD_CANCEL_ALL_LOAD_CONTROL_EVENTS: CommandId = CommandId(0x02);
/// Client → server: Report Event Status.
pub const CMD_REPORT_EVENT_STATUS: CommandId = CommandId(0x00);
/// Client → server: Get Scheduled Events.
pub const CMD_GET_SCHEDULED_EVENTS: CommandId = CommandId(0x01);

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_LOAD_CONTROL_EVENT,
        CMD_CANCEL_LOAD_CONTROL_EVENT,
        CMD_CANCEL_ALL_LOAD_CONTROL_EVENTS,
    ],
    generated: &[CMD_REPORT_EVENT_STATUS, CMD_GET_SCHEDULED_EVENTS],
};

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_REPORT_EVENT_STATUS, CMD_GET_SCHEDULED_EVENTS],
    generated: &[
        CMD_LOAD_CONTROL_EVENT,
        CMD_CANCEL_LOAD_CONTROL_EVENT,
        CMD_CANCEL_ALL_LOAD_CONTROL_EVENTS,
    ],
};

/// Device Class bits (Table D-2).
pub mod device_class {
    /// HVAC compressor or furnace.
    pub const HVAC: u16 = 1 << 0;
    /// Strip / baseboard heaters.
    pub const STRIP_HEATERS: u16 = 1 << 1;
    /// Water heater.
    pub const WATER_HEATER: u16 = 1 << 2;
    /// Pool pump / spa / jacuzzi.
    pub const POOL_PUMP: u16 = 1 << 3;
    /// Smart appliances.
    pub const SMART_APPLIANCES: u16 = 1 << 4;
    /// Irrigation pump.
    pub const IRRIGATION_PUMP: u16 = 1 << 5;
    /// Managed commercial and industrial loads.
    pub const MANAGED_CI_LOADS: u16 = 1 << 6;
    /// Simple miscellaneous (residential on/off) loads.
    pub const SIMPLE_MISC_LOADS: u16 = 1 << 7;
    /// Exterior lighting.
    pub const EXTERIOR_LIGHTING: u16 = 1 << 8;
    /// Interior lighting.
    pub const INTERIOR_LIGHTING: u16 = 1 << 9;
    /// Electric vehicle.
    pub const ELECTRIC_VEHICLE: u16 = 1 << 10;
    /// Generation systems.
    pub const GENERATION_SYSTEMS: u16 = 1 << 11;
}

/// Criticality levels (Table D-3).
pub mod criticality {
    /// Green.
    pub const GREEN: u8 = 1;
    /// Level 1 … Level 5 are 2 … 6.
    pub const LEVEL_1: u8 = 2;
    /// Level 5 (first mandatory level).
    pub const LEVEL_5: u8 = 6;
    /// Emergency.
    pub const EMERGENCY: u8 = 7;
    /// Planned outage.
    pub const PLANNED_OUTAGE: u8 = 8;
    /// Service disconnect.
    pub const SERVICE_DISCONNECT: u8 = 9;

    /// Whether participation is mandatory (levels 5 and above).
    pub const fn is_mandatory(level: u8) -> bool {
        level >= LEVEL_5 && level <= SERVICE_DISCONNECT
    }

    /// Whether the level is one the profile defines (1..=0x0F).
    pub const fn is_valid(level: u8) -> bool {
        level >= GREEN && level <= 0x0F
    }
}

/// Event Control bits (Table D-4).
pub mod event_control {
    /// Randomize the start time.
    pub const RANDOMIZE_START: u8 = 0x01;
    /// Randomize the duration.
    pub const RANDOMIZE_DURATION: u8 = 0x02;
}

/// Event Status values (Table D-9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EventStatus {
    /// Load Control Event command received.
    Received,
    /// Event started.
    Started,
    /// Event completed.
    Completed,
    /// User opted out.
    OptOut,
    /// User opted in.
    OptIn,
    /// The event was cancelled.
    Cancelled,
    /// The event was superseded.
    Superseded,
    /// Partially completed with user opt-out.
    PartiallyCompletedOptOut,
    /// Partially completed due to user opt-in.
    PartiallyCompletedOptIn,
    /// Completed without participation (previous opt-out).
    CompletedNoParticipation,
    /// Invalid opt-out of a mandatory event (Energy Management, D.12.2.5.1.2).
    InvalidOptOut,
    /// Event not found (Energy Management, D.12.2.5.1.2).
    EventNotFound,
    /// Rejected: invalid cancel command (default).
    RejectedInvalidCancel,
    /// Rejected: invalid cancel command (invalid effective time).
    RejectedInvalidEffectiveTime,
    /// Rejected: received after it had expired.
    RejectedExpired,
    /// Rejected: undefined event.
    RejectedUndefinedEvent,
    /// Rejected (0xFE).
    Rejected,
    /// Another value.
    Other(u8),
}

impl EventStatus {
    /// Raw value.
    pub const fn raw(self) -> u8 {
        match self {
            EventStatus::Received => 0x01,
            EventStatus::Started => 0x02,
            EventStatus::Completed => 0x03,
            EventStatus::OptOut => 0x04,
            EventStatus::OptIn => 0x05,
            EventStatus::Cancelled => 0x06,
            EventStatus::Superseded => 0x07,
            EventStatus::PartiallyCompletedOptOut => 0x08,
            EventStatus::PartiallyCompletedOptIn => 0x09,
            EventStatus::CompletedNoParticipation => 0x0A,
            EventStatus::InvalidOptOut => 0xF6,
            EventStatus::EventNotFound => 0xF7,
            EventStatus::RejectedInvalidCancel => 0xF8,
            EventStatus::RejectedInvalidEffectiveTime => 0xF9,
            EventStatus::RejectedExpired => 0xFB,
            EventStatus::RejectedUndefinedEvent => 0xFD,
            EventStatus::Rejected => 0xFE,
            EventStatus::Other(v) => v,
        }
    }

    /// From the raw value.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x01 => EventStatus::Received,
            0x02 => EventStatus::Started,
            0x03 => EventStatus::Completed,
            0x04 => EventStatus::OptOut,
            0x05 => EventStatus::OptIn,
            0x06 => EventStatus::Cancelled,
            0x07 => EventStatus::Superseded,
            0x08 => EventStatus::PartiallyCompletedOptOut,
            0x09 => EventStatus::PartiallyCompletedOptIn,
            0x0A => EventStatus::CompletedNoParticipation,
            0xF6 => EventStatus::InvalidOptOut,
            0xF7 => EventStatus::EventNotFound,
            0xF8 => EventStatus::RejectedInvalidCancel,
            0xF9 => EventStatus::RejectedInvalidEffectiveTime,
            0xFB => EventStatus::RejectedExpired,
            0xFD => EventStatus::RejectedUndefinedEvent,
            0xFE => EventStatus::Rejected,
            v => EventStatus::Other(v),
        }
    }
}

/// "Not used" markers of the optional fields (D.2.4.1.1).
pub const OFFSET_UNUSED: u8 = 0xFF;
/// Set point "not used".
pub const SET_POINT_UNUSED: i16 = i16::MIN;
/// Average Load Adjustment Percentage "not used" (0x80).
pub const LOAD_ADJUSTMENT_UNUSED: i8 = i8::MIN;
/// Duty Cycle "not used".
pub const DUTY_CYCLE_UNUSED: u8 = 0xFF;
/// The Utility Enrollment Group a server without the feature sends.
pub const ENROLLMENT_GROUP_UNSUPPORTED: u8 = 0x55;

/// Load Control Event payload (Figure D-2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LoadControlEvent {
    /// Issuer Event ID.
    pub issuer_event_id: u32,
    /// Device Class bitmap.
    pub device_class: u16,
    /// Utility Enrollment Group (0 addresses all groups).
    pub utility_enrollment_group: u8,
    /// Start time (UTC seconds; 0 = now).
    pub start_time: u32,
    /// Duration in minutes.
    pub duration_minutes: u16,
    /// Criticality level.
    pub criticality_level: u8,
    /// Cooling temperature offset in 0.1 °C (0xFF unused).
    pub cooling_temperature_offset: u8,
    /// Heating temperature offset in 0.1 °C (0xFF unused).
    pub heating_temperature_offset: u8,
    /// Cooling set point in 0.01 °C (0x8000 unused).
    pub cooling_temperature_set_point: i16,
    /// Heating set point in 0.01 °C (0x8000 unused).
    pub heating_temperature_set_point: i16,
    /// Average load adjustment percentage (-100..=100, 0x80 unused).
    pub average_load_adjustment_percentage: i8,
    /// Duty cycle percentage (0xFF unused).
    pub duty_cycle: u8,
    /// Event Control bits.
    pub event_control: u8,
}

impl LoadControlEvent {
    /// Encoded length.
    pub const LEN: usize = 23;

    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(LoadControlEvent {
            issuer_event_id: r.u32_le()?,
            device_class: r.u16_le()?,
            utility_enrollment_group: r.u8()?,
            start_time: r.u32_le()?,
            duration_minutes: r.u16_le()?,
            criticality_level: r.u8()?,
            cooling_temperature_offset: r.u8()?,
            heating_temperature_offset: r.u8()?,
            cooling_temperature_set_point: r.i16_le()?,
            heating_temperature_set_point: r.i16_le()?,
            average_load_adjustment_percentage: r.i8()?,
            duty_cycle: r.u8()?,
            event_control: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u16_le(self.device_class)?;
        w.u8(self.utility_enrollment_group)?;
        w.u32_le(self.start_time)?;
        w.u16_le(self.duration_minutes)?;
        w.u8(self.criticality_level)?;
        w.u8(self.cooling_temperature_offset)?;
        w.u8(self.heating_temperature_offset)?;
        w.i16_le(self.cooling_temperature_set_point)?;
        w.i16_le(self.heating_temperature_set_point)?;
        w.i8(self.average_load_adjustment_percentage)?;
        w.u8(self.duty_cycle)?;
        w.u8(self.event_control)
    }

    /// End time (start + duration), saturating.
    pub const fn end_time(&self) -> u32 {
        self.start_time
            .saturating_add((self.duration_minutes as u32).saturating_mul(60))
    }

    /// Whether the event addresses a client with `class` bits and
    /// enrollment `group` (D.2.2.3.1.1.1).
    pub const fn addresses(&self, class: u16, group: u8) -> bool {
        self.device_class & class != 0
            && (self.utility_enrollment_group == 0
                || group == 0
                || self.utility_enrollment_group == group)
    }
}

/// Cancel Load Control Event payload (Figure D-3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CancelLoadControlEvent {
    /// Issuer Event ID.
    pub issuer_event_id: u32,
    /// Device Class bitmap.
    pub device_class: u16,
    /// Utility Enrollment Group.
    pub utility_enrollment_group: u8,
    /// Cancel Control bit 0: end using the event's randomization.
    pub use_randomization: bool,
    /// Effective time (deprecated, 0 = now).
    pub effective_time: u32,
}

impl CancelLoadControlEvent {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CancelLoadControlEvent {
            issuer_event_id: r.u32_le()?,
            device_class: r.u16_le()?,
            utility_enrollment_group: r.u8()?,
            use_randomization: r.u8()? & 0x01 != 0,
            effective_time: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u16_le(self.device_class)?;
        w.u8(self.utility_enrollment_group)?;
        w.u8(u8::from(self.use_randomization))?;
        w.u32_le(self.effective_time)
    }
}

/// Signature Type of Report Event Status.
pub mod signature_type {
    /// No signature.
    pub const NONE: u8 = 0x00;
    /// ECDSA over the first ten fields with the MMO hash.
    pub const ECDSA: u8 = 0x01;
}

/// Length of the Signature field (Figure D-5).
pub const SIGNATURE_LEN: usize = 42;

/// Report Event Status payload (Figure D-5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReportEventStatus {
    /// Issuer Event ID.
    pub issuer_event_id: u32,
    /// Event status.
    pub event_status: EventStatus,
    /// Event status time (UTC seconds).
    pub event_status_time: u32,
    /// Criticality level applied.
    pub criticality_level_applied: u8,
    /// Cooling set point applied (0x8000 unused).
    pub cooling_temperature_set_point_applied: i16,
    /// Heating set point applied (0x8000 unused).
    pub heating_temperature_set_point_applied: i16,
    /// Average load adjustment percentage applied (0x80 unused).
    pub average_load_adjustment_percentage_applied: i8,
    /// Duty cycle applied (0xFF unused).
    pub duty_cycle_applied: u8,
    /// Event control.
    pub event_control: u8,
    /// Signature type.
    pub signature_type: u8,
    /// Signature (all 0xFF without a signature).
    pub signature: [u8; SIGNATURE_LEN],
}

impl ReportEventStatus {
    /// Encoded length.
    pub const LEN: usize = 18 + SIGNATURE_LEN;

    /// A report without signature and without the optional values.
    pub const fn new(issuer_event_id: u32, status: EventStatus, time: u32) -> Self {
        ReportEventStatus {
            issuer_event_id,
            event_status: status,
            event_status_time: time,
            criticality_level_applied: 0,
            cooling_temperature_set_point_applied: SET_POINT_UNUSED,
            heating_temperature_set_point_applied: SET_POINT_UNUSED,
            average_load_adjustment_percentage_applied: LOAD_ADJUSTMENT_UNUSED,
            duty_cycle_applied: DUTY_CYCLE_UNUSED,
            event_control: 0,
            signature_type: signature_type::NONE,
            signature: [0xFF; SIGNATURE_LEN],
        }
    }

    /// Parses the payload (a legacy report without the signature is
    /// accepted).
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let mut s = ReportEventStatus {
            issuer_event_id: r.u32_le()?,
            event_status: EventStatus::from_raw(r.u8()?),
            event_status_time: r.u32_le()?,
            criticality_level_applied: r.u8()?,
            cooling_temperature_set_point_applied: r.i16_le()?,
            heating_temperature_set_point_applied: r.i16_le()?,
            average_load_adjustment_percentage_applied: r.i8()?,
            duty_cycle_applied: r.u8()?,
            event_control: r.u8()?,
            signature_type: r.u8()?,
            signature: [0xFF; SIGNATURE_LEN],
        };
        if r.remaining() >= SIGNATURE_LEN {
            s.signature = r.array::<SIGNATURE_LEN>()?;
        }
        Ok(s)
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u8(self.event_status.raw())?;
        w.u32_le(self.event_status_time)?;
        w.u8(self.criticality_level_applied)?;
        w.i16_le(self.cooling_temperature_set_point_applied)?;
        w.i16_le(self.heating_temperature_set_point_applied)?;
        w.i8(self.average_load_adjustment_percentage_applied)?;
        w.u8(self.duty_cycle_applied)?;
        w.u8(self.event_control)?;
        w.u8(self.signature_type)?;
        w.bytes(&self.signature)
    }
}

/// Get Scheduled Events payload (Figure D-6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetScheduledEvents {
    /// Earliest end time (0 = the server's current time).
    pub earliest_end_time: u32,
    /// Maximum number of events (0 = no limit).
    pub number_of_events: u8,
    /// Minimum Issuer Event ID (0xFFFFFFFF = unused; absent in legacy
    /// requests).
    pub minimum_issuer_event_id: u32,
}

impl GetScheduledEvents {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetScheduledEvents {
            earliest_end_time: r.u32_le()?,
            number_of_events: r.u8()?,
            minimum_issuer_event_id: if r.remaining() >= 4 {
                r.u32_le()?
            } else {
                u32::MAX
            },
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.earliest_end_time)?;
        w.u8(self.number_of_events)?;
        w.u32_le(self.minimum_issuer_event_id)
    }
}

/// The phase of a scheduled event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Phase {
    /// Accepted, waiting for its (randomized) start.
    Scheduled,
    /// Running.
    Active,
    /// Running, but the user opted out.
    ActiveOptOut,
    /// Scheduled, and the user already opted out.
    ScheduledOptOut,
}

/// A scheduled event with its randomized times.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Scheduled {
    /// The event.
    pub event: LoadControlEvent,
    /// Effective start (UTC seconds).
    pub start: u32,
    /// Effective end (UTC seconds).
    pub end: u32,
    /// Phase.
    pub phase: Phase,
    /// Already reported as superseded: runs until `end` (the
    /// successor's effective start, Annex E rule 5b) and is then
    /// dropped without a completion report.
    pub superseded: bool,
}

/// Client-side event scheduler (D.2.3, D.2.4.2). `N` bounds the events
/// held. Times are UTC seconds; the caller supplies `now` and random
/// minutes for the randomization draws.
#[derive(Clone, Debug)]
pub struct Scheduler<const N: usize> {
    events: Vec<Scheduled, N>,
    /// `DeviceClassValue`.
    pub device_class: u16,
    /// `UtilityEnrollmentGroup`.
    pub enrollment_group: u8,
    /// `StartRandomizationMinutes`.
    pub start_randomization_minutes: u8,
    /// `DurationRandomizationMinutes`.
    pub duration_randomization_minutes: u8,
}

/// A status the client must report to the server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Report {
    /// Issuer Event ID.
    pub issuer_event_id: u32,
    /// Status.
    pub status: EventStatus,
    /// The event (for the applied values), when still known.
    pub event: Option<LoadControlEvent>,
}

impl<const N: usize> Scheduler<N> {
    /// A scheduler for a device of `device_class` bits.
    pub const fn new(device_class: u16) -> Self {
        Scheduler {
            events: Vec::new(),
            device_class,
            enrollment_group: 0,
            start_randomization_minutes: DEFAULT_START_RANDOMIZATION_MINUTES,
            duration_randomization_minutes: 0,
        }
    }

    /// Scheduled and active events.
    pub fn events(&self) -> &[Scheduled] {
        &self.events
    }

    /// The event with `id`.
    pub fn get(&self, issuer_event_id: u32) -> Option<&Scheduled> {
        self.events
            .iter()
            .find(|e| e.event.issuer_event_id == issuer_event_id)
    }

    /// Handles a Load Control Event: `None` when the event does not
    /// address this device (the caller drops it or answers a SUCCESS
    /// Default Response); otherwise the reports to send, in order.
    /// `random` supplies random minutes in `0..=max` for the
    /// randomization draws (D.2.3.2.2, D.2.3.2.3).
    pub fn on_event(
        &mut self,
        event: &LoadControlEvent,
        now: u32,
        mut random: impl FnMut(u8) -> u8,
    ) -> Option<Vec<Report, 4>> {
        if !event.addresses(self.device_class, self.enrollment_group) {
            return None;
        }
        let mut reports = Vec::new();
        let mut e = *event;
        if e.start_time == 0 {
            e.start_time = now;
        }
        // Scheduled end from the original start (Annex E rule 4
        // preserves it when the start lies in the past).
        let scheduled_end = e.end_time();
        if scheduled_end <= now || !criticality::is_valid(e.criticality_level) {
            let _ = reports.push(Report {
                issuer_event_id: e.issuer_event_id,
                status: if e.end_time() <= now {
                    EventStatus::RejectedExpired
                } else {
                    EventStatus::Rejected
                },
                event: Some(e),
            });
            return Some(reports);
        }
        // A repeat of a known event is acknowledged again, not
        // rescheduled (a superseded one is judged like a new event).
        if self.get(e.issuer_event_id).is_some_and(|k| !k.superseded) {
            let _ = reports.push(Report {
                issuer_event_id: e.issuer_event_id,
                status: EventStatus::Received,
                event: Some(e),
            });
            return Some(reports);
        }
        // An older event never supersedes a newer overlapping one.
        if self.events.iter().any(|s| {
            s.event.issuer_event_id > e.issuer_event_id
                && s.event.device_class & e.device_class != 0
                && overlaps(
                    s.event.start_time,
                    s.event.end_time(),
                    e.start_time,
                    scheduled_end,
                )
        }) {
            let _ = reports.push(Report {
                issuer_event_id: e.issuer_event_id,
                status: EventStatus::Rejected,
                event: Some(e),
            });
            return Some(reports);
        }
        // Rule 4: a start in the past runs from now.
        let scheduled_start = e.start_time.max(now);
        let mut start = scheduled_start;
        let mut end = scheduled_end;
        if e.event_control & event_control::RANDOMIZE_START != 0 {
            let r = u32::from(random(self.start_randomization_minutes)) * 60;
            start = start.saturating_add(r);
            end = end.saturating_add(r);
        }
        if e.event_control & event_control::RANDOMIZE_DURATION != 0 {
            end = end.saturating_add(u32::from(random(self.duration_randomization_minutes)) * 60);
        }
        // Newer overlapping events supersede (D.2.4 note; Annex E rule
        // 5). Overlap is judged on the scheduled periods so that
        // randomization never creates a conflict (rule 6b); the
        // previous event is superseded only when the new one covers
        // every device class of it this device has (rule 8).
        let mut i = 0;
        while i < self.events.len() {
            let s = &self.events[i];
            let common = s.event.device_class & self.device_class;
            let covered = common != 0 && common & !e.device_class == 0;
            let scheduled_overlap = overlaps(
                s.event.start_time,
                s.event.end_time(),
                scheduled_start,
                scheduled_end,
            );
            let successive =
                s.event.end_time() == e.start_time || s.event.end_time() == scheduled_start;
            if covered && scheduled_overlap && !s.superseded {
                let _ = reports.push(Report {
                    issuer_event_id: s.event.issuer_event_id,
                    status: EventStatus::Superseded,
                    event: Some(s.event),
                });
                if matches!(s.phase, Phase::Active | Phase::ActiveOptOut) && start > now {
                    // Rule 5b: keep the current state until the new
                    // event's effective start, then switch directly.
                    self.events[i].end = start;
                    self.events[i].superseded = true;
                    i += 1;
                } else {
                    self.events.remove(i);
                }
            } else if common != 0 && successive && s.event.start_time < e.start_time {
                // Rules 6b / 6d: the successor's effective start takes
                // precedence and no artificial gap is left.
                self.events[i].end = start;
                i += 1;
            } else {
                i += 1;
            }
        }
        let _ = reports.push(Report {
            issuer_event_id: e.issuer_event_id,
            status: EventStatus::Received,
            event: Some(e),
        });
        if self
            .events
            .push(Scheduled {
                event: e,
                start,
                end,
                phase: Phase::Scheduled,
                superseded: false,
            })
            .is_err()
        {
            reports.pop();
            let _ = reports.push(Report {
                issuer_event_id: e.issuer_event_id,
                status: EventStatus::Rejected,
                event: Some(e),
            });
        }
        Some(reports)
    }

    /// Handles a Cancel Load Control Event (D.2.2.3.2): the report to
    /// send.
    pub fn on_cancel(&mut self, cancel: &CancelLoadControlEvent, now: u32) -> Option<Report> {
        let idx = self
            .events
            .iter()
            .position(|s| s.event.issuer_event_id == cancel.issuer_event_id);
        let Some(idx) = idx else {
            return Some(Report {
                issuer_event_id: cancel.issuer_event_id,
                status: EventStatus::RejectedUndefinedEvent,
                event: None,
            });
        };
        let s = self.events[idx];
        if cancel.device_class & s.event.device_class == 0
            || (cancel.utility_enrollment_group != 0
                && s.event.utility_enrollment_group != 0
                && cancel.utility_enrollment_group != s.event.utility_enrollment_group)
        {
            return Some(Report {
                issuer_event_id: cancel.issuer_event_id,
                status: EventStatus::RejectedInvalidCancel,
                event: Some(s.event),
            });
        }
        // Effective Time is deprecated: cancellation is immediate, with
        // the event's randomization when asked for (D.2.2.3.2.1.1).
        let delay = if cancel.use_randomization {
            if s.event.event_control & event_control::RANDOMIZE_DURATION != 0 {
                s.end.saturating_sub(s.event.end_time())
            } else if s.event.event_control & event_control::RANDOMIZE_START != 0 {
                s.start.saturating_sub(s.event.start_time)
            } else {
                0
            }
        } else {
            0
        };
        let at = now.saturating_add(delay);
        if delay > 0 && matches!(s.phase, Phase::Active | Phase::ActiveOptOut) {
            // Ends early at the randomized moment; `poll` reports it.
            self.events[idx].end = at.min(s.end);
            return None;
        }
        self.events.remove(idx);
        Some(Report {
            issuer_event_id: s.event.issuer_event_id,
            status: EventStatus::Cancelled,
            event: Some(s.event),
        })
    }

    /// Handles a Cancel All Load Control Events (D.2.2.3.3).
    pub fn on_cancel_all(&mut self, use_randomization: bool, now: u32) -> Vec<Report, N> {
        let ids: Vec<(u32, u16, u8), N> = self
            .events
            .iter()
            .map(|s| {
                (
                    s.event.issuer_event_id,
                    s.event.device_class,
                    s.event.utility_enrollment_group,
                )
            })
            .collect();
        let mut out = Vec::new();
        for (id, class, group) in ids {
            let c = CancelLoadControlEvent {
                issuer_event_id: id,
                device_class: class,
                utility_enrollment_group: group,
                use_randomization,
                effective_time: 0,
            };
            if let Some(r) = self.on_cancel(&c, now) {
                let _ = out.push(r);
            }
        }
        out
    }

    /// The user opts out of (or back into) an event (D.2.4.2.4).
    pub fn set_opt_out(
        &mut self,
        issuer_event_id: u32,
        opt_out: bool,
        _now: u32,
    ) -> Option<Report> {
        let s = self
            .events
            .iter_mut()
            .find(|s| s.event.issuer_event_id == issuer_event_id)?;
        s.phase = match (s.phase, opt_out) {
            (Phase::Scheduled | Phase::ScheduledOptOut, true) => Phase::ScheduledOptOut,
            (Phase::Scheduled | Phase::ScheduledOptOut, false) => Phase::Scheduled,
            (Phase::Active | Phase::ActiveOptOut, true) => Phase::ActiveOptOut,
            (Phase::Active | Phase::ActiveOptOut, false) => Phase::Active,
        };
        Some(Report {
            issuer_event_id,
            status: if opt_out {
                EventStatus::OptOut
            } else {
                EventStatus::OptIn
            },
            event: Some(s.event),
        })
    }

    /// Advances time: starts and completes events, returning the
    /// reports to send.
    pub fn poll(&mut self, now: u32) -> Vec<Report, N> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.events.len() {
            let s = self.events[i];
            if now >= s.end {
                if s.superseded {
                    self.events.remove(i);
                    continue;
                }
                let opted_out = matches!(s.phase, Phase::ActiveOptOut | Phase::ScheduledOptOut);
                let _ = out.push(Report {
                    issuer_event_id: s.event.issuer_event_id,
                    status: if opted_out {
                        EventStatus::CompletedNoParticipation
                    } else {
                        EventStatus::Completed
                    },
                    event: Some(s.event),
                });
                self.events.remove(i);
                continue;
            }
            if now >= s.start && matches!(s.phase, Phase::Scheduled | Phase::ScheduledOptOut) {
                let opted_out = s.phase == Phase::ScheduledOptOut;
                self.events[i].phase = if opted_out {
                    Phase::ActiveOptOut
                } else {
                    Phase::Active
                };
                let _ = out.push(Report {
                    issuer_event_id: s.event.issuer_event_id,
                    status: EventStatus::Started,
                    event: Some(s.event),
                });
            }
            i += 1;
        }
        out
    }

    /// The next time [`Scheduler::poll`] changes something.
    pub fn next_deadline(&self) -> Option<u32> {
        self.events
            .iter()
            .map(|s| match s.phase {
                Phase::Scheduled | Phase::ScheduledOptOut => s.start.min(s.end),
                Phase::Active | Phase::ActiveOptOut => s.end,
            })
            .min()
    }

    /// Whether an event is running and the device should be shedding
    /// (the highest-criticality active event that was not opted out).
    pub fn active(&self) -> Option<&Scheduled> {
        self.events
            .iter()
            .filter(|s| s.phase == Phase::Active)
            .max_by_key(|s| s.event.criticality_level)
    }
}

const fn overlaps(a_start: u32, a_end: u32, b_start: u32, b_end: u32) -> bool {
    a_start < b_end && b_start < a_end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u32, start: u32, minutes: u16, class: u16, control: u8) -> LoadControlEvent {
        LoadControlEvent {
            issuer_event_id: id,
            device_class: class,
            utility_enrollment_group: 0,
            start_time: start,
            duration_minutes: minutes,
            criticality_level: criticality::LEVEL_1,
            cooling_temperature_offset: OFFSET_UNUSED,
            heating_temperature_offset: OFFSET_UNUSED,
            cooling_temperature_set_point: SET_POINT_UNUSED,
            heating_temperature_set_point: SET_POINT_UNUSED,
            average_load_adjustment_percentage: LOAD_ADJUSTMENT_UNUSED,
            duty_cycle: DUTY_CYCLE_UNUSED,
            event_control: control,
        }
    }

    #[test]
    fn codecs_round_trip() {
        let e = event(
            0x1234_5678,
            1000,
            30,
            device_class::HVAC | device_class::WATER_HEATER,
            1,
        );
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        e.encode(&mut w).unwrap();
        assert_eq!(w.position(), LoadControlEvent::LEN);
        assert_eq!(
            LoadControlEvent::parse(&buf[..LoadControlEvent::LEN]).unwrap(),
            e
        );
        assert_eq!(&buf[..4], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(buf[14], 0xFF);
        assert_eq!(&buf[16..18], &[0x00, 0x80]);
        assert_eq!(buf[20], 0x80);
        let r = ReportEventStatus::new(7, EventStatus::Started, 5000);
        let mut w = Writer::new(&mut buf);
        r.encode(&mut w).unwrap();
        assert_eq!(w.position(), ReportEventStatus::LEN);
        assert_eq!(
            ReportEventStatus::parse(&buf[..ReportEventStatus::LEN]).unwrap(),
            r
        );
        // Legacy report without the signature.
        assert_eq!(ReportEventStatus::parse(&buf[..18]).unwrap(), r);
        let g = GetScheduledEvents {
            earliest_end_time: 0,
            number_of_events: 3,
            minimum_issuer_event_id: 9,
        };
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        assert_eq!(GetScheduledEvents::parse(&buf[..9]).unwrap(), g);
        assert_eq!(
            GetScheduledEvents::parse(&buf[..5])
                .unwrap()
                .minimum_issuer_event_id,
            u32::MAX
        );
        let c = CancelLoadControlEvent {
            issuer_event_id: 1,
            device_class: 0xFFFF,
            utility_enrollment_group: 0,
            use_randomization: true,
            effective_time: 0,
        };
        let mut w = Writer::new(&mut buf);
        c.encode(&mut w).unwrap();
        assert_eq!(CancelLoadControlEvent::parse(&buf[..12]).unwrap(), c);
    }

    #[test]
    fn annex_e_overlap_rules() {
        // Rule 4: a start in the past runs from now, the end is kept.
        let mut s: Scheduler<4> = Scheduler::new(device_class::HVAC | device_class::POOL_PUMP);
        let r = s
            .on_event(&event(1, 1000, 60, device_class::HVAC, 0), 1600, |_| 0)
            .unwrap();
        assert_eq!(r[0].status, EventStatus::Received);
        let e1 = s.get(1).unwrap();
        assert_eq!((e1.start, e1.end), (1600, 1000 + 3600));
        assert_eq!(s.poll(1600)[0].status, EventStatus::Started);

        // Rule 5b: an overlapping event starting later supersedes the
        // running one now, but the device keeps its state until the
        // successor's effective start and then switches directly.
        let r = s
            .on_event(&event(2, 3000, 60, device_class::HVAC, 0), 2000, |_| 0)
            .unwrap();
        assert_eq!(r[0].status, EventStatus::Superseded);
        assert_eq!(r[0].issuer_event_id, 1);
        assert_eq!(r[1].status, EventStatus::Received);
        let e1 = s.get(1).unwrap();
        assert!(e1.superseded && e1.end == 3000);
        assert!(s.active().is_some_and(|a| a.event.issuer_event_id == 1));
        assert_eq!(s.next_deadline(), Some(3000));
        let reports = s.poll(3000);
        // Event 1 leaves silently, event 2 starts: one report only.
        assert_eq!(reports.len(), 1);
        assert_eq!(
            (reports[0].issuer_event_id, reports[0].status),
            (2, EventStatus::Started)
        );
        assert!(s.get(1).is_none());

        // Rule 8: an event for a subset of the device classes does not
        // supersede an event this device also follows for another class.
        let r = s
            .on_event(
                &event(3, 4000, 60, device_class::HVAC | device_class::POOL_PUMP, 0),
                3500,
                |_| 0,
            )
            .unwrap();
        assert_eq!(r[0].status, EventStatus::Superseded);
        assert_eq!(r[0].issuer_event_id, 2);
        let r = s
            .on_event(&event(4, 4000, 30, device_class::POOL_PUMP, 0), 3500, |_| 0)
            .unwrap();
        assert_eq!(r.len(), 1, "event 3 stays for the HVAC class: {r:?}");
        assert_eq!(r[0].status, EventStatus::Received);
        assert!(s.get(3).is_some() && s.get(4).is_some());

        // Rules 6b / 6d: successive events with randomization are not
        // superseded; the successor's effective start wins and no gap
        // is left.
        let mut s: Scheduler<4> = Scheduler::new(device_class::HVAC);
        s.start_randomization_minutes = 10;
        s.duration_randomization_minutes = 10;
        s.on_event(
            &event(
                10,
                10_000,
                60,
                device_class::HVAC,
                event_control::RANDOMIZE_DURATION,
            ),
            9000,
            |_| 8,
        )
        .unwrap();
        assert_eq!(s.get(10).unwrap().end, 13_600 + 480);
        let r = s
            .on_event(
                &event(
                    11,
                    13_600,
                    60,
                    device_class::HVAC,
                    event_control::RANDOMIZE_START,
                ),
                9000,
                |_| 2,
            )
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].status, EventStatus::Received);
        // Event 10 now ends exactly when event 11 effectively starts.
        assert_eq!(s.get(10).unwrap().end, 13_600 + 120);
        assert_eq!(s.get(11).unwrap().start, 13_600 + 120);
    }

    #[test]
    fn scheduler_accepts_supersedes_and_reports() {
        let mut s: Scheduler<4> = Scheduler::new(device_class::HVAC);
        s.start_randomization_minutes = 5;
        // Not addressed: water heater only.
        assert!(
            s.on_event(
                &event(1, 1000, 10, device_class::WATER_HEATER, 0),
                500,
                |_| 0
            )
            .is_none()
        );
        // Expired.
        let r = s
            .on_event(&event(2, 100, 1, device_class::HVAC, 0), 500, |_| 0)
            .unwrap();
        assert_eq!(r[0].status, EventStatus::RejectedExpired);
        // Accepted with a 3-minute start randomization carried to the end.
        let r = s
            .on_event(
                &event(
                    3,
                    1000,
                    10,
                    device_class::HVAC,
                    event_control::RANDOMIZE_START,
                ),
                500,
                |max| {
                    assert_eq!(max, 5);
                    3
                },
            )
            .unwrap();
        assert_eq!(
            r.as_slice(),
            &[Report {
                issuer_event_id: 3,
                status: EventStatus::Received,
                event: Some(event(3, 1000, 10, device_class::HVAC, 1))
            }]
        );
        let e = s.get(3).unwrap();
        assert_eq!((e.start, e.end), (1180, 1780));
        assert_eq!(s.next_deadline(), Some(1180));
        assert!(s.poll(1179).is_empty());
        let r = s.poll(1180);
        assert_eq!(r[0].status, EventStatus::Started);
        assert!(s.active().is_some());
        // A newer overlapping event supersedes it; an older one is rejected.
        let r = s
            .on_event(&event(4, 1500, 10, device_class::HVAC, 0), 1200, |_| 0)
            .unwrap();
        assert_eq!(r[0].status, EventStatus::Superseded);
        assert_eq!(r[0].issuer_event_id, 3);
        assert_eq!(r[1].status, EventStatus::Received);
        let r = s
            .on_event(&event(3, 1500, 10, device_class::HVAC, 0), 1200, |_| 0)
            .unwrap();
        assert_eq!(r[0].status, EventStatus::Rejected);
        // Opt-out before the start: it starts, then completes without
        // participation.
        assert_eq!(
            s.set_opt_out(4, true, 1300).unwrap().status,
            EventStatus::OptOut
        );
        assert_eq!(s.poll(1500)[0].status, EventStatus::Started);
        assert!(s.active().is_none());
        let r = s.poll(2100);
        assert_eq!(r[0].status, EventStatus::CompletedNoParticipation);
        assert!(s.events().is_empty());
        // Cancel: unknown, wrong class, then immediate.
        let _ = s.on_event(&event(5, 3000, 10, device_class::HVAC, 0), 2200, |_| 0);
        let c = CancelLoadControlEvent {
            issuer_event_id: 6,
            device_class: 0xFFFF,
            utility_enrollment_group: 0,
            use_randomization: false,
            effective_time: 0,
        };
        assert_eq!(
            s.on_cancel(&c, 2300).unwrap().status,
            EventStatus::RejectedUndefinedEvent
        );
        let c = CancelLoadControlEvent {
            issuer_event_id: 5,
            device_class: device_class::POOL_PUMP,
            ..c
        };
        assert_eq!(
            s.on_cancel(&c, 2300).unwrap().status,
            EventStatus::RejectedInvalidCancel
        );
        let c = CancelLoadControlEvent {
            device_class: device_class::HVAC,
            ..c
        };
        assert_eq!(
            s.on_cancel(&c, 2300).unwrap().status,
            EventStatus::Cancelled
        );
        assert!(s.events().is_empty());
        // Cancel all with randomization on an active randomized event
        // ends it early at the randomized moment.
        let _ = s.on_event(
            &event(
                7,
                4000,
                60,
                device_class::HVAC,
                event_control::RANDOMIZE_START,
            ),
            3900,
            |_| 2,
        );
        let _ = s.poll(4120);
        assert!(s.on_cancel_all(true, 4200).is_empty());
        assert_eq!(s.get(7).unwrap().end, 4320);
        assert_eq!(s.poll(4320)[0].status, EventStatus::Completed);
    }
}
