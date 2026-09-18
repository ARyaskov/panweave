//! Power Profile cluster (ZCL8 §3.17): an appliance's forecast of its
//! energy phases, handed to a scheduler (the client) which answers with
//! prices and energy-phase schedules.
//!
//! The server keeps its profiles, their current state, schedule and
//! constraints in the cluster instance; the dispatcher answers Power
//! Profile Request, Power Profile State Request, Power Profile Schedule
//! Constraints Request and Energy Phases Schedule State Request from it,
//! applies received schedules (§3.17.5.5) and hands prices to the
//! application. The client side is codecs only: the application
//! interprets notifications and answers the server's requests.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x001a);

/// `TotalProfileNum` (uint8, ≥ 1).
pub const TOTAL_PROFILE_NUM: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(1), Access::RO);
/// `MultipleScheduling` (bool).
pub const MULTIPLE_SCHEDULING: AttributeDef = AttributeDef::new(0x0001, DataType::Bool, Access::RO);
/// `EnergyFormatting` (map8: bits 0–2 fraction digits, 3–6 integer
/// digits, 7 suppress leading zeros).
pub const ENERGY_FORMATTING: AttributeDef =
    AttributeDef::new(0x0002, DataType::Bitmap(1), Access::RO);
/// `EnergyRemote` (bool).
pub const ENERGY_REMOTE: AttributeDef = AttributeDef::new(0x0003, DataType::Bool, Access::RO);
/// `ScheduleMode` (map8, Table 3-137, writable, reportable).
pub const SCHEDULE_MODE: AttributeDef =
    AttributeDef::new(0x0004, DataType::Bitmap(1), Access::RW_REPORT);

/// `ScheduleMode` bits (Table 3-137).
pub mod schedule_mode {
    /// Cheapest.
    pub const CHEAPEST: u8 = 0x01;
    /// Greenest.
    pub const GREENEST: u8 = 0x02;
}

/// Power Profile Request (client → server).
pub const CMD_POWER_PROFILE_REQUEST: CommandId = CommandId(0x00);
/// Power Profile State Request.
pub const CMD_POWER_PROFILE_STATE_REQUEST: CommandId = CommandId(0x01);
/// Get Power Profile Price Response.
pub const CMD_GET_POWER_PROFILE_PRICE_RESPONSE: CommandId = CommandId(0x02);
/// Get Overall Schedule Price Response.
pub const CMD_GET_OVERALL_SCHEDULE_PRICE_RESPONSE: CommandId = CommandId(0x03);
/// Energy Phases Schedule Notification.
pub const CMD_ENERGY_PHASES_SCHEDULE_NOTIFICATION: CommandId = CommandId(0x04);
/// Energy Phases Schedule Response.
pub const CMD_ENERGY_PHASES_SCHEDULE_RESPONSE: CommandId = CommandId(0x05);
/// Power Profile Schedule Constraints Request.
pub const CMD_SCHEDULE_CONSTRAINTS_REQUEST: CommandId = CommandId(0x06);
/// Energy Phases Schedule State Request.
pub const CMD_ENERGY_PHASES_SCHEDULE_STATE_REQUEST: CommandId = CommandId(0x07);
/// Get Power Profile Price Extended Response.
pub const CMD_GET_POWER_PROFILE_PRICE_EXTENDED_RESPONSE: CommandId = CommandId(0x08);

/// Power Profile Notification (server → client).
pub const CMD_POWER_PROFILE_NOTIFICATION: CommandId = CommandId(0x00);
/// Power Profile Response.
pub const CMD_POWER_PROFILE_RESPONSE: CommandId = CommandId(0x01);
/// Power Profile State Response.
pub const CMD_POWER_PROFILE_STATE_RESPONSE: CommandId = CommandId(0x02);
/// Get Power Profile Price.
pub const CMD_GET_POWER_PROFILE_PRICE: CommandId = CommandId(0x03);
/// Power Profile State Notification.
pub const CMD_POWER_PROFILE_STATE_NOTIFICATION: CommandId = CommandId(0x04);
/// Get Overall Schedule Price.
pub const CMD_GET_OVERALL_SCHEDULE_PRICE: CommandId = CommandId(0x05);
/// Energy Phases Schedule Request.
pub const CMD_ENERGY_PHASES_SCHEDULE_REQUEST: CommandId = CommandId(0x06);
/// Energy Phases Schedule State Response.
pub const CMD_ENERGY_PHASES_SCHEDULE_STATE_RESPONSE: CommandId = CommandId(0x07);
/// Energy Phases Schedule State Notification.
pub const CMD_ENERGY_PHASES_SCHEDULE_STATE_NOTIFICATION: CommandId = CommandId(0x08);
/// Power Profile Schedule Constraints Notification.
pub const CMD_SCHEDULE_CONSTRAINTS_NOTIFICATION: CommandId = CommandId(0x09);
/// Power Profile Schedule Constraints Response.
pub const CMD_SCHEDULE_CONSTRAINTS_RESPONSE: CommandId = CommandId(0x0a);
/// Get Power Profile Price Extended.
pub const CMD_GET_POWER_PROFILE_PRICE_EXTENDED: CommandId = CommandId(0x0b);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_POWER_PROFILE_REQUEST,
        CMD_POWER_PROFILE_STATE_REQUEST,
        CMD_GET_POWER_PROFILE_PRICE_RESPONSE,
        CMD_GET_OVERALL_SCHEDULE_PRICE_RESPONSE,
        CMD_ENERGY_PHASES_SCHEDULE_NOTIFICATION,
        CMD_ENERGY_PHASES_SCHEDULE_RESPONSE,
        CMD_SCHEDULE_CONSTRAINTS_REQUEST,
        CMD_ENERGY_PHASES_SCHEDULE_STATE_REQUEST,
        CMD_GET_POWER_PROFILE_PRICE_EXTENDED_RESPONSE,
    ],
    generated: &[
        CMD_POWER_PROFILE_NOTIFICATION,
        CMD_POWER_PROFILE_RESPONSE,
        CMD_POWER_PROFILE_STATE_RESPONSE,
        CMD_GET_POWER_PROFILE_PRICE,
        CMD_POWER_PROFILE_STATE_NOTIFICATION,
        CMD_GET_OVERALL_SCHEDULE_PRICE,
        CMD_ENERGY_PHASES_SCHEDULE_REQUEST,
        CMD_ENERGY_PHASES_SCHEDULE_STATE_RESPONSE,
        CMD_ENERGY_PHASES_SCHEDULE_STATE_NOTIFICATION,
        CMD_SCHEDULE_CONSTRAINTS_NOTIFICATION,
        CMD_SCHEDULE_CONSTRAINTS_RESPONSE,
        CMD_GET_POWER_PROFILE_PRICE_EXTENDED,
    ],
};

/// Energy phases per profile: a Power Profile Notification of 7 phases
/// fills a ZCL frame (3 + 7 × 10 octets); longer profiles need the
/// Partition cluster (§3.17.3.1).
pub const MAX_PHASES: usize = 7;
/// Profiles a server keeps.
pub const MAX_PROFILES: usize = 4;
/// The invalid Energy Phase ID (a profile in IDLE state).
pub const NO_PHASE: u8 = 0xff;
/// `MaxActivationDelay` of the first energy phase.
pub const FIRST_PHASE_DELAY: u16 = 0xffff;
/// `StopBefore` when unspecified.
pub const NO_STOP: u16 = 0xffff;

/// `PowerProfileState` values (Table 3-140).
pub mod state {
    /// The profile's parameters are not defined.
    pub const IDLE: u8 = 0x00;
    /// Defined, without a scheduled start.
    pub const PROGRAMMED: u8 = 0x01;
    /// An energy phase is running.
    pub const RUNNING: u8 = 0x03;
    /// The current energy phase is paused.
    pub const PAUSED: u8 = 0x04;
    /// Between two energy phases, or programmed and not yet started.
    pub const WAITING_TO_START: u8 = 0x05;
    /// Paused while waiting to start.
    pub const WAITING_PAUSED: u8 = 0x06;
    /// The whole profile terminated.
    pub const ENDED: u8 = 0x07;
}

/// One energy phase of a Power Profile (Figure 3-72).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EnergyPhase {
    /// Energy Phase ID (1-based, contiguous).
    pub id: u8,
    /// Macro Phase ID (the displayed phase).
    pub macro_phase: u8,
    /// Expected duration, minutes.
    pub expected_duration: u16,
    /// Peak power, watts.
    pub peak_power: u16,
    /// Energy, per `EnergyFormatting`.
    pub energy: u16,
    /// Maximum activation delay after the previous phase, minutes: 0
    /// means no pause possible, [`FIRST_PHASE_DELAY`] for the first.
    pub max_activation_delay: u16,
}

impl EnergyPhase {
    fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.id)?;
        w.u8(self.macro_phase)?;
        w.u16_le(self.expected_duration)?;
        w.u16_le(self.peak_power)?;
        w.u16_le(self.energy)?;
        w.u16_le(self.max_activation_delay)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(EnergyPhase {
            id: r.u8()?,
            macro_phase: r.u8()?,
            expected_duration: r.u16_le()?,
            peak_power: r.u16_le()?,
            energy: r.u16_le()?,
            max_activation_delay: r.u16_le()?,
        })
    }
}

/// A Power Profile (Power Profile Notification / Response payload).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PowerProfile {
    /// `TotalProfileNum` of the sender.
    pub total_profiles: u8,
    /// Power Profile ID (1-based).
    pub id: u8,
    /// The energy phases.
    pub phases: Vec<EnergyPhase, MAX_PHASES>,
}

impl PowerProfile {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let total_profiles = r.u8()?;
        let id = r.u8()?;
        let n = r.u8()?;
        let mut phases = Vec::new();
        for _ in 0..n {
            phases
                .push(EnergyPhase::read(&mut r)?)
                .map_err(|_| CodecError::Unrepresentable { field: "phases" })?;
        }
        Ok(PowerProfile {
            total_profiles,
            id,
            phases,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(self.total_profiles)?;
        w.u8(self.id)?;
        w.u8(u8::try_from(self.phases.len()).unwrap_or(u8::MAX))?;
        for p in &self.phases {
            p.write(&mut w)?;
        }
        Ok(w.position())
    }
}

/// A Power Profile record (Figure 3-74).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProfileRecord {
    /// Power Profile ID.
    pub id: u8,
    /// Current Energy Phase ID ([`NO_PHASE`] when idle).
    pub energy_phase: u8,
    /// Remotely controllable (schedulable).
    pub remote_control: bool,
    /// `PowerProfileState` (Table 3-140).
    pub state: u8,
}

impl ProfileRecord {
    /// Whether the profile's parameters are defined.
    pub const fn is_idle(&self) -> bool {
        self.state == state::IDLE
    }
}

/// Encodes a Power Profile State Response / Notification payload.
pub fn encode_records(records: &[ProfileRecord], out: &mut [u8]) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    w.u8(u8::try_from(records.len())
        .map_err(|_| CodecError::Unrepresentable { field: "records" })?)?;
    for rec in records {
        w.u8(rec.id)?;
        w.u8(rec.energy_phase)?;
        w.u8(u8::from(rec.remote_control))?;
        w.u8(rec.state)?;
    }
    Ok(w.position())
}

/// Parses a Power Profile State Response / Notification payload.
pub fn parse_records(payload: &[u8]) -> Result<Vec<ProfileRecord, MAX_PROFILES>, CodecError> {
    let mut r = Reader::new(payload);
    let n = r.u8()?;
    let mut out = Vec::new();
    for _ in 0..n {
        let rec = ProfileRecord {
            id: r.u8()?,
            energy_phase: r.u8()?,
            remote_control: r.u8()? != 0,
            state: r.u8()?,
        };
        out.push(rec)
            .map_err(|_| CodecError::Unrepresentable { field: "records" })?;
    }
    Ok(out)
}

/// A price of a profile (Get Power Profile Price (Extended) Response,
/// Figure 3-69).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Price {
    /// Power Profile ID.
    pub id: u8,
    /// ISO 4217 currency.
    pub currency: u16,
    /// Price with `trailing_digit` decimals.
    pub price: u32,
    /// Decimal digits of `price`.
    pub trailing_digit: u8,
}

impl Price {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(Price {
            id: r.u8()?,
            currency: r.u16_le()?,
            price: r.u32_le()?,
            trailing_digit: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(self.id)?;
        w.u16_le(self.currency)?;
        w.u32_le(self.price)?;
        w.u8(self.trailing_digit)?;
        Ok(w.position())
    }
}

/// The overall price of the scheduled profiles (Get Overall Schedule
/// Price Response, Figure 3-70).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OverallPrice {
    /// ISO 4217 currency.
    pub currency: u16,
    /// Price with `trailing_digit` decimals.
    pub price: u32,
    /// Decimal digits of `price`.
    pub trailing_digit: u8,
}

impl OverallPrice {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(OverallPrice {
            currency: r.u16_le()?,
            price: r.u32_le()?,
            trailing_digit: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u16_le(self.currency)?;
        w.u32_le(self.price)?;
        w.u8(self.trailing_digit)?;
        Ok(w.position())
    }
}

/// A scheduled energy phase (Figure 3-71).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScheduledPhase {
    /// Energy Phase ID.
    pub energy_phase: u8,
    /// Minutes after now (first phase) or after the previous scheduled
    /// phase ended.
    pub scheduled_time: u16,
}

/// An energy-phase schedule of one profile (Energy Phases Schedule
/// Notification / Response / State Response / State Notification).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Schedule {
    /// Power Profile ID.
    pub id: u8,
    /// The scheduled phases (empty: nothing scheduled, Figure 3-77).
    pub phases: Vec<ScheduledPhase, MAX_PHASES>,
}

impl Schedule {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let id = r.u8()?;
        let n = r.u8()?;
        let mut phases = Vec::new();
        for _ in 0..n {
            let p = ScheduledPhase {
                energy_phase: r.u8()?,
                scheduled_time: r.u16_le()?,
            };
            phases
                .push(p)
                .map_err(|_| CodecError::Unrepresentable { field: "phases" })?;
        }
        Ok(Schedule { id, phases })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(self.id)?;
        w.u8(u8::try_from(self.phases.len()).unwrap_or(u8::MAX))?;
        for p in &self.phases {
            w.u8(p.energy_phase)?;
            w.u16_le(p.scheduled_time)?;
        }
        Ok(w.position())
    }
}

/// Schedule constraints of a profile (Figure 3-78).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Constraints {
    /// Power Profile ID.
    pub id: u8,
    /// Start after this many minutes (0: unspecified).
    pub start_after: u16,
    /// Stop before this many minutes ([`NO_STOP`]: unspecified).
    pub stop_before: u16,
}

impl Constraints {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(Constraints {
            id: r.u8()?,
            start_after: r.u16_le()?,
            stop_before: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(self.id)?;
        w.u16_le(self.start_after)?;
        w.u16_le(self.stop_before)?;
        Ok(w.position())
    }
}

/// Get Power Profile Price Extended (Figure 3-79).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PriceExtendedRequest {
    /// Power Profile ID.
    pub id: u8,
    /// Price the profile as scheduled (delays between phases) rather
    /// than with contiguous phases (Table 3-141 bit 1).
    pub as_scheduled: bool,
    /// The potential start, minutes from now (Table 3-141 bit 0).
    pub start_time: Option<u16>,
}

impl PriceExtendedRequest {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let options = r.u8()?;
        let id = r.u8()?;
        let start_time = if options & 0x01 != 0 {
            Some(r.u16_le()?)
        } else {
            None
        };
        Ok(PriceExtendedRequest {
            id,
            as_scheduled: options & 0x02 != 0,
            start_time,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(u8::from(self.start_time.is_some()) | (u8::from(self.as_scheduled) << 1))?;
        w.u8(self.id)?;
        if let Some(t) = self.start_time {
            w.u16_le(t)?;
        }
        Ok(w.position())
    }
}

/// A profile kept by the server.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Entry {
    /// The forecast.
    pub phases: Vec<EnergyPhase, MAX_PHASES>,
    /// Current phase and state.
    pub record: ProfileRecord,
    /// The accepted schedule.
    pub schedule: Vec<ScheduledPhase, MAX_PHASES>,
    /// The constraints.
    pub constraints: Constraints,
}

/// Server state (`ClusterState::PowerProfile`): the profiles, in Power
/// Profile ID order (1-based, contiguous).
#[derive(Clone, Debug, Default)]
pub struct Profiles {
    /// The profiles.
    pub entries: Vec<Entry, MAX_PROFILES>,
}

impl Profiles {
    /// The profile with `id`.
    pub fn get(&self, id: u8) -> Option<&Entry> {
        self.entries.get(usize::from(id).checked_sub(1)?)
    }

    /// The profile with `id`, mutably.
    pub fn get_mut(&mut self, id: u8) -> Option<&mut Entry> {
        self.entries.get_mut(usize::from(id).checked_sub(1)?)
    }

    /// Every profile's record.
    pub fn records(&self) -> Vec<ProfileRecord, MAX_PROFILES> {
        self.entries.iter().map(|e| e.record).collect()
    }

    /// The Power Profile of `id` as notified.
    pub fn profile(&self, id: u8) -> Option<PowerProfile> {
        let e = self.get(id)?;
        Some(PowerProfile {
            total_profiles: u8::try_from(self.entries.len()).unwrap_or(u8::MAX),
            id,
            phases: e.phases.clone(),
        })
    }

    /// The schedule of `id`.
    pub fn schedule(&self, id: u8) -> Option<Schedule> {
        let e = self.get(id)?;
        Some(Schedule {
            id,
            phases: e.schedule.clone(),
        })
    }

    /// Applies a schedule to `id` (§3.17.5.5.3): refused with
    /// `NOT_AUTHORIZED` when the profile is not remotely controllable
    /// or a scheduled phase allows no activation delay, `NOT_FOUND`
    /// for an unknown profile or phase. A profile that was PROGRAMMED
    /// (or idle) becomes ENERGY_PHASE_WAITING_TO_START. Returns whether
    /// the schedule changed.
    pub fn apply_schedule(&mut self, schedule: &Schedule) -> Result<bool, ZclStatus> {
        let e = self.get_mut(schedule.id).ok_or(ZclStatus::NotFound)?;
        if !e.record.remote_control {
            return Err(ZclStatus::NotAuthorized);
        }
        for s in &schedule.phases {
            let phase = e
                .phases
                .iter()
                .find(|p| p.id == s.energy_phase)
                .ok_or(ZclStatus::NotFound)?;
            if phase.max_activation_delay == 0 {
                return Err(ZclStatus::NotAuthorized);
            }
        }
        let changed = e.schedule != schedule.phases;
        e.schedule.clone_from(&schedule.phases);
        if matches!(e.record.state, state::IDLE | state::PROGRAMMED) && !schedule.phases.is_empty()
        {
            e.record.state = state::WAITING_TO_START;
        }
        Ok(changed)
    }
}

/// Builds a server with `profiles` empty profiles in PROGRAMMED state
/// (at most [`MAX_PROFILES`], at least 1), `MultipleScheduling` and
/// `EnergyRemote` as given, `EnergyFormatting` 0x01 (one decimal) and
/// `ScheduleMode` 0.
pub fn server<const A: usize>(
    profiles: u8,
    multiple_scheduling: bool,
    energy_remote: bool,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let n = usize::from(profiles).clamp(1, MAX_PROFILES);
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(
        TOTAL_PROFILE_NUM,
        &Value::Uint {
            width: 1,
            value: n as u64,
        },
    )?;
    c.add_attribute(MULTIPLE_SCHEDULING, &Value::Bool(Some(multiple_scheduling)))?;
    c.add_attribute(
        ENERGY_FORMATTING,
        &Value::Bits {
            width: 1,
            bits: 0x01,
        },
    )?;
    c.add_attribute(ENERGY_REMOTE, &Value::Bool(Some(energy_remote)))?;
    c.add_reported_attribute(
        SCHEDULE_MODE,
        &Value::Bits { width: 1, bits: 0 },
        crate::attribute::DefaultReporting {
            min: 0,
            max: 0,
            change: 0,
        },
    )?;
    let mut state = Profiles::default();
    for i in 1..=n {
        let id = u8::try_from(i).unwrap_or(u8::MAX);
        let _ = state.entries.push(Entry {
            phases: Vec::new(),
            record: ProfileRecord {
                id,
                energy_phase: NO_PHASE,
                remote_control: energy_remote,
                state: state::IDLE,
            },
            schedule: Vec::new(),
            constraints: Constraints {
                id,
                start_after: 0,
                stop_before: NO_STOP,
            },
        });
    }
    c.state = ClusterState::PowerProfile(state);
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// The server's profiles.
pub fn profiles<const A: usize>(c: &ClusterInstance<A>) -> Option<&Profiles> {
    match &c.state {
        ClusterState::PowerProfile(p) => Some(p),
        _ => None,
    }
}

/// The server's profiles, mutably.
pub fn profiles_mut<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut Profiles> {
    match &mut c.state {
        ClusterState::PowerProfile(p) => Some(p),
        _ => None,
    }
}

/// Result of a received command (§3.17.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Reply with a Power Profile Response for each of these profiles.
    Profiles(Vec<u8, MAX_PROFILES>),
    /// Reply with a Power Profile State Response of these records.
    Records(Vec<ProfileRecord, MAX_PROFILES>),
    /// The scheduler priced a profile (for the application).
    Price(Price),
    /// The scheduler priced a profile under the extended options.
    PriceExtended(Price),
    /// The scheduler priced the overall schedule.
    OverallPrice(OverallPrice),
    /// A schedule was applied to this profile; `changed` when the
    /// scheduling state changed (an Energy Phases Schedule State
    /// Notification follows).
    Scheduled {
        /// Power Profile ID.
        id: u8,
        /// The stored schedule differs from before.
        changed: bool,
    },
    /// Reply with a Power Profile Schedule Constraints Response.
    Constraints(Constraints),
    /// Reply with an Energy Phases Schedule State Response.
    ScheduleState(Schedule),
    /// Refused with this status.
    Default(ZclStatus),
}

/// Handles a received command.
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
) -> Outcome {
    let Some(p) = profiles_mut(c) else {
        return Outcome::Default(ZclStatus::Failure);
    };
    match cmd {
        CMD_POWER_PROFILE_REQUEST => match payload.first() {
            Some(0) => Outcome::Profiles(p.entries.iter().map(|e| e.record.id).collect()),
            Some(&id) if p.get(id).is_some() => {
                let mut ids = Vec::new();
                let _ = ids.push(id);
                Outcome::Profiles(ids)
            }
            Some(_) => Outcome::Default(ZclStatus::NotFound),
            None => Outcome::Default(ZclStatus::MalformedCommand),
        },
        CMD_POWER_PROFILE_STATE_REQUEST => Outcome::Records(p.records()),
        CMD_GET_POWER_PROFILE_PRICE_RESPONSE => match Price::parse(payload) {
            Ok(price) => Outcome::Price(price),
            Err(_) => Outcome::Default(ZclStatus::MalformedCommand),
        },
        CMD_GET_POWER_PROFILE_PRICE_EXTENDED_RESPONSE => match Price::parse(payload) {
            Ok(price) => Outcome::PriceExtended(price),
            Err(_) => Outcome::Default(ZclStatus::MalformedCommand),
        },
        CMD_GET_OVERALL_SCHEDULE_PRICE_RESPONSE => match OverallPrice::parse(payload) {
            Ok(price) => Outcome::OverallPrice(price),
            Err(_) => Outcome::Default(ZclStatus::MalformedCommand),
        },
        CMD_ENERGY_PHASES_SCHEDULE_NOTIFICATION | CMD_ENERGY_PHASES_SCHEDULE_RESPONSE => {
            let Ok(schedule) = Schedule::parse(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            match p.apply_schedule(&schedule) {
                Ok(changed) => Outcome::Scheduled {
                    id: schedule.id,
                    changed,
                },
                Err(status) => Outcome::Default(status),
            }
        }
        CMD_SCHEDULE_CONSTRAINTS_REQUEST => match payload.first().and_then(|id| p.get(*id)) {
            Some(e) => Outcome::Constraints(e.constraints),
            None => Outcome::Default(ZclStatus::NotFound),
        },
        CMD_ENERGY_PHASES_SCHEDULE_STATE_REQUEST => {
            match payload.first().and_then(|id| p.schedule(*id)) {
                Some(s) => Outcome::ScheduleState(s),
                None => Outcome::Default(ZclStatus::NotFound),
            }
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wash() -> PowerProfile {
        let mut phases = Vec::new();
        phases
            .push(EnergyPhase {
                id: 1,
                macro_phase: 1,
                expected_duration: 20,
                peak_power: 2000,
                energy: 660,
                max_activation_delay: FIRST_PHASE_DELAY,
            })
            .unwrap();
        phases
            .push(EnergyPhase {
                id: 2,
                macro_phase: 2,
                expected_duration: 40,
                peak_power: 500,
                energy: 330,
                max_activation_delay: 0,
            })
            .unwrap();
        phases
            .push(EnergyPhase {
                id: 3,
                macro_phase: 3,
                expected_duration: 15,
                peak_power: 1500,
                energy: 370,
                max_activation_delay: 120,
            })
            .unwrap();
        PowerProfile {
            total_profiles: 1,
            id: 1,
            phases,
        }
    }

    #[test]
    fn codecs_round_trip() {
        let p = wash();
        let mut buf = [0u8; 80];
        let n = p.encode(&mut buf).unwrap();
        assert_eq!(n, 3 + 3 * 10);
        assert_eq!(&buf[..5], &[1, 1, 3, 1, 1]);
        assert_eq!(PowerProfile::parse(&buf[..n]).unwrap(), p);
        let recs = [ProfileRecord {
            id: 1,
            energy_phase: 2,
            remote_control: true,
            state: state::RUNNING,
        }];
        let n = encode_records(&recs, &mut buf).unwrap();
        assert_eq!(&buf[..n], &[1, 1, 2, 1, 3]);
        assert_eq!(parse_records(&buf[..n]).unwrap().as_slice(), &recs);
        let price = Price {
            id: 1,
            currency: 978,
            price: 115,
            trailing_digit: 2,
        };
        let n = price.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[1, 0xd2, 0x03, 115, 0, 0, 0, 2]);
        assert_eq!(Price::parse(&buf[..n]).unwrap(), price);
        let overall = OverallPrice {
            currency: 978,
            price: 1234,
            trailing_digit: 2,
        };
        let n = overall.encode(&mut buf).unwrap();
        assert_eq!(OverallPrice::parse(&buf[..n]).unwrap(), overall);
        let mut phases = Vec::new();
        phases
            .push(ScheduledPhase {
                energy_phase: 1,
                scheduled_time: 90,
            })
            .unwrap();
        let s = Schedule { id: 1, phases };
        let n = s.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[1, 1, 1, 90, 0]);
        assert_eq!(Schedule::parse(&buf[..n]).unwrap(), s);
        let empty = Schedule::parse(&[1, 0]).unwrap();
        assert!(empty.phases.is_empty());
        let c = Constraints {
            id: 1,
            start_after: 30,
            stop_before: NO_STOP,
        };
        let n = c.encode(&mut buf).unwrap();
        assert_eq!(Constraints::parse(&buf[..n]).unwrap(), c);
        let req = PriceExtendedRequest {
            id: 1,
            as_scheduled: true,
            start_time: Some(45),
        };
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x03, 1, 45, 0]);
        assert_eq!(PriceExtendedRequest::parse(&buf[..n]).unwrap(), req);
        let req = PriceExtendedRequest {
            start_time: None,
            as_scheduled: false,
            ..req
        };
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x00, 1]);
        assert_eq!(PriceExtendedRequest::parse(&buf[..n]).unwrap(), req);
    }

    #[test]
    fn server_answers_requests_and_applies_schedules() {
        let mut c: ClusterInstance<8> = server(2, true, true).unwrap();
        assert_eq!(c.u8(TOTAL_PROFILE_NUM.id), Some(2));
        let p = profiles_mut(&mut c).unwrap();
        let e = p.get_mut(1).unwrap();
        e.phases.clone_from(&wash().phases);
        e.record.state = state::PROGRAMMED;
        assert_eq!(
            handle(&mut c, CMD_POWER_PROFILE_REQUEST, &[0]),
            Outcome::Profiles(Vec::from_slice(&[1, 2]).unwrap())
        );
        assert_eq!(
            handle(&mut c, CMD_POWER_PROFILE_REQUEST, &[2]),
            Outcome::Profiles(Vec::from_slice(&[2]).unwrap())
        );
        assert_eq!(
            handle(&mut c, CMD_POWER_PROFILE_REQUEST, &[3]),
            Outcome::Default(ZclStatus::NotFound)
        );
        let Outcome::Records(recs) = handle(&mut c, CMD_POWER_PROFILE_STATE_REQUEST, &[]) else {
            panic!("no records");
        };
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].state, state::PROGRAMMED);
        assert_eq!(recs[1].energy_phase, NO_PHASE);
        // A schedule of phase 2 (no activation delay) is refused; one of
        // phases 1 and 3 is applied and moves the profile to waiting.
        assert_eq!(
            handle(
                &mut c,
                CMD_ENERGY_PHASES_SCHEDULE_NOTIFICATION,
                &[1, 1, 2, 5, 0]
            ),
            Outcome::Default(ZclStatus::NotAuthorized)
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_ENERGY_PHASES_SCHEDULE_NOTIFICATION,
                &[1, 1, 9, 5, 0]
            ),
            Outcome::Default(ZclStatus::NotFound)
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_ENERGY_PHASES_SCHEDULE_RESPONSE,
                &[1, 2, 1, 30, 0, 3, 60, 0]
            ),
            Outcome::Scheduled {
                id: 1,
                changed: true
            }
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_ENERGY_PHASES_SCHEDULE_RESPONSE,
                &[1, 2, 1, 30, 0, 3, 60, 0]
            ),
            Outcome::Scheduled {
                id: 1,
                changed: false
            }
        );
        assert_eq!(
            profiles(&c).unwrap().get(1).unwrap().record.state,
            state::WAITING_TO_START
        );
        let Outcome::ScheduleState(s) =
            handle(&mut c, CMD_ENERGY_PHASES_SCHEDULE_STATE_REQUEST, &[1])
        else {
            panic!("no schedule");
        };
        assert_eq!(s.phases.len(), 2);
        assert_eq!(s.phases[1].scheduled_time, 60);
        let Outcome::ScheduleState(s) =
            handle(&mut c, CMD_ENERGY_PHASES_SCHEDULE_STATE_REQUEST, &[2])
        else {
            panic!("no schedule");
        };
        assert!(s.phases.is_empty());
        assert_eq!(
            handle(&mut c, CMD_SCHEDULE_CONSTRAINTS_REQUEST, &[1]),
            Outcome::Constraints(Constraints {
                id: 1,
                start_after: 0,
                stop_before: NO_STOP
            })
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_GET_POWER_PROFILE_PRICE_RESPONSE,
                &[1, 0xd2, 0x03, 115, 0, 0, 0, 2]
            ),
            Outcome::Price(Price {
                id: 1,
                currency: 978,
                price: 115,
                trailing_digit: 2
            })
        );
        // Remote control off: no schedule is accepted.
        profiles_mut(&mut c)
            .unwrap()
            .get_mut(2)
            .unwrap()
            .record
            .remote_control = false;
        assert_eq!(
            handle(&mut c, CMD_ENERGY_PHASES_SCHEDULE_NOTIFICATION, &[2, 0]),
            Outcome::Default(ZclStatus::NotAuthorized)
        );
    }
}
