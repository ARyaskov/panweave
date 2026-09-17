//! Calendar cluster (SE 1.4a Annex D.9): the TOU / friendly credit /
//! auxiliary load switch calendars as command codecs (PublishCalendar,
//! PublishDayProfile with the three schedule entry formats,
//! PublishWeekProfile, PublishSeasons, PublishSpecialDays,
//! CancelCalendar and the Get* requests) and a bounded client-side
//! [`Store`] that keeps one calendar instance per type, applies the
//! replacement and cancellation rules, assembles fragmented tables and
//! resolves the day profile in force on a given date.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{AttributeId, ClusterId, CommandId};
use panweave_zcl::cluster::ClusterDef;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0707);

/// `AuxSwitchNLabel` (1-based `n` ≤ 8, octstr up to 22 characters).
pub const fn aux_switch_label(n: u8) -> AttributeId {
    AttributeId(n as u16 - 1)
}

/// Server → client: PublishCalendar.
pub const CMD_PUBLISH_CALENDAR: CommandId = CommandId(0x00);
/// Server → client: PublishDayProfile.
pub const CMD_PUBLISH_DAY_PROFILE: CommandId = CommandId(0x01);
/// Server → client: PublishWeekProfile.
pub const CMD_PUBLISH_WEEK_PROFILE: CommandId = CommandId(0x02);
/// Server → client: PublishSeasons.
pub const CMD_PUBLISH_SEASONS: CommandId = CommandId(0x03);
/// Server → client: PublishSpecialDays.
pub const CMD_PUBLISH_SPECIAL_DAYS: CommandId = CommandId(0x04);
/// Server → client: CancelCalendar.
pub const CMD_CANCEL_CALENDAR: CommandId = CommandId(0x05);
/// Client → server: GetCalendar.
pub const CMD_GET_CALENDAR: CommandId = CommandId(0x00);
/// Client → server: GetDayProfiles.
pub const CMD_GET_DAY_PROFILES: CommandId = CommandId(0x01);
/// Client → server: GetWeekProfiles.
pub const CMD_GET_WEEK_PROFILES: CommandId = CommandId(0x02);
/// Client → server: GetSeasons.
pub const CMD_GET_SEASONS: CommandId = CommandId(0x03);
/// Client → server: GetSpecialDays.
pub const CMD_GET_SPECIAL_DAYS: CommandId = CommandId(0x04);
/// Client → server: GetCalendarCancellation.
pub const CMD_GET_CALENDAR_CANCELLATION: CommandId = CommandId(0x05);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_GET_CALENDAR,
        CMD_GET_DAY_PROFILES,
        CMD_GET_WEEK_PROFILES,
        CMD_GET_SEASONS,
        CMD_GET_SPECIAL_DAYS,
        CMD_GET_CALENDAR_CANCELLATION,
    ],
    generated: &[
        CMD_PUBLISH_CALENDAR,
        CMD_PUBLISH_DAY_PROFILE,
        CMD_PUBLISH_WEEK_PROFILE,
        CMD_PUBLISH_SEASONS,
        CMD_PUBLISH_SPECIAL_DAYS,
        CMD_CANCEL_CALENDAR,
    ],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

/// Calendar Type values (Table D-159).
pub mod calendar_type {
    /// Delivered calendar.
    pub const DELIVERED: u8 = 0x00;
    /// Received calendar.
    pub const RECEIVED: u8 = 0x01;
    /// Delivered and received calendar.
    pub const DELIVERED_AND_RECEIVED: u8 = 0x02;
    /// Friendly credit calendar.
    pub const FRIENDLY_CREDIT: u8 = 0x03;
    /// Auxiliary load switch calendar.
    pub const AUXILIARY_LOAD_SWITCH: u8 = 0x04;
    /// All types (search criteria).
    pub const ALL: u8 = 0xff;
}

/// Calendar Time Reference values (Table D-160).
pub mod time_reference {
    /// UTC time.
    pub const UTC: u8 = 0x00;
    /// Standard time.
    pub const STANDARD: u8 = 0x01;
    /// Local time.
    pub const LOCAL: u8 = 0x02;
}

/// Not specified (issuer event id / provider id filters).
pub const UNSPECIFIED: u32 = 0xffff_ffff;
/// Start immediately.
pub const IMMEDIATELY: u32 = 0;
/// Cancel a pending special day table.
pub const CANCEL: u32 = 0xffff_ffff;
/// Longest calendar name.
pub const MAX_NAME: usize = 12;
/// Schedule entries per day profile kept.
pub const MAX_SCHEDULE_ENTRIES: usize = 12;
/// Day profiles per calendar kept.
pub const MAX_DAY_PROFILES: usize = 4;
/// Week profiles per calendar kept.
pub const MAX_WEEK_PROFILES: usize = 4;
/// Seasons per calendar kept.
pub const MAX_SEASONS: usize = 4;
/// Special days per calendar kept (the spec asks for 25).
pub const MAX_SPECIAL_DAYS: usize = 25;
/// Calendar instances kept (one per type).
pub const MAX_CALENDARS: usize = 3;

/// A ZCL Date: year since 1900, month, day of month, day of week.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Date {
    /// Year − 1900 (0xff unspecified).
    pub year: u8,
    /// Month 1–12 (0xff unspecified).
    pub month: u8,
    /// Day of month 1–31 (0xff unspecified).
    pub day: u8,
    /// Day of week 1 (Monday) – 7 (0xff unspecified).
    pub weekday: u8,
}

impl Date {
    fn parse(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Date {
            year: r.u8()?,
            month: r.u8()?,
            day: r.u8()?,
            weekday: r.u8()?,
        })
    }

    fn encode(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.year)?;
        w.u8(self.month)?;
        w.u8(self.day)?;
        w.u8(self.weekday)
    }

    /// Whether `self` is on or before `other` (year, month, day).
    pub fn on_or_before(self, other: Date) -> bool {
        (self.year, self.month, self.day) <= (other.year, other.month, other.day)
    }

    /// Whether the calendar dates coincide.
    pub const fn same_day(self, other: Date) -> bool {
        self.year == other.year && self.month == other.month && self.day == other.day
    }
}

/// PublishCalendar (D.9.2.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishCalendar<'a> {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// Start time (0 immediately).
    pub start_time: u32,
    /// Calendar type (Table D-159).
    pub calendar_type: u8,
    /// Time reference (Table D-160).
    pub time_reference: u8,
    /// Calendar name.
    pub name: &'a [u8],
    /// Number of seasons.
    pub seasons: u8,
    /// Number of week profiles.
    pub week_profiles: u8,
    /// Number of day profiles.
    pub day_profiles: u8,
}

fn read_octstr<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let n = r.u8()?;
    r.bytes(usize::from(n))
}

fn write_octstr(w: &mut Writer<'_>, s: &[u8]) -> Result<(), CodecError> {
    w.u8(
        u8::try_from(s.len()).map_err(|_| CodecError::Unrepresentable {
            field: "octet string",
        })?,
    )?;
    w.bytes(s)
}

impl<'a> PublishCalendar<'a> {
    /// Parses the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(PublishCalendar {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            calendar_id: r.u32_le()?,
            start_time: r.u32_le()?,
            calendar_type: r.u8()?,
            time_reference: r.u8()?,
            name: read_octstr(&mut r)?,
            seasons: r.u8()?,
            week_profiles: r.u8()?,
            day_profiles: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.calendar_id)?;
        w.u32_le(self.start_time)?;
        w.u8(self.calendar_type)?;
        w.u8(self.time_reference)?;
        write_octstr(w, self.name)?;
        w.u8(self.seasons)?;
        w.u8(self.week_profiles)?;
        w.u8(self.day_profiles)
    }
}

/// A day schedule entry: a start time in minutes from midnight and the
/// value in force from then on (price tier, friendly credit enable or
/// auxiliary switch state, per the calendar type; D.9.2.3.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScheduleEntry {
    /// Minutes from midnight.
    pub start_minute: u16,
    /// Price tier, friendly credit enable (0/1) or switch bitmap.
    pub value: u8,
}

/// PublishDayProfile (D.9.2.3.2).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishDayProfile {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// Day identifier (from 1).
    pub day_id: u8,
    /// Total schedule entries of the profile.
    pub total_entries: u8,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// Calendar type.
    pub calendar_type: u8,
    /// The entries carried by this command.
    pub entries: Vec<ScheduleEntry, MAX_SCHEDULE_ENTRIES>,
}

impl PublishDayProfile {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let provider_id = r.u32_le()?;
        let issuer_event_id = r.u32_le()?;
        let calendar_id = r.u32_le()?;
        let day_id = r.u8()?;
        let total_entries = r.u8()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let calendar_type = r.u8()?;
        let mut entries = Vec::new();
        while !r.is_empty() {
            let e = ScheduleEntry {
                start_minute: r.u16_le()?,
                value: r.u8()?,
            };
            entries.push(e).map_err(|_| CodecError::Unrepresentable {
                field: "schedule entries",
            })?;
        }
        Ok(PublishDayProfile {
            provider_id,
            issuer_event_id,
            calendar_id,
            day_id,
            total_entries,
            command_index,
            total_commands,
            calendar_type,
            entries,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.calendar_id)?;
        w.u8(self.day_id)?;
        w.u8(self.total_entries)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        w.u8(self.calendar_type)?;
        for e in &self.entries {
            w.u16_le(e.start_minute)?;
            w.u8(e.value)?;
        }
        Ok(())
    }
}

/// PublishWeekProfile (D.9.2.3.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishWeekProfile {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// Week identifier (from 1).
    pub week_id: u8,
    /// Day identifier references, Monday first.
    pub days: [u8; 7],
}

impl PublishWeekProfile {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(PublishWeekProfile {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            calendar_id: r.u32_le()?,
            week_id: r.u8()?,
            days: r.array::<7>()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.calendar_id)?;
        w.u8(self.week_id)?;
        w.bytes(&self.days)
    }
}

/// A season entry (Figure D-145).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SeasonEntry {
    /// Season start date.
    pub start: Date,
    /// Week identifier reference.
    pub week_id: u8,
}

/// PublishSeasons (D.9.2.3.4).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishSeasons {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// Season entries.
    pub seasons: Vec<SeasonEntry, MAX_SEASONS>,
}

impl PublishSeasons {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let provider_id = r.u32_le()?;
        let issuer_event_id = r.u32_le()?;
        let calendar_id = r.u32_le()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let mut seasons = Vec::new();
        while !r.is_empty() {
            let e = SeasonEntry {
                start: Date::parse(&mut r)?,
                week_id: r.u8()?,
            };
            seasons.push(e).map_err(|_| CodecError::Unrepresentable {
                field: "season entries",
            })?;
        }
        Ok(PublishSeasons {
            provider_id,
            issuer_event_id,
            calendar_id,
            command_index,
            total_commands,
            seasons,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.calendar_id)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        for e in &self.seasons {
            e.start.encode(w)?;
            w.u8(e.week_id)?;
        }
        Ok(())
    }
}

/// A special day entry (Figure D-147).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SpecialDay {
    /// The date.
    pub date: Date,
    /// Day identifier reference.
    pub day_id: u8,
}

/// PublishSpecialDays (D.9.2.3.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishSpecialDays {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// Start time (0 immediately, 0xffffffff cancel).
    pub start_time: u32,
    /// Calendar type.
    pub calendar_type: u8,
    /// Total special days of the table.
    pub total_special_days: u8,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// The entries carried by this command.
    pub entries: Vec<SpecialDay, MAX_SPECIAL_DAYS>,
}

impl PublishSpecialDays {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let provider_id = r.u32_le()?;
        let issuer_event_id = r.u32_le()?;
        let calendar_id = r.u32_le()?;
        let start_time = r.u32_le()?;
        let calendar_type = r.u8()?;
        let total_special_days = r.u8()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let mut entries = Vec::new();
        while !r.is_empty() {
            let e = SpecialDay {
                date: Date::parse(&mut r)?,
                day_id: r.u8()?,
            };
            entries.push(e).map_err(|_| CodecError::Unrepresentable {
                field: "special day entries",
            })?;
        }
        Ok(PublishSpecialDays {
            provider_id,
            issuer_event_id,
            calendar_id,
            start_time,
            calendar_type,
            total_special_days,
            command_index,
            total_commands,
            entries,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.calendar_id)?;
        w.u32_le(self.start_time)?;
        w.u8(self.calendar_type)?;
        w.u8(self.total_special_days)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        for e in &self.entries {
            e.date.encode(w)?;
            w.u8(e.day_id)?;
        }
        Ok(())
    }
}

/// CancelCalendar (D.9.2.3.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CancelCalendar {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// Calendar type.
    pub calendar_type: u8,
}

impl CancelCalendar {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CancelCalendar {
            provider_id: r.u32_le()?,
            calendar_id: r.u32_le()?,
            calendar_type: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.calendar_id)?;
        w.u8(self.calendar_type)
    }
}

/// GetCalendar (D.9.2.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetCalendar {
    /// Earliest start time.
    pub earliest_start: u32,
    /// Minimum issuer event identifier (0xffffffff unspecified).
    pub min_issuer_event_id: u32,
    /// Calendars wanted (0: all).
    pub count: u8,
    /// Calendar type (0xff unspecified).
    pub calendar_type: u8,
    /// Provider identifier (0xffffffff unspecified).
    pub provider_id: u32,
}

impl GetCalendar {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetCalendar {
            earliest_start: r.u32_le()?,
            min_issuer_event_id: r.u32_le()?,
            count: r.u8()?,
            calendar_type: r.u8()?,
            provider_id: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.earliest_start)?;
        w.u32_le(self.min_issuer_event_id)?;
        w.u8(self.count)?;
        w.u8(self.calendar_type)?;
        w.u32_le(self.provider_id)
    }
}

/// GetDayProfiles / GetWeekProfiles (D.9.2.4.2 / .3): a calendar, a
/// start identifier and a count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetProfiles {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// First day / week identifier (from 1).
    pub start_id: u8,
    /// Profiles wanted (0: all).
    pub count: u8,
}

impl GetProfiles {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetProfiles {
            provider_id: r.u32_le()?,
            calendar_id: r.u32_le()?,
            start_id: r.u8()?,
            count: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.calendar_id)?;
        w.u8(self.start_id)?;
        w.u8(self.count)
    }
}

/// GetSeasons (D.9.2.4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetSeasons {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
}

impl GetSeasons {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetSeasons {
            provider_id: r.u32_le()?,
            calendar_id: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.calendar_id)
    }
}

/// GetSpecialDays (D.9.2.4.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetSpecialDays {
    /// Start time (0: now).
    pub start_time: u32,
    /// Tables wanted (0: all).
    pub count: u8,
    /// Calendar type (0xff unspecified).
    pub calendar_type: u8,
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer calendar identifier (0: all).
    pub calendar_id: u32,
}

impl GetSpecialDays {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetSpecialDays {
            start_time: r.u32_le()?,
            count: r.u8()?,
            calendar_type: r.u8()?,
            provider_id: r.u32_le()?,
            calendar_id: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.start_time)?;
        w.u8(self.count)?;
        w.u8(self.calendar_type)?;
        w.u32_le(self.provider_id)?;
        w.u32_le(self.calendar_id)
    }
}

/// A stored day profile.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DayProfile {
    /// Day identifier.
    pub day_id: u8,
    /// Entries expected.
    pub total_entries: u8,
    /// Entries received so far, in start-time order.
    pub entries: Vec<ScheduleEntry, MAX_SCHEDULE_ENTRIES>,
}

impl DayProfile {
    /// Whether every entry has arrived.
    pub fn is_complete(&self) -> bool {
        self.entries.len() >= usize::from(self.total_entries)
    }

    /// The value in force at `minute` of the day.
    pub fn value_at(&self, minute: u16) -> Option<u8> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.start_minute <= minute)
            .map(|e| e.value)
    }
}

/// A stored calendar instance.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Calendar {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Issuer calendar identifier.
    pub calendar_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Calendar type.
    pub calendar_type: u8,
    /// Time reference.
    pub time_reference: u8,
    /// Name.
    pub name: Vec<u8, MAX_NAME>,
    /// Day profiles.
    pub day_profiles: Vec<DayProfile, MAX_DAY_PROFILES>,
    /// Week profiles (week id, Monday-first day references).
    pub week_profiles: Vec<(u8, [u8; 7]), MAX_WEEK_PROFILES>,
    /// Seasons in date order.
    pub seasons: Vec<SeasonEntry, MAX_SEASONS>,
    /// Special days in date order.
    pub special_days: Vec<SpecialDay, MAX_SPECIAL_DAYS>,
    /// Issuer event id of the special day table.
    pub special_days_event_id: u32,
}

impl Calendar {
    /// The day profile in force on `date` (special days first, then
    /// the season's week profile by weekday).
    pub fn day_profile_on(&self, date: Date) -> Option<&DayProfile> {
        let day_id = if let Some(s) = self.special_days.iter().find(|s| s.date.same_day(date)) {
            s.day_id
        } else {
            let season = self
                .seasons
                .iter()
                .rev()
                .find(|s| s.start.on_or_before(date))?;
            let week = self
                .week_profiles
                .iter()
                .find(|(id, _)| *id == season.week_id)?;
            let weekday = usize::from(date.weekday.checked_sub(1)?);
            *week.1.get(weekday)?
        };
        self.day_profiles.iter().find(|d| d.day_id == day_id)
    }
}

/// Why a publish command was refused (as ZCL statuses).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Refusal {
    /// No calendar instance matches (NOT_FOUND).
    NotFound,
    /// The table does not fit (INSUFFICIENT_SPACE).
    InsufficientSpace,
    /// Older than what is stored (SUCCESS, ignored).
    Stale,
}

/// Client-side calendar store.
#[derive(Clone, Default, Debug)]
pub struct Store {
    /// Calendar instances, at most one per type.
    pub calendars: Vec<Calendar, MAX_CALENDARS>,
}

impl Store {
    /// The calendar of `calendar_type`.
    pub fn calendar(&self, calendar_type: u8) -> Option<&Calendar> {
        self.calendars
            .iter()
            .find(|c| c.calendar_type == calendar_type)
    }

    fn by_id_mut(&mut self, calendar_id: u32) -> Option<&mut Calendar> {
        self.calendars
            .iter_mut()
            .find(|c| c.calendar_id == calendar_id)
    }

    /// Applies a PublishCalendar: a newer instance of the same type
    /// replaces the stored one (its tables start empty); an older one is
    /// stale.
    pub fn on_publish_calendar(&mut self, p: &PublishCalendar<'_>) -> Result<(), Refusal> {
        if let Some(existing) = self
            .calendars
            .iter()
            .find(|c| c.calendar_type == p.calendar_type)
            && existing.issuer_event_id > p.issuer_event_id
        {
            return Err(Refusal::Stale);
        }
        let c = Calendar {
            provider_id: p.provider_id,
            issuer_event_id: p.issuer_event_id,
            calendar_id: p.calendar_id,
            start_time: p.start_time,
            calendar_type: p.calendar_type,
            time_reference: p.time_reference,
            name: Vec::from_slice(p.name).map_err(|_| Refusal::InsufficientSpace)?,
            day_profiles: Vec::new(),
            week_profiles: Vec::new(),
            seasons: Vec::new(),
            special_days: Vec::new(),
            special_days_event_id: 0,
        };
        self.calendars
            .retain(|c| c.calendar_type != p.calendar_type);
        self.calendars
            .push(c)
            .map_err(|_| Refusal::InsufficientSpace)
    }

    /// Applies a PublishDayProfile (fragments append in order).
    pub fn on_publish_day_profile(&mut self, p: &PublishDayProfile) -> Result<(), Refusal> {
        let c = self.by_id_mut(p.calendar_id).ok_or(Refusal::NotFound)?;
        if let Some(d) = c.day_profiles.iter_mut().find(|d| d.day_id == p.day_id) {
            if p.command_index == 0 {
                d.entries.clear();
                d.total_entries = p.total_entries;
            }
            d.entries
                .extend_from_slice(&p.entries)
                .map_err(|_| Refusal::InsufficientSpace)?;
            return Ok(());
        }
        let d = DayProfile {
            day_id: p.day_id,
            total_entries: p.total_entries,
            entries: p.entries.clone(),
        };
        c.day_profiles
            .push(d)
            .map_err(|_| Refusal::InsufficientSpace)
    }

    /// Applies a PublishWeekProfile.
    pub fn on_publish_week_profile(&mut self, p: &PublishWeekProfile) -> Result<(), Refusal> {
        let c = self.by_id_mut(p.calendar_id).ok_or(Refusal::NotFound)?;
        if let Some(w) = c.week_profiles.iter_mut().find(|(id, _)| *id == p.week_id) {
            w.1 = p.days;
            return Ok(());
        }
        c.week_profiles
            .push((p.week_id, p.days))
            .map_err(|_| Refusal::InsufficientSpace)
    }

    /// Applies a PublishSeasons (fragments append in order).
    pub fn on_publish_seasons(&mut self, p: &PublishSeasons) -> Result<(), Refusal> {
        let c = self.by_id_mut(p.calendar_id).ok_or(Refusal::NotFound)?;
        if p.command_index == 0 {
            c.seasons.clear();
        }
        c.seasons
            .extend_from_slice(&p.seasons)
            .map_err(|_| Refusal::InsufficientSpace)
    }

    /// Applies a PublishSpecialDays: a newer table replaces the stored
    /// one, a cancellation (start time 0xffffffff) clears it, fragments
    /// append in order.
    pub fn on_publish_special_days(&mut self, p: &PublishSpecialDays) -> Result<(), Refusal> {
        let c = self
            .calendars
            .iter_mut()
            .find(|c| c.calendar_type == p.calendar_type && c.calendar_id == p.calendar_id)
            .ok_or(Refusal::NotFound)?;
        if p.start_time == CANCEL {
            if c.special_days_event_id == p.issuer_event_id {
                c.special_days.clear();
            }
            return Ok(());
        }
        if p.issuer_event_id < c.special_days_event_id {
            return Err(Refusal::Stale);
        }
        if p.command_index == 0 || p.issuer_event_id != c.special_days_event_id {
            c.special_days.clear();
        }
        c.special_days_event_id = p.issuer_event_id;
        c.special_days
            .extend_from_slice(&p.entries)
            .map_err(|_| Refusal::InsufficientSpace)
    }

    /// Applies a CancelCalendar; returns whether an instance was removed.
    pub fn on_cancel(&mut self, c: &CancelCalendar) -> bool {
        let before = self.calendars.len();
        self.calendars.retain(|k| {
            !(k.provider_id == c.provider_id
                && k.calendar_id == c.calendar_id
                && k.calendar_type == c.calendar_type)
        });
        self.calendars.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: PartialEq + core::fmt::Debug>(
        v: &T,
        enc: impl Fn(&T, &mut Writer<'_>) -> Result<(), CodecError>,
        dec: impl Fn(&[u8]) -> Result<T, CodecError>,
    ) -> usize {
        let mut buf = [0u8; 160];
        let mut w = Writer::new(&mut buf);
        enc(v, &mut w).unwrap();
        let n = w.position();
        assert_eq!(&dec(&buf[..n]).unwrap(), v);
        n
    }

    fn date(year: u8, month: u8, day: u8, weekday: u8) -> Date {
        Date {
            year,
            month,
            day,
            weekday,
        }
    }

    #[test]
    fn codecs_round_trip() {
        let cal = PublishCalendar {
            provider_id: 1,
            issuer_event_id: 10,
            calendar_id: 100,
            start_time: 0,
            calendar_type: calendar_type::DELIVERED,
            time_reference: time_reference::LOCAL,
            name: b"Summer",
            seasons: 2,
            week_profiles: 1,
            day_profiles: 2,
        };
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        cal.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 4 * 4 + 1 + 1 + 7 + 3);
        assert_eq!(PublishCalendar::parse(&buf[..n]).unwrap(), cal);

        let mut entries = Vec::new();
        entries
            .push(ScheduleEntry {
                start_minute: 0,
                value: 1,
            })
            .unwrap();
        entries
            .push(ScheduleEntry {
                start_minute: 420,
                value: 2,
            })
            .unwrap();
        let day = PublishDayProfile {
            provider_id: 1,
            issuer_event_id: 10,
            calendar_id: 100,
            day_id: 1,
            total_entries: 2,
            command_index: 0,
            total_commands: 1,
            calendar_type: calendar_type::DELIVERED,
            entries,
        };
        assert_eq!(
            roundtrip(&day, PublishDayProfile::encode, PublishDayProfile::parse),
            12 + 5 + 6
        );
        roundtrip(
            &PublishWeekProfile {
                provider_id: 1,
                issuer_event_id: 10,
                calendar_id: 100,
                week_id: 1,
                days: [1, 1, 1, 1, 1, 2, 2],
            },
            PublishWeekProfile::encode,
            PublishWeekProfile::parse,
        );
        let mut seasons = Vec::new();
        seasons
            .push(SeasonEntry {
                start: date(126, 1, 1, 4),
                week_id: 1,
            })
            .unwrap();
        roundtrip(
            &PublishSeasons {
                provider_id: 1,
                issuer_event_id: 10,
                calendar_id: 100,
                command_index: 0,
                total_commands: 1,
                seasons,
            },
            PublishSeasons::encode,
            PublishSeasons::parse,
        );
        let mut days = Vec::new();
        days.push(SpecialDay {
            date: date(126, 12, 25, 5),
            day_id: 2,
        })
        .unwrap();
        roundtrip(
            &PublishSpecialDays {
                provider_id: 1,
                issuer_event_id: 11,
                calendar_id: 100,
                start_time: 0,
                calendar_type: calendar_type::DELIVERED,
                total_special_days: 1,
                command_index: 0,
                total_commands: 1,
                entries: days,
            },
            PublishSpecialDays::encode,
            PublishSpecialDays::parse,
        );
        roundtrip(
            &CancelCalendar {
                provider_id: 1,
                calendar_id: 100,
                calendar_type: 0,
            },
            CancelCalendar::encode,
            CancelCalendar::parse,
        );
        roundtrip(
            &GetCalendar {
                earliest_start: 0,
                min_issuer_event_id: UNSPECIFIED,
                count: 0,
                calendar_type: calendar_type::ALL,
                provider_id: UNSPECIFIED,
            },
            GetCalendar::encode,
            GetCalendar::parse,
        );
        roundtrip(
            &GetProfiles {
                provider_id: 1,
                calendar_id: 100,
                start_id: 1,
                count: 0,
            },
            GetProfiles::encode,
            GetProfiles::parse,
        );
        roundtrip(
            &GetSeasons {
                provider_id: 1,
                calendar_id: 100,
            },
            GetSeasons::encode,
            GetSeasons::parse,
        );
        roundtrip(
            &GetSpecialDays {
                start_time: 0,
                count: 0,
                calendar_type: calendar_type::ALL,
                provider_id: 1,
                calendar_id: 0,
            },
            GetSpecialDays::encode,
            GetSpecialDays::parse,
        );
        assert_eq!(aux_switch_label(8), AttributeId(7));
    }

    fn publish_calendar(store: &mut Store, event: u32, id: u32) -> Result<(), Refusal> {
        store.on_publish_calendar(&PublishCalendar {
            provider_id: 1,
            issuer_event_id: event,
            calendar_id: id,
            start_time: 0,
            calendar_type: calendar_type::DELIVERED,
            time_reference: time_reference::LOCAL,
            name: b"TOU",
            seasons: 2,
            week_profiles: 2,
            day_profiles: 3,
        })
    }

    fn day(store: &mut Store, id: u8, entries: &[(u16, u8)], index: u8, total: u8) {
        let mut v = Vec::new();
        for (m, t) in entries {
            v.push(ScheduleEntry {
                start_minute: *m,
                value: *t,
            })
            .unwrap();
        }
        store
            .on_publish_day_profile(&PublishDayProfile {
                provider_id: 1,
                issuer_event_id: 10,
                calendar_id: 100,
                day_id: id,
                total_entries: total,
                command_index: index,
                total_commands: 2,
                calendar_type: calendar_type::DELIVERED,
                entries: v,
            })
            .unwrap();
    }

    #[test]
    fn store_resolves_the_day_profile_in_force() {
        let mut store = Store::default();
        assert!(
            store
                .on_publish_day_profile(&PublishDayProfile {
                    provider_id: 1,
                    issuer_event_id: 10,
                    calendar_id: 100,
                    day_id: 1,
                    total_entries: 0,
                    command_index: 0,
                    total_commands: 1,
                    calendar_type: 0,
                    entries: Vec::new(),
                })
                .is_err(),
            "no calendar yet"
        );
        publish_calendar(&mut store, 10, 100).unwrap();
        // Weekday profile (fragmented in two commands), weekend, holiday.
        day(&mut store, 1, &[(0, 1)], 0, 3);
        day(&mut store, 1, &[(420, 2), (1140, 1)], 1, 3);
        day(&mut store, 2, &[(0, 1)], 0, 1);
        day(&mut store, 3, &[(0, 0)], 0, 1);
        assert!(store.calendar(0).unwrap().day_profiles[0].is_complete());
        store
            .on_publish_week_profile(&PublishWeekProfile {
                provider_id: 1,
                issuer_event_id: 10,
                calendar_id: 100,
                week_id: 1,
                days: [1, 1, 1, 1, 1, 2, 2],
            })
            .unwrap();
        store
            .on_publish_week_profile(&PublishWeekProfile {
                provider_id: 1,
                issuer_event_id: 10,
                calendar_id: 100,
                week_id: 2,
                days: [2; 7],
            })
            .unwrap();
        let mut seasons = Vec::new();
        seasons
            .push(SeasonEntry {
                start: date(126, 1, 1, 4),
                week_id: 1,
            })
            .unwrap();
        seasons
            .push(SeasonEntry {
                start: date(126, 7, 1, 3),
                week_id: 2,
            })
            .unwrap();
        store
            .on_publish_seasons(&PublishSeasons {
                provider_id: 1,
                issuer_event_id: 10,
                calendar_id: 100,
                command_index: 0,
                total_commands: 1,
                seasons,
            })
            .unwrap();
        let mut days = Vec::new();
        days.push(SpecialDay {
            date: date(126, 5, 1, 5),
            day_id: 3,
        })
        .unwrap();
        store
            .on_publish_special_days(&PublishSpecialDays {
                provider_id: 1,
                issuer_event_id: 11,
                calendar_id: 100,
                start_time: 0,
                calendar_type: calendar_type::DELIVERED,
                total_special_days: 1,
                command_index: 0,
                total_commands: 1,
                entries: days,
            })
            .unwrap();
        let cal = store.calendar(calendar_type::DELIVERED).unwrap();
        // A March Wednesday: weekday profile, tier 2 at 08:00.
        let wed = cal.day_profile_on(date(126, 3, 4, 3)).unwrap();
        assert_eq!(wed.day_id, 1);
        assert_eq!(wed.value_at(8 * 60), Some(2));
        assert_eq!(wed.value_at(6 * 60), Some(1));
        assert_eq!(wed.value_at(20 * 60), Some(1));
        // A March Saturday: weekend profile.
        assert_eq!(cal.day_profile_on(date(126, 3, 7, 6)).unwrap().day_id, 2);
        // August Monday: summer season uses week 2 every day.
        assert_eq!(cal.day_profile_on(date(126, 8, 3, 1)).unwrap().day_id, 2);
        // 1 May: the special day.
        assert_eq!(cal.day_profile_on(date(126, 5, 1, 5)).unwrap().day_id, 3);
        // Before the first season: nothing applies.
        assert!(cal.day_profile_on(date(125, 12, 31, 3)).is_none());
        // Stale calendar refused, newer replaces and empties the tables.
        assert_eq!(publish_calendar(&mut store, 9, 99), Err(Refusal::Stale));
        publish_calendar(&mut store, 12, 101).unwrap();
        assert!(store.calendar(0).unwrap().day_profiles.is_empty());
        assert_eq!(store.calendar(0).unwrap().calendar_id, 101);
        assert_eq!(
            store.on_publish_seasons(&PublishSeasons {
                provider_id: 1,
                issuer_event_id: 12,
                calendar_id: 100,
                command_index: 0,
                total_commands: 1,
                seasons: Vec::new(),
            }),
            Err(Refusal::NotFound)
        );
        assert!(store.on_cancel(&CancelCalendar {
            provider_id: 1,
            calendar_id: 101,
            calendar_type: 0,
        }));
        assert!(store.calendars.is_empty());
    }

    #[test]
    fn special_day_tables_replace_and_cancel() {
        let mut store = Store::default();
        publish_calendar(&mut store, 10, 100).unwrap();
        let table = |event: u32, start: u32, d: u8| {
            let mut entries = Vec::new();
            entries
                .push(SpecialDay {
                    date: date(126, 1, d, 1),
                    day_id: 1,
                })
                .unwrap();
            PublishSpecialDays {
                provider_id: 1,
                issuer_event_id: event,
                calendar_id: 100,
                start_time: start,
                calendar_type: calendar_type::DELIVERED,
                total_special_days: 1,
                command_index: 0,
                total_commands: 1,
                entries,
            }
        };
        store.on_publish_special_days(&table(20, 0, 5)).unwrap();
        assert_eq!(
            store.on_publish_special_days(&table(19, 0, 6)),
            Err(Refusal::Stale)
        );
        store.on_publish_special_days(&table(21, 0, 7)).unwrap();
        let sd = &store.calendar(0).unwrap().special_days;
        assert_eq!((sd.len(), sd[0].date.day), (1, 7));
        store
            .on_publish_special_days(&table(21, CANCEL, 0))
            .unwrap();
        assert!(store.calendar(0).unwrap().special_days.is_empty());
        assert_eq!(
            store.on_publish_special_days(&PublishSpecialDays {
                calendar_type: calendar_type::FRIENDLY_CREDIT,
                ..table(22, 0, 1)
            }),
            Err(Refusal::NotFound)
        );
    }
}
