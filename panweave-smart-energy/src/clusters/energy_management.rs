//! Energy Management cluster (SE 1.4a Annex D.12, provisional): the
//! server attributes describing a DRLC client's load control state, the
//! ManageEvent command (opt in / opt out / duty cycling control of a
//! scheduled or running DRLC event) with its ReportEventStatus reply,
//! the Conformance Level rule and the DutyOnTime / DutyOffTime
//! algorithm of D.12.2.2.5.
//!
//! The server sits next to a [`drlc::Scheduler`]: [`Server::manage`]
//! applies a ManageEvent to the scheduler and produces both the Energy
//! Management reply and, when the event changed, the DRLC report the
//! client must also send.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::cluster::ClusterDef;
use panweave_zcl::types::DataType;

use super::drlc::{self, EventStatus, Phase, ReportEventStatus, Scheduler};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0706);

/// `LoadControlState` (Table D-193).
pub const LOAD_CONTROL_STATE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Bitmap(1), Access::RO);
/// `CurrentEventID` (0xFFFFFFFF when no event is active).
pub const CURRENT_EVENT_ID: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(4), Access::RO);
/// `CurrentEventStatus` (Table D-194).
pub const CURRENT_EVENT_STATUS: AttributeDef =
    AttributeDef::new(0x0002, DataType::Bitmap(1), Access::RO);
/// `ConformanceLevel` (1–7, or 0 read-only when unsupported).
pub const CONFORMANCE_LEVEL: AttributeDef =
    AttributeDef::new(0x0003, DataType::Uint(1), Access::RW);
/// `MinimumOffTime` in seconds (0xFFFF unsupported).
pub const MINIMUM_OFF_TIME: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(2), Access::RW);
/// `MinimumOnTime` in seconds.
pub const MINIMUM_ON_TIME: AttributeDef = AttributeDef::new(0x0005, DataType::Uint(2), Access::RW);
/// `MinimumCyclePeriod` in seconds (0 disables duty cycling).
pub const MINIMUM_CYCLE_PERIOD: AttributeDef =
    AttributeDef::new(0x0006, DataType::Uint(2), Access::RW);

/// Client → server: ManageEvent.
pub const CMD_MANAGE_EVENT: CommandId = CommandId(0x00);
/// Server → client: ReportEventStatus (the DRLC payload).
pub const CMD_REPORT_EVENT_STATUS: CommandId = CommandId(0x00);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_MANAGE_EVENT],
    generated: &[CMD_REPORT_EVENT_STATUS],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

/// Load Control State bits (Table D-193).
pub mod load_control_state {
    /// Relay open or consumption interrupted.
    pub const RELAY_OPEN: u8 = 0x01;
    /// An event is in progress.
    pub const EVENT_IN_PROGRESS: u8 = 0x02;
    /// Power stabilizing.
    pub const POWER_STABILIZING: u8 = 0x04;
    /// Other load reduction.
    pub const OTHER_LOAD_REDUCTION: u8 = 0x08;
    /// Currently consuming the commodity.
    pub const CONSUMING: u8 = 0x10;
    /// Load call: would consume if able.
    pub const LOAD_CALL: u8 = 0x20;
}

/// Current Event Status bits (Table D-194).
pub mod event_status_bits {
    /// Randomized start time.
    pub const RANDOMIZED_START: u8 = 0x01;
    /// Randomized duration.
    pub const RANDOMIZED_DURATION: u8 = 0x02;
    /// Extended bits present (always set).
    pub const EXTENDED_BITS: u8 = 0x04;
    /// Event active.
    pub const EVENT_ACTIVE: u8 = 0x08;
    /// Device participating (not opted out).
    pub const PARTICIPATING: u8 = 0x10;
    /// Reducing load.
    pub const REDUCING_LOAD: u8 = 0x20;
    /// On at the end of the event.
    pub const ON_AT_END: u8 = 0x40;
}

/// Action(s) Required bits (Table D-196).
pub mod action {
    /// Opt out of the event.
    pub const OPT_OUT: u8 = 0x01;
    /// Opt into the event.
    pub const OPT_IN: u8 = 0x02;
    /// Disable duty cycling.
    pub const DISABLE_DUTY_CYCLING: u8 = 0x04;
    /// Enable duty cycling.
    pub const ENABLE_DUTY_CYCLING: u8 = 0x08;
}

/// Issuer Event ID meaning the current running event.
pub const CURRENT_EVENT: u32 = 0xffff_ffff;
/// `CurrentEventID` value when no event is active.
pub const NO_EVENT: u32 = 0xffff_ffff;
/// Attribute value when a minimum time is unsupported.
pub const TIME_UNSUPPORTED: u16 = 0xffff;

/// ManageEvent (D.12.2.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ManageEvent {
    /// Issuer event id (`CURRENT_EVENT` for the running one).
    pub issuer_event_id: u32,
    /// Device class bitmap the command is directed at.
    pub device_class: u16,
    /// Utility enrollment group (0: any).
    pub utility_enrollment_group: u8,
    /// Actions (Table D-196).
    pub actions: u8,
}

impl ManageEvent {
    /// Encoded length.
    pub const LEN: usize = 8;

    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ManageEvent {
            issuer_event_id: r.u32_le()?,
            device_class: r.u16_le()?,
            utility_enrollment_group: r.u8()?,
            actions: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u16_le(self.device_class)?;
        w.u8(self.utility_enrollment_group)?;
        w.u8(self.actions)
    }
}

/// Duty cycle on / off times in seconds (D.12.2.2.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DutyTimes {
    /// Seconds on per cycle.
    pub on: u32,
    /// Seconds off per cycle.
    pub off: u32,
}

/// Computes DutyOnTime / DutyOffTime for `duty_cycle` percent from the
/// minimum times; `None` when duty cycling is disabled
/// (`min_cycle == 0`) or the percentage is out of 1..=99 (0 means off
/// for the whole event, 100 means no cycling).
pub fn duty_times(min_cycle: u16, min_on: u16, min_off: u16, duty_cycle: u8) -> Option<DutyTimes> {
    if min_cycle == 0 || duty_cycle == 0 || duty_cycle >= 100 {
        return None;
    }
    let applied = u32::from(duty_cycle);
    let cycle = u32::from(min_cycle);
    let min_on = if min_on == TIME_UNSUPPORTED {
        0
    } else {
        u32::from(min_on)
    };
    let min_off = if min_off == TIME_UNSUPPORTED {
        0
    } else {
        u32::from(min_off)
    };
    let mut on = cycle * applied / 100;
    let mut off = cycle - on;
    if on < min_on {
        on = min_on;
        off = min_on * (100 - applied) / applied;
    }
    if off < min_off {
        off = min_off;
        on = min_off * applied / (100 - applied);
    }
    Some(DutyTimes { on, off })
}

/// The outcome of a ManageEvent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Managed {
    /// The Energy Management ReportEventStatus reply.
    pub reply: ReportEventStatus,
    /// The DRLC report to send as well when the event changed.
    pub drlc_report: Option<drlc::Report>,
}

/// Energy Management server state next to a DRLC scheduler of `N`
/// events.
#[derive(Clone, Debug)]
pub struct Server<const N: usize> {
    /// `LoadControlState` bits other than `EVENT_IN_PROGRESS`, which
    /// is derived.
    pub state: u8,
    /// `ConformanceLevel` (0: unsupported, every event observed).
    pub conformance_level: u8,
    /// `MinimumOffTime`.
    pub minimum_off_time: u16,
    /// `MinimumOnTime`.
    pub minimum_on_time: u16,
    /// `MinimumCyclePeriod`.
    pub minimum_cycle_period: u16,
    /// Whether the device sheds load when an event is active.
    pub reducing_load: bool,
    /// Whether the load returns to normal after the event.
    pub on_at_end: bool,
    /// Last DRLC status sent per event.
    last_status: Vec<(u32, EventStatus), N>,
    /// Events whose duty cycling was disabled.
    duty_disabled: Vec<u32, N>,
}

impl<const N: usize> Default for Server<N> {
    fn default() -> Self {
        Server {
            state: 0,
            conformance_level: 0,
            minimum_off_time: TIME_UNSUPPORTED,
            minimum_on_time: TIME_UNSUPPORTED,
            minimum_cycle_period: TIME_UNSUPPORTED,
            reducing_load: true,
            on_at_end: true,
            last_status: Vec::new(),
            duty_disabled: Vec::new(),
        }
    }
}

impl<const N: usize> Server<N> {
    /// A server observing every event, without duty cycling support.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the status the DRLC client last reported for an event
    /// (feeds the Event Status field of later replies).
    pub fn note_report(&mut self, report: &drlc::Report) {
        if let Some(e) = self
            .last_status
            .iter_mut()
            .find(|(id, _)| *id == report.issuer_event_id)
        {
            e.1 = report.status;
        } else {
            if self.last_status.is_full() {
                self.last_status.remove(0);
            }
            let _ = self
                .last_status
                .push((report.issuer_event_id, report.status));
        }
        if matches!(
            report.status,
            EventStatus::Completed
                | EventStatus::CompletedNoParticipation
                | EventStatus::Cancelled
                | EventStatus::Superseded
        ) {
            self.duty_disabled
                .retain(|id| *id != report.issuer_event_id);
        }
    }

    /// Whether duty cycling is disabled for `issuer_event_id`.
    pub fn duty_cycling_disabled(&self, issuer_event_id: u32) -> bool {
        self.duty_disabled.contains(&issuer_event_id)
    }

    /// The running event, if any (the highest-criticality active one,
    /// opted out or not).
    fn current<'a>(sched: &'a Scheduler<N>, now: u32) -> Option<&'a drlc::Scheduled> {
        sched
            .events()
            .iter()
            .filter(|s| s.start <= now && now < s.end)
            .max_by_key(|s| s.event.criticality_level)
    }

    /// `CurrentEventID`.
    pub fn current_event_id(sched: &Scheduler<N>, now: u32) -> u32 {
        Self::current(sched, now).map_or(NO_EVENT, |s| s.event.issuer_event_id)
    }

    /// `LoadControlState`.
    pub fn load_control_state(&self, sched: &Scheduler<N>, now: u32) -> u8 {
        let in_progress = if Self::current(sched, now).is_some() {
            load_control_state::EVENT_IN_PROGRESS
        } else {
            0
        };
        self.state | in_progress
    }

    /// `CurrentEventStatus` (Table D-194).
    pub fn current_event_status(&self, sched: &Scheduler<N>, now: u32) -> u8 {
        let mut bits = event_status_bits::EXTENDED_BITS;
        let Some(s) = Self::current(sched, now) else {
            return bits;
        };
        bits |= event_status_bits::EVENT_ACTIVE;
        if s.event.event_control & drlc::event_control::RANDOMIZE_START != 0 {
            bits |= event_status_bits::RANDOMIZED_START;
        }
        if s.event.event_control & drlc::event_control::RANDOMIZE_DURATION != 0 {
            bits |= event_status_bits::RANDOMIZED_DURATION;
        }
        let participating = s.phase == Phase::Active;
        if participating {
            bits |= event_status_bits::PARTICIPATING;
            if self.reducing_load {
                bits |= event_status_bits::REDUCING_LOAD;
            }
        }
        if self.on_at_end {
            bits |= event_status_bits::ON_AT_END;
        }
        bits
    }

    /// Applies a ManageEvent. `None` when the command is not for this
    /// device (device class / enrollment group mismatch) and is
    /// ignored; otherwise the reply, with the DRLC report when the
    /// scheduler changed.
    pub fn manage(
        &mut self,
        sched: &mut Scheduler<N>,
        cmd: &ManageEvent,
        now: u32,
    ) -> Option<Managed> {
        if cmd.device_class & sched.device_class == 0 {
            return None;
        }
        if cmd.utility_enrollment_group != 0
            && cmd.utility_enrollment_group != sched.enrollment_group
        {
            return None;
        }
        let id = if cmd.issuer_event_id == CURRENT_EVENT {
            Self::current_event_id(sched, now)
        } else {
            cmd.issuer_event_id
        };
        let Some(s) = sched.get(id).copied() else {
            return Some(Managed {
                reply: ReportEventStatus::new(cmd.issuer_event_id, EventStatus::EventNotFound, now),
                drlc_report: None,
            });
        };
        let mut drlc_report = None;
        let mut status = None;
        if cmd.actions & action::OPT_OUT != 0 && cmd.actions & action::OPT_IN == 0 {
            if drlc::criticality::is_mandatory(s.event.criticality_level) {
                status = Some(EventStatus::InvalidOptOut);
            } else {
                drlc_report = sched.set_opt_out(id, true, now);
                status = Some(EventStatus::OptOut);
            }
        } else if cmd.actions & action::OPT_IN != 0 {
            drlc_report = sched.set_opt_out(id, false, now);
            status = Some(EventStatus::OptIn);
        }
        let cycling_requested = s.event.duty_cycle != drlc::DUTY_CYCLE_UNUSED
            && self.minimum_cycle_period != TIME_UNSUPPORTED;
        if cycling_requested {
            if cmd.actions & action::DISABLE_DUTY_CYCLING != 0
                && cmd.actions & action::ENABLE_DUTY_CYCLING == 0
                && !self.duty_disabled.contains(&id)
            {
                let _ = self.duty_disabled.push(id);
            } else if cmd.actions & action::ENABLE_DUTY_CYCLING != 0 {
                self.duty_disabled.retain(|e| *e != id);
            }
        }
        let status = status.unwrap_or(match s.phase {
            Phase::Scheduled | Phase::ScheduledOptOut => EventStatus::Received,
            Phase::Active => EventStatus::Started,
            Phase::ActiveOptOut => EventStatus::OptOut,
        });
        let mut reply = ReportEventStatus::new(id, status, now);
        reply.criticality_level_applied = s.event.criticality_level;
        reply.event_control = self.current_event_status(sched, now);
        if s.event.duty_cycle != drlc::DUTY_CYCLE_UNUSED {
            reply.duty_cycle_applied = if self.duty_disabled.contains(&id) {
                0
            } else {
                s.event.duty_cycle
            };
        }
        if let Some(r) = &drlc_report {
            self.note_report(r);
        }
        Some(Managed { reply, drlc_report })
    }

    /// Sets `ConformanceLevel`; events below it are opted out (and
    /// events at or above it opted back in). Returns the DRLC reports
    /// for the events whose participation changed. `None` for a level
    /// outside 1..=7.
    pub fn set_conformance_level(
        &mut self,
        sched: &mut Scheduler<N>,
        level: u8,
        now: u32,
    ) -> Option<Vec<drlc::Report, N>> {
        if !(1..=7).contains(&level) {
            return None;
        }
        self.conformance_level = level;
        let mut out = Vec::new();
        let ids: Vec<(u32, u8, bool), N> = sched
            .events()
            .iter()
            .map(|s| {
                (
                    s.event.issuer_event_id,
                    s.event.criticality_level,
                    matches!(s.phase, Phase::ActiveOptOut | Phase::ScheduledOptOut),
                )
            })
            .collect();
        for (id, crit, opted_out) in ids {
            let want_out = crit < level && !drlc::criticality::is_mandatory(crit);
            if want_out != opted_out
                && let Some(r) = sched.set_opt_out(id, want_out, now)
            {
                self.note_report(&r);
                let _ = out.push(r);
            }
        }
        Some(out)
    }

    /// Whether the scheduler should observe a new event of
    /// `criticality` under the conformance level (mandatory events are
    /// always observed).
    pub fn observes(&self, criticality: u8) -> bool {
        self.conformance_level == 0
            || criticality >= self.conformance_level
            || drlc::criticality::is_mandatory(criticality)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clusters::drlc::{LoadControlEvent, criticality, device_class};

    fn event(id: u32, start: u32, crit: u8, duty: u8) -> LoadControlEvent {
        LoadControlEvent {
            issuer_event_id: id,
            device_class: device_class::HVAC,
            utility_enrollment_group: 0,
            start_time: start,
            duration_minutes: 60,
            criticality_level: crit,
            cooling_temperature_offset: drlc::OFFSET_UNUSED,
            heating_temperature_offset: drlc::OFFSET_UNUSED,
            cooling_temperature_set_point: drlc::SET_POINT_UNUSED,
            heating_temperature_set_point: drlc::SET_POINT_UNUSED,
            average_load_adjustment_percentage: drlc::LOAD_ADJUSTMENT_UNUSED,
            duty_cycle: duty,
            event_control: 0,
        }
    }

    #[test]
    fn manage_event_codec() {
        let m = ManageEvent {
            issuer_event_id: 0x0102_0304,
            device_class: device_class::HVAC,
            utility_enrollment_group: 3,
            actions: action::OPT_OUT,
        };
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        m.encode(&mut w).unwrap();
        assert_eq!(w.position(), ManageEvent::LEN);
        assert_eq!(ManageEvent::parse(&buf).unwrap(), m);
    }

    #[test]
    fn duty_time_algorithm() {
        // 3600 s cycle at 50 %: 1800 / 1800.
        assert_eq!(
            duty_times(3600, 300, 300, 50),
            Some(DutyTimes {
                on: 1800,
                off: 1800
            })
        );
        // 1 % would give 36 s on: stretched to the 300 s minimum on.
        assert_eq!(
            duty_times(3600, 300, 300, 1),
            Some(DutyTimes {
                on: 300,
                off: 300 * 99
            })
        );
        // 99 %: 36 s off stretched to the minimum off.
        assert_eq!(
            duty_times(3600, 300, 300, 99),
            Some(DutyTimes {
                on: 300 * 99,
                off: 300
            })
        );
        assert_eq!(duty_times(0, 300, 300, 50), None);
        assert_eq!(duty_times(3600, 300, 300, 100), None);
        assert_eq!(
            duty_times(600, TIME_UNSUPPORTED, TIME_UNSUPPORTED, 25),
            Some(DutyTimes { on: 150, off: 450 })
        );
    }

    #[test]
    fn manage_event_applies_opt_out_rules() {
        let mut sched: Scheduler<4> = Scheduler::new(device_class::HVAC);
        let mut em: Server<4> = Server::new();
        em.minimum_cycle_period = 600;
        let now = 1000;
        sched.on_event(&event(1, now + 4000, criticality::LEVEL_1, 50), now, |_| 0);
        sched.on_event(
            &event(2, now + 60, criticality::EMERGENCY, drlc::DUTY_CYCLE_UNUSED),
            now,
            |_| 0,
        );
        // Wrong device class: ignored.
        let wrong = ManageEvent {
            issuer_event_id: 1,
            device_class: device_class::WATER_HEATER,
            utility_enrollment_group: 0,
            actions: action::OPT_OUT,
        };
        assert!(em.manage(&mut sched, &wrong, now).is_none());
        // Unknown event.
        let unknown = ManageEvent {
            issuer_event_id: 9,
            device_class: device_class::HVAC,
            ..wrong
        };
        assert_eq!(
            em.manage(&mut sched, &unknown, now)
                .unwrap()
                .reply
                .event_status,
            EventStatus::EventNotFound
        );
        // Opt out of the voluntary event: DRLC report too.
        let out = ManageEvent {
            issuer_event_id: 1,
            device_class: device_class::HVAC,
            ..wrong
        };
        let m = em.manage(&mut sched, &out, now).unwrap();
        assert_eq!(m.reply.event_status, EventStatus::OptOut);
        assert_eq!(m.drlc_report.unwrap().status, EventStatus::OptOut);
        assert_eq!(m.reply.duty_cycle_applied, 50);
        assert_eq!(sched.get(1).unwrap().phase, Phase::ScheduledOptOut);
        // Opting out of the emergency event is invalid.
        let m = em
            .manage(
                &mut sched,
                &ManageEvent {
                    issuer_event_id: 2,
                    ..out
                },
                now,
            )
            .unwrap();
        assert_eq!(m.reply.event_status, EventStatus::InvalidOptOut);
        assert!(m.drlc_report.is_none());
        assert_eq!(sched.get(2).unwrap().phase, Phase::Scheduled);
        // No action: status reflects the phase (not started).
        let m = em
            .manage(
                &mut sched,
                &ManageEvent {
                    issuer_event_id: 2,
                    actions: 0,
                    ..out
                },
                now,
            )
            .unwrap();
        assert_eq!(m.reply.event_status, EventStatus::Received);
        // Disable duty cycling on event 1: applied duty cycle reads 0.
        let m = em
            .manage(
                &mut sched,
                &ManageEvent {
                    issuer_event_id: 1,
                    actions: action::DISABLE_DUTY_CYCLING | action::OPT_IN,
                    ..out
                },
                now,
            )
            .unwrap();
        assert_eq!(m.reply.event_status, EventStatus::OptIn);
        assert_eq!(m.reply.duty_cycle_applied, 0);
        assert!(em.duty_cycling_disabled(1));
        // Event 2 starts: the current event, its attributes.
        let later = now + 120;
        for r in sched.poll(later) {
            em.note_report(&r);
        }
        assert_eq!(Server::current_event_id(&sched, later), 2);
        assert_eq!(
            em.load_control_state(&sched, later) & load_control_state::EVENT_IN_PROGRESS,
            load_control_state::EVENT_IN_PROGRESS
        );
        let bits = em.current_event_status(&sched, later);
        assert_eq!(
            bits,
            event_status_bits::EXTENDED_BITS
                | event_status_bits::EVENT_ACTIVE
                | event_status_bits::PARTICIPATING
                | event_status_bits::REDUCING_LOAD
                | event_status_bits::ON_AT_END
        );
        // CURRENT_EVENT addresses it.
        let m = em
            .manage(
                &mut sched,
                &ManageEvent {
                    issuer_event_id: CURRENT_EVENT,
                    actions: 0,
                    ..out
                },
                later,
            )
            .unwrap();
        assert_eq!(m.reply.issuer_event_id, 2);
        assert_eq!(m.reply.event_status, EventStatus::Started);
        assert_eq!(
            m.reply.event_control & event_status_bits::EVENT_ACTIVE,
            event_status_bits::EVENT_ACTIVE
        );
        // Conformance level 5 opts the level-1 event out, leaves the
        // emergency one alone.
        let reports = em.set_conformance_level(&mut sched, 6, later).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            (reports[0].issuer_event_id, reports[0].status),
            (1, EventStatus::OptOut)
        );
        assert!(em.set_conformance_level(&mut sched, 9, later).is_none());
        assert!(!em.observes(criticality::GREEN));
        assert!(em.observes(criticality::PLANNED_OUTAGE));
        // Back to level 1: opted in again.
        let reports = em.set_conformance_level(&mut sched, 1, later).unwrap();
        assert_eq!(reports[0].status, EventStatus::OptIn);
        // No event active: NO_EVENT and only the extended bit.
        assert_eq!(Server::current_event_id(&sched, now), NO_EVENT);
        assert_eq!(
            em.current_event_status(&sched, now),
            event_status_bits::EXTENDED_BITS
        );
    }
}
