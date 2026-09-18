//! IAS WD cluster (ZCL8 §8.4): the warning device. The server keeps
//! `MaxDuration`, decodes Start Warning (clamping the duration to it
//! and rounding the strobe duty cycle to tens) and Squawk (ignored
//! while a warning is active), tracks the active warning with the
//! cluster timer and hands both to the application; the client encodes
//! them.

use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0502);

/// `MaxDuration` (uint16 seconds, writable, default 240).
pub const MAX_DURATION: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(2), Access::RW);
/// `MaxDuration` default.
pub const DEFAULT_MAX_DURATION: u16 = 240;

/// Start Warning.
pub const CMD_START_WARNING: CommandId = CommandId(0x00);
/// Squawk.
pub const CMD_SQUAWK: CommandId = CommandId(0x01);

/// Warning modes (Table 8-21).
pub mod warning_mode {
    /// Stop.
    pub const STOP: u8 = 0;
    /// Burglar.
    pub const BURGLAR: u8 = 1;
    /// Fire.
    pub const FIRE: u8 = 2;
    /// Emergency.
    pub const EMERGENCY: u8 = 3;
    /// Police panic.
    pub const POLICE_PANIC: u8 = 4;
    /// Fire panic.
    pub const FIRE_PANIC: u8 = 5;
    /// Emergency panic.
    pub const EMERGENCY_PANIC: u8 = 6;
}

/// Squawk modes (Table 8-25).
pub mod squawk_mode {
    /// System armed.
    pub const ARMED: u8 = 0;
    /// System disarmed.
    pub const DISARMED: u8 = 1;
}

/// Sound / strobe levels (Tables 8-23, 8-24, 8-27).
pub mod level {
    /// Low.
    pub const LOW: u8 = 0;
    /// Medium.
    pub const MEDIUM: u8 = 1;
    /// High.
    pub const HIGH: u8 = 2;
    /// Very high.
    pub const VERY_HIGH: u8 = 3;
}

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[CMD_START_WARNING, CMD_SQUAWK],
    generated: &[],
};

/// A Start Warning command (§8.4.2.2.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Warning {
    /// Warning mode (Table 8-21).
    pub mode: u8,
    /// Strobe in parallel.
    pub strobe: bool,
    /// Siren level (Table 8-23).
    pub siren_level: u8,
    /// Duration in seconds (ignored when mode is Stop without strobe).
    pub duration: u16,
    /// Strobe duty cycle, 0–100 in tens.
    pub strobe_duty_cycle: u8,
    /// Strobe level (Table 8-24).
    pub strobe_level: u8,
}

impl Warning {
    /// Whether the command starts anything (a mode or the strobe).
    pub const fn is_active(&self) -> bool {
        self.mode != warning_mode::STOP || self.strobe
    }

    /// Parses the payload; the duty cycle is rounded to the nearest
    /// ten and clamped to 100.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let bits = r.u8()?;
        let duration = r.u16_le()?;
        let duty = r.u8()?;
        let strobe_level = r.u8()?;
        let mode = bits & 0x0f;
        if mode > warning_mode::EMERGENCY_PANIC {
            return Err(CodecError::InvalidField {
                field: "warning mode",
                value: u32::from(mode),
            });
        }
        Ok(Warning {
            mode,
            strobe: (bits >> 4) & 0x03 == 1,
            siren_level: bits >> 6,
            duration,
            strobe_duty_cycle: u8::try_from(((u16::from(duty.min(100)) + 5) / 10 * 10).min(100))
                .unwrap_or(100),
            strobe_level: strobe_level & 0x03,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8((self.mode & 0x0f) | (u8::from(self.strobe) << 4) | ((self.siren_level & 0x03) << 6))?;
        w.u16_le(self.duration)?;
        w.u8(self.strobe_duty_cycle)?;
        w.u8(self.strobe_level)?;
        Ok(w.position())
    }
}

/// A Squawk command (§8.4.2.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Squawk {
    /// Squawk mode (Table 8-25).
    pub mode: u8,
    /// Strobe blink in parallel.
    pub strobe: bool,
    /// Squawk level (Table 8-27).
    pub level: u8,
}

impl Squawk {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let bits = r.u8()?;
        Ok(Squawk {
            mode: bits & 0x0f,
            strobe: bits & 0x10 != 0,
            level: bits >> 6,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8((self.mode & 0x0f) | (u8::from(self.strobe) << 4) | ((self.level & 0x03) << 6))?;
        Ok(w.position())
    }
}

/// Builds a server with `MaxDuration` at `max_duration` seconds.
pub fn server<const A: usize>(max_duration: u16) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(
        MAX_DURATION,
        &Value::Uint {
            width: 2,
            value: u64::from(max_duration),
        },
    )?;
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// Whether a warning is active (the timer runs).
pub fn is_warning<const A: usize>(c: &ClusterInstance<A>) -> bool {
    c.tick.is_some()
}

/// Result of a received command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Start (or, when not active, stop) this warning; the duration is
    /// already clamped to `MaxDuration`.
    Warning(Warning),
    /// Emit this squawk.
    Squawk(Squawk),
    /// A Squawk arrived during a warning: ignored (SUCCESS).
    Ignored,
    /// Refused with this status.
    Default(ZclStatus),
}

/// Handles a received command (§8.4.2.2).
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
    now: Instant,
) -> Outcome {
    match cmd {
        CMD_START_WARNING => {
            let Ok(mut w) = Warning::parse(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let max = c.u16(MAX_DURATION.id).unwrap_or(DEFAULT_MAX_DURATION);
            w.duration = w.duration.min(max);
            // A new command always ends the previous one.
            c.tick = if w.is_active() && w.duration != 0 {
                Some(now.saturating_add(Duration::from_secs(u64::from(w.duration))))
            } else {
                None
            };
            if !w.is_active() {
                w.duration = 0;
            }
            Outcome::Warning(w)
        }
        CMD_SQUAWK => {
            if is_warning(c) {
                return Outcome::Ignored;
            }
            match Squawk::parse(payload) {
                Ok(s) => Outcome::Squawk(s),
                Err(_) => Outcome::Default(ZclStatus::MalformedCommand),
            }
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

/// Services the timer: `true` when the warning just expired.
pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> bool {
    if c.tick.is_some_and(|t| now.has_reached(t)) {
        c.tick = None;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Instant = Instant::from_millis(0);

    #[test]
    fn warning_round_trips_and_is_clamped() {
        let w = Warning {
            mode: warning_mode::FIRE,
            strobe: true,
            siren_level: level::HIGH,
            duration: 500,
            strobe_duty_cycle: 40,
            strobe_level: level::MEDIUM,
        };
        let mut buf = [0u8; 8];
        let n = w.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x92, 0xf4, 0x01, 40, 1]);
        assert_eq!(Warning::parse(&buf[..n]).unwrap(), w);
        // Duty cycle rounding: 44 → 40, 45 → 50, 120 → 100.
        assert_eq!(
            Warning::parse(&[0x01, 1, 0, 44, 0])
                .unwrap()
                .strobe_duty_cycle,
            40
        );
        assert_eq!(
            Warning::parse(&[0x01, 1, 0, 45, 0])
                .unwrap()
                .strobe_duty_cycle,
            50
        );
        assert_eq!(
            Warning::parse(&[0x01, 1, 0, 120, 0])
                .unwrap()
                .strobe_duty_cycle,
            100
        );
        assert!(Warning::parse(&[0x07, 1, 0, 0, 0]).is_err());

        let mut c: ClusterInstance<8> = server(240).unwrap();
        let o = handle(&mut c, CMD_START_WARNING, &buf[..n], T0);
        let Outcome::Warning(started) = o else {
            panic!("{o:?}");
        };
        assert_eq!(started.duration, 240, "clamped to MaxDuration");
        assert!(is_warning(&c));
        assert_eq!(c.tick, Some(T0.saturating_add(Duration::from_secs(240))));
        // Squawk is ignored while warning.
        assert_eq!(handle(&mut c, CMD_SQUAWK, &[0x11], T0), Outcome::Ignored);
        assert!(!tick(&mut c, T0.saturating_add(Duration::from_secs(239))));
        assert!(tick(&mut c, T0.saturating_add(Duration::from_secs(240))));
        assert!(!is_warning(&c));
        let o = handle(&mut c, CMD_SQUAWK, &[0xd1], T0);
        assert_eq!(
            o,
            Outcome::Squawk(Squawk {
                mode: squawk_mode::DISARMED,
                strobe: true,
                level: level::VERY_HIGH
            })
        );
        // Stop ends an active warning.
        handle(&mut c, CMD_START_WARNING, &buf[..n], T0);
        let o = handle(&mut c, CMD_START_WARNING, &[0x00, 10, 0, 0, 0], T0);
        assert!(matches!(o, Outcome::Warning(w) if !w.is_active() && w.duration == 0));
        assert!(!is_warning(&c));
        // Strobe only, with Stop mode, is active.
        let o = handle(&mut c, CMD_START_WARNING, &[0x10, 5, 0, 50, 0], T0);
        assert!(matches!(o, Outcome::Warning(w) if w.is_active() && w.duration == 5));
        assert!(is_warning(&c));
        assert_eq!(
            handle(&mut c, CMD_START_WARNING, &[0x10], T0),
            Outcome::Default(ZclStatus::MalformedCommand)
        );
    }

    #[test]
    fn squawk_round_trips() {
        let s = Squawk {
            mode: squawk_mode::ARMED,
            strobe: false,
            level: level::LOW,
        };
        let mut buf = [0u8; 2];
        let n = s.encode(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x00]);
        assert_eq!(Squawk::parse(&buf[..n]).unwrap(), s);
    }
}
