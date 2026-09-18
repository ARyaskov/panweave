//! Level Control cluster (ZCL8 §3.10), revision 3: `CurrentLevel` with
//! continuous transitions driven by the endpoint dispatcher's 100 ms
//! tick, the Options / ExecuteIfOff processing and the On/Off coupling of
//! Table 3-55.

use panweave_codec::Reader;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0008);
/// `CurrentLevel` (reportable, scene).
pub const CURRENT_LEVEL: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(1), Access::RO_REPORT);
/// `RemainingTime` (tenths of a second).
pub const REMAINING_TIME: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
/// `MinLevel`.
pub const MIN_LEVEL: AttributeDef = AttributeDef::new(0x0002, DataType::Uint(1), Access::RO);
/// `MaxLevel`.
pub const MAX_LEVEL: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(1), Access::RO);
/// `CurrentFrequency` (uint16, 10 Hz units, 0 unknown; reportable).
pub const CURRENT_FREQUENCY: AttributeDef =
    AttributeDef::new(0x0004, DataType::Uint(2), Access::RO_REPORT);
/// `MinFrequency` (uint16, 0 undefined).
pub const MIN_FREQUENCY: AttributeDef = AttributeDef::new(0x0005, DataType::Uint(2), Access::RO);
/// `MaxFrequency` (uint16, 0 undefined).
pub const MAX_FREQUENCY: AttributeDef = AttributeDef::new(0x0006, DataType::Uint(2), Access::RO);
/// `Options` (bit 0: ExecuteIfOff).
pub const OPTIONS: AttributeDef = AttributeDef::new(0x000F, DataType::Bitmap(1), Access::RW);
/// `OnOffTransitionTime` (tenths of a second).
pub const ON_OFF_TRANSITION_TIME: AttributeDef =
    AttributeDef::new(0x0010, DataType::Uint(2), Access::RW);
/// `OnLevel` (0xff: undefined).
pub const ON_LEVEL: AttributeDef = AttributeDef::new(0x0011, DataType::Uint(1), Access::RW);
/// `OnTransitionTime` (0xffff: undefined).
pub const ON_TRANSITION_TIME: AttributeDef =
    AttributeDef::new(0x0012, DataType::Uint(2), Access::RW);
/// `OffTransitionTime` (0xffff: undefined).
pub const OFF_TRANSITION_TIME: AttributeDef =
    AttributeDef::new(0x0013, DataType::Uint(2), Access::RW);
/// `DefaultMoveRate` (units per second).
pub const DEFAULT_MOVE_RATE: AttributeDef =
    AttributeDef::new(0x0014, DataType::Uint(1), Access::RW);
/// `StartUpCurrentLevel`.
pub const START_UP_CURRENT_LEVEL: AttributeDef =
    AttributeDef::new(0x4000, DataType::Uint(1), Access::RW);

/// Move to Level.
pub const CMD_MOVE_TO_LEVEL: CommandId = CommandId(0x00);
/// Move.
pub const CMD_MOVE: CommandId = CommandId(0x01);
/// Step.
pub const CMD_STEP: CommandId = CommandId(0x02);
/// Stop.
pub const CMD_STOP: CommandId = CommandId(0x03);
/// Move to Level (with On/Off).
pub const CMD_MOVE_TO_LEVEL_WITH_ON_OFF: CommandId = CommandId(0x04);
/// Move (with On/Off).
pub const CMD_MOVE_WITH_ON_OFF: CommandId = CommandId(0x05);
/// Step (with On/Off).
pub const CMD_STEP_WITH_ON_OFF: CommandId = CommandId(0x06);
/// Stop (with On/Off variant, identical, §3.10.2.3.4.2).
pub const CMD_STOP_WITH_ON_OFF: CommandId = CommandId(0x07);
/// Move to Closest Frequency (§3.10.2.3.5, with `CurrentFrequency`).
pub const CMD_MOVE_TO_CLOSEST_FREQUENCY: CommandId = CommandId(0x08);
/// Pulse Width Modulation cluster (§3.20): the Level engine over a duty
/// cycle (`CurrentLevel` 0…100 %) and a frequency.
pub const PWM_ID: ClusterId = ClusterId(0x001c);

/// `Options` bit: execute the 'without On/Off' commands while off.
pub const OPTION_EXECUTE_IF_OFF: u8 = 0x01;
/// `Options` bit (Level Control for Lighting, §3.19.2.2.3): couple
/// `CurrentLevel` to the colour temperature of the endpoint's Color
/// Control server (§5.2.2.1.1).
pub const OPTION_COUPLE_COLOR_TEMP_TO_LEVEL: u8 = 0x02;
/// `CurrentLevel` non-value (lighting, PWM).
pub const LEVEL_UNDEFINED: u8 = 0xff;

/// Move / Step mode: up.
pub const MODE_UP: u8 = 0x00;
/// Move / Step mode: down.
pub const MODE_DOWN: u8 = 0x01;

/// Undefined `OnLevel`.
pub const ON_LEVEL_UNDEFINED: u8 = 0xff;
/// Undefined transition time.
pub const TIME_UNDEFINED: u16 = 0xffff;

/// Default reporting of `CurrentLevel` (BDB 3.1 §6.5).
pub const DEFAULT_REPORTING: DefaultReporting = DefaultReporting {
    min: 1,
    max: 300,
    change: 1,
};

/// Period of the transition engine.
pub const TICK: Duration = Duration::from_millis(100);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[
        CMD_MOVE_TO_LEVEL,
        CMD_MOVE,
        CMD_STEP,
        CMD_STOP,
        CMD_MOVE_TO_LEVEL_WITH_ON_OFF,
        CMD_MOVE_WITH_ON_OFF,
        CMD_STEP_WITH_ON_OFF,
        CMD_STOP_WITH_ON_OFF,
    ],
    generated: &[],
};

/// Cluster definition with the frequency command (§3.10.2.3.5).
pub const FREQUENCY_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[
        CMD_MOVE_TO_LEVEL,
        CMD_MOVE,
        CMD_STEP,
        CMD_STOP,
        CMD_MOVE_TO_LEVEL_WITH_ON_OFF,
        CMD_MOVE_WITH_ON_OFF,
        CMD_STEP_WITH_ON_OFF,
        CMD_STOP_WITH_ON_OFF,
        CMD_MOVE_TO_CLOSEST_FREQUENCY,
    ],
    generated: &[],
};

/// Pulse Width Modulation cluster definition (Table 3-148).
pub const PWM_DEF: ClusterDef = ClusterDef {
    id: PWM_ID,
    revision: 1,
    received: FREQUENCY_DEF.received,
    generated: &[],
};

/// A transition in progress and the On/Off bookkeeping of Table 3-55.
#[derive(Clone, Copy, Debug, Default)]
pub struct Transition {
    /// A transition is running.
    pub active: bool,
    /// Level at `start`.
    pub from: u8,
    /// Level at `end`.
    pub target: u8,
    /// Start time.
    pub start: Instant,
    /// End time.
    pub end: Instant,
    /// 'With On/Off' command: reaching the minimum level turns off.
    pub with_on_off: bool,
    /// `CurrentLevel` before an On / Off command (Table 3-55).
    pub stored: Option<u8>,
    /// Restore `stored` when the current fade completes.
    pub restore_after: bool,
}

/// Builds a server instance with the given level range: `CurrentLevel`
/// (default reporting), `RemainingTime`, `MinLevel`, `MaxLevel`,
/// `Options`, the On/Off coupling attributes and `StartUpCurrentLevel`.
pub fn server<const A: usize>(min: u8, max: u8) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    let one = |v: u8| Value::Uint {
        width: 1,
        value: u64::from(v),
    };
    let two = |v: u16| Value::Uint {
        width: 2,
        value: u64::from(v),
    };
    c.add_reported_attribute(CURRENT_LEVEL, &one(min), DEFAULT_REPORTING)?;
    c.add_attribute(REMAINING_TIME, &two(0))?;
    c.add_attribute(MIN_LEVEL, &one(min))?;
    c.add_attribute(MAX_LEVEL, &one(max))?;
    c.add_attribute(OPTIONS, &Value::Bits { width: 1, bits: 0 })?;
    c.add_attribute(ON_OFF_TRANSITION_TIME, &two(0))?;
    c.add_attribute(ON_LEVEL, &one(ON_LEVEL_UNDEFINED))?;
    c.add_attribute(ON_TRANSITION_TIME, &two(TIME_UNDEFINED))?;
    c.add_attribute(OFF_TRANSITION_TIME, &two(TIME_UNDEFINED))?;
    c.add_attribute(DEFAULT_MOVE_RATE, &one(50))?;
    c.add_attribute(START_UP_CURRENT_LEVEL, &one(0xff))?;
    c.state = ClusterState::Level(Transition::default());
    c.write_guard = Some(guard);
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// Builds a Level Control for Lighting server (§3.19): the level range
/// is 1…0xfe (0 is never used, 0xff undefined).
pub fn lighting_server<const A: usize>(min: u8, max: u8) -> Result<ClusterInstance<A>, ZclStatus> {
    if min == 0 || max > 0xfe || min > max {
        return Err(ZclStatus::InvalidValue);
    }
    server(min, max)
}

/// Adds the frequency attributes (`CurrentFrequency` reported,
/// `MinFrequency` / `MaxFrequency` in 10 Hz, 0 = undefined) and the
/// Move to Closest Frequency command to a server (§3.10.2.2.5–7).
pub fn enable_frequency<const A: usize>(
    c: &mut ClusterInstance<A>,
    min: u16,
    max: u16,
) -> Result<(), ZclStatus> {
    if min != 0 && max != 0 && min > max {
        return Err(ZclStatus::InvalidValue);
    }
    let two = |v: u16| Value::Uint {
        width: 2,
        value: u64::from(v),
    };
    c.add_reported_attribute(CURRENT_FREQUENCY, &two(0), DEFAULT_REPORTING)?;
    c.add_attribute(MIN_FREQUENCY, &two(min))?;
    c.add_attribute(MAX_FREQUENCY, &two(max))?;
    if c.def.id == ID {
        c.def = FREQUENCY_DEF;
    }
    Ok(())
}

/// Builds a Pulse Width Modulation server (§3.20): the duty cycle
/// `min..=max` percent (at most 100) and the frequency range in 10 Hz.
pub fn pwm_server<const A: usize>(
    min: u8,
    max: u8,
    min_frequency: u16,
    max_frequency: u16,
) -> Result<ClusterInstance<A>, ZclStatus> {
    if max > 100 || min > max {
        return Err(ZclStatus::InvalidValue);
    }
    let mut c = server(min, max)?;
    c.def = PWM_DEF;
    enable_frequency(&mut c, min_frequency, max_frequency)?;
    Ok(c)
}

/// `CurrentFrequency` (0 unknown / unsupported).
pub fn current_frequency<const A: usize>(c: &ClusterInstance<A>) -> u16 {
    c.u16(CURRENT_FREQUENCY.id).unwrap_or(0)
}

/// Sets `CurrentFrequency` to the closest supported frequency (the
/// range `MinFrequency`…`MaxFrequency` where defined); returns it.
pub fn set_frequency<const A: usize>(c: &mut ClusterInstance<A>, frequency: u16) -> u16 {
    let min = c.u16(MIN_FREQUENCY.id).unwrap_or(0);
    let max = c.u16(MAX_FREQUENCY.id).unwrap_or(0);
    let mut f = frequency;
    if min != 0 {
        f = f.max(min);
    }
    if max != 0 {
        f = f.min(max);
    }
    c.set_u16(CURRENT_FREQUENCY.id, f);
    f
}

/// The colour temperature coupled to `CurrentLevel` (§5.2.2.1.1): the
/// maximum level maps to `couple_min_mireds` (the coolest coupled
/// colour), the minimum level to `physical_max_mireds` (the warmest),
/// linearly in between like an incandescent bulb dimming down.
pub fn coupled_mireds<const A: usize>(
    c: &ClusterInstance<A>,
    couple_min_mireds: u16,
    physical_max_mireds: u16,
) -> u16 {
    let (min, max, cur) = (min_level(c), max_level(c), current_level(c));
    if max <= min || physical_max_mireds <= couple_min_mireds {
        return couple_min_mireds;
    }
    let span = u32::from(physical_max_mireds - couple_min_mireds);
    let pos = u32::from(cur.clamp(min, max) - min);
    let range = u32::from(max - min);
    let warm = span - span * pos / range;
    u16::try_from(u32::from(couple_min_mireds) + warm).unwrap_or(physical_max_mireds)
}

/// Range checks of Table 3-56 for network writes.
fn guard<const A: usize>(
    t: &crate::attribute::AttributeTable<A>,
    id: panweave_types::AttributeId,
    v: &Value<'_>,
) -> ZclStatus {
    let Some(value) = v.as_u64() else {
        return ZclStatus::Success;
    };
    let min = t.u64(MIN_LEVEL.id).unwrap_or(0);
    let max = t.u64(MAX_LEVEL.id).unwrap_or(0xfe);
    let ok = match id {
        i if i == ON_LEVEL.id => {
            value == u64::from(ON_LEVEL_UNDEFINED) || (min..=max).contains(&value)
        }
        i if i == ON_TRANSITION_TIME.id || i == OFF_TRANSITION_TIME.id => true,
        i if i == DEFAULT_MOVE_RATE.id => value <= 0xfe,
        i if i == START_UP_CURRENT_LEVEL.id => true,
        _ => true,
    };
    if ok {
        ZclStatus::Success
    } else {
        ZclStatus::InvalidValue
    }
}

/// `CurrentLevel`.
pub fn current_level<const A: usize>(c: &ClusterInstance<A>) -> u8 {
    c.u8(CURRENT_LEVEL.id).unwrap_or(0)
}

fn min_level<const A: usize>(c: &ClusterInstance<A>) -> u8 {
    c.u8(MIN_LEVEL.id).unwrap_or(0)
}

fn max_level<const A: usize>(c: &ClusterInstance<A>) -> u8 {
    c.u8(MAX_LEVEL.id).unwrap_or(0xfe)
}

fn transition<const A: usize>(c: &mut ClusterInstance<A>) -> &mut Transition {
    if !matches!(c.state, ClusterState::Level(_)) {
        c.state = ClusterState::Level(Transition::default());
    }
    match &mut c.state {
        ClusterState::Level(t) => t,
        // Just installed above.
        _ => unreachable!(),
    }
}

/// Result of a received Level Control server command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// A transition (or an immediate change) was applied; `turn_on` asks
    /// the dispatcher to set `OnOff` = 1 on the endpoint ('with On/Off',
    /// §3.10.2.3.6).
    Applied {
        /// Set the On/Off cluster on.
        turn_on: bool,
    },
    /// Not executed: the endpoint is off and ExecuteIfOff is clear
    /// (§3.10.2.2.8.1).
    Suppressed,
    /// Move to Closest Frequency set `CurrentFrequency` (§3.10.2.3.5).
    Frequency(u16),
    /// Malformed or unsupported command.
    Default(ZclStatus),
}

/// Starts a transition from the current level to `target` taking
/// `tenths` tenths of a second (0 = immediate).
pub fn start<const A: usize>(
    c: &mut ClusterInstance<A>,
    target: u8,
    tenths: u16,
    with_on_off: bool,
    now: Instant,
) {
    let from = current_level(c);
    let target = target.clamp(min_level(c), max_level(c));
    let t = transition(c);
    t.active = true;
    t.from = from;
    t.target = target;
    t.start = now;
    t.end = now + Duration::from_millis(u64::from(tenths) * 100);
    t.with_on_off = with_on_off;
    t.restore_after = false;
    c.tick = Some(now);
}

/// Stops the transition in progress at the current level (§3.10.2.3.4).
pub fn stop<const A: usize>(c: &mut ClusterInstance<A>) {
    let t = transition(c);
    t.active = false;
    t.restore_after = false;
    t.stored = None;
    c.tick = None;
    c.set_u16(REMAINING_TIME.id, 0);
}

/// Processes a cluster-specific command received by the server
/// (§3.10.2.3). `on_off` is the endpoint's `OnOff` value when an On/Off
/// server exists on the endpoint.
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    command: CommandId,
    payload: &[u8],
    on_off: Option<bool>,
    now: Instant,
) -> Outcome {
    let with_on_off = matches!(
        command,
        CMD_MOVE_TO_LEVEL_WITH_ON_OFF | CMD_MOVE_WITH_ON_OFF | CMD_STEP_WITH_ON_OFF
    );
    let mut r = Reader::new(payload);
    // Fixed fields first, then the OptionsMask / OptionsOverride pair
    // (missing from legacy devices: defaults 0 / 0, §3.10.2.3.1.2).
    let parsed = match command {
        CMD_MOVE_TO_LEVEL | CMD_MOVE_TO_LEVEL_WITH_ON_OFF => {
            let (Ok(level), Ok(time)) = (r.u8(), r.u16_le()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            Parsed::MoveTo { level, time }
        }
        CMD_MOVE | CMD_MOVE_WITH_ON_OFF => {
            let (Ok(mode), Ok(rate)) = (r.u8(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            if mode > MODE_DOWN {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            Parsed::Move {
                up: mode == MODE_UP,
                rate,
            }
        }
        CMD_STEP | CMD_STEP_WITH_ON_OFF => {
            let (Ok(mode), Ok(size), Ok(time)) = (r.u8(), r.u8(), r.u16_le()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            if mode > MODE_DOWN {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            Parsed::Step {
                up: mode == MODE_UP,
                size,
                time,
            }
        }
        CMD_STOP | CMD_STOP_WITH_ON_OFF => Parsed::Stop,
        CMD_MOVE_TO_CLOSEST_FREQUENCY => {
            if c.attributes.get(CURRENT_FREQUENCY.id, None).is_none() {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let Ok(frequency) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            // Any frequency within the range is approximated by clamping;
            // a range the device cannot approach at all is refused.
            let min = c.u16(MIN_FREQUENCY.id).unwrap_or(0);
            let max = c.u16(MAX_FREQUENCY.id).unwrap_or(0);
            if frequency == 0
                || (min != 0
                    && max != 0
                    && (frequency < min / 2 || frequency > max.saturating_mul(2)))
            {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            return Outcome::Frequency(set_frequency(c, frequency));
        }
        _ => return Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    };
    let mask = r.u8().unwrap_or(0);
    let over = r.u8().unwrap_or(0);
    let options = c.u8(OPTIONS.id).unwrap_or(0);
    let temp = (options & !mask) | (over & mask);
    if !with_on_off && on_off == Some(false) && temp & OPTION_EXECUTE_IF_OFF == 0 {
        return Outcome::Suppressed;
    }
    let (min, max, cur) = (min_level(c), max_level(c), current_level(c));
    match parsed {
        Parsed::MoveTo { level, time } => {
            let tenths = if time == TIME_UNDEFINED {
                c.u16(ON_OFF_TRANSITION_TIME.id).unwrap_or(0)
            } else {
                time
            };
            let target = level.clamp(min, max);
            start(c, target, tenths, with_on_off, now);
            Outcome::Applied {
                turn_on: with_on_off && target > min,
            }
        }
        Parsed::Move { up, rate } => {
            let rate = if rate == 0xff {
                c.u8(DEFAULT_MOVE_RATE.id).unwrap_or(0xff)
            } else {
                rate
            };
            let target = if up { max } else { min };
            let distance = u16::from(target.abs_diff(cur));
            let tenths = if rate == 0 || rate == 0xff {
                0
            } else {
                // units / (units per second) in tenths, rounded up.
                (distance * 10).div_ceil(u16::from(rate))
            };
            start(c, target, tenths, with_on_off, now);
            Outcome::Applied {
                turn_on: with_on_off && target > min,
            }
        }
        Parsed::Step { up, size, time } => {
            let target = if up {
                cur.saturating_add(size).min(max)
            } else {
                cur.saturating_sub(size).max(min)
            };
            let actual = u16::from(target.abs_diff(cur));
            let tenths = if time == TIME_UNDEFINED || size == 0 {
                0
            } else {
                // Proportionally reduced when clamped (Table 3-63).
                u16::try_from(u32::from(time) * u32::from(actual) / u32::from(size))
                    .unwrap_or(u16::MAX)
            };
            start(c, target, tenths, with_on_off, now);
            Outcome::Applied {
                turn_on: with_on_off && target > min,
            }
        }
        Parsed::Stop => {
            stop(c);
            Outcome::Applied { turn_on: false }
        }
    }
}

enum Parsed {
    MoveTo { level: u8, time: u16 },
    Move { up: bool, rate: u8 },
    Step { up: bool, size: u8, time: u16 },
    Stop,
}

/// Effect of an On / Off command received by the On/Off cluster of the
/// same endpoint (Table 3-55).
pub fn on_off_effect<const A: usize>(c: &mut ClusterInstance<A>, on: bool, now: Instant) {
    let (min, cur) = (min_level(c), current_level(c));
    let on_level = c.u8(ON_LEVEL.id).filter(|l| *l != ON_LEVEL_UNDEFINED);
    let on_off_time = c.u16(ON_OFF_TRANSITION_TIME.id).unwrap_or(0);
    let on_time = c
        .u16(ON_TRANSITION_TIME.id)
        .filter(|t| *t != TIME_UNDEFINED)
        .unwrap_or(on_off_time);
    let off_time = c
        .u16(OFF_TRANSITION_TIME.id)
        .filter(|t| *t != TIME_UNDEFINED)
        .unwrap_or(on_off_time);
    // The level in effect before the first of a burst of On/Off commands
    // is what gets restored (§3.10.2.1.1).
    let stored = {
        let t = transition(c);
        *t.stored.get_or_insert(cur)
    };
    if on {
        c.set_u8(CURRENT_LEVEL.id, min);
        let target = on_level.unwrap_or(stored);
        start(c, target, on_time, false, now);
        let t = transition(c);
        t.restore_after = false;
        if on_level.is_some() {
            t.stored = None;
        }
    } else {
        start(c, min, off_time, false, now);
        let t = transition(c);
        t.restore_after = on_level.is_none();
        if on_level.is_some() {
            t.stored = None;
        }
    }
}

/// Result of a transition tick.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tick {
    /// The new `CurrentLevel`.
    pub level: u8,
    /// `CurrentLevel` changed.
    pub changed: bool,
    /// The transition completed.
    pub done: bool,
    /// A 'with On/Off' transition reached the minimum level: the On/Off
    /// cluster turns off (§3.10.2.3.6).
    pub turn_off: bool,
}

/// Advances the transition; returns the tick result when one ran.
pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<Tick> {
    let due = c.tick?;
    if !now.has_reached(due) {
        return None;
    }
    let t = *transition(c);
    if !t.active {
        c.tick = None;
        return None;
    }
    let min = min_level(c);
    let total = t.end.saturating_duration_since(t.start).as_millis();
    let elapsed = now.saturating_duration_since(t.start).as_millis();
    let done = elapsed >= total;
    let level = if done {
        t.target
    } else {
        let span = i64::from(t.target) - i64::from(t.from);
        let elapsed = i64::try_from(elapsed).unwrap_or(i64::MAX);
        let total = i64::try_from(total.max(1)).unwrap_or(i64::MAX);
        let delta = span.saturating_mul(elapsed) / total;
        u8::try_from(i64::from(t.from) + delta).unwrap_or(t.target)
    };
    let remaining = if done {
        0
    } else {
        u16::try_from(total.saturating_sub(elapsed).div_ceil(100)).unwrap_or(u16::MAX)
    };
    let mut changed = c.set_u8(CURRENT_LEVEL.id, level);
    c.set_u16(REMAINING_TIME.id, remaining);
    let mut turn_off = false;
    if done {
        let tr = transition(c);
        tr.active = false;
        let restore = tr.restore_after.then_some(tr.stored).flatten();
        tr.restore_after = false;
        tr.stored = None;
        turn_off = t.with_on_off && level == min;
        if let Some(level) = restore {
            changed |= c.set_u8(CURRENT_LEVEL.id, level);
        }
        c.tick = None;
    } else {
        c.tick = Some(now + TICK);
    }
    Some(Tick {
        level: current_level(c),
        changed,
        done,
        turn_off,
    })
}

/// Applies `StartUpCurrentLevel` at power-up (Table 3-58) given the
/// previous level; returns the resulting level.
pub fn start_up<const A: usize>(c: &mut ClusterInstance<A>, previous: u8) -> u8 {
    let v = match c.u8(START_UP_CURRENT_LEVEL.id) {
        Some(0x00) => min_level(c),
        Some(0xff) | None => previous,
        Some(v) => v.clamp(min_level(c), max_level(c)),
    };
    c.set_u8(CURRENT_LEVEL.id, v);
    v
}

/// Scene extension field set of the Level Control server (§3.10.2.5):
/// `CurrentLevel`.
pub fn scene_fields<const A: usize>(c: &ClusterInstance<A>) -> [u8; 1] {
    [current_level(c)]
}

/// Applies a scene extension field set over `tenths` tenths of a second.
pub fn apply_scene_fields<const A: usize>(
    c: &mut ClusterInstance<A>,
    fields: &[u8],
    tenths: u16,
    now: Instant,
) -> Option<u8> {
    let level = *fields.first()?;
    start(c, level, tenths, false, now);
    Some(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_lighting_and_pwm() {
        let t0 = Instant::from_millis(0);
        assert!(lighting_server::<16>(0, 254).is_err());
        assert!(lighting_server::<16>(1, 255).is_err());
        let mut c: ClusterInstance<16> = lighting_server(1, 254).unwrap();
        // Without the frequency attributes the command is unsupported.
        assert_eq!(
            handle(
                &mut c,
                CMD_MOVE_TO_CLOSEST_FREQUENCY,
                &[0x10, 0x27],
                None,
                t0
            ),
            Outcome::Default(ZclStatus::UnsupportedClusterCommand)
        );
        enable_frequency(&mut c, 100, 1000).unwrap();
        assert!(c.def.received.contains(&CMD_MOVE_TO_CLOSEST_FREQUENCY));
        assert_eq!(current_frequency(&c), 0);
        // 5 kHz (500 x 10 Hz) is within range; 20 kHz clamps to the
        // maximum; 1 Hz is too far below to approximate.
        assert_eq!(
            handle(
                &mut c,
                CMD_MOVE_TO_CLOSEST_FREQUENCY,
                &[0xf4, 0x01],
                None,
                t0
            ),
            Outcome::Frequency(500)
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_MOVE_TO_CLOSEST_FREQUENCY,
                &[0xd0, 0x07],
                None,
                t0
            ),
            Outcome::Frequency(1000)
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_MOVE_TO_CLOSEST_FREQUENCY,
                &[0x01, 0x00],
                None,
                t0
            ),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        assert_eq!(
            handle(&mut c, CMD_MOVE_TO_CLOSEST_FREQUENCY, &[0x01], None, t0),
            Outcome::Default(ZclStatus::MalformedCommand)
        );
        assert_eq!(current_frequency(&c), 1000);
        // Coupled colour temperature: full level is the coolest coupled
        // mireds, the minimum level the warmest physical value.
        c.set_u8(CURRENT_LEVEL.id, 254);
        assert_eq!(coupled_mireds(&c, 153, 500), 153);
        c.set_u8(CURRENT_LEVEL.id, 1);
        assert_eq!(coupled_mireds(&c, 153, 500), 500);
        c.set_u8(CURRENT_LEVEL.id, 128);
        let mid = coupled_mireds(&c, 153, 500);
        assert!((320..=330).contains(&mid), "{mid}");
        // PWM: a duty cycle of at most 100 %, the frequency range built in.
        assert!(pwm_server::<16>(0, 101, 0, 0).is_err());
        let mut p: ClusterInstance<16> = pwm_server(0, 100, 1, 5000).unwrap();
        assert_eq!(p.def.id, PWM_ID);
        assert_eq!(max_level(&p), 100);
        assert_eq!(
            handle(&mut p, CMD_MOVE_TO_LEVEL, &[50, 0, 0], None, t0),
            Outcome::Applied { turn_on: false }
        );
        assert_eq!(set_frequency(&mut p, 6000), 5000);
    }
}
