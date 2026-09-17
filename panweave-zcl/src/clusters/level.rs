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

/// `Options` bit: execute the 'without On/Off' commands while off.
pub const OPTION_EXECUTE_IF_OFF: u8 = 0x01;

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
    ClusterInstance::new(DEF, Role::Client)
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
