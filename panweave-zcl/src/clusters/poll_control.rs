//! Poll Control cluster (ZCL8 §3.16), revision 1: the server side run by a
//! sleepy end device (check-ins on `CheckInInterval`, fast poll mode on
//! request) and the client side that answers check-ins. The MAC data
//! poll rate itself belongs to the runtime, which reacts to the
//! [`Outcome`]s and ticks.

use panweave_codec::Reader;
use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, AttributeTable};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0020);
/// `CheckInInterval` (quarter-seconds; 0 disables check-ins).
pub const CHECK_IN_INTERVAL: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(4), Access::RW);
/// `LongPollInterval` (quarter-seconds).
pub const LONG_POLL_INTERVAL: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(4), Access::RO);
/// `ShortPollInterval` (quarter-seconds).
pub const SHORT_POLL_INTERVAL: AttributeDef =
    AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
/// `FastPollTimeout` (quarter-seconds).
pub const FAST_POLL_TIMEOUT: AttributeDef =
    AttributeDef::new(0x0003, DataType::Uint(2), Access::RW);
/// `CheckInIntervalMin`.
pub const CHECK_IN_INTERVAL_MIN: AttributeDef =
    AttributeDef::new(0x0004, DataType::Uint(4), Access::RO);
/// `LongPollIntervalMin`.
pub const LONG_POLL_INTERVAL_MIN: AttributeDef =
    AttributeDef::new(0x0005, DataType::Uint(4), Access::RO);
/// `FastPollTimeoutMax`.
pub const FAST_POLL_TIMEOUT_MAX: AttributeDef =
    AttributeDef::new(0x0006, DataType::Uint(2), Access::RO);

/// Check-in (server → client).
pub const CMD_CHECK_IN: CommandId = CommandId(0x00);
/// Check-in Response (client → server).
pub const CMD_CHECK_IN_RESPONSE: CommandId = CommandId(0x00);
/// Fast Poll Stop.
pub const CMD_FAST_POLL_STOP: CommandId = CommandId(0x01);
/// Set Long Poll Interval.
pub const CMD_SET_LONG_POLL_INTERVAL: CommandId = CommandId(0x02);
/// Set Short Poll Interval.
pub const CMD_SET_SHORT_POLL_INTERVAL: CommandId = CommandId(0x03);

/// Largest interval (quarter-seconds, Table 3-132).
pub const MAX_INTERVAL: u32 = 0x6E_0000;
/// Time the server waits for Check-in Responses after a check-in, in
/// temporary fast poll mode (§3.16.4.4: 7.68 s).
pub const CHECK_IN_RESPONSE_WAIT: Duration = Duration::from_millis(7680);

/// Table 3-132 defaults.
pub mod defaults {
    /// `CheckInInterval`: one hour.
    pub const CHECK_IN_INTERVAL: u32 = 0x3840;
    /// `LongPollInterval`: 5 s.
    pub const LONG_POLL_INTERVAL: u32 = 0x14;
    /// `ShortPollInterval`: 0.5 s.
    pub const SHORT_POLL_INTERVAL: u16 = 0x02;
    /// `FastPollTimeout`: 10 s.
    pub const FAST_POLL_TIMEOUT: u16 = 0x28;
}

/// Server definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_CHECK_IN_RESPONSE,
        CMD_FAST_POLL_STOP,
        CMD_SET_LONG_POLL_INTERVAL,
        CMD_SET_SHORT_POLL_INTERVAL,
    ],
    generated: &[CMD_CHECK_IN],
};

/// Client definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_CHECK_IN],
    generated: &[
        CMD_CHECK_IN_RESPONSE,
        CMD_FAST_POLL_STOP,
        CMD_SET_LONG_POLL_INTERVAL,
        CMD_SET_SHORT_POLL_INTERVAL,
    ],
};

/// Poll Control state (server timers, client policy).
#[derive(Clone, Copy, Debug, Default)]
pub struct State {
    /// Next check-in.
    pub next_check_in: Option<Instant>,
    /// `CheckInInterval` the schedule was derived from (§3.16.6.3).
    pub scheduled_interval: u32,
    /// End of the temporary fast poll mode awaiting Check-in Responses.
    pub awaiting_until: Option<Instant>,
    /// End of the requested fast poll mode.
    pub fast_poll_until: Option<Instant>,
    /// Client: ask servers to fast poll on check-in.
    pub client_start_fast_polling: bool,
    /// Client: Fast Poll Timeout sent in Check-in Responses (0 = the
    /// server's `FastPollTimeout`).
    pub client_fast_poll_timeout: u16,
}

/// Converts quarter-seconds to a duration.
pub const fn quarter_seconds(q: u32) -> Duration {
    Duration::from_millis(q as u64 * 250)
}

/// Builds a server instance with the Table 3-132 defaults and the
/// battery-protection minima / maxima given.
pub fn server<const A: usize>(
    check_in_interval_min: u32,
    long_poll_interval_min: u32,
    fast_poll_timeout_max: u16,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(SERVER_DEF, Role::Server);
    let four = |v: u32| Value::Uint {
        width: 4,
        value: u64::from(v),
    };
    let two = |v: u16| Value::Uint {
        width: 2,
        value: u64::from(v),
    };
    c.add_attribute(CHECK_IN_INTERVAL, &four(defaults::CHECK_IN_INTERVAL))?;
    c.add_attribute(LONG_POLL_INTERVAL, &four(defaults::LONG_POLL_INTERVAL))?;
    c.add_attribute(SHORT_POLL_INTERVAL, &two(defaults::SHORT_POLL_INTERVAL))?;
    c.add_attribute(FAST_POLL_TIMEOUT, &two(defaults::FAST_POLL_TIMEOUT))?;
    c.add_attribute(CHECK_IN_INTERVAL_MIN, &four(check_in_interval_min))?;
    c.add_attribute(LONG_POLL_INTERVAL_MIN, &four(long_poll_interval_min))?;
    c.add_attribute(FAST_POLL_TIMEOUT_MAX, &two(fast_poll_timeout_max))?;
    c.state = ClusterState::PollControl(State::default());
    c.write_guard = Some(guard);
    Ok(c)
}

/// Builds a client instance with its check-in policy.
pub fn client<const A: usize>(
    start_fast_polling: bool,
    fast_poll_timeout: u16,
) -> ClusterInstance<A> {
    let mut c = ClusterInstance::new(CLIENT_DEF, Role::Client);
    c.state = ClusterState::PollControl(State {
        client_start_fast_polling: start_fast_polling,
        client_fast_poll_timeout: fast_poll_timeout,
        ..State::default()
    });
    c
}

/// Validation of network writes (§3.16.4.1.1, §3.16.4.1.4).
fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
    let Some(value) = v.as_u64() else {
        return ZclStatus::Success;
    };
    let ok = if id == CHECK_IN_INTERVAL.id {
        let min = t.u64(CHECK_IN_INTERVAL_MIN.id).unwrap_or(0);
        let long = t.u64(LONG_POLL_INTERVAL.id).unwrap_or(0);
        value == 0 || (value <= u64::from(MAX_INTERVAL) && value >= min && value >= long)
    } else if id == FAST_POLL_TIMEOUT.id {
        let max = t.u64(FAST_POLL_TIMEOUT_MAX.id).unwrap_or(0xffff);
        (1..=0xffff).contains(&value) && (max == 0 || value <= max)
    } else {
        true
    };
    if ok {
        ZclStatus::Success
    } else {
        ZclStatus::InvalidValue
    }
}

fn state<const A: usize>(c: &mut ClusterInstance<A>) -> &mut State {
    if !matches!(c.state, ClusterState::PollControl(_)) {
        c.state = ClusterState::PollControl(State::default());
    }
    match &mut c.state {
        ClusterState::PollControl(s) => s,
        // Just installed above.
        _ => unreachable!(),
    }
}

fn rearm<const A: usize>(c: &mut ClusterInstance<A>) {
    let s = *state(c);
    c.tick = [s.next_check_in, s.awaiting_until, s.fast_poll_until]
        .into_iter()
        .flatten()
        .min_by_key(|t| t.as_millis());
}

/// `LongPollInterval` as a duration.
pub fn long_poll_interval<const A: usize>(c: &ClusterInstance<A>) -> Duration {
    quarter_seconds(
        c.u64(LONG_POLL_INTERVAL.id)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(defaults::LONG_POLL_INTERVAL),
    )
}

/// `ShortPollInterval` as a duration.
pub fn short_poll_interval<const A: usize>(c: &ClusterInstance<A>) -> Duration {
    quarter_seconds(u32::from(
        c.u16(SHORT_POLL_INTERVAL.id)
            .unwrap_or(defaults::SHORT_POLL_INTERVAL),
    ))
}

/// True while the server is in (temporary or requested) fast poll mode.
pub fn fast_polling<const A: usize>(c: &mut ClusterInstance<A>) -> bool {
    let s = *state(c);
    s.awaiting_until.is_some() || s.fast_poll_until.is_some()
}

/// Starts (or restarts, after `CheckInInterval` changed, §3.16.6.3) the
/// check-in schedule.
pub fn start<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) {
    let interval = c
        .u64(CHECK_IN_INTERVAL.id)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let s = state(c);
    s.scheduled_interval = interval;
    s.next_check_in = (interval > 0).then(|| now + quarter_seconds(interval));
    rearm(c);
}

/// What the server timers ask of the runtime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tick {
    /// Send a Check-in to the bound clients and poll at the short
    /// interval while awaiting responses (§3.16.6.2).
    CheckIn,
    /// Fast poll mode ended: back to `LongPollInterval`.
    FastPollEnded,
}

/// Advances the server timers.
pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<Tick> {
    if c.role != Role::Server {
        return None;
    }
    let interval = c
        .u64(CHECK_IN_INTERVAL.id)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    if state(c).scheduled_interval != interval {
        start(c, now);
    }
    let due = c.tick?;
    if !now.has_reached(due) {
        return None;
    }
    let s = state(c);
    if let Some(t) = s.next_check_in
        && now.has_reached(t)
    {
        // §3.16.6.1: the interval between check-ins stays constant.
        s.next_check_in = Some(t + quarter_seconds(s.scheduled_interval.max(1)));
        s.awaiting_until = Some(now + CHECK_IN_RESPONSE_WAIT);
        rearm(c);
        return Some(Tick::CheckIn);
    }
    let mut ended = false;
    if let Some(t) = s.awaiting_until
        && now.has_reached(t)
    {
        s.awaiting_until = None;
        ended = s.fast_poll_until.is_none();
    }
    if let Some(t) = s.fast_poll_until
        && now.has_reached(t)
    {
        s.fast_poll_until = None;
        ended = s.awaiting_until.is_none();
    }
    rearm(c);
    ended.then_some(Tick::FastPollEnded)
}

/// Result of a received Poll Control command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Server: fast poll mode requested until the instant (poll at
    /// `ShortPollInterval`); reply Default Response SUCCESS.
    FastPoll(Instant),
    /// Server: fast poll mode ended (Fast Poll Stop, or a Check-in
    /// Response declining it); reply SUCCESS.
    FastPollEnded,
    /// Server: `LongPollInterval` changed; reply SUCCESS.
    LongPollInterval(Duration),
    /// Server: `ShortPollInterval` changed; reply SUCCESS.
    ShortPollInterval(Duration),
    /// Client: a Check-in arrived; send the Check-in Response payload.
    CheckInResponse([u8; 3]),
    /// Reply with a Default Response.
    Default(ZclStatus),
}

/// Processes a cluster-specific command received by a server or client
/// instance (§3.16.5).
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    command: CommandId,
    payload: &[u8],
    now: Instant,
) -> Outcome {
    let mut r = Reader::new(payload);
    if c.role == Role::Client {
        if command != CMD_CHECK_IN {
            return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
        }
        let s = *state(c);
        let t = s.client_fast_poll_timeout.to_le_bytes();
        return Outcome::CheckInResponse([u8::from(s.client_start_fast_polling), t[0], t[1]]);
    }
    match command {
        CMD_CHECK_IN_RESPONSE => {
            let (Ok(start), Ok(timeout)) = (r.u8(), r.u16_le()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let max = c.u16(FAST_POLL_TIMEOUT_MAX.id).unwrap_or(0);
            if max != 0 && timeout > max {
                return Outcome::Default(ZclStatus::InvalidField);
            }
            let default_timeout = c
                .u16(FAST_POLL_TIMEOUT.id)
                .unwrap_or(defaults::FAST_POLL_TIMEOUT);
            let s = state(c);
            if s.awaiting_until.is_none() && s.fast_poll_until.is_none() {
                // After the temporary fast poll mode (§3.16.5.3).
                return Outcome::Default(ZclStatus::Failure);
            }
            s.awaiting_until = None;
            if start != 0 {
                let t = if timeout == 0 {
                    default_timeout
                } else {
                    timeout
                };
                let until = now + quarter_seconds(u32::from(t));
                // The longest request wins (§3.16.6.2).
                let until = match s.fast_poll_until {
                    Some(u) if u.as_millis() > until.as_millis() => u,
                    _ => until,
                };
                s.fast_poll_until = Some(until);
                rearm(c);
                Outcome::FastPoll(until)
            } else if s.fast_poll_until.is_none() {
                rearm(c);
                Outcome::FastPollEnded
            } else {
                rearm(c);
                Outcome::Default(ZclStatus::Success)
            }
        }
        CMD_FAST_POLL_STOP => {
            let s = state(c);
            if s.fast_poll_until.is_none() {
                return Outcome::Default(ZclStatus::Failure);
            }
            s.fast_poll_until = None;
            let ended = s.awaiting_until.is_none();
            rearm(c);
            if ended {
                Outcome::FastPollEnded
            } else {
                Outcome::Default(ZclStatus::Success)
            }
        }
        CMD_SET_LONG_POLL_INTERVAL => {
            let Ok(v) = r.u32_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let min = c.u64(LONG_POLL_INTERVAL_MIN.id).unwrap_or(0);
            let short = c.u64(SHORT_POLL_INTERVAL.id).unwrap_or(0);
            let check_in = c.u64(CHECK_IN_INTERVAL.id).unwrap_or(0);
            let v64 = u64::from(v);
            if v == 0
                || v > MAX_INTERVAL
                || v64 < min
                || v64 < short
                || (check_in != 0 && v64 > check_in)
            {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            c.set(
                LONG_POLL_INTERVAL.id,
                &Value::Uint {
                    width: 4,
                    value: v64,
                },
            );
            Outcome::LongPollInterval(quarter_seconds(v))
        }
        CMD_SET_SHORT_POLL_INTERVAL => {
            let Ok(v) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let long = c.u64(LONG_POLL_INTERVAL.id).unwrap_or(0);
            if v == 0 || u64::from(v) > long {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            c.set_u16(SHORT_POLL_INTERVAL.id, v);
            Outcome::ShortPollInterval(quarter_seconds(u32::from(v)))
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}
