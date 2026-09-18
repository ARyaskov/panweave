//! On/Off cluster (ZCL8 §3.8), revision 2: `OnOff` with the global scene
//! and timed-off attributes, executed by the endpoint dispatcher. The
//! cross-cluster effects (Level Control fades, the global scene) are
//! applied by the dispatcher, which sees every cluster of the endpoint.

use panweave_codec::Reader;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0006);
/// `OnOff` (reportable, scene).
pub const ON_OFF: AttributeDef = AttributeDef::new(0x0000, DataType::Bool, Access::RO_REPORT);
/// `GlobalSceneControl`.
pub const GLOBAL_SCENE_CONTROL: AttributeDef =
    AttributeDef::new(0x4000, DataType::Bool, Access::RO);
/// `OnTime` (tenths of a second).
pub const ON_TIME: AttributeDef = AttributeDef::new(0x4001, DataType::Uint(2), Access::RW);
/// `OffWaitTime` (tenths of a second).
pub const OFF_WAIT_TIME: AttributeDef = AttributeDef::new(0x4002, DataType::Uint(2), Access::RW);
/// `StartUpOnOff`.
pub const START_UP_ON_OFF: AttributeDef = AttributeDef::new(0x4003, DataType::Enum8, Access::RW);

/// Off command.
pub const CMD_OFF: CommandId = CommandId(0x00);
/// On command.
pub const CMD_ON: CommandId = CommandId(0x01);
/// Toggle command.
pub const CMD_TOGGLE: CommandId = CommandId(0x02);
/// Off With Effect command.
pub const CMD_OFF_WITH_EFFECT: CommandId = CommandId(0x40);
/// On With Recall Global Scene command.
pub const CMD_ON_WITH_RECALL_GLOBAL_SCENE: CommandId = CommandId(0x41);
/// On With Timed Off command.
pub const CMD_ON_WITH_TIMED_OFF: CommandId = CommandId(0x42);

/// Default reporting of `OnOff` (BDB 3.1 §6.5): on change, and at least
/// every 5 minutes.
pub const DEFAULT_REPORTING: DefaultReporting = DefaultReporting {
    min: 0,
    max: 300,
    change: 0,
};

/// `StartUpOnOff` values (Table 3-46).
pub mod start_up {
    /// Off.
    pub const OFF: u8 = 0x00;
    /// On.
    pub const ON: u8 = 0x01;
    /// Toggle the previous value.
    pub const TOGGLE: u8 = 0x02;
    /// Previous value.
    pub const PREVIOUS: u8 = 0xff;
}

/// Off With Effect identifiers (Table 3-48).
pub mod effect {
    /// Delayed All Off.
    pub const DELAYED_ALL_OFF: u8 = 0x00;
    /// Dying Light.
    pub const DYING_LIGHT: u8 = 0x01;
}

/// Period of the OnTime / OffWaitTime countdown (§3.8.2.3.6.4).
pub const TICK: Duration = Duration::from_millis(100);

/// Cluster definition (all commands).
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[
        CMD_OFF,
        CMD_ON,
        CMD_TOGGLE,
        CMD_OFF_WITH_EFFECT,
        CMD_ON_WITH_RECALL_GLOBAL_SCENE,
        CMD_ON_WITH_TIMED_OFF,
    ],
    generated: &[],
};

/// Builds a server instance: `OnOff` = false with its default reporting
/// configuration, `GlobalSceneControl`, `OnTime`, `OffWaitTime` and
/// `StartUpOnOff` (previous value).
pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_reported_attribute(ON_OFF, &Value::Bool(Some(false)), DEFAULT_REPORTING)?;
    c.add_attribute(GLOBAL_SCENE_CONTROL, &Value::Bool(Some(true)))?;
    c.add_attribute(ON_TIME, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(OFF_WAIT_TIME, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(START_UP_ON_OFF, &Value::Enum8(start_up::PREVIOUS))?;
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// Current `OnOff` value.
pub fn is_on<const A: usize>(c: &ClusterInstance<A>) -> bool {
    c.bool(ON_OFF.id)
}

/// Sets `OnOff` directly (Level Control 'with On/Off' commands, scene
/// recall, §3.8.2.1 / §3.8.2.2.2): maintains `OnTime`, `OffWaitTime` and
/// `GlobalSceneControl`. Returns whether the value changed.
pub fn set_on<const A: usize>(c: &mut ClusterInstance<A>, on: bool, now: Instant) -> bool {
    let changed = c.set_bool(ON_OFF.id, on);
    if on {
        if c.u16(ON_TIME.id) == Some(0) {
            c.set_u16(OFF_WAIT_TIME.id, 0);
        }
        c.set_bool(GLOBAL_SCENE_CONTROL.id, true);
    } else {
        c.set_u16(ON_TIME.id, 0);
    }
    arm(c, now);
    changed
}

/// Arms the 100 ms countdown while OnTime or OffWaitTime run (§3.8.2.4).
fn arm<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) {
    let on_time = c.u16(ON_TIME.id).unwrap_or(0);
    let off_wait = c.u16(OFF_WAIT_TIME.id).unwrap_or(0);
    let on = is_on(c);
    let running =
        (on && (1..0xffff).contains(&on_time)) || (!on && (1..0xffff).contains(&off_wait));
    if running {
        if c.tick.is_none() {
            c.tick = Some(now + TICK);
        }
    } else {
        c.tick = None;
    }
}

/// Result of a received On/Off server command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// `OnOff` was set (possibly unchanged) to this value.
    Set(bool),
    /// Off With Effect (§3.8.2.3.4.3): the caller stores the global scene
    /// when `store_global_scene` is set, then applies
    /// [`turn_off_with_effect`]; the device performs the effect.
    OffWithEffect {
        /// Effect identifier.
        effect: u8,
        /// Effect variant.
        variant: u8,
        /// Store the global scene before turning off.
        store_global_scene: bool,
    },
    /// On With Recall Global Scene: recall the global scene (§3.8.2.3.5).
    RecallGlobalScene,
    /// The command was discarded (§3.8.2.3.5.1, §3.8.2.3.6.4).
    Discarded,
    /// Malformed or unsupported command.
    Default(ZclStatus),
}

/// Applies an Off / On / Toggle command to the server's `OnOff`
/// attribute (§3.8.2.3.1–§3.8.2.3.3). Returns the new state or `None`
/// for an unsupported command.
pub fn apply<const A: usize>(
    c: &mut ClusterInstance<A>,
    command: CommandId,
    now: Instant,
) -> Option<bool> {
    match handle(c, command, &[], now) {
        Outcome::Set(on) => Some(on),
        _ => None,
    }
}

/// Processes a cluster-specific command received by the server
/// (§3.8.2.3). The dispatcher applies the outcome to the other clusters
/// of the endpoint.
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    command: CommandId,
    payload: &[u8],
    now: Instant,
) -> Outcome {
    let on = is_on(c);
    match command {
        CMD_OFF => {
            set_on(c, false, now);
            Outcome::Set(false)
        }
        CMD_ON => {
            set_on(c, true, now);
            Outcome::Set(true)
        }
        CMD_TOGGLE => {
            set_on(c, !on, now);
            Outcome::Set(!on)
        }
        CMD_OFF_WITH_EFFECT => {
            let mut r = Reader::new(payload);
            let (Ok(effect), Ok(variant)) = (r.u8(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            // The dispatcher stores the global scene (while still on)
            // and then calls [`turn_off_with_effect`].
            let store_global_scene = c.bool(GLOBAL_SCENE_CONTROL.id);
            Outcome::OffWithEffect {
                effect,
                variant,
                store_global_scene,
            }
        }
        CMD_ON_WITH_RECALL_GLOBAL_SCENE => {
            if c.bool(GLOBAL_SCENE_CONTROL.id) {
                return Outcome::Discarded;
            }
            // The scene sets OnOff; GlobalSceneControl and OffWaitTime
            // follow §3.8.2.3.5.1.
            c.set_bool(GLOBAL_SCENE_CONTROL.id, true);
            if c.u16(ON_TIME.id) == Some(0) {
                c.set_u16(OFF_WAIT_TIME.id, 0);
            }
            Outcome::RecallGlobalScene
        }
        CMD_ON_WITH_TIMED_OFF => {
            let mut r = Reader::new(payload);
            let (Ok(control), Ok(on_time), Ok(off_wait)) = (r.u8(), r.u16_le(), r.u16_le()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            if on_time == 0xffff || off_wait == 0xffff {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if control & 0x01 != 0 && !on {
                return Outcome::Discarded;
            }
            let cur_off_wait = c.u16(OFF_WAIT_TIME.id).unwrap_or(0);
            if cur_off_wait > 0 && !on {
                // Guarded off: only shorten the wait.
                c.set_u16(OFF_WAIT_TIME.id, cur_off_wait.min(off_wait));
                arm(c, now);
                return Outcome::Set(false);
            }
            let cur_on_time = c.u16(ON_TIME.id).unwrap_or(0);
            c.set_u16(ON_TIME.id, cur_on_time.max(on_time));
            c.set_u16(OFF_WAIT_TIME.id, off_wait);
            c.set_bool(ON_OFF.id, true);
            c.set_bool(GLOBAL_SCENE_CONTROL.id, true);
            arm(c, now);
            Outcome::Set(true)
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

/// Second half of Off With Effect (§3.8.2.3.4.3): clears
/// `GlobalSceneControl` and enters the off state.
pub fn turn_off_with_effect<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) {
    c.set_bool(GLOBAL_SCENE_CONTROL.id, false);
    set_on(c, false, now);
}

/// Advances the OnTime / OffWaitTime countdown (§3.8.2.3.6.4). Returns
/// `Some(false)` when the timed-on period expired and the device turned
/// off.
pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<bool> {
    let due = c.tick?;
    if !now.has_reached(due) {
        return None;
    }
    // Catch up one tenth per elapsed 100 ms without skipping the
    // bookkeeping of the transitions.
    let mut result = None;
    let mut next = due;
    while now.has_reached(next) {
        let on = is_on(c);
        if on {
            let t = c.u16(ON_TIME.id).unwrap_or(0);
            if (1..0xffff).contains(&t) {
                let t = t - 1;
                c.set_u16(ON_TIME.id, t);
                if t == 0 {
                    // §3.8.2.3.6.4 (literal): an expired OnTime clears
                    // OffWaitTime; the guarded "Delayed Off" state is
                    // entered by an Off command during the timed-on
                    // period, which keeps OffWaitTime.
                    c.set_u16(OFF_WAIT_TIME.id, 0);
                    c.set_bool(ON_OFF.id, false);
                    result = Some(false);
                    c.tick = None;
                    return result;
                }
            } else {
                c.tick = None;
                return result;
            }
        } else {
            let w = c.u16(OFF_WAIT_TIME.id).unwrap_or(0);
            if (1..0xffff).contains(&w) {
                c.set_u16(OFF_WAIT_TIME.id, w - 1);
                if w - 1 == 0 {
                    c.tick = None;
                    return result;
                }
            } else {
                c.tick = None;
                return result;
            }
        }
        next += TICK;
    }
    c.tick = Some(next);
    result
}

/// Applies `StartUpOnOff` at power-up (Table 3-46) given the previous
/// `OnOff` value; returns the resulting state.
pub fn start_up<const A: usize>(c: &mut ClusterInstance<A>, previous: bool) -> bool {
    let v = match c.u8(START_UP_ON_OFF.id) {
        Some(start_up::OFF) => false,
        Some(start_up::ON) => true,
        Some(start_up::TOGGLE) => !previous,
        _ => previous,
    };
    c.set_bool(ON_OFF.id, v);
    v
}

/// Scene extension field set of the On/Off server (§3.8.2.6): `OnOff`.
pub fn scene_fields<const A: usize>(c: &ClusterInstance<A>) -> [u8; 1] {
    [u8::from(is_on(c))]
}

/// Applies a scene extension field set (§3.8.2.6) to the server; trailing
/// fields absent from `fields` leave the attribute unchanged.
pub fn apply_scene_fields<const A: usize>(
    c: &mut ClusterInstance<A>,
    fields: &[u8],
    now: Instant,
) -> Option<bool> {
    let on = *fields.first()? != 0;
    set_on(c, on, now);
    Some(on)
}
