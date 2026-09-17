//! Window Covering cluster (ZCL8 §7.4): the information and settings
//! attribute sets, the seven motion commands with their validation, the
//! open-loop interpretation of percentages, the `Mode` maintenance bit
//! and the scene extension. The physical motion belongs to the
//! application: the dispatcher reports each accepted command as a
//! [`Command`] and the application feeds positions back with
//! [`set_lift`] / [`set_tilt`] / [`set_percentages`].

use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, AttributeTable, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0102);

/// `WindowCoveringType` (enum8, Table 7-41).
pub const WINDOW_COVERING_TYPE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Enum8, Access::RO);
/// `PhysicalClosedLimitLift` (uint16, cm).
pub const PHYSICAL_CLOSED_LIMIT_LIFT: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
/// `PhysicalClosedLimitTilt` (uint16, 0.1°).
pub const PHYSICAL_CLOSED_LIMIT_TILT: AttributeDef =
    AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
/// `CurrentPositionLift` (uint16, cm from the top).
pub const CURRENT_POSITION_LIFT: AttributeDef =
    AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
/// `CurrentPositionTilt` (uint16, 0.1° from open).
pub const CURRENT_POSITION_TILT: AttributeDef =
    AttributeDef::new(0x0004, DataType::Uint(2), Access::RO);
/// `NumberOfActuationsLift`.
pub const NUMBER_OF_ACTUATIONS_LIFT: AttributeDef =
    AttributeDef::new(0x0005, DataType::Uint(2), Access::RO);
/// `NumberOfActuationsTilt`.
pub const NUMBER_OF_ACTUATIONS_TILT: AttributeDef =
    AttributeDef::new(0x0006, DataType::Uint(2), Access::RO);
/// `ConfigStatus` (map8, Table 7-42).
pub const CONFIG_STATUS: AttributeDef = AttributeDef::new(0x0007, DataType::Bitmap(1), Access::RO);
/// `CurrentPositionLiftPercentage` (uint8 0–100, reportable, scene).
pub const CURRENT_POSITION_LIFT_PERCENTAGE: AttributeDef =
    AttributeDef::new(0x0008, DataType::Uint(1), Access::RO_REPORT);
/// `CurrentPositionTiltPercentage` (uint8 0–100, reportable, scene).
pub const CURRENT_POSITION_TILT_PERCENTAGE: AttributeDef =
    AttributeDef::new(0x0009, DataType::Uint(1), Access::RO_REPORT);
/// `InstalledOpenLimitLift` (uint16, cm).
pub const INSTALLED_OPEN_LIMIT_LIFT: AttributeDef =
    AttributeDef::new(0x0010, DataType::Uint(2), Access::RO);
/// `InstalledClosedLimitLift` (uint16, cm).
pub const INSTALLED_CLOSED_LIMIT_LIFT: AttributeDef =
    AttributeDef::new(0x0011, DataType::Uint(2), Access::RO);
/// `InstalledOpenLimitTilt` (uint16, 0.1°).
pub const INSTALLED_OPEN_LIMIT_TILT: AttributeDef =
    AttributeDef::new(0x0012, DataType::Uint(2), Access::RO);
/// `InstalledClosedLimitTilt` (uint16, 0.1°).
pub const INSTALLED_CLOSED_LIMIT_TILT: AttributeDef =
    AttributeDef::new(0x0013, DataType::Uint(2), Access::RO);
/// `VelocityLift` (uint16, cm/s, writable).
pub const VELOCITY_LIFT: AttributeDef = AttributeDef::new(0x0014, DataType::Uint(2), Access::RW);
/// `AccelerationTimeLift` (uint16, 0.1 s, writable).
pub const ACCELERATION_TIME_LIFT: AttributeDef =
    AttributeDef::new(0x0015, DataType::Uint(2), Access::RW);
/// `DecelerationTimeLift` (uint16, 0.1 s, writable).
pub const DECELERATION_TIME_LIFT: AttributeDef =
    AttributeDef::new(0x0016, DataType::Uint(2), Access::RW);
/// `Mode` (map8, Table 7-44, writable).
pub const MODE: AttributeDef = AttributeDef::new(0x0017, DataType::Bitmap(1), Access::RW);

/// Unknown percentage (non-value, CCB 2555).
pub const PERCENTAGE_UNKNOWN: u8 = 0xff;

/// `WindowCoveringType` values (Table 7-41).
pub mod covering_type {
    /// Rollershade (lift).
    pub const ROLLERSHADE: u8 = 0x00;
    /// Rollershade, two motors (lift).
    pub const ROLLERSHADE_2_MOTOR: u8 = 0x01;
    /// Exterior rollershade (lift).
    pub const ROLLERSHADE_EXTERIOR: u8 = 0x02;
    /// Exterior rollershade, two motors (lift).
    pub const ROLLERSHADE_EXTERIOR_2_MOTOR: u8 = 0x03;
    /// Drapery (lift).
    pub const DRAPERY: u8 = 0x04;
    /// Awning (lift).
    pub const AWNING: u8 = 0x05;
    /// Shutter (tilt).
    pub const SHUTTER: u8 = 0x06;
    /// Tilt-only blind.
    pub const TILT_BLIND_TILT_ONLY: u8 = 0x07;
    /// Lift-and-tilt blind.
    pub const TILT_BLIND_LIFT_AND_TILT: u8 = 0x08;
    /// Projector screen (lift).
    pub const PROJECTOR_SCREEN: u8 = 0x09;

    /// Whether the type supports lift actions.
    pub const fn supports_lift(t: u8) -> bool {
        !matches!(t, SHUTTER | TILT_BLIND_TILT_ONLY) && t <= PROJECTOR_SCREEN
    }

    /// Whether the type supports tilt actions.
    pub const fn supports_tilt(t: u8) -> bool {
        matches!(t, SHUTTER | TILT_BLIND_TILT_ONLY | TILT_BLIND_LIFT_AND_TILT)
    }
}

/// `ConfigStatus` bits (Table 7-42).
pub mod config_status {
    /// Operational.
    pub const OPERATIONAL: u8 = 1 << 0;
    /// Online.
    pub const ONLINE: u8 = 1 << 1;
    /// Up/Open commands reversed.
    pub const REVERSED: u8 = 1 << 2;
    /// Lift control is closed loop.
    pub const LIFT_CLOSED_LOOP: u8 = 1 << 3;
    /// Tilt control is closed loop.
    pub const TILT_CLOSED_LOOP: u8 = 1 << 4;
    /// Lift uses an encoder.
    pub const LIFT_ENCODER: u8 = 1 << 5;
    /// Tilt uses an encoder.
    pub const TILT_ENCODER: u8 = 1 << 6;
}

/// `Mode` bits (Table 7-44).
pub mod mode {
    /// Motor direction reversed.
    pub const REVERSED: u8 = 1 << 0;
    /// Calibration mode.
    pub const CALIBRATION: u8 = 1 << 1;
    /// Maintenance mode: the motor cannot be moved over the network.
    pub const MAINTENANCE: u8 = 1 << 2;
    /// Feedback LEDs on.
    pub const LEDS: u8 = 1 << 3;
    /// Default of Table 7-43.
    pub const DEFAULT: u8 = MAINTENANCE;
    /// The defined bits.
    pub const ALL: u8 = REVERSED | CALIBRATION | MAINTENANCE | LEDS;
}

/// Up / Open.
pub const CMD_UP_OPEN: CommandId = CommandId(0x00);
/// Down / Close.
pub const CMD_DOWN_CLOSE: CommandId = CommandId(0x01);
/// Stop.
pub const CMD_STOP: CommandId = CommandId(0x02);
/// Go To Lift Value.
pub const CMD_GO_TO_LIFT_VALUE: CommandId = CommandId(0x04);
/// Go To Lift Percentage.
pub const CMD_GO_TO_LIFT_PERCENTAGE: CommandId = CommandId(0x05);
/// Go To Tilt Value.
pub const CMD_GO_TO_TILT_VALUE: CommandId = CommandId(0x07);
/// Go To Tilt Percentage.
pub const CMD_GO_TO_TILT_PERCENTAGE: CommandId = CommandId(0x08);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[
        CMD_UP_OPEN,
        CMD_DOWN_CLOSE,
        CMD_STOP,
        CMD_GO_TO_LIFT_VALUE,
        CMD_GO_TO_LIFT_PERCENTAGE,
        CMD_GO_TO_TILT_VALUE,
        CMD_GO_TO_TILT_PERCENTAGE,
    ],
    generated: &[],
};

/// Default reporting of the percentages (§7.4.2.5): every 1 %.
pub const PERCENTAGE_REPORTING: DefaultReporting = DefaultReporting {
    min: 1,
    max: 300,
    change: 1,
};

/// How one axis (lift or tilt) is controlled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Control {
    /// The axis is not supported.
    Unsupported,
    /// Open loop: the device only knows open, closed and stop.
    OpenLoop,
    /// Closed loop between the installed limits (cm or 0.1°).
    ClosedLoop {
        /// `InstalledOpenLimit`.
        open: u16,
        /// `InstalledClosedLimit`.
        closed: u16,
        /// Positioned by an encoder rather than a timer.
        encoder: bool,
    },
}

/// A command accepted by the server, for the application to execute.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Command {
    /// Move lift and tilt to their open limits as fast as possible.
    Open,
    /// Move lift and tilt to their closed limits as fast as possible.
    Close,
    /// Stop every motion.
    Stop,
    /// Move the lift to this position (cm).
    LiftValue(u16),
    /// Move the lift to this percentage of the installed range.
    LiftPercentage(u8),
    /// Move the tilt to this position (0.1°).
    TiltValue(u16),
    /// Move the tilt to this percentage of the installed range.
    TiltPercentage(u8),
    /// A recalled scene (§7.4.2.4): the percentages to reach over
    /// `tenths` tenths of a second (unsupported axes are `None`).
    Scene {
        /// Lift percentage.
        lift: Option<u8>,
        /// Tilt percentage.
        tilt: Option<u8>,
        /// Transition time.
        tenths: u16,
    },
}

/// Result of a received command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Accepted: the application executes `Command`.
    Execute(Command),
    /// Refused with this status.
    Default(ZclStatus),
}

/// Write guard: `Mode` accepts the defined bits only.
fn guard<const A: usize>(_t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
    if id == MODE.id && v.as_u64().is_none_or(|m| m & !u64::from(mode::ALL) != 0) {
        ZclStatus::InvalidValue
    } else {
        ZclStatus::Success
    }
}

fn u16v(v: u16) -> Value<'static> {
    Value::Uint {
        width: 2,
        value: u64::from(v),
    }
}

fn u8v(v: u8) -> Value<'static> {
    Value::Uint {
        width: 1,
        value: u64::from(v),
    }
}

/// Builds a server of `kind` (Table 7-41) with the given lift and tilt
/// control; closed-loop axes carry the current position, its
/// percentage (reported) and the installed limits.
pub fn server<const A: usize>(
    kind: u8,
    lift: Control,
    tilt: Control,
) -> Result<ClusterInstance<A>, ZclStatus> {
    if kind > covering_type::PROJECTOR_SCREEN {
        return Err(ZclStatus::InvalidValue);
    }
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(WINDOW_COVERING_TYPE, &Value::Enum8(kind))?;
    let mut status = config_status::OPERATIONAL | config_status::ONLINE;
    if let Control::ClosedLoop {
        open,
        closed,
        encoder,
    } = lift
    {
        status |= config_status::LIFT_CLOSED_LOOP;
        if encoder {
            status |= config_status::LIFT_ENCODER;
        }
        c.add_attribute(CURRENT_POSITION_LIFT, &u16v(open))?;
        c.add_attribute(NUMBER_OF_ACTUATIONS_LIFT, &u16v(0))?;
        c.add_reported_attribute(
            CURRENT_POSITION_LIFT_PERCENTAGE,
            &u8v(PERCENTAGE_UNKNOWN),
            PERCENTAGE_REPORTING,
        )?;
        c.add_attribute(INSTALLED_OPEN_LIMIT_LIFT, &u16v(open))?;
        c.add_attribute(INSTALLED_CLOSED_LIMIT_LIFT, &u16v(closed))?;
    }
    if let Control::ClosedLoop {
        open,
        closed,
        encoder,
    } = tilt
    {
        status |= config_status::TILT_CLOSED_LOOP;
        if encoder {
            status |= config_status::TILT_ENCODER;
        }
        c.add_attribute(CURRENT_POSITION_TILT, &u16v(open))?;
        c.add_attribute(NUMBER_OF_ACTUATIONS_TILT, &u16v(0))?;
        c.add_reported_attribute(
            CURRENT_POSITION_TILT_PERCENTAGE,
            &u8v(PERCENTAGE_UNKNOWN),
            PERCENTAGE_REPORTING,
        )?;
        c.add_attribute(INSTALLED_OPEN_LIMIT_TILT, &u16v(open))?;
        c.add_attribute(INSTALLED_CLOSED_LIMIT_TILT, &u16v(closed))?;
    }
    c.add_attribute(
        CONFIG_STATUS,
        &Value::Bits {
            width: 1,
            bits: u64::from(status),
        },
    )?;
    c.add_attribute(
        MODE,
        &Value::Bits {
            width: 1,
            bits: u64::from(mode::DEFAULT),
        },
    )?;
    c.write_guard = Some(guard::<A>);
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

fn bits<const A: usize>(c: &ClusterInstance<A>, id: AttributeId) -> u8 {
    c.attributes
        .value(id)
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0)
}

/// The lift control of a server instance, read back from its attributes.
pub fn lift_control<const A: usize>(c: &ClusterInstance<A>) -> Control {
    let kind = c.u8(WINDOW_COVERING_TYPE.id).unwrap_or(0);
    match (
        c.u16(INSTALLED_OPEN_LIMIT_LIFT.id),
        c.u16(INSTALLED_CLOSED_LIMIT_LIFT.id),
    ) {
        (Some(open), Some(closed)) => Control::ClosedLoop {
            open,
            closed,
            encoder: bits(c, CONFIG_STATUS.id) & config_status::LIFT_ENCODER != 0,
        },
        _ if covering_type::supports_lift(kind) => Control::OpenLoop,
        _ => Control::Unsupported,
    }
}

/// The tilt control of a server instance, read back from its attributes.
pub fn tilt_control<const A: usize>(c: &ClusterInstance<A>) -> Control {
    let kind = c.u8(WINDOW_COVERING_TYPE.id).unwrap_or(0);
    match (
        c.u16(INSTALLED_OPEN_LIMIT_TILT.id),
        c.u16(INSTALLED_CLOSED_LIMIT_TILT.id),
    ) {
        (Some(open), Some(closed)) => Control::ClosedLoop {
            open,
            closed,
            encoder: bits(c, CONFIG_STATUS.id) & config_status::TILT_ENCODER != 0,
        },
        _ if covering_type::supports_tilt(kind) => Control::OpenLoop,
        _ => Control::Unsupported,
    }
}

/// Whether `Mode` has the maintenance bit set: motion over the network
/// is refused (Table 7-44 bit 2).
pub fn in_maintenance<const A: usize>(c: &ClusterInstance<A>) -> bool {
    bits(c, MODE.id) & mode::MAINTENANCE != 0
}

/// Mirrors the `Mode` reversal bit into `ConfigStatus` (Table 7-42
/// bit 2); called after a network write.
pub fn after_write<const A: usize>(c: &mut ClusterInstance<A>) {
    let reversed = bits(c, MODE.id) & mode::REVERSED != 0;
    let mut status = bits(c, CONFIG_STATUS.id) & !config_status::REVERSED;
    if reversed {
        status |= config_status::REVERSED;
    }
    c.set(
        CONFIG_STATUS.id,
        &Value::Bits {
            width: 1,
            bits: u64::from(status),
        },
    );
}

/// The percentage of `position` between `open` (0 %) and `closed`
/// (100 %), rounded to the nearest unit and clamped.
pub fn percentage(open: u16, closed: u16, position: u16) -> u8 {
    let (lo, hi) = (open.min(closed), open.max(closed));
    if lo == hi {
        return 0;
    }
    let span = u32::from(hi - lo);
    let offset = u32::from(position.clamp(lo, hi) - lo);
    let from_open = if open <= closed {
        offset
    } else {
        span - offset
    };
    u8::try_from((from_open * 100 + span / 2) / span).unwrap_or(100)
}

/// The position at `percent` of the way from `open` to `closed`.
pub fn position(open: u16, closed: u16, percent: u8) -> u16 {
    let p = u32::from(percent.min(100));
    let (lo, hi) = (u32::from(open), u32::from(closed));
    let v = if hi >= lo {
        lo + (hi - lo) * p / 100
    } else {
        lo - (lo - hi) * p / 100
    };
    u16::try_from(v).unwrap_or(u16::MAX)
}

/// Records the lift position (cm) of a closed-loop server, updates its
/// percentage and counts an actuation; returns whether the percentage
/// changed.
pub fn set_lift<const A: usize>(c: &mut ClusterInstance<A>, lift: u16) -> bool {
    let Control::ClosedLoop { open, closed, .. } = lift_control(c) else {
        return false;
    };
    if c.set_u16(CURRENT_POSITION_LIFT.id, lift) {
        let n = c.u16(NUMBER_OF_ACTUATIONS_LIFT.id).unwrap_or(0);
        c.set_u16(NUMBER_OF_ACTUATIONS_LIFT.id, n.wrapping_add(1));
    }
    c.set_u8(
        CURRENT_POSITION_LIFT_PERCENTAGE.id,
        percentage(open, closed, lift),
    )
}

/// Records the tilt position (0.1°) of a closed-loop server, updates
/// its percentage and counts an actuation; returns whether the
/// percentage changed.
pub fn set_tilt<const A: usize>(c: &mut ClusterInstance<A>, tilt: u16) -> bool {
    let Control::ClosedLoop { open, closed, .. } = tilt_control(c) else {
        return false;
    };
    if c.set_u16(CURRENT_POSITION_TILT.id, tilt) {
        let n = c.u16(NUMBER_OF_ACTUATIONS_TILT.id).unwrap_or(0);
        c.set_u16(NUMBER_OF_ACTUATIONS_TILT.id, n.wrapping_add(1));
    }
    c.set_u8(
        CURRENT_POSITION_TILT_PERCENTAGE.id,
        percentage(open, closed, tilt),
    )
}

/// Records percentages directly (e.g. a timed closed loop without an
/// encoder), also deriving the positions from the installed limits.
pub fn set_percentages<const A: usize>(
    c: &mut ClusterInstance<A>,
    lift: Option<u8>,
    tilt: Option<u8>,
) {
    if let Some(p) = lift
        && let Control::ClosedLoop { open, closed, .. } = lift_control(c)
    {
        set_lift(c, position(open, closed, p));
    }
    if let Some(p) = tilt
        && let Control::ClosedLoop { open, closed, .. } = tilt_control(c)
    {
        set_tilt(c, position(open, closed, p));
    }
}

/// Current lift percentage, `None` when unknown or unsupported.
pub fn lift_percentage<const A: usize>(c: &ClusterInstance<A>) -> Option<u8> {
    c.u8(CURRENT_POSITION_LIFT_PERCENTAGE.id)
        .filter(|p| *p <= 100)
}

/// Current tilt percentage, `None` when unknown or unsupported.
pub fn tilt_percentage<const A: usize>(c: &ClusterInstance<A>) -> Option<u8> {
    c.u8(CURRENT_POSITION_TILT_PERCENTAGE.id)
        .filter(|p| *p <= 100)
}

fn within(open: u16, closed: u16, v: u16) -> bool {
    (open.min(closed)..=open.max(closed)).contains(&v)
}

/// Handles a received command (§7.4.2.2). Values outside the installed
/// limits and percentages above 100 are `INVALID_VALUE`; a percentage
/// on an open-loop axis becomes Close (0 %) or Open; an axis the
/// device lacks is `UNSUPPORTED_COMMAND`; maintenance mode refuses
/// every motion with `FAILURE`.
pub fn handle<const A: usize>(c: &ClusterInstance<A>, cmd: CommandId, payload: &[u8]) -> Outcome {
    let lift = lift_control(c);
    let tilt = tilt_control(c);
    let command = match cmd {
        CMD_UP_OPEN if payload.is_empty() => Command::Open,
        CMD_DOWN_CLOSE if payload.is_empty() => Command::Close,
        CMD_STOP if payload.is_empty() => Command::Stop,
        CMD_UP_OPEN | CMD_DOWN_CLOSE | CMD_STOP => {
            return Outcome::Default(ZclStatus::MalformedCommand);
        }
        CMD_GO_TO_LIFT_VALUE | CMD_GO_TO_TILT_VALUE => {
            let [lo, hi] = payload else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let v = u16::from_le_bytes([*lo, *hi]);
            let (control, make): (Control, fn(u16) -> Command) = if cmd == CMD_GO_TO_LIFT_VALUE {
                (lift, Command::LiftValue)
            } else {
                (tilt, Command::TiltValue)
            };
            match control {
                Control::ClosedLoop { open, closed, .. } if within(open, closed, v) => make(v),
                Control::ClosedLoop { .. } => return Outcome::Default(ZclStatus::InvalidValue),
                // Open-loop axes have no positions to go to.
                _ => return Outcome::Default(ZclStatus::UnsupportedClusterCommand),
            }
        }
        CMD_GO_TO_LIFT_PERCENTAGE | CMD_GO_TO_TILT_PERCENTAGE => {
            let [p] = payload else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let (control, make): (Control, fn(u8) -> Command) = if cmd == CMD_GO_TO_LIFT_PERCENTAGE
            {
                (lift, Command::LiftPercentage)
            } else {
                (tilt, Command::TiltPercentage)
            };
            match control {
                _ if *p > 100 => return Outcome::Default(ZclStatus::InvalidValue),
                Control::ClosedLoop { .. } => make(*p),
                Control::OpenLoop if *p == 0 => Command::Close,
                Control::OpenLoop => Command::Open,
                Control::Unsupported => {
                    return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
                }
            }
        }
        _ => return Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    };
    if command != Command::Stop && in_maintenance(c) {
        return Outcome::Default(ZclStatus::Failure);
    }
    Outcome::Execute(command)
}

/// Scene extension field set (§7.4.2.4): CurrentPositionLiftPercentage,
/// CurrentPositionTiltPercentage (0xff when unknown).
pub fn scene_fields<const A: usize>(c: &ClusterInstance<A>) -> [u8; 2] {
    [
        lift_percentage(c).unwrap_or(PERCENTAGE_UNKNOWN),
        tilt_percentage(c).unwrap_or(PERCENTAGE_UNKNOWN),
    ]
}

/// Interprets a recalled scene as a go-to command over `tenths` tenths
/// of a second: axes the device lacks or unknown percentages are
/// dropped, open-loop axes ignore the transition time (§7.4.2.4).
/// `None` when nothing applies or maintenance mode is on.
pub fn apply_scene_fields<const A: usize>(
    c: &ClusterInstance<A>,
    fields: &[u8],
    tenths: u16,
) -> Option<Command> {
    let [lift, tilt, ..] = fields else {
        return None;
    };
    if in_maintenance(c) {
        return None;
    }
    let axis = |control: Control, p: u8| match control {
        _ if p > 100 => None,
        Control::Unsupported => None,
        Control::OpenLoop => Some(if p == 0 { 0 } else { 100 }),
        Control::ClosedLoop { .. } => Some(p),
    };
    let lift = axis(lift_control(c), *lift);
    let tilt = axis(tilt_control(c), *tilt);
    if lift.is_none() && tilt.is_none() {
        return None;
    }
    let open_loop = lift.is_some() && lift_control(c) == Control::OpenLoop
        || tilt.is_some() && tilt_control(c) == Control::OpenLoop;
    Some(Command::Scene {
        lift,
        tilt,
        tenths: if open_loop { 0 } else { tenths },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIFT: Control = Control::ClosedLoop {
        open: 0,
        closed: 200,
        encoder: true,
    };
    const TILT: Control = Control::ClosedLoop {
        open: 900,
        closed: 0,
        encoder: false,
    };

    fn blind() -> ClusterInstance<24> {
        server(covering_type::TILT_BLIND_LIFT_AND_TILT, LIFT, TILT).unwrap()
    }

    #[test]
    fn server_reflects_the_control_in_config_status() {
        let c = blind();
        assert_eq!(
            bits(&c, CONFIG_STATUS.id),
            config_status::OPERATIONAL
                | config_status::ONLINE
                | config_status::LIFT_CLOSED_LOOP
                | config_status::TILT_CLOSED_LOOP
                | config_status::LIFT_ENCODER
        );
        assert_eq!(lift_control(&c), LIFT);
        assert_eq!(tilt_control(&c), TILT);
        assert_eq!(lift_percentage(&c), None);
        assert!(in_maintenance(&c));

        let shade: ClusterInstance<24> = server(
            covering_type::ROLLERSHADE,
            Control::OpenLoop,
            Control::Unsupported,
        )
        .unwrap();
        assert_eq!(lift_control(&shade), Control::OpenLoop);
        assert_eq!(tilt_control(&shade), Control::Unsupported);
        assert!(shade.u8(CURRENT_POSITION_LIFT_PERCENTAGE.id).is_none());
        assert!(server::<24>(0x0a, LIFT, TILT).is_err());
    }

    #[test]
    fn percentages_follow_the_installed_limits_in_either_direction() {
        assert_eq!(percentage(0, 200, 50), 25);
        assert_eq!(percentage(0, 200, 201), 100);
        assert_eq!(percentage(900, 0, 900), 0);
        assert_eq!(percentage(900, 0, 0), 100);
        assert_eq!(percentage(900, 0, 450), 50);
        assert_eq!(percentage(5, 5, 7), 0);
        assert_eq!(position(0, 200, 25), 50);
        assert_eq!(position(900, 0, 50), 450);
        assert_eq!(position(900, 0, 100), 0);
        assert_eq!(position(0, 200, 150), 200);
    }

    #[test]
    fn positions_update_percentages_and_count_actuations() {
        let mut c = blind();
        assert!(set_lift(&mut c, 100));
        assert_eq!(lift_percentage(&c), Some(50));
        assert_eq!(c.u16(NUMBER_OF_ACTUATIONS_LIFT.id), Some(1));
        assert!(!set_lift(&mut c, 100));
        assert_eq!(c.u16(NUMBER_OF_ACTUATIONS_LIFT.id), Some(1));
        set_percentages(&mut c, None, Some(50));
        assert_eq!(c.u16(CURRENT_POSITION_TILT.id), Some(450));
        assert_eq!(tilt_percentage(&c), Some(50));
        assert_eq!(scene_fields(&c), [50, 50]);
    }

    #[test]
    fn commands_are_validated_against_the_control() {
        let mut c = blind();
        assert_eq!(
            handle(&c, CMD_UP_OPEN, &[]),
            Outcome::Default(ZclStatus::Failure)
        );
        assert_eq!(handle(&c, CMD_STOP, &[]), Outcome::Execute(Command::Stop));
        c.set(MODE.id, &Value::Bits { width: 1, bits: 0 });
        assert_eq!(
            handle(&c, CMD_UP_OPEN, &[]),
            Outcome::Execute(Command::Open)
        );
        assert_eq!(
            handle(&c, CMD_DOWN_CLOSE, &[1]),
            Outcome::Default(ZclStatus::MalformedCommand)
        );
        assert_eq!(
            handle(&c, CMD_GO_TO_LIFT_VALUE, &[150, 0]),
            Outcome::Execute(Command::LiftValue(150))
        );
        assert_eq!(
            handle(&c, CMD_GO_TO_LIFT_VALUE, &[201, 0]),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        assert_eq!(
            handle(&c, CMD_GO_TO_TILT_VALUE, &[0x84, 0x03]),
            Outcome::Execute(Command::TiltValue(900))
        );
        assert_eq!(
            handle(&c, CMD_GO_TO_TILT_PERCENTAGE, &[101]),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        assert_eq!(
            handle(&c, CMD_GO_TO_TILT_PERCENTAGE, &[30]),
            Outcome::Execute(Command::TiltPercentage(30))
        );
        assert_eq!(
            handle(&c, CommandId(0x03), &[]),
            Outcome::Default(ZclStatus::UnsupportedClusterCommand)
        );

        let mut shade: ClusterInstance<24> = server(
            covering_type::ROLLERSHADE,
            Control::OpenLoop,
            Control::Unsupported,
        )
        .unwrap();
        shade.set(MODE.id, &Value::Bits { width: 1, bits: 0 });
        assert_eq!(
            handle(&shade, CMD_GO_TO_LIFT_PERCENTAGE, &[0]),
            Outcome::Execute(Command::Close)
        );
        assert_eq!(
            handle(&shade, CMD_GO_TO_LIFT_PERCENTAGE, &[40]),
            Outcome::Execute(Command::Open)
        );
        assert_eq!(
            handle(&shade, CMD_GO_TO_LIFT_VALUE, &[1, 0]),
            Outcome::Default(ZclStatus::UnsupportedClusterCommand)
        );
        assert_eq!(
            handle(&shade, CMD_GO_TO_TILT_PERCENTAGE, &[40]),
            Outcome::Default(ZclStatus::UnsupportedClusterCommand)
        );
    }

    #[test]
    fn mode_writes_are_guarded_and_mirrored() {
        let mut c = blind();
        assert_eq!(
            guard(
                &c.attributes,
                MODE.id,
                &Value::Bits {
                    width: 1,
                    bits: 0x10
                }
            ),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            guard(
                &c.attributes,
                MODE.id,
                &Value::Bits {
                    width: 1,
                    bits: u64::from(mode::REVERSED)
                }
            ),
            ZclStatus::Success
        );
        c.set(
            MODE.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(mode::REVERSED),
            },
        );
        after_write(&mut c);
        assert_ne!(bits(&c, CONFIG_STATUS.id) & config_status::REVERSED, 0);
        c.set(MODE.id, &Value::Bits { width: 1, bits: 0 });
        after_write(&mut c);
        assert_eq!(bits(&c, CONFIG_STATUS.id) & config_status::REVERSED, 0);
    }

    #[test]
    fn scenes_become_timed_go_to_commands() {
        let mut c = blind();
        c.set(MODE.id, &Value::Bits { width: 1, bits: 0 });
        assert_eq!(
            apply_scene_fields(&c, &[40, 0xff], 25),
            Some(Command::Scene {
                lift: Some(40),
                tilt: None,
                tenths: 25
            })
        );
        assert_eq!(apply_scene_fields(&c, &[0xff, 0xff], 25), None);
        assert_eq!(apply_scene_fields(&c, &[40], 25), None);

        let mut shade: ClusterInstance<24> = server(
            covering_type::ROLLERSHADE,
            Control::OpenLoop,
            Control::Unsupported,
        )
        .unwrap();
        shade.set(MODE.id, &Value::Bits { width: 1, bits: 0 });
        assert_eq!(
            apply_scene_fields(&shade, &[40, 60], 25),
            Some(Command::Scene {
                lift: Some(100),
                tilt: None,
                tenths: 0
            })
        );
    }
}
