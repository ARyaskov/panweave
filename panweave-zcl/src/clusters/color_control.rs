//! Color Control cluster (ZCL8 §5.2): hue / saturation (8-bit and
//! enhanced 16-bit hue), CIE xyY, colour temperature and the colour loop,
//! with the timed transitions, continuous moves and steps of §5.2.2.3
//! run by the dispatcher on a 100 ms tick. Colour-mode conversions
//! (§5.2.2.3.2) are manufacturer dependent and not performed: a command
//! in another mode starts from the attributes of that mode as they are.

use panweave_codec::Reader;
use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0300);

/// `CurrentHue` (uint8, reportable).
pub const CURRENT_HUE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(1), Access::RO_REPORT);
/// `CurrentSaturation` (uint8, reportable, scene).
pub const CURRENT_SATURATION: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(1), Access::RO_REPORT);
/// `RemainingTime` (uint16, tenths).
pub const REMAINING_TIME: AttributeDef = AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
/// `CurrentX` (uint16, reportable, scene).
pub const CURRENT_X: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(2), Access::RO_REPORT);
/// `CurrentY` (uint16, reportable, scene).
pub const CURRENT_Y: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(2), Access::RO_REPORT);
/// `ColorTemperatureMireds` (uint16, reportable, scene).
pub const COLOR_TEMPERATURE_MIREDS: AttributeDef =
    AttributeDef::new(0x0007, DataType::Uint(2), Access::RO_REPORT);
/// `ColorMode` (enum8).
pub const COLOR_MODE: AttributeDef = AttributeDef::new(0x0008, DataType::Enum8, Access::RO);
/// `Options` (map8, writable).
pub const OPTIONS: AttributeDef = AttributeDef::new(0x000f, DataType::Bitmap(1), Access::RW);
/// `EnhancedCurrentHue` (uint16, scene).
pub const ENHANCED_CURRENT_HUE: AttributeDef =
    AttributeDef::new(0x4000, DataType::Uint(2), Access::RO);
/// `EnhancedColorMode` (enum8).
pub const ENHANCED_COLOR_MODE: AttributeDef =
    AttributeDef::new(0x4001, DataType::Enum8, Access::RO);
/// `ColorLoopActive` (uint8, scene).
pub const COLOR_LOOP_ACTIVE: AttributeDef =
    AttributeDef::new(0x4002, DataType::Uint(1), Access::RO);
/// `ColorLoopDirection` (uint8, scene).
pub const COLOR_LOOP_DIRECTION: AttributeDef =
    AttributeDef::new(0x4003, DataType::Uint(1), Access::RO);
/// `ColorLoopTime` (uint16 seconds, scene).
pub const COLOR_LOOP_TIME: AttributeDef = AttributeDef::new(0x4004, DataType::Uint(2), Access::RO);
/// `ColorLoopStartEnhancedHue` (uint16).
pub const COLOR_LOOP_START_ENHANCED_HUE: AttributeDef =
    AttributeDef::new(0x4005, DataType::Uint(2), Access::RO);
/// `ColorLoopStoredEnhancedHue` (uint16).
pub const COLOR_LOOP_STORED_ENHANCED_HUE: AttributeDef =
    AttributeDef::new(0x4006, DataType::Uint(2), Access::RO);
/// `ColorCapabilities` (map16).
pub const COLOR_CAPABILITIES: AttributeDef =
    AttributeDef::new(0x400a, DataType::Bitmap(2), Access::RO);
/// `ColorTempPhysicalMinMireds` (uint16).
pub const COLOR_TEMP_PHYSICAL_MIN_MIREDS: AttributeDef =
    AttributeDef::new(0x400b, DataType::Uint(2), Access::RO);
/// `DriftCompensation` (enum8, Table 5.4).
pub const DRIFT_COMPENSATION: AttributeDef = AttributeDef::new(0x0005, DataType::Enum8, Access::RO);
/// `CompensationText` (string).
pub const COMPENSATION_TEXT: AttributeDef =
    AttributeDef::new(0x0006, DataType::CharString, Access::RO);
/// `NumberOfPrimaries` (uint8, 0…6).
pub const NUMBER_OF_PRIMARIES: AttributeDef =
    AttributeDef::new(0x0010, DataType::Uint(1), Access::RO);
/// `WhitePointX` (uint16, writable).
pub const WHITE_POINT_X: AttributeDef = AttributeDef::new(0x0030, DataType::Uint(2), Access::RW);
/// `WhitePointY`.
pub const WHITE_POINT_Y: AttributeDef = AttributeDef::new(0x0031, DataType::Uint(2), Access::RW);

/// `DriftCompensation` values (Table 5.4).
pub mod drift_compensation {
    /// None.
    pub const NONE: u8 = 0x00;
    /// Other / unknown.
    pub const OTHER: u8 = 0x01;
    /// Temperature monitoring.
    pub const TEMPERATURE_MONITORING: u8 = 0x02;
    /// Optical luminance monitoring and feedback.
    pub const OPTICAL_LUMINANCE: u8 = 0x03;
    /// Optical colour monitoring and feedback.
    pub const OPTICAL_COLOR: u8 = 0x04;
}

/// A defined primary or a colour point: CIE xyY chromaticity (x and y
/// scaled by 65536) and relative intensity (0xff unknown).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Primary {
    /// x × 65536.
    pub x: u16,
    /// y × 65536.
    pub y: u16,
    /// Relative intensity.
    pub intensity: u8,
}

/// The `PrimaryNX` / `PrimaryNY` / `PrimaryNIntensity` attributes of
/// primary `n` (1…6): primaries 1–3 in the Defined Primaries set from
/// 0x0011 (Table 5.10), 4–6 in the Additional Defined Primaries set
/// from 0x0020 (Table 5.11), four identifiers apart.
pub const fn primary_attrs(n: u8) -> [AttributeDef; 3] {
    let base = if n <= 3 {
        0x0011 + 4 * (n as u16 - 1)
    } else {
        0x0020 + 4 * (n as u16 - 4)
    };
    [
        AttributeDef::new(base, DataType::Uint(2), Access::RO),
        AttributeDef::new(base + 1, DataType::Uint(2), Access::RO),
        AttributeDef::new(base + 2, DataType::Uint(1), Access::RO),
    ]
}

/// The colour points of Table 5.12: red, green and blue.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ColorPoint {
    /// `ColorPointR*` (0x0032–0x0034).
    Red,
    /// `ColorPointG*` (0x0036–0x0038).
    Green,
    /// `ColorPointB*` (0x003a–0x003c).
    Blue,
}

/// The X / Y / Intensity attributes of `point` (writable).
pub const fn color_point_attrs(point: ColorPoint) -> [AttributeDef; 3] {
    let base = match point {
        ColorPoint::Red => 0x0032,
        ColorPoint::Green => 0x0036,
        ColorPoint::Blue => 0x003a,
    };
    [
        AttributeDef::new(base, DataType::Uint(2), Access::RW),
        AttributeDef::new(base + 1, DataType::Uint(2), Access::RW),
        AttributeDef::new(base + 2, DataType::Uint(1), Access::RW),
    ]
}

/// Largest chromaticity coordinate.
pub const MAX_CHROMATICITY: u16 = 0xfeff;

/// Adds the drift compensation attributes (§5.2.2.2.1.6–7).
pub fn enable_drift_compensation<const A: usize>(
    c: &mut ClusterInstance<A>,
    method: u8,
    text: &[u8],
) -> Result<(), ZclStatus> {
    if method > drift_compensation::OPTICAL_COLOR || text.len() > 254 {
        return Err(ZclStatus::InvalidValue);
    }
    c.add_attribute(DRIFT_COMPENSATION, &Value::Enum8(method))?;
    c.add_attribute(
        COMPENSATION_TEXT,
        &Value::String {
            ty: DataType::CharString,
            bytes: Some(text),
        },
    )
}

/// Adds the Defined Primaries information set (Tables 5.10 / 5.11):
/// `NumberOfPrimaries` and the X / Y / Intensity of each of the at most
/// six `primaries`.
pub fn enable_primaries<const A: usize>(
    c: &mut ClusterInstance<A>,
    primaries: &[Primary],
) -> Result<(), ZclStatus> {
    if primaries.len() > 6
        || primaries
            .iter()
            .any(|p| p.x > MAX_CHROMATICITY || p.y > MAX_CHROMATICITY)
    {
        return Err(ZclStatus::InvalidValue);
    }
    c.add_attribute(
        NUMBER_OF_PRIMARIES,
        &Value::Uint {
            width: 1,
            value: u64::try_from(primaries.len()).unwrap_or(0),
        },
    )?;
    for (i, p) in primaries.iter().enumerate() {
        let [x, y, intensity] = primary_attrs(u8::try_from(i + 1).unwrap_or(1));
        c.add_attribute(x, &u16v(p.x))?;
        c.add_attribute(y, &u16v(p.y))?;
        c.add_attribute(
            intensity,
            &Value::Uint {
                width: 1,
                value: u64::from(p.intensity),
            },
        )?;
    }
    Ok(())
}

/// Adds the Defined Colour Points set (Table 5.12): the white point and
/// the red, green and blue colour points, all writable.
pub fn enable_color_points<const A: usize>(
    c: &mut ClusterInstance<A>,
    white: (u16, u16),
    red: Primary,
    green: Primary,
    blue: Primary,
) -> Result<(), ZclStatus> {
    c.add_attribute(WHITE_POINT_X, &u16v(white.0.min(MAX_CHROMATICITY)))?;
    c.add_attribute(WHITE_POINT_Y, &u16v(white.1.min(MAX_CHROMATICITY)))?;
    for (point, p) in [
        (ColorPoint::Red, red),
        (ColorPoint::Green, green),
        (ColorPoint::Blue, blue),
    ] {
        let [x, y, intensity] = color_point_attrs(point);
        c.add_attribute(x, &u16v(p.x.min(MAX_CHROMATICITY)))?;
        c.add_attribute(y, &u16v(p.y.min(MAX_CHROMATICITY)))?;
        c.add_attribute(
            intensity,
            &Value::Uint {
                width: 1,
                value: u64::from(p.intensity),
            },
        )?;
    }
    Ok(())
}

/// `ColorTempPhysicalMaxMireds` (uint16).
pub const COLOR_TEMP_PHYSICAL_MAX_MIREDS: AttributeDef =
    AttributeDef::new(0x400c, DataType::Uint(2), Access::RO);
/// `CoupleColorTempToLevelMinMireds` (uint16).
pub const COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS: AttributeDef =
    AttributeDef::new(0x400d, DataType::Uint(2), Access::RO);
/// `StartUpColorTemperatureMireds` (uint16, writable).
pub const START_UP_COLOR_TEMPERATURE_MIREDS: AttributeDef =
    AttributeDef::new(0x4010, DataType::Uint(2), Access::RW);

/// `ColorCapabilities` bits (Table 5.8).
pub mod capability {
    /// Hue / saturation.
    pub const HUE_SATURATION: u16 = 1 << 0;
    /// Enhanced hue.
    pub const ENHANCED_HUE: u16 = 1 << 1;
    /// Colour loop.
    pub const COLOR_LOOP: u16 = 1 << 2;
    /// XY.
    pub const XY: u16 = 1 << 3;
    /// Colour temperature.
    pub const COLOR_TEMPERATURE: u16 = 1 << 4;
}

/// `ColorMode` / `EnhancedColorMode` values (Tables 5.5, 5.7).
pub mod color_mode {
    /// CurrentHue and CurrentSaturation.
    pub const HUE_SATURATION: u8 = 0x00;
    /// CurrentX and CurrentY.
    pub const XY: u8 = 0x01;
    /// ColorTemperatureMireds.
    pub const COLOR_TEMPERATURE: u8 = 0x02;
    /// EnhancedCurrentHue and CurrentSaturation (enhanced mode only).
    pub const ENHANCED_HUE_SATURATION: u8 = 0x03;
}

/// `Options` bit 0: ExecuteIfOff.
pub const OPTION_EXECUTE_IF_OFF: u8 = 0x01;
/// Largest hue / saturation value.
pub const MAX_HUE: u8 = 0xfe;
/// Largest X / Y / mireds value.
pub const MAX_XY: u16 = 0xfeff;
/// `StartUpColorTemperatureMireds`: previous value.
pub const START_UP_PREVIOUS: u16 = 0xffff;

/// Move to Hue.
pub const CMD_MOVE_TO_HUE: CommandId = CommandId(0x00);
/// Move Hue.
pub const CMD_MOVE_HUE: CommandId = CommandId(0x01);
/// Step Hue.
pub const CMD_STEP_HUE: CommandId = CommandId(0x02);
/// Move to Saturation.
pub const CMD_MOVE_TO_SATURATION: CommandId = CommandId(0x03);
/// Move Saturation.
pub const CMD_MOVE_SATURATION: CommandId = CommandId(0x04);
/// Step Saturation.
pub const CMD_STEP_SATURATION: CommandId = CommandId(0x05);
/// Move to Hue and Saturation.
pub const CMD_MOVE_TO_HUE_AND_SATURATION: CommandId = CommandId(0x06);
/// Move to Color.
pub const CMD_MOVE_TO_COLOR: CommandId = CommandId(0x07);
/// Move Color.
pub const CMD_MOVE_COLOR: CommandId = CommandId(0x08);
/// Step Color.
pub const CMD_STEP_COLOR: CommandId = CommandId(0x09);
/// Move to Color Temperature.
pub const CMD_MOVE_TO_COLOR_TEMPERATURE: CommandId = CommandId(0x0a);
/// Enhanced Move to Hue.
pub const CMD_ENHANCED_MOVE_TO_HUE: CommandId = CommandId(0x40);
/// Enhanced Move Hue.
pub const CMD_ENHANCED_MOVE_HUE: CommandId = CommandId(0x41);
/// Enhanced Step Hue.
pub const CMD_ENHANCED_STEP_HUE: CommandId = CommandId(0x42);
/// Enhanced Move to Hue and Saturation.
pub const CMD_ENHANCED_MOVE_TO_HUE_AND_SATURATION: CommandId = CommandId(0x43);
/// Color Loop Set.
pub const CMD_COLOR_LOOP_SET: CommandId = CommandId(0x44);
/// Stop Move Step.
pub const CMD_STOP_MOVE_STEP: CommandId = CommandId(0x47);
/// Move Color Temperature.
pub const CMD_MOVE_COLOR_TEMPERATURE: CommandId = CommandId(0x4b);
/// Step Color Temperature.
pub const CMD_STEP_COLOR_TEMPERATURE: CommandId = CommandId(0x4c);

/// Cluster definition (every command).
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 5,
    received: &[
        CMD_MOVE_TO_HUE,
        CMD_MOVE_HUE,
        CMD_STEP_HUE,
        CMD_MOVE_TO_SATURATION,
        CMD_MOVE_SATURATION,
        CMD_STEP_SATURATION,
        CMD_MOVE_TO_HUE_AND_SATURATION,
        CMD_MOVE_TO_COLOR,
        CMD_MOVE_COLOR,
        CMD_STEP_COLOR,
        CMD_MOVE_TO_COLOR_TEMPERATURE,
        CMD_ENHANCED_MOVE_TO_HUE,
        CMD_ENHANCED_MOVE_HUE,
        CMD_ENHANCED_STEP_HUE,
        CMD_ENHANCED_MOVE_TO_HUE_AND_SATURATION,
        CMD_COLOR_LOOP_SET,
        CMD_STOP_MOVE_STEP,
        CMD_MOVE_COLOR_TEMPERATURE,
        CMD_STEP_COLOR_TEMPERATURE,
    ],
    generated: &[],
};

/// Transition tick.
pub const TICK: Duration = Duration::from_millis(100);
/// Default reporting of the colour attributes (on change, hourly).
pub const DEFAULT_REPORTING: DefaultReporting = DefaultReporting {
    min: 1,
    max: 3600,
    change: 1,
};

/// One channel's motion: a timed transition or a rate-driven move.
/// Values are in the attribute's units (enhanced hue for hue).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Motion {
    /// Running.
    pub active: bool,
    /// Value at `start`.
    pub from: i32,
    /// Value at `end` (timed); ignored for rate moves.
    pub target: i32,
    /// Start.
    pub start: Instant,
    /// End of a timed transition.
    pub end: Instant,
    /// Units per second for a rate move (0 = timed transition).
    pub rate: i32,
    /// Wrap around modulo this span (hue), or clamp into `min..=max`.
    pub wrap: Option<i32>,
    /// Lower clamp.
    pub min: i32,
    /// Upper clamp.
    pub max: i32,
}

impl Motion {
    /// Value at `now`, and whether the motion is finished.
    fn value_at(&self, now: Instant) -> (i64, bool) {
        let (from, target, min, max) = (
            i64::from(self.from),
            i64::from(self.target),
            i64::from(self.min),
            i64::from(self.max),
        );
        let wrap = self.wrap.map(i64::from);
        if !self.active {
            return (from, true);
        }
        let elapsed = i64::try_from(now.saturating_duration_since(self.start).as_millis())
            .unwrap_or(i64::MAX);
        if self.rate != 0 {
            let v = from.saturating_add(i64::from(self.rate).saturating_mul(elapsed) / 1000);
            return match wrap {
                Some(w) => (v.rem_euclid(w), false),
                None => {
                    let c = v.clamp(min, max);
                    (c, c != v)
                }
            };
        }
        let total = i64::try_from(self.end.saturating_duration_since(self.start).as_millis())
            .unwrap_or(i64::MAX);
        if elapsed >= total {
            let t = match wrap {
                Some(w) => target.rem_euclid(w),
                None => target,
            };
            return (t, true);
        }
        let v = from.saturating_add((target - from).saturating_mul(elapsed) / total);
        (
            match wrap {
                Some(w) => v.rem_euclid(w),
                None => v,
            },
            false,
        )
    }
}

/// Engine state of a server.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Engine {
    /// Enhanced hue motion (0..0x10000, wraps).
    pub hue: Motion,
    /// Saturation motion.
    pub saturation: Motion,
    /// X motion.
    pub x: Motion,
    /// Y motion.
    pub y: Motion,
    /// Colour temperature motion.
    pub temperature: Motion,
    /// Colour loop running (rate on the enhanced hue).
    pub color_loop: Motion,
}

/// Builds a server with the given `capabilities` (Table 5.8) and, when
/// colour temperature is supported, the physical mired range.
pub fn server<const A: usize>(
    capabilities: u16,
    mireds_range: (u16, u16),
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    let hs = capabilities & capability::HUE_SATURATION != 0;
    let enhanced = capabilities & capability::ENHANCED_HUE != 0;
    let color_loop = capabilities & capability::COLOR_LOOP != 0;
    let xy = capabilities & capability::XY != 0;
    let temp = capabilities & capability::COLOR_TEMPERATURE != 0;
    if (enhanced && !hs) || (color_loop && !enhanced) || capabilities & !0x1f != 0 {
        return Err(ZclStatus::InvalidValue);
    }
    if hs {
        c.add_reported_attribute(CURRENT_HUE, &u8v(0), DEFAULT_REPORTING)?;
        c.add_reported_attribute(CURRENT_SATURATION, &u8v(0), DEFAULT_REPORTING)?;
    }
    c.add_attribute(REMAINING_TIME, &u16v(0))?;
    if xy {
        c.add_reported_attribute(CURRENT_X, &u16v(0x616b), DEFAULT_REPORTING)?;
        c.add_reported_attribute(CURRENT_Y, &u16v(0x607d), DEFAULT_REPORTING)?;
    }
    if temp {
        c.add_reported_attribute(COLOR_TEMPERATURE_MIREDS, &u16v(0x00fa), DEFAULT_REPORTING)?;
    }
    let initial_mode = if temp && !hs && !xy {
        color_mode::COLOR_TEMPERATURE
    } else if xy && !hs {
        color_mode::XY
    } else {
        color_mode::HUE_SATURATION
    };
    c.add_attribute(COLOR_MODE, &Value::Enum8(initial_mode))?;
    c.add_attribute(OPTIONS, &Value::Bits { width: 1, bits: 0 })?;
    if enhanced {
        c.add_attribute(ENHANCED_CURRENT_HUE, &u16v(0))?;
    }
    c.add_attribute(ENHANCED_COLOR_MODE, &Value::Enum8(initial_mode))?;
    if color_loop {
        c.add_attribute(COLOR_LOOP_ACTIVE, &u8v(0))?;
        c.add_attribute(COLOR_LOOP_DIRECTION, &u8v(0))?;
        c.add_attribute(COLOR_LOOP_TIME, &u16v(0x0019))?;
        c.add_attribute(COLOR_LOOP_START_ENHANCED_HUE, &u16v(0x2300))?;
        c.add_attribute(COLOR_LOOP_STORED_ENHANCED_HUE, &u16v(0))?;
    }
    c.add_attribute(
        COLOR_CAPABILITIES,
        &Value::Bits {
            width: 2,
            bits: u64::from(capabilities),
        },
    )?;
    if temp {
        let (min, max) = mireds_range;
        if min == 0 || min > max || max > MAX_XY {
            return Err(ZclStatus::InvalidValue);
        }
        c.add_attribute(COLOR_TEMP_PHYSICAL_MIN_MIREDS, &u16v(min))?;
        c.add_attribute(COLOR_TEMP_PHYSICAL_MAX_MIREDS, &u16v(max))?;
        c.add_attribute(COUPLE_COLOR_TEMP_TO_LEVEL_MIN_MIREDS, &u16v(min))?;
        c.add_attribute(START_UP_COLOR_TEMPERATURE_MIREDS, &u16v(START_UP_PREVIOUS))?;
        c.set_u16(COLOR_TEMPERATURE_MIREDS.id, 0x00fa.clamp(min, max));
    }
    c.state = ClusterState::Color(Engine::default());
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

const fn u8v(v: u8) -> Value<'static> {
    Value::Uint {
        width: 1,
        value: v as u64,
    }
}

const fn u16v(v: u16) -> Value<'static> {
    Value::Uint {
        width: 2,
        value: v as u64,
    }
}

fn engine<const A: usize>(c: &mut ClusterInstance<A>) -> &mut Engine {
    if !matches!(c.state, ClusterState::Color(_)) {
        c.state = ClusterState::Color(Engine::default());
    }
    match &mut c.state {
        ClusterState::Color(e) => e,
        _ => unreachable!(),
    }
}

/// Capabilities of a server.
pub fn capabilities<const A: usize>(c: &ClusterInstance<A>) -> u16 {
    c.u16(COLOR_CAPABILITIES.id).unwrap_or(0)
}

/// Current enhanced hue (derived from `CurrentHue` without the enhanced
/// attribute).
pub fn enhanced_hue<const A: usize>(c: &ClusterInstance<A>) -> u16 {
    c.u16(ENHANCED_CURRENT_HUE.id)
        .unwrap_or_else(|| u16::from(c.u8(CURRENT_HUE.id).unwrap_or(0)) << 8)
}

fn set_enhanced_hue<const A: usize>(c: &mut ClusterInstance<A>, hue: u16) -> bool {
    let mut changed = false;
    if c.attributes.get(ENHANCED_CURRENT_HUE.id, None).is_some() {
        changed |= c.set_u16(ENHANCED_CURRENT_HUE.id, hue);
    }
    let h8 = u8::try_from(hue >> 8).unwrap_or(MAX_HUE).min(MAX_HUE);
    changed | c.set_u8(CURRENT_HUE.id, h8)
}

fn set_mode<const A: usize>(c: &mut ClusterInstance<A>, mode: u8) {
    let basic = if mode == color_mode::ENHANCED_HUE_SATURATION {
        color_mode::HUE_SATURATION
    } else {
        mode
    };
    c.set(COLOR_MODE.id, &Value::Enum8(basic));
    c.set(ENHANCED_COLOR_MODE.id, &Value::Enum8(mode));
}

/// Applies the OptionsMask / OptionsOverride pair (§5.2.2.3.3) and the
/// ExecuteIfOff rule: whether the command executes.
fn executes<const A: usize>(
    c: &ClusterInstance<A>,
    on_off: Option<bool>,
    mask: u8,
    over: u8,
) -> bool {
    let options = c.u8(OPTIONS.id).unwrap_or(0);
    let temp = (options & !mask) | (over & mask);
    on_off != Some(false) || temp & OPTION_EXECUTE_IF_OFF != 0
}

/// Result of a received command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Applied (a Default Response with SUCCESS applies).
    Applied,
    /// Not executed: the endpoint is off and ExecuteIfOff is clear.
    Suppressed,
    /// Refused with this status.
    Default(ZclStatus),
}

/// Hue direction of Move to Hue (Table 5.14).
pub mod direction {
    /// Shortest distance.
    pub const SHORTEST: u8 = 0x00;
    /// Longest distance.
    pub const LONGEST: u8 = 0x01;
    /// Up.
    pub const UP: u8 = 0x02;
    /// Down.
    pub const DOWN: u8 = 0x03;
}

/// Move / step modes (Tables 5.15, 5.17).
pub mod mode {
    /// Stop (move only).
    pub const STOP: u8 = 0x00;
    /// Up.
    pub const UP: u8 = 0x01;
    /// Down.
    pub const DOWN: u8 = 0x03;
}

const HUE_SPAN: i64 = 0x1_0000;

/// Signed distance on the hue circle from `from` to `target` for a
/// direction (both in 0..span).
fn hue_delta(from: i64, target: i64, span: i64, dir: u8) -> Option<i64> {
    let up = (target - from).rem_euclid(span);
    let down = up - span; // negative or zero
    Some(match dir {
        direction::UP => up,
        direction::DOWN => down,
        direction::SHORTEST => {
            if up <= -down {
                up
            } else {
                down
            }
        }
        direction::LONGEST => {
            if up >= -down {
                up
            } else {
                down
            }
        }
        _ => return None,
    })
}

fn i32c(v: i64) -> i32 {
    i32::try_from(v).unwrap_or(if v < 0 { i32::MIN } else { i32::MAX })
}

fn timed(
    from: i64,
    target: i64,
    tenths: u16,
    now: Instant,
    wrap: Option<i64>,
    min: i64,
    max: i64,
) -> Motion {
    Motion {
        active: true,
        from: i32c(from),
        target: i32c(target),
        start: now,
        end: now + Duration::from_millis(u64::from(tenths) * 100),
        rate: 0,
        wrap: wrap.map(i32c),
        min: i32c(min),
        max: i32c(max),
    }
}

fn moving(from: i64, rate: i32, now: Instant, wrap: Option<i64>, min: i64, max: i64) -> Motion {
    Motion {
        active: true,
        from: i32c(from),
        target: i32c(from),
        start: now,
        end: now,
        rate,
        wrap: wrap.map(i32c),
        min: i32c(min),
        max: i32c(max),
    }
}

fn stop_all(e: &mut Engine) {
    e.hue.active = false;
    e.saturation.active = false;
    e.x.active = false;
    e.y.active = false;
    e.temperature.active = false;
}

fn read_options(r: &mut Reader<'_>) -> (u8, u8) {
    let mask = r.u8().unwrap_or(0);
    let over = r.u8().unwrap_or(0);
    (mask, over)
}

/// Processes a cluster-specific server command (§5.2.2.3); `on_off` is
/// the endpoint's `OnOff` value when an On/Off server is present.
#[allow(clippy::too_many_lines)]
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    command: CommandId,
    payload: &[u8],
    on_off: Option<bool>,
    now: Instant,
) -> Outcome {
    let caps = capabilities(c);
    let has = |bit: u16| caps & bit != 0;
    let mut r = Reader::new(payload);
    macro_rules! field {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(_) => return Outcome::Default(ZclStatus::MalformedCommand),
            }
        };
    }
    let sat_now = i64::from(c.u8(CURRENT_SATURATION.id).unwrap_or(0));
    let hue_now = i64::from(enhanced_hue(c));
    let x_now = i64::from(c.u16(CURRENT_X.id).unwrap_or(0));
    let y_now = i64::from(c.u16(CURRENT_Y.id).unwrap_or(0));
    let temp_now = i64::from(c.u16(COLOR_TEMPERATURE_MIREDS.id).unwrap_or(0));
    let phys_min = i64::from(c.u16(COLOR_TEMP_PHYSICAL_MIN_MIREDS.id).unwrap_or(1));
    let phys_max = i64::from(c.u16(COLOR_TEMP_PHYSICAL_MAX_MIREDS.id).unwrap_or(MAX_XY));
    let sat_range = (0, i64::from(MAX_HUE));
    let xy_range = (0, i64::from(MAX_XY));
    match command {
        CMD_MOVE_TO_HUE | CMD_ENHANCED_MOVE_TO_HUE => {
            let enhanced = command == CMD_ENHANCED_MOVE_TO_HUE;
            if !has(if enhanced {
                capability::ENHANCED_HUE
            } else {
                capability::HUE_SATURATION
            }) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let target = if enhanced {
                i64::from(field!(r.u16_le()))
            } else {
                i64::from(field!(r.u8()).min(MAX_HUE)) << 8
            };
            let dir = field!(r.u8());
            let time = field!(r.u16_le());
            let (mask, over) = read_options(&mut r);
            let Some(delta) = hue_delta(hue_now, target, HUE_SPAN, dir) else {
                return Outcome::Default(ZclStatus::InvalidValue);
            };
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(
                c,
                if enhanced {
                    color_mode::ENHANCED_HUE_SATURATION
                } else {
                    color_mode::HUE_SATURATION
                },
            );
            let e = engine(c);
            stop_all(e);
            e.hue = timed(
                hue_now,
                hue_now + delta,
                time,
                now,
                Some(HUE_SPAN),
                0,
                HUE_SPAN,
            );
        }
        CMD_MOVE_HUE | CMD_ENHANCED_MOVE_HUE => {
            let enhanced = command == CMD_ENHANCED_MOVE_HUE;
            if !has(if enhanced {
                capability::ENHANCED_HUE
            } else {
                capability::HUE_SATURATION
            }) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let m = field!(r.u8());
            let rate = if enhanced {
                i32::from(field!(r.u16_le()))
            } else {
                i32::from(field!(r.u8())) << 8
            };
            let (mask, over) = read_options(&mut r);
            if !matches!(m, mode::STOP | mode::UP | mode::DOWN) {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if m != mode::STOP && rate == 0 {
                return Outcome::Default(ZclStatus::InvalidField);
            }
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(
                c,
                if enhanced {
                    color_mode::ENHANCED_HUE_SATURATION
                } else {
                    color_mode::HUE_SATURATION
                },
            );
            let e = engine(c);
            if m == mode::STOP {
                stop_all(e);
            } else {
                stop_all(e);
                let signed = if m == mode::UP { rate } else { -rate };
                e.hue = moving(hue_now, signed, now, Some(HUE_SPAN), 0, HUE_SPAN);
            }
        }
        CMD_STEP_HUE | CMD_ENHANCED_STEP_HUE => {
            let enhanced = command == CMD_ENHANCED_STEP_HUE;
            if !has(if enhanced {
                capability::ENHANCED_HUE
            } else {
                capability::HUE_SATURATION
            }) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let m = field!(r.u8());
            let (size, time) = if enhanced {
                (i64::from(field!(r.u16_le())), field!(r.u16_le()))
            } else {
                (i64::from(field!(r.u8())) << 8, u16::from(field!(r.u8())))
            };
            let (mask, over) = read_options(&mut r);
            if !matches!(m, mode::UP | mode::DOWN) {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(
                c,
                if enhanced {
                    color_mode::ENHANCED_HUE_SATURATION
                } else {
                    color_mode::HUE_SATURATION
                },
            );
            let delta = if m == mode::UP { size } else { -size };
            let e = engine(c);
            stop_all(e);
            e.hue = timed(
                hue_now,
                hue_now + delta,
                time,
                now,
                Some(HUE_SPAN),
                0,
                HUE_SPAN,
            );
        }
        CMD_MOVE_TO_SATURATION => {
            if !has(capability::HUE_SATURATION) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let target = i64::from(field!(r.u8()).min(MAX_HUE));
            let time = field!(r.u16_le());
            let (mask, over) = read_options(&mut r);
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::HUE_SATURATION);
            let e = engine(c);
            stop_all(e);
            e.saturation = timed(sat_now, target, time, now, None, sat_range.0, sat_range.1);
        }
        CMD_MOVE_SATURATION => {
            if !has(capability::HUE_SATURATION) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let m = field!(r.u8());
            let rate = i32::from(field!(r.u8()));
            let (mask, over) = read_options(&mut r);
            if !matches!(m, mode::STOP | mode::UP | mode::DOWN) {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if m != mode::STOP && rate == 0 {
                return Outcome::Default(ZclStatus::InvalidField);
            }
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::HUE_SATURATION);
            let e = engine(c);
            stop_all(e);
            if m != mode::STOP {
                let signed = if m == mode::UP { rate } else { -rate };
                e.saturation = moving(sat_now, signed, now, None, sat_range.0, sat_range.1);
            }
        }
        CMD_STEP_SATURATION => {
            if !has(capability::HUE_SATURATION) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let m = field!(r.u8());
            let size = i64::from(field!(r.u8()));
            let time = u16::from(field!(r.u8()));
            let (mask, over) = read_options(&mut r);
            if !matches!(m, mode::UP | mode::DOWN) {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::HUE_SATURATION);
            let target = if m == mode::UP {
                sat_now + size
            } else {
                sat_now - size
            }
            .clamp(sat_range.0, sat_range.1);
            let e = engine(c);
            stop_all(e);
            e.saturation = timed(sat_now, target, time, now, None, sat_range.0, sat_range.1);
        }
        CMD_MOVE_TO_HUE_AND_SATURATION | CMD_ENHANCED_MOVE_TO_HUE_AND_SATURATION => {
            let enhanced = command == CMD_ENHANCED_MOVE_TO_HUE_AND_SATURATION;
            if !has(if enhanced {
                capability::ENHANCED_HUE
            } else {
                capability::HUE_SATURATION
            }) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let hue = if enhanced {
                i64::from(field!(r.u16_le()))
            } else {
                i64::from(field!(r.u8()).min(MAX_HUE)) << 8
            };
            let sat = i64::from(field!(r.u8()).min(MAX_HUE));
            let time = field!(r.u16_le());
            let (mask, over) = read_options(&mut r);
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(
                c,
                if enhanced {
                    color_mode::ENHANCED_HUE_SATURATION
                } else {
                    color_mode::HUE_SATURATION
                },
            );
            let delta = hue_delta(hue_now, hue, HUE_SPAN, direction::SHORTEST).unwrap_or(0);
            let e = engine(c);
            stop_all(e);
            e.hue = timed(
                hue_now,
                hue_now + delta,
                time,
                now,
                Some(HUE_SPAN),
                0,
                HUE_SPAN,
            );
            e.saturation = timed(sat_now, sat, time, now, None, sat_range.0, sat_range.1);
        }
        CMD_MOVE_TO_COLOR => {
            if !has(capability::XY) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let x = i64::from(field!(r.u16_le()).min(MAX_XY));
            let y = i64::from(field!(r.u16_le()).min(MAX_XY));
            let time = field!(r.u16_le());
            let (mask, over) = read_options(&mut r);
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::XY);
            let e = engine(c);
            stop_all(e);
            e.x = timed(x_now, x, time, now, None, xy_range.0, xy_range.1);
            e.y = timed(y_now, y, time, now, None, xy_range.0, xy_range.1);
        }
        CMD_MOVE_COLOR => {
            if !has(capability::XY) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let rx = i32::from(field!(r.i16_le()));
            let ry = i32::from(field!(r.i16_le()));
            let (mask, over) = read_options(&mut r);
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::XY);
            let e = engine(c);
            stop_all(e);
            if rx != 0 {
                e.x = moving(x_now, rx, now, None, xy_range.0, xy_range.1);
            }
            if ry != 0 {
                e.y = moving(y_now, ry, now, None, xy_range.0, xy_range.1);
            }
        }
        CMD_STEP_COLOR => {
            if !has(capability::XY) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let sx = i64::from(field!(r.i16_le()));
            let sy = i64::from(field!(r.i16_le()));
            let time = field!(r.u16_le());
            let (mask, over) = read_options(&mut r);
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::XY);
            let e = engine(c);
            stop_all(e);
            e.x = timed(
                x_now,
                (x_now + sx).clamp(xy_range.0, xy_range.1),
                time,
                now,
                None,
                xy_range.0,
                xy_range.1,
            );
            e.y = timed(
                y_now,
                (y_now + sy).clamp(xy_range.0, xy_range.1),
                time,
                now,
                None,
                xy_range.0,
                xy_range.1,
            );
        }
        CMD_MOVE_TO_COLOR_TEMPERATURE => {
            if !has(capability::COLOR_TEMPERATURE) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let target = i64::from(field!(r.u16_le()));
            let time = field!(r.u16_le());
            let (mask, over) = read_options(&mut r);
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::COLOR_TEMPERATURE);
            // Unachievable targets are clipped at the physical range
            // (§5.2.2.3.1).
            let target = target.clamp(phys_min, phys_max);
            let e = engine(c);
            stop_all(e);
            e.temperature = timed(temp_now, target, time, now, None, phys_min, phys_max);
        }
        CMD_MOVE_COLOR_TEMPERATURE => {
            if !has(capability::COLOR_TEMPERATURE) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let m = field!(r.u8());
            let rate = i32::from(field!(r.u16_le()));
            let min = i64::from(field!(r.u16_le()));
            let max = i64::from(field!(r.u16_le()));
            let (mask, over) = read_options(&mut r);
            if !matches!(m, mode::STOP | mode::UP | mode::DOWN) {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if m != mode::STOP && rate == 0 {
                return Outcome::Default(ZclStatus::InvalidField);
            }
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::COLOR_TEMPERATURE);
            let lo = if min == 0 {
                phys_min
            } else {
                min.max(phys_min)
            };
            let hi = if max == 0 {
                phys_max
            } else {
                max.min(phys_max)
            };
            let e = engine(c);
            stop_all(e);
            if m != mode::STOP {
                let signed = if m == mode::UP { rate } else { -rate };
                e.temperature = moving(temp_now, signed, now, None, lo, hi.max(lo));
            }
        }
        CMD_STEP_COLOR_TEMPERATURE => {
            if !has(capability::COLOR_TEMPERATURE) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let m = field!(r.u8());
            let size = i64::from(field!(r.u16_le()));
            let time = field!(r.u16_le());
            let min = i64::from(field!(r.u16_le()));
            let max = i64::from(field!(r.u16_le()));
            let (mask, over) = read_options(&mut r);
            if !matches!(m, mode::UP | mode::DOWN) {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            set_mode(c, color_mode::COLOR_TEMPERATURE);
            let lo = if min == 0 {
                phys_min
            } else {
                min.max(phys_min)
            };
            let hi = if max == 0 {
                phys_max
            } else {
                max.min(phys_max)
            }
            .max(lo);
            let target = if m == mode::UP {
                temp_now + size
            } else {
                temp_now - size
            }
            .clamp(lo, hi);
            let e = engine(c);
            stop_all(e);
            e.temperature = timed(temp_now, target, time, now, None, lo, hi);
        }
        CMD_COLOR_LOOP_SET => {
            if !has(capability::COLOR_LOOP) {
                return Outcome::Default(ZclStatus::UnsupportedClusterCommand);
            }
            let flags = field!(r.u8());
            let action = field!(r.u8());
            let dir = field!(r.u8());
            let time = field!(r.u16_le());
            let start_hue = field!(r.u16_le());
            let (mask, over) = read_options(&mut r);
            if flags & 0x01 != 0 && action > 0x02 || flags & 0x02 != 0 && dir > 0x01 {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            if flags & 0x02 != 0 {
                c.set_u8(COLOR_LOOP_DIRECTION.id, dir);
            }
            if flags & 0x04 != 0 {
                c.set_u16(COLOR_LOOP_TIME.id, time);
            }
            if flags & 0x08 != 0 {
                c.set_u16(COLOR_LOOP_START_ENHANCED_HUE.id, start_hue);
            }
            let active = c.u8(COLOR_LOOP_ACTIVE.id) == Some(1);
            if flags & 0x01 != 0 {
                match action {
                    0x00 if active => {
                        c.set_u8(COLOR_LOOP_ACTIVE.id, 0);
                        let stored = c.u16(COLOR_LOOP_STORED_ENHANCED_HUE.id).unwrap_or(0);
                        set_enhanced_hue(c, stored);
                        engine(c).color_loop.active = false;
                    }
                    0x01 | 0x02 => {
                        let current = enhanced_hue(c);
                        c.set_u16(COLOR_LOOP_STORED_ENHANCED_HUE.id, current);
                        c.set_u8(COLOR_LOOP_ACTIVE.id, 1);
                        let from = if action == 0x01 {
                            c.u16(COLOR_LOOP_START_ENHANCED_HUE.id).unwrap_or(0)
                        } else {
                            current
                        };
                        set_enhanced_hue(c, from);
                        set_mode(c, color_mode::ENHANCED_HUE_SATURATION);
                    }
                    _ => {}
                }
            }
            // A running loop follows the (possibly updated) direction and
            // time at once.
            if c.u8(COLOR_LOOP_ACTIVE.id) == Some(1) {
                let secs = i64::from(c.u16(COLOR_LOOP_TIME.id).unwrap_or(1).max(1));
                let rate = i32::try_from(HUE_SPAN / secs).unwrap_or(i32::MAX);
                let signed = if c.u8(COLOR_LOOP_DIRECTION.id) == Some(1) {
                    rate
                } else {
                    -rate
                };
                let from = i64::from(enhanced_hue(c));
                let e = engine(c);
                e.hue.active = false;
                e.color_loop = moving(from, signed, now, Some(HUE_SPAN), 0, HUE_SPAN);
            }
        }
        CMD_STOP_MOVE_STEP => {
            let (mask, over) = read_options(&mut r);
            if !executes(c, on_off, mask, over) {
                return Outcome::Suppressed;
            }
            stop_all(engine(c));
            c.set_u16(REMAINING_TIME.id, 0);
        }
        _ => return Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
    c.tick = Some(now);
    Outcome::Applied
}

/// Result of a tick.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Tick {
    /// An attribute changed.
    pub changed: bool,
    /// Every motion finished (the colour loop excepted).
    pub done: bool,
}

/// Runs the engine once when its tick is due.
pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<Tick> {
    let due = c.tick?;
    if !now.has_reached(due) {
        return None;
    }
    let e = *engine(c);
    let mut changed = false;
    let mut remaining_ms: u64 = 0;
    let mut running = false;
    let mut settle = |m: &Motion| -> (i64, bool) {
        let (v, finished) = m.value_at(now);
        if m.active && !finished {
            running = true;
            if m.rate == 0 {
                remaining_ms = remaining_ms.max(m.end.saturating_duration_since(now).as_millis());
            }
        }
        (v, finished)
    };
    if e.color_loop.active {
        let (v, _) = settle(&e.color_loop);
        changed |= set_enhanced_hue(c, u16::try_from(v).unwrap_or(0));
    } else if e.hue.active {
        let (v, fin) = settle(&e.hue);
        changed |= set_enhanced_hue(c, u16::try_from(v.rem_euclid(HUE_SPAN)).unwrap_or(0));
        if fin {
            engine(c).hue.active = false;
        }
    }
    if e.saturation.active {
        let (v, fin) = settle(&e.saturation);
        changed |= c.set_u8(CURRENT_SATURATION.id, u8::try_from(v).unwrap_or(MAX_HUE));
        if fin {
            engine(c).saturation.active = false;
        }
    }
    if e.x.active {
        let (v, fin) = settle(&e.x);
        changed |= c.set_u16(CURRENT_X.id, u16::try_from(v).unwrap_or(MAX_XY));
        if fin {
            engine(c).x.active = false;
        }
    }
    if e.y.active {
        let (v, fin) = settle(&e.y);
        changed |= c.set_u16(CURRENT_Y.id, u16::try_from(v).unwrap_or(MAX_XY));
        if fin {
            engine(c).y.active = false;
        }
    }
    if e.temperature.active {
        let (v, fin) = settle(&e.temperature);
        changed |= c.set_u16(
            COLOR_TEMPERATURE_MIREDS.id,
            u16::try_from(v).unwrap_or(MAX_XY),
        );
        if fin {
            engine(c).temperature.active = false;
        }
    }
    let e = *engine(c);
    let any =
        e.hue.active || e.saturation.active || e.x.active || e.y.active || e.temperature.active;
    c.set_u16(
        REMAINING_TIME.id,
        u16::try_from(remaining_ms.div_ceil(100)).unwrap_or(u16::MAX),
    );
    c.tick = if any || e.color_loop.active {
        Some(now + TICK)
    } else {
        None
    };
    Some(Tick {
        changed,
        done: !any,
    })
}

/// Scene extension field set (§5.2.2.5): CurrentX, CurrentY,
/// EnhancedCurrentHue, CurrentSaturation, ColorLoopActive,
/// ColorLoopDirection, ColorLoopTime, ColorTemperatureMireds.
pub fn scene_fields<const A: usize>(c: &ClusterInstance<A>) -> [u8; 13] {
    let mut f = [0u8; 13];
    f[..2].copy_from_slice(&c.u16(CURRENT_X.id).unwrap_or(0).to_le_bytes());
    f[2..4].copy_from_slice(&c.u16(CURRENT_Y.id).unwrap_or(0).to_le_bytes());
    f[4..6].copy_from_slice(&enhanced_hue(c).to_le_bytes());
    f[6] = c.u8(CURRENT_SATURATION.id).unwrap_or(0);
    f[7] = c.u8(COLOR_LOOP_ACTIVE.id).unwrap_or(0);
    f[8] = c.u8(COLOR_LOOP_DIRECTION.id).unwrap_or(0);
    f[9..11].copy_from_slice(&c.u16(COLOR_LOOP_TIME.id).unwrap_or(0).to_le_bytes());
    f[11..13].copy_from_slice(
        &c.u16(COLOR_TEMPERATURE_MIREDS.id)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    f
}

/// Applies a scene extension field set over `tenths` tenths of a
/// second, in the colour mode the device is in (the fields of
/// unsupported attributes are ignored, §5.2.2.5).
pub fn apply_scene_fields<const A: usize>(
    c: &mut ClusterInstance<A>,
    fields: &[u8],
    tenths: u16,
    now: Instant,
) {
    let mut r = Reader::new(fields);
    let x = r.u16_le().ok();
    let y = r.u16_le().ok();
    let hue = r.u16_le().ok();
    let sat = r.u8().ok();
    let loop_active = r.u8().ok();
    let loop_dir = r.u8().ok();
    let loop_time = r.u16_le().ok();
    let temp = r.u16_le().ok();
    let caps = capabilities(c);
    let mode = c.u8(ENHANCED_COLOR_MODE.id).unwrap_or(0);
    let e_stop = engine(c);
    stop_all(e_stop);
    e_stop.color_loop.active = false;
    let hue_now = i64::from(enhanced_hue(c));
    let sat_now = i64::from(c.u8(CURRENT_SATURATION.id).unwrap_or(0));
    match mode {
        color_mode::XY if caps & capability::XY != 0 => {
            if let (Some(x), Some(y)) = (x, y) {
                let (xn, yn) = (
                    i64::from(c.u16(CURRENT_X.id).unwrap_or(0)),
                    i64::from(c.u16(CURRENT_Y.id).unwrap_or(0)),
                );
                let e = engine(c);
                e.x = timed(
                    xn,
                    i64::from(x.min(MAX_XY)),
                    tenths,
                    now,
                    None,
                    0,
                    i64::from(MAX_XY),
                );
                e.y = timed(
                    yn,
                    i64::from(y.min(MAX_XY)),
                    tenths,
                    now,
                    None,
                    0,
                    i64::from(MAX_XY),
                );
            }
        }
        color_mode::COLOR_TEMPERATURE if caps & capability::COLOR_TEMPERATURE != 0 => {
            if let Some(t) = temp {
                let (min, max) = (
                    i64::from(c.u16(COLOR_TEMP_PHYSICAL_MIN_MIREDS.id).unwrap_or(1)),
                    i64::from(c.u16(COLOR_TEMP_PHYSICAL_MAX_MIREDS.id).unwrap_or(MAX_XY)),
                );
                let tn = i64::from(c.u16(COLOR_TEMPERATURE_MIREDS.id).unwrap_or(0));
                let e = engine(c);
                e.temperature = timed(
                    tn,
                    i64::from(t).clamp(min, max),
                    tenths,
                    now,
                    None,
                    min,
                    max,
                );
            }
        }
        _ if caps & capability::HUE_SATURATION != 0 => {
            if let (Some(h), Some(s)) = (hue, sat) {
                let delta =
                    hue_delta(hue_now, i64::from(h), HUE_SPAN, direction::SHORTEST).unwrap_or(0);
                let e = engine(c);
                e.hue = timed(
                    hue_now,
                    hue_now + delta,
                    tenths,
                    now,
                    Some(HUE_SPAN),
                    0,
                    HUE_SPAN,
                );
                e.saturation = timed(
                    sat_now,
                    i64::from(s.min(MAX_HUE)),
                    tenths,
                    now,
                    None,
                    0,
                    i64::from(MAX_HUE),
                );
            }
            if caps & capability::COLOR_LOOP != 0
                && let (Some(a), Some(d), Some(t)) = (loop_active, loop_dir, loop_time)
            {
                c.set_u8(COLOR_LOOP_ACTIVE.id, a.min(1));
                c.set_u8(COLOR_LOOP_DIRECTION.id, d.min(1));
                c.set_u16(COLOR_LOOP_TIME.id, t);
            }
        }
        _ => {}
    }
    c.tick = Some(now);
}

/// Applies `StartUpColorTemperatureMireds` at power-up (Table 5.9).
pub fn start_up<const A: usize>(c: &mut ClusterInstance<A>) {
    match c.u16(START_UP_COLOR_TEMPERATURE_MIREDS.id) {
        Some(START_UP_PREVIOUS) | None => {}
        Some(v) => {
            let min = c.u16(COLOR_TEMP_PHYSICAL_MIN_MIREDS.id).unwrap_or(1);
            let max = c.u16(COLOR_TEMP_PHYSICAL_MAX_MIREDS.id).unwrap_or(MAX_XY);
            c.set_u16(COLOR_TEMPERATURE_MIREDS.id, v.clamp(min, max));
            set_mode(c, color_mode::COLOR_TEMPERATURE);
        }
    }
}

/// The attribute identifier of `ColorTemperatureMireds`.
pub const fn color_temperature_id() -> AttributeId {
    COLOR_TEMPERATURE_MIREDS.id
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u16 = capability::HUE_SATURATION
        | capability::ENHANCED_HUE
        | capability::COLOR_LOOP
        | capability::XY
        | capability::COLOR_TEMPERATURE;

    fn run<const A: usize>(c: &mut ClusterInstance<A>, from: Instant, to: Instant) -> Option<Tick> {
        let mut t = from;
        let mut last = None;
        while t.as_millis() <= to.as_millis() {
            if let Some(k) = tick(c, t) {
                last = Some(k);
            }
            t += TICK;
        }
        last
    }

    #[test]
    fn hue_directions_and_timed_transition() {
        let t0 = Instant::from_millis(0);
        let mut c: ClusterInstance<36> = server(ALL, (153, 500)).unwrap();
        // Move to hue 200 (of 254) the shortest way from 0: down through
        // the wrap, in 1 s.
        let out = handle(
            &mut c,
            CMD_MOVE_TO_HUE,
            &[200, direction::SHORTEST, 10, 0, 0, 0],
            Some(true),
            t0,
        );
        assert_eq!(out, Outcome::Applied);
        assert_eq!(c.u8(COLOR_MODE.id), Some(color_mode::HUE_SATURATION));
        let k = tick(&mut c, t0 + Duration::from_millis(500)).unwrap();
        assert!(k.changed && !k.done);
        let mid = c.u8(CURRENT_HUE.id).unwrap();
        assert!(mid > 200 && mid < 255, "{mid}");
        assert!(c.u16(REMAINING_TIME.id).unwrap() <= 5);
        let k = run(
            &mut c,
            t0 + Duration::from_millis(600),
            t0 + Duration::from_millis(1100),
        )
        .unwrap();
        assert!(k.done);
        assert_eq!(c.u8(CURRENT_HUE.id), Some(200));
        assert_eq!(c.u16(ENHANCED_CURRENT_HUE.id), Some(200 << 8));
        assert_eq!(c.u16(REMAINING_TIME.id), Some(0));
        // Longest way back to 0: down through 199 … 1 (200 units) rather
        // than up through the wrap (54 units).
        handle(
            &mut c,
            CMD_MOVE_TO_HUE,
            &[0, direction::LONGEST, 10, 0],
            Some(true),
            t0 + Duration::from_secs(2),
        );
        tick(&mut c, t0 + Duration::from_millis(2100)).unwrap();
        let h = c.u8(CURRENT_HUE.id).unwrap();
        assert!((170..200).contains(&h), "{h}");
        // Off with ExecuteIfOff clear: suppressed; overridden: executes.
        assert_eq!(
            handle(
                &mut c,
                CMD_MOVE_TO_SATURATION,
                &[100, 0, 0, 0, 0],
                Some(false),
                t0
            ),
            Outcome::Suppressed
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_MOVE_TO_SATURATION,
                &[100, 0, 0, 1, 1],
                Some(false),
                t0 + Duration::from_secs(3)
            ),
            Outcome::Applied
        );
        tick(&mut c, t0 + Duration::from_secs(3)).unwrap();
        assert_eq!(c.u8(CURRENT_SATURATION.id), Some(100));
        // Move hue with rate 0 is INVALID_FIELD; stop halts a move.
        assert_eq!(
            handle(&mut c, CMD_MOVE_HUE, &[mode::UP, 0], Some(true), t0),
            Outcome::Default(ZclStatus::InvalidField)
        );
        let t4 = t0 + Duration::from_secs(4);
        let h0 = c.u8(CURRENT_HUE.id).unwrap();
        handle(&mut c, CMD_MOVE_HUE, &[mode::UP, 10], Some(true), t4);
        run(&mut c, t4, t4 + Duration::from_secs(1));
        let h = c.u8(CURRENT_HUE.id).unwrap();
        assert!((h0 + 9..=h0 + 11).contains(&h), "{h0} -> {h}");
        handle(
            &mut c,
            CMD_STOP_MOVE_STEP,
            &[],
            Some(true),
            t4 + Duration::from_secs(1),
        );
        run(
            &mut c,
            t4 + Duration::from_secs(1),
            t4 + Duration::from_secs(2),
        );
        assert_eq!(c.u8(CURRENT_HUE.id), Some(h));
    }

    #[test]
    fn xy_temperature_and_color_loop() {
        let t0 = Instant::from_millis(0);
        let mut c: ClusterInstance<36> = server(ALL, (153, 500)).unwrap();
        // Move to colour in 1 s.
        handle(
            &mut c,
            CMD_MOVE_TO_COLOR,
            &[0x00, 0x40, 0x00, 0x20, 10, 0, 0, 0],
            Some(true),
            t0,
        );
        assert_eq!(c.u8(COLOR_MODE.id), Some(color_mode::XY));
        run(&mut c, t0, t0 + Duration::from_millis(1100));
        assert_eq!(c.u16(CURRENT_X.id), Some(0x4000));
        assert_eq!(c.u16(CURRENT_Y.id), Some(0x2000));
        // Step colour by -0x1000 / +0x100 immediately.
        handle(
            &mut c,
            CMD_STEP_COLOR,
            &[0x00, 0xf0, 0x00, 0x01, 0, 0, 0, 0],
            Some(true),
            t0 + Duration::from_secs(2),
        );
        tick(&mut c, t0 + Duration::from_secs(2)).unwrap();
        assert_eq!(c.u16(CURRENT_X.id), Some(0x3000));
        assert_eq!(c.u16(CURRENT_Y.id), Some(0x2100));
        // Colour temperature: an unachievable target is clipped to the
        // physical range; a move stops at the command's bound.
        handle(
            &mut c,
            CMD_MOVE_TO_COLOR_TEMPERATURE,
            &[0x10, 0x27, 0, 0, 0, 0],
            Some(true),
            t0 + Duration::from_secs(3),
        );
        assert_eq!(c.u8(COLOR_MODE.id), Some(color_mode::COLOR_TEMPERATURE));
        tick(&mut c, t0 + Duration::from_secs(3)).unwrap();
        assert_eq!(c.u16(COLOR_TEMPERATURE_MIREDS.id), Some(500));
        let t4 = t0 + Duration::from_secs(4);
        handle(
            &mut c,
            CMD_MOVE_COLOR_TEMPERATURE,
            &[mode::DOWN, 100, 0, 0xc8, 0x01, 0, 0, 0, 0],
            Some(true),
            t4,
        );
        let k = run(&mut c, t4, t4 + Duration::from_secs(1)).unwrap();
        assert_eq!(c.u16(COLOR_TEMPERATURE_MIREDS.id), Some(456));
        assert!(k.done, "the move stops at the command's bound");
        assert!(
            run(
                &mut c,
                t4 + Duration::from_secs(1),
                t4 + Duration::from_secs(2)
            )
            .is_none()
        );
        // Colour loop: activate from the start hue, 2 s per loop, up.
        let t8 = t0 + Duration::from_secs(8);
        c.set_u16(ENHANCED_CURRENT_HUE.id, 0x1234);
        handle(
            &mut c,
            CMD_COLOR_LOOP_SET,
            &[0x0f, 0x01, 0x01, 2, 0, 0x00, 0x10, 0, 0],
            Some(true),
            t8,
        );
        assert_eq!(c.u8(COLOR_LOOP_ACTIVE.id), Some(1));
        assert_eq!(c.u16(COLOR_LOOP_STORED_ENHANCED_HUE.id), Some(0x1234));
        assert_eq!(c.u16(ENHANCED_CURRENT_HUE.id), Some(0x1000));
        run(&mut c, t8, t8 + Duration::from_millis(500));
        let h = c.u16(ENHANCED_CURRENT_HUE.id).unwrap();
        assert!((0x4f00..=0x5100).contains(&h), "{h:#x}");
        // Stop Move Step does not stop the loop; deactivating restores
        // the stored hue.
        handle(
            &mut c,
            CMD_STOP_MOVE_STEP,
            &[],
            Some(true),
            t8 + Duration::from_millis(500),
        );
        run(
            &mut c,
            t8 + Duration::from_millis(500),
            t8 + Duration::from_millis(700),
        );
        assert_ne!(c.u16(ENHANCED_CURRENT_HUE.id), Some(h));
        handle(
            &mut c,
            CMD_COLOR_LOOP_SET,
            &[0x01, 0x00, 0, 0, 0, 0, 0, 0, 0],
            Some(true),
            t8 + Duration::from_secs(1),
        );
        assert_eq!(c.u8(COLOR_LOOP_ACTIVE.id), Some(0));
        assert_eq!(c.u16(ENHANCED_CURRENT_HUE.id), Some(0x1234));
        // Scene fields round trip.
        let f = scene_fields(&c);
        assert_eq!(f.len(), 13);
        assert_eq!(&f[11..13], &456u16.to_le_bytes());
        // Unsupported capability: a temperature-only lamp refuses hue.
        let mut t: ClusterInstance<16> = server(capability::COLOR_TEMPERATURE, (153, 500)).unwrap();
        assert_eq!(t.u8(COLOR_MODE.id), Some(color_mode::COLOR_TEMPERATURE));
        assert_eq!(
            handle(&mut t, CMD_MOVE_TO_HUE, &[1, 0, 0, 0], Some(true), t0),
            Outcome::Default(ZclStatus::UnsupportedClusterCommand)
        );
        assert!(server::<16>(capability::ENHANCED_HUE, (1, 2)).is_err());
    }

    #[test]
    fn primaries_color_points_and_drift_compensation() {
        let mut c: ClusterInstance<64> =
            server(capability::XY | capability::COLOR_TEMPERATURE, (153, 500)).unwrap();
        enable_drift_compensation(&mut c, drift_compensation::TEMPERATURE_MONITORING, b"NTC")
            .unwrap();
        let red = Primary {
            x: 0xb333,
            y: 0x4ccc,
            intensity: 200,
        };
        let green = Primary {
            x: 0x4ccc,
            y: 0x9999,
            intensity: 220,
        };
        let blue = Primary {
            x: 0x2666,
            y: 0x0f5c,
            intensity: 60,
        };
        enable_primaries(&mut c, &[red, green, blue]).unwrap();
        enable_color_points(&mut c, (0x5000, 0x5400), red, green, blue).unwrap();
        assert_eq!(c.u8(NUMBER_OF_PRIMARIES.id), Some(3));
        assert_eq!(primary_attrs(2)[0].id.0, 0x0015);
        assert_eq!(primary_attrs(6)[2].id.0, 0x002a);
        assert_eq!(c.u16(primary_attrs(3)[0].id), Some(0x2666));
        assert_eq!(c.u8(primary_attrs(1)[2].id), Some(200));
        assert!(c.attributes.get(primary_attrs(4)[0].id, None).is_none());
        assert_eq!(color_point_attrs(ColorPoint::Blue)[2].id.0, 0x003c);
        assert_eq!(
            c.u16(color_point_attrs(ColorPoint::Green)[1].id),
            Some(0x9999)
        );
        assert_eq!(c.u16(WHITE_POINT_X.id), Some(0x5000));
        assert_eq!(
            c.u8(DRIFT_COMPENSATION.id),
            Some(drift_compensation::TEMPERATURE_MONITORING)
        );
        // Seven primaries or an out-of-range chromaticity are refused.
        let mut d: ClusterInstance<64> = server(capability::XY, (153, 500)).unwrap();
        assert!(enable_primaries(&mut d, &[red; 7]).is_err());
        assert!(
            enable_primaries(
                &mut d,
                &[Primary {
                    x: 0xff00,
                    y: 0,
                    intensity: 0
                }]
            )
            .is_err()
        );
        assert!(enable_drift_compensation(&mut d, 5, b"").is_err());
    }
}
