//! The hub's data model, shared by the firmware and host applications:
//! device categories and capabilities, interview progress, normalized
//! device state and the application brightness scale.
//!
//! Every enumeration has a stable one-octet wire code ([`DeviceCategory::code`]
//! and friends); unknown codes decode to the `Unknown` variant where one
//! exists, so a newer firmware never breaks an older host.

use core::fmt;

/// What a device is, derived from its descriptors and attributes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DeviceCategory {
    /// Not classified (interview incomplete, or nothing recognised).
    #[default]
    Unknown,
    /// A router without a recognised application function.
    Router,
    /// IAS Zone of type Water Sensor.
    WaterLeakSensor,
    /// IAS Zone of type Contact Switch.
    ContactSensor,
    /// IAS Zone of type Motion Sensor, or an Occupancy Sensing server.
    MotionSensor,
    /// IAS Zone of another or an unknown type.
    IasZone,
    /// On/Off light.
    OnOffLight,
    /// Dimmable light (On/Off and Level Control).
    DimmableLight,
    /// Color light (On/Off, Level Control and Color Control).
    ColorLight,
    /// An On/Off output that is not a light (plug, relay).
    OnOffOutput,
    /// Temperature (and possibly humidity) sensor.
    TemperatureSensor,
    /// A controller: client clusters only (remote, switch).
    Controller,
}

impl DeviceCategory {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            DeviceCategory::Unknown => 0,
            DeviceCategory::Router => 1,
            DeviceCategory::WaterLeakSensor => 2,
            DeviceCategory::ContactSensor => 3,
            DeviceCategory::MotionSensor => 4,
            DeviceCategory::IasZone => 5,
            DeviceCategory::OnOffLight => 6,
            DeviceCategory::DimmableLight => 7,
            DeviceCategory::ColorLight => 8,
            DeviceCategory::OnOffOutput => 9,
            DeviceCategory::TemperatureSensor => 10,
            DeviceCategory::Controller => 11,
        }
    }

    /// The category of a wire code (`Unknown` for codes this version
    /// does not know).
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => DeviceCategory::Router,
            2 => DeviceCategory::WaterLeakSensor,
            3 => DeviceCategory::ContactSensor,
            4 => DeviceCategory::MotionSensor,
            5 => DeviceCategory::IasZone,
            6 => DeviceCategory::OnOffLight,
            7 => DeviceCategory::DimmableLight,
            8 => DeviceCategory::ColorLight,
            9 => DeviceCategory::OnOffOutput,
            10 => DeviceCategory::TemperatureSensor,
            11 => DeviceCategory::Controller,
            _ => DeviceCategory::Unknown,
        }
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            DeviceCategory::Unknown => "unknown",
            DeviceCategory::Router => "router",
            DeviceCategory::WaterLeakSensor => "water-leak-sensor",
            DeviceCategory::ContactSensor => "contact-sensor",
            DeviceCategory::MotionSensor => "motion-sensor",
            DeviceCategory::IasZone => "ias-zone",
            DeviceCategory::OnOffLight => "on-off-light",
            DeviceCategory::DimmableLight => "dimmable-light",
            DeviceCategory::ColorLight => "color-light",
            DeviceCategory::OnOffOutput => "on-off-output",
            DeviceCategory::TemperatureSensor => "temperature-sensor",
            DeviceCategory::Controller => "controller",
        }
    }
}

/// What a device can do, as a set of flags derived from the clusters it
/// serves and the attributes it answered for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Capabilities(pub u32);

impl Capabilities {
    /// On/Off server.
    pub const ON_OFF: u32 = 1 << 0;
    /// Level Control server.
    pub const LEVEL: u32 = 1 << 1;
    /// Color Control server.
    pub const COLOR: u32 = 1 << 2;
    /// Contact sensing (IAS Zone, Contact Switch).
    pub const CONTACT: u32 = 1 << 3;
    /// Water leak sensing (IAS Zone, Water Sensor).
    pub const WATER_LEAK: u32 = 1 << 4;
    /// IAS Zone server.
    pub const IAS_ZONE: u32 = 1 << 5;
    /// Battery voltage (Power Configuration `BatteryVoltage`).
    pub const BATTERY_VOLTAGE: u32 = 1 << 6;
    /// Battery percentage (Power Configuration
    /// `BatteryPercentageRemaining`).
    pub const BATTERY_PERCENTAGE: u32 = 1 << 7;
    /// Temperature Measurement server.
    pub const TEMPERATURE: u32 = 1 << 8;
    /// Relative Humidity Measurement server.
    pub const HUMIDITY: u32 = 1 << 9;
    /// Occupancy Sensing server, or an IAS Motion Sensor zone.
    pub const OCCUPANCY: u32 = 1 << 10;
    /// Illuminance Measurement server.
    pub const ILLUMINANCE: u32 = 1 << 11;
    /// Identify server.
    pub const IDENTIFY: u32 = 1 << 12;
    /// Poll Control server (a sleepy device that checks in).
    pub const POLL_CONTROL: u32 = 1 << 13;
    /// Power Configuration server.
    pub const POWER_CONFIGURATION: u32 = 1 << 14;

    const NAMES: [(u32, &'static str); 15] = [
        (Self::ON_OFF, "on-off"),
        (Self::LEVEL, "level"),
        (Self::COLOR, "color"),
        (Self::CONTACT, "contact"),
        (Self::WATER_LEAK, "water-leak"),
        (Self::IAS_ZONE, "ias-zone"),
        (Self::BATTERY_VOLTAGE, "battery-voltage"),
        (Self::BATTERY_PERCENTAGE, "battery-percentage"),
        (Self::TEMPERATURE, "temperature"),
        (Self::HUMIDITY, "humidity"),
        (Self::OCCUPANCY, "occupancy"),
        (Self::ILLUMINANCE, "illuminance"),
        (Self::IDENTIFY, "identify"),
        (Self::POLL_CONTROL, "poll-control"),
        (Self::POWER_CONFIGURATION, "power-configuration"),
    ];

    /// Whether every flag of `flags` is set.
    pub const fn contains(self, flags: u32) -> bool {
        self.0 & flags == flags
    }

    /// Sets `flags`.
    pub fn insert(&mut self, flags: u32) {
        self.0 |= flags;
    }

    /// The names of the flags that are set.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |(f, _)| self.0 & f != 0)
            .map(|(_, n)| n)
    }
}

/// Where a device's interview stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum InterviewStatus {
    /// Not started yet.
    #[default]
    NotStarted,
    /// In progress.
    InProgress,
    /// Every step succeeded.
    Complete,
    /// Finished, but optional steps (Basic attributes, IAS enrolment
    /// confirmation, bindings, reporting, initial state) failed.
    Partial,
    /// A mandatory step went unanswered after its retries; the interview
    /// resumes the next time the device is heard (a sleepy device may
    /// simply not have polled).
    Stalled,
}

impl InterviewStatus {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            InterviewStatus::NotStarted => 0,
            InterviewStatus::InProgress => 1,
            InterviewStatus::Complete => 2,
            InterviewStatus::Partial => 3,
            InterviewStatus::Stalled => 4,
        }
    }

    /// The status of a wire code.
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => InterviewStatus::InProgress,
            2 => InterviewStatus::Complete,
            3 => InterviewStatus::Partial,
            4 => InterviewStatus::Stalled,
            _ => InterviewStatus::NotStarted,
        }
    }

    /// Whether the interview has finished (completely or partially).
    pub const fn is_finished(self) -> bool {
        matches!(self, InterviewStatus::Complete | InterviewStatus::Partial)
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            InterviewStatus::NotStarted => "not-started",
            InterviewStatus::InProgress => "in-progress",
            InterviewStatus::Complete => "complete",
            InterviewStatus::Partial => "partial",
            InterviewStatus::Stalled => "stalled",
        }
    }
}

/// The steps of a device interview, in order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum InterviewStage {
    /// Node_Desc_req: logical type, power, manufacturer code.
    #[default]
    NodeDescriptor,
    /// Active_EP_req.
    ActiveEndpoints,
    /// Simple_Desc_req for every active endpoint.
    SimpleDescriptors,
    /// Basic cluster: ManufacturerName, ModelIdentifier, SWBuildID,
    /// PowerSource.
    BasicAttributes,
    /// IAS Zone: zone attributes, CIE address, enrolment.
    IasZone,
    /// Bind_req of the reportable clusters to the hub.
    Bindings,
    /// Configure Reporting of the reportable attributes.
    Reporting,
    /// Reads of the current state.
    InitialState,
    /// Finished.
    Done,
}

impl InterviewStage {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            InterviewStage::NodeDescriptor => 0,
            InterviewStage::ActiveEndpoints => 1,
            InterviewStage::SimpleDescriptors => 2,
            InterviewStage::BasicAttributes => 3,
            InterviewStage::IasZone => 4,
            InterviewStage::Bindings => 5,
            InterviewStage::Reporting => 6,
            InterviewStage::InitialState => 7,
            InterviewStage::Done => 8,
        }
    }

    /// The stage of a wire code.
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => InterviewStage::ActiveEndpoints,
            2 => InterviewStage::SimpleDescriptors,
            3 => InterviewStage::BasicAttributes,
            4 => InterviewStage::IasZone,
            5 => InterviewStage::Bindings,
            6 => InterviewStage::Reporting,
            7 => InterviewStage::InitialState,
            8 => InterviewStage::Done,
            _ => InterviewStage::NodeDescriptor,
        }
    }

    /// The next stage ([`InterviewStage::Done`] stays done).
    pub const fn next(self) -> Self {
        match self {
            InterviewStage::Done => InterviewStage::Done,
            s => Self::from_code(s.code() + 1),
        }
    }

    /// Whether the interview cannot finish without this stage.
    pub const fn is_mandatory(self) -> bool {
        matches!(
            self,
            InterviewStage::ActiveEndpoints | InterviewStage::SimpleDescriptors
        )
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            InterviewStage::NodeDescriptor => "node-descriptor",
            InterviewStage::ActiveEndpoints => "active-endpoints",
            InterviewStage::SimpleDescriptors => "simple-descriptors",
            InterviewStage::BasicAttributes => "basic-attributes",
            InterviewStage::IasZone => "ias-zone",
            InterviewStage::Bindings => "bindings",
            InterviewStage::Reporting => "reporting",
            InterviewStage::InitialState => "initial-state",
            InterviewStage::Done => "done",
        }
    }
}

/// How a device is powered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PowerSource {
    /// Not known.
    #[default]
    Unknown,
    /// Mains (single or three phase, or the node descriptor's mains flag).
    Mains,
    /// Battery.
    Battery,
    /// DC source.
    Dc,
    /// Another source (emergency mains, …).
    Other,
}

impl PowerSource {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            PowerSource::Unknown => 0,
            PowerSource::Mains => 1,
            PowerSource::Battery => 2,
            PowerSource::Dc => 3,
            PowerSource::Other => 4,
        }
    }

    /// The source of a wire code.
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => PowerSource::Mains,
            2 => PowerSource::Battery,
            3 => PowerSource::Dc,
            4 => PowerSource::Other,
            _ => PowerSource::Unknown,
        }
    }

    /// The source named by the Basic cluster's `PowerSource` attribute
    /// (ZCL8 §3.2.2.2.8; bit 7 flags a secondary battery backup).
    pub const fn from_basic(value: u8) -> Self {
        match value & 0x7f {
            0x01 | 0x02 => PowerSource::Mains,
            0x03 => PowerSource::Battery,
            0x04 => PowerSource::Dc,
            0x05 | 0x06 => PowerSource::Other,
            _ => PowerSource::Unknown,
        }
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            PowerSource::Unknown => "unknown",
            PowerSource::Mains => "mains",
            PowerSource::Battery => "battery",
            PowerSource::Dc => "dc",
            PowerSource::Other => "other",
        }
    }
}

/// The Zigbee logical device type from the node descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogicalType {
    /// Coordinator.
    Coordinator,
    /// Router.
    Router,
    /// End device.
    EndDevice,
}

impl LogicalType {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            LogicalType::Coordinator => 0,
            LogicalType::Router => 1,
            LogicalType::EndDevice => 2,
        }
    }

    /// The type of a wire code.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(LogicalType::Coordinator),
            1 => Some(LogicalType::Router),
            2 => Some(LogicalType::EndDevice),
            _ => None,
        }
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            LogicalType::Coordinator => "coordinator",
            LogicalType::Router => "router",
            LogicalType::EndDevice => "end-device",
        }
    }
}

/// The state of a contact (door / window) sensor.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ContactState {
    /// Not determined: no report yet, or a zone type that does not
    /// define contact semantics.
    #[default]
    Unknown,
    /// Closed.
    Closed,
    /// Open.
    Open,
}

impl ContactState {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            ContactState::Unknown => 0,
            ContactState::Closed => 1,
            ContactState::Open => 2,
        }
    }

    /// The state of a wire code.
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => ContactState::Closed,
            2 => ContactState::Open,
            _ => ContactState::Unknown,
        }
    }
}

/// The state of a water leak sensor.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LeakState {
    /// Not determined.
    #[default]
    Unknown,
    /// No water detected.
    Dry,
    /// Water detected.
    Leak,
}

impl LeakState {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            LeakState::Unknown => 0,
            LeakState::Dry => 1,
            LeakState::Leak => 2,
        }
    }

    /// The state of a wire code.
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => LeakState::Dry,
            2 => LeakState::Leak,
            _ => LeakState::Unknown,
        }
    }
}

/// A condition flag that may be unknown (tamper, low battery, trouble,
/// motion).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Flag {
    /// Not determined.
    #[default]
    Unknown,
    /// The condition is not present.
    Clear,
    /// The condition is present.
    Set,
}

impl Flag {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            Flag::Unknown => 0,
            Flag::Clear => 1,
            Flag::Set => 2,
        }
    }

    /// The flag of a wire code.
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => Flag::Clear,
            2 => Flag::Set,
            _ => Flag::Unknown,
        }
    }

    /// A known flag from a bit.
    pub const fn from_bit(set: bool) -> Self {
        if set { Flag::Set } else { Flag::Clear }
    }
}

/// The normalized last known state of a device. Every field starts
/// unknown and is only set from what the device reported or answered;
/// nothing is assumed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeviceState {
    /// On/Off `OnOff`.
    pub on: Option<bool>,
    /// Level Control `CurrentLevel` (0–254; see [`level_to_brightness`]).
    pub level: Option<u8>,
    /// Contact state (IAS Contact Switch).
    pub contact: ContactState,
    /// Water leak state (IAS Water Sensor).
    pub water_leak: LeakState,
    /// Motion / occupancy.
    pub motion: Flag,
    /// Tamper (IAS ZoneStatus bit 2).
    pub tamper: Flag,
    /// Low battery (IAS ZoneStatus bit 3 or Power Configuration
    /// `BatteryAlarmState` bit 0).
    pub battery_low: Flag,
    /// Trouble / failure (IAS ZoneStatus bit 6).
    pub trouble: Flag,
    /// Battery charge in percent (0–100).
    pub battery_percent: Option<u8>,
    /// Battery voltage in millivolts.
    pub battery_mv: Option<u16>,
    /// Temperature in hundredths of a degree Celsius.
    pub temperature_centi: Option<i16>,
    /// Relative humidity in hundredths of a percent.
    pub humidity_centi: Option<u16>,
    /// The raw IAS `ZoneStatus` last received.
    pub zone_status: Option<u16>,
}

/// Highest application brightness.
pub const BRIGHTNESS_MAX: u8 = 100;

/// Highest Level Control level a light accepts (0xff is invalid).
pub const LEVEL_MAX: u8 = 254;

/// Application brightness (percent, 1–100) to a Level Control level
/// (1–254), rounding to the nearest level: 1 % is the minimum level, 100 %
/// the maximum. 0 % is not a level but "off" (`None`), as is anything
/// above 100.
pub fn brightness_to_level(percent: u8) -> Option<u8> {
    if percent == 0 || percent > BRIGHTNESS_MAX {
        return None;
    }
    let p = u16::from(percent) - 1;
    u8::try_from(1 + (p * 253 + 49) / 99).ok()
}

/// A Level Control level (0–254) as application brightness (0–100 %):
/// the inverse of [`brightness_to_level`]. 0xff (invalid) is `None`.
pub fn level_to_brightness(level: u8) -> Option<u8> {
    match level {
        0 => Some(0),
        0xff => None,
        l => u8::try_from(1 + ((u16::from(l) - 1) * 99 + 126) / 253).ok(),
    }
}

/// An IEEE address formatted as `00:11:22:33:44:55:66:77`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ieee(pub u64);

impl fmt::Display for Ieee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0.to_be_bytes();
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
        )
    }
}

impl Ieee {
    /// Parses `0011223344556677`, `0x0011223344556677` or the
    /// colon/dash-separated form.
    pub fn parse(text: &str) -> Option<Ieee> {
        let t = text.trim();
        let t = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        let mut value: u64 = 0;
        let mut digits = 0u8;
        for c in t.chars() {
            if c == ':' || c == '-' {
                continue;
            }
            let d = c.to_digit(16)?;
            digits += 1;
            if digits > 16 {
                return None;
            }
            value = (value << 4) | u64::from(d);
        }
        (digits == 16).then_some(Ieee(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brightness_round_trips_through_the_level_range() {
        assert_eq!(brightness_to_level(0), None);
        assert_eq!(brightness_to_level(101), None);
        assert_eq!(brightness_to_level(1), Some(1));
        assert_eq!(brightness_to_level(100), Some(LEVEL_MAX));
        assert_eq!(brightness_to_level(50), Some(126));
        for p in 1..=100u8 {
            let l = brightness_to_level(p).unwrap();
            assert!((1..=LEVEL_MAX).contains(&l));
            assert_eq!(level_to_brightness(l), Some(p), "percent {p} level {l}");
        }
        let mut last = 0;
        for l in 0..=LEVEL_MAX {
            let p = level_to_brightness(l).unwrap();
            assert!(p >= last && p <= BRIGHTNESS_MAX);
            last = p;
        }
        assert_eq!(level_to_brightness(0xff), None);
    }

    #[test]
    fn ieee_parses_every_documented_form() {
        let v = Some(Ieee(0x0011_2233_4455_6677));
        assert_eq!(Ieee::parse("0011223344556677"), v);
        assert_eq!(Ieee::parse("0x0011223344556677"), v);
        assert_eq!(Ieee::parse("00:11:22:33:44:55:66:77"), v);
        assert_eq!(Ieee::parse("00-11-22-33-44-55-66-77"), v);
        assert_eq!(Ieee::parse("0011"), None);
        assert_eq!(Ieee::parse("00112233445566778"), None);
        assert_eq!(Ieee::parse("zz11223344556677"), None);
        let mut s = heapless::String::<32>::new();
        fmt::write(&mut s, format_args!("{}", Ieee(0x0011_2233_4455_6677))).unwrap();
        assert_eq!(s.as_str(), "00:11:22:33:44:55:66:77");
    }

    #[test]
    fn codes_are_stable_and_unknown_codes_degrade() {
        for c in 0..=11 {
            assert_eq!(DeviceCategory::from_code(c).code(), c);
        }
        assert_eq!(DeviceCategory::from_code(200), DeviceCategory::Unknown);
        for c in 0..=8 {
            assert_eq!(InterviewStage::from_code(c).code(), c);
        }
        assert_eq!(InterviewStage::Done.next(), InterviewStage::Done);
        assert_eq!(PowerSource::from_basic(0x83), PowerSource::Battery);
        assert_eq!(PowerSource::from_basic(0x01), PowerSource::Mains);
        let caps = Capabilities(Capabilities::ON_OFF | Capabilities::LEVEL);
        assert!(caps.contains(Capabilities::ON_OFF));
        assert_eq!(caps.names().count(), 2);
    }
}
