//! Panweave Hub Protocol, version 1.
//!
//! A host application and the hub exchange three kinds of messages over
//! a byte stream framed by [`frame`]:
//!
//! * **requests** (host → hub), each with a 16-bit request identifier
//!   chosen by the host;
//! * **responses** (hub → host), one per request, carrying the request's
//!   identifier: the result itself, or [`Response::Accepted`] with a
//!   command identifier when the work continues over the radio;
//! * **events** (hub → host), unsolicited, numbered by a 16-bit sequence
//!   so a host notices gaps; [`Event::EventsDropped`] reports events the
//!   hub had to discard because the host was not reading.
//!
//! Every message body starts with the protocol version ([`VERSION`]),
//! the kind and the identifier; a hub answers a request of another
//! version with [`ErrorCode::UnsupportedVersion`]. Fields are
//! little-endian; optional values are a presence octet (0 or 1) and the
//! value; strings and lists are a count octet and the items. Unknown
//! enumeration codes decode to their `Unknown` variant where one exists.
//! A body never exceeds [`frame::MAX_BODY`] octets.

pub mod alerts;
pub mod diagnostics;
pub mod frame;
pub mod gp;
pub mod ota;
pub mod security;

pub use alerts::{
    AlertConfigUpdate, AlertError, AlertKind, AlertStage, AlertState, AlertStatus, ScanEntry,
    WifiFailure, WifiScan,
};
pub use diagnostics::{
    BootReport, CapturePage, MAX_BOOT_FINDINGS, MAX_BOOT_PARTITIONS, MAX_CAPTURE_PAGE,
    MAX_CAPTURE_SECONDS, MAX_TRACE_PAGE, NetworkRestore, PartitionEntry, PartitionFinding,
    QueueUsage, RadioDiagnostics, RadioDriverStats, ResetKind, RuntimeDiagnostics,
    StorageDiagnostics, StoreUsage, StoredNetwork, TargetMetrics, TraceConfiguration, TracePage,
};
pub use gp::{GPD_PAGE, GpdAddress, GpdInfo, GpdList, MAX_GPD_PAYLOAD};
pub use ota::{MAX_OTA_CHUNK, OtaImage, OtaOffer, OtaStatus};
pub use security::{
    DeniedCounts, DeviceAuthorization, ExemptionInfo, MAX_EXEMPTION_SECONDS, MAX_EXEMPTIONS,
    MAX_UNAUTHORIZED, SecurityStatus,
};

use core::fmt;

use crate::capture::CaptureMode;

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};

use crate::model::{
    Capabilities, ColorMode, ColorState, ContactState, DeviceCategory, DeviceState, Flag, Ieee,
    InterviewStage, InterviewStatus, LeakState, LogicalType, PowerSource,
};

/// The protocol version this crate speaks.
pub const VERSION: u8 = 1;

/// Devices per [`Response::DeviceList`] page.
pub const DEVICE_PAGE: usize = 8;

/// Longest manufacturer name or model identifier kept.
pub const MAX_NAME: usize = 32;

/// Longest software build identifier kept.
pub const MAX_BUILD: usize = 16;

/// Endpoints kept per device.
pub const MAX_ENDPOINTS: usize = 4;

/// Input (server) clusters kept per endpoint.
pub const MAX_INPUT_CLUSTERS: usize = 16;

/// Output (client) clusters kept per endpoint.
pub const MAX_OUTPUT_CLUSTERS: usize = 8;

/// Longest raw attribute value carried in a message.
pub const MAX_ATTRIBUTE: usize = 32;

/// Longest firmware version string.
pub const MAX_FIRMWARE: usize = 16;

/// Longest permit-join window a host may open, in seconds.
pub const MAX_PERMIT_JOIN_SECONDS: u8 = 254;

const KIND_REQUEST: u8 = 1;
const KIND_RESPONSE: u8 = 2;
const KIND_EVENT: u8 = 3;

/// Bytes: a manufacturer name, model or build identifier as the device
/// sent it (ZCL character strings are not guaranteed to be UTF-8).
pub type Text<const N: usize> = Vec<u8, N>;

/// Why a body could not be decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProtocolError {
    /// A message of another protocol version; `id` is its request
    /// identifier, for the error response.
    UnsupportedVersion {
        /// The version received.
        version: u8,
        /// The request identifier, when the message is a request.
        id: Option<u16>,
    },
    /// An unknown message kind.
    UnknownKind(u8),
    /// An unknown request, response or event tag.
    UnknownTag(u8),
    /// A field is truncated, out of range, or trailing bytes follow.
    Malformed,
    /// The message does not fit [`frame::MAX_BODY`].
    TooLarge,
}

impl From<CodecError> for ProtocolError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::BufferTooSmall { .. } => ProtocolError::TooLarge,
            _ => ProtocolError::Malformed,
        }
    }
}

/// Error codes of [`Response::Error`], [`Event::CommandFailed`] and
/// [`Event::HubError`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrorCode {
    /// The request's protocol version is not supported.
    UnsupportedVersion,
    /// The request could not be decoded.
    Malformed,
    /// The request tag is unknown.
    UnknownRequest,
    /// The session may not issue this request (see [`Access`]).
    Unauthorized,
    /// No such device in the registry.
    UnknownDevice,
    /// A bounded queue is full; retry later.
    Busy,
    /// The device lacks the capability the request needs.
    NotSupported,
    /// An argument is out of range.
    InvalidArgument,
    /// The Zigbee network is not up.
    NetworkDown,
    /// Persistent storage failed.
    StorageFailure,
    /// The device registry is full.
    RegistryFull,
    /// The device did not answer in time.
    Timeout,
    /// The device answered with a ZCL error status (see the status).
    ZclFailure,
    /// The device answered with a ZDP error status (see the status).
    ZdoFailure,
    /// The device has no known network address or left the network.
    Unreachable,
    /// The stack refused to send the frame.
    SendFailed,
    /// A code this version does not know.
    Unknown(u8),
}

impl ErrorCode {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            ErrorCode::UnsupportedVersion => 0x01,
            ErrorCode::Malformed => 0x02,
            ErrorCode::UnknownRequest => 0x03,
            ErrorCode::Unauthorized => 0x04,
            ErrorCode::UnknownDevice => 0x05,
            ErrorCode::Busy => 0x06,
            ErrorCode::NotSupported => 0x07,
            ErrorCode::InvalidArgument => 0x08,
            ErrorCode::NetworkDown => 0x09,
            ErrorCode::StorageFailure => 0x0a,
            ErrorCode::RegistryFull => 0x0b,
            ErrorCode::Timeout => 0x0c,
            ErrorCode::ZclFailure => 0x0d,
            ErrorCode::ZdoFailure => 0x0e,
            ErrorCode::Unreachable => 0x0f,
            ErrorCode::SendFailed => 0x10,
            ErrorCode::Unknown(c) => c,
        }
    }

    /// The error of a wire code.
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x01 => ErrorCode::UnsupportedVersion,
            0x02 => ErrorCode::Malformed,
            0x03 => ErrorCode::UnknownRequest,
            0x04 => ErrorCode::Unauthorized,
            0x05 => ErrorCode::UnknownDevice,
            0x06 => ErrorCode::Busy,
            0x07 => ErrorCode::NotSupported,
            0x08 => ErrorCode::InvalidArgument,
            0x09 => ErrorCode::NetworkDown,
            0x0a => ErrorCode::StorageFailure,
            0x0b => ErrorCode::RegistryFull,
            0x0c => ErrorCode::Timeout,
            0x0d => ErrorCode::ZclFailure,
            0x0e => ErrorCode::ZdoFailure,
            0x0f => ErrorCode::Unreachable,
            0x10 => ErrorCode::SendFailed,
            c => ErrorCode::Unknown(c),
        }
    }

    /// A short description for displays.
    pub const fn name(self) -> &'static str {
        match self {
            ErrorCode::UnsupportedVersion => "unsupported protocol version",
            ErrorCode::Malformed => "malformed request",
            ErrorCode::UnknownRequest => "unknown request",
            ErrorCode::Unauthorized => "not authorized",
            ErrorCode::UnknownDevice => "unknown device",
            ErrorCode::Busy => "busy, retry later",
            ErrorCode::NotSupported => "not supported by the device",
            ErrorCode::InvalidArgument => "invalid argument",
            ErrorCode::NetworkDown => "network not up",
            ErrorCode::StorageFailure => "storage failure",
            ErrorCode::RegistryFull => "device registry full",
            ErrorCode::Timeout => "timed out",
            ErrorCode::ZclFailure => "ZCL error status",
            ErrorCode::ZdoFailure => "ZDO error status",
            ErrorCode::Unreachable => "device unreachable",
            ErrorCode::SendFailed => "send failed",
            ErrorCode::Unknown(_) => "unknown error",
        }
    }
}

/// What a session may do. Requests that only read need
/// [`Access::Monitor`]; requests that act on devices need
/// [`Access::Control`]; requests that change the network or the
/// registry need [`Access::Admin`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Access {
    /// Read-only.
    Monitor,
    /// Read and control devices.
    Control,
    /// Everything the protocol offers.
    Admin,
}

/// An application-level light command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LightCommand {
    /// On/Off On.
    TurnOn,
    /// On/Off Off.
    TurnOff,
    /// On/Off Toggle.
    Toggle,
    /// Level Control Move to Level (with On/Off): brightness in percent
    /// (1–100; 0 turns the light off) over `transition_ds` tenths of a
    /// second.
    SetBrightness {
        /// Percent, 0–100.
        percent: u8,
        /// Transition time in tenths of a second.
        transition_ds: u16,
    },
    /// Color Control Move to Color Temperature (0.4).
    SetColorTemperature {
        /// Mireds (1 000 000 / kelvin).
        mireds: u16,
        /// Transition time in tenths of a second.
        transition_ds: u16,
    },
    /// Color Control Move to Color: CIE 1931 x and y × 65536 (0.4).
    SetColorXy {
        /// x.
        x: u16,
        /// y.
        y: u16,
        /// Transition time in tenths of a second.
        transition_ds: u16,
    },
    /// Color Control Move to Hue and Saturation (0.4).
    SetHueSaturation {
        /// Hue, 0–254 for 0–360°.
        hue: u8,
        /// Saturation, 0–254.
        saturation: u8,
        /// Transition time in tenths of a second.
        transition_ds: u16,
    },
}

impl LightCommand {
    /// The wire code (the request tag of [`Request::Light`]).
    const fn code(self) -> u8 {
        match self {
            LightCommand::TurnOn => 0x0c,
            LightCommand::TurnOff => 0x0d,
            LightCommand::Toggle => 0x0e,
            LightCommand::SetBrightness { .. } => 0x0f,
            LightCommand::SetColorTemperature { .. } => 0x24,
            LightCommand::SetColorXy { .. } => 0x25,
            LightCommand::SetHueSaturation { .. } => 0x26,
        }
    }

    const fn is_code(code: u8) -> bool {
        matches!(code, 0x0c..=0x0f | 0x24..=0x26)
    }

    /// The ZCL cluster that carries the command.
    pub const fn cluster(self) -> u16 {
        match self {
            LightCommand::TurnOn | LightCommand::TurnOff | LightCommand::Toggle => 0x0006,
            LightCommand::SetBrightness { .. } => 0x0008,
            LightCommand::SetColorTemperature { .. }
            | LightCommand::SetColorXy { .. }
            | LightCommand::SetHueSaturation { .. } => 0x0300,
        }
    }

    fn write_params(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            LightCommand::TurnOn | LightCommand::TurnOff | LightCommand::Toggle => Ok(()),
            LightCommand::SetBrightness {
                percent,
                transition_ds,
            } => {
                w.u8(percent)?;
                w.u16_le(transition_ds)
            }
            LightCommand::SetColorTemperature {
                mireds,
                transition_ds,
            } => {
                w.u16_le(mireds)?;
                w.u16_le(transition_ds)
            }
            LightCommand::SetColorXy {
                x,
                y,
                transition_ds,
            } => {
                w.u16_le(x)?;
                w.u16_le(y)?;
                w.u16_le(transition_ds)
            }
            LightCommand::SetHueSaturation {
                hue,
                saturation,
                transition_ds,
            } => {
                w.u8(hue)?;
                w.u8(saturation)?;
                w.u16_le(transition_ds)
            }
        }
    }

    fn read(code: u8, r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(match code {
            0x0c => LightCommand::TurnOn,
            0x0d => LightCommand::TurnOff,
            0x0e => LightCommand::Toggle,
            0x0f => LightCommand::SetBrightness {
                percent: r.u8()?,
                transition_ds: r.u16_le()?,
            },
            0x24 => LightCommand::SetColorTemperature {
                mireds: r.u16_le()?,
                transition_ds: r.u16_le()?,
            },
            0x25 => LightCommand::SetColorXy {
                x: r.u16_le()?,
                y: r.u16_le()?,
                transition_ds: r.u16_le()?,
            },
            0x26 => LightCommand::SetHueSaturation {
                hue: r.u8()?,
                saturation: r.u8()?,
                transition_ds: r.u16_le()?,
            },
            t => return Err(ProtocolError::UnknownTag(t)),
        })
    }
}

/// Requests (host → hub).
// No allocator to box the large variant (`SetAlertConfig`): requests are
// decoded and handled one at a time on the stack.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Request {
    /// Hub identity and protocol version.
    GetHubInfo,
    /// Network parameters and the permit-join window.
    GetNetworkStatus,
    /// Opens the network for joining for `seconds` (1–254).
    PermitJoin {
        /// Window length.
        seconds: u8,
    },
    /// Closes the network for joining.
    CloseNetwork,
    /// A page of the registry, from index `start`.
    ListDevices {
        /// First index.
        start: u8,
    },
    /// Everything known about a device.
    GetDevice {
        /// The device.
        ieee: u64,
    },
    /// Restarts a device's interview from the beginning.
    InterviewDevice {
        /// The device.
        ieee: u64,
    },
    /// A device's normalized state.
    GetDeviceState {
        /// The device.
        ieee: u64,
    },
    /// Reads one attribute of a device (result in
    /// [`Event::CommandCompleted`]).
    ReadAttribute {
        /// The device.
        ieee: u64,
        /// Its endpoint.
        endpoint: u8,
        /// The cluster (server side on the device).
        cluster: u16,
        /// The attribute.
        attribute: u16,
    },
    /// Configures reporting of one attribute to the hub (bind the
    /// cluster first).
    ConfigureReporting {
        /// The device.
        ieee: u64,
        /// Its endpoint.
        endpoint: u8,
        /// The cluster.
        cluster: u16,
        /// The attribute.
        attribute: u16,
        /// The attribute's ZCL data type.
        data_type: u8,
        /// Minimum interval, seconds.
        min_interval: u16,
        /// Maximum interval, seconds.
        max_interval: u16,
        /// Reportable change (analog types; little-endian, truncated to
        /// the type's width).
        change: u32,
    },
    /// Binds a device's cluster to the hub's endpoint.
    Bind {
        /// The device.
        ieee: u64,
        /// Its endpoint.
        endpoint: u8,
        /// The cluster.
        cluster: u16,
    },
    /// A light command.
    Light {
        /// The device.
        ieee: u64,
        /// Its endpoint, 0 for the first one that can execute the
        /// command.
        endpoint: u8,
        /// The command.
        command: LightCommand,
    },
    /// Removes a device: from the registry only (`leave` false), or also
    /// from the network with a Leave request (`leave` true).
    RemoveDevice {
        /// The device.
        ieee: u64,
        /// Ask it to leave the network.
        leave: bool,
    },
    /// Counters for troubleshooting.
    GetDiagnostics,
    /// What the hub found at boot (0.2.1).
    GetBootReport,
    /// Radio, MAC, NWK and APS counters (0.2.1).
    GetRadioDiagnostics,
    /// Persistence state (0.2.1).
    GetStorageDiagnostics,
    /// Runtime metrics (0.2.1).
    GetRuntimeDiagnostics,
    /// The trace configuration (0.2.1).
    GetTraceConfiguration,
    /// Changes what the trace keeps (0.2.1).
    SetTraceConfiguration {
        /// Minimum severity code (`crate::diag::Severity`).
        min_severity: u8,
        /// Category mask.
        categories: u32,
    },
    /// A page of the trace from sequence number `from` (0.2.1).
    ReadTrace {
        /// First sequence number wanted.
        from: u32,
        /// Records wanted (1..=[`MAX_TRACE_PAGE`]).
        max: u8,
        /// Only the records of this device.
        ieee: Option<u64>,
    },
    /// Empties the trace (0.2.1).
    ClearTrace,
    /// Starts capturing radio frames for `seconds` (0.2.1).
    StartCapture {
        /// Duration, 1..=[`MAX_CAPTURE_SECONDS`].
        seconds: u16,
        /// What to keep of each frame ([`CaptureMode::Sanitized`]
        /// recommended; [`CaptureMode::Raw`] exposes key transports).
        mode: CaptureMode,
    },
    /// Stops the capture (0.2.1).
    StopCapture,
    /// Takes up to `max` captured frames (0.2.1).
    ReadCapture {
        /// Frames wanted (1..=[`MAX_CAPTURE_PAGE`]).
        max: u8,
    },
    /// Exempts a device from the Trust Center's key-exchange requirement
    /// for a joining window of `seconds` (1..=[`MAX_EXEMPTION_SECONDS`]);
    /// once the device joins inside the window the exemption is kept
    /// (persisted with the device) until revoked. `seconds = 0` revokes
    /// it (0.2.1).
    SetKeyExchangeExemption {
        /// The device.
        ieee: u64,
        /// Window length; 0 revokes.
        seconds: u16,
    },
    /// The Trust Center's security state (0.2.1).
    GetSecurityStatus,
    /// The experimental Wi-Fi notification state, without secrets
    /// (0.3.x).
    GetAlertStatus,
    /// Changes the experimental Wi-Fi notification settings; secrets are
    /// write only (0.3.x).
    SetAlertConfig(AlertConfigUpdate),
    /// Queues a test notification through the normal path (0.3.x).
    QueueTestAlert,
    /// Runs the radio-switch experiment once: 802.15.4 off, Wi-Fi on and
    /// associated, Wi-Fi off, 802.15.4 back; nothing is sent. The result
    /// is in [`AlertStatus`] (0.3.x).
    RunRadioProbe,
    /// What the last radio-switch experiment heard: access points in
    /// range, the strongest ones, the configured SSID (0.3.x).
    GetWifiScan,
    /// A colour light's capabilities and colour (0.4).
    GetLightColor {
        /// The device.
        ieee: u64,
    },
    /// Adds a device's endpoint to a group (Groups Add Group; 0.4).
    AddGroup {
        /// The device.
        ieee: u64,
        /// Its endpoint, 0 for the first with a Groups server.
        endpoint: u8,
        /// The group (0x0001–0xfff7).
        group: u16,
    },
    /// Removes a device's endpoint from a group (0.4).
    RemoveGroup {
        /// The device.
        ieee: u64,
        /// Its endpoint, 0 for the first with a Groups server.
        endpoint: u8,
        /// The group.
        group: u16,
    },
    /// A light command to every member of a group, in one group-addressed
    /// frame: answered [`Response::Done`] once sent; nothing confirms it
    /// (0.4).
    GroupLight {
        /// The group.
        group: u16,
        /// The command.
        command: LightCommand,
    },
    /// Stores a device's current state as scene `scene` of `group`
    /// (Scenes Store Scene; 0.4).
    StoreScene {
        /// The device.
        ieee: u64,
        /// Its endpoint, 0 for the first with a Scenes server.
        endpoint: u8,
        /// The group the scene belongs to (0: no group).
        group: u16,
        /// The scene.
        scene: u8,
    },
    /// Recalls scene `scene` on every member of `group` (one
    /// group-addressed frame; [`Response::Done`] once sent; 0.4).
    RecallScene {
        /// The group.
        group: u16,
        /// The scene.
        scene: u8,
        /// Transition time in tenths of a second (0: the scene's own).
        transition_ds: u16,
    },
    /// Offers an OTA image to devices, replacing any earlier offer; its
    /// bytes follow as [`Request::OtaData`] when the hub asks for them
    /// (0.4).
    OtaOffer(OtaOffer),
    /// Image octets from `offset`, which must be where the hub's window
    /// ends ([`Event::OtaDataWanted`]; 0.4).
    OtaData {
        /// File offset of `data`.
        offset: u32,
        /// At most [`MAX_OTA_CHUNK`] octets.
        data: Vec<u8, MAX_OTA_CHUNK>,
    },
    /// Withdraws the offer; a download in progress is aborted (0.4).
    OtaCancel,
    /// The OTA server's state (0.4).
    GetOtaStatus,
    /// Lets `ieee` join with the link key derived from its install code
    /// (`code` and its CRC-16, 8, 10, 14 or 18 octets, as printed on the
    /// device; 0.4). The key is installed at the Trust Center as a
    /// provisional unique key; the code is not kept.
    AddInstallCode {
        /// The device.
        ieee: u64,
        /// Install code with its CRC.
        code: Vec<u8, MAX_INSTALL_CODE>,
    },
    /// Opens the Green Power sink's commissioning window for `seconds`
    /// (proxies included); 0 closes it (0.4, feature `green-power`).
    GreenPowerCommission {
        /// Window length; 0 closes.
        seconds: u16,
    },
    /// A page of the paired Green Power Devices, from index `start`
    /// (0.4).
    ListGreenPowerDevices {
        /// First index.
        start: u8,
    },
    /// Removes a GPD's pairing from the sink (0.4).
    RemoveGreenPowerDevice {
        /// The GPD.
        gpd: GpdAddress,
    },
    /// Measures the energy on every 2.4 GHz channel (the result comes as
    /// [`Event::EnergyScan`]); the hub is off its channel for the scan:
    /// about 16 × (2^`duration` + 1) × 15.36 ms. `NotSupported` when the
    /// radio driver cannot measure (0.4).
    ScanEnergy {
        /// MAC scan duration exponent, 0–5.
        duration: u8,
    },
    /// Moves the whole network to `channel` (11–26): the routers and
    /// rx-on devices are told (Mgmt_NWK_Update_req), sleepy ones follow
    /// their parent; [`Event::ChannelChanged`] once the hub switched.
    /// `Busy` within an hour of the previous change (0.4).
    ChangeChannel {
        /// The new channel.
        channel: u8,
    },
}

/// Longest install code with its CRC (ZD 1.1 / BDB §10.1).
pub const MAX_INSTALL_CODE: usize = 18;

impl Request {
    /// The access a session needs to issue this request.
    pub const fn required_access(&self) -> Access {
        match self {
            Request::GetHubInfo
            | Request::GetNetworkStatus
            | Request::GetSecurityStatus
            | Request::GetAlertStatus
            | Request::ListDevices { .. }
            | Request::GetDevice { .. }
            | Request::GetDeviceState { .. }
            | Request::GetDiagnostics
            | Request::GetBootReport
            | Request::GetRadioDiagnostics
            | Request::GetStorageDiagnostics
            | Request::GetRuntimeDiagnostics
            | Request::GetTraceConfiguration
            | Request::GetLightColor { .. }
            | Request::GetOtaStatus
            | Request::ListGreenPowerDevices { .. }
            | Request::ReadTrace { .. } => Access::Monitor,
            Request::InterviewDevice { .. }
            | Request::ReadAttribute { .. }
            | Request::ConfigureReporting { .. }
            | Request::Bind { .. }
            | Request::AddGroup { .. }
            | Request::RemoveGroup { .. }
            | Request::GroupLight { .. }
            | Request::StoreScene { .. }
            | Request::RecallScene { .. }
            | Request::Light { .. } => Access::Control,
            Request::PermitJoin { .. }
            | Request::CloseNetwork
            | Request::RemoveDevice { .. }
            | Request::SetTraceConfiguration { .. }
            | Request::ClearTrace
            | Request::StartCapture { .. }
            | Request::StopCapture
            | Request::ReadCapture { .. }
            | Request::SetKeyExchangeExemption { .. }
            | Request::SetAlertConfig(_)
            | Request::QueueTestAlert
            | Request::RunRadioProbe
            | Request::OtaOffer(_)
            | Request::OtaData { .. }
            | Request::OtaCancel
            | Request::AddInstallCode { .. }
            | Request::GreenPowerCommission { .. }
            | Request::RemoveGreenPowerDevice { .. }
            | Request::ScanEnergy { .. }
            | Request::ChangeChannel { .. }
            | Request::GetWifiScan => Access::Admin,
        }
    }

    const fn tag(&self) -> u8 {
        match self {
            Request::GetHubInfo => 0x01,
            Request::GetNetworkStatus => 0x02,
            Request::PermitJoin { .. } => 0x03,
            Request::CloseNetwork => 0x04,
            Request::ListDevices { .. } => 0x05,
            Request::GetDevice { .. } => 0x06,
            Request::InterviewDevice { .. } => 0x07,
            Request::GetDeviceState { .. } => 0x08,
            Request::ReadAttribute { .. } => 0x09,
            Request::ConfigureReporting { .. } => 0x0a,
            Request::Bind { .. } => 0x0b,
            Request::Light { command, .. } => command.code(),
            Request::RemoveDevice { .. } => 0x10,
            Request::GetDiagnostics => 0x11,
            Request::GetBootReport => 0x12,
            Request::GetRadioDiagnostics => 0x13,
            Request::GetStorageDiagnostics => 0x14,
            Request::GetRuntimeDiagnostics => 0x15,
            Request::GetTraceConfiguration => 0x16,
            Request::SetTraceConfiguration { .. } => 0x17,
            Request::ReadTrace { .. } => 0x18,
            Request::ClearTrace => 0x19,
            Request::StartCapture { .. } => 0x1a,
            Request::StopCapture => 0x1b,
            Request::ReadCapture { .. } => 0x1c,
            Request::SetKeyExchangeExemption { .. } => 0x1d,
            Request::GetSecurityStatus => 0x1e,
            Request::GetAlertStatus => 0x1f,
            Request::SetAlertConfig(_) => 0x20,
            Request::QueueTestAlert => 0x21,
            Request::RunRadioProbe => 0x22,
            Request::GetWifiScan => 0x23,
            Request::GetLightColor { .. } => 0x27,
            Request::AddGroup { .. } => 0x28,
            Request::RemoveGroup { .. } => 0x29,
            Request::GroupLight { .. } => 0x2a,
            Request::StoreScene { .. } => 0x2b,
            Request::RecallScene { .. } => 0x2c,
            Request::OtaOffer(_) => 0x2d,
            Request::OtaData { .. } => 0x2e,
            Request::OtaCancel => 0x2f,
            Request::GetOtaStatus => 0x30,
            Request::AddInstallCode { .. } => 0x31,
            Request::GreenPowerCommission { .. } => 0x32,
            Request::ListGreenPowerDevices { .. } => 0x33,
            Request::RemoveGreenPowerDevice { .. } => 0x34,
            Request::ScanEnergy { .. } => 0x35,
            Request::ChangeChannel { .. } => 0x36,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.tag())?;
        match self {
            Request::GetHubInfo
            | Request::GetNetworkStatus
            | Request::GetSecurityStatus
            | Request::GetAlertStatus
            | Request::QueueTestAlert
            | Request::RunRadioProbe
            | Request::GetWifiScan
            | Request::CloseNetwork
            | Request::GetDiagnostics
            | Request::GetBootReport
            | Request::GetRadioDiagnostics
            | Request::GetStorageDiagnostics
            | Request::GetRuntimeDiagnostics
            | Request::GetTraceConfiguration
            | Request::ClearTrace
            | Request::OtaCancel
            | Request::GetOtaStatus
            | Request::StopCapture => Ok(()),
            Request::OtaOffer(o) => ota::write_offer(w, o),
            Request::GreenPowerCommission { seconds } => w.u16_le(*seconds),
            Request::ScanEnergy { duration } => w.u8(*duration),
            Request::ChangeChannel { channel } => w.u8(*channel),
            Request::ListGreenPowerDevices { start } => w.u8(*start),
            Request::RemoveGreenPowerDevice { gpd } => gp::write_gpd(w, gpd),
            Request::AddInstallCode { ieee, code } => {
                w.u64_le(*ieee)?;
                w.u8(count(code.len())?)?;
                w.bytes(code)
            }
            Request::OtaData { offset, data } => {
                w.u32_le(*offset)?;
                ota::write_chunk(w, data)
            }
            Request::SetTraceConfiguration {
                min_severity,
                categories,
            } => {
                w.u8(*min_severity)?;
                w.u32_le(*categories)
            }
            Request::ReadTrace { from, max, ieee } => {
                w.u32_le(*from)?;
                w.u8(*max)?;
                match ieee {
                    Some(i) => {
                        w.u8(1)?;
                        w.u64_le(*i)
                    }
                    None => w.u8(0),
                }
            }
            Request::StartCapture { seconds, mode } => {
                w.u16_le(*seconds)?;
                w.u8(mode.code())
            }
            Request::ReadCapture { max } => w.u8(*max),
            Request::SetAlertConfig(u) => alerts::write_update(w, u),
            Request::SetKeyExchangeExemption { ieee, seconds } => {
                w.u64_le(*ieee)?;
                w.u16_le(*seconds)
            }
            Request::PermitJoin { seconds } => w.u8(*seconds),
            Request::ListDevices { start } => w.u8(*start),
            Request::GetDevice { ieee }
            | Request::InterviewDevice { ieee }
            | Request::GetLightColor { ieee }
            | Request::GetDeviceState { ieee } => w.u64_le(*ieee),
            Request::AddGroup {
                ieee,
                endpoint,
                group,
            }
            | Request::RemoveGroup {
                ieee,
                endpoint,
                group,
            } => {
                w.u64_le(*ieee)?;
                w.u8(*endpoint)?;
                w.u16_le(*group)
            }
            Request::GroupLight { group, command } => {
                w.u16_le(*group)?;
                w.u8(command.code())?;
                command.write_params(w)
            }
            Request::StoreScene {
                ieee,
                endpoint,
                group,
                scene,
            } => {
                w.u64_le(*ieee)?;
                w.u8(*endpoint)?;
                w.u16_le(*group)?;
                w.u8(*scene)
            }
            Request::RecallScene {
                group,
                scene,
                transition_ds,
            } => {
                w.u16_le(*group)?;
                w.u8(*scene)?;
                w.u16_le(*transition_ds)
            }
            Request::ReadAttribute {
                ieee,
                endpoint,
                cluster,
                attribute,
            } => {
                w.u64_le(*ieee)?;
                w.u8(*endpoint)?;
                w.u16_le(*cluster)?;
                w.u16_le(*attribute)
            }
            Request::ConfigureReporting {
                ieee,
                endpoint,
                cluster,
                attribute,
                data_type,
                min_interval,
                max_interval,
                change,
            } => {
                w.u64_le(*ieee)?;
                w.u8(*endpoint)?;
                w.u16_le(*cluster)?;
                w.u16_le(*attribute)?;
                w.u8(*data_type)?;
                w.u16_le(*min_interval)?;
                w.u16_le(*max_interval)?;
                w.u32_le(*change)
            }
            Request::Bind {
                ieee,
                endpoint,
                cluster,
            } => {
                w.u64_le(*ieee)?;
                w.u8(*endpoint)?;
                w.u16_le(*cluster)
            }
            Request::Light {
                ieee,
                endpoint,
                command,
            } => {
                w.u64_le(*ieee)?;
                w.u8(*endpoint)?;
                command.write_params(w)
            }
            Request::RemoveDevice { ieee, leave } => {
                w.u64_le(*ieee)?;
                w.u8(u8::from(*leave))
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let tag = r.u8()?;
        Ok(match tag {
            0x01 => Request::GetHubInfo,
            0x02 => Request::GetNetworkStatus,
            0x03 => Request::PermitJoin { seconds: r.u8()? },
            0x04 => Request::CloseNetwork,
            0x05 => Request::ListDevices { start: r.u8()? },
            0x06 => Request::GetDevice { ieee: r.u64_le()? },
            0x07 => Request::InterviewDevice { ieee: r.u64_le()? },
            0x08 => Request::GetDeviceState { ieee: r.u64_le()? },
            0x09 => Request::ReadAttribute {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                cluster: r.u16_le()?,
                attribute: r.u16_le()?,
            },
            0x0a => Request::ConfigureReporting {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                cluster: r.u16_le()?,
                attribute: r.u16_le()?,
                data_type: r.u8()?,
                min_interval: r.u16_le()?,
                max_interval: r.u16_le()?,
                change: r.u32_le()?,
            },
            0x0b => Request::Bind {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                cluster: r.u16_le()?,
            },
            t if LightCommand::is_code(t) => {
                let ieee = r.u64_le()?;
                let endpoint = r.u8()?;
                let command = LightCommand::read(t, r)?;
                Request::Light {
                    ieee,
                    endpoint,
                    command,
                }
            }
            0x10 => Request::RemoveDevice {
                ieee: r.u64_le()?,
                leave: read_bool(r)?,
            },
            0x11 => Request::GetDiagnostics,
            0x12 => Request::GetBootReport,
            0x13 => Request::GetRadioDiagnostics,
            0x14 => Request::GetStorageDiagnostics,
            0x15 => Request::GetRuntimeDiagnostics,
            0x16 => Request::GetTraceConfiguration,
            0x17 => Request::SetTraceConfiguration {
                min_severity: r.u8()?,
                categories: r.u32_le()?,
            },
            0x18 => Request::ReadTrace {
                from: r.u32_le()?,
                max: r.u8()?,
                ieee: if read_bool(r)? {
                    Some(r.u64_le()?)
                } else {
                    None
                },
            },
            0x19 => Request::ClearTrace,
            0x1a => Request::StartCapture {
                seconds: r.u16_le()?,
                mode: CaptureMode::from_code(r.u8()?).ok_or(ProtocolError::Malformed)?,
            },
            0x1b => Request::StopCapture,
            0x1c => Request::ReadCapture { max: r.u8()? },
            0x1d => Request::SetKeyExchangeExemption {
                ieee: r.u64_le()?,
                seconds: r.u16_le()?,
            },
            0x1e => Request::GetSecurityStatus,
            0x1f => Request::GetAlertStatus,
            0x20 => Request::SetAlertConfig(alerts::read_update(r)?),
            0x21 => Request::QueueTestAlert,
            0x22 => Request::RunRadioProbe,
            0x23 => Request::GetWifiScan,
            0x27 => Request::GetLightColor { ieee: r.u64_le()? },
            0x28 => Request::AddGroup {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                group: r.u16_le()?,
            },
            0x29 => Request::RemoveGroup {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                group: r.u16_le()?,
            },
            0x2a => {
                let group = r.u16_le()?;
                let code = r.u8()?;
                if !LightCommand::is_code(code) {
                    return Err(ProtocolError::Malformed);
                }
                Request::GroupLight {
                    group,
                    command: LightCommand::read(code, r)?,
                }
            }
            0x2b => Request::StoreScene {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                group: r.u16_le()?,
                scene: r.u8()?,
            },
            0x2c => Request::RecallScene {
                group: r.u16_le()?,
                scene: r.u8()?,
                transition_ds: r.u16_le()?,
            },
            0x2d => Request::OtaOffer(ota::read_offer(r)?),
            0x2e => Request::OtaData {
                offset: r.u32_le()?,
                data: ota::read_chunk(r)?,
            },
            0x2f => Request::OtaCancel,
            0x30 => Request::GetOtaStatus,
            0x32 => Request::GreenPowerCommission {
                seconds: r.u16_le()?,
            },
            0x33 => Request::ListGreenPowerDevices { start: r.u8()? },
            0x35 => Request::ScanEnergy { duration: r.u8()? },
            0x36 => Request::ChangeChannel { channel: r.u8()? },
            0x34 => Request::RemoveGreenPowerDevice {
                gpd: gp::read_gpd(r)?,
            },
            0x31 => Request::AddInstallCode {
                ieee: r.u64_le()?,
                code: {
                    let n = usize::from(r.u8()?);
                    Vec::from_slice(r.bytes(n)?).map_err(|_| ProtocolError::TooLarge)?
                },
            },
            t => return Err(ProtocolError::UnknownTag(t)),
        })
    }
}

/// The hub's identity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HubInfo {
    /// Protocol version spoken ([`VERSION`]).
    pub protocol_version: u8,
    /// Firmware version string.
    pub firmware: Text<MAX_FIRMWARE>,
    /// The coordinator's IEEE address.
    pub ieee: u64,
    /// Registry capacity.
    pub max_devices: u8,
    /// Seconds since the hub started.
    pub uptime_s: u32,
    /// Whether the registry is kept in persistent storage.
    pub persistent: bool,
}

/// State of the Zigbee network.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkState {
    /// No network (factory new, or formation failed).
    Down,
    /// Forming or resuming.
    Forming,
    /// Operating.
    Up,
}

impl NetworkState {
    const fn code(self) -> u8 {
        match self {
            NetworkState::Down => 0,
            NetworkState::Forming => 1,
            NetworkState::Up => 2,
        }
    }

    const fn from_code(c: u8) -> Self {
        match c {
            1 => NetworkState::Forming,
            2 => NetworkState::Up,
            _ => NetworkState::Down,
        }
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            NetworkState::Down => "down",
            NetworkState::Forming => "forming",
            NetworkState::Up => "up",
        }
    }
}

/// Network parameters (never the network key).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetworkInfo {
    /// PAN identifier.
    pub pan_id: u16,
    /// Extended PAN identifier.
    pub extended_pan_id: u64,
    /// Channel (11–26).
    pub channel: u8,
}

/// Network status.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetworkStatus {
    /// State.
    pub state: NetworkState,
    /// Parameters (meaningful when up).
    pub network: NetworkInfo,
    /// The coordinator's network address.
    pub short: u16,
    /// Seconds left in the permit-join window (0 = closed).
    pub permit_join_s: u8,
    /// Devices in the registry.
    pub devices: u8,
}

/// A registry entry in a list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceSummary {
    /// IEEE address (stable identity).
    pub ieee: u64,
    /// Current network address.
    pub short: u16,
    /// Category.
    pub category: DeviceCategory,
    /// Capabilities.
    pub capabilities: Capabilities,
    /// Interview status.
    pub interview: InterviewStatus,
    /// On the network (not left).
    pub present: bool,
    /// Seconds since boot when the device was last heard, if ever.
    pub last_seen_s: Option<u32>,
    /// Model identifier.
    pub model: Text<MAX_NAME>,
}

/// A page of the registry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceList {
    /// Devices in the registry.
    pub total: u8,
    /// Index of the first entry of this page.
    pub start: u8,
    /// The entries.
    pub devices: Vec<DeviceSummary, DEVICE_PAGE>,
}

/// One endpoint's simple descriptor.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EndpointDescriptor {
    /// Endpoint.
    pub endpoint: u8,
    /// Profile.
    pub profile: u16,
    /// Device identifier.
    pub device_id: u16,
    /// Input (server) clusters.
    pub inputs: Vec<u16, MAX_INPUT_CLUSTERS>,
    /// Output (client) clusters.
    pub outputs: Vec<u16, MAX_OUTPUT_CLUSTERS>,
}

/// IAS Zone details of a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ZoneInfo {
    /// The endpoint with the IAS Zone server.
    pub endpoint: u8,
    /// `ZoneType`, once read or announced.
    pub zone_type: Option<u16>,
    /// Zone identifier assigned by the hub.
    pub zone_id: Option<u8>,
    /// `ZoneState` read back as enrolled.
    pub enrolled: bool,
}

/// Everything the registry knows about a device.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceInfo {
    /// The summary fields.
    pub summary: DeviceSummary,
    /// Manufacturer name.
    pub manufacturer: Text<MAX_NAME>,
    /// Software build identifier.
    pub sw_build: Text<MAX_BUILD>,
    /// Manufacturer code from the node descriptor.
    pub manufacturer_code: Option<u16>,
    /// Logical type.
    pub logical_type: Option<LogicalType>,
    /// Receiver on when idle (`false`: a sleepy end device).
    pub rx_on_when_idle: Option<bool>,
    /// Power source.
    pub power_source: PowerSource,
    /// Interview stage reached.
    pub interview_stage: InterviewStage,
    /// Endpoints.
    pub endpoints: Vec<EndpointDescriptor, MAX_ENDPOINTS>,
    /// IAS Zone details.
    pub zone: Option<ZoneInfo>,
    /// Link quality to the hub when the device is its neighbor.
    pub lqi: Option<u8>,
    /// Normalized state.
    pub state: DeviceState,
}

/// Counters for troubleshooting.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Diagnostics {
    /// Seconds since boot.
    pub uptime_s: u32,
    /// Radio frames received.
    pub radio_rx: u32,
    /// Radio frames transmitted.
    pub radio_tx: u32,
    /// Radio frames the driver's queue dropped.
    pub radio_dropped: u32,
    /// Stack events dropped (queue full).
    pub stack_events_dropped: u32,
    /// Devices in the registry.
    pub devices: u8,
    /// Registry capacity.
    pub max_devices: u8,
    /// Zigbee transactions awaiting an answer.
    pub pending: u8,
    /// Host commands in flight.
    pub commands: u8,
    /// Hub events dropped (host not reading).
    pub events_dropped: u32,
    /// Interview steps that exhausted their retries.
    pub interview_failures: u32,
    /// Host commands that timed out.
    pub command_timeouts: u32,
    /// Registry records written.
    pub storage_writes: u32,
    /// Registry storage errors.
    pub storage_errors: u32,
    /// Devices refused because the registry was full.
    pub registry_full: u32,
    /// Protocol frames received intact.
    pub frames_rx: u32,
    /// Protocol frames queued for transmission.
    pub frames_tx: u32,
    /// Frames rejected for a CRC or COBS error.
    pub frames_corrupt: u32,
    /// Frames rejected for their size.
    pub frames_oversize: u32,
    /// Frames that did not decode as a request.
    pub frames_malformed: u32,
    /// Requests refused for lack of access.
    pub unauthorized: u32,
    /// Responses dropped because the transmit queue was full.
    pub responses_dropped: u32,
}

/// Responses (hub → host).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// To [`Request::GetHubInfo`].
    HubInfo(HubInfo),
    /// To [`Request::GetNetworkStatus`].
    NetworkStatus(NetworkStatus),
    /// The request was carried out.
    Done,
    /// To [`Request::ListDevices`].
    DeviceList(DeviceList),
    /// To [`Request::GetDevice`].
    Device(DeviceInfo),
    /// To [`Request::GetDeviceState`].
    DeviceState {
        /// The device.
        ieee: u64,
        /// Its state.
        state: DeviceState,
        /// Seconds since boot when it was last heard.
        last_seen_s: Option<u32>,
    },
    /// The request was accepted and continues over the radio; the
    /// outcome arrives as [`Event::CommandCompleted`] or
    /// [`Event::CommandFailed`] with this command identifier.
    Accepted {
        /// Command identifier.
        command: u16,
    },
    /// To [`Request::GetDiagnostics`].
    Diagnostics(Diagnostics),
    /// To [`Request::GetBootReport`].
    BootReport(BootReport),
    /// To [`Request::GetRadioDiagnostics`].
    RadioDiagnostics(RadioDiagnostics),
    /// To [`Request::GetStorageDiagnostics`].
    StorageDiagnostics(StorageDiagnostics),
    /// To [`Request::GetRuntimeDiagnostics`].
    RuntimeDiagnostics(RuntimeDiagnostics),
    /// To [`Request::GetTraceConfiguration`] and
    /// [`Request::SetTraceConfiguration`].
    TraceConfiguration(TraceConfiguration),
    /// To [`Request::ReadTrace`].
    TracePage(TracePage),
    /// To [`Request::ReadCapture`].
    CapturePage(CapturePage),
    /// To [`Request::GetSecurityStatus`].
    SecurityStatus(SecurityStatus),
    /// To [`Request::GetAlertStatus`].
    AlertStatus(AlertStatus),
    /// To [`Request::GetWifiScan`] (`None`: no experiment has scanned
    /// since boot).
    WifiScan(Option<WifiScan>),
    /// To [`Request::GetLightColor`].
    LightColor {
        /// The device.
        ieee: u64,
        /// Its Color Control server.
        color: ColorState,
    },
    /// To [`Request::GetOtaStatus`].
    OtaStatus(OtaStatus),
    /// To [`Request::ListGreenPowerDevices`].
    GreenPowerDevices(GpdList),
    /// The request failed.
    Error(ErrorCode),
}

/// A raw attribute value: its ZCL data type and its ZCL encoding.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttributeData {
    /// ZCL data type identifier.
    pub data_type: u8,
    /// The value as encoded on the air (strings keep their length
    /// prefix).
    pub raw: Vec<u8, MAX_ATTRIBUTE>,
}

impl AttributeData {
    /// The value as an unsigned integer, for integer, enumeration,
    /// bitmap and boolean types.
    pub fn as_u64(&self) -> Option<u64> {
        let width = match self.data_type {
            0x10 | 0x30 => 1,
            0x31 => 2,
            0x08..=0x0f => usize::from(self.data_type - 0x07),
            0x18..=0x1f => usize::from(self.data_type - 0x17),
            0x20..=0x27 => usize::from(self.data_type - 0x1f),
            _ => return None,
        };
        let bytes = self.raw.get(..width)?;
        Some(
            bytes
                .iter()
                .rev()
                .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)),
        )
    }

    /// The value as a signed integer, for the signed integer types.
    pub fn as_i64(&self) -> Option<i64> {
        if !(0x28..=0x2f).contains(&self.data_type) {
            return None;
        }
        let width = usize::from(self.data_type - 0x27);
        let bytes = self.raw.get(..width)?;
        let v = bytes
            .iter()
            .rev()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        let shift = 64 - 8 * u32::try_from(width).ok()?;
        Some(i64::from_ne_bytes((v << shift).to_ne_bytes()) >> shift)
    }
}

impl fmt::Display for AttributeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.data_type {
            0x10 => match self.raw.first() {
                Some(0) => f.write_str("false"),
                Some(1) => f.write_str("true"),
                _ => f.write_str("invalid"),
            },
            0x28..=0x2f => match self.as_i64() {
                Some(v) => write!(f, "{v}"),
                None => f.write_str("invalid"),
            },
            0x20..=0x27 | 0x30 | 0x31 => match self.as_u64() {
                Some(v) => write!(f, "{v}"),
                None => f.write_str("invalid"),
            },
            0x08..=0x0f | 0x18..=0x1f => match self.as_u64() {
                Some(v) => write!(f, "{v:#x}"),
                None => f.write_str("invalid"),
            },
            0x42 => {
                f.write_str("\"")?;
                for &b in self.raw.iter().skip(1) {
                    if b.is_ascii_graphic() || b == b' ' {
                        write!(f, "{}", char::from(b))?;
                    } else {
                        write!(f, "\\x{b:02x}")?;
                    }
                }
                f.write_str("\"")
            }
            0xf0 if self.raw.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.raw);
                write!(f, "{}", Ieee(u64::from_le_bytes(b)))
            }
            t => {
                write!(f, "type {t:#04x}: ")?;
                for b in &self.raw {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// How far a host command got.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CommandStage {
    /// Accepted by the hub, not yet handed to the stack.
    Accepted,
    /// Handed to the Zigbee stack for transmission.
    Sent,
    /// The device answered (Default Response or the request's response).
    Responded,
    /// The device's resulting state was read back.
    Confirmed,
}

impl CommandStage {
    const fn code(self) -> u8 {
        match self {
            CommandStage::Accepted => 0,
            CommandStage::Sent => 1,
            CommandStage::Responded => 2,
            CommandStage::Confirmed => 3,
        }
    }

    const fn from_code(c: u8) -> Self {
        match c {
            1 => CommandStage::Sent,
            2 => CommandStage::Responded,
            3 => CommandStage::Confirmed,
            _ => CommandStage::Accepted,
        }
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            CommandStage::Accepted => "accepted",
            CommandStage::Sent => "sent",
            CommandStage::Responded => "responded",
            CommandStage::Confirmed => "confirmed",
        }
    }
}

/// Normalized sensor events.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SensorEvent {
    /// A water sensor reports water.
    WaterLeakDetected,
    /// A water sensor reports no water.
    WaterLeakCleared,
    /// A water sensor's state can no longer be determined.
    WaterLeakStateUnknown,
    /// A contact sensor opened.
    ContactOpened,
    /// A contact sensor closed.
    ContactClosed,
    /// A contact sensor's state can no longer be determined.
    ContactStateUnknown,
    /// The device signalled a low battery.
    BatteryLow,
    /// The device signalled tampering.
    TamperDetected,
}

impl SensorEvent {
    const ALL: [SensorEvent; 8] = [
        SensorEvent::WaterLeakDetected,
        SensorEvent::WaterLeakCleared,
        SensorEvent::WaterLeakStateUnknown,
        SensorEvent::ContactOpened,
        SensorEvent::ContactClosed,
        SensorEvent::ContactStateUnknown,
        SensorEvent::BatteryLow,
        SensorEvent::TamperDetected,
    ];

    const fn tag(self) -> u8 {
        match self {
            SensorEvent::WaterLeakDetected => 0x09,
            SensorEvent::WaterLeakCleared => 0x0a,
            SensorEvent::WaterLeakStateUnknown => 0x0b,
            SensorEvent::ContactOpened => 0x0c,
            SensorEvent::ContactClosed => 0x0d,
            SensorEvent::ContactStateUnknown => 0x0e,
            SensorEvent::BatteryLow => 0x0f,
            SensorEvent::TamperDetected => 0x10,
        }
    }

    /// A short name for displays.
    pub const fn name(self) -> &'static str {
        match self {
            SensorEvent::WaterLeakDetected => "water-leak-detected",
            SensorEvent::WaterLeakCleared => "water-leak-cleared",
            SensorEvent::WaterLeakStateUnknown => "water-leak-state-unknown",
            SensorEvent::ContactOpened => "contact-opened",
            SensorEvent::ContactClosed => "contact-closed",
            SensorEvent::ContactStateUnknown => "contact-state-unknown",
            SensorEvent::BatteryLow => "battery-low",
            SensorEvent::TamperDetected => "tamper-detected",
        }
    }
}

/// Events (hub → host).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// The hub formed a new network.
    NetworkStarted(NetworkInfo),
    /// The hub resumed its network from persistent storage.
    NetworkRestored(NetworkInfo),
    /// The permit-join window opened (`seconds` > 0) or closed.
    PermitJoinChanged {
        /// Seconds left.
        seconds: u8,
    },
    /// A device joined or rejoined.
    DeviceJoined {
        /// The device.
        ieee: u64,
        /// Its network address.
        short: u16,
        /// A known device came back (rejoin, reboot, new address).
        rejoin: bool,
    },
    /// A device left the network.
    DeviceLeft {
        /// The device.
        ieee: u64,
    },
    /// An interview finished.
    DeviceInterviewCompleted {
        /// The device.
        ieee: u64,
        /// Category.
        category: DeviceCategory,
        /// Capabilities.
        capabilities: Capabilities,
        /// Optional steps failed.
        partial: bool,
    },
    /// An interview step went unanswered after its retries; it resumes
    /// when the device is heard again.
    DeviceInterviewFailed {
        /// The device.
        ieee: u64,
        /// The stage.
        stage: InterviewStage,
        /// Why.
        error: ErrorCode,
    },
    /// A device's normalized state changed.
    DeviceStateChanged {
        /// The device.
        ieee: u64,
        /// The new state.
        state: DeviceState,
    },
    /// A normalized sensor event.
    Sensor {
        /// The device.
        ieee: u64,
        /// The event.
        event: SensorEvent,
    },
    /// An attribute report the state model does not cover.
    AttributeReport {
        /// The device.
        ieee: u64,
        /// Its endpoint.
        endpoint: u8,
        /// The cluster.
        cluster: u16,
        /// The attribute.
        attribute: u16,
        /// The value.
        value: AttributeData,
    },
    /// A host command finished.
    CommandCompleted {
        /// Command identifier from [`Response::Accepted`].
        command: u16,
        /// The device.
        ieee: u64,
        /// The furthest stage reached.
        stage: CommandStage,
        /// The value read, for reads and confirmations.
        value: Option<AttributeData>,
    },
    /// A host command failed.
    CommandFailed {
        /// Command identifier.
        command: u16,
        /// The device.
        ieee: u64,
        /// The furthest stage reached.
        stage: CommandStage,
        /// Why.
        error: ErrorCode,
        /// The ZCL or ZDP status for [`ErrorCode::ZclFailure`] /
        /// [`ErrorCode::ZdoFailure`], else 0.
        status: u8,
    },
    /// A hub-level failure (storage, registry overflow, …).
    HubError {
        /// What failed.
        error: ErrorCode,
        /// Detail (a device count, a status).
        detail: u16,
    },
    /// Events were dropped because the host did not read them in time;
    /// re-read the state the host relies on.
    EventsDropped {
        /// How many.
        count: u16,
    },
    /// A colour light's Color Control state changed (0.4).
    LightColorChanged {
        /// The device.
        ieee: u64,
        /// Its Color Control server.
        color: ColorState,
    },
    /// The hub wants image octets from `offset`: send up to `length` of
    /// them as [`Request::OtaData`] (0.4).
    OtaDataWanted {
        /// File offset.
        offset: u32,
        /// Octets the window has room for.
        length: u16,
    },
    /// A device's download advanced (every 5 %; 0.4).
    OtaProgress {
        /// The device.
        ieee: u64,
        /// Octets delivered.
        offset: u32,
        /// Image size.
        size: u32,
    },
    /// A device's download ended (0.4): `status` 0 the device verified
    /// the image and was told to upgrade now; otherwise the ZCL status
    /// it reported, ABORT (0x95) when cancelled, TIMEOUT (0x94) when it
    /// stopped asking.
    OtaFinished {
        /// The device.
        ieee: u64,
        /// The outcome.
        status: u8,
    },
    /// The Green Power commissioning window opened (`seconds` left) or
    /// closed (0; 0.4).
    GreenPowerCommissioning {
        /// Seconds left.
        seconds: u16,
    },
    /// A GPD was paired (0.4).
    GreenPowerPaired {
        /// The GPD.
        gpd: GpdAddress,
        /// Its GPD DeviceID.
        device_id: u8,
    },
    /// A GPD's pairing was removed: it decommissioned itself or the host
    /// removed it (0.4).
    GreenPowerRemoved {
        /// The GPD.
        gpd: GpdAddress,
    },
    /// A command from a paired GPD (a button press, …), once however
    /// many proxies forwarded it (0.4).
    GreenPowerCommand {
        /// The GPD.
        gpd: GpdAddress,
        /// GPD CommandID ([`gp::command_name`]).
        command: u8,
        /// Its payload (at most [`MAX_GPD_PAYLOAD`] octets kept).
        payload: Vec<u8, MAX_GPD_PAYLOAD>,
    },
    /// The result of [`Request::ScanEnergy`] (0.4).
    EnergyScan {
        /// Channel and energy (0 quiet … 255 saturated, the MAC's ED
        /// level), per channel scanned.
        levels: Vec<(u8, u8), 16>,
    },
    /// The hub moved the network to `channel` (0.4).
    ChannelChanged {
        /// The new channel.
        channel: u8,
    },
}

impl Event {
    const fn tag(&self) -> u8 {
        match self {
            Event::NetworkStarted(_) => 0x01,
            Event::NetworkRestored(_) => 0x02,
            Event::PermitJoinChanged { .. } => 0x03,
            Event::DeviceJoined { .. } => 0x04,
            Event::DeviceLeft { .. } => 0x05,
            Event::DeviceInterviewCompleted { .. } => 0x06,
            Event::DeviceInterviewFailed { .. } => 0x07,
            Event::DeviceStateChanged { .. } => 0x08,
            Event::Sensor { event, .. } => event.tag(),
            Event::AttributeReport { .. } => 0x11,
            Event::CommandCompleted { .. } => 0x12,
            Event::CommandFailed { .. } => 0x13,
            Event::HubError { .. } => 0x14,
            Event::EventsDropped { .. } => 0x15,
            Event::LightColorChanged { .. } => 0x16,
            Event::OtaDataWanted { .. } => 0x17,
            Event::OtaProgress { .. } => 0x18,
            Event::OtaFinished { .. } => 0x19,
            Event::GreenPowerCommissioning { .. } => 0x1a,
            Event::GreenPowerPaired { .. } => 0x1b,
            Event::GreenPowerRemoved { .. } => 0x1c,
            Event::GreenPowerCommand { .. } => 0x1d,
            Event::EnergyScan { .. } => 0x1e,
            Event::ChannelChanged { .. } => 0x1f,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.tag())?;
        match self {
            Event::NetworkStarted(n) | Event::NetworkRestored(n) => write_network(w, n),
            Event::PermitJoinChanged { seconds } => w.u8(*seconds),
            Event::DeviceJoined {
                ieee,
                short,
                rejoin,
            } => {
                w.u64_le(*ieee)?;
                w.u16_le(*short)?;
                w.u8(u8::from(*rejoin))
            }
            Event::DeviceLeft { ieee } | Event::Sensor { ieee, .. } => w.u64_le(*ieee),
            Event::DeviceInterviewCompleted {
                ieee,
                category,
                capabilities,
                partial,
            } => {
                w.u64_le(*ieee)?;
                w.u8(category.code())?;
                w.u32_le(capabilities.0)?;
                w.u8(u8::from(*partial))
            }
            Event::DeviceInterviewFailed { ieee, stage, error } => {
                w.u64_le(*ieee)?;
                w.u8(stage.code())?;
                w.u8(error.code())
            }
            Event::DeviceStateChanged { ieee, state } => {
                w.u64_le(*ieee)?;
                write_state(w, state)
            }
            Event::AttributeReport {
                ieee,
                endpoint,
                cluster,
                attribute,
                value,
            } => {
                w.u64_le(*ieee)?;
                w.u8(*endpoint)?;
                w.u16_le(*cluster)?;
                w.u16_le(*attribute)?;
                write_attribute(w, value)
            }
            Event::CommandCompleted {
                command,
                ieee,
                stage,
                value,
            } => {
                w.u16_le(*command)?;
                w.u64_le(*ieee)?;
                w.u8(stage.code())?;
                match value {
                    Some(v) => {
                        w.u8(1)?;
                        write_attribute(w, v)
                    }
                    None => w.u8(0),
                }
            }
            Event::CommandFailed {
                command,
                ieee,
                stage,
                error,
                status,
            } => {
                w.u16_le(*command)?;
                w.u64_le(*ieee)?;
                w.u8(stage.code())?;
                w.u8(error.code())?;
                w.u8(*status)
            }
            Event::HubError { error, detail } => {
                w.u8(error.code())?;
                w.u16_le(*detail)
            }
            Event::EventsDropped { count } => w.u16_le(*count),
            Event::LightColorChanged { ieee, color } => {
                w.u64_le(*ieee)?;
                write_color(w, color)
            }
            Event::OtaDataWanted { offset, length } => {
                w.u32_le(*offset)?;
                w.u16_le(*length)
            }
            Event::OtaProgress { ieee, offset, size } => {
                w.u64_le(*ieee)?;
                w.u32_le(*offset)?;
                w.u32_le(*size)
            }
            Event::OtaFinished { ieee, status } => {
                w.u64_le(*ieee)?;
                w.u8(*status)
            }
            Event::GreenPowerCommissioning { seconds } => w.u16_le(*seconds),
            Event::GreenPowerPaired { gpd, device_id } => {
                gp::write_gpd(w, gpd)?;
                w.u8(*device_id)
            }
            Event::GreenPowerRemoved { gpd } => gp::write_gpd(w, gpd),
            Event::EnergyScan { levels } => {
                w.u8(count(levels.len())?)?;
                for (c, e) in levels {
                    w.u8(*c)?;
                    w.u8(*e)?;
                }
                Ok(())
            }
            Event::ChannelChanged { channel } => w.u8(*channel),
            Event::GreenPowerCommand {
                gpd,
                command,
                payload,
            } => {
                gp::write_gpd(w, gpd)?;
                w.u8(*command)?;
                gp::write_payload(w, payload)
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let tag = r.u8()?;
        if let Some(event) = SensorEvent::ALL.into_iter().find(|e| e.tag() == tag) {
            return Ok(Event::Sensor {
                ieee: r.u64_le()?,
                event,
            });
        }
        Ok(match tag {
            0x01 => Event::NetworkStarted(read_network(r)?),
            0x02 => Event::NetworkRestored(read_network(r)?),
            0x03 => Event::PermitJoinChanged { seconds: r.u8()? },
            0x04 => Event::DeviceJoined {
                ieee: r.u64_le()?,
                short: r.u16_le()?,
                rejoin: read_bool(r)?,
            },
            0x05 => Event::DeviceLeft { ieee: r.u64_le()? },
            0x06 => Event::DeviceInterviewCompleted {
                ieee: r.u64_le()?,
                category: DeviceCategory::from_code(r.u8()?),
                capabilities: Capabilities(r.u32_le()?),
                partial: read_bool(r)?,
            },
            0x07 => Event::DeviceInterviewFailed {
                ieee: r.u64_le()?,
                stage: InterviewStage::from_code(r.u8()?),
                error: ErrorCode::from_code(r.u8()?),
            },
            0x08 => Event::DeviceStateChanged {
                ieee: r.u64_le()?,
                state: read_state(r)?,
            },
            0x11 => Event::AttributeReport {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                cluster: r.u16_le()?,
                attribute: r.u16_le()?,
                value: read_attribute(r)?,
            },
            0x12 => Event::CommandCompleted {
                command: r.u16_le()?,
                ieee: r.u64_le()?,
                stage: CommandStage::from_code(r.u8()?),
                value: if read_bool(r)? {
                    Some(read_attribute(r)?)
                } else {
                    None
                },
            },
            0x13 => Event::CommandFailed {
                command: r.u16_le()?,
                ieee: r.u64_le()?,
                stage: CommandStage::from_code(r.u8()?),
                error: ErrorCode::from_code(r.u8()?),
                status: r.u8()?,
            },
            0x14 => Event::HubError {
                error: ErrorCode::from_code(r.u8()?),
                detail: r.u16_le()?,
            },
            0x15 => Event::EventsDropped { count: r.u16_le()? },
            0x16 => Event::LightColorChanged {
                ieee: r.u64_le()?,
                color: read_color(r)?,
            },
            0x17 => Event::OtaDataWanted {
                offset: r.u32_le()?,
                length: r.u16_le()?,
            },
            0x18 => Event::OtaProgress {
                ieee: r.u64_le()?,
                offset: r.u32_le()?,
                size: r.u32_le()?,
            },
            0x19 => Event::OtaFinished {
                ieee: r.u64_le()?,
                status: r.u8()?,
            },
            0x1a => Event::GreenPowerCommissioning {
                seconds: r.u16_le()?,
            },
            0x1b => Event::GreenPowerPaired {
                gpd: gp::read_gpd(r)?,
                device_id: r.u8()?,
            },
            0x1c => Event::GreenPowerRemoved {
                gpd: gp::read_gpd(r)?,
            },
            0x1e => {
                let n = r.u8()?;
                let mut levels = Vec::new();
                for _ in 0..n {
                    levels
                        .push((r.u8()?, r.u8()?))
                        .map_err(|_| ProtocolError::TooLarge)?;
                }
                Event::EnergyScan { levels }
            }
            0x1f => Event::ChannelChanged { channel: r.u8()? },
            0x1d => Event::GreenPowerCommand {
                gpd: gp::read_gpd(r)?,
                command: r.u8()?,
                payload: gp::read_payload(r)?,
            },
            t => return Err(ProtocolError::UnknownTag(t)),
        })
    }
}

impl Response {
    const fn tag(&self) -> u8 {
        match self {
            Response::HubInfo(_) => 0x01,
            Response::NetworkStatus(_) => 0x02,
            Response::Done => 0x03,
            Response::DeviceList(_) => 0x04,
            Response::Device(_) => 0x05,
            Response::DeviceState { .. } => 0x06,
            Response::Accepted { .. } => 0x07,
            Response::Diagnostics(_) => 0x08,
            Response::BootReport(_) => 0x09,
            Response::RadioDiagnostics(_) => 0x0a,
            Response::StorageDiagnostics(_) => 0x0b,
            Response::RuntimeDiagnostics(_) => 0x0c,
            Response::TraceConfiguration(_) => 0x0d,
            Response::TracePage(_) => 0x0e,
            Response::CapturePage(_) => 0x0f,
            Response::SecurityStatus(_) => 0x10,
            Response::AlertStatus(_) => 0x11,
            Response::WifiScan(_) => 0x12,
            Response::LightColor { .. } => 0x13,
            Response::OtaStatus(_) => 0x14,
            Response::GreenPowerDevices(_) => 0x15,
            Response::Error(_) => 0x7f,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.tag())?;
        match self {
            Response::HubInfo(h) => {
                w.u8(h.protocol_version)?;
                write_text(w, &h.firmware)?;
                w.u64_le(h.ieee)?;
                w.u8(h.max_devices)?;
                w.u32_le(h.uptime_s)?;
                w.u8(u8::from(h.persistent))
            }
            Response::NetworkStatus(s) => {
                w.u8(s.state.code())?;
                write_network(w, &s.network)?;
                w.u16_le(s.short)?;
                w.u8(s.permit_join_s)?;
                w.u8(s.devices)
            }
            Response::Done => Ok(()),
            Response::DeviceList(l) => {
                w.u8(l.total)?;
                w.u8(l.start)?;
                w.u8(count(l.devices.len())?)?;
                for d in &l.devices {
                    write_summary(w, d)?;
                }
                Ok(())
            }
            Response::Device(d) => write_info(w, d),
            Response::DeviceState {
                ieee,
                state,
                last_seen_s,
            } => {
                w.u64_le(*ieee)?;
                write_state(w, state)?;
                write_opt_u32(w, *last_seen_s)
            }
            Response::Accepted { command } => w.u16_le(*command),
            Response::LightColor { ieee, color } => {
                w.u64_le(*ieee)?;
                write_color(w, color)
            }
            Response::OtaStatus(st) => ota::write_status(w, st),
            Response::GreenPowerDevices(l) => gp::write_list(w, l),
            Response::Diagnostics(d) => write_diagnostics(w, d),
            Response::BootReport(b) => diagnostics::write_boot_report(w, b),
            Response::RadioDiagnostics(d) => diagnostics::write_radio(w, d),
            Response::StorageDiagnostics(d) => diagnostics::write_storage(w, d),
            Response::RuntimeDiagnostics(d) => diagnostics::write_runtime(w, d),
            Response::TraceConfiguration(c) => diagnostics::write_trace_config(w, c),
            Response::TracePage(p) => diagnostics::write_trace_page(w, p),
            Response::CapturePage(p) => diagnostics::write_capture_page(w, p),
            Response::SecurityStatus(st) => security::write_security(w, st),
            Response::AlertStatus(st) => alerts::write_status(w, st),
            Response::WifiScan(s) => alerts::write_scan(w, s.as_ref()),
            Response::Error(e) => w.u8(e.code()),
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(match r.u8()? {
            0x01 => Response::HubInfo(HubInfo {
                protocol_version: r.u8()?,
                firmware: read_text(r)?,
                ieee: r.u64_le()?,
                max_devices: r.u8()?,
                uptime_s: r.u32_le()?,
                persistent: read_bool(r)?,
            }),
            0x02 => Response::NetworkStatus(NetworkStatus {
                state: NetworkState::from_code(r.u8()?),
                network: read_network(r)?,
                short: r.u16_le()?,
                permit_join_s: r.u8()?,
                devices: r.u8()?,
            }),
            0x03 => Response::Done,
            0x04 => {
                let total = r.u8()?;
                let start = r.u8()?;
                let n = r.u8()?;
                let mut devices = Vec::new();
                for _ in 0..n {
                    devices
                        .push(read_summary(r)?)
                        .map_err(|_| ProtocolError::Malformed)?;
                }
                Response::DeviceList(DeviceList {
                    total,
                    start,
                    devices,
                })
            }
            0x05 => Response::Device(read_info(r)?),
            0x06 => Response::DeviceState {
                ieee: r.u64_le()?,
                state: read_state(r)?,
                last_seen_s: read_opt_u32(r)?,
            },
            0x07 => Response::Accepted {
                command: r.u16_le()?,
            },
            0x08 => Response::Diagnostics(read_diagnostics(r)?),
            0x09 => Response::BootReport(diagnostics::read_boot_report(r)?),
            0x0a => Response::RadioDiagnostics(diagnostics::read_radio(r)?),
            0x0b => Response::StorageDiagnostics(diagnostics::read_storage(r)?),
            0x0c => Response::RuntimeDiagnostics(diagnostics::read_runtime(r)?),
            0x0d => Response::TraceConfiguration(diagnostics::read_trace_config(r)?),
            0x0e => Response::TracePage(diagnostics::read_trace_page(r)?),
            0x0f => Response::CapturePage(diagnostics::read_capture_page(r)?),
            0x10 => Response::SecurityStatus(security::read_security(r)?),
            0x11 => Response::AlertStatus(alerts::read_status(r)?),
            0x12 => Response::WifiScan(alerts::read_scan(r)?),
            0x13 => Response::LightColor {
                ieee: r.u64_le()?,
                color: read_color(r)?,
            },
            0x14 => Response::OtaStatus(ota::read_status(r)?),
            0x15 => Response::GreenPowerDevices(gp::read_list(r)?),
            0x7f => Response::Error(ErrorCode::from_code(r.u8()?)),
            t => return Err(ProtocolError::UnknownTag(t)),
        })
    }
}

/// A protocol message.
// No allocator to box the large variants: messages are built and
// encoded one at a time on the stack.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Message {
    /// A request.
    Request {
        /// Request identifier.
        id: u16,
        /// The request.
        request: Request,
    },
    /// A response.
    Response {
        /// The request's identifier.
        id: u16,
        /// The response.
        response: Response,
    },
    /// An event.
    Event {
        /// Event sequence number.
        seq: u16,
        /// The event.
        event: Event,
    },
}

impl Message {
    /// Encodes the message body into `out`; returns its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ProtocolError> {
        let mut w = Writer::new(out);
        w.u8(VERSION)?;
        match self {
            Message::Request { id, request } => {
                w.u8(KIND_REQUEST)?;
                w.u16_le(*id)?;
                request.encode(&mut w)?;
            }
            Message::Response { id, response } => {
                w.u8(KIND_RESPONSE)?;
                w.u16_le(*id)?;
                response.encode(&mut w)?;
            }
            Message::Event { seq, event } => {
                w.u8(KIND_EVENT)?;
                w.u16_le(*seq)?;
                event.encode(&mut w)?;
            }
        }
        if w.position() > frame::MAX_BODY {
            return Err(ProtocolError::TooLarge);
        }
        Ok(w.position())
    }

    /// Decodes a message body; the whole body must be consumed.
    pub fn decode(body: &[u8]) -> Result<Message, ProtocolError> {
        let mut r = Reader::new(body);
        let version = r.u8()?;
        let kind = r.u8()?;
        let id = r.u16_le()?;
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                version,
                id: (kind == KIND_REQUEST).then_some(id),
            });
        }
        let m = match kind {
            KIND_REQUEST => Message::Request {
                id,
                request: Request::decode(&mut r)?,
            },
            KIND_RESPONSE => Message::Response {
                id,
                response: Response::decode(&mut r)?,
            },
            KIND_EVENT => Message::Event {
                seq: id,
                event: Event::decode(&mut r)?,
            },
            k => return Err(ProtocolError::UnknownKind(k)),
        };
        if !r.is_empty() {
            return Err(ProtocolError::Malformed);
        }
        Ok(m)
    }

    /// Encodes the message as a complete wire frame into `out` (at least
    /// [`frame::MAX_WIRE`] octets); returns the frame's length.
    pub fn encode_frame(&self, out: &mut [u8]) -> Result<usize, ProtocolError> {
        let mut body = [0u8; frame::MAX_BODY];
        let n = self.encode(&mut body)?;
        frame::encode(&body[..n], out).map_err(|_| ProtocolError::TooLarge)
    }

    /// The request identifier of a request body that could not be
    /// decoded completely, for an error response.
    pub fn request_id(body: &[u8]) -> Option<u16> {
        let mut r = Reader::new(body);
        let _version = r.u8().ok()?;
        (r.u8().ok()? == KIND_REQUEST).then_some(())?;
        r.u16_le().ok()
    }
}

fn count(n: usize) -> Result<u8, CodecError> {
    u8::try_from(n).map_err(|_| CodecError::Unrepresentable { field: "count" })
}

pub(crate) fn read_bool(r: &mut Reader<'_>) -> Result<bool, ProtocolError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProtocolError::Malformed),
    }
}

pub(crate) fn write_opt_u8(w: &mut Writer<'_>, v: Option<u8>) -> Result<(), CodecError> {
    match v {
        Some(x) => {
            w.u8(1)?;
            w.u8(x)
        }
        None => w.u8(0),
    }
}

pub(crate) fn write_opt_u16(w: &mut Writer<'_>, v: Option<u16>) -> Result<(), CodecError> {
    match v {
        Some(x) => {
            w.u8(1)?;
            w.u16_le(x)
        }
        None => w.u8(0),
    }
}

fn write_opt_u32(w: &mut Writer<'_>, v: Option<u32>) -> Result<(), CodecError> {
    match v {
        Some(x) => {
            w.u8(1)?;
            w.u32_le(x)
        }
        None => w.u8(0),
    }
}

fn read_opt<'a, T>(
    r: &mut Reader<'a>,
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, CodecError>,
) -> Result<Option<T>, ProtocolError> {
    if read_bool(r)? {
        Ok(Some(f(r)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn read_opt_u8(r: &mut Reader<'_>) -> Result<Option<u8>, ProtocolError> {
    read_opt(r, Reader::u8)
}

pub(crate) fn read_opt_u16(r: &mut Reader<'_>) -> Result<Option<u16>, ProtocolError> {
    read_opt(r, Reader::u16_le)
}

fn read_opt_u32(r: &mut Reader<'_>) -> Result<Option<u32>, ProtocolError> {
    read_opt(r, Reader::u32_le)
}

pub(crate) fn write_text<const N: usize>(
    w: &mut Writer<'_>,
    t: &Text<N>,
) -> Result<(), CodecError> {
    w.u8(count(t.len())?)?;
    w.bytes(t)
}

pub(crate) fn read_text<const N: usize>(r: &mut Reader<'_>) -> Result<Text<N>, ProtocolError> {
    let n = usize::from(r.u8()?);
    Vec::from_slice(r.bytes(n)?).map_err(|_| ProtocolError::Malformed)
}

pub(crate) fn write_list<const N: usize>(
    w: &mut Writer<'_>,
    l: &Vec<u16, N>,
) -> Result<(), CodecError> {
    w.u8(count(l.len())?)?;
    for v in l {
        w.u16_le(*v)?;
    }
    Ok(())
}

pub(crate) fn read_list<const N: usize>(r: &mut Reader<'_>) -> Result<Vec<u16, N>, ProtocolError> {
    let n = r.u8()?;
    let mut l = Vec::new();
    for _ in 0..n {
        l.push(r.u16_le()?).map_err(|_| ProtocolError::Malformed)?;
    }
    Ok(l)
}

fn write_network(w: &mut Writer<'_>, n: &NetworkInfo) -> Result<(), CodecError> {
    w.u16_le(n.pan_id)?;
    w.u64_le(n.extended_pan_id)?;
    w.u8(n.channel)
}

fn read_network(r: &mut Reader<'_>) -> Result<NetworkInfo, ProtocolError> {
    Ok(NetworkInfo {
        pan_id: r.u16_le()?,
        extended_pan_id: r.u64_le()?,
        channel: r.u8()?,
    })
}

fn write_attribute(w: &mut Writer<'_>, a: &AttributeData) -> Result<(), CodecError> {
    w.u8(a.data_type)?;
    w.u8(count(a.raw.len())?)?;
    w.bytes(&a.raw)
}

fn read_attribute(r: &mut Reader<'_>) -> Result<AttributeData, ProtocolError> {
    Ok(AttributeData {
        data_type: r.u8()?,
        raw: read_text(r)?,
    })
}

fn write_color(w: &mut Writer<'_>, c: &ColorState) -> Result<(), CodecError> {
    write_opt_u16(w, c.capabilities)?;
    write_opt_u16(w, c.mireds_min)?;
    write_opt_u16(w, c.mireds_max)?;
    w.u8(c.mode.map_or(0xff, ColorMode::code))?;
    write_opt_u16(w, c.x)?;
    write_opt_u16(w, c.y)?;
    write_opt_u16(w, c.mireds)?;
    write_opt_u8(w, c.hue)?;
    write_opt_u8(w, c.saturation)
}

fn read_color(r: &mut Reader<'_>) -> Result<ColorState, ProtocolError> {
    Ok(ColorState {
        capabilities: read_opt_u16(r)?,
        mireds_min: read_opt_u16(r)?,
        mireds_max: read_opt_u16(r)?,
        mode: ColorMode::from_code(r.u8()?),
        x: read_opt_u16(r)?,
        y: read_opt_u16(r)?,
        mireds: read_opt_u16(r)?,
        hue: read_opt_u8(r)?,
        saturation: read_opt_u8(r)?,
    })
}

fn write_state(w: &mut Writer<'_>, s: &DeviceState) -> Result<(), CodecError> {
    w.u8(match s.on {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    })?;
    write_opt_u8(w, s.level)?;
    w.u8(s.contact.code())?;
    w.u8(s.water_leak.code())?;
    w.u8(s.motion.code())?;
    w.u8(s.tamper.code())?;
    w.u8(s.battery_low.code())?;
    w.u8(s.trouble.code())?;
    write_opt_u8(w, s.battery_percent)?;
    write_opt_u16(w, s.battery_mv)?;
    write_opt_u16(
        w,
        s.temperature_centi
            .map(|t| u16::from_ne_bytes(t.to_ne_bytes())),
    )?;
    write_opt_u16(w, s.humidity_centi)?;
    write_opt_u16(w, s.zone_status)
}

fn read_state(r: &mut Reader<'_>) -> Result<DeviceState, ProtocolError> {
    Ok(DeviceState {
        on: match r.u8()? {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(ProtocolError::Malformed),
        },
        level: read_opt_u8(r)?,
        contact: ContactState::from_code(r.u8()?),
        water_leak: LeakState::from_code(r.u8()?),
        motion: Flag::from_code(r.u8()?),
        tamper: Flag::from_code(r.u8()?),
        battery_low: Flag::from_code(r.u8()?),
        trouble: Flag::from_code(r.u8()?),
        battery_percent: read_opt_u8(r)?,
        battery_mv: read_opt_u16(r)?,
        temperature_centi: read_opt_u16(r)?.map(|t| i16::from_ne_bytes(t.to_ne_bytes())),
        humidity_centi: read_opt_u16(r)?,
        zone_status: read_opt_u16(r)?,
    })
}

fn write_summary(w: &mut Writer<'_>, d: &DeviceSummary) -> Result<(), CodecError> {
    w.u64_le(d.ieee)?;
    w.u16_le(d.short)?;
    w.u8(d.category.code())?;
    w.u32_le(d.capabilities.0)?;
    w.u8(d.interview.code())?;
    w.u8(u8::from(d.present))?;
    write_opt_u32(w, d.last_seen_s)?;
    write_text(w, &d.model)
}

fn read_summary(r: &mut Reader<'_>) -> Result<DeviceSummary, ProtocolError> {
    Ok(DeviceSummary {
        ieee: r.u64_le()?,
        short: r.u16_le()?,
        category: DeviceCategory::from_code(r.u8()?),
        capabilities: Capabilities(r.u32_le()?),
        interview: InterviewStatus::from_code(r.u8()?),
        present: read_bool(r)?,
        last_seen_s: read_opt_u32(r)?,
        model: read_text(r)?,
    })
}

fn write_info(w: &mut Writer<'_>, d: &DeviceInfo) -> Result<(), CodecError> {
    write_summary(w, &d.summary)?;
    write_text(w, &d.manufacturer)?;
    write_text(w, &d.sw_build)?;
    write_opt_u16(w, d.manufacturer_code)?;
    w.u8(d.logical_type.map_or(0xff, LogicalType::code))?;
    w.u8(match d.rx_on_when_idle {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    })?;
    w.u8(d.power_source.code())?;
    w.u8(d.interview_stage.code())?;
    w.u8(count(d.endpoints.len())?)?;
    for e in &d.endpoints {
        w.u8(e.endpoint)?;
        w.u16_le(e.profile)?;
        w.u16_le(e.device_id)?;
        write_list(w, &e.inputs)?;
        write_list(w, &e.outputs)?;
    }
    match &d.zone {
        Some(z) => {
            w.u8(1)?;
            w.u8(z.endpoint)?;
            write_opt_u16(w, z.zone_type)?;
            write_opt_u8(w, z.zone_id)?;
            w.u8(u8::from(z.enrolled))?;
        }
        None => w.u8(0)?,
    }
    write_opt_u8(w, d.lqi)?;
    write_state(w, &d.state)
}

fn read_info(r: &mut Reader<'_>) -> Result<DeviceInfo, ProtocolError> {
    let summary = read_summary(r)?;
    let manufacturer = read_text(r)?;
    let sw_build = read_text(r)?;
    let manufacturer_code = read_opt_u16(r)?;
    let logical_type = LogicalType::from_code(r.u8()?);
    let rx_on_when_idle = match r.u8()? {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        _ => return Err(ProtocolError::Malformed),
    };
    let power_source = PowerSource::from_code(r.u8()?);
    let interview_stage = InterviewStage::from_code(r.u8()?);
    let n = r.u8()?;
    let mut endpoints = Vec::new();
    for _ in 0..n {
        let e = EndpointDescriptor {
            endpoint: r.u8()?,
            profile: r.u16_le()?,
            device_id: r.u16_le()?,
            inputs: read_list(r)?,
            outputs: read_list(r)?,
        };
        endpoints.push(e).map_err(|_| ProtocolError::Malformed)?;
    }
    let zone = if read_bool(r)? {
        Some(ZoneInfo {
            endpoint: r.u8()?,
            zone_type: read_opt_u16(r)?,
            zone_id: read_opt_u8(r)?,
            enrolled: read_bool(r)?,
        })
    } else {
        None
    };
    Ok(DeviceInfo {
        summary,
        manufacturer,
        sw_build,
        manufacturer_code,
        logical_type,
        rx_on_when_idle,
        power_source,
        interview_stage,
        endpoints,
        zone,
        lqi: read_opt_u8(r)?,
        state: read_state(r)?,
    })
}

fn write_diagnostics(w: &mut Writer<'_>, d: &Diagnostics) -> Result<(), CodecError> {
    w.u32_le(d.uptime_s)?;
    w.u32_le(d.radio_rx)?;
    w.u32_le(d.radio_tx)?;
    w.u32_le(d.radio_dropped)?;
    w.u32_le(d.stack_events_dropped)?;
    w.u8(d.devices)?;
    w.u8(d.max_devices)?;
    w.u8(d.pending)?;
    w.u8(d.commands)?;
    for v in [
        d.events_dropped,
        d.interview_failures,
        d.command_timeouts,
        d.storage_writes,
        d.storage_errors,
        d.registry_full,
        d.frames_rx,
        d.frames_tx,
        d.frames_corrupt,
        d.frames_oversize,
        d.frames_malformed,
        d.unauthorized,
        d.responses_dropped,
    ] {
        w.u32_le(v)?;
    }
    Ok(())
}

fn read_diagnostics(r: &mut Reader<'_>) -> Result<Diagnostics, ProtocolError> {
    Ok(Diagnostics {
        uptime_s: r.u32_le()?,
        radio_rx: r.u32_le()?,
        radio_tx: r.u32_le()?,
        radio_dropped: r.u32_le()?,
        stack_events_dropped: r.u32_le()?,
        devices: r.u8()?,
        max_devices: r.u8()?,
        pending: r.u8()?,
        commands: r.u8()?,
        events_dropped: r.u32_le()?,
        interview_failures: r.u32_le()?,
        command_timeouts: r.u32_le()?,
        storage_writes: r.u32_le()?,
        storage_errors: r.u32_le()?,
        registry_full: r.u32_le()?,
        frames_rx: r.u32_le()?,
        frames_tx: r.u32_le()?,
        frames_corrupt: r.u32_le()?,
        frames_oversize: r.u32_le()?,
        frames_malformed: r.u32_le()?,
        unauthorized: r.u32_le()?,
        responses_dropped: r.u32_le()?,
    })
}
