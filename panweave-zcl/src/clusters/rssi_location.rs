//! RSSI Location cluster (ZCL8 §3.13): a device's location (absolute or
//! calculated), the channel parameters used to calculate it, and the
//! RSSI exchange among one-hop neighbours of a centralized location
//! scheme.
//!
//! The server keeps the location and settings as attributes and its
//! transient work (repeated location responses, ping blasts, collected
//! RSSI responses) in the cluster instance, serviced by the endpoint
//! dispatcher's timer. The client side is codecs only.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, CommandId, ExtendedAddress};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x000b);

/// `LocationType` (data8, Table 3-73).
pub const LOCATION_TYPE: AttributeDef = AttributeDef::new(0x0000, DataType::Data(1), Access::RW);
/// `LocationMethod` (enum8, Table 3-74).
pub const LOCATION_METHOD: AttributeDef = AttributeDef::new(0x0001, DataType::Enum8, Access::RW);
/// `LocationAge` (uint16 seconds).
pub const LOCATION_AGE: AttributeDef = AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
/// `QualityMeasure` (0–100).
pub const QUALITY_MEASURE: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(1), Access::RO);
/// `NumberOfDevices`.
pub const NUMBER_OF_DEVICES: AttributeDef =
    AttributeDef::new(0x0004, DataType::Uint(1), Access::RO);
/// `Coordinate1` (int16, decimetres).
pub const COORDINATE1: AttributeDef = AttributeDef::new(0x0010, DataType::Int(2), Access::RW);
/// `Coordinate2`.
pub const COORDINATE2: AttributeDef = AttributeDef::new(0x0011, DataType::Int(2), Access::RW);
/// `Coordinate3`.
pub const COORDINATE3: AttributeDef = AttributeDef::new(0x0012, DataType::Int(2), Access::RW);
/// `Power` (int16, 0.01 dBm at one metre).
pub const POWER: AttributeDef = AttributeDef::new(0x0013, DataType::Int(2), Access::RW);
/// `PathLossExponent` (uint16, 0.01).
pub const PATH_LOSS_EXPONENT: AttributeDef =
    AttributeDef::new(0x0014, DataType::Uint(2), Access::RW);
/// `ReportingPeriod` (uint16 seconds; 0 = no periodic notification).
pub const REPORTING_PERIOD: AttributeDef = AttributeDef::new(0x0015, DataType::Uint(2), Access::RW);
/// `CalculationPeriod` (uint16 milliseconds).
pub const CALCULATION_PERIOD: AttributeDef =
    AttributeDef::new(0x0016, DataType::Uint(2), Access::RW);
/// `NumberRSSIMeasurements` (uint8 ≥ 1).
pub const NUMBER_RSSI_MEASUREMENTS: AttributeDef =
    AttributeDef::new(0x0017, DataType::Uint(1), Access::RW);

/// The unknown coordinate / power / exponent value.
pub const UNKNOWN: i16 = i16::MIN;

/// `LocationMethod` values (Table 3-74).
pub mod method {
    /// Lateration from three or more RSSI sources.
    pub const LATERATION: u8 = 0x00;
    /// The location of the strongest neighbour.
    pub const SIGNPOSTING: u8 = 0x01;
    /// RSSI signature database.
    pub const RF_FINGERPRINTING: u8 = 0x02;
    /// An out-of-band device.
    pub const OUT_OF_BAND: u8 = 0x03;
    /// A device on the network (e.g. the gateway).
    pub const CENTRALIZED: u8 = 0x04;
}

/// Set Absolute Location (client → server).
pub const CMD_SET_ABSOLUTE_LOCATION: CommandId = CommandId(0x00);
/// Set Device Configuration.
pub const CMD_SET_DEVICE_CONFIGURATION: CommandId = CommandId(0x01);
/// Get Device Configuration.
pub const CMD_GET_DEVICE_CONFIGURATION: CommandId = CommandId(0x02);
/// Get Location Data.
pub const CMD_GET_LOCATION_DATA: CommandId = CommandId(0x03);
/// RSSI Response.
pub const CMD_RSSI_RESPONSE: CommandId = CommandId(0x04);
/// Send Pings.
pub const CMD_SEND_PINGS: CommandId = CommandId(0x05);
/// Anchor Node Announce.
pub const CMD_ANCHOR_NODE_ANNOUNCE: CommandId = CommandId(0x06);

/// Device Configuration Response (server → client).
pub const CMD_DEVICE_CONFIGURATION_RESPONSE: CommandId = CommandId(0x00);
/// Location Data Response.
pub const CMD_LOCATION_DATA_RESPONSE: CommandId = CommandId(0x01);
/// Location Data Notification.
pub const CMD_LOCATION_DATA_NOTIFICATION: CommandId = CommandId(0x02);
/// Compact Location Data Notification.
pub const CMD_COMPACT_LOCATION_DATA_NOTIFICATION: CommandId = CommandId(0x03);
/// RSSI Ping.
pub const CMD_RSSI_PING: CommandId = CommandId(0x04);
/// RSSI Request.
pub const CMD_RSSI_REQUEST: CommandId = CommandId(0x05);
/// Report RSSI Measurements.
pub const CMD_REPORT_RSSI_MEASUREMENTS: CommandId = CommandId(0x06);
/// Request Own Location.
pub const CMD_REQUEST_OWN_LOCATION: CommandId = CommandId(0x07);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_SET_ABSOLUTE_LOCATION,
        CMD_SET_DEVICE_CONFIGURATION,
        CMD_GET_DEVICE_CONFIGURATION,
        CMD_GET_LOCATION_DATA,
        CMD_RSSI_RESPONSE,
        CMD_SEND_PINGS,
        CMD_ANCHOR_NODE_ANNOUNCE,
    ],
    generated: &[
        CMD_DEVICE_CONFIGURATION_RESPONSE,
        CMD_LOCATION_DATA_RESPONSE,
        CMD_LOCATION_DATA_NOTIFICATION,
        CMD_COMPACT_LOCATION_DATA_NOTIFICATION,
        CMD_RSSI_PING,
        CMD_RSSI_REQUEST,
        CMD_REPORT_RSSI_MEASUREMENTS,
        CMD_REQUEST_OWN_LOCATION,
    ],
};

/// Neighbours a Report RSSI Measurements carries (8 + 1 + 16 n ≤ 77).
pub const MAX_NEIGHBORS: usize = 4;

/// `LocationType` (Table 3-73).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LocationType {
    /// Known absolute location rather than a calculated one.
    pub absolute: bool,
    /// Two-dimensional (Coordinate 3 unknown).
    pub two_d: bool,
    /// Coordinate system (0: rectangular; others reserved).
    pub coordinate_system: u8,
}

impl LocationType {
    /// The attribute value.
    pub const fn to_raw(self) -> u8 {
        (self.absolute as u8) | ((self.two_d as u8) << 1) | ((self.coordinate_system & 0x03) << 2)
    }

    /// From the attribute value.
    pub const fn from_raw(raw: u8) -> Self {
        LocationType {
            absolute: raw & 0x01 != 0,
            two_d: raw & 0x02 != 0,
            coordinate_system: (raw >> 2) & 0x03,
        }
    }
}

/// Set Absolute Location (Figure 3-49).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AbsoluteLocation {
    /// Coordinate 1 ([`UNKNOWN`] when not known).
    pub coordinate1: i16,
    /// Coordinate 2.
    pub coordinate2: i16,
    /// Coordinate 3.
    pub coordinate3: i16,
    /// Power.
    pub power: i16,
    /// Path Loss Exponent.
    pub path_loss_exponent: u16,
}

impl AbsoluteLocation {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(AbsoluteLocation {
            coordinate1: r.i16_le()?,
            coordinate2: r.i16_le()?,
            coordinate3: r.i16_le()?,
            power: r.i16_le()?,
            path_loss_exponent: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.i16_le(self.coordinate1)?;
        w.i16_le(self.coordinate2)?;
        w.i16_le(self.coordinate3)?;
        w.i16_le(self.power)?;
        w.u16_le(self.path_loss_exponent)?;
        Ok(w.position())
    }
}

/// The location parameters (Set Device Configuration, Figure 3-50, and
/// the body of a Device Configuration Response).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceConfiguration {
    /// Power.
    pub power: i16,
    /// Path Loss Exponent.
    pub path_loss_exponent: u16,
    /// Calculation Period (ms).
    pub calculation_period: u16,
    /// Number RSSI Measurements.
    pub number_rssi_measurements: u8,
    /// Reporting Period (s).
    pub reporting_period: u16,
}

impl DeviceConfiguration {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        Self::read(&mut Reader::new(payload))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(DeviceConfiguration {
            power: r.i16_le()?,
            path_loss_exponent: r.u16_le()?,
            calculation_period: r.u16_le()?,
            number_rssi_measurements: r.u8()?,
            reporting_period: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        self.write(&mut w)?;
        Ok(w.position())
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.i16_le(self.power)?;
        w.u16_le(self.path_loss_exponent)?;
        w.u16_le(self.calculation_period)?;
        w.u8(self.number_rssi_measurements)?;
        w.u16_le(self.reporting_period)
    }
}

/// Encodes a Device Configuration Response (Figure 3-56): the status
/// alone when the configuration is not available.
pub fn encode_configuration_response(
    configuration: Option<&DeviceConfiguration>,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    match configuration {
        Some(c) => {
            w.u8(ZclStatus::Success.raw())?;
            c.write(&mut w)?;
        }
        None => w.u8(ZclStatus::NotFound.raw())?,
    }
    Ok(w.position())
}

/// Parses a Device Configuration Response into (status, configuration).
pub fn parse_configuration_response(
    payload: &[u8],
) -> Result<(ZclStatus, Option<DeviceConfiguration>), CodecError> {
    let mut r = Reader::new(payload);
    let status = ZclStatus::from_raw(r.u8()?);
    if status == ZclStatus::Success {
        let c = DeviceConfiguration::read(&mut r)?;
        Ok((status, Some(c)))
    } else {
        Ok((status, None))
    }
}

/// Get Location Data (Figure 3-52).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetLocationData {
    /// Only absolute locations are wanted.
    pub absolute_only: bool,
    /// Calculate a new location first.
    pub recalculate: bool,
    /// Sent as a broadcast / multicast (no target address).
    pub broadcast_indicator: bool,
    /// Subsequent responses are broadcast.
    pub broadcast_response: bool,
    /// Subsequent responses use the compact notification.
    pub compact_response: bool,
    /// Responses wanted (≥ 1).
    pub number_responses: u8,
    /// The device asked about (absent on broadcasts).
    pub target: Option<ExtendedAddress>,
}

impl GetLocationData {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let bits = r.u8()?;
        let number_responses = r.u8()?;
        let broadcast_indicator = bits & 0x04 != 0;
        let target = if broadcast_indicator {
            None
        } else {
            Some(ExtendedAddress(r.u64_le()?))
        };
        Ok(GetLocationData {
            absolute_only: bits & 0x01 != 0,
            recalculate: bits & 0x02 != 0,
            broadcast_indicator,
            broadcast_response: bits & 0x08 != 0,
            compact_response: bits & 0x10 != 0,
            number_responses,
            target,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(u8::from(self.absolute_only)
            | (u8::from(self.recalculate) << 1)
            | (u8::from(self.broadcast_indicator) << 2)
            | (u8::from(self.broadcast_response) << 3)
            | (u8::from(self.compact_response) << 4))?;
        w.u8(self.number_responses)?;
        if !self.broadcast_indicator {
            w.u64_le(self.target.unwrap_or(ExtendedAddress(0)).0)?;
        }
        Ok(w.position())
    }
}

/// The location of a device (Location Data Notification, Figure 3-58,
/// and the body of a Location Data Response).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LocationData {
    /// Location Type.
    pub location_type: LocationType,
    /// Coordinate 1.
    pub coordinate1: i16,
    /// Coordinate 2.
    pub coordinate2: i16,
    /// Coordinate 3 (absent for a 2-D location).
    pub coordinate3: Option<i16>,
    /// Power.
    pub power: i16,
    /// Path Loss Exponent.
    pub path_loss_exponent: u16,
    /// Location Method, Quality Measure and Location Age (absent for
    /// an absolute location).
    pub calculated: Option<Calculated>,
}

/// The calculation fields of a measured location.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Calculated {
    /// Location Method.
    pub method: u8,
    /// Quality Measure.
    pub quality: u8,
    /// Location Age (s).
    pub age: u16,
}

impl LocationData {
    /// Parses a Location Data Notification (`compact` for the Compact
    /// Location Data Notification, which omits Power, Path Loss
    /// Exponent and Location Method).
    pub fn parse(payload: &[u8], compact: bool) -> Result<Self, CodecError> {
        Self::read(&mut Reader::new(payload), compact)
    }

    fn read(r: &mut Reader<'_>, compact: bool) -> Result<Self, CodecError> {
        let location_type = LocationType::from_raw(r.u8()?);
        let coordinate1 = r.i16_le()?;
        let coordinate2 = r.i16_le()?;
        let coordinate3 = if location_type.two_d {
            None
        } else {
            Some(r.i16_le()?)
        };
        let (power, path_loss_exponent) = if compact {
            (UNKNOWN, 0)
        } else {
            (r.i16_le()?, r.u16_le()?)
        };
        let calculated = if location_type.absolute {
            None
        } else {
            let method = if compact {
                method::CENTRALIZED
            } else {
                r.u8()?
            };
            Some(Calculated {
                method,
                quality: r.u8()?,
                age: r.u16_le()?,
            })
        };
        Ok(LocationData {
            location_type,
            coordinate1,
            coordinate2,
            coordinate3,
            power,
            path_loss_exponent,
            calculated,
        })
    }

    /// Encodes a Location Data Notification (or its compact form).
    pub fn encode(&self, compact: bool, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        self.write(&mut w, compact)?;
        Ok(w.position())
    }

    fn write(&self, w: &mut Writer<'_>, compact: bool) -> Result<(), CodecError> {
        w.u8(self.location_type.to_raw())?;
        w.i16_le(self.coordinate1)?;
        w.i16_le(self.coordinate2)?;
        if !self.location_type.two_d {
            w.i16_le(self.coordinate3.unwrap_or(UNKNOWN))?;
        }
        if !compact {
            w.i16_le(self.power)?;
            w.u16_le(self.path_loss_exponent)?;
        }
        if !self.location_type.absolute {
            let c = self.calculated.unwrap_or(Calculated {
                method: method::LATERATION,
                quality: 0,
                age: 0,
            });
            if !compact {
                w.u8(c.method)?;
            }
            w.u8(c.quality)?;
            w.u16_le(c.age)?;
        }
        Ok(())
    }
}

/// Encodes a Location Data Response (Figure 3-57): the status alone
/// when the location is not available.
pub fn encode_location_response(
    location: Option<&LocationData>,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    match location {
        Some(l) => {
            w.u8(ZclStatus::Success.raw())?;
            l.write(&mut w, false)?;
        }
        None => w.u8(ZclStatus::NotFound.raw())?,
    }
    Ok(w.position())
}

/// Parses a Location Data Response into (status, location).
pub fn parse_location_response(
    payload: &[u8],
) -> Result<(ZclStatus, Option<LocationData>), CodecError> {
    let mut r = Reader::new(payload);
    let status = ZclStatus::from_raw(r.u8()?);
    if status == ZclStatus::Success {
        let l = LocationData::read(&mut r, false)?;
        Ok((status, Some(l)))
    } else {
        Ok((status, None))
    }
}

/// An RSSI measurement of a neighbour (RSSI Response, Figure 3-53, and
/// the Neighbor Info structure of Figure 3-61).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighborInfo {
    /// The neighbour.
    pub neighbor: ExtendedAddress,
    /// Its X coordinate.
    pub x: i16,
    /// Its Y coordinate.
    pub y: i16,
    /// Its Z coordinate.
    pub z: i16,
    /// The RSSI it measured, dBm.
    pub rssi: i8,
    /// Packets averaged (1: no averaging).
    pub measurements: u8,
}

impl NeighborInfo {
    /// Parses an RSSI Response payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        Self::read(&mut Reader::new(payload))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(NeighborInfo {
            neighbor: ExtendedAddress(r.u64_le()?),
            x: r.i16_le()?,
            y: r.i16_le()?,
            z: r.i16_le()?,
            rssi: r.i8()?,
            measurements: r.u8()?,
        })
    }

    /// Encodes an RSSI Response payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        self.write(&mut w)?;
        Ok(w.position())
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.neighbor.0)?;
        w.i16_le(self.x)?;
        w.i16_le(self.y)?;
        w.i16_le(self.z)?;
        w.i8(self.rssi)?;
        w.u8(self.measurements)
    }
}

/// Send Pings (Figure 3-54).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SendPings {
    /// The node that blasts.
    pub target: ExtendedAddress,
    /// Pings to send.
    pub number_rssi_measurements: u8,
    /// Interval between pings (ms).
    pub calculation_period: u16,
}

impl SendPings {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(SendPings {
            target: ExtendedAddress(r.u64_le()?),
            number_rssi_measurements: r.u8()?,
            calculation_period: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u64_le(self.target.0)?;
        w.u8(self.number_rssi_measurements)?;
        w.u16_le(self.calculation_period)?;
        Ok(w.position())
    }
}

/// Anchor Node Announce (Figure 3-55).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AnchorNodeAnnounce {
    /// The anchor node.
    pub anchor: ExtendedAddress,
    /// X.
    pub x: i16,
    /// Y.
    pub y: i16,
    /// Z.
    pub z: i16,
}

impl AnchorNodeAnnounce {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(AnchorNodeAnnounce {
            anchor: ExtendedAddress(r.u64_le()?),
            x: r.i16_le()?,
            y: r.i16_le()?,
            z: r.i16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u64_le(self.anchor.0)?;
        w.i16_le(self.x)?;
        w.i16_le(self.y)?;
        w.i16_le(self.z)?;
        Ok(w.position())
    }
}

/// Report RSSI Measurements (Figure 3-60).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RssiReport {
    /// The measuring device (the one that blasted).
    pub measuring: ExtendedAddress,
    /// The neighbours' measurements.
    pub neighbors: Vec<NeighborInfo, MAX_NEIGHBORS>,
}

impl RssiReport {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let measuring = ExtendedAddress(r.u64_le()?);
        let n = r.u8()?;
        let mut neighbors = Vec::new();
        for _ in 0..n {
            neighbors
                .push(NeighborInfo::read(&mut r)?)
                .map_err(|_| CodecError::Unrepresentable { field: "neighbors" })?;
        }
        Ok(RssiReport {
            measuring,
            neighbors,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u64_le(self.measuring.0)?;
        w.u8(u8::try_from(self.neighbors.len()).unwrap_or(u8::MAX))?;
        for n in &self.neighbors {
            n.write(&mut w)?;
        }
        Ok(w.position())
    }
}

/// Parses an address-only payload (Get Device Configuration, Request
/// Own Location).
pub fn parse_address(payload: &[u8]) -> Result<ExtendedAddress, CodecError> {
    Reader::new(payload).u64_le().map(ExtendedAddress)
}

/// Encodes an address-only payload.
pub fn encode_address(address: ExtendedAddress, out: &mut [u8]) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    w.u64_le(address.0)?;
    Ok(w.position())
}

/// Transient server work (`ClusterState::RssiLocation`).
#[derive(Clone, Debug)]
pub struct State {
    /// The device's own IEEE address (the target it answers for).
    pub ieee: ExtendedAddress,
    /// Location responses still to send after the first, with the
    /// requested form (compact, broadcast).
    pub pending_responses: u8,
    /// Subsequent responses use the compact notification.
    pub compact: bool,
    /// Subsequent responses are broadcast.
    pub broadcast: bool,
    /// The requester of the repeated responses.
    pub requester: Option<(panweave_types::ShortAddress, panweave_types::Endpoint)>,
    /// RSSI Pings still to send.
    pub pending_pings: u8,
    /// RSSI Responses collected for a Report RSSI Measurements.
    pub collected: Vec<NeighborInfo, MAX_NEIGHBORS>,
    /// When the collected responses are reported.
    pub report_at: Option<Instant>,
    /// When the next response / ping is due.
    pub next_response: Option<Instant>,
    /// When the next ping is due.
    pub next_ping: Option<Instant>,
    /// When the next periodic Location Data Notification is due.
    pub next_report: Option<Instant>,
    /// When the location was last calculated (for `LocationAge`).
    pub calculated_at: Option<Instant>,
}

impl State {
    fn new(ieee: ExtendedAddress) -> Self {
        State {
            ieee,
            pending_responses: 0,
            compact: false,
            broadcast: false,
            requester: None,
            pending_pings: 0,
            collected: Vec::new(),
            report_at: None,
            next_response: None,
            next_ping: None,
            next_report: None,
            calculated_at: None,
        }
    }

    fn earliest(&self) -> Option<Instant> {
        [
            self.next_response,
            self.next_ping,
            self.next_report,
            self.report_at,
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// Builds a server for the device `ieee` with an unknown, measured,
/// three-dimensional location: coordinates, `Power` and
/// `PathLossExponent` unknown, `LocationMethod` `method`,
/// `NumberRSSIMeasurements` 1, periods 0.
pub fn server<const A: usize>(
    ieee: ExtendedAddress,
    method: u8,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    let unknown = Value::Int {
        width: 2,
        value: i64::from(UNKNOWN),
    };
    c.add_attribute(LOCATION_TYPE, &Value::Data { width: 1, bits: 0 })?;
    c.add_attribute(LOCATION_METHOD, &Value::Enum8(method))?;
    c.add_attribute(LOCATION_AGE, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(QUALITY_MEASURE, &Value::Uint { width: 1, value: 0 })?;
    c.add_attribute(NUMBER_OF_DEVICES, &Value::Uint { width: 1, value: 0 })?;
    c.add_attribute(COORDINATE1, &unknown)?;
    c.add_attribute(COORDINATE2, &unknown)?;
    c.add_attribute(COORDINATE3, &unknown)?;
    c.add_attribute(POWER, &unknown)?;
    c.add_attribute(
        PATH_LOSS_EXPONENT,
        &Value::Uint {
            width: 2,
            value: 0xffff,
        },
    )?;
    c.add_attribute(REPORTING_PERIOD, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(CALCULATION_PERIOD, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(
        NUMBER_RSSI_MEASUREMENTS,
        &Value::Uint { width: 1, value: 1 },
    )?;
    c.state = ClusterState::RssiLocation(State::new(ieee));
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// The server's transient state.
pub fn state<const A: usize>(c: &ClusterInstance<A>) -> Option<&State> {
    match &c.state {
        ClusterState::RssiLocation(s) => Some(s),
        _ => None,
    }
}

fn state_mut<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut State> {
    match &mut c.state {
        ClusterState::RssiLocation(s) => Some(s),
        _ => None,
    }
}

fn set_location_type<const A: usize>(c: &mut ClusterInstance<A>, t: LocationType) {
    c.set(
        LOCATION_TYPE.id,
        &Value::Data {
            width: 1,
            bits: u64::from(t.to_raw()),
        },
    );
}

/// The server's `LocationType`.
pub fn location_type<const A: usize>(c: &ClusterInstance<A>) -> LocationType {
    LocationType::from_raw(c.u8(LOCATION_TYPE.id).unwrap_or(0))
}

/// The server's location as reported (`LocationAge` measured from the
/// last calculation, `now`).
pub fn location<const A: usize>(c: &ClusterInstance<A>, now: Instant) -> LocationData {
    let location_type = location_type(c);
    let age = state(c).and_then(|s| s.calculated_at).map_or(0, |t| {
        u16::try_from(now.saturating_duration_since(t).as_secs()).unwrap_or(u16::MAX)
    });
    LocationData {
        location_type,
        coordinate1: c.i16(COORDINATE1.id).unwrap_or(UNKNOWN),
        coordinate2: c.i16(COORDINATE2.id).unwrap_or(UNKNOWN),
        coordinate3: if location_type.two_d {
            None
        } else {
            Some(c.i16(COORDINATE3.id).unwrap_or(UNKNOWN))
        },
        power: c.i16(POWER.id).unwrap_or(UNKNOWN),
        path_loss_exponent: c.u16(PATH_LOSS_EXPONENT.id).unwrap_or(0xffff),
        calculated: if location_type.absolute {
            None
        } else {
            Some(Calculated {
                method: c.u8(LOCATION_METHOD.id).unwrap_or(method::LATERATION),
                quality: c.u8(QUALITY_MEASURE.id).unwrap_or(0),
                age,
            })
        },
    }
}

/// The server's device configuration.
pub fn configuration<const A: usize>(c: &ClusterInstance<A>) -> DeviceConfiguration {
    DeviceConfiguration {
        power: c.i16(POWER.id).unwrap_or(UNKNOWN),
        path_loss_exponent: c.u16(PATH_LOSS_EXPONENT.id).unwrap_or(0xffff),
        calculation_period: c.u16(CALCULATION_PERIOD.id).unwrap_or(0),
        number_rssi_measurements: c.u8(NUMBER_RSSI_MEASUREMENTS.id).unwrap_or(1),
        reporting_period: c.u16(REPORTING_PERIOD.id).unwrap_or(0),
    }
}

/// Records a calculated (measured) location: the coordinates, the
/// confidence and the number of devices used, `LocationAge` restarting
/// at 0. Returns whether a periodic notification is configured.
pub fn set_measured<const A: usize>(
    c: &mut ClusterInstance<A>,
    coordinates: (i16, i16, Option<i16>),
    quality: u8,
    devices: u8,
    now: Instant,
) {
    let mut t = location_type(c);
    t.absolute = false;
    t.two_d = coordinates.2.is_none();
    set_location_type(c, t);
    c.set_i16(COORDINATE1.id, coordinates.0);
    c.set_i16(COORDINATE2.id, coordinates.1);
    c.set_i16(COORDINATE3.id, coordinates.2.unwrap_or(UNKNOWN));
    c.set_u8(QUALITY_MEASURE.id, quality.min(100));
    c.set_u8(NUMBER_OF_DEVICES.id, devices);
    c.set_u16(LOCATION_AGE.id, 0);
    if let Some(s) = state_mut(c) {
        s.calculated_at = Some(now);
    }
    schedule_report(c, now);
}

/// Sets an absolute location (also the effect of Set Absolute Location).
pub fn set_absolute<const A: usize>(
    c: &mut ClusterInstance<A>,
    l: &AbsoluteLocation,
    now: Instant,
) {
    let mut t = location_type(c);
    t.absolute = true;
    t.two_d = l.coordinate3 == UNKNOWN;
    set_location_type(c, t);
    c.set_i16(COORDINATE1.id, l.coordinate1);
    c.set_i16(COORDINATE2.id, l.coordinate2);
    c.set_i16(COORDINATE3.id, l.coordinate3);
    c.set_i16(POWER.id, l.power);
    c.set_u16(PATH_LOSS_EXPONENT.id, l.path_loss_exponent);
    schedule_report(c, now);
}

/// Applies a device configuration (the effect of Set Device
/// Configuration).
pub fn set_configuration<const A: usize>(
    c: &mut ClusterInstance<A>,
    cfg: &DeviceConfiguration,
    now: Instant,
) {
    c.set_i16(POWER.id, cfg.power);
    c.set_u16(PATH_LOSS_EXPONENT.id, cfg.path_loss_exponent);
    c.set_u16(CALCULATION_PERIOD.id, cfg.calculation_period);
    c.set_u8(
        NUMBER_RSSI_MEASUREMENTS.id,
        cfg.number_rssi_measurements.max(1),
    );
    c.set_u16(REPORTING_PERIOD.id, cfg.reporting_period);
    schedule_report(c, now);
}

/// (Re)arms the periodic Location Data Notification from
/// `ReportingPeriod`.
fn schedule_report<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) {
    let period = c.u16(REPORTING_PERIOD.id).unwrap_or(0);
    if let Some(s) = state_mut(c) {
        s.next_report = (period > 0).then(|| now + Duration::from_secs(u64::from(period)));
    }
    rearm(c);
}

fn rearm<const A: usize>(c: &mut ClusterInstance<A>) {
    c.tick = state(c).and_then(State::earliest);
}

/// Result of a received command (§3.13.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Attributes updated: Default Response SUCCESS.
    Updated,
    /// Reply with a Device Configuration Response (`None`: NOT_FOUND).
    Configuration(Option<DeviceConfiguration>),
    /// Reply with a Location Data Response (`None`: NOT_FOUND status);
    /// `recalculate` asks the application for a fresh calculation
    /// first.
    Location {
        /// The location, or `None` for a NOT_FOUND response.
        location: Option<LocationData>,
        /// A new calculation was requested.
        recalculate: bool,
    },
    /// No response (a broadcast asked for absolute locations only).
    Silent,
    /// An anchor node announced its position (for the application).
    Anchor(AnchorNodeAnnounce),
    /// An RSSI Response was collected; the report follows after
    /// `CalculationPeriod`.
    Collected,
    /// Refused with this status.
    Default(ZclStatus),
}

/// Handles a received command from `src`.
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
    src: (panweave_types::ShortAddress, panweave_types::Endpoint),
    now: Instant,
) -> Outcome {
    match cmd {
        CMD_SET_ABSOLUTE_LOCATION => {
            let Ok(l) = AbsoluteLocation::parse(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            set_absolute(c, &l, now);
            Outcome::Updated
        }
        CMD_SET_DEVICE_CONFIGURATION => {
            let Ok(cfg) = DeviceConfiguration::parse(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            if location_type(c).absolute {
                // Invalid for an absolute location (§3.13.2.3.2).
                return Outcome::Default(ZclStatus::Failure);
            }
            set_configuration(c, &cfg, now);
            Outcome::Updated
        }
        CMD_GET_DEVICE_CONFIGURATION => {
            let Ok(target) = parse_address(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let own = state(c).map(|s| s.ieee);
            if own == Some(target) {
                Outcome::Configuration(Some(configuration(c)))
            } else {
                Outcome::Configuration(None)
            }
        }
        CMD_GET_LOCATION_DATA => {
            let Ok(req) = GetLocationData::parse(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let own = state(c).map(|s| s.ieee);
            let mine = req.broadcast_indicator || req.target == own;
            if !mine {
                return Outcome::Location {
                    location: None,
                    recalculate: false,
                };
            }
            let t = location_type(c);
            if req.absolute_only && !t.absolute {
                return Outcome::Silent;
            }
            if req.number_responses > 1 {
                let period = c.u16(REPORTING_PERIOD.id).unwrap_or(0).max(1);
                if let Some(s) = state_mut(c) {
                    s.pending_responses = req.number_responses.saturating_sub(1);
                    s.compact = req.compact_response;
                    s.broadcast = req.broadcast_response;
                    s.requester = Some(src);
                    s.next_response = Some(now + Duration::from_secs(u64::from(period)));
                }
                rearm(c);
            }
            Outcome::Location {
                location: Some(location(c, now)),
                recalculate: req.recalculate && !t.absolute,
            }
        }
        CMD_RSSI_RESPONSE => {
            let Ok(info) = NeighborInfo::parse(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let period = c.u16(CALCULATION_PERIOD.id).unwrap_or(0);
            let Some(s) = state_mut(c) else {
                return Outcome::Default(ZclStatus::Failure);
            };
            s.collected.retain(|n| n.neighbor != info.neighbor);
            if s.collected.push(info).is_err() {
                return Outcome::Default(ZclStatus::InsufficientSpace);
            }
            if s.report_at.is_none() {
                s.report_at = Some(now + Duration::from_millis(u64::from(period)));
            }
            rearm(c);
            Outcome::Collected
        }
        CMD_SEND_PINGS => {
            let Ok(p) = SendPings::parse(payload) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            c.set_u8(
                NUMBER_RSSI_MEASUREMENTS.id,
                p.number_rssi_measurements.max(1),
            );
            c.set_u16(CALCULATION_PERIOD.id, p.calculation_period);
            if let Some(s) = state_mut(c) {
                s.pending_pings = p.number_rssi_measurements.max(1);
                s.next_ping = Some(now);
            }
            rearm(c);
            Outcome::Updated
        }
        CMD_ANCHOR_NODE_ANNOUNCE => match AnchorNodeAnnounce::parse(payload) {
            Ok(a) => Outcome::Anchor(a),
            Err(_) => Outcome::Default(ZclStatus::MalformedCommand),
        },
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

/// Timer work due at `now`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Due {
    /// Send a (compact) Location Data Notification to the requester
    /// of repeated responses, or broadcast it.
    Response {
        /// Compact form.
        compact: bool,
        /// Broadcast rather than unicast to the requester.
        broadcast: bool,
        /// The requester.
        requester: Option<(panweave_types::ShortAddress, panweave_types::Endpoint)>,
    },
    /// Send an RSSI Ping.
    Ping,
    /// Send this Report RSSI Measurements to the central device.
    Report(RssiReport),
    /// Send the periodic Location Data Notification.
    Periodic,
}

/// Services the timer: returns the work due at `now`, one item per
/// call (call until `None`).
pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<Due> {
    let reporting = u64::from(c.u16(REPORTING_PERIOD.id).unwrap_or(0).max(1));
    let calculation = u64::from(c.u16(CALCULATION_PERIOD.id).unwrap_or(0));
    let s = state_mut(c)?;
    let due = if s.next_response.is_some_and(|t| now.has_reached(t)) {
        s.pending_responses = s.pending_responses.saturating_sub(1);
        s.next_response = (s.pending_responses > 0).then(|| now + Duration::from_secs(reporting));
        Some(Due::Response {
            compact: s.compact,
            broadcast: s.broadcast,
            requester: s.requester,
        })
    } else if s.next_ping.is_some_and(|t| now.has_reached(t)) {
        s.pending_pings = s.pending_pings.saturating_sub(1);
        s.next_ping = (s.pending_pings > 0).then(|| now + Duration::from_millis(calculation));
        Some(Due::Ping)
    } else if s.report_at.is_some_and(|t| now.has_reached(t)) {
        s.report_at = None;
        let report = RssiReport {
            measuring: s.ieee,
            neighbors: core::mem::take(&mut s.collected),
        };
        Some(Due::Report(report))
    } else if s.next_report.is_some_and(|t| now.has_reached(t)) {
        s.next_report = Some(now + Duration::from_secs(reporting));
        Some(Due::Periodic)
    } else {
        None
    };
    rearm(c);
    due
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::{Endpoint, ShortAddress};

    const OWN: ExtendedAddress = ExtendedAddress(0x0011_2233_4455_6677);
    const SRC: (ShortAddress, Endpoint) = (ShortAddress(0x1234), Endpoint(5));

    #[test]
    fn codecs_round_trip() {
        let t = LocationType {
            absolute: true,
            two_d: true,
            coordinate_system: 0,
        };
        assert_eq!(t.to_raw(), 0x03);
        assert_eq!(LocationType::from_raw(0x03), t);
        let mut buf = [0u8; 80];
        let l = AbsoluteLocation {
            coordinate1: 100,
            coordinate2: -200,
            coordinate3: UNKNOWN,
            power: -4000,
            path_loss_exponent: 250,
        };
        let n = l.encode(&mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(AbsoluteLocation::parse(&buf[..n]).unwrap(), l);
        let cfg = DeviceConfiguration {
            power: -4000,
            path_loss_exponent: 250,
            calculation_period: 500,
            number_rssi_measurements: 4,
            reporting_period: 60,
        };
        let n = encode_configuration_response(Some(&cfg), &mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(
            parse_configuration_response(&buf[..n]).unwrap(),
            (ZclStatus::Success, Some(cfg))
        );
        let n = encode_configuration_response(None, &mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x8b]);
        assert_eq!(
            parse_configuration_response(&buf[..n]).unwrap(),
            (ZclStatus::NotFound, None)
        );
        let g = GetLocationData {
            absolute_only: false,
            recalculate: true,
            broadcast_indicator: false,
            broadcast_response: false,
            compact_response: true,
            number_responses: 3,
            target: Some(OWN),
        };
        let n = g.encode(&mut buf).unwrap();
        assert_eq!(&buf[..2], &[0x12, 3]);
        assert_eq!(n, 10);
        assert_eq!(GetLocationData::parse(&buf[..n]).unwrap(), g);
        let g = GetLocationData {
            broadcast_indicator: true,
            target: None,
            ..g
        };
        let n = g.encode(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(GetLocationData::parse(&buf[..n]).unwrap(), g);
        // A measured 3-D location, full and compact; an absolute 2-D one.
        let l = LocationData {
            location_type: LocationType::default(),
            coordinate1: 10,
            coordinate2: 20,
            coordinate3: Some(30),
            power: -4000,
            path_loss_exponent: 250,
            calculated: Some(Calculated {
                method: method::LATERATION,
                quality: 80,
                age: 5,
            }),
        };
        let n = l.encode(false, &mut buf).unwrap();
        assert_eq!(n, 1 + 6 + 4 + 4);
        assert_eq!(LocationData::parse(&buf[..n], false).unwrap(), l);
        let n = l.encode(true, &mut buf).unwrap();
        assert_eq!(n, 1 + 6 + 3);
        let compact = LocationData::parse(&buf[..n], true).unwrap();
        assert_eq!(compact.power, UNKNOWN);
        assert_eq!(compact.calculated.unwrap().quality, 80);
        let a = LocationData {
            location_type: LocationType {
                absolute: true,
                two_d: true,
                coordinate_system: 0,
            },
            coordinate3: None,
            calculated: None,
            ..l
        };
        let n = encode_location_response(Some(&a), &mut buf).unwrap();
        assert_eq!(n, 1 + 1 + 4 + 4);
        assert_eq!(
            parse_location_response(&buf[..n]).unwrap(),
            (ZclStatus::Success, Some(a))
        );
        let info = NeighborInfo {
            neighbor: OWN,
            x: 1,
            y: 2,
            z: 3,
            rssi: -70,
            measurements: 4,
        };
        let n = info.encode(&mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(NeighborInfo::parse(&buf[..n]).unwrap(), info);
        let mut report = RssiReport {
            measuring: ExtendedAddress(1),
            neighbors: Vec::new(),
        };
        report.neighbors.push(info).unwrap();
        let n = report.encode(&mut buf).unwrap();
        assert_eq!(n, 9 + 16);
        assert_eq!(RssiReport::parse(&buf[..n]).unwrap(), report);
        let p = SendPings {
            target: OWN,
            number_rssi_measurements: 5,
            calculation_period: 200,
        };
        let n = p.encode(&mut buf).unwrap();
        assert_eq!(SendPings::parse(&buf[..n]).unwrap(), p);
        let an = AnchorNodeAnnounce {
            anchor: OWN,
            x: 1,
            y: 2,
            z: UNKNOWN,
        };
        let n = an.encode(&mut buf).unwrap();
        assert_eq!(AnchorNodeAnnounce::parse(&buf[..n]).unwrap(), an);
    }

    #[test]
    fn server_answers_and_schedules() {
        let now = Instant::from_millis(1000);
        let mut c: ClusterInstance<16> = server(OWN, method::CENTRALIZED).unwrap();
        // Set Absolute Location updates the attributes and the type.
        let l = AbsoluteLocation {
            coordinate1: 100,
            coordinate2: 200,
            coordinate3: UNKNOWN,
            power: -4000,
            path_loss_exponent: 250,
        };
        let mut buf = [0u8; 16];
        let n = l.encode(&mut buf).unwrap();
        assert_eq!(
            handle(&mut c, CMD_SET_ABSOLUTE_LOCATION, &buf[..n], SRC, now),
            Outcome::Updated
        );
        assert_eq!(
            location_type(&c),
            LocationType {
                absolute: true,
                two_d: true,
                coordinate_system: 0
            }
        );
        // Set Device Configuration is invalid for an absolute location.
        let cfg = DeviceConfiguration {
            power: -4000,
            path_loss_exponent: 250,
            calculation_period: 100,
            number_rssi_measurements: 3,
            reporting_period: 10,
        };
        let n = cfg.encode(&mut buf).unwrap();
        assert_eq!(
            handle(&mut c, CMD_SET_DEVICE_CONFIGURATION, &buf[..n], SRC, now),
            Outcome::Default(ZclStatus::Failure)
        );
        // Get Device Configuration: own address answered, others NOT_FOUND.
        let n = encode_address(OWN, &mut buf).unwrap();
        assert_eq!(
            handle(&mut c, CMD_GET_DEVICE_CONFIGURATION, &buf[..n], SRC, now),
            Outcome::Configuration(Some(configuration(&c)))
        );
        let n = encode_address(ExtendedAddress(9), &mut buf).unwrap();
        assert_eq!(
            handle(&mut c, CMD_GET_DEVICE_CONFIGURATION, &buf[..n], SRC, now),
            Outcome::Configuration(None)
        );
        // Back to a measured location; Set Device Configuration applies
        // and arms the periodic notification.
        set_measured(&mut c, (10, 20, Some(30)), 90, 3, now);
        assert_eq!(
            handle(&mut c, CMD_SET_DEVICE_CONFIGURATION, &buf[..0], SRC, now),
            Outcome::Default(ZclStatus::MalformedCommand)
        );
        let n = cfg.encode(&mut buf).unwrap();
        assert_eq!(
            handle(&mut c, CMD_SET_DEVICE_CONFIGURATION, &buf[..n], SRC, now),
            Outcome::Updated
        );
        assert_eq!(c.tick, Some(now + Duration::from_secs(10)));
        // Get Location Data with three responses: the first at once,
        // the others as compact notifications every ReportingPeriod.
        let g = GetLocationData {
            absolute_only: false,
            recalculate: true,
            broadcast_indicator: false,
            broadcast_response: false,
            compact_response: true,
            number_responses: 3,
            target: Some(OWN),
        };
        let n = g.encode(&mut buf).unwrap();
        let later = now + Duration::from_secs(5);
        let Outcome::Location {
            location: Some(l),
            recalculate: true,
        } = handle(&mut c, CMD_GET_LOCATION_DATA, &buf[..n], SRC, later)
        else {
            panic!("no location");
        };
        assert_eq!(l.coordinate3, Some(30));
        assert_eq!(l.calculated.unwrap().age, 5);
        assert_eq!(tick(&mut c, later), None);
        // now + 15 s: the second response (ReportingPeriod after the
        // request) and the periodic notification (armed at now) are due.
        let t1 = later + Duration::from_secs(10);
        assert_eq!(
            tick(&mut c, t1),
            Some(Due::Response {
                compact: true,
                broadcast: false,
                requester: Some(SRC)
            })
        );
        assert_eq!(tick(&mut c, t1), Some(Due::Periodic));
        assert_eq!(tick(&mut c, t1), None);
        assert_eq!(tick(&mut c, t1 + Duration::from_secs(5)), None);
        let t2 = t1 + Duration::from_secs(10);
        assert!(matches!(tick(&mut c, t2), Some(Due::Response { .. })));
        assert_eq!(tick(&mut c, t2), Some(Due::Periodic));
        assert_eq!(tick(&mut c, t2), None);
        assert_eq!(state(&c).unwrap().pending_responses, 0);
        // A broadcast asking for absolute locations only is not answered.
        let g = GetLocationData {
            absolute_only: true,
            broadcast_indicator: true,
            target: None,
            number_responses: 1,
            ..g
        };
        let n = g.encode(&mut buf).unwrap();
        assert_eq!(
            handle(&mut c, CMD_GET_LOCATION_DATA, &buf[..n], SRC, now),
            Outcome::Silent
        );
        // Send Pings: NumberRSSIMeasurements pings, CalculationPeriod apart.
        let p = SendPings {
            target: OWN,
            number_rssi_measurements: 2,
            calculation_period: 200,
        };
        let n = p.encode(&mut buf).unwrap();
        c.set_u16(REPORTING_PERIOD.id, 0);
        schedule_report(&mut c, now);
        let t3 = Instant::from_millis(100_000);
        assert_eq!(
            handle(&mut c, CMD_SEND_PINGS, &buf[..n], SRC, t3),
            Outcome::Updated
        );
        assert_eq!(tick(&mut c, t3), Some(Due::Ping));
        assert_eq!(tick(&mut c, t3), None);
        assert_eq!(
            tick(&mut c, t3 + Duration::from_millis(200)),
            Some(Due::Ping)
        );
        assert_eq!(tick(&mut c, t3 + Duration::from_millis(400)), None);
        // RSSI Responses are collected and reported after CalculationPeriod.
        let info = NeighborInfo {
            neighbor: ExtendedAddress(2),
            x: 1,
            y: 2,
            z: 3,
            rssi: -60,
            measurements: 2,
        };
        let n = info.encode(&mut buf).unwrap();
        assert_eq!(
            handle(&mut c, CMD_RSSI_RESPONSE, &buf[..n], SRC, t3),
            Outcome::Collected
        );
        let n = NeighborInfo {
            neighbor: ExtendedAddress(2),
            rssi: -55,
            ..info
        }
        .encode(&mut buf)
        .unwrap();
        assert_eq!(
            handle(&mut c, CMD_RSSI_RESPONSE, &buf[..n], SRC, t3),
            Outcome::Collected
        );
        let Some(Due::Report(r)) = tick(&mut c, t3 + Duration::from_millis(200)) else {
            panic!("no report");
        };
        assert_eq!(r.measuring, OWN);
        assert_eq!(r.neighbors.len(), 1);
        assert_eq!(r.neighbors[0].rssi, -55);
    }
}
