//! Metering cluster (SE 1.4a Annex D.3): the mandatory server
//! attributes of the Reading Information, Meter Status and Formatting
//! sets plus the common Historical Consumption attributes, the
//! formatting helpers, and the Get Profile / Get Profile Response
//! commands. Mirroring, snapshots, sampling, supply control and the
//! notification scheme are not implemented.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::cluster::ClusterDef;
use panweave_zcl::types::DataType;

pub mod extended;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0702);

// Reading Information Set (Table D-11).
/// `CurrentSummationDelivered` (uint48, mandatory).
pub const CURRENT_SUMMATION_DELIVERED: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(6), Access::RO_REPORT);
/// `CurrentSummationReceived` (uint48).
pub const CURRENT_SUMMATION_RECEIVED: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(6), Access::RO_REPORT);
/// `CurrentMaxDemandDelivered` (uint48).
pub const CURRENT_MAX_DEMAND_DELIVERED: AttributeDef =
    AttributeDef::new(0x0002, DataType::Uint(6), Access::RO);
/// `CurrentMaxDemandReceived` (uint48).
pub const CURRENT_MAX_DEMAND_RECEIVED: AttributeDef =
    AttributeDef::new(0x0003, DataType::Uint(6), Access::RO);
/// `DFTSummation` (uint48).
pub const DFT_SUMMATION: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(6), Access::RO);
/// `DailyFreezeTime` (uint16, hhmm).
pub const DAILY_FREEZE_TIME: AttributeDef =
    AttributeDef::new(0x0005, DataType::Uint(2), Access::RO);
/// `PowerFactor` (int8).
pub const POWER_FACTOR: AttributeDef = AttributeDef::new(0x0006, DataType::Int(1), Access::RO);
/// `ReadingSnapshotTime` (UTC).
pub const READING_SNAPSHOT_TIME: AttributeDef =
    AttributeDef::new(0x0007, DataType::UtcTime, Access::RO);
/// `CurrentMaxDemandDeliveredTime` (UTC).
pub const CURRENT_MAX_DEMAND_DELIVERED_TIME: AttributeDef =
    AttributeDef::new(0x0008, DataType::UtcTime, Access::RO);

// Meter Status (Table D-24).
/// `Status` (map8, mandatory).
pub const STATUS: AttributeDef = AttributeDef::new(0x0200, DataType::Bitmap(1), Access::RO);
/// `RemainingBatteryLife` (uint8, percent).
pub const REMAINING_BATTERY_LIFE: AttributeDef =
    AttributeDef::new(0x0201, DataType::Uint(1), Access::RO);
/// `HoursInOperation` (uint24).
pub const HOURS_IN_OPERATION: AttributeDef =
    AttributeDef::new(0x0202, DataType::Uint(3), Access::RO);
/// `HoursInFault` (uint24).
pub const HOURS_IN_FAULT: AttributeDef = AttributeDef::new(0x0203, DataType::Uint(3), Access::RO);
/// `ExtendedStatus` (map64).
pub const EXTENDED_STATUS: AttributeDef =
    AttributeDef::new(0x0204, DataType::Bitmap(8), Access::RO);

// Formatting (Table D-25).
/// `UnitofMeasure` (enum8, mandatory).
pub const UNIT_OF_MEASURE: AttributeDef = AttributeDef::new(0x0300, DataType::Enum8, Access::RO);
/// `Multiplier` (uint24).
pub const MULTIPLIER: AttributeDef = AttributeDef::new(0x0301, DataType::Uint(3), Access::RO);
/// `Divisor` (uint24).
pub const DIVISOR: AttributeDef = AttributeDef::new(0x0302, DataType::Uint(3), Access::RO);
/// `SummationFormatting` (map8, mandatory).
pub const SUMMATION_FORMATTING: AttributeDef =
    AttributeDef::new(0x0303, DataType::Bitmap(1), Access::RO);
/// `DemandFormatting` (map8).
pub const DEMAND_FORMATTING: AttributeDef =
    AttributeDef::new(0x0304, DataType::Bitmap(1), Access::RO);
/// `HistoricalConsumptionFormatting` (map8).
pub const HISTORICAL_CONSUMPTION_FORMATTING: AttributeDef =
    AttributeDef::new(0x0305, DataType::Bitmap(1), Access::RO);
/// `MeteringDeviceType` (map8, mandatory).
pub const METERING_DEVICE_TYPE: AttributeDef =
    AttributeDef::new(0x0306, DataType::Bitmap(1), Access::RO);
/// `SiteID` (octet string, up to 32 characters).
pub const SITE_ID: AttributeDef = AttributeDef::new(0x0307, DataType::OctetString, Access::RO);
/// `MeterSerialNumber` (octet string, up to 24 characters).
pub const METER_SERIAL_NUMBER: AttributeDef =
    AttributeDef::new(0x0308, DataType::OctetString, Access::RO);

// Historical Consumption (Table D-29).
/// `InstantaneousDemand` (int24).
pub const INSTANTANEOUS_DEMAND: AttributeDef =
    AttributeDef::new(0x0400, DataType::Int(3), Access::RO_REPORT);
/// `CurrentDayConsumptionDelivered` (uint24).
pub const CURRENT_DAY_CONSUMPTION_DELIVERED: AttributeDef =
    AttributeDef::new(0x0401, DataType::Uint(3), Access::RO);
/// `CurrentDayConsumptionReceived` (uint24).
pub const CURRENT_DAY_CONSUMPTION_RECEIVED: AttributeDef =
    AttributeDef::new(0x0402, DataType::Uint(3), Access::RO);
/// `PreviousDayConsumptionDelivered` (uint24).
pub const PREVIOUS_DAY_CONSUMPTION_DELIVERED: AttributeDef =
    AttributeDef::new(0x0403, DataType::Uint(3), Access::RO);
/// `PreviousDayConsumptionReceived` (uint24).
pub const PREVIOUS_DAY_CONSUMPTION_RECEIVED: AttributeDef =
    AttributeDef::new(0x0404, DataType::Uint(3), Access::RO);

/// The attributes every Metering server carries (Tables D-11, D-24,
/// D-25 mandatory rows).
pub const MANDATORY: &[AttributeDef] = &[
    CURRENT_SUMMATION_DELIVERED,
    STATUS,
    UNIT_OF_MEASURE,
    SUMMATION_FORMATTING,
    METERING_DEVICE_TYPE,
];

/// Client → server: Get Profile.
pub const CMD_GET_PROFILE: CommandId = CommandId(0x00);
/// Server → client: Get Profile Response.
pub const CMD_GET_PROFILE_RESPONSE: CommandId = CommandId(0x00);

/// Server cluster definition (Get Profile only).
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_GET_PROFILE],
    generated: &[CMD_GET_PROFILE_RESPONSE],
};

/// Client cluster definition (Get Profile only).
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_GET_PROFILE_RESPONSE],
    generated: &[CMD_GET_PROFILE],
};

/// Server cluster definition with every command of Tables D-47 / D-63
/// (see [`extended`]).
pub const FULL_SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: extended::RECEIVED,
    generated: extended::GENERATED,
};

/// Client cluster definition with every command.
pub const FULL_CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: extended::GENERATED,
    generated: extended::RECEIVED,
};

/// `UnitofMeasure` values (Table D-26); 0x80 | value is the BCD form.
pub mod unit_of_measure {
    /// kWh and kW.
    pub const KWH: u8 = 0x00;
    /// Cubic meters and m³/h.
    pub const CUBIC_METER: u8 = 0x01;
    /// Cubic feet and ft³/h.
    pub const CUBIC_FEET: u8 = 0x02;
    /// Centum cubic feet.
    pub const CCF: u8 = 0x03;
    /// US gallons.
    pub const US_GALLON: u8 = 0x04;
    /// Imperial gallons.
    pub const IMPERIAL_GALLON: u8 = 0x05;
    /// BTU and BTU/h.
    pub const BTU: u8 = 0x06;
    /// Liters and l/h.
    pub const LITER: u8 = 0x07;
    /// kPa gauge.
    pub const KPA_GAUGE: u8 = 0x08;
    /// kPa absolute.
    pub const KPA_ABSOLUTE: u8 = 0x09;
    /// mcf (1000 cubic feet).
    pub const MCF: u8 = 0x0A;
    /// Unitless.
    pub const UNITLESS: u8 = 0x0B;
    /// MJ and MJ/s.
    pub const MEGAJOULE: u8 = 0x0C;
    /// kVar and kVarh.
    pub const KVAR: u8 = 0x0D;
    /// BCD encoding flag.
    pub const BCD: u8 = 0x80;
}

/// `MeteringDeviceType` values (Table D-27); 127 + value is the mirrored
/// form.
pub mod device_type {
    /// Electric metering.
    pub const ELECTRIC: u8 = 0;
    /// Gas metering.
    pub const GAS: u8 = 1;
    /// Water metering.
    pub const WATER: u8 = 2;
    /// Pressure metering.
    pub const PRESSURE: u8 = 4;
    /// Heat metering.
    pub const HEAT: u8 = 5;
    /// Cooling metering.
    pub const COOLING: u8 = 6;
    /// End use measurement device (EV charging).
    pub const EUMD: u8 = 7;
    /// PV generation metering.
    pub const PV_GENERATION: u8 = 8;
    /// First mirrored value (Mirrored Electric Metering).
    pub const MIRRORED_BASE: u8 = 127;

    /// The mirrored form of a device type.
    pub const fn mirrored(t: u8) -> u8 {
        t.saturating_add(MIRRORED_BASE)
    }
}

/// `Status` bits (Table D-24 / D.3.2.2.3.1, electric).
pub mod status {
    /// Check meter.
    pub const CHECK_METER: u8 = 0x01;
    /// Low battery.
    pub const LOW_BATTERY: u8 = 0x02;
    /// Tamper detect.
    pub const TAMPER_DETECT: u8 = 0x04;
    /// Power failure.
    pub const POWER_FAILURE: u8 = 0x08;
    /// Power quality.
    pub const POWER_QUALITY: u8 = 0x10;
    /// Leak detect.
    pub const LEAK_DETECT: u8 = 0x20;
    /// Service disconnect open.
    pub const SERVICE_DISCONNECT_OPEN: u8 = 0x40;
}

/// A formatting octet (D.3.2.2.4.4): digits right and left of the
/// decimal point and leading-zero suppression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Formatting {
    /// Digits right of the decimal point (0–7).
    pub right: u8,
    /// Digits left of the decimal point (0–15).
    pub left: u8,
    /// Suppress leading zeros.
    pub suppress_leading_zeros: bool,
}

impl Formatting {
    /// Decodes the octet.
    pub const fn from_raw(v: u8) -> Self {
        Formatting {
            right: v & 0x07,
            left: (v >> 3) & 0x0F,
            suppress_leading_zeros: v & 0x80 != 0,
        }
    }

    /// Encodes the octet.
    pub const fn raw(self) -> u8 {
        (self.right & 0x07)
            | ((self.left & 0x0F) << 3)
            | if self.suppress_leading_zeros { 0x80 } else { 0 }
    }

    /// Splits a raw summation into its integer and fractional parts in
    /// the units of measure, honouring `right`.
    pub const fn split(self, raw: u64) -> (u64, u64) {
        let mut scale = 1u64;
        let mut i = 0;
        while i < self.right {
            scale = scale.saturating_mul(10);
            i += 1;
        }
        (raw / scale, raw % scale)
    }
}

/// Converts a raw reading to the unit of measure with the `Multiplier`
/// and `Divisor` attributes (both 1 when unsupported), as a fixed-point
/// value scaled by `scale` (e.g. 1000 for three decimals).
pub const fn scaled(raw: u64, multiplier: u32, divisor: u32, scale: u32) -> u64 {
    let m = if multiplier == 0 {
        1
    } else {
        multiplier as u64
    };
    let d = if divisor == 0 { 1 } else { divisor as u64 };
    raw.saturating_mul(m).saturating_mul(scale as u64) / d
}

/// Interval Channel values (Table D-64).
pub mod interval_channel {
    /// Consumption delivered.
    pub const CONSUMPTION_DELIVERED: u8 = 0;
    /// Consumption received.
    pub const CONSUMPTION_RECEIVED: u8 = 1;
    /// Reactive consumption delivered.
    pub const REACTIVE_CONSUMPTION_DELIVERED: u8 = 2;
    /// Reactive consumption received.
    pub const REACTIVE_CONSUMPTION_RECEIVED: u8 = 3;
}

/// ProfileIntervalPeriod values (Table D-49).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IntervalPeriod {
    /// Daily.
    Daily,
    /// 60 minutes.
    Minutes60,
    /// 30 minutes.
    Minutes30,
    /// 15 minutes.
    Minutes15,
    /// 10 minutes.
    Minutes10,
    /// 7.5 minutes.
    Minutes7_5,
    /// 5 minutes.
    Minutes5,
    /// 2.5 minutes.
    Minutes2_5,
    /// 1 minute.
    Minute1,
}

impl IntervalPeriod {
    /// Raw value.
    pub const fn raw(self) -> u8 {
        self as u8
    }

    /// From the raw value.
    pub const fn from_raw(v: u8) -> Option<Self> {
        Some(match v {
            0 => IntervalPeriod::Daily,
            1 => IntervalPeriod::Minutes60,
            2 => IntervalPeriod::Minutes30,
            3 => IntervalPeriod::Minutes15,
            4 => IntervalPeriod::Minutes10,
            5 => IntervalPeriod::Minutes7_5,
            6 => IntervalPeriod::Minutes5,
            7 => IntervalPeriod::Minutes2_5,
            8 => IntervalPeriod::Minute1,
            _ => return None,
        })
    }

    /// Length in seconds.
    pub const fn seconds(self) -> u32 {
        match self {
            IntervalPeriod::Daily => 86_400,
            IntervalPeriod::Minutes60 => 3600,
            IntervalPeriod::Minutes30 => 1800,
            IntervalPeriod::Minutes15 => 900,
            IntervalPeriod::Minutes10 => 600,
            IntervalPeriod::Minutes7_5 => 450,
            IntervalPeriod::Minutes5 => 300,
            IntervalPeriod::Minutes2_5 => 150,
            IntervalPeriod::Minute1 => 60,
        }
    }
}

/// Get Profile Response status (Table D-48).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ProfileStatus {
    /// Success.
    Success,
    /// Undefined interval channel requested.
    UndefinedChannel,
    /// Interval channel not supported.
    ChannelNotSupported,
    /// Invalid end time.
    InvalidEndTime,
    /// More periods requested than can be returned.
    TooManyPeriods,
    /// No intervals available for the requested time.
    NoIntervals,
    /// Reserved value.
    Reserved(u8),
}

impl ProfileStatus {
    /// Raw value.
    pub const fn raw(self) -> u8 {
        match self {
            ProfileStatus::Success => 0,
            ProfileStatus::UndefinedChannel => 1,
            ProfileStatus::ChannelNotSupported => 2,
            ProfileStatus::InvalidEndTime => 3,
            ProfileStatus::TooManyPeriods => 4,
            ProfileStatus::NoIntervals => 5,
            ProfileStatus::Reserved(v) => v,
        }
    }

    /// From the raw value.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0 => ProfileStatus::Success,
            1 => ProfileStatus::UndefinedChannel,
            2 => ProfileStatus::ChannelNotSupported,
            3 => ProfileStatus::InvalidEndTime,
            4 => ProfileStatus::TooManyPeriods,
            5 => ProfileStatus::NoIntervals,
            v => ProfileStatus::Reserved(v),
        }
    }
}

/// An invalid interval value.
pub const INTERVAL_INVALID: u32 = 0xFF_FFFF;

/// Get Profile payload (Figure D-38).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetProfile {
    /// Interval channel.
    pub channel: u8,
    /// End time of the most recent interval wanted (0 = the latest).
    pub end_time: u32,
    /// Number of intervals.
    pub number_of_periods: u8,
}

impl GetProfile {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetProfile {
            channel: r.u8()?,
            end_time: r.u32_le()?,
            number_of_periods: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.channel)?;
        w.u32_le(self.end_time)?;
        w.u8(self.number_of_periods)
    }
}

/// Get Profile Response payload (Figure D-12); the intervals are the
/// raw 24-bit values, most recent first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GetProfileResponse<'a> {
    /// End time of the most recent interval returned.
    pub end_time: u32,
    /// Status.
    pub status: ProfileStatus,
    /// Interval period.
    pub interval_period: u8,
    /// Encoded intervals (3 octets each, little-endian).
    pub intervals: &'a [u8],
}

impl<'a> GetProfileResponse<'a> {
    /// Parses the payload; the NumberOfPeriodsDelivered field must
    /// match the intervals present.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let end_time = r.u32_le()?;
        let status = ProfileStatus::from_raw(r.u8()?);
        let interval_period = r.u8()?;
        let n = r.u8()?;
        let intervals = r.take_rest();
        if intervals.len() != usize::from(n) * 3 {
            return Err(CodecError::InvalidField {
                field: "NumberOfPeriodsDelivered",
                value: u32::from(n),
            });
        }
        Ok(GetProfileResponse {
            end_time,
            status,
            interval_period,
            intervals,
        })
    }

    /// Encodes a response from `intervals` (most recent first).
    pub fn encode(
        w: &mut Writer<'_>,
        end_time: u32,
        status: ProfileStatus,
        interval_period: u8,
        intervals: &[u32],
    ) -> Result<(), CodecError> {
        let n = u8::try_from(intervals.len()).map_err(|_| CodecError::InvalidField {
            field: "NumberOfPeriodsDelivered",
            value: 0,
        })?;
        w.u32_le(end_time)?;
        w.u8(status.raw())?;
        w.u8(interval_period)?;
        w.u8(n)?;
        for v in intervals {
            let b = v.to_le_bytes();
            w.bytes(&b[..3])?;
        }
        Ok(())
    }

    /// Number of intervals.
    pub const fn len(&self) -> usize {
        self.intervals.len() / 3
    }

    /// Whether no intervals were returned.
    pub const fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// The intervals, most recent first.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.intervals
            .chunks_exact(3)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], 0]))
    }
}

/// Largest number of intervals a Get Profile Response carries (the
/// unfragmented budget of Table D-46: 4 + 3 + 3 × 24).
pub const MAX_PERIODS_DELIVERED: usize = 24;

/// Server-side interval log of one channel (D.3.2.3.1.1, D.3.3.3.1.1):
/// the last `N` completed intervals of `channel`, newest first, each the
/// consumption change over one `period`.
#[derive(Clone, Debug)]
pub struct ProfileLog<const N: usize> {
    /// Interval channel (Table D-64).
    pub channel: u8,
    /// `ProfileIntervalPeriod`.
    pub period: IntervalPeriod,
    /// `MaxNumberOfPeriodsDelivered` (at most [`MAX_PERIODS_DELIVERED`]).
    pub max_periods: u8,
    /// End time of the newest interval (0: none yet).
    end_time: u32,
    /// Intervals, newest first (`INTERVAL_INVALID` for a gap).
    intervals: Vec<u32, N>,
}

impl<const N: usize> ProfileLog<N> {
    /// An empty log for `channel` with `period` intervals.
    pub const fn new(channel: u8, period: IntervalPeriod, max_periods: u8) -> Self {
        ProfileLog {
            channel,
            period,
            max_periods,
            end_time: 0,
            intervals: Vec::new(),
        }
    }

    /// Records the interval that ended at `end_time` (gaps since the
    /// previous one are filled with `INTERVAL_INVALID`); the oldest
    /// intervals fall out when the log is full.
    pub fn record(&mut self, value: u32, end_time: u32) {
        let period = self.period.seconds();
        if self.end_time != 0 && end_time > self.end_time {
            let mut gap = (end_time - self.end_time) / period;
            while gap > 1 {
                self.push_front(INTERVAL_INVALID);
                gap -= 1;
            }
        }
        self.push_front(value & INTERVAL_INVALID);
        self.end_time = end_time;
    }

    fn push_front(&mut self, v: u32) {
        if self.intervals.is_full() {
            self.intervals.pop();
        }
        let _ = self.intervals.insert(0, v);
    }

    /// The intervals held, newest first.
    pub fn intervals(&self) -> &[u32] {
        &self.intervals
    }

    /// End time of the newest interval.
    pub const fn end_time(&self) -> u32 {
        self.end_time
    }

    /// Answers a Get Profile for this channel: the response's end time,
    /// status and intervals (newest first). A request for another
    /// channel is refused with UNDEFINED_INTERVAL_CHANNEL (channels
    /// beyond Table D-64) or INTERVAL_CHANNEL_NOT_SUPPORTED; an end time
    /// older than the oldest interval is INVALID_END_TIME; more periods
    /// than `max_periods` are capped and flagged.
    pub fn get(&self, req: &GetProfile) -> (u32, ProfileStatus, Vec<u32, MAX_PERIODS_DELIVERED>) {
        let mut out = Vec::new();
        if req.channel != self.channel {
            let status = if req.channel > 3 {
                ProfileStatus::UndefinedChannel
            } else {
                ProfileStatus::ChannelNotSupported
            };
            return (req.end_time, status, out);
        }
        if self.intervals.is_empty() {
            return (req.end_time, ProfileStatus::NoIntervals, out);
        }
        let period = self.period.seconds();
        // The block ends at the newest interval ending at or before the
        // requested end time.
        let skip = if req.end_time == 0 || req.end_time >= self.end_time {
            0
        } else {
            let behind = (self.end_time - req.end_time).div_ceil(period);
            usize::try_from(behind).unwrap_or(usize::MAX)
        };
        if skip >= self.intervals.len() {
            return (req.end_time, ProfileStatus::InvalidEndTime, out);
        }
        let end = self
            .end_time
            .saturating_sub(u32::try_from(skip).unwrap_or(0).saturating_mul(period));
        let max = usize::from(self.max_periods).min(MAX_PERIODS_DELIVERED);
        let wanted = usize::from(req.number_of_periods);
        let count = wanted.min(max).min(self.intervals.len() - skip);
        for v in self.intervals.iter().skip(skip).take(count) {
            let _ = out.push(*v);
        }
        let status = if wanted > max {
            ProfileStatus::TooManyPeriods
        } else if out.is_empty() {
            ProfileStatus::NoIntervals
        } else {
            ProfileStatus::Success
        };
        (end, status, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_log_answers_get_profile() {
        let mut log: ProfileLog<8> = ProfileLog::new(0, IntervalPeriod::Minutes30, 4);
        let (_, status, _) = log.get(&GetProfile {
            channel: 0,
            end_time: 0,
            number_of_periods: 2,
        });
        assert_eq!(status, ProfileStatus::NoIntervals);
        // Five intervals ending at 1800, 3600, (gap at 5400), 7200, 9000.
        log.record(10, 1800);
        log.record(11, 3600);
        log.record(13, 7200);
        log.record(14, 9000);
        assert_eq!(log.intervals(), &[14, 13, INTERVAL_INVALID, 11, 10]);
        // The most recent block, capped at the maximum and flagged.
        let (end, status, iv) = log.get(&GetProfile {
            channel: 0,
            end_time: 0,
            number_of_periods: 6,
        });
        assert_eq!(end, 9000);
        assert_eq!(status, ProfileStatus::TooManyPeriods);
        assert_eq!(iv.as_slice(), &[14, 13, INTERVAL_INVALID, 11]);
        // An earlier block by end time.
        let (end, status, iv) = log.get(&GetProfile {
            channel: 0,
            end_time: 3700,
            number_of_periods: 2,
        });
        assert_eq!((end, status), (3600, ProfileStatus::Success));
        assert_eq!(iv.as_slice(), &[11, 10]);
        let (_, status, iv) = log.get(&GetProfile {
            channel: 0,
            end_time: 1000,
            number_of_periods: 2,
        });
        assert_eq!(status, ProfileStatus::InvalidEndTime);
        assert!(iv.is_empty());
        // Other channels.
        assert_eq!(
            log.get(&GetProfile {
                channel: 1,
                end_time: 0,
                number_of_periods: 1
            })
            .1,
            ProfileStatus::ChannelNotSupported
        );
        assert_eq!(
            log.get(&GetProfile {
                channel: 9,
                end_time: 0,
                number_of_periods: 1
            })
            .1,
            ProfileStatus::UndefinedChannel
        );
        // A full log drops the oldest.
        for i in 0..8 {
            log.record(20 + i, 10_800 + i * 1800);
        }
        assert_eq!(log.intervals().len(), 8);
        assert_eq!(log.intervals()[0], 27);
    }

    #[test]
    fn formatting_and_profile() {
        let f = Formatting::from_raw(0x83 | (5 << 3));
        assert_eq!(
            f,
            Formatting {
                right: 3,
                left: 5,
                suppress_leading_zeros: true
            }
        );
        assert_eq!(f.raw(), 0xAB);
        assert_eq!(f.split(1_234_567), (1234, 567));
        assert_eq!(scaled(1500, 1, 1000, 1000), 1500);
        assert_eq!(scaled(7, 3, 2, 10), 105);
        assert_eq!(scaled(7, 0, 0, 1), 7);
        assert_eq!(IntervalPeriod::from_raw(3), Some(IntervalPeriod::Minutes15));
        assert_eq!(IntervalPeriod::Minutes7_5.seconds(), 450);
        assert_eq!(IntervalPeriod::from_raw(9), None);
        assert_eq!(device_type::mirrored(device_type::GAS), 128);

        let g = GetProfile {
            channel: interval_channel::CONSUMPTION_DELIVERED,
            end_time: 0,
            number_of_periods: 3,
        };
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        assert_eq!(GetProfile::parse(&buf[..6]).unwrap(), g);
        let mut w = Writer::new(&mut buf);
        GetProfileResponse::encode(
            &mut w,
            3600,
            ProfileStatus::Success,
            IntervalPeriod::Minutes60.raw(),
            &[0x0001_0203, INTERVAL_INVALID, 7],
        )
        .unwrap();
        let n = w.position();
        assert_eq!(n, 7 + 9);
        let r = GetProfileResponse::parse(&buf[..n]).unwrap();
        assert_eq!(r.end_time, 3600);
        assert_eq!(r.status, ProfileStatus::Success);
        assert_eq!(r.len(), 3);
        let v: Vec<u32, 4> = r.iter().collect();
        assert_eq!(v.as_slice(), &[0x0001_0203, INTERVAL_INVALID, 7]);
        // A count that disagrees with the payload is rejected.
        buf[6] = 2;
        assert!(GetProfileResponse::parse(&buf[..n]).is_err());
    }
}
