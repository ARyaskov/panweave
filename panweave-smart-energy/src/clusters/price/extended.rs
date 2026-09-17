//! The optional Price cluster commands beyond Publish Price (SE 1.4a
//! D.4.2.3.5–D.4.2.3.18, D.4.2.4.2–D.4.2.4.15): block periods,
//! conversion factor, calorific value, tariff information with its
//! price matrix, block thresholds and tier labels, CO2 value, billing
//! periods, consolidated bills, critical peak pricing events, credit
//! payments, currency conversion and tariff cancellation — the codecs,
//! a generic two-instance [`Scheduled`] store with the cancellation
//! (start time 0xFFFFFFFF) and newer-issuer-event rules, and a client
//! [`TariffStore`] assembling a tariff from its fragmented parts and
//! discarding it on Cancel Tariff.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::CommandId;

/// Client → server: GetBlockPeriod(s).
pub const CMD_GET_BLOCK_PERIODS: CommandId = CommandId(0x03);
/// Client → server: GetConversionFactor.
pub const CMD_GET_CONVERSION_FACTOR: CommandId = CommandId(0x04);
/// Client → server: GetCalorificValue.
pub const CMD_GET_CALORIFIC_VALUE: CommandId = CommandId(0x05);
/// Client → server: GetTariffInformation.
pub const CMD_GET_TARIFF_INFORMATION: CommandId = CommandId(0x06);
/// Client → server: GetPriceMatrix.
pub const CMD_GET_PRICE_MATRIX: CommandId = CommandId(0x07);
/// Client → server: GetBlockThresholds.
pub const CMD_GET_BLOCK_THRESHOLDS: CommandId = CommandId(0x08);
/// Client → server: GetCO2Value.
pub const CMD_GET_CO2_VALUE: CommandId = CommandId(0x09);
/// Client → server: GetTierLabels.
pub const CMD_GET_TIER_LABELS: CommandId = CommandId(0x0A);
/// Client → server: GetBillingPeriod.
pub const CMD_GET_BILLING_PERIOD: CommandId = CommandId(0x0B);
/// Client → server: GetConsolidatedBill.
pub const CMD_GET_CONSOLIDATED_BILL: CommandId = CommandId(0x0C);
/// Client → server: CPPEventResponse (provisional).
pub const CMD_CPP_EVENT_RESPONSE: CommandId = CommandId(0x0D);
/// Client → server: GetCreditPayment.
pub const CMD_GET_CREDIT_PAYMENT: CommandId = CommandId(0x0E);
/// Client → server: GetCurrencyConversion (no payload).
pub const CMD_GET_CURRENCY_CONVERSION: CommandId = CommandId(0x0F);
/// Client → server: GetTariffCancellation (no payload).
pub const CMD_GET_TARIFF_CANCELLATION: CommandId = CommandId(0x10);
/// Server → client: PublishBlockPeriod.
pub const CMD_PUBLISH_BLOCK_PERIOD: CommandId = CommandId(0x01);
/// Server → client: PublishConversionFactor.
pub const CMD_PUBLISH_CONVERSION_FACTOR: CommandId = CommandId(0x02);
/// Server → client: PublishCalorificValue.
pub const CMD_PUBLISH_CALORIFIC_VALUE: CommandId = CommandId(0x03);
/// Server → client: PublishTariffInformation.
pub const CMD_PUBLISH_TARIFF_INFORMATION: CommandId = CommandId(0x04);
/// Server → client: PublishPriceMatrix.
pub const CMD_PUBLISH_PRICE_MATRIX: CommandId = CommandId(0x05);
/// Server → client: PublishBlockThresholds.
pub const CMD_PUBLISH_BLOCK_THRESHOLDS: CommandId = CommandId(0x06);
/// Server → client: PublishCO2Value.
pub const CMD_PUBLISH_CO2_VALUE: CommandId = CommandId(0x07);
/// Server → client: PublishTierLabels.
pub const CMD_PUBLISH_TIER_LABELS: CommandId = CommandId(0x08);
/// Server → client: PublishBillingPeriod.
pub const CMD_PUBLISH_BILLING_PERIOD: CommandId = CommandId(0x09);
/// Server → client: PublishConsolidatedBill.
pub const CMD_PUBLISH_CONSOLIDATED_BILL: CommandId = CommandId(0x0A);
/// Server → client: PublishCPPEvent (provisional).
pub const CMD_PUBLISH_CPP_EVENT: CommandId = CommandId(0x0B);
/// Server → client: PublishCreditPayment.
pub const CMD_PUBLISH_CREDIT_PAYMENT: CommandId = CommandId(0x0C);
/// Server → client: PublishCurrencyConversion.
pub const CMD_PUBLISH_CURRENCY_CONVERSION: CommandId = CommandId(0x0D);
/// Server → client: CancelTariff.
pub const CMD_CANCEL_TARIFF: CommandId = CommandId(0x0E);

/// Every client → server command of the cluster, for a cluster
/// definition.
pub const RECEIVED: &[CommandId] = &[
    super::CMD_GET_CURRENT_PRICE,
    super::CMD_GET_SCHEDULED_PRICES,
    super::CMD_PRICE_ACKNOWLEDGEMENT,
    CMD_GET_BLOCK_PERIODS,
    CMD_GET_CONVERSION_FACTOR,
    CMD_GET_CALORIFIC_VALUE,
    CMD_GET_TARIFF_INFORMATION,
    CMD_GET_PRICE_MATRIX,
    CMD_GET_BLOCK_THRESHOLDS,
    CMD_GET_CO2_VALUE,
    CMD_GET_TIER_LABELS,
    CMD_GET_BILLING_PERIOD,
    CMD_GET_CONSOLIDATED_BILL,
    CMD_CPP_EVENT_RESPONSE,
    CMD_GET_CREDIT_PAYMENT,
    CMD_GET_CURRENCY_CONVERSION,
    CMD_GET_TARIFF_CANCELLATION,
];

/// Every server → client command of the cluster.
pub const GENERATED: &[CommandId] = &[
    super::CMD_PUBLISH_PRICE,
    CMD_PUBLISH_BLOCK_PERIOD,
    CMD_PUBLISH_CONVERSION_FACTOR,
    CMD_PUBLISH_CALORIFIC_VALUE,
    CMD_PUBLISH_TARIFF_INFORMATION,
    CMD_PUBLISH_PRICE_MATRIX,
    CMD_PUBLISH_BLOCK_THRESHOLDS,
    CMD_PUBLISH_CO2_VALUE,
    CMD_PUBLISH_TIER_LABELS,
    CMD_PUBLISH_BILLING_PERIOD,
    CMD_PUBLISH_CONSOLIDATED_BILL,
    CMD_PUBLISH_CPP_EVENT,
    CMD_PUBLISH_CREDIT_PAYMENT,
    CMD_PUBLISH_CURRENCY_CONVERSION,
    CMD_CANCEL_TARIFF,
];

/// Start time meaning "now".
pub const START_NOW: u32 = 0;
/// Start time cancelling the pending command of the same provider and
/// issuer event.
pub const START_CANCEL: u32 = 0xffff_ffff;
/// Issuer event id filter "not specified".
pub const ANY_EVENT: u32 = 0xffff_ffff;
/// Tariff type "not specified" in a request.
pub const ANY_TARIFF_TYPE: u8 = 0xff;
/// Block period duration "until changed".
pub const DURATION_UNTIL_CHANGED_24: u32 = 0x00ff_ffff;
/// An unused 48-bit block threshold.
pub const THRESHOLD_UNUSED: u64 = 0xffff_ffff_ffff;
/// An unused 32-bit value (standing charge, CO2 value).
pub const VALUE_UNUSED: u32 = 0xffff_ffff;
/// Longest tariff label.
pub const MAX_TARIFF_LABEL: usize = 24;
/// Longest tier label.
pub const MAX_TIER_LABEL: usize = 12;
/// Longest credit payment reference.
pub const MAX_PAYMENT_REF: usize = 20;
/// Price matrix entries carried by one command.
pub const MAX_MATRIX_ENTRIES: usize = 16;
/// Price matrix entries a client keeps per tariff (15 tiers × up to
/// 16 blocks is the specification maximum; this store keeps 48).
pub const MAX_MATRIX: usize = 48;
/// Block thresholds per tier.
pub const MAX_THRESHOLDS: usize = 15;
/// Tier sets of thresholds carried by one command.
pub const MAX_THRESHOLD_SETS: usize = 4;
/// Tier labels per tariff.
pub const MAX_TIER_LABELS: usize = 16;

/// Tariff type (Table D-108, low nibble).
pub mod tariff_type {
    /// Delivered.
    pub const DELIVERED: u8 = 0x0;
    /// Received.
    pub const RECEIVED: u8 = 0x1;
    /// Delivered and received.
    pub const DELIVERED_AND_RECEIVED: u8 = 0x2;

    /// The tariff type nibble of a Tariff Type / Charging Scheme field.
    pub const fn of(field: u8) -> u8 {
        field & 0x0f
    }
}

/// Charging scheme (Table D-109, high nibble of the tariff type field).
pub mod charging_scheme {
    /// TOU tariff.
    pub const TOU: u8 = 0x0;
    /// Block tariff.
    pub const BLOCK: u8 = 0x1;
    /// Block / TOU with common thresholds.
    pub const BLOCK_TOU_COMMON: u8 = 0x2;
    /// Block / TOU with thresholds per tier.
    pub const BLOCK_TOU_PER_TIER: u8 = 0x3;

    /// The scheme nibble of a Tariff Type / Charging Scheme field.
    pub const fn of(field: u8) -> u8 {
        field >> 4
    }

    /// A Tariff Type / Charging Scheme field.
    pub const fn field(tariff_type: u8, scheme: u8) -> u8 {
        (scheme << 4) | (tariff_type & 0x0f)
    }
}

/// Duration timebase (Table D-105, low nibble) and control (Table
/// D-106, high nibble) of a duration type field.
pub mod duration_type {
    /// Minutes.
    pub const MINUTES: u8 = 0x0;
    /// Days.
    pub const DAYS: u8 = 0x1;
    /// Weeks.
    pub const WEEKS: u8 = 0x2;
    /// Months.
    pub const MONTHS: u8 = 0x3;
    /// Control: from the start of the timebase.
    pub const START_OF_TIMEBASE: u8 = 0x0;
    /// Control: from the end of the timebase.
    pub const END_OF_TIMEBASE: u8 = 0x1;
    /// Control: not specified (minutes).
    pub const NOT_SPECIFIED: u8 = 0x2;

    /// A duration type field.
    pub const fn field(timebase: u8, control: u8) -> u8 {
        (control << 4) | (timebase & 0x0f)
    }

    /// The timebase nibble.
    pub const fn timebase(field: u8) -> u8 {
        field & 0x0f
    }

    /// The control nibble.
    pub const fn control(field: u8) -> u8 {
        field >> 4
    }
}

/// Block Period Control bits (Table D-104).
pub mod block_period_control {
    /// Price Acknowledgement required.
    pub const ACKNOWLEDGEMENT_REQUIRED: u8 = 0x01;
    /// Repeating block.
    pub const REPEATING: u8 = 0x02;
}

/// Tariff resolution period (Table D-107).
pub mod resolution_period {
    /// Not defined.
    pub const NOT_DEFINED: u8 = 0x00;
    /// Block period.
    pub const BLOCK_PERIOD: u8 = 0x01;
    /// One day.
    pub const ONE_DAY: u8 = 0x02;
}

/// CPP price tiers (Table D-112).
pub mod cpp_tier {
    /// CPP1.
    pub const CPP1: u8 = 0;
    /// CPP2.
    pub const CPP2: u8 = 1;
}

/// CPP authorisation (Table D-113).
pub mod cpp_auth {
    /// Pending.
    pub const PENDING: u8 = 0;
    /// Accepted.
    pub const ACCEPTED: u8 = 1;
    /// Rejected.
    pub const REJECTED: u8 = 2;
    /// Forced.
    pub const FORCED: u8 = 3;
}

/// Currency change control flags (Table D-114).
pub mod currency_change {
    /// Clear billing information.
    pub const CLEAR_BILLING: u32 = 1 << 0;
    /// Convert billing information to the new currency.
    pub const CONVERT_BILLING: u32 = 1 << 1;
    /// Clear old consumption data.
    pub const CLEAR_CONSUMPTION: u32 = 1 << 2;
    /// Convert old consumption data to the new currency.
    pub const CONVERT_CONSUMPTION: u32 = 1 << 3;
}

fn read_octstr<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let n = r.u8()?;
    r.bytes(usize::from(n))
}

fn write_octstr(w: &mut Writer<'_>, s: &[u8]) -> Result<(), CodecError> {
    w.u8(
        u8::try_from(s.len()).map_err(|_| CodecError::Unrepresentable {
            field: "octet string",
        })?,
    )?;
    w.bytes(s)
}

fn read_u48(r: &mut Reader<'_>) -> Result<u64, CodecError> {
    let lo = u64::from(r.u32_le()?);
    let hi = u64::from(r.u16_le()?);
    Ok(lo | (hi << 32))
}

fn write_u48(w: &mut Writer<'_>, v: u64) -> Result<(), CodecError> {
    w.u32_le(u32::try_from(v & 0xffff_ffff).unwrap_or(u32::MAX))?;
    w.u16_le(u16::try_from((v >> 32) & 0xffff).unwrap_or(u16::MAX))
}

fn octstr<const N: usize>(bytes: &[u8], field: &'static str) -> Result<Vec<u8, N>, CodecError> {
    Vec::from_slice(bytes).map_err(|_| CodecError::Unrepresentable { field })
}

// ----- Requests -----

/// GetBlockPeriod(s) (D.4.2.3.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetBlockPeriods {
    /// Minimum end time of the periods wanted (0: now).
    pub start_time: u32,
    /// Periods wanted (0: all).
    pub count: u8,
    /// Tariff type; absent means Delivered.
    pub tariff_type: Option<u8>,
}

impl GetBlockPeriods {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetBlockPeriods {
            start_time: r.u32_le()?,
            count: r.u8()?,
            tariff_type: if r.is_empty() { None } else { Some(r.u8()?) },
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.start_time)?;
        w.u8(self.count)?;
        if let Some(t) = self.tariff_type {
            w.u8(t)?;
        }
        Ok(())
    }

    /// The tariff type asked for (Delivered when absent).
    pub fn tariff(&self) -> u8 {
        self.tariff_type.unwrap_or(tariff_type::DELIVERED)
    }
}

/// GetConversionFactor / GetCalorificValue / GetTariffInformation /
/// GetCO2Value / GetBillingPeriod / GetConsolidatedBill (D.4.2.3.6 to
/// D.4.2.3.14): scheduled instances from a start time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetScheduled {
    /// Earliest start time.
    pub earliest_start: u32,
    /// Minimum issuer event id (`ANY_EVENT`: any).
    pub min_issuer_event_id: u32,
    /// Commands wanted (0: all).
    pub count: u8,
    /// Tariff type, when the command carries one (`ANY_TARIFF_TYPE`
    /// for any).
    pub tariff_type: Option<u8>,
}

impl GetScheduled {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetScheduled {
            earliest_start: r.u32_le()?,
            min_issuer_event_id: r.u32_le()?,
            count: r.u8()?,
            tariff_type: if r.is_empty() { None } else { Some(r.u8()?) },
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.earliest_start)?;
        w.u32_le(self.min_issuer_event_id)?;
        w.u8(self.count)?;
        if let Some(t) = self.tariff_type {
            w.u8(t)?;
        }
        Ok(())
    }

    /// Whether an instance of `tariff_type` is wanted.
    pub fn wants_tariff(&self, tariff_type: u8) -> bool {
        match self.tariff_type {
            None => true,
            Some(ANY_TARIFF_TYPE) => true,
            Some(t) => tariff_type::of(t) == tariff_type::of(tariff_type),
        }
    }
}

/// GetPriceMatrix / GetBlockThresholds / GetTierLabels (D.4.2.3.9,
/// .10, .12): by issuer tariff id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetByTariff {
    /// Issuer tariff id.
    pub issuer_tariff_id: u32,
}

impl GetByTariff {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetByTariff {
            issuer_tariff_id: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_tariff_id)
    }
}

/// CPPEventResponse (D.4.2.3.15).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CppEventResponse {
    /// Issuer event id of the CPP event.
    pub issuer_event_id: u32,
    /// Accepted or Rejected (Table D-113).
    pub auth: u8,
}

impl CppEventResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CppEventResponse {
            issuer_event_id: r.u32_le()?,
            auth: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u8(self.auth)
    }
}

/// GetCreditPayment (D.4.2.3.16).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetCreditPayment {
    /// Latest payment date wanted.
    pub latest_end_time: u32,
    /// Records wanted (0: all), most recent first.
    pub count: u8,
}

impl GetCreditPayment {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetCreditPayment {
            latest_end_time: r.u32_le()?,
            count: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.latest_end_time)?;
        w.u8(self.count)
    }
}

// ----- Published instances -----

/// A published instance identified by provider and issuer event with a
/// start time (the common shape of the scheduled commands).
pub trait Instance: Clone {
    /// Provider id.
    fn provider_id(&self) -> u32;
    /// Issuer event id.
    fn issuer_event_id(&self) -> u32;
    /// Start time (`START_NOW` / `START_CANCEL` as published).
    fn start_time(&self) -> u32;
    /// Replaces the start time (resolving `START_NOW`).
    fn set_start_time(&mut self, t: u32);
    /// Tariff type, for stores that keep one instance per type.
    fn tariff_type(&self) -> u8 {
        tariff_type::DELIVERED
    }
}

macro_rules! instance {
    ($t:ty, $provider:ident, $event:ident, $start:ident $(, $tariff:ident)?) => {
        impl Instance for $t {
            fn provider_id(&self) -> u32 {
                self.$provider
            }
            fn issuer_event_id(&self) -> u32 {
                self.$event
            }
            fn start_time(&self) -> u32 {
                self.$start
            }
            fn set_start_time(&mut self, t: u32) {
                self.$start = t;
            }
            $(fn tariff_type(&self) -> u8 {
                tariff_type::of(self.$tariff)
            })?
        }
    };
}

/// PublishBlockPeriod (D.4.2.4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BlockPeriod {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Duration (24 bits, `DURATION_UNTIL_CHANGED_24`).
    pub duration: u32,
    /// Block period control (Table D-104).
    pub control: u8,
    /// Duration type (Tables D-105 / D-106).
    pub duration_type: u8,
    /// Tariff type.
    pub tariff_type: u8,
    /// Tariff resolution period (Table D-107).
    pub resolution_period: u8,
}
instance!(
    BlockPeriod,
    provider_id,
    issuer_event_id,
    start_time,
    tariff_type
);

impl BlockPeriod {
    /// Encoded length.
    pub const LEN: usize = 19;

    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(BlockPeriod {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            duration: r.u24_le()?,
            control: r.u8()?,
            duration_type: r.u8()?,
            tariff_type: r.u8()?,
            resolution_period: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u24_le(self.duration)?;
        w.u8(self.control)?;
        w.u8(self.duration_type)?;
        w.u8(self.tariff_type)?;
        w.u8(self.resolution_period)
    }

    /// End time when the duration is in minutes (`None` for other
    /// timebases or "until changed").
    pub fn end_time(&self) -> Option<u32> {
        (duration_type::timebase(self.duration_type) == duration_type::MINUTES
            && self.duration != DURATION_UNTIL_CHANGED_24)
            .then(|| {
                self.start_time
                    .saturating_add(self.duration.saturating_mul(60))
            })
    }
}

/// PublishConversionFactor (D.4.2.4.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConversionFactor {
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Conversion factor.
    pub factor: u32,
    /// Trailing digit (high nibble).
    pub trailing_digit: u8,
}

impl Instance for ConversionFactor {
    fn provider_id(&self) -> u32 {
        0
    }
    fn issuer_event_id(&self) -> u32 {
        self.issuer_event_id
    }
    fn start_time(&self) -> u32 {
        self.start_time
    }
    fn set_start_time(&mut self, t: u32) {
        self.start_time = t;
    }
}

impl ConversionFactor {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ConversionFactor {
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            factor: r.u32_le()?,
            trailing_digit: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u32_le(self.factor)?;
        w.u8(self.trailing_digit)
    }
}

/// PublishCalorificValue (D.4.2.4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CalorificValue {
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Calorific value.
    pub value: u32,
    /// Unit (D.4.2.2.4.6).
    pub unit: u8,
    /// Trailing digit (high nibble).
    pub trailing_digit: u8,
}

impl Instance for CalorificValue {
    fn provider_id(&self) -> u32 {
        0
    }
    fn issuer_event_id(&self) -> u32 {
        self.issuer_event_id
    }
    fn start_time(&self) -> u32 {
        self.start_time
    }
    fn set_start_time(&mut self, t: u32) {
        self.start_time = t;
    }
}

impl CalorificValue {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CalorificValue {
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            value: r.u32_le()?,
            unit: r.u8()?,
            trailing_digit: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u32_le(self.value)?;
        w.u8(self.unit)?;
        w.u8(self.trailing_digit)
    }
}

/// PublishTariffInformation (D.4.2.4.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TariffInformation {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Issuer tariff id.
    pub issuer_tariff_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Tariff type (low nibble) and charging scheme (high nibble).
    pub tariff_type_scheme: u8,
    /// Tariff label.
    pub label: Vec<u8, MAX_TARIFF_LABEL>,
    /// Price tiers in use.
    pub price_tiers: u8,
    /// Block thresholds in use.
    pub block_thresholds: u8,
    /// Unit of measure.
    pub unit_of_measure: u8,
    /// Currency (ISO 4217).
    pub currency: u16,
    /// Price trailing digit (high nibble).
    pub price_trailing_digit: u8,
    /// Standing charge (`VALUE_UNUSED`).
    pub standing_charge: u32,
    /// Tier / block mode (0xff unused).
    pub tier_block_mode: u8,
    /// Block threshold multiplier (24 bits).
    pub threshold_multiplier: u32,
    /// Block threshold divisor (24 bits).
    pub threshold_divisor: u32,
}
instance!(
    TariffInformation,
    provider_id,
    issuer_event_id,
    start_time,
    tariff_type_scheme
);

impl TariffInformation {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(TariffInformation {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            issuer_tariff_id: r.u32_le()?,
            start_time: r.u32_le()?,
            tariff_type_scheme: r.u8()?,
            label: octstr(read_octstr(&mut r)?, "tariff label")?,
            price_tiers: r.u8()?,
            block_thresholds: r.u8()?,
            unit_of_measure: r.u8()?,
            currency: r.u16_le()?,
            price_trailing_digit: r.u8()?,
            standing_charge: r.u32_le()?,
            tier_block_mode: r.u8()?,
            threshold_multiplier: r.u24_le()?,
            threshold_divisor: r.u24_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.issuer_tariff_id)?;
        w.u32_le(self.start_time)?;
        w.u8(self.tariff_type_scheme)?;
        write_octstr(w, &self.label)?;
        w.u8(self.price_tiers)?;
        w.u8(self.block_thresholds)?;
        w.u8(self.unit_of_measure)?;
        w.u16_le(self.currency)?;
        w.u8(self.price_trailing_digit)?;
        w.u32_le(self.standing_charge)?;
        w.u8(self.tier_block_mode)?;
        w.u24_le(self.threshold_multiplier)?;
        w.u24_le(self.threshold_divisor)
    }

    /// The charging scheme (Table D-109).
    pub const fn scheme(&self) -> u8 {
        charging_scheme::of(self.tariff_type_scheme)
    }
}

/// The header shared by PublishPriceMatrix and PublishBlockThresholds
/// (Figures D-79, D-81).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TariffPartHeader {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id (the same on every fragment).
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Issuer tariff id.
    pub issuer_tariff_id: u32,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// Sub-payload control.
    pub control: u8,
}

impl TariffPartHeader {
    fn parse(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(TariffPartHeader {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            issuer_tariff_id: r.u32_le()?,
            command_index: r.u8()?,
            total_commands: r.u8()?,
            control: r.u8()?,
        })
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u32_le(self.issuer_tariff_id)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        w.u8(self.control)
    }
}

/// Sub-payload control bit of PublishPriceMatrix: TOU-based entries
/// (Table D-110).
pub const MATRIX_TOU: u8 = 0x01;
/// Sub-payload control bit of PublishBlockThresholds: thresholds apply
/// to all tiers (Table D-111).
pub const THRESHOLDS_ALL_TIERS: u8 = 0x01;

/// A price matrix entry: the Tier/Block ID (Figure D-80) and its price.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MatrixEntry {
    /// Tier/Block ID: `tier << 4 | block` for block-based matrices, the
    /// TOU tier (1–48) for TOU-based ones.
    pub id: u8,
    /// Price.
    pub price: u32,
}

impl MatrixEntry {
    /// A block-based id.
    pub const fn block(tier: u8, block: u8) -> u8 {
        (tier << 4) | (block & 0x0f)
    }
}

/// PublishPriceMatrix (D.4.2.4.6).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PriceMatrix {
    /// Header.
    pub header: TariffPartHeader,
    /// Entries of this fragment.
    pub entries: Vec<MatrixEntry, MAX_MATRIX_ENTRIES>,
}

impl PriceMatrix {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let header = TariffPartHeader::parse(&mut r)?;
        let mut entries = Vec::new();
        while !r.is_empty() {
            let e = MatrixEntry {
                id: r.u8()?,
                price: r.u32_le()?,
            };
            entries
                .push(e)
                .map_err(|_| CodecError::Unrepresentable { field: "entries" })?;
        }
        Ok(PriceMatrix { header, entries })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        self.header.encode(w)?;
        for e in &self.entries {
            w.u8(e.id)?;
            w.u32_le(e.price)?;
        }
        Ok(())
    }
}

/// A tier's block thresholds (Figure D-82).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TierThresholds {
    /// Tier (0 when the thresholds apply to all tiers).
    pub tier: u8,
    /// Thresholds, ascending.
    pub thresholds: Vec<u64, MAX_THRESHOLDS>,
}

/// PublishBlockThresholds (D.4.2.4.7).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BlockThresholds {
    /// Header.
    pub header: TariffPartHeader,
    /// Threshold sets of this fragment.
    pub sets: Vec<TierThresholds, MAX_THRESHOLD_SETS>,
}

impl BlockThresholds {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let header = TariffPartHeader::parse(&mut r)?;
        let mut sets = Vec::new();
        while !r.is_empty() {
            let b = r.u8()?;
            let count = usize::from(b & 0x0f);
            let mut thresholds = Vec::new();
            for _ in 0..count {
                thresholds
                    .push(read_u48(&mut r)?)
                    .map_err(|_| CodecError::Unrepresentable {
                        field: "thresholds",
                    })?;
            }
            sets.push(TierThresholds {
                tier: b >> 4,
                thresholds,
            })
            .map_err(|_| CodecError::Unrepresentable { field: "sets" })?;
        }
        Ok(BlockThresholds { header, sets })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        self.header.encode(w)?;
        for s in &self.sets {
            let count = u8::try_from(s.thresholds.len())
                .ok()
                .filter(|n| *n <= 15)
                .ok_or(CodecError::Unrepresentable {
                    field: "thresholds",
                })?;
            w.u8((s.tier << 4) | count)?;
            for t in &s.thresholds {
                write_u48(w, *t)?;
            }
        }
        Ok(())
    }
}

/// PublishCO2Value (D.4.2.4.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Co2Value {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Tariff type.
    pub tariff_type: u8,
    /// CO2 value (`VALUE_UNUSED`).
    pub value: u32,
    /// Unit (0xff unused).
    pub unit: u8,
    /// Trailing digit (0xff unused).
    pub trailing_digit: u8,
}
instance!(
    Co2Value,
    provider_id,
    issuer_event_id,
    start_time,
    tariff_type
);

impl Co2Value {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(Co2Value {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            tariff_type: r.u8()?,
            value: r.u32_le()?,
            unit: r.u8()?,
            trailing_digit: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u8(self.tariff_type)?;
        w.u32_le(self.value)?;
        w.u8(self.unit)?;
        w.u8(self.trailing_digit)
    }
}

/// PublishTierLabels (D.4.2.4.9).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TierLabels {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Issuer tariff id.
    pub issuer_tariff_id: u32,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// (tier id, label) pairs.
    pub labels: Vec<(u8, Vec<u8, MAX_TIER_LABEL>), 8>,
}

impl TierLabels {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let provider_id = r.u32_le()?;
        let issuer_event_id = r.u32_le()?;
        let issuer_tariff_id = r.u32_le()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let n = r.u8()?;
        let mut labels = Vec::new();
        for _ in 0..n {
            let tier = r.u8()?;
            let label = octstr(read_octstr(&mut r)?, "tier label")?;
            labels
                .push((tier, label))
                .map_err(|_| CodecError::Unrepresentable { field: "labels" })?;
        }
        Ok(TierLabels {
            provider_id,
            issuer_event_id,
            issuer_tariff_id,
            command_index,
            total_commands,
            labels,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.issuer_tariff_id)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        w.u8(u8::try_from(self.labels.len())
            .map_err(|_| CodecError::Unrepresentable { field: "labels" })?)?;
        for (tier, label) in &self.labels {
            w.u8(*tier)?;
            write_octstr(w, label)?;
        }
        Ok(())
    }
}

/// PublishBillingPeriod (D.4.2.4.10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BillingPeriod {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Duration (24 bits).
    pub duration: u32,
    /// Duration type.
    pub duration_type: u8,
    /// Tariff type.
    pub tariff_type: u8,
}
instance!(
    BillingPeriod,
    provider_id,
    issuer_event_id,
    start_time,
    tariff_type
);

impl BillingPeriod {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(BillingPeriod {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            duration: r.u24_le()?,
            duration_type: r.u8()?,
            tariff_type: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u24_le(self.duration)?;
        w.u8(self.duration_type)?;
        w.u8(self.tariff_type)
    }
}

/// PublishConsolidatedBill (D.4.2.4.11).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConsolidatedBill {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Billing period start time.
    pub start_time: u32,
    /// Billing period duration (24 bits).
    pub duration: u32,
    /// Duration type.
    pub duration_type: u8,
    /// Tariff type.
    pub tariff_type: u8,
    /// The bill.
    pub bill: u32,
    /// Currency (ISO 4217).
    pub currency: u16,
    /// Bill trailing digit (high nibble).
    pub trailing_digit: u8,
}
instance!(
    ConsolidatedBill,
    provider_id,
    issuer_event_id,
    start_time,
    tariff_type
);

impl ConsolidatedBill {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ConsolidatedBill {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            duration: r.u24_le()?,
            duration_type: r.u8()?,
            tariff_type: r.u8()?,
            bill: r.u32_le()?,
            currency: r.u16_le()?,
            trailing_digit: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u24_le(self.duration)?;
        w.u8(self.duration_type)?;
        w.u8(self.tariff_type)?;
        w.u32_le(self.bill)?;
        w.u16_le(self.currency)?;
        w.u8(self.trailing_digit)
    }
}

/// PublishCPPEvent (D.4.2.4.12, provisional).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CppEvent {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Duration in minutes.
    pub duration_minutes: u16,
    /// Tariff type.
    pub tariff_type: u8,
    /// CPP price tier (Table D-112).
    pub tier: u8,
    /// Authorisation (Table D-113).
    pub auth: u8,
}
instance!(
    CppEvent,
    provider_id,
    issuer_event_id,
    start_time,
    tariff_type
);

impl CppEvent {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CppEvent {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            duration_minutes: r.u16_le()?,
            tariff_type: r.u8()?,
            tier: r.u8()?,
            auth: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u16_le(self.duration_minutes)?;
        w.u8(self.tariff_type)?;
        w.u8(self.tier)?;
        w.u8(self.auth)
    }

    /// The ESI's re-publication after a CPPEventResponse (D.4.2.3.15.4).
    pub const fn with_auth(mut self, auth: u8) -> Self {
        self.auth = auth;
        self
    }

    /// Whether the event is in force for the client (accepted or
    /// forced; a pending event waits for the consumer, D.4.2.4.12.4).
    pub const fn is_authorised(&self) -> bool {
        matches!(self.auth, cpp_auth::ACCEPTED | cpp_auth::FORCED)
    }
}

/// PublishCreditPayment (D.4.2.4.13).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CreditPayment {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Next payment due date.
    pub due_date: u32,
    /// Overdue amount.
    pub overdue_amount: u32,
    /// Payment status (D.4.2.2.9.2).
    pub status: u8,
    /// Last payment.
    pub payment: u32,
    /// Last payment date.
    pub payment_date: u32,
    /// Payment reference.
    pub reference: Vec<u8, MAX_PAYMENT_REF>,
}

impl CreditPayment {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CreditPayment {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            due_date: r.u32_le()?,
            overdue_amount: r.u32_le()?,
            status: r.u8()?,
            payment: r.u32_le()?,
            payment_date: r.u32_le()?,
            reference: octstr(read_octstr(&mut r)?, "payment reference")?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.due_date)?;
        w.u32_le(self.overdue_amount)?;
        w.u8(self.status)?;
        w.u32_le(self.payment)?;
        w.u32_le(self.payment_date)?;
        write_octstr(w, &self.reference)
    }
}

/// PublishCurrencyConversion (D.4.2.4.14).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CurrencyConversion {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Old currency.
    pub old_currency: u16,
    /// New currency.
    pub new_currency: u16,
    /// Conversion factor.
    pub factor: u32,
    /// Trailing digit (high nibble).
    pub trailing_digit: u8,
    /// Change control flags (Table D-114).
    pub flags: u32,
}
instance!(CurrencyConversion, provider_id, issuer_event_id, start_time);

impl CurrencyConversion {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CurrencyConversion {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            old_currency: r.u16_le()?,
            new_currency: r.u16_le()?,
            factor: r.u32_le()?,
            trailing_digit: r.u8()?,
            flags: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u16_le(self.old_currency)?;
        w.u16_le(self.new_currency)?;
        w.u32_le(self.factor)?;
        w.u8(self.trailing_digit)?;
        w.u32_le(self.flags)
    }
}

/// CancelTariff (D.4.2.4.15).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CancelTariff {
    /// Provider id.
    pub provider_id: u32,
    /// Issuer tariff id.
    pub issuer_tariff_id: u32,
    /// Tariff type.
    pub tariff_type: u8,
}

impl CancelTariff {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CancelTariff {
            provider_id: r.u32_le()?,
            issuer_tariff_id: r.u32_le()?,
            tariff_type: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_tariff_id)?;
        w.u8(self.tariff_type)
    }
}

// ----- Stores -----

/// What a store did with a published instance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Applied {
    /// Stored (replacing older overlapping instances).
    Stored,
    /// Older than what is held: ignored.
    Stale,
    /// A cancellation removed the instance.
    Cancelled,
    /// A cancellation named an unknown instance (NOT_FOUND).
    NotFound,
    /// No room (INSUFFICIENT_SPACE).
    Full,
}

/// A bounded store of scheduled instances (`N` per tariff type, the
/// specification's "current and next" being two): a newer issuer event
/// id replaces an instance starting at the same time, a start time of
/// 0xFFFFFFFF cancels the instance with the same provider and issuer
/// event id, and the active instance at a time is the latest one that
/// has started (D.4.2.4.3 – D.4.2.4.14).
#[derive(Clone, Debug)]
pub struct Scheduled<T: Instance, const N: usize> {
    items: Vec<T, N>,
}

impl<T: Instance, const N: usize> Default for Scheduled<T, N> {
    fn default() -> Self {
        Scheduled { items: Vec::new() }
    }
}

impl<T: Instance, const N: usize> Scheduled<T, N> {
    /// An empty store.
    pub const fn new() -> Self {
        Scheduled { items: Vec::new() }
    }

    /// Applies a published instance received at `now`.
    pub fn publish(&mut self, mut item: T, now: u32) -> Applied {
        if item.start_time() == START_CANCEL {
            let before = self.items.len();
            self.items.retain(|i| {
                !(i.provider_id() == item.provider_id()
                    && i.issuer_event_id() == item.issuer_event_id())
            });
            return if self.items.len() != before {
                Applied::Cancelled
            } else {
                Applied::NotFound
            };
        }
        if item.start_time() == START_NOW {
            item.set_start_time(now);
        }
        // Same type and start: the newer issuer event wins.
        if let Some(existing) = self
            .items
            .iter()
            .find(|i| i.tariff_type() == item.tariff_type() && i.start_time() == item.start_time())
            && existing.issuer_event_id() > item.issuer_event_id()
        {
            return Applied::Stale;
        }
        self.items.retain(|i| {
            !(i.tariff_type() == item.tariff_type() && i.start_time() == item.start_time())
        });
        // Drop the oldest superseded instance of the type when full:
        // anything starting before an instance that itself started
        // before now is history.
        if self.items.is_full() {
            let mut victim = None;
            let mut oldest = u32::MAX;
            for (i, e) in self.items.iter().enumerate() {
                if e.tariff_type() == item.tariff_type()
                    && e.start_time() <= now
                    && e.start_time() < oldest
                {
                    oldest = e.start_time();
                    victim = Some(i);
                }
            }
            match victim {
                Some(i)
                    if self
                        .items
                        .iter()
                        .filter(|e| e.tariff_type() == item.tariff_type() && e.start_time() <= now)
                        .count()
                        > 1 =>
                {
                    self.items.remove(i);
                }
                _ => return Applied::Full,
            }
        }
        let _ = self.items.push(item);
        Applied::Stored
    }

    /// The instance in force at `now` for `tariff_type`.
    pub fn active(&self, now: u32, tariff_type: u8) -> Option<&T> {
        self.items
            .iter()
            .filter(|i| i.tariff_type() == tariff_type && i.start_time() <= now)
            .max_by_key(|i| (i.start_time(), i.issuer_event_id()))
    }

    /// The next instance to become active after `now`.
    pub fn next(&self, now: u32, tariff_type: u8) -> Option<&T> {
        self.items
            .iter()
            .filter(|i| i.tariff_type() == tariff_type && i.start_time() > now)
            .min_by_key(|i| (i.start_time(), core::cmp::Reverse(i.issuer_event_id())))
    }

    /// Answers a Get request (D.4.2.3.6 etc.): the instance active at
    /// the earliest start time followed by the scheduled ones in start
    /// order, filtered by issuer event id and tariff type, at most
    /// `count` (0: all). Empty means NOT_FOUND.
    pub fn scheduled(&self, req: &GetScheduled, now: u32, out: &mut Vec<T, N>) {
        let earliest = if req.earliest_start == 0 {
            now
        } else {
            req.earliest_start
        };
        let mut candidates: Vec<&T, N> = Vec::new();
        for i in &self.items {
            if req.min_issuer_event_id != ANY_EVENT && i.issuer_event_id() < req.min_issuer_event_id
            {
                continue;
            }
            if !req.wants_tariff(i.tariff_type()) {
                continue;
            }
            let is_active = i.start_time() <= earliest
                && self
                    .active(earliest, i.tariff_type())
                    .is_some_and(|a| a.issuer_event_id() == i.issuer_event_id());
            if is_active || i.start_time() >= earliest {
                let _ = candidates.push(i);
            }
        }
        candidates.sort_unstable_by_key(|i| (i.start_time(), i.issuer_event_id()));
        let limit = if req.count == 0 {
            usize::MAX
        } else {
            usize::from(req.count)
        };
        for i in candidates.into_iter().take(limit) {
            let _ = out.push(i.clone());
        }
    }

    /// Every instance held.
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// Drops instances superseded before `now` (keeping the active one).
    pub fn expire(&mut self, now: u32) {
        let mut keep: Vec<u32, N> = Vec::new();
        for t in 0..=tariff_type::DELIVERED_AND_RECEIVED {
            if let Some(a) = self.active(now, t) {
                let _ = keep.push(a.issuer_event_id());
            }
        }
        self.items
            .retain(|i| i.start_time() > now || keep.contains(&i.issuer_event_id()));
    }
}

/// A tariff assembled from its parts (D.4.2.4.5 – D.4.2.4.9).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tariff {
    /// The tariff information.
    pub info: TariffInformation,
    /// Price matrix entries (issuer event id of the fragments, entries,
    /// fragments received as a bitmask, total).
    pub matrix: Vec<MatrixEntry, MAX_MATRIX>,
    matrix_event: u32,
    matrix_fragments: u16,
    matrix_total: u8,
    /// Whether the matrix is TOU-based.
    pub matrix_tou: bool,
    /// Block thresholds per tier (tier 0 for "all tiers").
    pub thresholds: Vec<TierThresholds, 16>,
    thresholds_event: u32,
    thresholds_fragments: u16,
    thresholds_total: u8,
    /// Tier labels.
    pub labels: Vec<(u8, Vec<u8, MAX_TIER_LABEL>), MAX_TIER_LABELS>,
}

impl Tariff {
    fn new(info: TariffInformation) -> Self {
        Tariff {
            info,
            matrix: Vec::new(),
            matrix_event: 0,
            matrix_fragments: 0,
            matrix_total: 0,
            matrix_tou: false,
            thresholds: Vec::new(),
            thresholds_event: 0,
            thresholds_fragments: 0,
            thresholds_total: 0,
            labels: Vec::new(),
        }
    }

    /// Whether every price matrix fragment arrived.
    pub fn matrix_complete(&self) -> bool {
        self.matrix_total > 0
            && (0..self.matrix_total).all(|i| self.matrix_fragments & (1 << (i & 0x0f)) != 0)
    }

    /// Whether every block threshold fragment arrived.
    pub fn thresholds_complete(&self) -> bool {
        self.thresholds_total > 0
            && (0..self.thresholds_total)
                .all(|i| self.thresholds_fragments & (1 << (i & 0x0f)) != 0)
    }

    /// The price of `tier` (1-based) and `block` (1-based) from a
    /// complete matrix; for a TOU matrix the tier alone.
    pub fn price(&self, tier: u8, block: u8) -> Option<u32> {
        if !self.matrix_complete() {
            return None;
        }
        let id = if self.matrix_tou {
            tier
        } else {
            MatrixEntry::block(tier, block.saturating_sub(1))
        };
        self.matrix.iter().find(|e| e.id == id).map(|e| e.price)
    }

    /// The block (1-based) that `consumption` falls in for `tier`,
    /// using the tier's thresholds or the all-tiers set, scaled by the
    /// tariff's multiplier and divisor.
    pub fn block_for(&self, tier: u8, consumption: u64) -> Option<u8> {
        if !self.thresholds_complete() {
            return None;
        }
        let set = self
            .thresholds
            .iter()
            .find(|s| s.tier == tier)
            .or_else(|| self.thresholds.iter().find(|s| s.tier == 0))?;
        let mult = u64::from(self.info.threshold_multiplier.max(1));
        let div = u64::from(self.info.threshold_divisor.max(1));
        let mut block = 1u8;
        for t in &set.thresholds {
            if *t == THRESHOLD_UNUSED {
                break;
            }
            let scaled = t.saturating_mul(mult) / div;
            if consumption >= scaled {
                block = block.saturating_add(1);
            } else {
                break;
            }
        }
        Some(block)
    }

    /// The label of `tier`.
    pub fn label(&self, tier: u8) -> Option<&[u8]> {
        self.labels
            .iter()
            .find(|(t, _)| *t == tier)
            .map(|(_, l)| l.as_slice())
    }
}

/// Client tariff store: at most `N` tariffs (the current and next per
/// tariff type), each assembled from PublishTariffInformation,
/// PublishPriceMatrix, PublishBlockThresholds and PublishTierLabels and
/// discarded by CancelTariff (D.4.2.4.15.3).
#[derive(Clone, Debug, Default)]
pub struct TariffStore<const N: usize> {
    tariffs: Vec<Tariff, N>,
}

impl<const N: usize> TariffStore<N> {
    /// An empty store.
    pub const fn new() -> Self {
        TariffStore {
            tariffs: Vec::new(),
        }
    }

    /// The tariff with `issuer_tariff_id`.
    pub fn get(&self, issuer_tariff_id: u32) -> Option<&Tariff> {
        self.tariffs
            .iter()
            .find(|t| t.info.issuer_tariff_id == issuer_tariff_id)
    }

    fn get_mut(&mut self, issuer_tariff_id: u32) -> Option<&mut Tariff> {
        self.tariffs
            .iter_mut()
            .find(|t| t.info.issuer_tariff_id == issuer_tariff_id)
    }

    /// Applies a PublishTariffInformation: a newer issuer event for the
    /// same tariff id replaces the information (keeping the assembled
    /// parts); when full, the oldest-starting tariff of the same type
    /// that is not the one active at `now` makes room.
    pub fn on_tariff_information(&mut self, info: &TariffInformation, now: u32) -> Applied {
        let mut info = info.clone();
        if info.start_time == START_NOW {
            info.start_time = now;
        }
        if let Some(t) = self.get_mut(info.issuer_tariff_id) {
            if t.info.issuer_event_id > info.issuer_event_id {
                return Applied::Stale;
            }
            t.info = info;
            return Applied::Stored;
        }
        if self.tariffs.is_full() {
            let ty = tariff_type::of(info.tariff_type_scheme);
            let active = self.active(now, ty).map(|t| t.info.issuer_tariff_id);
            let victim = self
                .tariffs
                .iter()
                .enumerate()
                .filter(|(_, t)| {
                    tariff_type::of(t.info.tariff_type_scheme) == ty
                        && Some(t.info.issuer_tariff_id) != active
                        && t.info.start_time <= now
                })
                .min_by_key(|(_, t)| t.info.start_time)
                .map(|(i, _)| i);
            match victim {
                Some(i) => {
                    self.tariffs.remove(i);
                }
                None => return Applied::Full,
            }
        }
        let _ = self.tariffs.push(Tariff::new(info));
        Applied::Stored
    }

    /// Applies a PublishPriceMatrix fragment (NOT_FOUND when the tariff
    /// is unknown).
    pub fn on_price_matrix(&mut self, m: &PriceMatrix) -> Applied {
        let Some(t) = self.get_mut(m.header.issuer_tariff_id) else {
            return Applied::NotFound;
        };
        if m.header.issuer_event_id < t.matrix_event {
            return Applied::Stale;
        }
        if m.header.issuer_event_id != t.matrix_event || m.header.total_commands != t.matrix_total {
            t.matrix.clear();
            t.matrix_fragments = 0;
            t.matrix_event = m.header.issuer_event_id;
            t.matrix_total = m.header.total_commands.max(1);
            t.matrix_tou = m.header.control & MATRIX_TOU != 0;
        }
        let bit = 1u16 << (m.header.command_index & 0x0f);
        if t.matrix_fragments & bit != 0 {
            return Applied::Stored;
        }
        for e in &m.entries {
            if let Some(x) = t.matrix.iter_mut().find(|x| x.id == e.id) {
                x.price = e.price;
            } else if t.matrix.push(*e).is_err() {
                return Applied::Full;
            }
        }
        t.matrix_fragments |= bit;
        Applied::Stored
    }

    /// Applies a PublishBlockThresholds fragment.
    pub fn on_block_thresholds(&mut self, b: &BlockThresholds) -> Applied {
        let Some(t) = self.get_mut(b.header.issuer_tariff_id) else {
            return Applied::NotFound;
        };
        if b.header.issuer_event_id < t.thresholds_event {
            return Applied::Stale;
        }
        if b.header.issuer_event_id != t.thresholds_event
            || b.header.total_commands != t.thresholds_total
        {
            t.thresholds.clear();
            t.thresholds_fragments = 0;
            t.thresholds_event = b.header.issuer_event_id;
            t.thresholds_total = b.header.total_commands.max(1);
        }
        let bit = 1u16 << (b.header.command_index & 0x0f);
        if t.thresholds_fragments & bit != 0 {
            return Applied::Stored;
        }
        for s in &b.sets {
            let tier = if b.header.control & THRESHOLDS_ALL_TIERS != 0 {
                0
            } else {
                s.tier
            };
            if let Some(x) = t.thresholds.iter_mut().find(|x| x.tier == tier) {
                // A tier split across fragments: append.
                for v in &s.thresholds {
                    if x.thresholds.push(*v).is_err() {
                        return Applied::Full;
                    }
                }
            } else if t
                .thresholds
                .push(TierThresholds {
                    tier,
                    thresholds: s.thresholds.clone(),
                })
                .is_err()
            {
                return Applied::Full;
            }
        }
        t.thresholds_fragments |= bit;
        Applied::Stored
    }

    /// Applies a PublishTierLabels fragment.
    pub fn on_tier_labels(&mut self, l: &TierLabels) -> Applied {
        let Some(t) = self.get_mut(l.issuer_tariff_id) else {
            return Applied::NotFound;
        };
        if l.command_index == 0 {
            t.labels.clear();
        }
        for (tier, label) in &l.labels {
            if let Some(x) = t.labels.iter_mut().find(|(x, _)| x == tier) {
                x.1 = label.clone();
            } else if t.labels.push((*tier, label.clone())).is_err() {
                return Applied::Full;
            }
        }
        Applied::Stored
    }

    /// Applies a CancelTariff: discards every part of the tariff.
    pub fn on_cancel(&mut self, c: &CancelTariff) -> Applied {
        let before = self.tariffs.len();
        self.tariffs.retain(|t| {
            !(t.info.provider_id == c.provider_id
                && t.info.issuer_tariff_id == c.issuer_tariff_id
                && tariff_type::of(t.info.tariff_type_scheme) == tariff_type::of(c.tariff_type))
        });
        if self.tariffs.len() != before {
            Applied::Cancelled
        } else {
            Applied::NotFound
        }
    }

    /// The tariff in force at `now` for `tariff_type`.
    pub fn active(&self, now: u32, tariff_type: u8) -> Option<&Tariff> {
        self.tariffs
            .iter()
            .filter(|t| {
                tariff_type::of(t.info.tariff_type_scheme) == tariff_type
                    && t.info.start_time <= now
            })
            .max_by_key(|t| (t.info.start_time, t.info.issuer_event_id))
    }

    /// Every tariff held.
    pub fn tariffs(&self) -> &[Tariff] {
        &self.tariffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T: PartialEq + core::fmt::Debug>(
        v: &T,
        enc: impl Fn(&T, &mut Writer<'_>) -> Result<(), CodecError>,
        dec: impl Fn(&[u8]) -> Result<T, CodecError>,
    ) -> usize {
        let mut buf = [0u8; 200];
        let mut w = Writer::new(&mut buf);
        enc(v, &mut w).unwrap();
        let n = w.position();
        assert_eq!(&dec(&buf[..n]).unwrap(), v);
        n
    }

    fn info(event: u32, tariff: u32, start: u32, scheme: u8) -> TariffInformation {
        TariffInformation {
            provider_id: 1,
            issuer_event_id: event,
            issuer_tariff_id: tariff,
            start_time: start,
            tariff_type_scheme: charging_scheme::field(tariff_type::DELIVERED, scheme),
            label: Vec::from_slice(b"Std").unwrap(),
            price_tiers: 2,
            block_thresholds: 2,
            unit_of_measure: 0,
            currency: 826,
            price_trailing_digit: 0x30,
            standing_charge: VALUE_UNUSED,
            tier_block_mode: 0xff,
            threshold_multiplier: 1,
            threshold_divisor: 1,
        }
    }

    #[test]
    fn codecs_round_trip() {
        assert_eq!(
            rt(
                &GetBlockPeriods {
                    start_time: 0,
                    count: 1,
                    tariff_type: None
                },
                GetBlockPeriods::encode,
                GetBlockPeriods::parse
            ),
            5
        );
        rt(
            &GetScheduled {
                earliest_start: 1,
                min_issuer_event_id: ANY_EVENT,
                count: 0,
                tariff_type: Some(ANY_TARIFF_TYPE),
            },
            GetScheduled::encode,
            GetScheduled::parse,
        );
        assert_eq!(
            rt(
                &GetScheduled {
                    earliest_start: 1,
                    min_issuer_event_id: 2,
                    count: 3,
                    tariff_type: None
                },
                GetScheduled::encode,
                GetScheduled::parse
            ),
            9
        );
        rt(
            &GetByTariff {
                issuer_tariff_id: 9,
            },
            GetByTariff::encode,
            GetByTariff::parse,
        );
        rt(
            &CppEventResponse {
                issuer_event_id: 4,
                auth: cpp_auth::ACCEPTED,
            },
            CppEventResponse::encode,
            CppEventResponse::parse,
        );
        rt(
            &GetCreditPayment {
                latest_end_time: 5,
                count: 2,
            },
            GetCreditPayment::encode,
            GetCreditPayment::parse,
        );
        let bp = BlockPeriod {
            provider_id: 1,
            issuer_event_id: 2,
            start_time: 1000,
            duration: 60,
            control: block_period_control::REPEATING,
            duration_type: duration_type::field(
                duration_type::MINUTES,
                duration_type::NOT_SPECIFIED,
            ),
            tariff_type: 0,
            resolution_period: resolution_period::BLOCK_PERIOD,
        };
        assert_eq!(
            rt(&bp, BlockPeriod::encode, BlockPeriod::parse),
            BlockPeriod::LEN
        );
        assert_eq!(bp.end_time(), Some(4600));
        rt(
            &ConversionFactor {
                issuer_event_id: 1,
                start_time: 2,
                factor: 3,
                trailing_digit: 0x70,
            },
            ConversionFactor::encode,
            ConversionFactor::parse,
        );
        rt(
            &CalorificValue {
                issuer_event_id: 1,
                start_time: 2,
                value: 39_000_000,
                unit: 1,
                trailing_digit: 0x60,
            },
            CalorificValue::encode,
            CalorificValue::parse,
        );
        rt(
            &info(1, 2, 3, charging_scheme::BLOCK_TOU_COMMON),
            TariffInformation::encode,
            TariffInformation::parse,
        );
        let header = TariffPartHeader {
            provider_id: 1,
            issuer_event_id: 2,
            start_time: 3,
            issuer_tariff_id: 4,
            command_index: 0,
            total_commands: 1,
            control: 0,
        };
        let mut entries = Vec::new();
        entries
            .push(MatrixEntry {
                id: MatrixEntry::block(1, 0),
                price: 100,
            })
            .unwrap();
        rt(
            &PriceMatrix { header, entries },
            PriceMatrix::encode,
            PriceMatrix::parse,
        );
        let mut sets = Vec::new();
        sets.push(TierThresholds {
            tier: 1,
            thresholds: Vec::from_slice(&[1000, 2000, THRESHOLD_UNUSED]).unwrap(),
        })
        .unwrap();
        let n = rt(
            &BlockThresholds { header, sets },
            BlockThresholds::encode,
            BlockThresholds::parse,
        );
        assert_eq!(n, 19 + 1 + 18);
        rt(
            &Co2Value {
                provider_id: 1,
                issuer_event_id: 2,
                start_time: 3,
                tariff_type: 0,
                value: 500,
                unit: 1,
                trailing_digit: 0x30,
            },
            Co2Value::encode,
            Co2Value::parse,
        );
        let mut labels = Vec::new();
        labels
            .push((1u8, Vec::from_slice(b"Peak").unwrap()))
            .unwrap();
        rt(
            &TierLabels {
                provider_id: 1,
                issuer_event_id: 2,
                issuer_tariff_id: 4,
                command_index: 0,
                total_commands: 1,
                labels,
            },
            TierLabels::encode,
            TierLabels::parse,
        );
        rt(
            &BillingPeriod {
                provider_id: 1,
                issuer_event_id: 2,
                start_time: 3,
                duration: 30,
                duration_type: duration_type::field(
                    duration_type::DAYS,
                    duration_type::START_OF_TIMEBASE,
                ),
                tariff_type: 0,
            },
            BillingPeriod::encode,
            BillingPeriod::parse,
        );
        rt(
            &ConsolidatedBill {
                provider_id: 1,
                issuer_event_id: 2,
                start_time: 3,
                duration: 30,
                duration_type: 0x01,
                tariff_type: 0,
                bill: 12345,
                currency: 826,
                trailing_digit: 0x20,
            },
            ConsolidatedBill::encode,
            ConsolidatedBill::parse,
        );
        let cpp = CppEvent {
            provider_id: 1,
            issuer_event_id: 2,
            start_time: 3,
            duration_minutes: 120,
            tariff_type: 0,
            tier: cpp_tier::CPP1,
            auth: cpp_auth::PENDING,
        };
        rt(&cpp, CppEvent::encode, CppEvent::parse);
        assert!(!cpp.is_authorised() && cpp.with_auth(cpp_auth::FORCED).is_authorised());
        rt(
            &CreditPayment {
                provider_id: 1,
                issuer_event_id: 2,
                due_date: 3,
                overdue_amount: 4,
                status: 5,
                payment: 6,
                payment_date: 7,
                reference: Vec::from_slice(b"REF-1").unwrap(),
            },
            CreditPayment::encode,
            CreditPayment::parse,
        );
        rt(
            &CurrencyConversion {
                provider_id: 1,
                issuer_event_id: 2,
                start_time: 3,
                old_currency: 826,
                new_currency: 978,
                factor: 11_700,
                trailing_digit: 0x40,
                flags: currency_change::CONVERT_BILLING,
            },
            CurrencyConversion::encode,
            CurrencyConversion::parse,
        );
        rt(
            &CancelTariff {
                provider_id: 1,
                issuer_tariff_id: 4,
                tariff_type: 0,
            },
            CancelTariff::encode,
            CancelTariff::parse,
        );
        assert_eq!(RECEIVED.len(), 17);
        assert_eq!(GENERATED.len(), 15);
    }

    fn co2(event: u32, start: u32, value: u32) -> Co2Value {
        Co2Value {
            provider_id: 1,
            issuer_event_id: event,
            start_time: start,
            tariff_type: 0,
            value,
            unit: 1,
            trailing_digit: 0x30,
        }
    }

    #[test]
    fn scheduled_store_keeps_current_and_next() {
        let mut s: Scheduled<Co2Value, 2> = Scheduled::new();
        let now = 1000;
        assert_eq!(s.publish(co2(1, 0, 100), now), Applied::Stored);
        assert_eq!(s.active(now, 0).unwrap().value, 100);
        assert_eq!(s.items()[0].start_time, now, "start now resolved");
        // The next instance.
        assert_eq!(s.publish(co2(2, 5000, 200), now), Applied::Stored);
        assert_eq!(s.next(now, 0).unwrap().value, 200);
        assert_eq!(s.active(6000, 0).unwrap().value, 200);
        // An older event at the same start is stale; a newer replaces.
        assert_eq!(s.publish(co2(1, 5000, 999), now), Applied::Stale);
        assert_eq!(s.publish(co2(3, 5000, 300), now), Applied::Stored);
        assert_eq!(s.items().len(), 2);
        // Full with two future-or-active instances: no room.
        assert_eq!(s.publish(co2(4, 9000, 400), now), Applied::Full);
        // Once the next became active the old current is history.
        assert_eq!(s.publish(co2(4, 9000, 400), 6000), Applied::Stored);
        assert_eq!(s.active(6000, 0).unwrap().value, 300);
        // Cancellation by provider and issuer event.
        assert_eq!(s.publish(co2(4, START_CANCEL, 0), 6000), Applied::Cancelled);
        assert_eq!(s.publish(co2(4, START_CANCEL, 0), 6000), Applied::NotFound);
        // Get: the active one first, then scheduled, honouring filters.
        s.publish(co2(5, 9000, 500), 6000);
        let mut out = Vec::new();
        s.scheduled(
            &GetScheduled {
                earliest_start: 0,
                min_issuer_event_id: ANY_EVENT,
                count: 0,
                tariff_type: Some(ANY_TARIFF_TYPE),
            },
            6000,
            &mut out,
        );
        let ids: Vec<u32, 2> = out.iter().map(|i| i.issuer_event_id).collect();
        assert_eq!(ids.as_slice(), &[3, 5]);
        out.clear();
        s.scheduled(
            &GetScheduled {
                earliest_start: 0,
                min_issuer_event_id: 5,
                count: 1,
                tariff_type: Some(tariff_type::RECEIVED),
            },
            6000,
            &mut out,
        );
        assert!(out.is_empty());
        s.expire(10_000);
        assert_eq!(s.items().len(), 1);
        assert_eq!(s.items()[0].issuer_event_id, 5);
    }

    #[test]
    fn tariff_store_assembles_and_cancels() {
        let mut store: TariffStore<2> = TariffStore::new();
        let now = 1000;
        assert_eq!(
            store.on_tariff_information(&info(10, 100, 0, charging_scheme::BLOCK_TOU_COMMON), now),
            Applied::Stored
        );
        assert_eq!(
            store.on_tariff_information(&info(9, 100, 0, charging_scheme::BLOCK_TOU_COMMON), now),
            Applied::Stale
        );
        let header = |index: u8, total: u8, control: u8| TariffPartHeader {
            provider_id: 1,
            issuer_event_id: 11,
            start_time: 0,
            issuer_tariff_id: 100,
            command_index: index,
            total_commands: total,
            control,
        };
        // A two-fragment matrix: tier 1 block 1 / 2 / 3 and tier 2.
        let mut e1 = Vec::new();
        e1.push(MatrixEntry {
            id: MatrixEntry::block(1, 0),
            price: 10,
        })
        .unwrap();
        e1.push(MatrixEntry {
            id: MatrixEntry::block(1, 1),
            price: 20,
        })
        .unwrap();
        let mut e2 = Vec::new();
        e2.push(MatrixEntry {
            id: MatrixEntry::block(1, 2),
            price: 30,
        })
        .unwrap();
        e2.push(MatrixEntry {
            id: MatrixEntry::block(2, 0),
            price: 15,
        })
        .unwrap();
        assert_eq!(
            store.on_price_matrix(&PriceMatrix {
                header: header(1, 2, 0),
                entries: e2
            }),
            Applied::Stored
        );
        assert!(!store.get(100).unwrap().matrix_complete());
        assert_eq!(store.get(100).unwrap().price(1, 1), None);
        assert_eq!(
            store.on_price_matrix(&PriceMatrix {
                header: header(0, 2, 0),
                entries: e1
            }),
            Applied::Stored
        );
        let t = store.get(100).unwrap();
        assert!(t.matrix_complete());
        assert_eq!(t.price(1, 3), Some(30));
        assert_eq!(t.price(2, 1), Some(15));
        assert_eq!(t.price(3, 1), None);
        // Thresholds for all tiers: 1000 and 2000.
        let mut sets = Vec::new();
        sets.push(TierThresholds {
            tier: 0,
            thresholds: Vec::from_slice(&[1000, 2000]).unwrap(),
        })
        .unwrap();
        assert_eq!(
            store.on_block_thresholds(&BlockThresholds {
                header: header(0, 1, THRESHOLDS_ALL_TIERS),
                sets
            }),
            Applied::Stored
        );
        let t = store.get(100).unwrap();
        assert_eq!(t.block_for(1, 999), Some(1));
        assert_eq!(t.block_for(1, 1000), Some(2));
        assert_eq!(t.block_for(2, 2500), Some(3));
        // Labels.
        let mut labels = Vec::new();
        labels
            .push((1u8, Vec::from_slice(b"Day").unwrap()))
            .unwrap();
        store.on_tier_labels(&TierLabels {
            provider_id: 1,
            issuer_event_id: 11,
            issuer_tariff_id: 100,
            command_index: 0,
            total_commands: 1,
            labels,
        });
        assert_eq!(store.get(100).unwrap().label(1), Some(&b"Day"[..]));
        // Unknown tariff parts are NOT_FOUND.
        assert_eq!(
            store.on_tier_labels(&TierLabels {
                provider_id: 1,
                issuer_event_id: 11,
                issuer_tariff_id: 7,
                command_index: 0,
                total_commands: 1,
                labels: Vec::new(),
            }),
            Applied::NotFound
        );
        // A second (next) tariff, then the store is full for a third
        // until the first is history.
        assert_eq!(
            store.on_tariff_information(&info(12, 101, 5000, charging_scheme::TOU), now),
            Applied::Stored
        );
        assert_eq!(
            store.on_tariff_information(&info(13, 102, 9000, charging_scheme::TOU), now),
            Applied::Full
        );
        assert_eq!(
            store.on_tariff_information(&info(13, 102, 9000, charging_scheme::TOU), 6000),
            Applied::Stored
        );
        assert_eq!(store.active(6000, 0).unwrap().info.issuer_tariff_id, 101);
        assert!(store.get(100).is_none());
        // Cancel discards everything of the tariff.
        assert_eq!(
            store.on_cancel(&CancelTariff {
                provider_id: 1,
                issuer_tariff_id: 101,
                tariff_type: 0
            }),
            Applied::Cancelled
        );
        assert!(store.get(101).is_none());
        assert_eq!(
            store.on_cancel(&CancelTariff {
                provider_id: 1,
                issuer_tariff_id: 101,
                tariff_type: 0
            }),
            Applied::NotFound
        );
    }
}
