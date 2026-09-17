//! The optional Metering cluster commands beyond Get Profile (SE 1.4a
//! D.3.2.3.1.2–D.3.2.3.1.14, D.3.3.3.1.2–D.3.3.3.1.15): mirroring,
//! fast poll mode, snapshots, sampling, notification schemes and supply
//! control — the codecs plus the server-side state they drive: a
//! [`FastPoll`] mode applying the D.3.4.2 limits, a [`Sampler`]
//! answering GetSampledData, a [`Snapshots`] store answering
//! GetSnapshot with offsets and fragmenting Publish Snapshot, a
//! [`SupplyControl`] applying Change Supply with its cancellation and
//! override rules, and an ESI-side [`MirrorTable`].

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::CommandId;

/// Server → client: RequestMirror (no payload).
pub const CMD_REQUEST_MIRROR: CommandId = CommandId(0x01);
/// Server → client: RemoveMirror (no payload).
pub const CMD_REMOVE_MIRROR: CommandId = CommandId(0x02);
/// Server → client: RequestFastPollModeResponse.
pub const CMD_REQUEST_FAST_POLL_MODE_RESPONSE: CommandId = CommandId(0x03);
/// Server → client: ScheduleSnapshotResponse.
pub const CMD_SCHEDULE_SNAPSHOT_RESPONSE: CommandId = CommandId(0x04);
/// Server → client: TakeSnapshotResponse.
pub const CMD_TAKE_SNAPSHOT_RESPONSE: CommandId = CommandId(0x05);
/// Server → client: PublishSnapshot.
pub const CMD_PUBLISH_SNAPSHOT: CommandId = CommandId(0x06);
/// Server → client: GetSampledDataResponse.
pub const CMD_GET_SAMPLED_DATA_RESPONSE: CommandId = CommandId(0x07);
/// Server → client: ConfigureMirror.
pub const CMD_CONFIGURE_MIRROR: CommandId = CommandId(0x08);
/// Server → client: ConfigureNotificationScheme (provisional).
pub const CMD_CONFIGURE_NOTIFICATION_SCHEME: CommandId = CommandId(0x09);
/// Server → client: ConfigureNotificationFlags (provisional).
pub const CMD_CONFIGURE_NOTIFICATION_FLAGS: CommandId = CommandId(0x0A);
/// Server → client: GetNotifiedMessage.
pub const CMD_GET_NOTIFIED_MESSAGE: CommandId = CommandId(0x0B);
/// Server → client: SupplyStatusResponse.
pub const CMD_SUPPLY_STATUS_RESPONSE: CommandId = CommandId(0x0C);
/// Server → client: StartSamplingResponse.
pub const CMD_START_SAMPLING_RESPONSE: CommandId = CommandId(0x0D);
/// Client → server: RequestMirrorResponse.
pub const CMD_REQUEST_MIRROR_RESPONSE: CommandId = CommandId(0x01);
/// Client → server: MirrorRemoved.
pub const CMD_MIRROR_REMOVED: CommandId = CommandId(0x02);
/// Client → server: RequestFastPollMode.
pub const CMD_REQUEST_FAST_POLL_MODE: CommandId = CommandId(0x03);
/// Client → server: ScheduleSnapshot.
pub const CMD_SCHEDULE_SNAPSHOT: CommandId = CommandId(0x04);
/// Client → server: TakeSnapshot.
pub const CMD_TAKE_SNAPSHOT: CommandId = CommandId(0x05);
/// Client → server: GetSnapshot.
pub const CMD_GET_SNAPSHOT: CommandId = CommandId(0x06);
/// Client → server: StartSampling.
pub const CMD_START_SAMPLING: CommandId = CommandId(0x07);
/// Client → server: GetSampledData.
pub const CMD_GET_SAMPLED_DATA: CommandId = CommandId(0x08);
/// Client → server: MirrorReportAttributeResponse.
pub const CMD_MIRROR_REPORT_ATTRIBUTE_RESPONSE: CommandId = CommandId(0x09);
/// Client → server: ResetLoadLimitCounter.
pub const CMD_RESET_LOAD_LIMIT_COUNTER: CommandId = CommandId(0x0A);
/// Client → server: ChangeSupply.
pub const CMD_CHANGE_SUPPLY: CommandId = CommandId(0x0B);
/// Client → server: LocalChangeSupply.
pub const CMD_LOCAL_CHANGE_SUPPLY: CommandId = CommandId(0x0C);
/// Client → server: SetSupplyStatus.
pub const CMD_SET_SUPPLY_STATUS: CommandId = CommandId(0x0D);
/// Client → server: SetUncontrolledFlowThreshold.
pub const CMD_SET_UNCONTROLLED_FLOW_THRESHOLD: CommandId = CommandId(0x0E);

/// Every server → client command (Table D-47).
pub const GENERATED: &[CommandId] = &[
    super::CMD_GET_PROFILE_RESPONSE,
    CMD_REQUEST_MIRROR,
    CMD_REMOVE_MIRROR,
    CMD_REQUEST_FAST_POLL_MODE_RESPONSE,
    CMD_SCHEDULE_SNAPSHOT_RESPONSE,
    CMD_TAKE_SNAPSHOT_RESPONSE,
    CMD_PUBLISH_SNAPSHOT,
    CMD_GET_SAMPLED_DATA_RESPONSE,
    CMD_CONFIGURE_MIRROR,
    CMD_CONFIGURE_NOTIFICATION_SCHEME,
    CMD_CONFIGURE_NOTIFICATION_FLAGS,
    CMD_GET_NOTIFIED_MESSAGE,
    CMD_SUPPLY_STATUS_RESPONSE,
    CMD_START_SAMPLING_RESPONSE,
];

/// Every client → server command (Table D-63).
pub const RECEIVED: &[CommandId] = &[
    super::CMD_GET_PROFILE,
    CMD_REQUEST_MIRROR_RESPONSE,
    CMD_MIRROR_REMOVED,
    CMD_REQUEST_FAST_POLL_MODE,
    CMD_SCHEDULE_SNAPSHOT,
    CMD_TAKE_SNAPSHOT,
    CMD_GET_SNAPSHOT,
    CMD_START_SAMPLING,
    CMD_GET_SAMPLED_DATA,
    CMD_MIRROR_REPORT_ATTRIBUTE_RESPONSE,
    CMD_RESET_LOAD_LIMIT_COUNTER,
    CMD_CHANGE_SUPPLY,
    CMD_LOCAL_CHANGE_SUPPLY,
    CMD_SET_SUPPLY_STATUS,
    CMD_SET_UNCONTROLLED_FLOW_THRESHOLD,
];

/// Longest fast poll mode (D.3.4.2).
pub const FAST_POLL_MAX_MINUTES: u8 = 15;
/// Endpoint id returned when the ESI cannot mirror.
pub const MIRROR_UNAVAILABLE: u16 = 0xffff;
/// Sample id returned when no further sampling session is possible.
pub const SAMPLE_ID_UNAVAILABLE: u16 = 0xffff;
/// An invalid sample / interval.
pub const SAMPLE_INVALID: u32 = 0x00ff_ffff;
/// Start time cancelling a StartSampling / ChangeSupply.
pub const CANCEL: u32 = 0xffff_ffff;
/// Start time "now".
pub const NOW: u32 = 0;
/// Snapshot cause selecting every snapshot.
pub const ANY_CAUSE: u32 = 0xffff_ffff;
/// Samples kept per session.
pub const MAX_SAMPLES: usize = 32;
/// Samples carried by one GetSampledDataResponse.
pub const MAX_SAMPLES_PER_COMMAND: usize = 16;
/// Snapshot sub-payload bytes kept.
pub const MAX_SNAPSHOT_PAYLOAD: usize = 64;
/// Snapshot sub-payload bytes per Publish Snapshot fragment.
pub const SNAPSHOT_FRAGMENT: usize = 32;
/// Tier summations in a TOU snapshot.
pub const MAX_TIERS: usize = 8;
/// Notification flag attributes in a MirrorReportAttributeResponse.
pub const MAX_NOTIFICATION_FLAGS: usize = 8;
/// Snapshot schedules per ScheduleSnapshot command.
pub const MAX_SCHEDULES: usize = 4;

/// Snapshot Cause bits (Table D-52).
pub mod snapshot_cause {
    /// General.
    pub const GENERAL: u32 = 1 << 0;
    /// End of billing period.
    pub const END_OF_BILLING_PERIOD: u32 = 1 << 1;
    /// End of block period.
    pub const END_OF_BLOCK_PERIOD: u32 = 1 << 2;
    /// Change of tariff information.
    pub const CHANGE_OF_TARIFF: u32 = 1 << 3;
    /// Change of price matrix.
    pub const CHANGE_OF_PRICE_MATRIX: u32 = 1 << 4;
    /// Change of block thresholds.
    pub const CHANGE_OF_BLOCK_THRESHOLDS: u32 = 1 << 5;
    /// Change of calorific value.
    pub const CHANGE_OF_CV: u32 = 1 << 6;
    /// Change of conversion factor.
    pub const CHANGE_OF_CF: u32 = 1 << 7;
    /// Change of calendar.
    pub const CHANGE_OF_CALENDAR: u32 = 1 << 8;
    /// Critical peak pricing.
    pub const CRITICAL_PEAK_PRICING: u32 = 1 << 9;
    /// Manually triggered from a client.
    pub const MANUALLY_TRIGGERED: u32 = 1 << 10;
    /// End of resolve period.
    pub const END_OF_RESOLVE_PERIOD: u32 = 1 << 11;
    /// Change of tenancy.
    pub const CHANGE_OF_TENANCY: u32 = 1 << 12;
    /// Change of supplier.
    pub const CHANGE_OF_SUPPLIER: u32 = 1 << 13;
    /// Change of meter mode.
    pub const CHANGE_OF_MODE: u32 = 1 << 14;
    /// Debt payment.
    pub const DEBT_PAYMENT: u32 = 1 << 15;
    /// Scheduled snapshot.
    pub const SCHEDULED: u32 = 1 << 16;
    /// OTA firmware download.
    pub const OTA_DOWNLOAD: u32 = 1 << 17;
}

/// Snapshot payload types (Table D-53).
pub mod snapshot_type {
    /// TOU information set, delivered registers.
    pub const TOU_DELIVERED: u8 = 0;
    /// TOU information set, received registers.
    pub const TOU_RECEIVED: u8 = 1;
    /// Block tier information set, delivered.
    pub const BLOCK_DELIVERED: u8 = 2;
    /// Block tier information set, received.
    pub const BLOCK_RECEIVED: u8 = 3;
    /// TOU delivered, no billing.
    pub const TOU_DELIVERED_NO_BILLING: u8 = 4;
    /// TOU received, no billing.
    pub const TOU_RECEIVED_NO_BILLING: u8 = 5;
    /// Block delivered, no billing.
    pub const BLOCK_DELIVERED_NO_BILLING: u8 = 6;
    /// Block received, no billing.
    pub const BLOCK_RECEIVED_NO_BILLING: u8 = 7;
    /// Data unavailable.
    pub const DATA_UNAVAILABLE: u8 = 128;
}

/// Snapshot schedule confirmations (Table D-50).
pub mod schedule_confirmation {
    /// Accepted.
    pub const ACCEPTED: u8 = 0x00;
    /// Snapshot type not supported.
    pub const TYPE_NOT_SUPPORTED: u8 = 0x01;
    /// Snapshot cause not supported.
    pub const CAUSE_NOT_SUPPORTED: u8 = 0x02;
    /// Schedule not currently available.
    pub const NOT_AVAILABLE: u8 = 0x03;
    /// Schedules not supported.
    pub const NOT_SUPPORTED: u8 = 0x04;
    /// Insufficient space.
    pub const INSUFFICIENT_SPACE: u8 = 0x05;
}

/// Snapshot confirmations (Table D-51).
pub mod snapshot_confirmation {
    /// Accepted.
    pub const ACCEPTED: u8 = 0x00;
    /// Cause not supported.
    pub const CAUSE_NOT_SUPPORTED: u8 = 0x01;
}

/// Sample types (Table D-54).
pub mod sample_type {
    /// Consumption delivered.
    pub const CONSUMPTION_DELIVERED: u8 = 0;
    /// Consumption received.
    pub const CONSUMPTION_RECEIVED: u8 = 1;
    /// Reactive consumption delivered.
    pub const REACTIVE_DELIVERED: u8 = 2;
    /// Reactive consumption received.
    pub const REACTIVE_RECEIVED: u8 = 3;
    /// Instantaneous demand (signed samples).
    pub const INSTANTANEOUS_DEMAND: u8 = 4;
}

/// Notification schemes (Figure D-31).
pub mod notification_scheme {
    /// None defined.
    pub const NONE: u8 = 0x00;
    /// Predefined scheme A.
    pub const A: u8 = 0x01;
    /// Predefined scheme B.
    pub const B: u8 = 0x02;

    /// Whether a scheme value may be defined by ConfigureNotificationScheme
    /// (the predefined ones may not be overwritten, D.3.2.3.1.10).
    pub const fn is_configurable(scheme: u8) -> bool {
        matches!(scheme, 0x03..=0xfe)
    }
}

/// Supply status (Tables D-56, D-68).
pub mod supply_status {
    /// Supply off.
    pub const OFF: u8 = 0x00;
    /// Supply off / armed.
    pub const OFF_ARMED: u8 = 0x01;
    /// Supply on.
    pub const ON: u8 = 0x02;
    /// Unchanged (SetSupplyStatus only).
    pub const UNCHANGED: u8 = 0x03;
}

/// Supply control bits (Table D-66).
pub mod supply_control {
    /// A Supply Status Response is required.
    pub const ACKNOWLEDGE_REQUIRED: u8 = 0x01;
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

macro_rules! simple_codec {
    ($(#[$m:meta])* $name:ident { $($(#[$fm:meta])* $field:ident : $ty:ident),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct $name {
            $($(#[$fm])* pub $field: $ty,)*
        }

        impl $name {
            /// Parses the payload.
            pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
                let mut r = Reader::new(bytes);
                Ok($name {
                    $($field: simple_codec!(@read r, $ty),)*
                })
            }

            /// Encodes the payload.
            pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
                $(simple_codec!(@write w, self.$field, $ty);)*
                Ok(())
            }
        }
    };
    (@read $r:ident, u8) => { $r.u8()? };
    (@read $r:ident, u16) => { $r.u16_le()? };
    (@read $r:ident, u32) => { $r.u32_le()? };
    (@read $r:ident, bool) => { $r.u8()? != 0 };
    (@write $w:ident, $v:expr, u8) => { $w.u8($v)? };
    (@write $w:ident, $v:expr, u16) => { $w.u16_le($v)? };
    (@write $w:ident, $v:expr, u32) => { $w.u32_le($v)? };
    (@write $w:ident, $v:expr, bool) => { $w.u8(u8::from($v))? };
}

simple_codec!(
    /// RequestFastPollModeResponse (D.3.2.3.1.4).
    FastPollModeResponse {
        /// Applied update period in seconds.
        applied_update_period: u8,
        /// When fast poll mode ends.
        end_time: u32,
    }
);

simple_codec!(
    /// TakeSnapshotResponse (D.3.2.3.1.6).
    TakeSnapshotResponse {
        /// Snapshot id.
        snapshot_id: u32,
        /// Confirmation (Table D-51).
        confirmation: u8,
    }
);

simple_codec!(
    /// ConfigureMirror (D.3.2.3.1.9).
    ConfigureMirror {
        /// Issuer event id.
        issuer_event_id: u32,
        /// Reporting interval in seconds (24 bits used).
        reporting_interval: u32,
        /// Whether MirrorReportAttributeResponse is enabled.
        notification_reporting: bool,
        /// Notification scheme (Figure D-31).
        scheme: u8,
    }
);

simple_codec!(
    /// ConfigureNotificationScheme (D.3.2.3.1.10, provisional).
    ConfigureNotificationScheme {
        /// Issuer event id.
        issuer_event_id: u32,
        /// Scheme (0x03–0xfe).
        scheme: u8,
        /// Notification flag order (eight nibbles, Table D-55).
        flag_order: u32,
    }
);

simple_codec!(
    /// GetNotifiedMessage (D.3.2.3.1.12).
    GetNotifiedMessage {
        /// Scheme.
        scheme: u8,
        /// Notification flag attribute id.
        flag_attribute: u16,
        /// The flags requested.
        flags: u32,
    }
);

simple_codec!(
    /// SupplyStatusResponse (D.3.2.3.1.13).
    SupplyStatusResponse {
        /// Provider id.
        provider_id: u32,
        /// Issuer event id.
        issuer_event_id: u32,
        /// Implementation time.
        implementation_time: u32,
        /// Supply status after implementation (Table D-56).
        status: u8,
    }
);

simple_codec!(
    /// StartSamplingResponse (D.3.2.3.1.14).
    StartSamplingResponse {
        /// Sample id (`SAMPLE_ID_UNAVAILABLE`).
        sample_id: u16,
    }
);

simple_codec!(
    /// RequestMirrorResponse (D.3.3.3.1.2).
    RequestMirrorResponse {
        /// Mirror endpoint (`MIRROR_UNAVAILABLE`).
        endpoint: u16,
    }
);

simple_codec!(
    /// MirrorRemoved (D.3.3.3.1.3).
    MirrorRemoved {
        /// The endpoint that held the mirror.
        endpoint: u16,
    }
);

simple_codec!(
    /// RequestFastPollMode (D.3.3.3.1.4).
    RequestFastPollMode {
        /// Desired update period in seconds.
        update_period: u8,
        /// Desired duration in minutes (≤ 15).
        duration_minutes: u8,
    }
);

simple_codec!(
    /// TakeSnapshot (D.3.3.3.1.6).
    TakeSnapshot {
        /// Cause (Table D-52).
        cause: u32,
    }
);

simple_codec!(
    /// GetSnapshot (D.3.3.3.1.7).
    GetSnapshot {
        /// Earliest snapshot time.
        earliest_start: u32,
        /// Latest snapshot time.
        latest_end: u32,
        /// Which matching snapshot (0: the first).
        offset: u8,
        /// Cause filter (`ANY_CAUSE`).
        cause: u32,
    }
);

simple_codec!(
    /// StartSampling (D.3.3.3.1.8).
    StartSampling {
        /// Issuer event id.
        issuer_event_id: u32,
        /// Start time (`NOW`, `CANCEL`).
        start_time: u32,
        /// Sample type (Table D-54).
        sample_type: u8,
        /// Interval in seconds.
        interval: u16,
        /// Samples to take.
        max_samples: u16,
    }
);

simple_codec!(
    /// GetSampledData (D.3.3.3.1.9).
    GetSampledData {
        /// Sample id.
        sample_id: u16,
        /// Earliest sample time.
        earliest_time: u32,
        /// Sample type.
        sample_type: u8,
        /// Samples wanted.
        count: u16,
    }
);

simple_codec!(
    /// ResetLoadLimitCounter (D.3.3.3.1.11).
    ResetLoadLimitCounter {
        /// Provider id.
        provider_id: u32,
        /// Issuer event id.
        issuer_event_id: u32,
    }
);

simple_codec!(
    /// ChangeSupply (D.3.3.3.1.12).
    ChangeSupply {
        /// Provider id.
        provider_id: u32,
        /// Issuer event id.
        issuer_event_id: u32,
        /// When the change was requested.
        request_time: u32,
        /// When to apply (`NOW`, `CANCEL`).
        implementation_time: u32,
        /// Proposed supply status (Table D-56).
        proposed_status: u8,
        /// Supply control bits (Table D-66).
        control: u8,
    }
);

simple_codec!(
    /// LocalChangeSupply (D.3.3.3.1.13).
    LocalChangeSupply {
        /// OFF_ARMED or ON (Table D-67).
        proposed_status: u8,
    }
);

simple_codec!(
    /// SetSupplyStatus (D.3.3.3.1.14).
    SetSupplyStatus {
        /// Issuer event id.
        issuer_event_id: u32,
        /// Status after a tamper event.
        tamper: u8,
        /// Status after battery depletion.
        depletion: u8,
        /// Status after an uncontrolled flow.
        uncontrolled_flow: u8,
        /// Status in load-limit state.
        load_limit: u8,
    }
);

simple_codec!(
    /// SetUncontrolledFlowThreshold (D.3.3.3.1.15).
    SetUncontrolledFlowThreshold {
        /// Provider id.
        provider_id: u32,
        /// Issuer event id.
        issuer_event_id: u32,
        /// Threshold (0: unused).
        threshold: u16,
        /// Unit of measure.
        unit: u8,
        /// Multiplier.
        multiplier: u16,
        /// Divisor.
        divisor: u16,
        /// Stabilisation period.
        stabilisation_period: u8,
        /// Measurement period.
        measurement_period: u16,
    }
);

impl ConfigureMirror {
    /// Parses the payload (the interval is 24 bits on the wire).
    pub fn parse_wire(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ConfigureMirror {
            issuer_event_id: r.u32_le()?,
            reporting_interval: r.u24_le()?,
            notification_reporting: r.u8()? != 0,
            scheme: r.u8()?,
        })
    }

    /// Encodes the payload with the 24-bit interval.
    pub fn encode_wire(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u24_le(self.reporting_interval & 0x00ff_ffff)?;
        w.u8(u8::from(self.notification_reporting))?;
        w.u8(self.scheme)
    }
}

/// ScheduleSnapshotResponse (D.3.2.3.1.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScheduleSnapshotResponse {
    /// Issuer event id of the ScheduleSnapshot.
    pub issuer_event_id: u32,
    /// (schedule id, confirmation) pairs.
    pub confirmations: Vec<(u8, u8), MAX_SCHEDULES>,
}

impl ScheduleSnapshotResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let issuer_event_id = r.u32_le()?;
        let mut confirmations = Vec::new();
        while !r.is_empty() {
            let c = (r.u8()?, r.u8()?);
            confirmations
                .push(c)
                .map_err(|_| CodecError::Unrepresentable {
                    field: "confirmations",
                })?;
        }
        Ok(ScheduleSnapshotResponse {
            issuer_event_id,
            confirmations,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        for (id, c) in &self.confirmations {
            w.u8(*id)?;
            w.u8(*c)?;
        }
        Ok(())
    }
}

/// A snapshot schedule (Figure D-43).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SnapshotSchedule {
    /// Schedule id (1–254).
    pub schedule_id: u8,
    /// Start time.
    pub start_time: u32,
    /// Schedule bitmap (Table D-65; 24 bits).
    pub schedule: u32,
    /// Payload type (Table D-53).
    pub payload_type: u8,
    /// Cause (Table D-52).
    pub cause: u32,
}

/// ScheduleSnapshot (D.3.3.3.1.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScheduleSnapshot {
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// Schedules of this fragment.
    pub schedules: Vec<SnapshotSchedule, MAX_SCHEDULES>,
}

impl ScheduleSnapshot {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let issuer_event_id = r.u32_le()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let mut schedules = Vec::new();
        while !r.is_empty() {
            let s = SnapshotSchedule {
                schedule_id: r.u8()?,
                start_time: r.u32_le()?,
                schedule: r.u24_le()?,
                payload_type: r.u8()?,
                cause: r.u32_le()?,
            };
            schedules
                .push(s)
                .map_err(|_| CodecError::Unrepresentable { field: "schedules" })?;
        }
        Ok(ScheduleSnapshot {
            issuer_event_id,
            command_index,
            total_commands,
            schedules,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        for s in &self.schedules {
            w.u8(s.schedule_id)?;
            w.u32_le(s.start_time)?;
            w.u24_le(s.schedule & 0x00ff_ffff)?;
            w.u8(s.payload_type)?;
            w.u32_le(s.cause)?;
        }
        Ok(())
    }
}

/// PublishSnapshot (D.3.2.3.1.7): the leading fields with a fragment of
/// the type-dependent sub-payload.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishSnapshot {
    /// Snapshot id.
    pub snapshot_id: u32,
    /// When it was taken.
    pub time: u32,
    /// Snapshots matching the request.
    pub total_found: u8,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// Cause.
    pub cause: u32,
    /// Payload type.
    pub payload_type: u8,
    /// The sub-payload fragment.
    pub payload: Vec<u8, MAX_SNAPSHOT_PAYLOAD>,
}

impl PublishSnapshot {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(PublishSnapshot {
            snapshot_id: r.u32_le()?,
            time: r.u32_le()?,
            total_found: r.u8()?,
            command_index: r.u8()?,
            total_commands: r.u8()?,
            cause: r.u32_le()?,
            payload_type: r.u8()?,
            payload: Vec::from_slice(r.take_rest()).map_err(|_| CodecError::Unrepresentable {
                field: "snapshot payload",
            })?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.snapshot_id)?;
        w.u32_le(self.time)?;
        w.u8(self.total_found)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        w.u32_le(self.cause)?;
        w.u8(self.payload_type)?;
        w.bytes(&self.payload)
    }
}

/// The TOU information snapshot sub-payload (Figures D-19 / D-20;
/// types 0, 1 and, without the billing fields, 4, 5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TouSnapshot {
    /// Current summation.
    pub summation: u64,
    /// Billing: (bill to date, its timestamp, projected bill, its
    /// timestamp, trailing digit); absent for the no-billing types.
    pub billing: Option<(u32, u32, u32, u32, u8)>,
    /// Tier summations, tier 1 first.
    pub tiers: Vec<u64, MAX_TIERS>,
}

impl TouSnapshot {
    /// Parses a complete sub-payload of `payload_type`.
    pub fn parse(payload_type: u8, bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let summation = read_u48(&mut r)?;
        let billing = match payload_type {
            snapshot_type::TOU_DELIVERED | snapshot_type::TOU_RECEIVED => {
                Some((r.u32_le()?, r.u32_le()?, r.u32_le()?, r.u32_le()?, r.u8()?))
            }
            snapshot_type::TOU_DELIVERED_NO_BILLING | snapshot_type::TOU_RECEIVED_NO_BILLING => {
                None
            }
            other => {
                return Err(CodecError::InvalidField {
                    field: "snapshot payload type",
                    value: u32::from(other),
                });
            }
        };
        let n = r.u8()?;
        let mut tiers = Vec::new();
        for _ in 0..n {
            tiers
                .push(read_u48(&mut r)?)
                .map_err(|_| CodecError::Unrepresentable { field: "tiers" })?;
        }
        Ok(TouSnapshot {
            summation,
            billing,
            tiers,
        })
    }

    /// Encodes the sub-payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        write_u48(w, self.summation)?;
        if let Some((bill, bill_ts, projected, projected_ts, digit)) = self.billing {
            w.u32_le(bill)?;
            w.u32_le(bill_ts)?;
            w.u32_le(projected)?;
            w.u32_le(projected_ts)?;
            w.u8(digit)?;
        }
        w.u8(u8::try_from(self.tiers.len())
            .map_err(|_| CodecError::Unrepresentable { field: "tiers" })?)?;
        for t in &self.tiers {
            write_u48(w, *t)?;
        }
        Ok(())
    }

    /// The payload type of this snapshot for `received` registers.
    pub const fn payload_type(&self, received: bool) -> u8 {
        match (self.billing.is_some(), received) {
            (true, false) => snapshot_type::TOU_DELIVERED,
            (true, true) => snapshot_type::TOU_RECEIVED,
            (false, false) => snapshot_type::TOU_DELIVERED_NO_BILLING,
            (false, true) => snapshot_type::TOU_RECEIVED_NO_BILLING,
        }
    }
}

/// GetSampledDataResponse (D.3.2.3.1.8).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SampledDataResponse {
    /// Sample id.
    pub sample_id: u16,
    /// Time of the first sample.
    pub start_time: u32,
    /// Sample type.
    pub sample_type: u8,
    /// Interval in seconds.
    pub interval: u16,
    /// Samples, oldest first (24-bit; signed for instantaneous demand).
    pub samples: Vec<u32, MAX_SAMPLES_PER_COMMAND>,
}

impl SampledDataResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let sample_id = r.u16_le()?;
        let start_time = r.u32_le()?;
        let sample_type = r.u8()?;
        let interval = r.u16_le()?;
        let n = r.u16_le()?;
        let mut samples = Vec::new();
        for _ in 0..n {
            samples
                .push(r.u24_le()?)
                .map_err(|_| CodecError::Unrepresentable { field: "samples" })?;
        }
        Ok(SampledDataResponse {
            sample_id,
            start_time,
            sample_type,
            interval,
            samples,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.sample_id)?;
        w.u32_le(self.start_time)?;
        w.u8(self.sample_type)?;
        w.u16_le(self.interval)?;
        w.u16_le(
            u16::try_from(self.samples.len())
                .map_err(|_| CodecError::Unrepresentable { field: "samples" })?,
        )?;
        for s in &self.samples {
            w.u24_le(*s & 0x00ff_ffff)?;
        }
        Ok(())
    }
}

/// A bit-field allocation of ConfigureNotificationFlags (Figure D-34).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BitFieldAllocation {
    /// Cluster.
    pub cluster: u16,
    /// Manufacturer code.
    pub manufacturer: u16,
    /// Command ids, in bit order.
    pub commands: Vec<u8, 32>,
}

/// ConfigureNotificationFlags (D.3.2.3.1.11, provisional).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConfigureNotificationFlags {
    /// Issuer event id.
    pub issuer_event_id: u32,
    /// Scheme.
    pub scheme: u8,
    /// Notification flag attribute id (flags 2–8).
    pub flag_attribute: u16,
    /// Allocations, in bit order.
    pub allocations: Vec<BitFieldAllocation, 4>,
}

impl ConfigureNotificationFlags {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let issuer_event_id = r.u32_le()?;
        let scheme = r.u8()?;
        let flag_attribute = r.u16_le()?;
        let mut allocations = Vec::new();
        while !r.is_empty() {
            let cluster = r.u16_le()?;
            let manufacturer = r.u16_le()?;
            let n = r.u8()?;
            let mut commands = Vec::new();
            for _ in 0..n {
                commands
                    .push(r.u8()?)
                    .map_err(|_| CodecError::Unrepresentable { field: "commands" })?;
            }
            allocations
                .push(BitFieldAllocation {
                    cluster,
                    manufacturer,
                    commands,
                })
                .map_err(|_| CodecError::Unrepresentable {
                    field: "allocations",
                })?;
        }
        Ok(ConfigureNotificationFlags {
            issuer_event_id,
            scheme,
            flag_attribute,
            allocations,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u8(self.scheme)?;
        w.u16_le(self.flag_attribute)?;
        for a in &self.allocations {
            w.u16_le(a.cluster)?;
            w.u16_le(a.manufacturer)?;
            w.u8(u8::try_from(a.commands.len())
                .map_err(|_| CodecError::Unrepresentable { field: "commands" })?)?;
            w.bytes(&a.commands)?;
        }
        Ok(())
    }
}

/// MirrorReportAttributeResponse (D.3.3.3.1.10).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MirrorReportAttributeResponse {
    /// Scheme.
    pub scheme: u8,
    /// Notification flags, in the scheme's order.
    pub flags: Vec<u32, MAX_NOTIFICATION_FLAGS>,
}

impl MirrorReportAttributeResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let scheme = r.u8()?;
        let mut flags = Vec::new();
        while !r.is_empty() {
            flags
                .push(r.u32_le()?)
                .map_err(|_| CodecError::Unrepresentable { field: "flags" })?;
        }
        Ok(MirrorReportAttributeResponse { scheme, flags })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.scheme)?;
        for f in &self.flags {
            w.u32_le(*f)?;
        }
        Ok(())
    }
}

// ----- Server-side state -----

/// Fast poll mode of a metering server (D.3.2.3.1.4, D.3.4.2).
#[derive(Clone, Copy, Debug)]
pub struct FastPoll {
    /// `FastPollUpdatePeriod`: the shortest period offered, seconds.
    pub minimum_period: u8,
    /// `DefaultUpdatePeriod`, seconds.
    pub default_period: u8,
    active: Option<(u8, u32)>,
}

impl FastPoll {
    /// A server with the given minimum and default periods.
    pub const fn new(minimum_period: u8, default_period: u8) -> Self {
        FastPoll {
            minimum_period,
            default_period,
            active: None,
        }
    }

    /// Handles a RequestFastPollMode at `now`: the applied period is at
    /// least the minimum; a mode already running is not extended and
    /// its end time is answered; the duration is capped at 15 minutes.
    pub fn request(&mut self, req: &RequestFastPollMode, now: u32) -> FastPollModeResponse {
        if let Some((period, end)) = self.active
            && now < end
        {
            return FastPollModeResponse {
                applied_update_period: period,
                end_time: end,
            };
        }
        let period = req.update_period.max(self.minimum_period);
        let minutes = req.duration_minutes.min(FAST_POLL_MAX_MINUTES);
        let end = now.saturating_add(u32::from(minutes) * 60);
        self.active = Some((period, end));
        FastPollModeResponse {
            applied_update_period: period,
            end_time: end,
        }
    }

    /// The update period in force at `now`.
    pub fn period(&self, now: u32) -> u8 {
        match self.active {
            Some((p, end)) if now < end => p,
            _ => self.default_period,
        }
    }

    /// When fast poll mode ends, while active.
    pub fn end_time(&self, now: u32) -> Option<u32> {
        self.active.filter(|(_, end)| now < *end).map(|(_, e)| e)
    }
}

/// A sampling session (D.3.3.3.1.8).
#[derive(Clone, Debug)]
pub struct Session {
    /// Sample id.
    pub sample_id: u16,
    /// Issuer event id of the StartSampling.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Sample type.
    pub sample_type: u8,
    /// Interval in seconds.
    pub interval: u16,
    /// Samples to take.
    pub max_samples: u16,
    /// Samples taken, oldest first.
    pub samples: Vec<u32, MAX_SAMPLES>,
}

impl Session {
    /// Time of the sample at `index`.
    pub fn sample_time(&self, index: usize) -> u32 {
        self.start_time.saturating_add(
            u32::try_from(index)
                .unwrap_or(u32::MAX)
                .saturating_mul(u32::from(self.interval)),
        )
    }

    /// Time of the next sample to take, while the session is open.
    pub fn next_sample_time(&self) -> Option<u32> {
        (self.samples.len() < usize::from(self.max_samples) && !self.samples.is_full())
            .then(|| self.sample_time(self.samples.len()))
    }
}

/// Sampling sessions of a metering server (`N` at a time).
#[derive(Clone, Debug, Default)]
pub struct Sampler<const N: usize> {
    sessions: Vec<Session, N>,
    next_id: u16,
}

impl<const N: usize> Sampler<N> {
    /// No sessions; ids start at 1 (0 may be reserved for profile data).
    pub const fn new() -> Self {
        Sampler {
            sessions: Vec::new(),
            next_id: 1,
        }
    }

    /// Handles a StartSampling at `now`: a new session's id, `None`
    /// for a cancellation that removed nothing (NOT_FOUND) or a repeated
    /// issuer event id, `Some(SAMPLE_ID_UNAVAILABLE)` when full.
    pub fn start(&mut self, req: &StartSampling, now: u32) -> Option<StartSamplingResponse> {
        if req.start_time == CANCEL {
            let before = self.sessions.len();
            self.sessions
                .retain(|s| s.issuer_event_id != req.issuer_event_id);
            return (self.sessions.len() != before).then_some(StartSamplingResponse {
                sample_id: SAMPLE_ID_UNAVAILABLE,
            });
        }
        if self
            .sessions
            .iter()
            .any(|s| s.issuer_event_id == req.issuer_event_id)
        {
            return None;
        }
        if self.sessions.is_full() {
            return Some(StartSamplingResponse {
                sample_id: SAMPLE_ID_UNAVAILABLE,
            });
        }
        let sample_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == SAMPLE_ID_UNAVAILABLE || self.next_id == 0 {
            self.next_id = 1;
        }
        let _ = self.sessions.push(Session {
            sample_id,
            issuer_event_id: req.issuer_event_id,
            start_time: if req.start_time == NOW {
                now
            } else {
                req.start_time
            },
            sample_type: req.sample_type,
            interval: req.interval,
            max_samples: req.max_samples,
            samples: Vec::new(),
        });
        Some(StartSamplingResponse { sample_id })
    }

    /// Records a sample for every session of `sample_type` whose next
    /// sample time has come.
    pub fn sample(&mut self, sample_type: u8, value: u32, now: u32) {
        for s in self.sessions.iter_mut() {
            if s.sample_type == sample_type && s.next_sample_time().is_some_and(|t| t <= now) {
                let _ = s.samples.push(value & 0x00ff_ffff);
            }
        }
    }

    /// The earliest next sample time over the open sessions.
    pub fn next_deadline(&self) -> Option<u32> {
        self.sessions
            .iter()
            .filter_map(Session::next_sample_time)
            .min()
    }

    /// Answers a GetSampledData: the samples of the session from the
    /// earliest time, at most `count` and at most the session's maximum;
    /// `None` for NOT_FOUND.
    pub fn sampled_data(&self, req: &GetSampledData) -> Option<SampledDataResponse> {
        let s = self
            .sessions
            .iter()
            .find(|s| s.sample_id == req.sample_id && s.sample_type == req.sample_type)?;
        let first = (0..s.samples.len()).find(|i| s.sample_time(*i) >= req.earliest_time)?;
        let limit = usize::from(req.count.min(s.max_samples)).min(MAX_SAMPLES_PER_COMMAND);
        let mut samples = Vec::new();
        for v in s.samples.iter().skip(first).take(limit) {
            let _ = samples.push(*v);
        }
        if samples.is_empty() {
            return None;
        }
        Some(SampledDataResponse {
            sample_id: s.sample_id,
            start_time: s.sample_time(first),
            sample_type: s.sample_type,
            interval: s.interval,
            samples,
        })
    }

    /// The sessions.
    pub fn sessions(&self) -> &[Session] {
        &self.sessions
    }
}

/// A stored snapshot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Snapshot {
    /// Snapshot id.
    pub id: u32,
    /// When it was taken.
    pub time: u32,
    /// Cause.
    pub cause: u32,
    /// Payload type.
    pub payload_type: u8,
    /// The complete sub-payload.
    pub payload: Vec<u8, MAX_SNAPSHOT_PAYLOAD>,
}

/// Snapshot store of a metering server (`N` snapshots, oldest evicted).
#[derive(Clone, Debug, Default)]
pub struct Snapshots<const N: usize> {
    snapshots: Vec<Snapshot, N>,
    next_id: u32,
}

impl<const N: usize> Snapshots<N> {
    /// An empty store.
    pub const fn new() -> Self {
        Snapshots {
            snapshots: Vec::new(),
            next_id: 1,
        }
    }

    /// Stores a snapshot taken at `now` and returns its id.
    pub fn take(&mut self, cause: u32, payload_type: u8, payload: &[u8], now: u32) -> Option<u32> {
        let payload = Vec::from_slice(payload).ok()?;
        if self.snapshots.is_full() {
            self.snapshots.remove(0);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let _ = self.snapshots.push(Snapshot {
            id,
            time: now,
            cause,
            payload_type,
            payload,
        });
        Some(id)
    }

    /// Handles a TakeSnapshot (D.3.3.3.1.6.3): the snapshot is taken
    /// with the Manually Triggered cause added; `supported` says
    /// whether the requested cause can be honoured.
    pub fn on_take_snapshot(
        &mut self,
        req: &TakeSnapshot,
        supported: bool,
        payload_type: u8,
        payload: &[u8],
        now: u32,
    ) -> TakeSnapshotResponse {
        if !supported {
            return TakeSnapshotResponse {
                snapshot_id: 0,
                confirmation: snapshot_confirmation::CAUSE_NOT_SUPPORTED,
            };
        }
        let cause = req.cause | snapshot_cause::MANUALLY_TRIGGERED;
        match self.take(cause, payload_type, payload, now) {
            Some(id) => TakeSnapshotResponse {
                snapshot_id: id,
                confirmation: snapshot_confirmation::ACCEPTED,
            },
            None => TakeSnapshotResponse {
                snapshot_id: 0,
                confirmation: snapshot_confirmation::CAUSE_NOT_SUPPORTED,
            },
        }
    }

    /// Answers a GetSnapshot (D.3.3.3.1.7.3): the Publish Snapshot
    /// fragments of the `offset`-th matching snapshot, or `None` for
    /// NOT_FOUND.
    pub fn get(&self, req: &GetSnapshot, out: &mut Vec<PublishSnapshot, 4>) -> Option<()> {
        let matching = self.snapshots.iter().filter(|s| {
            s.time >= req.earliest_start
                && s.time <= req.latest_end
                && (req.cause == ANY_CAUSE || s.cause & req.cause != 0)
        });
        let total = matching.clone().count();
        let s = matching.clone().nth(usize::from(req.offset))?;
        let chunks = s.payload.chunks(SNAPSHOT_FRAGMENT);
        let total_commands = u8::try_from(chunks.len().max(1)).unwrap_or(u8::MAX);
        let total_found = u8::try_from(total).unwrap_or(u8::MAX);
        if s.payload.is_empty() {
            let _ = out.push(PublishSnapshot {
                snapshot_id: s.id,
                time: s.time,
                total_found,
                command_index: 0,
                total_commands,
                cause: s.cause,
                payload_type: s.payload_type,
                payload: Vec::new(),
            });
            return Some(());
        }
        for (i, chunk) in chunks.enumerate() {
            let _ = out.push(PublishSnapshot {
                snapshot_id: s.id,
                time: s.time,
                total_found,
                command_index: u8::try_from(i).unwrap_or(u8::MAX),
                total_commands,
                cause: s.cause,
                payload_type: s.payload_type,
                payload: Vec::from_slice(chunk).unwrap_or_default(),
            });
        }
        Some(())
    }

    /// The snapshots held.
    pub fn snapshots(&self) -> &[Snapshot] {
        &self.snapshots
    }
}

/// Reassembles a fragmented Publish Snapshot on the client.
#[derive(Clone, Debug, Default)]
pub struct SnapshotAssembler {
    current: Option<Snapshot>,
    received: u16,
    total: u8,
}

impl SnapshotAssembler {
    /// Feeds a fragment; the complete snapshot when all arrived.
    pub fn feed(&mut self, p: &PublishSnapshot) -> Option<Snapshot> {
        let restart = self.current.as_ref().is_none_or(|c| c.id != p.snapshot_id)
            || self.total != p.total_commands.max(1);
        if restart {
            self.current = Some(Snapshot {
                id: p.snapshot_id,
                time: p.time,
                cause: p.cause,
                payload_type: p.payload_type,
                payload: Vec::new(),
            });
            self.received = 0;
            self.total = p.total_commands.max(1);
        }
        let bit = 1u16 << (p.command_index & 0x0f);
        if self.received & bit != 0 {
            return None;
        }
        let c = self.current.as_mut()?;
        if c.payload.extend_from_slice(&p.payload).is_err() {
            self.current = None;
            return None;
        }
        self.received |= bit;
        if (0..self.total).all(|i| self.received & (1 << (i & 0x0f)) != 0) {
            self.received = 0;
            self.total = 0;
            return self.current.take();
        }
        None
    }
}

/// Outcome of a Change Supply on the meter (D.3.3.3.1.12.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SupplyOutcome {
    /// Applied now; the response to send when acknowledgement was
    /// requested.
    Applied(Option<SupplyStatusResponse>),
    /// Scheduled for its implementation time.
    Scheduled,
    /// A pending command was cancelled.
    Cancelled,
    /// A cancellation named no pending command (NOT_FOUND).
    NotFound,
    /// The meter cannot carry the change out (UNSUP_CLUSTER_COMMAND).
    Unsupported,
    /// Not allowed in the current application (NOT_AUTHORIZED).
    NotAuthorized,
}

/// Supply (contactor / valve) control of a metering server.
#[derive(Clone, Copy, Debug)]
pub struct SupplyControl {
    /// Current supply status (Table D-56).
    pub status: u8,
    /// Whether the meter has a contactor / valve at all.
    pub capable: bool,
    /// Whether a remote or local RESTORE (ON) is allowed.
    pub restore_allowed: bool,
    pending: Option<ChangeSupply>,
}

impl SupplyControl {
    /// A meter with the given status and capabilities.
    pub const fn new(status: u8, capable: bool, restore_allowed: bool) -> Self {
        SupplyControl {
            status,
            capable,
            restore_allowed,
            pending: None,
        }
    }

    /// `ProposedChangeSupplyImplementationTime` (0 when none).
    pub fn proposed_implementation_time(&self) -> u32 {
        self.pending.map_or(0, |p| p.implementation_time)
    }

    fn allowed(&self, proposed: u8) -> Result<(), SupplyOutcome> {
        if !self.capable {
            return Err(SupplyOutcome::Unsupported);
        }
        if proposed == supply_status::ON && !self.restore_allowed {
            return Err(SupplyOutcome::NotAuthorized);
        }
        Ok(())
    }

    /// Handles a Change Supply at `now`: immediate commands execute
    /// without cancelling a delayed one; a new delayed command
    /// overrides an existing one; 0xFFFFFFFF cancels by provider and
    /// issuer event.
    pub fn change(&mut self, cmd: &ChangeSupply, now: u32) -> SupplyOutcome {
        if cmd.implementation_time == CANCEL {
            return match self.pending {
                Some(p)
                    if p.provider_id == cmd.provider_id
                        && p.issuer_event_id == cmd.issuer_event_id =>
                {
                    self.pending = None;
                    SupplyOutcome::Cancelled
                }
                _ => SupplyOutcome::NotFound,
            };
        }
        if let Err(e) = self.allowed(cmd.proposed_status) {
            return e;
        }
        if cmd.implementation_time == NOW || cmd.implementation_time <= now {
            self.status = cmd.proposed_status;
            let ack = (cmd.control & supply_control::ACKNOWLEDGE_REQUIRED != 0).then_some(
                SupplyStatusResponse {
                    provider_id: cmd.provider_id,
                    issuer_event_id: cmd.issuer_event_id,
                    implementation_time: now,
                    status: self.status,
                },
            );
            return SupplyOutcome::Applied(ack);
        }
        self.pending = Some(*cmd);
        SupplyOutcome::Scheduled
    }

    /// Applies a due delayed command; the response to send when it
    /// asked for one.
    pub fn poll(&mut self, now: u32) -> Option<Option<SupplyStatusResponse>> {
        let p = self.pending.filter(|p| p.implementation_time <= now)?;
        self.pending = None;
        self.status = p.proposed_status;
        Some(
            (p.control & supply_control::ACKNOWLEDGE_REQUIRED != 0).then_some(
                SupplyStatusResponse {
                    provider_id: p.provider_id,
                    issuer_event_id: p.issuer_event_id,
                    implementation_time: p.implementation_time,
                    status: self.status,
                },
            ),
        )
    }

    /// When the pending command is due.
    pub fn next_deadline(&self) -> Option<u32> {
        self.pending.map(|p| p.implementation_time)
    }

    /// Handles a Local Change Supply (D.3.3.3.1.13): only OFF/ARMED or
    /// ON, never answered with a Supply Status Response.
    pub fn local_change(&mut self, cmd: &LocalChangeSupply) -> SupplyOutcome {
        if !matches!(
            cmd.proposed_status,
            supply_status::OFF_ARMED | supply_status::ON
        ) {
            return SupplyOutcome::NotAuthorized;
        }
        if let Err(e) = self.allowed(cmd.proposed_status) {
            return e;
        }
        // Reconnection is only from the armed state.
        if cmd.proposed_status == supply_status::ON && self.status != supply_status::OFF_ARMED {
            return SupplyOutcome::NotAuthorized;
        }
        self.status = cmd.proposed_status;
        SupplyOutcome::Applied(None)
    }
}

/// A mirror the ESI hosts for a battery-operated meter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Mirror {
    /// The meter (short address).
    pub meter: u16,
    /// The mirror endpoint.
    pub endpoint: u8,
    /// Configuration from ConfigureMirror, once received.
    pub config: Option<ConfigureMirror>,
}

/// ESI-side mirror allocation (D.3.2.3.1.2 / .3, D.3.3.3.1.2 / .3).
#[derive(Clone, Debug)]
pub struct MirrorTable<const N: usize> {
    mirrors: Vec<Mirror, N>,
    /// Endpoints available for mirrors (1–240).
    pub endpoints: &'static [u8],
}

impl<const N: usize> MirrorTable<N> {
    /// A table allocating from `endpoints`.
    pub const fn new(endpoints: &'static [u8]) -> Self {
        MirrorTable {
            mirrors: Vec::new(),
            endpoints,
        }
    }

    /// Handles a RequestMirror from `meter`: an existing mirror is
    /// answered again, otherwise a free endpoint is allocated.
    pub fn request(&mut self, meter: u16) -> RequestMirrorResponse {
        if let Some(m) = self.mirrors.iter().find(|m| m.meter == meter) {
            return RequestMirrorResponse {
                endpoint: u16::from(m.endpoint),
            };
        }
        let free = self
            .endpoints
            .iter()
            .copied()
            .find(|e| !self.mirrors.iter().any(|m| m.endpoint == *e));
        match free {
            Some(endpoint) if !self.mirrors.is_full() => {
                let _ = self.mirrors.push(Mirror {
                    meter,
                    endpoint,
                    config: None,
                });
                RequestMirrorResponse {
                    endpoint: u16::from(endpoint),
                }
            }
            _ => RequestMirrorResponse {
                endpoint: MIRROR_UNAVAILABLE,
            },
        }
    }

    /// Handles a RemoveMirror sent to `endpoint` by `meter` (only the
    /// creator may remove it); `None` when there is nothing to remove.
    pub fn remove(&mut self, meter: u16, endpoint: u8) -> Option<MirrorRemoved> {
        let i = self
            .mirrors
            .iter()
            .position(|m| m.endpoint == endpoint && m.meter == meter)?;
        self.mirrors.remove(i);
        Some(MirrorRemoved {
            endpoint: u16::from(endpoint),
        })
    }

    /// Handles a ConfigureMirror on `endpoint`; `false` when the
    /// endpoint holds no mirror or the scheme is unsupported
    /// (INVALID_FIELD).
    pub fn configure(
        &mut self,
        endpoint: u8,
        cfg: &ConfigureMirror,
        scheme_supported: bool,
    ) -> bool {
        if !scheme_supported {
            return false;
        }
        match self.mirrors.iter_mut().find(|m| m.endpoint == endpoint) {
            Some(m) => {
                if m.config
                    .is_some_and(|c| c.issuer_event_id > cfg.issuer_event_id)
                {
                    return true;
                }
                m.config = Some(*cfg);
                true
            }
            None => false,
        }
    }

    /// The mirror on `endpoint`.
    pub fn on_endpoint(&self, endpoint: u8) -> Option<&Mirror> {
        self.mirrors.iter().find(|m| m.endpoint == endpoint)
    }

    /// The mirrors.
    pub fn mirrors(&self) -> &[Mirror] {
        &self.mirrors
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
        let mut buf = [0u8; 160];
        let mut w = Writer::new(&mut buf);
        enc(v, &mut w).unwrap();
        let n = w.position();
        assert_eq!(&dec(&buf[..n]).unwrap(), v);
        n
    }

    #[test]
    fn codecs_round_trip() {
        assert_eq!(
            rt(
                &FastPollModeResponse {
                    applied_update_period: 5,
                    end_time: 900
                },
                FastPollModeResponse::encode,
                FastPollModeResponse::parse
            ),
            5
        );
        rt(
            &TakeSnapshotResponse {
                snapshot_id: 1,
                confirmation: 0,
            },
            TakeSnapshotResponse::encode,
            TakeSnapshotResponse::parse,
        );
        let cm = ConfigureMirror {
            issuer_event_id: 1,
            reporting_interval: 3600,
            notification_reporting: true,
            scheme: notification_scheme::A,
        };
        assert_eq!(
            rt(
                &cm,
                ConfigureMirror::encode_wire,
                ConfigureMirror::parse_wire
            ),
            9
        );
        rt(
            &ConfigureNotificationScheme {
                issuer_event_id: 1,
                scheme: 0x10,
                flag_order: 0x7654_3210,
            },
            ConfigureNotificationScheme::encode,
            ConfigureNotificationScheme::parse,
        );
        rt(
            &GetNotifiedMessage {
                scheme: 1,
                flag_attribute: 0x0001,
                flags: 0x5,
            },
            GetNotifiedMessage::encode,
            GetNotifiedMessage::parse,
        );
        rt(
            &SupplyStatusResponse {
                provider_id: 1,
                issuer_event_id: 2,
                implementation_time: 3,
                status: supply_status::ON,
            },
            SupplyStatusResponse::encode,
            SupplyStatusResponse::parse,
        );
        rt(
            &StartSamplingResponse { sample_id: 7 },
            StartSamplingResponse::encode,
            StartSamplingResponse::parse,
        );
        rt(
            &RequestMirrorResponse { endpoint: 5 },
            RequestMirrorResponse::encode,
            RequestMirrorResponse::parse,
        );
        rt(
            &MirrorRemoved { endpoint: 5 },
            MirrorRemoved::encode,
            MirrorRemoved::parse,
        );
        rt(
            &RequestFastPollMode {
                update_period: 2,
                duration_minutes: 10,
            },
            RequestFastPollMode::encode,
            RequestFastPollMode::parse,
        );
        rt(
            &TakeSnapshot { cause: 1 },
            TakeSnapshot::encode,
            TakeSnapshot::parse,
        );
        rt(
            &GetSnapshot {
                earliest_start: 0,
                latest_end: u32::MAX,
                offset: 0,
                cause: ANY_CAUSE,
            },
            GetSnapshot::encode,
            GetSnapshot::parse,
        );
        rt(
            &StartSampling {
                issuer_event_id: 1,
                start_time: 0,
                sample_type: sample_type::CONSUMPTION_DELIVERED,
                interval: 60,
                max_samples: 10,
            },
            StartSampling::encode,
            StartSampling::parse,
        );
        rt(
            &GetSampledData {
                sample_id: 1,
                earliest_time: 0,
                sample_type: 0,
                count: 10,
            },
            GetSampledData::encode,
            GetSampledData::parse,
        );
        rt(
            &ResetLoadLimitCounter {
                provider_id: 1,
                issuer_event_id: 2,
            },
            ResetLoadLimitCounter::encode,
            ResetLoadLimitCounter::parse,
        );
        rt(
            &ChangeSupply {
                provider_id: 1,
                issuer_event_id: 2,
                request_time: 3,
                implementation_time: 4,
                proposed_status: supply_status::OFF_ARMED,
                control: supply_control::ACKNOWLEDGE_REQUIRED,
            },
            ChangeSupply::encode,
            ChangeSupply::parse,
        );
        rt(
            &LocalChangeSupply {
                proposed_status: supply_status::ON,
            },
            LocalChangeSupply::encode,
            LocalChangeSupply::parse,
        );
        rt(
            &SetSupplyStatus {
                issuer_event_id: 1,
                tamper: 0,
                depletion: 1,
                uncontrolled_flow: 0,
                load_limit: 3,
            },
            SetSupplyStatus::encode,
            SetSupplyStatus::parse,
        );
        rt(
            &SetUncontrolledFlowThreshold {
                provider_id: 1,
                issuer_event_id: 2,
                threshold: 300,
                unit: 1,
                multiplier: 1,
                divisor: 1000,
                stabilisation_period: 5,
                measurement_period: 60,
            },
            SetUncontrolledFlowThreshold::encode,
            SetUncontrolledFlowThreshold::parse,
        );
        let mut confirmations = Vec::new();
        confirmations.push((1u8, 0u8)).unwrap();
        rt(
            &ScheduleSnapshotResponse {
                issuer_event_id: 9,
                confirmations,
            },
            ScheduleSnapshotResponse::encode,
            ScheduleSnapshotResponse::parse,
        );
        let mut schedules = Vec::new();
        schedules
            .push(SnapshotSchedule {
                schedule_id: 1,
                start_time: 100,
                schedule: 0x01,
                payload_type: 0,
                cause: snapshot_cause::END_OF_BILLING_PERIOD,
            })
            .unwrap();
        rt(
            &ScheduleSnapshot {
                issuer_event_id: 9,
                command_index: 0,
                total_commands: 1,
                schedules,
            },
            ScheduleSnapshot::encode,
            ScheduleSnapshot::parse,
        );
        let tou = TouSnapshot {
            summation: 0x0001_0203_0405,
            billing: Some((100, 5, 200, 6, 0x20)),
            tiers: Vec::from_slice(&[1, 2]).unwrap(),
        };
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        tou.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 6 + 17 + 1 + 12);
        assert_eq!(
            TouSnapshot::parse(tou.payload_type(false), &buf[..n]).unwrap(),
            tou
        );
        assert!(TouSnapshot::parse(snapshot_type::BLOCK_DELIVERED, &buf[..n]).is_err());
        let ps = PublishSnapshot {
            snapshot_id: 1,
            time: 2,
            total_found: 1,
            command_index: 0,
            total_commands: 1,
            cause: 1,
            payload_type: 0,
            payload: Vec::from_slice(&buf[..n]).unwrap(),
        };
        rt(&ps, PublishSnapshot::encode, PublishSnapshot::parse);
        rt(
            &SampledDataResponse {
                sample_id: 1,
                start_time: 2,
                sample_type: 4,
                interval: 60,
                samples: Vec::from_slice(&[1, SAMPLE_INVALID, 3]).unwrap(),
            },
            SampledDataResponse::encode,
            SampledDataResponse::parse,
        );
        let mut allocations = Vec::new();
        allocations
            .push(BitFieldAllocation {
                cluster: 0x0700,
                manufacturer: 0,
                commands: Vec::from_slice(&[0x00, 0x01]).unwrap(),
            })
            .unwrap();
        rt(
            &ConfigureNotificationFlags {
                issuer_event_id: 1,
                scheme: 0x10,
                flag_attribute: 0x0002,
                allocations,
            },
            ConfigureNotificationFlags::encode,
            ConfigureNotificationFlags::parse,
        );
        rt(
            &MirrorReportAttributeResponse {
                scheme: 1,
                flags: Vec::from_slice(&[0x1, 0x2]).unwrap(),
            },
            MirrorReportAttributeResponse::encode,
            MirrorReportAttributeResponse::parse,
        );
        assert!(notification_scheme::is_configurable(0x10));
        assert!(!notification_scheme::is_configurable(
            notification_scheme::A
        ));
        assert_eq!(GENERATED.len(), 14);
        assert_eq!(RECEIVED.len(), 15);
    }

    #[test]
    fn fast_poll_applies_the_limits() {
        let mut f = FastPoll::new(5, 30);
        assert_eq!(f.period(0), 30);
        let r = f.request(
            &RequestFastPollMode {
                update_period: 2,
                duration_minutes: 20,
            },
            1000,
        );
        assert_eq!((r.applied_update_period, r.end_time), (5, 1000 + 900));
        assert_eq!(f.period(1500), 5);
        // A second request while active does not extend the mode.
        let r = f.request(
            &RequestFastPollMode {
                update_period: 10,
                duration_minutes: 15,
            },
            1500,
        );
        assert_eq!(r.end_time, 1900);
        assert_eq!(f.end_time(1500), Some(1900));
        assert_eq!(f.period(1900), 30);
        assert_eq!(f.end_time(1900), None);
    }

    #[test]
    fn sampler_answers_get_sampled_data() {
        let mut s: Sampler<2> = Sampler::new();
        let start = StartSampling {
            issuer_event_id: 1,
            start_time: 0,
            sample_type: sample_type::CONSUMPTION_DELIVERED,
            interval: 60,
            max_samples: 3,
        };
        assert_eq!(s.start(&start, 1000).unwrap().sample_id, 1);
        assert!(s.start(&start, 1000).is_none(), "repeated issuer event");
        assert_eq!(
            s.start(
                &StartSampling {
                    issuer_event_id: 2,
                    ..start
                },
                1000
            )
            .unwrap()
            .sample_id,
            2
        );
        assert_eq!(
            s.start(
                &StartSampling {
                    issuer_event_id: 3,
                    ..start
                },
                1000
            )
            .unwrap()
            .sample_id,
            SAMPLE_ID_UNAVAILABLE
        );
        assert_eq!(s.next_deadline(), Some(1000));
        s.sample(sample_type::CONSUMPTION_DELIVERED, 10, 1000);
        s.sample(sample_type::CONSUMPTION_DELIVERED, 11, 1030);
        assert_eq!(s.sessions()[0].samples.len(), 1, "not yet due");
        s.sample(sample_type::CONSUMPTION_DELIVERED, 11, 1060);
        s.sample(sample_type::CONSUMPTION_DELIVERED, 12, 1120);
        s.sample(sample_type::CONSUMPTION_DELIVERED, 13, 1180);
        assert_eq!(s.sessions()[0].samples.len(), 3, "capped at max");
        assert_eq!(s.next_deadline(), None);
        let r = s
            .sampled_data(&GetSampledData {
                sample_id: 1,
                earliest_time: 1060,
                sample_type: sample_type::CONSUMPTION_DELIVERED,
                count: 10,
            })
            .unwrap();
        assert_eq!((r.start_time, r.samples.as_slice()), (1060, &[11, 12][..]));
        assert!(
            s.sampled_data(&GetSampledData {
                sample_id: 1,
                earliest_time: 5000,
                sample_type: 0,
                count: 1,
            })
            .is_none()
        );
        // Cancellation.
        assert!(
            s.start(
                &StartSampling {
                    issuer_event_id: 2,
                    start_time: CANCEL,
                    ..start
                },
                2000
            )
            .is_some()
        );
        assert!(
            s.start(
                &StartSampling {
                    issuer_event_id: 2,
                    start_time: CANCEL,
                    ..start
                },
                2000
            )
            .is_none()
        );
        assert_eq!(s.sessions().len(), 1);
    }

    #[test]
    fn snapshots_are_stored_published_and_reassembled() {
        let mut store: Snapshots<2> = Snapshots::new();
        let payload = [0x11u8; 50];
        let r = store.on_take_snapshot(
            &TakeSnapshot {
                cause: snapshot_cause::GENERAL,
            },
            true,
            snapshot_type::TOU_DELIVERED,
            &payload,
            1000,
        );
        assert_eq!(
            (r.snapshot_id, r.confirmation),
            (1, snapshot_confirmation::ACCEPTED)
        );
        assert_eq!(
            store.snapshots()[0].cause,
            snapshot_cause::GENERAL | snapshot_cause::MANUALLY_TRIGGERED
        );
        store.take(snapshot_cause::END_OF_BILLING_PERIOD, 0, &[0x22; 10], 2000);
        store.take(snapshot_cause::END_OF_BILLING_PERIOD, 0, &[0x33; 10], 3000);
        assert_eq!(store.snapshots().len(), 2, "oldest evicted");
        let mut out = Vec::new();
        assert!(
            store
                .get(
                    &GetSnapshot {
                        earliest_start: 0,
                        latest_end: 5000,
                        offset: 1,
                        cause: snapshot_cause::END_OF_BILLING_PERIOD,
                    },
                    &mut out
                )
                .is_some()
        );
        assert_eq!(out[0].snapshot_id, 3);
        assert_eq!(out[0].total_found, 2);
        out.clear();
        assert!(
            store
                .get(
                    &GetSnapshot {
                        earliest_start: 0,
                        latest_end: 5000,
                        offset: 2,
                        cause: ANY_CAUSE,
                    },
                    &mut out
                )
                .is_none()
        );
        // A long payload is fragmented and reassembled.
        let mut big: Snapshots<1> = Snapshots::new();
        big.take(1, 0, &payload, 100);
        out.clear();
        big.get(
            &GetSnapshot {
                earliest_start: 0,
                latest_end: 100,
                offset: 0,
                cause: ANY_CAUSE,
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        let mut a = SnapshotAssembler::default();
        assert!(a.feed(&out[1]).is_none());
        let s = a.feed(&out[0]).unwrap();
        assert_eq!(s.payload.as_slice(), &payload[..]);
        assert_eq!(
            store
                .on_take_snapshot(&TakeSnapshot { cause: 1 }, false, 0, &[], 1)
                .confirmation,
            snapshot_confirmation::CAUSE_NOT_SUPPORTED
        );
    }

    #[test]
    fn supply_control_applies_change_supply_rules() {
        let mut s = SupplyControl::new(supply_status::ON, true, true);
        let cmd = ChangeSupply {
            provider_id: 1,
            issuer_event_id: 10,
            request_time: 1000,
            implementation_time: 5000,
            proposed_status: supply_status::OFF_ARMED,
            control: supply_control::ACKNOWLEDGE_REQUIRED,
        };
        assert_eq!(s.change(&cmd, 1000), SupplyOutcome::Scheduled);
        assert_eq!(s.proposed_implementation_time(), 5000);
        // An immediate command executes without cancelling the delayed
        // one.
        let now_cmd = ChangeSupply {
            issuer_event_id: 11,
            implementation_time: NOW,
            proposed_status: supply_status::OFF,
            control: 0,
            ..cmd
        };
        assert_eq!(s.change(&now_cmd, 1500), SupplyOutcome::Applied(None));
        assert_eq!(s.status, supply_status::OFF);
        assert_eq!(s.next_deadline(), Some(5000));
        // Cancel with the wrong event: not found; right one: cancelled.
        assert_eq!(
            s.change(
                &ChangeSupply {
                    issuer_event_id: 99,
                    implementation_time: CANCEL,
                    ..cmd
                },
                1600
            ),
            SupplyOutcome::NotFound
        );
        assert_eq!(
            s.change(
                &ChangeSupply {
                    implementation_time: CANCEL,
                    ..cmd
                },
                1600
            ),
            SupplyOutcome::Cancelled
        );
        assert_eq!(s.proposed_implementation_time(), 0);
        // Delayed again, then due: applied with the acknowledgement.
        s.change(&cmd, 1700);
        assert!(s.poll(4999).is_none());
        let ack = s.poll(5000).unwrap().unwrap();
        assert_eq!(
            (ack.issuer_event_id, ack.status),
            (10, supply_status::OFF_ARMED)
        );
        // Local reconnection from armed; a local OFF is refused.
        assert_eq!(
            s.local_change(&LocalChangeSupply {
                proposed_status: supply_status::ON
            }),
            SupplyOutcome::Applied(None)
        );
        assert_eq!(
            s.local_change(&LocalChangeSupply {
                proposed_status: supply_status::OFF
            }),
            SupplyOutcome::NotAuthorized
        );
        // Restore not allowed remotely; no contactor at all.
        s.restore_allowed = false;
        s.status = supply_status::OFF_ARMED;
        assert_eq!(
            s.change(
                &ChangeSupply {
                    proposed_status: supply_status::ON,
                    implementation_time: NOW,
                    ..cmd
                },
                6000
            ),
            SupplyOutcome::NotAuthorized
        );
        let mut gas = SupplyControl::new(supply_status::ON, false, false);
        assert_eq!(gas.change(&now_cmd, 1), SupplyOutcome::Unsupported);
    }

    #[test]
    fn mirror_table_allocates_endpoints() {
        static ENDPOINTS: [u8; 2] = [11, 12];
        let mut t: MirrorTable<2> = MirrorTable::new(&ENDPOINTS);
        assert_eq!(t.request(0x1000).endpoint, 11);
        assert_eq!(t.request(0x1000).endpoint, 11, "same meter, same mirror");
        assert_eq!(t.request(0x2000).endpoint, 12);
        assert_eq!(t.request(0x3000).endpoint, MIRROR_UNAVAILABLE);
        let cfg = ConfigureMirror {
            issuer_event_id: 5,
            reporting_interval: 600,
            notification_reporting: true,
            scheme: notification_scheme::A,
        };
        assert!(t.configure(11, &cfg, true));
        assert!(!t.configure(11, &cfg, false));
        assert!(!t.configure(13, &cfg, true));
        assert_eq!(t.on_endpoint(11).unwrap().config, Some(cfg));
        // Only the creator removes a mirror.
        assert!(t.remove(0x2000, 11).is_none());
        assert_eq!(t.remove(0x1000, 11).unwrap().endpoint, 11);
        assert_eq!(t.request(0x3000).endpoint, 11);
    }
}
