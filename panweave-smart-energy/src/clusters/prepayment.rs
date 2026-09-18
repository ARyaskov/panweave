//! Prepayment cluster (SE 1.4a Annex D.7): the information, top-up,
//! debt and alarm attribute identifiers with their bitmaps, the client
//! → server command codecs (Select Available Emergency Credit, Change
//! Debt, Emergency Credit Setup, Consumer Top Up, Credit Adjustment,
//! Change Payment Mode, Get Prepay Snapshot, Get Top Up Log, Set Low
//! Credit Warning Level, Get Debt Repayment Log, Set Maximum Credit
//! Limit, Set Overall Debt Cap) and the server → client codecs (Publish
//! Prepay Snapshot with the Debt/Credit Status payload, Change Payment
//! Mode Response, Consumer Top Up Response, Publish Top Up Log, Publish
//! Debt Log), plus a small [`Account`] applying the credit rules a
//! metering device follows (top-ups against the limits, emergency credit
//! selection, credit status derivation, top-up and debt logs).

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{AttributeId, ClusterId, CommandId};
use panweave_zcl::cluster::ClusterDef;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0705);

/// Prepayment Information attribute set (Table D-129).
pub mod attr {
    use super::AttributeId;

    /// `PaymentControlConfiguration` (map16).
    pub const PAYMENT_CONTROL_CONFIGURATION: AttributeId = AttributeId(0x0000);
    /// `CreditRemaining` (int32).
    pub const CREDIT_REMAINING: AttributeId = AttributeId(0x0001);
    /// `EmergencyCreditRemaining` (int32).
    pub const EMERGENCY_CREDIT_REMAINING: AttributeId = AttributeId(0x0002);
    /// `CreditStatus` (map8).
    pub const CREDIT_STATUS: AttributeId = AttributeId(0x0003);
    /// `CreditRemainingTimeStamp` (UTC).
    pub const CREDIT_REMAINING_TIMESTAMP: AttributeId = AttributeId(0x0004);
    /// `AccumulatedDebt` (int32).
    pub const ACCUMULATED_DEBT: AttributeId = AttributeId(0x0005);
    /// `OverallDebtCap` (int32).
    pub const OVERALL_DEBT_CAP: AttributeId = AttributeId(0x0006);
    /// `EmergencyCreditLimit/Allowance` (uint32).
    pub const EMERGENCY_CREDIT_LIMIT: AttributeId = AttributeId(0x0010);
    /// `EmergencyCreditThreshold` (uint32).
    pub const EMERGENCY_CREDIT_THRESHOLD: AttributeId = AttributeId(0x0011);
    /// `TotalCreditAdded` (uint48).
    pub const TOTAL_CREDIT_ADDED: AttributeId = AttributeId(0x0020);
    /// `MaxCreditLimit` (uint32).
    pub const MAX_CREDIT_LIMIT: AttributeId = AttributeId(0x0021);
    /// `MaxCreditPerTopUp` (uint32).
    pub const MAX_CREDIT_PER_TOP_UP: AttributeId = AttributeId(0x0022);
    /// `FriendlyCreditWarning` (uint8).
    pub const FRIENDLY_CREDIT_WARNING: AttributeId = AttributeId(0x0030);
    /// `LowCreditWarningLevel` (uint32).
    pub const LOW_CREDIT_WARNING_LEVEL: AttributeId = AttributeId(0x0031);
    /// `IHDLowCreditWarningLevel` (uint32, writable).
    pub const IHD_LOW_CREDIT_WARNING_LEVEL: AttributeId = AttributeId(0x0032);
    /// `InterruptSuspendTime` (uint8).
    pub const INTERRUPT_SUSPEND_TIME: AttributeId = AttributeId(0x0033);
    /// `RemainingFriendlyCreditTime` (uint16).
    pub const REMAINING_FRIENDLY_CREDIT_TIME: AttributeId = AttributeId(0x0034);
    /// `NextFriendlyCreditPeriod` (UTC).
    pub const NEXT_FRIENDLY_CREDIT_PERIOD: AttributeId = AttributeId(0x0035);
    /// `CutOffValue` (int32).
    pub const CUT_OFF_VALUE: AttributeId = AttributeId(0x0040);
    /// `TokenCarrierID` (octstr, writable).
    pub const TOKEN_CARRIER_ID: AttributeId = AttributeId(0x0080);
    /// `PrepaymentAlarmStatus` (map16).
    pub const PREPAYMENT_ALARM_STATUS: AttributeId = AttributeId(0x0400);
    /// `PrepayGenericAlarmMask` (map16).
    pub const PREPAY_GENERIC_ALARM_MASK: AttributeId = AttributeId(0x0401);
    /// `PrepaySwitchAlarmMask` (map16).
    pub const PREPAY_SWITCH_ALARM_MASK: AttributeId = AttributeId(0x0402);
    /// `PrepayEventAlarmMask` (map16).
    pub const PREPAY_EVENT_ALARM_MASK: AttributeId = AttributeId(0x0403);

    /// `TopUpDateTime#n` (1-based `n` ≤ 5).
    pub const fn top_up_time(n: u8) -> AttributeId {
        AttributeId(0x0100 + 0x10 * (n as u16 - 1))
    }
    /// `TopUpAmount#n`.
    pub const fn top_up_amount(n: u8) -> AttributeId {
        AttributeId(0x0101 + 0x10 * (n as u16 - 1))
    }
    /// `OriginatingDevice#n`.
    pub const fn top_up_originator(n: u8) -> AttributeId {
        AttributeId(0x0102 + 0x10 * (n as u16 - 1))
    }
    /// `TopUpCode#n`.
    pub const fn top_up_code(n: u8) -> AttributeId {
        AttributeId(0x0103 + 0x10 * (n as u16 - 1))
    }
    /// `DebtLabel#n` (1-based `n` ≤ 3).
    pub const fn debt_label(n: u8) -> AttributeId {
        AttributeId(0x0210 + 0x10 * (n as u16 - 1))
    }
    /// `DebtAmount#n`.
    pub const fn debt_amount(n: u8) -> AttributeId {
        AttributeId(0x0211 + 0x10 * (n as u16 - 1))
    }
    /// `DebtRecoveryMethod#n`.
    pub const fn debt_recovery_method(n: u8) -> AttributeId {
        AttributeId(0x0212 + 0x10 * (n as u16 - 1))
    }
    /// `DebtRecoveryStartTime#n`.
    pub const fn debt_recovery_start_time(n: u8) -> AttributeId {
        AttributeId(0x0213 + 0x10 * (n as u16 - 1))
    }
    /// `DebtRecoveryCollectionTime#n`.
    pub const fn debt_recovery_collection_time(n: u8) -> AttributeId {
        AttributeId(0x0214 + 0x10 * (n as u16 - 1))
    }
    /// `DebtRecoveryFrequency#n`.
    pub const fn debt_recovery_frequency(n: u8) -> AttributeId {
        AttributeId(0x0216 + 0x10 * (n as u16 - 1))
    }
    /// `DebtRecoveryAmount#n`.
    pub const fn debt_recovery_amount(n: u8) -> AttributeId {
        AttributeId(0x0217 + 0x10 * (n as u16 - 1))
    }
    /// `DebtRecoveryTopUpPercentage#n`.
    pub const fn debt_recovery_top_up_percentage(n: u8) -> AttributeId {
        AttributeId(0x0219 + 0x10 * (n as u16 - 1))
    }
}

/// `PaymentControlConfiguration` bits (Table D-130).
pub mod payment_control {
    /// Disconnection enabled.
    pub const DISCONNECTION_ENABLED: u16 = 1 << 0;
    /// Prepayment enabled (else a credit meter).
    pub const PREPAYMENT_ENABLED: u16 = 1 << 1;
    /// Credit management enabled.
    pub const CREDIT_MANAGEMENT_ENABLED: u16 = 1 << 2;
    /// Credit display enabled.
    pub const CREDIT_DISPLAY_ENABLED: u16 = 1 << 4;
    /// Account base: unit based (1) rather than monetary (0).
    pub const ACCOUNT_BASE_UNITS: u16 = 1 << 6;
    /// Contactor fitted.
    pub const CONTACTOR_FITTED: u16 = 1 << 7;
    /// Standing charge halted when credit is exhausted.
    pub const STANDING_CHARGE_CONFIGURATION: u16 = 1 << 8;
    /// Standing charge halted in emergency credit.
    pub const EMERGENCY_STANDING_CHARGE_CONFIGURATION: u16 = 1 << 9;
    /// Debt collection halted when credit is exhausted.
    pub const DEBT_CONFIGURATION: u16 = 1 << 10;
    /// Debt collected in emergency credit.
    pub const EMERGENCY_DEBT_CONFIGURATION: u16 = 1 << 11;
}

/// `CreditStatus` bits (Table D-131).
pub mod credit_status {
    /// Credit OK.
    pub const CREDIT_OK: u8 = 1 << 0;
    /// Low credit.
    pub const LOW_CREDIT: u8 = 1 << 1;
    /// Emergency credit enabled.
    pub const EMERGENCY_CREDIT_ENABLED: u8 = 1 << 2;
    /// Emergency credit available.
    pub const EMERGENCY_CREDIT_AVAILABLE: u8 = 1 << 3;
    /// Emergency credit selected.
    pub const EMERGENCY_CREDIT_SELECTED: u8 = 1 << 4;
    /// Emergency credit in use.
    pub const EMERGENCY_CREDIT_IN_USE: u8 = 1 << 5;
    /// Credit exhausted.
    pub const CREDIT_EXHAUSTED: u8 = 1 << 6;
}

/// `PrepaymentAlarmStatus` bits (Table D-138).
pub mod alarm_status {
    /// Low credit warning.
    pub const LOW_CREDIT_WARNING: u16 = 1 << 0;
    /// Top-up code error.
    pub const TOP_UP_CODE_ERROR: u16 = 1 << 1;
    /// Top-up code already used.
    pub const TOP_UP_CODE_ALREADY_USED: u16 = 1 << 2;
    /// Top-up code invalid.
    pub const TOP_UP_CODE_INVALID: u16 = 1 << 3;
    /// Friendly credit in use.
    pub const FRIENDLY_CREDIT_IN_USE: u16 = 1 << 4;
    /// Friendly credit period end warning.
    pub const FRIENDLY_CREDIT_PERIOD_END_WARNING: u16 = 1 << 5;
    /// Emergency credit available.
    pub const EC_AVAILABLE: u16 = 1 << 6;
    /// Unauthorised energy use.
    pub const UNAUTHORISED_ENERGY_USE: u16 = 1 << 7;
    /// Disconnected supply due to credit.
    pub const DISCONNECTED_DUE_TO_CREDIT: u16 = 1 << 8;
    /// Disconnected supply due to tamper.
    pub const DISCONNECTED_DUE_TO_TAMPER: u16 = 1 << 9;
    /// Disconnected supply due to HES.
    pub const DISCONNECTED_DUE_TO_HES: u16 = 1 << 10;
    /// Physical attack.
    pub const PHYSICAL_ATTACK: u16 = 1 << 11;
    /// Electronic attack.
    pub const ELECTRONIC_ATTACK: u16 = 1 << 12;
    /// Manufacturer alarm code A.
    pub const MANUFACTURER_ALARM_A: u16 = 1 << 13;
    /// Manufacturer alarm code B.
    pub const MANUFACTURER_ALARM_B: u16 = 1 << 14;
}

/// Originating Device values (Table D-146).
pub mod originating_device {
    /// Energy Service Interface.
    pub const ESI: u8 = 0x00;
    /// Meter.
    pub const METER: u8 = 0x01;
    /// In-Home Display.
    pub const IHD: u8 = 0x02;
}

/// Debt Amount Type values (Table D-147).
pub mod debt_amount_type {
    /// Type 1 absolute.
    pub const TYPE_1_ABSOLUTE: u8 = 0x00;
    /// Type 1 incremental.
    pub const TYPE_1_INCREMENTAL: u8 = 0x01;
    /// Type 2 absolute.
    pub const TYPE_2_ABSOLUTE: u8 = 0x02;
    /// Type 2 incremental.
    pub const TYPE_2_INCREMENTAL: u8 = 0x03;
    /// Type 3 absolute.
    pub const TYPE_3_ABSOLUTE: u8 = 0x04;
    /// Type 3 incremental.
    pub const TYPE_3_INCREMENTAL: u8 = 0x05;
}

/// Credit Adjustment Type values (Table D-148).
pub mod credit_adjustment_type {
    /// Incremental.
    pub const INCREMENTAL: u8 = 0x00;
    /// Absolute.
    pub const ABSOLUTE: u8 = 0x01;
}

/// Debt Type values (Table D-149).
pub mod debt_type {
    /// Debt 1.
    pub const DEBT_1: u8 = 0x00;
    /// Debt 2.
    pub const DEBT_2: u8 = 0x01;
    /// Debt 3.
    pub const DEBT_3: u8 = 0x02;
    /// All debts.
    pub const ALL: u8 = 0xff;
}

/// Consumer Top Up Response result types (Table D-154).
pub mod top_up_result {
    /// Accepted.
    pub const ACCEPTED: u8 = 0x00;
    /// Rejected: invalid top-up.
    pub const REJECTED_INVALID: u8 = 0x01;
    /// Rejected: duplicate top-up.
    pub const REJECTED_DUPLICATE: u8 = 0x02;
    /// Rejected: error.
    pub const REJECTED_ERROR: u8 = 0x03;
    /// Rejected: maximum credit reached.
    pub const REJECTED_MAX_CREDIT: u8 = 0x04;
    /// Rejected: keypad lock.
    pub const REJECTED_KEYPAD_LOCK: u8 = 0x05;
    /// Rejected: top-up value too large.
    pub const REJECTED_TOO_LARGE: u8 = 0x06;
    /// Accepted, supply enabled.
    pub const ACCEPTED_SUPPLY_ENABLED: u8 = 0x10;
    /// Accepted, supply disabled.
    pub const ACCEPTED_SUPPLY_DISABLED: u8 = 0x11;
    /// Accepted, supply armed.
    pub const ACCEPTED_SUPPLY_ARMED: u8 = 0x12;
}

/// The alarm codes of the three alarm groups (Tables D-139 to D-142)
/// and the alarm mask attribute that enables each (D.7.2.2.5.2): bit
/// `code - group offset` of the group's mask.
pub mod alarm_code {
    use super::AttributeId;
    use super::attr;

    /// First code of the PrepayGenericAlarmGroup.
    pub const GENERIC_GROUP: u8 = 0x00;
    /// First code of the PrepaySwitchAlarmGroup.
    pub const SWITCH_GROUP: u8 = 0x10;
    /// First code of the PrepayEventAlarmGroup.
    pub const EVENT_GROUP: u8 = 0x20;
    /// First reserved code.
    pub const RESERVED: u8 = 0x50;

    /// Low credit (for all types of credit).
    pub const LOW_CREDIT: u8 = 0x00;
    /// No credit (zero credit).
    pub const NO_CREDIT: u8 = 0x01;
    /// Credit exhausted.
    pub const CREDIT_EXHAUSTED: u8 = 0x02;
    /// Emergency credit enabled.
    pub const EMERGENCY_CREDIT_ENABLED: u8 = 0x03;
    /// Emergency credit exhausted.
    pub const EMERGENCY_CREDIT_EXHAUSTED: u8 = 0x04;
    /// IHD low credit warning.
    pub const IHD_LOW_CREDIT_WARNING: u8 = 0x05;
    /// Event log cleared.
    pub const EVENT_LOG_CLEARED: u8 = 0x06;

    /// Supply ON.
    pub const SUPPLY_ON: u8 = 0x10;
    /// Supply ARM.
    pub const SUPPLY_ARM: u8 = 0x11;
    /// Supply OFF.
    pub const SUPPLY_OFF: u8 = 0x12;
    /// Disconnection failure (shut-off mechanism fail).
    pub const DISCONNECTION_FAILURE: u8 = 0x13;
    /// Disconnected due to tamper detected.
    pub const DISCONNECTED_TAMPER: u8 = 0x14;
    /// Disconnected due to cut-off value.
    pub const DISCONNECTED_CUT_OFF_VALUE: u8 = 0x15;
    /// Remote disconnected.
    pub const REMOTE_DISCONNECTED: u8 = 0x16;

    /// Physical attack on the prepay meter.
    pub const PHYSICAL_ATTACK: u8 = 0x20;
    /// Electronic attack on the prepay meter.
    pub const ELECTRONIC_ATTACK: u8 = 0x21;
    /// Discount applied.
    pub const DISCOUNT_APPLIED: u8 = 0x22;
    /// Credit adjustment.
    pub const CREDIT_ADJUSTMENT: u8 = 0x23;
    /// Credit adjustment fail.
    pub const CREDIT_ADJUSTMENT_FAIL: u8 = 0x24;
    /// Debt adjustment.
    pub const DEBT_ADJUSTMENT: u8 = 0x25;
    /// Debt adjustment fail.
    pub const DEBT_ADJUSTMENT_FAIL: u8 = 0x26;
    /// Mode change.
    pub const MODE_CHANGE: u8 = 0x27;
    /// Top-up code error.
    pub const TOP_UP_CODE_ERROR: u8 = 0x28;
    /// Top-up already used.
    pub const TOP_UP_ALREADY_USED: u8 = 0x29;
    /// Top-up code invalid.
    pub const TOP_UP_CODE_INVALID: u8 = 0x2A;
    /// Friendly credit in use.
    pub const FRIENDLY_CREDIT_IN_USE: u8 = 0x2B;
    /// Friendly credit period end warning.
    pub const FRIENDLY_CREDIT_PERIOD_END_WARNING: u8 = 0x2C;
    /// Friendly credit period end.
    pub const FRIENDLY_CREDIT_PERIOD_END: u8 = 0x2D;
    /// ErrorRegClear.
    pub const ERROR_REG_CLEAR: u8 = 0x30;
    /// AlarmRegClear.
    pub const ALARM_REG_CLEAR: u8 = 0x31;
    /// Prepay cluster not found.
    pub const PREPAY_CLUSTER_NOT_FOUND: u8 = 0x32;
    /// ModeCredit2Prepay.
    pub const MODE_CREDIT_TO_PREPAY: u8 = 0x41;
    /// ModePrepay2Credit.
    pub const MODE_PREPAY_TO_CREDIT: u8 = 0x42;
    /// ModeDefault.
    pub const MODE_DEFAULT: u8 = 0x43;

    /// The alarm mask attribute governing `code` and the bit of the mask
    /// that enables it; `None` for a reserved code.
    pub const fn mask_bit(code: u8) -> Option<(AttributeId, u16)> {
        let (mask, offset) = if code < SWITCH_GROUP {
            (attr::PREPAY_GENERIC_ALARM_MASK, GENERIC_GROUP)
        } else if code < EVENT_GROUP {
            (attr::PREPAY_SWITCH_ALARM_MASK, SWITCH_GROUP)
        } else if code < RESERVED {
            (attr::PREPAY_EVENT_ALARM_MASK, EVENT_GROUP)
        } else {
            return None;
        };
        let bit = code - offset;
        if bit >= 16 {
            return None;
        }
        Some((mask, 1 << bit))
    }

    /// Whether `code` is enabled by the masks `generic`, `switch` and
    /// `event` (the three mask attributes' values).
    pub const fn enabled(code: u8, generic: u16, switch: u16, event: u16) -> bool {
        match mask_bit(code) {
            Some((mask, bit)) => {
                let value = if mask.0 == attr::PREPAY_GENERIC_ALARM_MASK.0 {
                    generic
                } else if mask.0 == attr::PREPAY_SWITCH_ALARM_MASK.0 {
                    switch
                } else {
                    event
                };
                value & bit != 0
            }
            None => false,
        }
    }
}

/// The Historical Cost Consumption Information attribute set (Table
/// D-143): the cost of consumption per day, week and month, with the
/// formatting, unit, currency scaling and currency that apply to all of
/// them (D.7.2.2.6.1-D.7.2.2.6.4).
pub mod historical_cost {
    use super::AttributeId;

    /// `HistoricalCostConsumptionFormatting` (map8: digits left / right
    /// of the decimal point).
    pub const FORMATTING: AttributeId = AttributeId(0x0500);
    /// `ConsumptionUnitofMeasurement` (enum8, Table D-26).
    pub const CONSUMPTION_UNIT_OF_MEASUREMENT: AttributeId = AttributeId(0x0501);
    /// `CurrencyScalingFactor` (enum8).
    pub const CURRENCY_SCALING_FACTOR: AttributeId = AttributeId(0x0502);
    /// `Currency` (uint16, ISO 4217).
    pub const CURRENCY: AttributeId = AttributeId(0x0503);
    /// `CurrentDayCostConsumptionDelivered` (uint48).
    pub const CURRENT_DAY_DELIVERED: AttributeId = AttributeId(0x051C);
    /// `CurrentDayCostConsumptionReceived` (uint48).
    pub const CURRENT_DAY_RECEIVED: AttributeId = AttributeId(0x051D);
    /// `CurrentWeekCostConsumptionDelivered` (uint48).
    pub const CURRENT_WEEK_DELIVERED: AttributeId = AttributeId(0x0530);
    /// `CurrentWeekCostConsumptionReceived` (uint48).
    pub const CURRENT_WEEK_RECEIVED: AttributeId = AttributeId(0x0531);
    /// `CurrentMonthCostConsumptionDelivered` (uint48).
    pub const CURRENT_MONTH_DELIVERED: AttributeId = AttributeId(0x0540);
    /// `CurrentMonthCostConsumptionReceived` (uint48).
    pub const CURRENT_MONTH_RECEIVED: AttributeId = AttributeId(0x0541);
    /// `HistoricalFreezeTime` (uint16).
    pub const HISTORICAL_FREEZE_TIME: AttributeId = AttributeId(0x055C);
    /// Previous days kept (PreviousDay, PreviousDay2-8).
    pub const PREVIOUS_DAYS: u8 = 8;
    /// Previous weeks kept (PreviousWeek, PreviousWeek2-5).
    pub const PREVIOUS_WEEKS: u8 = 5;
    /// Previous months kept (PreviousMonth, PreviousMonth2-13).
    pub const PREVIOUS_MONTHS: u8 = 13;

    /// `PreviousDay[n]CostConsumptionDelivered` / `Received` (n = 1 for
    /// PreviousDay, 2-8 for PreviousDay2-8).
    pub const fn previous_day(n: u8, received: bool) -> Option<AttributeId> {
        if n == 0 || n > PREVIOUS_DAYS {
            return None;
        }
        Some(AttributeId(0x051E + 2 * (n as u16 - 1) + received as u16))
    }

    /// `PreviousWeek[n]CostConsumptionDelivered` / `Received` (n = 1-5).
    pub const fn previous_week(n: u8, received: bool) -> Option<AttributeId> {
        if n == 0 || n > PREVIOUS_WEEKS {
            return None;
        }
        Some(AttributeId(0x0532 + 2 * (n as u16 - 1) + received as u16))
    }

    /// `PreviousMonth[n]CostConsumptionDelivered` / `Received` (n = 1-13).
    pub const fn previous_month(n: u8, received: bool) -> Option<AttributeId> {
        if n == 0 || n > PREVIOUS_MONTHS {
            return None;
        }
        Some(AttributeId(0x0542 + 2 * (n as u16 - 1) + received as u16))
    }
}

/// Snapshot cause bits (Table D-151).
pub mod snapshot_cause {
    /// General.
    pub const GENERAL: u32 = 1 << 0;
    /// End of billing period.
    pub const END_OF_BILLING_PERIOD: u32 = 1 << 1;
    /// Change of tariff information.
    pub const CHANGE_OF_TARIFF: u32 = 1 << 3;
    /// Change of price matrix.
    pub const CHANGE_OF_PRICE_MATRIX: u32 = 1 << 4;
    /// Manually triggered from client.
    pub const MANUAL: u32 = 1 << 10;
    /// Change of tenancy.
    pub const CHANGE_OF_TENANCY: u32 = 1 << 12;
    /// Change of supplier.
    pub const CHANGE_OF_SUPPLIER: u32 = 1 << 13;
    /// Change of meter mode.
    pub const CHANGE_OF_METER_MODE: u32 = 1 << 14;
    /// Top-up addition.
    pub const TOP_UP_ADDITION: u32 = 1 << 18;
    /// Debt / credit addition.
    pub const DEBT_CREDIT_ADDITION: u32 = 1 << 19;
    /// Every cause.
    pub const ALL: u32 = 0xffff_ffff;
}

/// Snapshot payload type: Debt/Credit Status (Table D-152).
pub const SNAPSHOT_PAYLOAD_DEBT_CREDIT_STATUS: u8 = 0x00;
/// "Unchanged" marker of 32-bit command fields.
pub const UNCHANGED_U32: u32 = 0xffff_ffff;
/// "Unchanged" marker of 16-bit command fields.
pub const UNCHANGED_U16: u16 = 0xffff;
/// "Unchanged" marker of 8-bit command fields.
pub const UNCHANGED_U8: u8 = 0xff;
/// Execute immediately (start / implementation time).
pub const IMMEDIATELY: u32 = 0;
/// Cancel a pending command (start / implementation time).
pub const CANCEL: u32 = 0xffff_ffff;
/// Longest top-up code (D.7.2.3.5.2).
pub const MAX_TOP_UP_CODE: usize = 25;
/// Longest debt label (D.7.2.2.3.1).
pub const MAX_DEBT_LABEL: usize = 12;

/// Client → server: Select Available Emergency Credit.
pub const CMD_SELECT_AVAILABLE_EMERGENCY_CREDIT: CommandId = CommandId(0x00);
/// Client → server: Change Debt.
pub const CMD_CHANGE_DEBT: CommandId = CommandId(0x02);
/// Client → server: Emergency Credit Setup.
pub const CMD_EMERGENCY_CREDIT_SETUP: CommandId = CommandId(0x03);
/// Client → server: Consumer Top Up.
pub const CMD_CONSUMER_TOP_UP: CommandId = CommandId(0x04);
/// Client → server: Credit Adjustment.
pub const CMD_CREDIT_ADJUSTMENT: CommandId = CommandId(0x05);
/// Client → server: Change Payment Mode.
pub const CMD_CHANGE_PAYMENT_MODE: CommandId = CommandId(0x06);
/// Client → server: Get Prepay Snapshot.
pub const CMD_GET_PREPAY_SNAPSHOT: CommandId = CommandId(0x07);
/// Client → server: Get Top Up Log.
pub const CMD_GET_TOP_UP_LOG: CommandId = CommandId(0x08);
/// Client → server: Set Low Credit Warning Level.
pub const CMD_SET_LOW_CREDIT_WARNING_LEVEL: CommandId = CommandId(0x09);
/// Client → server: Get Debt Repayment Log.
pub const CMD_GET_DEBT_REPAYMENT_LOG: CommandId = CommandId(0x0a);
/// Client → server: Set Maximum Credit Limit.
pub const CMD_SET_MAXIMUM_CREDIT_LIMIT: CommandId = CommandId(0x0b);
/// Client → server: Set Overall Debt Cap.
pub const CMD_SET_OVERALL_DEBT_CAP: CommandId = CommandId(0x0c);

/// Server → client: Publish Prepay Snapshot.
pub const CMD_PUBLISH_PREPAY_SNAPSHOT: CommandId = CommandId(0x01);
/// Server → client: Change Payment Mode Response.
pub const CMD_CHANGE_PAYMENT_MODE_RESPONSE: CommandId = CommandId(0x02);
/// Server → client: Consumer Top Up Response.
pub const CMD_CONSUMER_TOP_UP_RESPONSE: CommandId = CommandId(0x03);
/// Server → client: Publish Top Up Log.
pub const CMD_PUBLISH_TOP_UP_LOG: CommandId = CommandId(0x05);
/// Server → client: Publish Debt Log.
pub const CMD_PUBLISH_DEBT_LOG: CommandId = CommandId(0x06);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_SELECT_AVAILABLE_EMERGENCY_CREDIT,
        CMD_CHANGE_DEBT,
        CMD_EMERGENCY_CREDIT_SETUP,
        CMD_CONSUMER_TOP_UP,
        CMD_CREDIT_ADJUSTMENT,
        CMD_CHANGE_PAYMENT_MODE,
        CMD_GET_PREPAY_SNAPSHOT,
        CMD_GET_TOP_UP_LOG,
        CMD_SET_LOW_CREDIT_WARNING_LEVEL,
        CMD_GET_DEBT_REPAYMENT_LOG,
        CMD_SET_MAXIMUM_CREDIT_LIMIT,
        CMD_SET_OVERALL_DEBT_CAP,
    ],
    generated: &[
        CMD_PUBLISH_PREPAY_SNAPSHOT,
        CMD_CHANGE_PAYMENT_MODE_RESPONSE,
        CMD_CONSUMER_TOP_UP_RESPONSE,
        CMD_PUBLISH_TOP_UP_LOG,
        CMD_PUBLISH_DEBT_LOG,
    ],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

fn read_octstr<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let n = r.u8()?;
    if n == 0xff {
        return Ok(&[0xff]);
    }
    r.bytes(usize::from(n))
}

fn write_octstr(w: &mut Writer<'_>, s: &[u8]) -> Result<(), CodecError> {
    if s == [0xff] {
        return w.u8(0xff);
    }
    w.u8(
        u8::try_from(s.len()).map_err(|_| CodecError::Unrepresentable {
            field: "octet string",
        })?,
    )?;
    w.bytes(s)
}

/// Select Available Emergency Credit (D.7.2.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SelectEmergencyCredit {
    /// Command issue date / time.
    pub issued: u32,
    /// Originating device (Table D-146).
    pub originator: u8,
}

impl SelectEmergencyCredit {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(SelectEmergencyCredit {
            issued: r.u32_le()?,
            originator: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issued)?;
        w.u8(self.originator)
    }
}

/// Change Debt (D.7.2.3.3); "unchanged" markers keep the current values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChangeDebt<'a> {
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Debt label (`[0xff]` unchanged).
    pub label: &'a [u8],
    /// Debt amount.
    pub amount: i32,
    /// Recovery method.
    pub recovery_method: u8,
    /// Debt amount type (Table D-147).
    pub amount_type: u8,
    /// Recovery start time.
    pub recovery_start: u32,
    /// Recovery collection time (minutes).
    pub recovery_collection_time: u16,
    /// Recovery frequency.
    pub recovery_frequency: u8,
    /// Recovery amount.
    pub recovery_amount: i32,
    /// Recovery balance percentage.
    pub recovery_balance_percentage: u16,
}

impl<'a> ChangeDebt<'a> {
    /// Parses the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ChangeDebt {
            issuer_event_id: r.u32_le()?,
            label: read_octstr(&mut r)?,
            amount: r.i32_le()?,
            recovery_method: r.u8()?,
            amount_type: r.u8()?,
            recovery_start: r.u32_le()?,
            recovery_collection_time: r.u16_le()?,
            recovery_frequency: r.u8()?,
            recovery_amount: r.i32_le()?,
            recovery_balance_percentage: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        write_octstr(w, self.label)?;
        w.i32_le(self.amount)?;
        w.u8(self.recovery_method)?;
        w.u8(self.amount_type)?;
        w.u32_le(self.recovery_start)?;
        w.u16_le(self.recovery_collection_time)?;
        w.u8(self.recovery_frequency)?;
        w.i32_le(self.recovery_amount)?;
        w.u16_le(self.recovery_balance_percentage)
    }

    /// The debt slot (1–3) addressed by the amount type.
    pub const fn debt_index(&self) -> u8 {
        self.amount_type / 2 + 1
    }

    /// Whether the amount is incremental.
    pub const fn is_incremental(&self) -> bool {
        self.amount_type % 2 == 1
    }
}

/// Emergency Credit Setup (D.7.2.3.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EmergencyCreditSetup {
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Start time (0 immediately, 0xffffffff cancel).
    pub start_time: u32,
    /// Emergency credit limit / allowance.
    pub limit: u32,
    /// Emergency credit threshold.
    pub threshold: u32,
}

impl EmergencyCreditSetup {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(EmergencyCreditSetup {
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            limit: r.u32_le()?,
            threshold: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u32_le(self.limit)?;
        w.u32_le(self.threshold)
    }
}

/// Consumer Top Up (D.7.2.3.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConsumerTopUp<'a> {
    /// Originating device.
    pub originator: u8,
    /// Top-up code (1–25 octets).
    pub code: &'a [u8],
}

impl<'a> ConsumerTopUp<'a> {
    /// Parses the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ConsumerTopUp {
            originator: r.u8()?,
            code: read_octstr(&mut r)?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.originator)?;
        write_octstr(w, self.code)
    }
}

/// Credit Adjustment (D.7.2.3.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CreditAdjustment {
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Start time.
    pub start_time: u32,
    /// Adjustment type (Table D-148).
    pub adjustment_type: u8,
    /// Adjustment value.
    pub value: i32,
}

impl CreditAdjustment {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CreditAdjustment {
            issuer_event_id: r.u32_le()?,
            start_time: r.u32_le()?,
            adjustment_type: r.u8()?,
            value: r.i32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u8(self.adjustment_type)?;
        w.i32_le(self.value)
    }
}

/// Change Payment Mode (D.7.2.3.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChangePaymentMode {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Implementation date / time.
    pub implementation_time: u32,
    /// Proposed `PaymentControlConfiguration`.
    pub proposed_configuration: u16,
    /// Cut-off value (0xffffffff unchanged).
    pub cut_off_value: i32,
}

impl ChangePaymentMode {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ChangePaymentMode {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            implementation_time: r.u32_le()?,
            proposed_configuration: r.u16_le()?,
            cut_off_value: r.i32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.implementation_time)?;
        w.u16_le(self.proposed_configuration)?;
        w.i32_le(self.cut_off_value)
    }
}

/// Get Prepay Snapshot (D.7.2.3.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetPrepaySnapshot {
    /// Earliest start time.
    pub earliest_start: u32,
    /// Latest end time.
    pub latest_end: u32,
    /// Snapshot offset.
    pub offset: u8,
    /// Snapshot cause filter.
    pub cause: u32,
}

impl GetPrepaySnapshot {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetPrepaySnapshot {
            earliest_start: r.u32_le()?,
            latest_end: r.u32_le()?,
            offset: r.u8()?,
            cause: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.earliest_start)?;
        w.u32_le(self.latest_end)?;
        w.u8(self.offset)?;
        w.u32_le(self.cause)
    }
}

/// Get Top Up Log (D.7.2.3.9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetTopUpLog {
    /// Latest end time.
    pub latest_end: u32,
    /// Records wanted (0: all).
    pub records: u8,
}

impl GetTopUpLog {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetTopUpLog {
            latest_end: r.u32_le()?,
            records: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.latest_end)?;
        w.u8(self.records)
    }
}

/// Get Debt Repayment Log (D.7.2.3.11).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetDebtRepaymentLog {
    /// Latest end time.
    pub latest_end: u32,
    /// Records wanted (0: all).
    pub records: u8,
    /// Debt type filter (Table D-149).
    pub debt_type: u8,
}

impl GetDebtRepaymentLog {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetDebtRepaymentLog {
            latest_end: r.u32_le()?,
            records: r.u8()?,
            debt_type: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.latest_end)?;
        w.u8(self.records)?;
        w.u8(self.debt_type)
    }
}

/// Set Maximum Credit Limit (D.7.2.3.12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SetMaximumCreditLimit {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Implementation date / time.
    pub implementation_time: u32,
    /// Maximum credit level (0xffffffff disabled).
    pub max_credit_level: u32,
    /// Maximum credit per top-up (0xffffffff disabled).
    pub max_credit_per_top_up: u32,
}

impl SetMaximumCreditLimit {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(SetMaximumCreditLimit {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            implementation_time: r.u32_le()?,
            max_credit_level: r.u32_le()?,
            max_credit_per_top_up: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.implementation_time)?;
        w.u32_le(self.max_credit_level)?;
        w.u32_le(self.max_credit_per_top_up)
    }
}

/// Set Overall Debt Cap (D.7.2.3.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SetOverallDebtCap {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Implementation date / time.
    pub implementation_time: u32,
    /// Overall debt cap.
    pub cap: i32,
}

impl SetOverallDebtCap {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(SetOverallDebtCap {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            implementation_time: r.u32_le()?,
            cap: r.i32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.implementation_time)?;
        w.i32_le(self.cap)
    }
}

/// Reads a Set Low Credit Warning Level payload.
pub fn parse_low_credit_warning_level(bytes: &[u8]) -> Result<u32, CodecError> {
    Reader::new(bytes).u32_le()
}

/// The Debt/Credit Status snapshot payload (Figure D-128).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DebtCreditStatus {
    /// Accumulated debt.
    pub accumulated_debt: i32,
    /// Type 1 debt remaining.
    pub type1_debt: u32,
    /// Type 2 debt remaining.
    pub type2_debt: u32,
    /// Type 3 debt remaining.
    pub type3_debt: u32,
    /// Emergency credit remaining.
    pub emergency_credit_remaining: i32,
    /// Credit remaining.
    pub credit_remaining: i32,
}

/// Publish Prepay Snapshot (D.7.2.4.2) with a Debt/Credit Status payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishPrepaySnapshot {
    /// Snapshot identifier.
    pub snapshot_id: u32,
    /// Snapshot time.
    pub snapshot_time: u32,
    /// Total snapshots found.
    pub total_found: u8,
    /// Command index.
    pub command_index: u8,
    /// Total number of commands.
    pub total_commands: u8,
    /// Snapshot cause.
    pub cause: u32,
    /// The status payload.
    pub status: DebtCreditStatus,
}

impl PublishPrepaySnapshot {
    /// Parses the payload (Debt/Credit Status type only).
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let snapshot_id = r.u32_le()?;
        let snapshot_time = r.u32_le()?;
        let total_found = r.u8()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let cause = r.u32_le()?;
        let ty = r.u8()?;
        if ty != SNAPSHOT_PAYLOAD_DEBT_CREDIT_STATUS {
            return Err(CodecError::Unsupported {
                what: "prepay snapshot payload type",
            });
        }
        let status = DebtCreditStatus {
            accumulated_debt: r.i32_le()?,
            type1_debt: r.u32_le()?,
            type2_debt: r.u32_le()?,
            type3_debt: r.u32_le()?,
            emergency_credit_remaining: r.i32_le()?,
            credit_remaining: r.i32_le()?,
        };
        Ok(PublishPrepaySnapshot {
            snapshot_id,
            snapshot_time,
            total_found,
            command_index,
            total_commands,
            cause,
            status,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.snapshot_id)?;
        w.u32_le(self.snapshot_time)?;
        w.u8(self.total_found)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        w.u32_le(self.cause)?;
        w.u8(SNAPSHOT_PAYLOAD_DEBT_CREDIT_STATUS)?;
        w.i32_le(self.status.accumulated_debt)?;
        w.u32_le(self.status.type1_debt)?;
        w.u32_le(self.status.type2_debt)?;
        w.u32_le(self.status.type3_debt)?;
        w.i32_le(self.status.emergency_credit_remaining)?;
        w.i32_le(self.status.credit_remaining)
    }
}

/// Change Payment Mode Response (D.7.2.4.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChangePaymentModeResponse {
    /// Friendly credit enabled (bit 0).
    pub friendly_credit: u8,
    /// Friendly credit calendar identifier.
    pub friendly_credit_calendar_id: u32,
    /// Emergency credit limit.
    pub emergency_credit_limit: u32,
    /// Emergency credit threshold.
    pub emergency_credit_threshold: u32,
}

impl ChangePaymentModeResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ChangePaymentModeResponse {
            friendly_credit: r.u8()?,
            friendly_credit_calendar_id: r.u32_le()?,
            emergency_credit_limit: r.u32_le()?,
            emergency_credit_threshold: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.friendly_credit)?;
        w.u32_le(self.friendly_credit_calendar_id)?;
        w.u32_le(self.emergency_credit_limit)?;
        w.u32_le(self.emergency_credit_threshold)
    }
}

/// Consumer Top Up Response (D.7.2.4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConsumerTopUpResponse {
    /// Result type (Table D-154).
    pub result: u8,
    /// Top-up value (-1 when not accepted).
    pub value: i32,
    /// Source of the top-up.
    pub source: u8,
    /// Credit remaining (-1 when not accepted).
    pub credit_remaining: i32,
}

impl ConsumerTopUpResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ConsumerTopUpResponse {
            result: r.u8()?,
            value: r.i32_le()?,
            source: r.u8()?,
            credit_remaining: r.i32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.result)?;
        w.i32_le(self.value)?;
        w.u8(self.source)?;
        w.i32_le(self.credit_remaining)
    }
}

/// A top-up log record.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TopUpRecord {
    /// Top-up code.
    pub code: Vec<u8, MAX_TOP_UP_CODE>,
    /// Amount.
    pub amount: i32,
    /// Time.
    pub time: u32,
}

/// Records per Publish Top Up Log kept here.
pub const MAX_TOP_UP_RECORDS: usize = 5;

/// Publish Top Up Log (D.7.2.4.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishTopUpLog {
    /// Command index.
    pub command_index: u8,
    /// Total number of commands.
    pub total_commands: u8,
    /// Records, most recent first.
    pub records: Vec<TopUpRecord, MAX_TOP_UP_RECORDS>,
}

impl PublishTopUpLog {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let mut records = Vec::new();
        while !r.is_empty() {
            let code = read_octstr(&mut r)?;
            let rec = TopUpRecord {
                code: Vec::from_slice(code).map_err(|_| CodecError::Unrepresentable {
                    field: "top-up code",
                })?,
                amount: r.i32_le()?,
                time: r.u32_le()?,
            };
            records.push(rec).map_err(|_| CodecError::Unrepresentable {
                field: "top-up records",
            })?;
        }
        Ok(PublishTopUpLog {
            command_index,
            total_commands,
            records,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        for rec in &self.records {
            write_octstr(w, &rec.code)?;
            w.i32_le(rec.amount)?;
            w.u32_le(rec.time)?;
        }
        Ok(())
    }
}

/// A debt repayment record (Figure D-134).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DebtRecord {
    /// Collection time.
    pub collection_time: u32,
    /// Amount collected.
    pub amount_collected: u32,
    /// Debt type (Table D-149).
    pub debt_type: u8,
    /// Outstanding debt.
    pub outstanding: u32,
}

/// Records per Publish Debt Log kept here.
pub const MAX_DEBT_RECORDS: usize = 8;

/// Publish Debt Log (D.7.2.4.6).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishDebtLog {
    /// Command index.
    pub command_index: u8,
    /// Total number of commands.
    pub total_commands: u8,
    /// Records, most recent first.
    pub records: Vec<DebtRecord, MAX_DEBT_RECORDS>,
}

impl PublishDebtLog {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let mut records = Vec::new();
        while !r.is_empty() {
            let rec = DebtRecord {
                collection_time: r.u32_le()?,
                amount_collected: r.u32_le()?,
                debt_type: r.u8()?,
                outstanding: r.u32_le()?,
            };
            records.push(rec).map_err(|_| CodecError::Unrepresentable {
                field: "debt records",
            })?;
        }
        Ok(PublishDebtLog {
            command_index,
            total_commands,
            records,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        for rec in &self.records {
            w.u32_le(rec.collection_time)?;
            w.u32_le(rec.amount_collected)?;
            w.u8(rec.debt_type)?;
            w.u32_le(rec.outstanding)?;
        }
        Ok(())
    }
}

/// A prepayment account: the credit rules of a metering device.
#[derive(Clone, Debug)]
pub struct Account {
    /// `PaymentControlConfiguration`.
    pub configuration: u16,
    /// Credit remaining.
    pub credit: i32,
    /// Emergency credit remaining.
    pub emergency_credit: i32,
    /// Emergency credit limit / allowance.
    pub emergency_limit: u32,
    /// Emergency credit threshold.
    pub emergency_threshold: u32,
    /// Emergency credit selected by the consumer.
    pub emergency_selected: bool,
    /// Accumulated debt.
    pub accumulated_debt: i32,
    /// Overall debt cap.
    pub overall_debt_cap: i32,
    /// Maximum credit limit (0xffffffff disabled).
    pub max_credit_limit: u32,
    /// Maximum credit per top-up (0xffffffff disabled).
    pub max_credit_per_top_up: u32,
    /// Low credit warning level.
    pub low_credit_warning: u32,
    /// Cut-off value.
    pub cut_off: i32,
    /// Total credit added.
    pub total_credit_added: u64,
    /// Top-up log, most recent first.
    pub top_ups: Vec<TopUpRecord, MAX_TOP_UP_RECORDS>,
    /// Debt repayment log, most recent first.
    pub debts: Vec<DebtRecord, MAX_DEBT_RECORDS>,
    /// Outstanding debt per type (1–3).
    pub debt_remaining: [u32; 3],
    /// When the payment mode last changed (0: never).
    pub payment_mode_changed_at: u32,
}

impl Account {
    /// A prepayment account with no credit.
    pub const fn new(configuration: u16) -> Self {
        Account {
            configuration,
            credit: 0,
            emergency_credit: 0,
            emergency_limit: 0,
            emergency_threshold: 0,
            emergency_selected: false,
            accumulated_debt: 0,
            overall_debt_cap: i32::MAX,
            max_credit_limit: UNCHANGED_U32,
            max_credit_per_top_up: UNCHANGED_U32,
            low_credit_warning: 0,
            cut_off: 0,
            total_credit_added: 0,
            top_ups: Vec::new(),
            debts: Vec::new(),
            debt_remaining: [0; 3],
            payment_mode_changed_at: 0,
        }
    }

    /// `CreditStatus` derived from the balances (Table D-131, D.7.4.1).
    pub fn credit_status(&self) -> u8 {
        let mut s = 0;
        let above_cut_off = self.credit > self.cut_off;
        if above_cut_off
            && u64::try_from(self.credit - self.cut_off).unwrap_or(0)
                > u64::from(self.low_credit_warning)
        {
            s |= credit_status::CREDIT_OK;
        } else if above_cut_off {
            s |= credit_status::LOW_CREDIT;
        }
        if self.emergency_limit > 0 {
            s |= credit_status::EMERGENCY_CREDIT_ENABLED;
            if self.emergency_credit > 0 {
                let below_threshold = u64::try_from(self.credit.max(0)).unwrap_or(0)
                    <= u64::from(self.emergency_threshold);
                if below_threshold && !self.emergency_selected {
                    s |= credit_status::EMERGENCY_CREDIT_AVAILABLE;
                }
                if self.emergency_selected {
                    s |= credit_status::EMERGENCY_CREDIT_SELECTED;
                    if !above_cut_off {
                        s |= credit_status::EMERGENCY_CREDIT_IN_USE;
                    }
                }
            }
        }
        let emergency_running = self.emergency_selected && self.emergency_credit > 0;
        if !above_cut_off && !emergency_running {
            s |= credit_status::CREDIT_EXHAUSTED;
        }
        s
    }

    /// Selects emergency credit (D.7.2.3.1); `false` when none is
    /// available or credit is not below the threshold.
    pub fn select_emergency_credit(&mut self) -> bool {
        let below =
            u64::try_from(self.credit.max(0)).unwrap_or(0) <= u64::from(self.emergency_threshold);
        if self.emergency_limit == 0 || self.emergency_credit <= 0 || !below {
            return false;
        }
        self.emergency_selected = true;
        true
    }

    /// Applies an Emergency Credit Setup: resets the remaining emergency
    /// credit to the new allowance.
    pub fn setup_emergency_credit(&mut self, setup: &EmergencyCreditSetup) {
        self.emergency_limit = setup.limit;
        self.emergency_threshold = setup.threshold;
        self.emergency_credit = i32::try_from(setup.limit).unwrap_or(i32::MAX);
        self.emergency_selected = false;
    }

    /// Applies a top-up of `amount` (already validated by the
    /// application's token handling) at `time`; returns the Consumer Top
    /// Up Response result and records the top-up on success.
    pub fn top_up(&mut self, code: &[u8], amount: i32, time: u32) -> u8 {
        if code.is_empty() || code.len() > MAX_TOP_UP_CODE {
            return top_up_result::REJECTED_INVALID;
        }
        if self.top_ups.iter().any(|t| t.code.as_slice() == code) {
            return top_up_result::REJECTED_DUPLICATE;
        }
        if amount < 0 {
            return top_up_result::REJECTED_INVALID;
        }
        if self.max_credit_per_top_up != UNCHANGED_U32
            && u32::try_from(amount).unwrap_or(u32::MAX) > self.max_credit_per_top_up
        {
            return top_up_result::REJECTED_TOO_LARGE;
        }
        let new_credit = self.credit.saturating_add(amount);
        if self.max_credit_limit != UNCHANGED_U32
            && u64::try_from(new_credit).unwrap_or(0) > u64::from(self.max_credit_limit)
        {
            return top_up_result::REJECTED_MAX_CREDIT;
        }
        self.credit = new_credit;
        self.total_credit_added = self
            .total_credit_added
            .saturating_add(u64::try_from(amount).unwrap_or(0));
        // Restoring credit ends an emergency credit period.
        if self.credit > self.cut_off {
            self.emergency_selected = false;
        }
        let rec = TopUpRecord {
            code: Vec::from_slice(code).unwrap_or_default(),
            amount,
            time,
        };
        if self.top_ups.is_full() {
            self.top_ups.pop();
        }
        let _ = self.top_ups.insert(0, rec);
        top_up_result::ACCEPTED
    }

    /// Applies a Credit Adjustment (D.7.2.3.6).
    pub fn adjust_credit(&mut self, adjustment: &CreditAdjustment) -> bool {
        match adjustment.adjustment_type {
            credit_adjustment_type::INCREMENTAL => {
                self.credit = self.credit.saturating_add(adjustment.value);
            }
            credit_adjustment_type::ABSOLUTE => self.credit = adjustment.value,
            _ => return false,
        }
        true
    }

    /// Applies a Change Debt (D.7.2.3.3) to the addressed debt slot;
    /// `false` for a reserved amount type.
    pub fn change_debt(&mut self, change: &ChangeDebt<'_>) -> bool {
        let i = usize::from(change.debt_index()).checked_sub(1);
        let Some(slot) = i.and_then(|i| self.debt_remaining.get_mut(i)) else {
            return false;
        };
        if change.amount_type > debt_amount_type::TYPE_3_INCREMENTAL {
            return false;
        }
        if change.amount != -1 {
            let amount = u32::try_from(change.amount.max(0)).unwrap_or(0);
            *slot = if change.is_incremental() {
                slot.saturating_add(amount)
            } else {
                amount
            };
        }
        let total: u64 = self.debt_remaining.iter().map(|d| u64::from(*d)).sum();
        self.accumulated_debt = i32::try_from(total).unwrap_or(i32::MAX);
        true
    }

    /// Records a debt collection of `amount` from debt `debt_type`
    /// (0–2) at `time`.
    pub fn collect_debt(&mut self, debt_type: u8, amount: u32, time: u32) -> Option<DebtRecord> {
        let slot = self.debt_remaining.get_mut(usize::from(debt_type))?;
        *slot = slot.saturating_sub(amount);
        let outstanding = *slot;
        let total: u64 = self.debt_remaining.iter().map(|d| u64::from(*d)).sum();
        self.accumulated_debt = i32::try_from(total).unwrap_or(i32::MAX);
        self.credit = self
            .credit
            .saturating_sub(i32::try_from(amount).unwrap_or(i32::MAX));
        let rec = DebtRecord {
            collection_time: time,
            amount_collected: amount,
            debt_type,
            outstanding,
        };
        if self.debts.is_full() {
            self.debts.pop();
        }
        let _ = self.debts.insert(0, rec);
        Some(rec)
    }

    /// Applies Set Maximum Credit Limit.
    pub fn set_maximum_credit(&mut self, s: &SetMaximumCreditLimit) {
        self.max_credit_limit = s.max_credit_level;
        self.max_credit_per_top_up = s.max_credit_per_top_up;
    }

    /// The Debt/Credit Status snapshot payload.
    pub fn snapshot(&self) -> DebtCreditStatus {
        DebtCreditStatus {
            accumulated_debt: self.accumulated_debt,
            type1_debt: self.debt_remaining[0],
            type2_debt: self.debt_remaining[1],
            type3_debt: self.debt_remaining[2],
            emergency_credit_remaining: self.emergency_credit,
            credit_remaining: self.credit,
        }
    }

    /// The top-up log entries matching a Get Top Up Log request.
    pub fn top_up_log(&self, req: &GetTopUpLog) -> PublishTopUpLog {
        let mut records = Vec::new();
        for t in self.top_ups.iter().filter(|t| t.time <= req.latest_end) {
            if req.records != 0 && records.len() >= usize::from(req.records) {
                break;
            }
            if records.push(t.clone()).is_err() {
                break;
            }
        }
        PublishTopUpLog {
            command_index: 0,
            total_commands: 1,
            records,
        }
    }

    /// The debt log entries matching a Get Debt Repayment Log request.
    pub fn debt_log(&self, req: &GetDebtRepaymentLog) -> PublishDebtLog {
        let mut records = Vec::new();
        for d in self.debts.iter().filter(|d| {
            d.collection_time <= req.latest_end
                && (req.debt_type == debt_type::ALL || d.debt_type == req.debt_type)
        }) {
            if req.records != 0 && records.len() >= usize::from(req.records) {
                break;
            }
            if records.push(*d).is_err() {
                break;
            }
        }
        PublishDebtLog {
            command_index: 0,
            total_commands: 1,
            records,
        }
    }
}

/// A timed prepayment command awaiting its start / implementation time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Timed {
    /// Emergency Credit Setup.
    EmergencyCredit(EmergencyCreditSetup),
    /// Credit Adjustment.
    CreditAdjustment(CreditAdjustment),
    /// Change Payment Mode.
    PaymentMode(ChangePaymentMode),
    /// Set Maximum Credit Limit.
    MaximumCredit(SetMaximumCreditLimit),
    /// Set Overall Debt Cap.
    DebtCap(SetOverallDebtCap),
}

impl Timed {
    /// The command's start / implementation time.
    pub const fn time(&self) -> u32 {
        match self {
            Timed::EmergencyCredit(c) => c.start_time,
            Timed::CreditAdjustment(c) => c.start_time,
            Timed::PaymentMode(c) => c.implementation_time,
            Timed::MaximumCredit(c) => c.implementation_time,
            Timed::DebtCap(c) => c.implementation_time,
        }
    }

    /// Issuer event id.
    pub const fn issuer_event_id(&self) -> u32 {
        match self {
            Timed::EmergencyCredit(c) => c.issuer_event_id,
            Timed::CreditAdjustment(c) => c.issuer_event_id,
            Timed::PaymentMode(c) => c.issuer_event_id,
            Timed::MaximumCredit(c) => c.issuer_event_id,
            Timed::DebtCap(c) => c.issuer_event_id,
        }
    }

    /// Provider id, for the commands that carry one.
    pub const fn provider_id(&self) -> Option<u32> {
        match self {
            Timed::EmergencyCredit(_) | Timed::CreditAdjustment(_) => None,
            Timed::PaymentMode(c) => Some(c.provider_id),
            Timed::MaximumCredit(c) => Some(c.provider_id),
            Timed::DebtCap(c) => Some(c.provider_id),
        }
    }

    const fn kind(&self) -> u8 {
        match self {
            Timed::EmergencyCredit(_) => 0,
            Timed::CreditAdjustment(_) => 1,
            Timed::PaymentMode(_) => 2,
            Timed::MaximumCredit(_) => 3,
            Timed::DebtCap(_) => 4,
        }
    }

    /// Applies the command to the account at `now`.
    pub fn apply(&self, account: &mut Account, now: u32) -> bool {
        match self {
            Timed::EmergencyCredit(c) => {
                account.setup_emergency_credit(c);
                true
            }
            Timed::CreditAdjustment(c) => account.adjust_credit(c),
            Timed::PaymentMode(c) => {
                account.configuration = c.proposed_configuration;
                if c.cut_off_value != -1 {
                    account.cut_off = c.cut_off_value;
                }
                account.payment_mode_changed_at = now;
                true
            }
            Timed::MaximumCredit(c) => {
                account.set_maximum_credit(c);
                true
            }
            Timed::DebtCap(c) => {
                account.overall_debt_cap = c.cap;
                true
            }
        }
    }
}

/// What the scheduler did with a timed command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Scheduling {
    /// Applied immediately.
    Applied,
    /// Queued for its time (replacing an older pending command of the
    /// same kind).
    Scheduled,
    /// A pending command was cancelled.
    Cancelled,
    /// A cancellation named no pending command (NOT_FOUND).
    NotFound,
    /// Older than a pending command of the same kind: ignored.
    Stale,
    /// The command is malformed (FAILURE).
    Rejected,
}

/// Scheduler of the timed prepayment commands (D.7.2.3.4, .6, .7, .11,
/// .12): a start / implementation time of 0 applies now, 0xFFFFFFFF
/// cancels the pending command with the same issuer event id (and
/// provider, where carried), a newer pending command of the same kind
/// replaces an older one, and [`Pending::poll`] applies due commands.
#[derive(Clone, Debug, Default)]
pub struct Pending {
    queue: Vec<Timed, 8>,
}

impl Pending {
    /// Nothing pending.
    pub const fn new() -> Self {
        Pending { queue: Vec::new() }
    }

    /// Schedules (or applies, or cancels) `cmd` at `now`.
    pub fn schedule(&mut self, cmd: Timed, account: &mut Account, now: u32) -> Scheduling {
        if cmd.time() == CANCEL {
            let before = self.queue.len();
            self.queue.retain(|p| {
                !(p.kind() == cmd.kind()
                    && p.issuer_event_id() == cmd.issuer_event_id()
                    && p.provider_id() == cmd.provider_id())
            });
            return if self.queue.len() != before {
                Scheduling::Cancelled
            } else {
                Scheduling::NotFound
            };
        }
        if cmd.time() == IMMEDIATELY || cmd.time() <= now {
            return if cmd.apply(account, now) {
                Scheduling::Applied
            } else {
                Scheduling::Rejected
            };
        }
        if self
            .queue
            .iter()
            .any(|p| p.kind() == cmd.kind() && p.issuer_event_id() > cmd.issuer_event_id())
        {
            return Scheduling::Stale;
        }
        self.queue.retain(|p| p.kind() != cmd.kind());
        match self.queue.push(cmd) {
            Ok(()) => Scheduling::Scheduled,
            Err(_) => Scheduling::Rejected,
        }
    }

    /// Applies the commands whose time has come; returns them.
    pub fn poll(&mut self, account: &mut Account, now: u32) -> Vec<Timed, 8> {
        let mut due = Vec::new();
        let mut i = 0;
        while i < self.queue.len() {
            if self.queue[i].time() <= now {
                let cmd = self.queue.remove(i);
                cmd.apply(account, now);
                let _ = due.push(cmd);
            } else {
                i += 1;
            }
        }
        due
    }

    /// When the next command is due.
    pub fn next_deadline(&self) -> Option<u32> {
        self.queue.iter().map(Timed::time).min()
    }

    /// The pending commands.
    pub fn pending(&self) -> &[Timed] {
        &self.queue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: PartialEq + core::fmt::Debug>(
        v: &T,
        enc: impl Fn(&T, &mut Writer<'_>) -> Result<(), CodecError>,
        dec: impl Fn(&[u8]) -> Result<T, CodecError>,
    ) -> usize {
        let mut buf = [0u8; 128];
        let mut w = Writer::new(&mut buf);
        enc(v, &mut w).unwrap();
        let n = w.position();
        assert_eq!(&dec(&buf[..n]).unwrap(), v);
        n
    }

    #[test]
    fn alarm_codes_map_to_their_masks_and_historical_costs_to_their_ids() {
        use alarm_code as ac;
        assert_eq!(
            ac::mask_bit(ac::LOW_CREDIT),
            Some((attr::PREPAY_GENERIC_ALARM_MASK, 1 << 0))
        );
        assert_eq!(
            ac::mask_bit(ac::REMOTE_DISCONNECTED),
            Some((attr::PREPAY_SWITCH_ALARM_MASK, 1 << 6))
        );
        assert_eq!(
            ac::mask_bit(ac::FRIENDLY_CREDIT_PERIOD_END),
            Some((attr::PREPAY_EVENT_ALARM_MASK, 1 << 13))
        );
        // Event codes beyond 0x2F have no bit in a 16-bit mask.
        assert_eq!(ac::mask_bit(ac::PREPAY_CLUSTER_NOT_FOUND), None);
        assert_eq!(ac::mask_bit(ac::MODE_DEFAULT), None);
        assert_eq!(ac::mask_bit(0x50), None);
        // Enabled when the group's mask has the bit set.
        assert!(ac::enabled(ac::SUPPLY_OFF, 0, 1 << 2, 0));
        assert!(!ac::enabled(ac::SUPPLY_OFF, 0xFFFF, 0, 0xFFFF));
        assert!(ac::enabled(ac::TOP_UP_CODE_ERROR, 0, 0, 1 << 8));
        assert!(!ac::enabled(0x60, 0xFFFF, 0xFFFF, 0xFFFF));

        use historical_cost as hc;
        assert_eq!(hc::previous_day(1, false), Some(AttributeId(0x051E)));
        assert_eq!(hc::previous_day(1, true), Some(AttributeId(0x051F)));
        assert_eq!(hc::previous_day(8, true), Some(AttributeId(0x052D)));
        assert_eq!(hc::previous_day(9, false), None);
        assert_eq!(hc::previous_week(5, true), Some(AttributeId(0x053B)));
        assert_eq!(hc::previous_week(6, false), None);
        assert_eq!(hc::previous_month(13, true), Some(AttributeId(0x055B)));
        assert_eq!(hc::previous_month(0, false), None);
    }

    #[test]
    fn command_codecs_round_trip() {
        roundtrip(
            &SelectEmergencyCredit {
                issued: 1,
                originator: originating_device::IHD,
            },
            SelectEmergencyCredit::encode,
            SelectEmergencyCredit::parse,
        );
        let cd = ChangeDebt {
            issuer_event_id: 5,
            label: b"Arrears",
            amount: 1000,
            recovery_method: 0,
            amount_type: debt_amount_type::TYPE_2_INCREMENTAL,
            recovery_start: 0,
            recovery_collection_time: 60,
            recovery_frequency: 1,
            recovery_amount: 10,
            recovery_balance_percentage: 500,
        };
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        cd.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 4 + 8 + 4 + 1 + 1 + 4 + 2 + 1 + 4 + 2);
        assert_eq!(ChangeDebt::parse(&buf[..n]).unwrap(), cd);
        assert_eq!((cd.debt_index(), cd.is_incremental()), (2, true));
        let unchanged = ChangeDebt {
            label: &[0xff],
            ..cd
        };
        let mut w = Writer::new(&mut buf);
        unchanged.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(ChangeDebt::parse(&buf[..n]).unwrap(), unchanged);
        roundtrip(
            &EmergencyCreditSetup {
                issuer_event_id: 1,
                start_time: IMMEDIATELY,
                limit: 500,
                threshold: 100,
            },
            EmergencyCreditSetup::encode,
            EmergencyCreditSetup::parse,
        );
        let top_up = ConsumerTopUp {
            originator: originating_device::ESI,
            code: b"12345678901234567890",
        };
        let mut w = Writer::new(&mut buf);
        top_up.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(ConsumerTopUp::parse(&buf[..n]).unwrap(), top_up);
        roundtrip(
            &CreditAdjustment {
                issuer_event_id: 1,
                start_time: 0,
                adjustment_type: credit_adjustment_type::ABSOLUTE,
                value: -5,
            },
            CreditAdjustment::encode,
            CreditAdjustment::parse,
        );
        roundtrip(
            &ChangePaymentMode {
                provider_id: 1,
                issuer_event_id: 2,
                implementation_time: 3,
                proposed_configuration: payment_control::PREPAYMENT_ENABLED,
                cut_off_value: -1,
            },
            ChangePaymentMode::encode,
            ChangePaymentMode::parse,
        );
        roundtrip(
            &GetPrepaySnapshot {
                earliest_start: 0,
                latest_end: 100,
                offset: 0,
                cause: snapshot_cause::ALL,
            },
            GetPrepaySnapshot::encode,
            GetPrepaySnapshot::parse,
        );
        roundtrip(
            &GetTopUpLog {
                latest_end: 100,
                records: 2,
            },
            GetTopUpLog::encode,
            GetTopUpLog::parse,
        );
        roundtrip(
            &GetDebtRepaymentLog {
                latest_end: 100,
                records: 0,
                debt_type: debt_type::ALL,
            },
            GetDebtRepaymentLog::encode,
            GetDebtRepaymentLog::parse,
        );
        roundtrip(
            &SetMaximumCreditLimit {
                provider_id: 1,
                issuer_event_id: 2,
                implementation_time: 0,
                max_credit_level: 10_000,
                max_credit_per_top_up: 1_000,
            },
            SetMaximumCreditLimit::encode,
            SetMaximumCreditLimit::parse,
        );
        roundtrip(
            &SetOverallDebtCap {
                provider_id: 1,
                issuer_event_id: 2,
                implementation_time: 0,
                cap: 5000,
            },
            SetOverallDebtCap::encode,
            SetOverallDebtCap::parse,
        );
        assert_eq!(
            parse_low_credit_warning_level(&[0x10, 0, 0, 0]).unwrap(),
            16
        );
    }

    #[test]
    fn response_codecs_round_trip() {
        let snap = PublishPrepaySnapshot {
            snapshot_id: 7,
            snapshot_time: 100,
            total_found: 1,
            command_index: 0,
            total_commands: 1,
            cause: snapshot_cause::TOP_UP_ADDITION,
            status: DebtCreditStatus {
                accumulated_debt: 30,
                type1_debt: 10,
                type2_debt: 20,
                type3_debt: 0,
                emergency_credit_remaining: 500,
                credit_remaining: 1234,
            },
        };
        assert_eq!(
            roundtrip(
                &snap,
                PublishPrepaySnapshot::encode,
                PublishPrepaySnapshot::parse
            ),
            16 + 24
        );
        roundtrip(
            &ChangePaymentModeResponse {
                friendly_credit: 1,
                friendly_credit_calendar_id: 9,
                emergency_credit_limit: 500,
                emergency_credit_threshold: 100,
            },
            ChangePaymentModeResponse::encode,
            ChangePaymentModeResponse::parse,
        );
        roundtrip(
            &ConsumerTopUpResponse {
                result: top_up_result::ACCEPTED,
                value: 1000,
                source: originating_device::IHD,
                credit_remaining: 1234,
            },
            ConsumerTopUpResponse::encode,
            ConsumerTopUpResponse::parse,
        );
        let mut records = Vec::new();
        records
            .push(TopUpRecord {
                code: Vec::from_slice(b"ABC").unwrap(),
                amount: 10,
                time: 5,
            })
            .unwrap();
        records
            .push(TopUpRecord {
                code: Vec::from_slice(b"DEF").unwrap(),
                amount: 20,
                time: 3,
            })
            .unwrap();
        roundtrip(
            &PublishTopUpLog {
                command_index: 0,
                total_commands: 1,
                records,
            },
            PublishTopUpLog::encode,
            PublishTopUpLog::parse,
        );
        let mut debts = Vec::new();
        debts
            .push(DebtRecord {
                collection_time: 5,
                amount_collected: 10,
                debt_type: debt_type::DEBT_1,
                outstanding: 90,
            })
            .unwrap();
        roundtrip(
            &PublishDebtLog {
                command_index: 0,
                total_commands: 1,
                records: debts,
            },
            PublishDebtLog::encode,
            PublishDebtLog::parse,
        );
    }

    #[test]
    fn account_applies_top_ups_limits_and_status() {
        let mut a = Account::new(
            payment_control::PREPAYMENT_ENABLED | payment_control::DISCONNECTION_ENABLED,
        );
        a.low_credit_warning = 200;
        assert_eq!(a.credit_status(), credit_status::CREDIT_EXHAUSTED);
        assert_eq!(a.top_up(b"", 100, 1), top_up_result::REJECTED_INVALID);
        assert_eq!(a.top_up(b"T1", 1000, 1), top_up_result::ACCEPTED);
        assert_eq!(a.credit, 1000);
        assert_eq!(a.credit_status(), credit_status::CREDIT_OK);
        assert_eq!(a.top_up(b"T1", 1000, 2), top_up_result::REJECTED_DUPLICATE);
        a.set_maximum_credit(&SetMaximumCreditLimit {
            provider_id: 1,
            issuer_event_id: 1,
            implementation_time: 0,
            max_credit_level: 1500,
            max_credit_per_top_up: 400,
        });
        assert_eq!(a.top_up(b"T2", 500, 3), top_up_result::REJECTED_TOO_LARGE);
        assert_eq!(a.top_up(b"T2", 400, 3), top_up_result::ACCEPTED);
        assert_eq!(a.top_up(b"T3", 400, 4), top_up_result::REJECTED_MAX_CREDIT);
        assert_eq!(a.total_credit_added, 1400);
        assert_eq!(a.top_ups[0].code.as_slice(), b"T2", "most recent first");
        // Credit burns down: low credit, then exhausted with emergency credit.
        a.adjust_credit(&CreditAdjustment {
            issuer_event_id: 1,
            start_time: 0,
            adjustment_type: credit_adjustment_type::ABSOLUTE,
            value: 150,
        });
        assert_eq!(a.credit_status(), credit_status::LOW_CREDIT);
        a.setup_emergency_credit(&EmergencyCreditSetup {
            issuer_event_id: 2,
            start_time: 0,
            limit: 300,
            threshold: 200,
        });
        assert_eq!(
            a.credit_status(),
            credit_status::LOW_CREDIT
                | credit_status::EMERGENCY_CREDIT_ENABLED
                | credit_status::EMERGENCY_CREDIT_AVAILABLE
        );
        assert!(a.select_emergency_credit());
        a.adjust_credit(&CreditAdjustment {
            issuer_event_id: 3,
            start_time: 0,
            adjustment_type: credit_adjustment_type::INCREMENTAL,
            value: -150,
        });
        assert_eq!(
            a.credit_status(),
            credit_status::EMERGENCY_CREDIT_ENABLED
                | credit_status::EMERGENCY_CREDIT_SELECTED
                | credit_status::EMERGENCY_CREDIT_IN_USE
        );
        // A top-up above the cut-off ends the emergency period.
        assert_eq!(a.top_up(b"T4", 300, 5), top_up_result::ACCEPTED);
        assert!(!a.emergency_selected);
        let log = a.top_up_log(&GetTopUpLog {
            latest_end: 4,
            records: 1,
        });
        assert_eq!(log.records.len(), 1);
        assert_eq!(log.records[0].code.as_slice(), b"T2");
    }

    #[test]
    fn account_tracks_debts() {
        let mut a = Account::new(payment_control::PREPAYMENT_ENABLED);
        a.credit = 1000;
        assert!(a.change_debt(&ChangeDebt {
            issuer_event_id: 1,
            label: b"Debt",
            amount: 500,
            recovery_method: 0,
            amount_type: debt_amount_type::TYPE_1_ABSOLUTE,
            recovery_start: 0,
            recovery_collection_time: 0,
            recovery_frequency: 0,
            recovery_amount: 50,
            recovery_balance_percentage: 0,
        }));
        assert!(a.change_debt(&ChangeDebt {
            issuer_event_id: 2,
            label: &[0xff],
            amount: 100,
            recovery_method: UNCHANGED_U8,
            amount_type: debt_amount_type::TYPE_1_INCREMENTAL,
            recovery_start: UNCHANGED_U32,
            recovery_collection_time: UNCHANGED_U16,
            recovery_frequency: UNCHANGED_U8,
            recovery_amount: -1,
            recovery_balance_percentage: UNCHANGED_U16,
        }));
        assert_eq!(a.debt_remaining, [600, 0, 0]);
        assert_eq!(a.accumulated_debt, 600);
        let rec = a.collect_debt(debt_type::DEBT_1, 50, 10).unwrap();
        assert_eq!(
            (rec.outstanding, a.credit, a.accumulated_debt),
            (550, 950, 550)
        );
        assert!(a.collect_debt(5, 1, 1).is_none());
        let s = a.snapshot();
        assert_eq!((s.type1_debt, s.credit_remaining), (550, 950));
        let log = a.debt_log(&GetDebtRepaymentLog {
            latest_end: 100,
            records: 0,
            debt_type: debt_type::DEBT_2,
        });
        assert!(log.records.is_empty());
        let log = a.debt_log(&GetDebtRepaymentLog {
            latest_end: 100,
            records: 0,
            debt_type: debt_type::ALL,
        });
        assert_eq!(log.records.len(), 1);
        assert_eq!(attr::debt_amount(3), AttributeId(0x0231));
        assert_eq!(attr::top_up_code(5), AttributeId(0x0143));
    }

    #[test]
    fn timed_commands_are_scheduled_cancelled_and_applied() {
        let mut account = Account::new(0);
        let mut pending = Pending::new();
        let now = 1000;
        let setup = EmergencyCreditSetup {
            issuer_event_id: 1,
            start_time: 5000,
            limit: 500,
            threshold: 100,
        };
        assert_eq!(
            pending.schedule(Timed::EmergencyCredit(setup), &mut account, now),
            Scheduling::Scheduled
        );
        assert_eq!(account.emergency_limit, 0);
        // An older one is stale, a newer one replaces.
        assert_eq!(
            pending.schedule(
                Timed::EmergencyCredit(EmergencyCreditSetup {
                    issuer_event_id: 0,
                    ..setup
                }),
                &mut account,
                now
            ),
            Scheduling::Stale
        );
        assert_eq!(
            pending.schedule(
                Timed::EmergencyCredit(EmergencyCreditSetup {
                    issuer_event_id: 2,
                    limit: 600,
                    ..setup
                }),
                &mut account,
                now
            ),
            Scheduling::Scheduled
        );
        assert_eq!(pending.pending().len(), 1);
        // Immediate commands apply at once.
        let mode = ChangePaymentMode {
            provider_id: 7,
            issuer_event_id: 3,
            implementation_time: IMMEDIATELY,
            proposed_configuration: 0x0001,
            cut_off_value: -1,
        };
        assert_eq!(
            pending.schedule(Timed::PaymentMode(mode), &mut account, now),
            Scheduling::Applied
        );
        assert_eq!(account.configuration, 0x0001);
        assert_eq!(account.payment_mode_changed_at, now);
        // A delayed debt cap, cancelled by provider and issuer event.
        let cap = SetOverallDebtCap {
            provider_id: 7,
            issuer_event_id: 4,
            implementation_time: 8000,
            cap: 1000,
        };
        assert_eq!(
            pending.schedule(Timed::DebtCap(cap), &mut account, now),
            Scheduling::Scheduled
        );
        assert_eq!(pending.next_deadline(), Some(5000));
        assert_eq!(
            pending.schedule(
                Timed::DebtCap(SetOverallDebtCap {
                    provider_id: 8,
                    implementation_time: CANCEL,
                    ..cap
                }),
                &mut account,
                now
            ),
            Scheduling::NotFound
        );
        assert_eq!(
            pending.schedule(
                Timed::DebtCap(SetOverallDebtCap {
                    implementation_time: CANCEL,
                    ..cap
                }),
                &mut account,
                now
            ),
            Scheduling::Cancelled
        );
        // Due commands apply on poll.
        assert!(pending.poll(&mut account, 4999).is_empty());
        let due = pending.poll(&mut account, 5000);
        assert_eq!(due.len(), 1);
        assert_eq!(account.emergency_limit, 600);
        assert_eq!(pending.next_deadline(), None);
        // A reserved adjustment type is rejected.
        assert_eq!(
            pending.schedule(
                Timed::CreditAdjustment(CreditAdjustment {
                    issuer_event_id: 5,
                    start_time: 0,
                    adjustment_type: 0x77,
                    value: 1,
                }),
                &mut account,
                now
            ),
            Scheduling::Rejected
        );
    }
}
