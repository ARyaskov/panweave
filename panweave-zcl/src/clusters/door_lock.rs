//! Door Lock cluster (ZCL8 §7.3): the information, operational,
//! security and event-mask attribute sets, the RF lock operations
//! (Lock, Unlock, Toggle, Unlock with Timeout) with the operating-mode,
//! actuator, PIN and lockout rules, a bounded PIN user table (Set / Get
//! / Clear PIN Code, Clear All, Set / Get User Status and Type), auto
//! relock, the scene extension (a delayed lock or unlock) and the
//! Operation / Programming Event Notifications gated by their masks.
//! The physical bolt belongs to the application: accepted operations
//! are handed over as an [`Action`] and the lock reports back with
//! [`set_lock_state`]. Schedules, RFID codes and the event log are not
//! implemented.
//!
//! PIN codes are credentials: they are stored in a [`Pin`] whose `Debug`
//! output is redacted, compared in constant time, and sent over the air
//! only when `SendPINOverTheAir` allows (masked with 0xff otherwise,
//! §7.3.2.13.3).

use core::fmt;

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId, CommandId};
use subtle::ConstantTimeEq;

use crate::attribute::{Access, AttributeDef, AttributeTable, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0101);

/// `LockState` (enum8, reportable, scene).
pub const LOCK_STATE: AttributeDef = AttributeDef::new(0x0000, DataType::Enum8, Access::RO_REPORT);
/// `LockType` (enum8).
pub const LOCK_TYPE: AttributeDef = AttributeDef::new(0x0001, DataType::Enum8, Access::RO);
/// `ActuatorEnabled` (bool).
pub const ACTUATOR_ENABLED: AttributeDef = AttributeDef::new(0x0002, DataType::Bool, Access::RO);
/// `DoorState` (enum8, reportable).
pub const DOOR_STATE: AttributeDef = AttributeDef::new(0x0003, DataType::Enum8, Access::RO_REPORT);
/// `DoorOpenEvents` (uint32, writable).
pub const DOOR_OPEN_EVENTS: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(4), Access::RW);
/// `DoorClosedEvents` (uint32, writable).
pub const DOOR_CLOSED_EVENTS: AttributeDef =
    AttributeDef::new(0x0005, DataType::Uint(4), Access::RW);
/// `OpenPeriod` (uint16 minutes, writable).
pub const OPEN_PERIOD: AttributeDef = AttributeDef::new(0x0006, DataType::Uint(2), Access::RW);
/// `NumberOfLogRecordsSupported`.
pub const NUMBER_OF_LOG_RECORDS_SUPPORTED: AttributeDef =
    AttributeDef::new(0x0010, DataType::Uint(2), Access::RO);
/// `NumberOfTotalUsersSupported`.
pub const NUMBER_OF_TOTAL_USERS_SUPPORTED: AttributeDef =
    AttributeDef::new(0x0011, DataType::Uint(2), Access::RO);
/// `NumberOfPINUsersSupported`.
pub const NUMBER_OF_PIN_USERS_SUPPORTED: AttributeDef =
    AttributeDef::new(0x0012, DataType::Uint(2), Access::RO);
/// `NumberOfRFIDUsersSupported`.
pub const NUMBER_OF_RFID_USERS_SUPPORTED: AttributeDef =
    AttributeDef::new(0x0013, DataType::Uint(2), Access::RO);
/// `NumberOfWeekDaySchedulesSupportedPerUser`.
pub const NUMBER_OF_WEEK_DAY_SCHEDULES_SUPPORTED_PER_USER: AttributeDef =
    AttributeDef::new(0x0014, DataType::Uint(1), Access::RO);
/// `NumberOfYearDaySchedulesSupportedPerUser`.
pub const NUMBER_OF_YEAR_DAY_SCHEDULES_SUPPORTED_PER_USER: AttributeDef =
    AttributeDef::new(0x0015, DataType::Uint(1), Access::RO);
/// `NumberOfHolidaySchedulesSupported`.
pub const NUMBER_OF_HOLIDAY_SCHEDULES_SUPPORTED: AttributeDef =
    AttributeDef::new(0x0016, DataType::Uint(1), Access::RO);
/// `MaxPINCodeLength` (default 8).
pub const MAX_PIN_CODE_LENGTH: AttributeDef =
    AttributeDef::new(0x0017, DataType::Uint(1), Access::RO);
/// `MinPINCodeLength` (default 4).
pub const MIN_PIN_CODE_LENGTH: AttributeDef =
    AttributeDef::new(0x0018, DataType::Uint(1), Access::RO);
/// `MaxRFIDCodeLength`.
pub const MAX_RFID_CODE_LENGTH: AttributeDef =
    AttributeDef::new(0x0019, DataType::Uint(1), Access::RO);
/// `MinRFIDCodeLength`.
pub const MIN_RFID_CODE_LENGTH: AttributeDef =
    AttributeDef::new(0x001a, DataType::Uint(1), Access::RO);
/// `EnableLogging` (bool, writable).
pub const ENABLE_LOGGING: AttributeDef = AttributeDef::new(0x0020, DataType::Bool, Access::RW);
/// `Language` (string, writable).
pub const LANGUAGE: AttributeDef = AttributeDef::new(0x0021, DataType::CharString, Access::RW);
/// `LEDSettings` (uint8, writable).
pub const LED_SETTINGS: AttributeDef = AttributeDef::new(0x0022, DataType::Uint(1), Access::RW);
/// `AutoRelockTime` (uint32 seconds, writable, 0 = disabled).
pub const AUTO_RELOCK_TIME: AttributeDef = AttributeDef::new(0x0023, DataType::Uint(4), Access::RW);
/// `SoundVolume` (uint8, writable).
pub const SOUND_VOLUME: AttributeDef = AttributeDef::new(0x0024, DataType::Uint(1), Access::RW);
/// `OperatingMode` (enum8, writable).
pub const OPERATING_MODE: AttributeDef = AttributeDef::new(0x0025, DataType::Enum8, Access::RW);
/// `SupportedOperatingModes` (map16).
pub const SUPPORTED_OPERATING_MODES: AttributeDef =
    AttributeDef::new(0x0026, DataType::Bitmap(2), Access::RO);
/// `DefaultConfigurationRegister` (map16).
pub const DEFAULT_CONFIGURATION_REGISTER: AttributeDef =
    AttributeDef::new(0x0027, DataType::Bitmap(2), Access::RO);
/// `EnableLocalProgramming` (bool, writable).
pub const ENABLE_LOCAL_PROGRAMMING: AttributeDef =
    AttributeDef::new(0x0028, DataType::Bool, Access::RW);
/// `EnableOneTouchLocking` (bool, writable).
pub const ENABLE_ONE_TOUCH_LOCKING: AttributeDef =
    AttributeDef::new(0x0029, DataType::Bool, Access::RW);
/// `EnableInsideStatusLED` (bool, writable).
pub const ENABLE_INSIDE_STATUS_LED: AttributeDef =
    AttributeDef::new(0x002a, DataType::Bool, Access::RW);
/// `EnablePrivacyModeButton` (bool, writable).
pub const ENABLE_PRIVACY_MODE_BUTTON: AttributeDef =
    AttributeDef::new(0x002b, DataType::Bool, Access::RW);
/// `WrongCodeEntryLimit` (uint8, writable).
pub const WRONG_CODE_ENTRY_LIMIT: AttributeDef =
    AttributeDef::new(0x0030, DataType::Uint(1), Access::RW);
/// `UserCodeTemporaryDisableTime` (uint8 seconds, writable).
pub const USER_CODE_TEMPORARY_DISABLE_TIME: AttributeDef =
    AttributeDef::new(0x0031, DataType::Uint(1), Access::RW);
/// `SendPINOverTheAir` (bool, writable).
pub const SEND_PIN_OVER_THE_AIR: AttributeDef =
    AttributeDef::new(0x0032, DataType::Bool, Access::RW);
/// `RequirePINforRFOperation` (bool, writable).
pub const REQUIRE_PIN_FOR_RF_OPERATION: AttributeDef =
    AttributeDef::new(0x0033, DataType::Bool, Access::RW);
/// `SecurityLevel` (enum8).
pub const SECURITY_LEVEL: AttributeDef = AttributeDef::new(0x0034, DataType::Enum8, Access::RO);
/// `AlarmMask` (map16, writable).
pub const ALARM_MASK: AttributeDef = AttributeDef::new(0x0040, DataType::Bitmap(2), Access::RW);
/// `KeypadOperationEventMask` (map16, writable).
pub const KEYPAD_OPERATION_EVENT_MASK: AttributeDef =
    AttributeDef::new(0x0041, DataType::Bitmap(2), Access::RW);
/// `RFOperationEventMask` (map16, writable).
pub const RF_OPERATION_EVENT_MASK: AttributeDef =
    AttributeDef::new(0x0042, DataType::Bitmap(2), Access::RW);
/// `ManualOperationEventMask` (map16, writable).
pub const MANUAL_OPERATION_EVENT_MASK: AttributeDef =
    AttributeDef::new(0x0043, DataType::Bitmap(2), Access::RW);
/// `RFIDOperationEventMask` (map16, writable).
pub const RFID_OPERATION_EVENT_MASK: AttributeDef =
    AttributeDef::new(0x0044, DataType::Bitmap(2), Access::RW);
/// `KeypadProgrammingEventMask` (map16, writable).
pub const KEYPAD_PROGRAMMING_EVENT_MASK: AttributeDef =
    AttributeDef::new(0x0045, DataType::Bitmap(2), Access::RW);
/// `RFProgrammingEventMask` (map16, writable).
pub const RF_PROGRAMMING_EVENT_MASK: AttributeDef =
    AttributeDef::new(0x0046, DataType::Bitmap(2), Access::RW);
/// `RFIDProgrammingEventMask` (map16, writable).
pub const RFID_PROGRAMMING_EVENT_MASK: AttributeDef =
    AttributeDef::new(0x0047, DataType::Bitmap(2), Access::RW);

/// `LockState` values (Table 7-9).
pub mod lock_state {
    /// Not fully locked.
    pub const NOT_FULLY_LOCKED: u8 = 0x00;
    /// Locked.
    pub const LOCKED: u8 = 0x01;
    /// Unlocked.
    pub const UNLOCKED: u8 = 0x02;
    /// Undefined.
    pub const UNDEFINED: u8 = 0xff;
}

/// `LockType` values (Table 7-10).
pub mod lock_type {
    /// Dead bolt.
    pub const DEAD_BOLT: u8 = 0x00;
    /// Magnetic.
    pub const MAGNETIC: u8 = 0x01;
    /// Other.
    pub const OTHER: u8 = 0x02;
    /// Mortise.
    pub const MORTISE: u8 = 0x03;
    /// Rim.
    pub const RIM: u8 = 0x04;
    /// Latch bolt.
    pub const LATCH_BOLT: u8 = 0x05;
    /// Cylindrical lock.
    pub const CYLINDRICAL: u8 = 0x06;
    /// Tubular lock.
    pub const TUBULAR: u8 = 0x07;
    /// Interconnected lock.
    pub const INTERCONNECTED: u8 = 0x08;
    /// Dead latch.
    pub const DEAD_LATCH: u8 = 0x09;
    /// Door furniture.
    pub const DOOR_FURNITURE: u8 = 0x0a;
}

/// `DoorState` values (Table 7-12).
pub mod door_state {
    /// Open.
    pub const OPEN: u8 = 0x00;
    /// Closed.
    pub const CLOSED: u8 = 0x01;
    /// Jammed.
    pub const ERROR_JAMMED: u8 = 0x02;
    /// Forced open.
    pub const ERROR_FORCED_OPEN: u8 = 0x03;
    /// Unspecified error.
    pub const ERROR_UNSPECIFIED: u8 = 0x04;
    /// Undefined.
    pub const UNDEFINED: u8 = 0xff;
}

/// `OperatingMode` values (Table 7-15).
pub mod operating_mode {
    /// Normal: every interface enabled.
    pub const NORMAL: u8 = 0x00;
    /// Vacation: RF only.
    pub const VACATION: u8 = 0x01;
    /// Privacy: no external interaction.
    pub const PRIVACY: u8 = 0x02;
    /// No RF lock / unlock.
    pub const NO_RF_LOCK_UNLOCK: u8 = 0x03;
    /// Passage: open at will.
    pub const PASSAGE: u8 = 0x04;

    /// Whether RF lock operations are accepted in `mode` (§7.3.2.12.3):
    /// Privacy and No RF Lock/Unlock refuse them with FAILURE.
    pub const fn rf_enabled(mode: u8) -> bool {
        !matches!(mode, PRIVACY | NO_RF_LOCK_UNLOCK)
    }
}

/// `AlarmMask` bits / alarm codes (Table 7-22).
pub mod alarm {
    /// Deadbolt jammed.
    pub const DEADBOLT_JAMMED: u8 = 0;
    /// Lock reset to factory defaults.
    pub const RESET_TO_FACTORY_DEFAULTS: u8 = 1;
    /// RF module power cycled.
    pub const RF_MODULE_POWER_CYCLED: u8 = 3;
    /// Tamper: wrong code entry limit.
    pub const TAMPER_WRONG_CODE_ENTRY_LIMIT: u8 = 4;
    /// Tamper: front escutcheon removed.
    pub const TAMPER_FRONT_ESCUTCHEON_REMOVED: u8 = 5;
    /// Forced door open under door locked condition.
    pub const FORCED_DOOR_OPEN: u8 = 6;
}

/// User status values (Table 7-24).
pub mod user_status {
    /// Available.
    pub const AVAILABLE: u8 = 0x00;
    /// Occupied / enabled.
    pub const OCCUPIED_ENABLED: u8 = 0x01;
    /// Occupied / disabled.
    pub const OCCUPIED_DISABLED: u8 = 0x03;
    /// Not supported.
    pub const NOT_SUPPORTED: u8 = 0xff;
}

/// User type values (Table 7-25).
pub mod user_type {
    /// Unrestricted (default).
    pub const UNRESTRICTED: u8 = 0x00;
    /// Year-day schedule user.
    pub const YEAR_DAY_SCHEDULE: u8 = 0x01;
    /// Week-day schedule user.
    pub const WEEK_DAY_SCHEDULE: u8 = 0x02;
    /// Master user.
    pub const MASTER: u8 = 0x03;
    /// Non-access user.
    pub const NON_ACCESS: u8 = 0x04;
    /// Not supported.
    pub const NOT_SUPPORTED: u8 = 0xff;
}

/// Event sources (Tables 7-28 / 7-34).
pub mod source {
    /// Keypad.
    pub const KEYPAD: u8 = 0x00;
    /// RF.
    pub const RF: u8 = 0x01;
    /// Manual (operation events only).
    pub const MANUAL: u8 = 0x02;
    /// RFID.
    pub const RFID: u8 = 0x03;
    /// Indeterminate.
    pub const INDETERMINATE: u8 = 0xff;
}

/// Operation event codes (Table 7-29).
pub mod operation_event {
    /// Unknown or manufacturer specific.
    pub const UNKNOWN: u8 = 0x00;
    /// Lock.
    pub const LOCK: u8 = 0x01;
    /// Unlock.
    pub const UNLOCK: u8 = 0x02;
    /// Lock failure: invalid PIN or ID.
    pub const LOCK_FAILURE_INVALID_PIN: u8 = 0x03;
    /// Lock failure: invalid schedule.
    pub const LOCK_FAILURE_INVALID_SCHEDULE: u8 = 0x04;
    /// Unlock failure: invalid PIN or ID.
    pub const UNLOCK_FAILURE_INVALID_PIN: u8 = 0x05;
    /// Unlock failure: invalid schedule.
    pub const UNLOCK_FAILURE_INVALID_SCHEDULE: u8 = 0x06;
    /// One-touch lock.
    pub const ONE_TOUCH_LOCK: u8 = 0x07;
    /// Key lock.
    pub const KEY_LOCK: u8 = 0x08;
    /// Key unlock.
    pub const KEY_UNLOCK: u8 = 0x09;
    /// Auto lock.
    pub const AUTO_LOCK: u8 = 0x0a;
    /// Schedule lock.
    pub const SCHEDULE_LOCK: u8 = 0x0b;
    /// Schedule unlock.
    pub const SCHEDULE_UNLOCK: u8 = 0x0c;
    /// Manual lock (key or thumb turn).
    pub const MANUAL_LOCK: u8 = 0x0d;
    /// Manual unlock (key or thumb turn).
    pub const MANUAL_UNLOCK: u8 = 0x0e;
    /// Non-access user operational event.
    pub const NON_ACCESS_USER: u8 = 0x0f;
}

/// Programming event codes (Table 7-35).
pub mod programming_event {
    /// Unknown or manufacturer specific.
    pub const UNKNOWN: u8 = 0x00;
    /// Master code changed.
    pub const MASTER_CODE_CHANGED: u8 = 0x01;
    /// PIN code added.
    pub const PIN_ADDED: u8 = 0x02;
    /// PIN code deleted.
    pub const PIN_DELETED: u8 = 0x03;
    /// PIN code changed.
    pub const PIN_CHANGED: u8 = 0x04;
    /// RFID code added.
    pub const RFID_ADDED: u8 = 0x05;
    /// RFID code deleted.
    pub const RFID_DELETED: u8 = 0x06;
}

/// Lock Door.
pub const CMD_LOCK_DOOR: CommandId = CommandId(0x00);
/// Unlock Door.
pub const CMD_UNLOCK_DOOR: CommandId = CommandId(0x01);
/// Toggle.
pub const CMD_TOGGLE: CommandId = CommandId(0x02);
/// Unlock with Timeout.
pub const CMD_UNLOCK_WITH_TIMEOUT: CommandId = CommandId(0x03);
/// Get Log Record.
pub const CMD_GET_LOG_RECORD: CommandId = CommandId(0x04);
/// Set PIN Code.
pub const CMD_SET_PIN_CODE: CommandId = CommandId(0x05);
/// Get PIN Code.
pub const CMD_GET_PIN_CODE: CommandId = CommandId(0x06);
/// Clear PIN Code.
pub const CMD_CLEAR_PIN_CODE: CommandId = CommandId(0x07);
/// Clear All PIN Codes.
pub const CMD_CLEAR_ALL_PIN_CODES: CommandId = CommandId(0x08);
/// Set User Status.
pub const CMD_SET_USER_STATUS: CommandId = CommandId(0x09);
/// Get User Status.
pub const CMD_GET_USER_STATUS: CommandId = CommandId(0x0a);
/// Set User Type.
pub const CMD_SET_USER_TYPE: CommandId = CommandId(0x14);
/// Get User Type.
pub const CMD_GET_USER_TYPE: CommandId = CommandId(0x15);

/// Lock Door Response.
pub const CMD_LOCK_DOOR_RESPONSE: CommandId = CommandId(0x00);
/// Unlock Door Response.
pub const CMD_UNLOCK_DOOR_RESPONSE: CommandId = CommandId(0x01);
/// Toggle Response.
pub const CMD_TOGGLE_RESPONSE: CommandId = CommandId(0x02);
/// Unlock with Timeout Response.
pub const CMD_UNLOCK_WITH_TIMEOUT_RESPONSE: CommandId = CommandId(0x03);
/// Set PIN Code Response.
pub const CMD_SET_PIN_CODE_RESPONSE: CommandId = CommandId(0x05);
/// Get PIN Code Response.
pub const CMD_GET_PIN_CODE_RESPONSE: CommandId = CommandId(0x06);
/// Clear PIN Code Response.
pub const CMD_CLEAR_PIN_CODE_RESPONSE: CommandId = CommandId(0x07);
/// Clear All PIN Codes Response.
pub const CMD_CLEAR_ALL_PIN_CODES_RESPONSE: CommandId = CommandId(0x08);
/// Set User Status Response.
pub const CMD_SET_USER_STATUS_RESPONSE: CommandId = CommandId(0x09);
/// Get User Status Response.
pub const CMD_GET_USER_STATUS_RESPONSE: CommandId = CommandId(0x0a);
/// Set User Type Response.
pub const CMD_SET_USER_TYPE_RESPONSE: CommandId = CommandId(0x14);
/// Get User Type Response.
pub const CMD_GET_USER_TYPE_RESPONSE: CommandId = CommandId(0x15);
/// Operation Event Notification.
pub const CMD_OPERATION_EVENT_NOTIFICATION: CommandId = CommandId(0x20);
/// Programming Event Notification.
pub const CMD_PROGRAMMING_EVENT_NOTIFICATION: CommandId = CommandId(0x21);

/// Set PIN Code Response statuses (§7.3.2.16.6).
pub mod set_pin_status {
    /// Success.
    pub const SUCCESS: u8 = 0;
    /// General failure.
    pub const GENERAL_FAILURE: u8 = 1;
    /// Memory full.
    pub const MEMORY_FULL: u8 = 2;
    /// Duplicate code.
    pub const DUPLICATE_CODE: u8 = 3;
}

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[
        CMD_LOCK_DOOR,
        CMD_UNLOCK_DOOR,
        CMD_TOGGLE,
        CMD_UNLOCK_WITH_TIMEOUT,
        CMD_SET_PIN_CODE,
        CMD_GET_PIN_CODE,
        CMD_CLEAR_PIN_CODE,
        CMD_CLEAR_ALL_PIN_CODES,
        CMD_SET_USER_STATUS,
        CMD_GET_USER_STATUS,
        CMD_SET_USER_TYPE,
        CMD_GET_USER_TYPE,
    ],
    generated: &[
        CMD_LOCK_DOOR_RESPONSE,
        CMD_UNLOCK_DOOR_RESPONSE,
        CMD_TOGGLE_RESPONSE,
        CMD_UNLOCK_WITH_TIMEOUT_RESPONSE,
        CMD_SET_PIN_CODE_RESPONSE,
        CMD_GET_PIN_CODE_RESPONSE,
        CMD_CLEAR_PIN_CODE_RESPONSE,
        CMD_CLEAR_ALL_PIN_CODES_RESPONSE,
        CMD_SET_USER_STATUS_RESPONSE,
        CMD_GET_USER_STATUS_RESPONSE,
        CMD_SET_USER_TYPE_RESPONSE,
        CMD_GET_USER_TYPE_RESPONSE,
        CMD_OPERATION_EVENT_NOTIFICATION,
        CMD_PROGRAMMING_EVENT_NOTIFICATION,
    ],
};

/// Default reporting of `LockState` and `DoorState`: on change.
pub const STATE_REPORTING: DefaultReporting = DefaultReporting {
    min: 0,
    max: 3600,
    change: 0,
};

/// PIN users a server keeps.
pub const MAX_PIN_USERS: usize = 8;
/// Longest PIN code (also the `MaxPINCodeLength` default).
pub const MAX_PIN_LENGTH: usize = 8;
/// `MinPINCodeLength` default.
pub const DEFAULT_MIN_PIN_LENGTH: u8 = 4;
/// Local time when the lock has no clock (§7.3.2.16.27.5).
pub const NO_TIME: u32 = 0xffff_ffff;
/// User identifier when none applies.
pub const NO_USER: u16 = 0xffff;

/// A PIN code: ASCII digits or characters (§7.3.2.4), never printed.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Pin(Vec<u8, MAX_PIN_LENGTH>);

impl Pin {
    /// Wraps `code`, refusing more than [`MAX_PIN_LENGTH`] octets.
    pub fn new(code: &[u8]) -> Option<Pin> {
        Vec::from_slice(code).ok().map(Pin)
    }

    /// Length in octets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the code is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The code bytes (for the application's own use).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time comparison with `code`.
    pub fn matches(&self, code: &[u8]) -> bool {
        self.0.len() == code.len() && bool::from(self.0.as_slice().ct_eq(code))
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin(<{} octets redacted>)", self.0.len())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Pin {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Pin(<{} octets redacted>)", self.0.len());
    }
}

/// A PIN user slot.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct User {
    /// User status (Table 7-24).
    pub status: u8,
    /// User type (Table 7-25).
    pub kind: u8,
    /// The PIN code.
    pub pin: Pin,
}

impl User {
    const fn occupied(&self) -> bool {
        self.status != user_status::AVAILABLE
    }
}

/// Server state kept by the dispatcher.
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct State {
    /// PIN users, indexed by user identifier.
    pub users: Vec<User, MAX_PIN_USERS>,
    /// Consecutive wrong code entries.
    pub wrong_entries: u8,
    /// Codes are refused until this instant (wrong code lockout).
    pub lockout_until: Option<Instant>,
    /// An automatic relock is due at this instant.
    pub relock_at: Option<Instant>,
    /// A scene-recalled operation is due at this instant.
    pub pending: Option<(Action, Instant)>,
}

/// What the application does with its bolt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Action {
    /// Lock.
    Lock,
    /// Unlock.
    Unlock,
}

/// A frame the server sends: a response to the requester, or a
/// notification to the bound clients.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Frame {
    /// Command identifier (server to client).
    pub command: CommandId,
    /// Payload.
    pub payload: Vec<u8, 32>,
}

/// Result of a received command.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Outcome {
    /// Cluster-specific response to the requester; `None` means a
    /// Default Response with `status`.
    pub response: Option<Frame>,
    /// Status of the Default Response when there is no response frame.
    pub status: ZclStatus,
    /// Bolt operation for the application, with the user (or
    /// [`NO_USER`]).
    pub action: Option<(Action, u16)>,
    /// An event notification for the bound clients.
    pub notify: Option<Frame>,
    /// An alarm code to raise through the Alarms cluster (already
    /// checked against `AlarmMask`).
    pub alarm: Option<u8>,
}

impl Default for Outcome {
    fn default() -> Self {
        Outcome {
            response: None,
            status: ZclStatus::Success,
            action: None,
            notify: None,
            alarm: None,
        }
    }
}

impl Outcome {
    fn default_response(status: ZclStatus) -> Outcome {
        Outcome {
            status,
            ..Outcome::default()
        }
    }

    fn reply(command: CommandId, payload: &[u8]) -> Outcome {
        Outcome {
            response: Some(Frame {
                command,
                payload: Vec::from_slice(payload).unwrap_or_default(),
            }),
            status: ZclStatus::Success,
            ..Outcome::default()
        }
    }
}

/// Write guard: `OperatingMode` must be supported, the statuses and
/// lengths of the security set stay in range.
fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
    let val = v.as_u64().unwrap_or(u64::MAX);
    let ok = match id {
        i if i == OPERATING_MODE.id => {
            let supported = t.u64(SUPPORTED_OPERATING_MODES.id).unwrap_or(1);
            val <= u64::from(operating_mode::PASSAGE) && supported & (1 << val) != 0
        }
        i if i == LED_SETTINGS.id || i == SOUND_VOLUME.id => val <= 2,
        i if i == LANGUAGE.id => matches!(v, Value::String { bytes: Some(b), .. } if b.len() == 2),
        _ => true,
    };
    if ok {
        ZclStatus::Success
    } else {
        ZclStatus::InvalidValue
    }
}

fn bits16(v: u16) -> Value<'static> {
    Value::Bits {
        width: 2,
        bits: u64::from(v),
    }
}

/// Builds a server of `lock_type` with `pin_users` PIN user slots (at
/// most [`MAX_PIN_USERS`]); `actuator` is the `ActuatorEnabled` value.
/// Every event mask starts at zero (nothing is notified) and
/// `SupportedOperatingModes` lists Normal, Vacation, Privacy and No RF
/// Lock/Unlock.
pub fn server<const A: usize>(
    lock_type: u8,
    pin_users: u8,
    actuator: bool,
) -> Result<ClusterInstance<A>, ZclStatus> {
    if lock_type > lock_type::DOOR_FURNITURE || usize::from(pin_users) > MAX_PIN_USERS {
        return Err(ZclStatus::InvalidValue);
    }
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_reported_attribute(
        LOCK_STATE,
        &Value::Enum8(lock_state::UNDEFINED),
        STATE_REPORTING,
    )?;
    c.add_attribute(LOCK_TYPE, &Value::Enum8(lock_type))?;
    c.add_attribute(ACTUATOR_ENABLED, &Value::Bool(Some(actuator)))?;
    c.add_reported_attribute(
        DOOR_STATE,
        &Value::Enum8(door_state::UNDEFINED),
        STATE_REPORTING,
    )?;
    c.add_attribute(
        NUMBER_OF_PIN_USERS_SUPPORTED,
        &Value::Uint {
            width: 2,
            value: u64::from(pin_users),
        },
    )?;
    c.add_attribute(
        MAX_PIN_CODE_LENGTH,
        &Value::Uint {
            width: 1,
            value: u64::try_from(MAX_PIN_LENGTH).unwrap_or(u64::MAX),
        },
    )?;
    c.add_attribute(
        MIN_PIN_CODE_LENGTH,
        &Value::Uint {
            width: 1,
            value: u64::from(DEFAULT_MIN_PIN_LENGTH),
        },
    )?;
    c.add_attribute(AUTO_RELOCK_TIME, &Value::Uint { width: 4, value: 0 })?;
    c.add_attribute(OPERATING_MODE, &Value::Enum8(operating_mode::NORMAL))?;
    c.add_attribute(SUPPORTED_OPERATING_MODES, &bits16(0x000f))?;
    c.add_attribute(WRONG_CODE_ENTRY_LIMIT, &Value::Uint { width: 1, value: 0 })?;
    c.add_attribute(
        USER_CODE_TEMPORARY_DISABLE_TIME,
        &Value::Uint { width: 1, value: 0 },
    )?;
    c.add_attribute(SEND_PIN_OVER_THE_AIR, &Value::Bool(Some(false)))?;
    c.add_attribute(REQUIRE_PIN_FOR_RF_OPERATION, &Value::Bool(Some(false)))?;
    c.add_attribute(ALARM_MASK, &bits16(0))?;
    c.add_attribute(KEYPAD_OPERATION_EVENT_MASK, &bits16(0))?;
    c.add_attribute(RF_OPERATION_EVENT_MASK, &bits16(0))?;
    c.add_attribute(MANUAL_OPERATION_EVENT_MASK, &bits16(0))?;
    c.add_attribute(KEYPAD_PROGRAMMING_EVENT_MASK, &bits16(0))?;
    c.add_attribute(RF_PROGRAMMING_EVENT_MASK, &bits16(0))?;
    let mut users = Vec::new();
    for _ in 0..pin_users {
        let _ = users.push(User::default());
    }
    c.state = ClusterState::DoorLock(State {
        users,
        ..State::default()
    });
    c.write_guard = Some(guard::<A>);
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

fn state<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut State> {
    match &mut c.state {
        ClusterState::DoorLock(s) => Some(s),
        _ => None,
    }
}

fn state_ref<const A: usize>(c: &ClusterInstance<A>) -> Option<&State> {
    match &c.state {
        ClusterState::DoorLock(s) => Some(s),
        _ => None,
    }
}

/// The PIN user table of a server.
pub fn users<const A: usize>(c: &ClusterInstance<A>) -> &[User] {
    state_ref(c).map_or(&[], |s| s.users.as_slice())
}

fn mask<const A: usize>(c: &ClusterInstance<A>, id: AttributeId) -> u16 {
    c.u16(id).unwrap_or(0)
}

/// Whether alarm `code` is enabled by `AlarmMask` (Table 7-22).
pub fn alarm_enabled<const A: usize>(c: &ClusterInstance<A>, code: u8) -> bool {
    code < 16 && mask(c, ALARM_MASK.id) & (1 << code) != 0
}

/// Sets `LockState` (the application's report of the bolt); returns
/// whether it changed.
pub fn set_lock_state<const A: usize>(c: &mut ClusterInstance<A>, state: u8) -> bool {
    c.set(LOCK_STATE.id, &Value::Enum8(state))
}

/// Current `LockState`.
pub fn lock_state<const A: usize>(c: &ClusterInstance<A>) -> u8 {
    c.u8(LOCK_STATE.id).unwrap_or(lock_state::UNDEFINED)
}

/// Sets `DoorState`; returns whether it changed.
pub fn set_door_state<const A: usize>(c: &mut ClusterInstance<A>, state: u8) -> bool {
    c.set(DOOR_STATE.id, &Value::Enum8(state))
}

fn refresh_tick<const A: usize>(c: &mut ClusterInstance<A>) {
    let Some(s) = state_ref(c) else {
        return;
    };
    let mut next: Option<Instant> = None;
    for t in [s.relock_at, s.lockout_until, s.pending.map(|(_, t)| t)]
        .into_iter()
        .flatten()
    {
        next = Some(next.map_or(t, |n| if t.as_millis() < n.as_millis() { t } else { n }));
    }
    c.tick = next;
}

/// Writes a PIN octet string, masked with 0xff unless
/// `SendPINOverTheAir` is set (§7.3.2.13.3).
fn write_pin<const A: usize>(
    c: &ClusterInstance<A>,
    w: &mut Writer<'_>,
    pin: &[u8],
) -> Result<(), CodecError> {
    let n = u8::try_from(pin.len()).map_err(|_| CodecError::Unrepresentable { field: "pin" })?;
    w.u8(n)?;
    if c.bool(SEND_PIN_OVER_THE_AIR.id) {
        w.bytes(pin)
    } else {
        for _ in 0..n {
            w.u8(0xff)?;
        }
        Ok(())
    }
}

fn read_pin<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let n = r.u8()?;
    r.bytes(usize::from(n))
}

/// Encodes an Operation Event Notification (§7.3.2.16.27) when
/// `source` / `code` is enabled by the matching mask.
pub fn operation_event<const A: usize>(
    c: &ClusterInstance<A>,
    source: u8,
    code: u8,
    user: u16,
    pin: &[u8],
    local_time: u32,
) -> Option<Frame> {
    let (mask_id, bit) = match source {
        source::KEYPAD | source::RF | source::RFID => {
            let bit = match code {
                operation_event::NON_ACCESS_USER => 7,
                c if c <= operation_event::UNLOCK_FAILURE_INVALID_SCHEDULE => c,
                _ => return None,
            };
            let id = match source {
                source::KEYPAD => KEYPAD_OPERATION_EVENT_MASK.id,
                source::RF => RF_OPERATION_EVENT_MASK.id,
                _ => RFID_OPERATION_EVENT_MASK.id,
            };
            (id, bit)
        }
        source::MANUAL => {
            let bit = match code {
                operation_event::UNKNOWN | operation_event::LOCK | operation_event::UNLOCK => code,
                c if (operation_event::ONE_TOUCH_LOCK..=operation_event::MANUAL_UNLOCK)
                    .contains(&c) =>
                {
                    c - operation_event::ONE_TOUCH_LOCK + 3
                }
                _ => return None,
            };
            (MANUAL_OPERATION_EVENT_MASK.id, bit)
        }
        _ => return None,
    };
    if mask(c, mask_id) & (1 << bit) == 0 {
        return None;
    }
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    w.u8(source).ok()?;
    w.u8(code).ok()?;
    w.u16_le(user).ok()?;
    write_pin(c, &mut w, pin).ok()?;
    w.u32_le(local_time).ok()?;
    w.u8(0).ok()?;
    let n = w.position();
    Some(Frame {
        command: CMD_OPERATION_EVENT_NOTIFICATION,
        payload: Vec::from_slice(buf.get(..n)?).ok()?,
    })
}

/// Encodes a Programming Event Notification (§7.3.2.16.28) when
/// `source` / `code` is enabled by the matching mask.
pub fn programming_event<const A: usize>(
    c: &ClusterInstance<A>,
    source: u8,
    code: u8,
    user: &User,
    user_id: u16,
    local_time: u32,
) -> Option<Frame> {
    if code > programming_event::RFID_DELETED {
        return None;
    }
    let mask_id = match source {
        source::KEYPAD => KEYPAD_PROGRAMMING_EVENT_MASK.id,
        source::RF => RF_PROGRAMMING_EVENT_MASK.id,
        source::RFID => RFID_PROGRAMMING_EVENT_MASK.id,
        _ => return None,
    };
    if mask(c, mask_id) & (1 << code) == 0 {
        return None;
    }
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    w.u8(source).ok()?;
    w.u8(code).ok()?;
    w.u16_le(user_id).ok()?;
    write_pin(c, &mut w, user.pin.as_bytes()).ok()?;
    w.u8(user.kind).ok()?;
    w.u8(user.status).ok()?;
    w.u32_le(local_time).ok()?;
    w.u8(0).ok()?;
    let n = w.position();
    Some(Frame {
        command: CMD_PROGRAMMING_EVENT_NOTIFICATION,
        payload: Vec::from_slice(buf.get(..n)?).ok()?,
    })
}

/// Why an RF lock operation was refused.
enum Refusal {
    /// Operating mode, actuator or lockout: FAILURE without an event.
    Plain,
    /// Wrong or missing code: FAILURE with an invalid-PIN event.
    InvalidPin,
}

/// Validates the PIN of an RF operation (§7.3.2.13.4): returns the
/// user identifier (or [`NO_USER`] when no code was needed).
fn check_pin<const A: usize>(
    c: &mut ClusterInstance<A>,
    pin: &[u8],
    now: Instant,
) -> Result<u16, Refusal> {
    let required = c.bool(REQUIRE_PIN_FOR_RF_OPERATION.id);
    let limit = c.u8(WRONG_CODE_ENTRY_LIMIT.id).unwrap_or(0);
    let disable = c.u8(USER_CODE_TEMPORARY_DISABLE_TIME.id).unwrap_or(0);
    let Some(s) = state(c) else {
        return Err(Refusal::Plain);
    };
    if s.lockout_until.is_some_and(|t| !now.has_reached(t)) {
        return Err(Refusal::Plain);
    }
    s.lockout_until = None;
    if pin.is_empty() {
        return if required {
            Err(Refusal::InvalidPin)
        } else {
            Ok(NO_USER)
        };
    }
    let found = s
        .users
        .iter()
        .enumerate()
        .find(|(_, u)| u.occupied() && u.pin.matches(pin))
        .map(|(i, u)| (i, u.status, u.kind));
    match found {
        Some((i, user_status::OCCUPIED_ENABLED, kind)) if kind != user_type::NON_ACCESS => {
            s.wrong_entries = 0;
            Ok(u16::try_from(i).unwrap_or(NO_USER))
        }
        Some(_) => Err(Refusal::Plain),
        None => {
            s.wrong_entries = s.wrong_entries.saturating_add(1);
            if limit != 0 && s.wrong_entries >= limit {
                s.wrong_entries = 0;
                s.lockout_until = Some(now.saturating_add(Duration::from_secs(u64::from(disable))));
            }
            Err(Refusal::InvalidPin)
        }
    }
}

fn user_index<const A: usize>(c: &ClusterInstance<A>, id: u16) -> Option<usize> {
    let n = usize::from(c.u16(NUMBER_OF_PIN_USERS_SUPPORTED.id).unwrap_or(0));
    let i = usize::from(id);
    (i < n).then_some(i)
}

/// Handles a received command (§7.3.2.15); `local_time` stamps the
/// event notifications ([`NO_TIME`] without a clock).
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
    now: Instant,
    local_time: u32,
) -> Outcome {
    let mut r = Reader::new(payload);
    let out = match cmd {
        CMD_LOCK_DOOR | CMD_UNLOCK_DOOR | CMD_TOGGLE | CMD_UNLOCK_WITH_TIMEOUT => {
            let timeout = if cmd == CMD_UNLOCK_WITH_TIMEOUT {
                match r.u16_le() {
                    Ok(t) => Some(t),
                    Err(_) => return Outcome::default_response(ZclStatus::MalformedCommand),
                }
            } else {
                None
            };
            // The code is optional (HA 1.2): absent means empty.
            let pin = if r.is_empty() {
                &[][..]
            } else {
                match read_pin(&mut r) {
                    Ok(p) => p,
                    Err(_) => return Outcome::default_response(ZclStatus::MalformedCommand),
                }
            };
            let response = CommandId(cmd.0);
            let action = match cmd {
                CMD_LOCK_DOOR => Action::Lock,
                CMD_TOGGLE if lock_state(c) == lock_state::LOCKED => Action::Unlock,
                CMD_TOGGLE => Action::Lock,
                _ => Action::Unlock,
            };
            let mode = c.u8(OPERATING_MODE.id).unwrap_or(operating_mode::NORMAL);
            if !operating_mode::rf_enabled(mode) || !c.bool(ACTUATOR_ENABLED.id) {
                return Outcome::reply(response, &[ZclStatus::Failure.raw()]);
            }
            match check_pin(c, pin, now) {
                Ok(user) => {
                    let code = match action {
                        Action::Lock => operation_event::LOCK,
                        Action::Unlock => operation_event::UNLOCK,
                    };
                    let notify = operation_event(c, source::RF, code, user, pin, local_time);
                    let auto = c.u64(AUTO_RELOCK_TIME.id).unwrap_or(0);
                    if let Some(s) = state(c) {
                        s.pending = None;
                        s.relock_at = match (action, timeout) {
                            (Action::Unlock, Some(t)) => {
                                Some(now.saturating_add(Duration::from_secs(u64::from(t))))
                            }
                            (Action::Unlock, None) if auto != 0 => {
                                Some(now.saturating_add(Duration::from_secs(auto)))
                            }
                            _ => None,
                        };
                    }
                    let mut o = Outcome::reply(response, &[ZclStatus::Success.raw()]);
                    o.action = Some((action, user));
                    o.notify = notify;
                    o
                }
                Err(Refusal::InvalidPin) => {
                    let code = match action {
                        Action::Lock => operation_event::LOCK_FAILURE_INVALID_PIN,
                        Action::Unlock => operation_event::UNLOCK_FAILURE_INVALID_PIN,
                    };
                    let mut o = Outcome::reply(response, &[ZclStatus::Failure.raw()]);
                    o.notify = operation_event(c, source::RF, code, NO_USER, pin, local_time);
                    if state_ref(c).is_some_and(|s| s.lockout_until.is_some())
                        && alarm_enabled(c, alarm::TAMPER_WRONG_CODE_ENTRY_LIMIT)
                    {
                        o.alarm = Some(alarm::TAMPER_WRONG_CODE_ENTRY_LIMIT);
                    }
                    o
                }
                Err(Refusal::Plain) => Outcome::reply(response, &[ZclStatus::Failure.raw()]),
            }
        }
        CMD_SET_PIN_CODE => {
            let (Ok(id), Ok(status), Ok(kind), Ok(pin)) =
                (r.u16_le(), r.u8(), r.u8(), read_pin(&mut r))
            else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let min = usize::from(
                c.u8(MIN_PIN_CODE_LENGTH.id)
                    .unwrap_or(DEFAULT_MIN_PIN_LENGTH),
            );
            let max = usize::from(c.u8(MAX_PIN_CODE_LENGTH.id).unwrap_or(8)).min(MAX_PIN_LENGTH);
            let Some(i) = user_index(c, id) else {
                return Outcome::reply(
                    CMD_SET_PIN_CODE_RESPONSE,
                    &[set_pin_status::GENERAL_FAILURE],
                );
            };
            let valid_status = matches!(
                status,
                user_status::OCCUPIED_ENABLED | user_status::OCCUPIED_DISABLED
            );
            if !valid_status || kind > user_type::NON_ACCESS || !(min..=max).contains(&pin.len()) {
                return Outcome::reply(
                    CMD_SET_PIN_CODE_RESPONSE,
                    &[set_pin_status::GENERAL_FAILURE],
                );
            }
            let Some(s) = state(c) else {
                return Outcome::reply(
                    CMD_SET_PIN_CODE_RESPONSE,
                    &[set_pin_status::GENERAL_FAILURE],
                );
            };
            if s.users
                .iter()
                .enumerate()
                .any(|(j, u)| j != i && u.occupied() && u.pin.matches(pin))
            {
                return Outcome::reply(
                    CMD_SET_PIN_CODE_RESPONSE,
                    &[set_pin_status::DUPLICATE_CODE],
                );
            }
            let Some(code) = Pin::new(pin) else {
                return Outcome::reply(
                    CMD_SET_PIN_CODE_RESPONSE,
                    &[set_pin_status::GENERAL_FAILURE],
                );
            };
            let existed = s.users.get(i).is_some_and(User::occupied);
            let user = User {
                status,
                kind,
                pin: code,
            };
            if let Some(slot) = s.users.get_mut(i) {
                *slot = user.clone();
            }
            let event = if existed {
                programming_event::PIN_CHANGED
            } else {
                programming_event::PIN_ADDED
            };
            let mut o = Outcome::reply(CMD_SET_PIN_CODE_RESPONSE, &[set_pin_status::SUCCESS]);
            o.notify = programming_event(c, source::RF, event, &user, id, local_time);
            o
        }
        CMD_GET_PIN_CODE => {
            let Ok(id) = r.u16_le() else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let Some(i) = user_index(c, id) else {
                return Outcome::default_response(ZclStatus::InvalidField);
            };
            let user = users(c).get(i).cloned().unwrap_or_default();
            let mut buf = [0u8; 16];
            let mut w = Writer::new(&mut buf);
            let _ = w.u16_le(id);
            if user.occupied() {
                let _ = w.u8(user.status);
                let _ = w.u8(user.kind);
                let _ = write_pin(c, &mut w, user.pin.as_bytes());
            } else {
                let _ = w.u8(user_status::AVAILABLE);
                let _ = w.u8(user_type::NOT_SUPPORTED);
                let _ = w.u8(0);
            }
            let n = w.position();
            Outcome::reply(CMD_GET_PIN_CODE_RESPONSE, buf.get(..n).unwrap_or(&[]))
        }
        CMD_CLEAR_PIN_CODE => {
            let Ok(id) = r.u16_le() else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let Some(i) = user_index(c, id) else {
                return Outcome::reply(CMD_CLEAR_PIN_CODE_RESPONSE, &[1]);
            };
            let Some(s) = state(c) else {
                return Outcome::reply(CMD_CLEAR_PIN_CODE_RESPONSE, &[1]);
            };
            let removed = s.users.get_mut(i).map(core::mem::take).unwrap_or_default();
            let mut o = Outcome::reply(CMD_CLEAR_PIN_CODE_RESPONSE, &[0]);
            if removed.occupied() {
                o.notify = programming_event(
                    c,
                    source::RF,
                    programming_event::PIN_DELETED,
                    &removed,
                    id,
                    local_time,
                );
            }
            o
        }
        CMD_CLEAR_ALL_PIN_CODES => {
            if let Some(s) = state(c) {
                for u in s.users.iter_mut() {
                    *u = User::default();
                }
            }
            Outcome::reply(CMD_CLEAR_ALL_PIN_CODES_RESPONSE, &[0])
        }
        CMD_SET_USER_STATUS | CMD_SET_USER_TYPE => {
            let (Ok(id), Ok(v)) = (r.u16_le(), r.u8()) else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let response = if cmd == CMD_SET_USER_STATUS {
                CMD_SET_USER_STATUS_RESPONSE
            } else {
                CMD_SET_USER_TYPE_RESPONSE
            };
            let valid = if cmd == CMD_SET_USER_STATUS {
                matches!(
                    v,
                    user_status::OCCUPIED_ENABLED | user_status::OCCUPIED_DISABLED
                )
            } else {
                v <= user_type::NON_ACCESS
            };
            let Some(i) = user_index(c, id) else {
                return Outcome::reply(response, &[1]);
            };
            let Some(u) = state(c).and_then(|s| s.users.get_mut(i)) else {
                return Outcome::reply(response, &[1]);
            };
            if !valid || !u.occupied() {
                return Outcome::reply(response, &[1]);
            }
            if cmd == CMD_SET_USER_STATUS {
                u.status = v;
            } else {
                u.kind = v;
            }
            Outcome::reply(response, &[0])
        }
        CMD_GET_USER_STATUS | CMD_GET_USER_TYPE => {
            let Ok(id) = r.u16_le() else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let Some(i) = user_index(c, id) else {
                return Outcome::default_response(ZclStatus::InvalidField);
            };
            let user = users(c).get(i).cloned().unwrap_or_default();
            let (response, v) = if cmd == CMD_GET_USER_STATUS {
                (CMD_GET_USER_STATUS_RESPONSE, user.status)
            } else {
                (
                    CMD_GET_USER_TYPE_RESPONSE,
                    if user.occupied() {
                        user.kind
                    } else {
                        user_type::NOT_SUPPORTED
                    },
                )
            };
            let [lo, hi] = id.to_le_bytes();
            Outcome::reply(response, &[lo, hi, v])
        }
        _ => Outcome::default_response(ZclStatus::UnsupportedClusterCommand),
    };
    refresh_tick(c);
    out
}

/// Services the timers at `now` (the automatic relock, a
/// scene-recalled operation, the end of the wrong-code lockout): an
/// operation for the application, with the Manual-source Auto Lock
/// event frame when the relock fired and its mask bit is set.
pub fn tick<const A: usize>(
    c: &mut ClusterInstance<A>,
    now: Instant,
    local_time: u32,
) -> Option<(Action, Option<Frame>)> {
    let mut result = None;
    if let Some(s) = state(c) {
        if s.lockout_until.is_some_and(|t| now.has_reached(t)) {
            s.lockout_until = None;
        }
        if s.relock_at.is_some_and(|t| now.has_reached(t)) {
            s.relock_at = None;
            result = Some((Action::Lock, true));
        } else if let Some((action, at)) = s.pending
            && now.has_reached(at)
        {
            s.pending = None;
            result = Some((action, false));
        }
    }
    refresh_tick(c);
    result.map(|(t, auto)| {
        let frame = auto
            .then(|| {
                operation_event(
                    c,
                    source::MANUAL,
                    operation_event::AUTO_LOCK,
                    NO_USER,
                    &[],
                    local_time,
                )
            })
            .flatten();
        (t, frame)
    })
}

/// Scene extension field set (§7.3.2.17): LockState.
pub fn scene_fields<const A: usize>(c: &ClusterInstance<A>) -> [u8; 1] {
    [lock_state(c)]
}

/// Applies a recalled scene: Locked or Unlocked schedules the operation
/// `tenths` tenths of a second later (Not fully locked is ignored).
pub fn apply_scene_fields<const A: usize>(
    c: &mut ClusterInstance<A>,
    fields: &[u8],
    tenths: u16,
    now: Instant,
) {
    let action = match fields.first() {
        Some(&lock_state::LOCKED) => Action::Lock,
        Some(&lock_state::UNLOCKED) => Action::Unlock,
        _ => return,
    };
    if let Some(s) = state(c) {
        s.pending = Some((
            action,
            now.saturating_add(Duration::from_millis(u64::from(tenths) * 100)),
        ));
    }
    refresh_tick(c);
}

/// Client-side view of a Get PIN Code Response (§7.3.2.16.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PinCodeResponse<'a> {
    /// User identifier.
    pub user_id: u16,
    /// User status.
    pub status: u8,
    /// User type.
    pub kind: u8,
    /// The code (masked when the lock does not send PINs).
    pub code: &'a [u8],
}

impl<'a> PinCodeResponse<'a> {
    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(PinCodeResponse {
            user_id: r.u16_le()?,
            status: r.u8()?,
            kind: r.u8()?,
            code: read_pin(&mut r)?,
        })
    }
}

/// Client-side view of an Operation Event Notification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OperationEvent<'a> {
    /// Source (Table 7-28).
    pub source: u8,
    /// Code (Table 7-29).
    pub code: u8,
    /// User identifier.
    pub user_id: u16,
    /// PIN (masked when the lock does not send PINs).
    pub pin: &'a [u8],
    /// Local time ([`NO_TIME`] without a clock).
    pub local_time: u32,
}

impl<'a> OperationEvent<'a> {
    /// Parses the payload (the trailing data string is ignored).
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(OperationEvent {
            source: r.u8()?,
            code: r.u8()?,
            user_id: r.u16_le()?,
            pin: read_pin(&mut r)?,
            local_time: r.u32_le()?,
        })
    }
}

/// Client-side view of a Programming Event Notification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProgrammingEvent<'a> {
    /// Source (Table 7-34).
    pub source: u8,
    /// Code (Table 7-35).
    pub code: u8,
    /// User identifier.
    pub user_id: u16,
    /// PIN (masked when the lock does not send PINs).
    pub pin: &'a [u8],
    /// User type.
    pub kind: u8,
    /// User status.
    pub status: u8,
    /// Local time.
    pub local_time: u32,
}

impl<'a> ProgrammingEvent<'a> {
    /// Parses the payload (the trailing data string is ignored).
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(ProgrammingEvent {
            source: r.u8()?,
            code: r.u8()?,
            user_id: r.u16_le()?,
            pin: read_pin(&mut r)?,
            kind: r.u8()?,
            status: r.u8()?,
            local_time: r.u32_le()?,
        })
    }
}

/// Encodes a Lock / Unlock / Toggle payload with an optional code.
pub fn encode_operation(pin: &[u8], out: &mut [u8]) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    let n = u8::try_from(pin.len()).map_err(|_| CodecError::Unrepresentable { field: "pin" })?;
    w.u8(n)?;
    w.bytes(pin)?;
    Ok(w.position())
}

/// Encodes a Set PIN Code payload (§7.3.2.15.7).
pub fn encode_set_pin_code(
    user_id: u16,
    status: u8,
    kind: u8,
    pin: &[u8],
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    w.u16_le(user_id)?;
    w.u8(status)?;
    w.u8(kind)?;
    let n = u8::try_from(pin.len()).map_err(|_| CodecError::Unrepresentable { field: "pin" })?;
    w.u8(n)?;
    w.bytes(pin)?;
    Ok(w.position())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Instant = Instant::from_millis(1_000);

    fn lock() -> ClusterInstance<36> {
        server(lock_type::DEAD_BOLT, 4, true).unwrap()
    }

    fn set_pin(c: &mut ClusterInstance<36>, id: u16, status: u8, kind: u8, pin: &[u8]) -> u8 {
        let mut buf = [0u8; 16];
        let n = encode_set_pin_code(id, status, kind, pin, &mut buf).unwrap();
        let o = handle(c, CMD_SET_PIN_CODE, &buf[..n], T0, NO_TIME);
        let f = o.response.unwrap();
        assert_eq!(f.command, CMD_SET_PIN_CODE_RESPONSE);
        f.payload[0]
    }

    fn operate(c: &mut ClusterInstance<36>, cmd: CommandId, pin: &[u8], now: Instant) -> Outcome {
        let mut buf = [0u8; 16];
        let n = encode_operation(pin, &mut buf).unwrap();
        handle(c, cmd, &buf[..n], now, 1234)
    }

    #[test]
    fn pins_are_redacted_and_compared_in_constant_time() {
        let p = Pin::new(b"1234").unwrap();
        let s = debug_string(&p);
        assert!(!s.contains("1234"), "{s}");
        assert!(p.matches(b"1234"));
        assert!(!p.matches(b"12345"));
        assert!(!p.matches(b"1235"));
        assert!(Pin::new(b"123456789").is_none());
    }

    fn debug_string(p: &Pin) -> heapless::String<64> {
        let mut s = heapless::String::new();
        fmt::write(&mut s, format_args!("{p:?}")).unwrap();
        s
    }

    #[test]
    fn lock_operations_follow_mode_actuator_and_pin_rules() {
        let mut c = lock();
        // No PIN required: Lock is accepted and handed to the application.
        let o = operate(&mut c, CMD_LOCK_DOOR, &[], T0);
        assert_eq!(
            o.response,
            Some(Frame {
                command: CMD_LOCK_DOOR_RESPONSE,
                payload: Vec::from_slice(&[0]).unwrap()
            })
        );
        assert_eq!(o.action, Some((Action::Lock, NO_USER)));
        assert_eq!(o.notify, None, "RF event mask is zero");
        set_lock_state(&mut c, lock_state::LOCKED);
        // Toggle unlocks a locked door.
        let o = operate(&mut c, CMD_TOGGLE, &[], T0);
        assert_eq!(o.action, Some((Action::Unlock, NO_USER)));
        assert_eq!(o.response.unwrap().command, CMD_TOGGLE_RESPONSE);
        // No RF Lock/Unlock mode: FAILURE, no action.
        c.set(
            OPERATING_MODE.id,
            &Value::Enum8(operating_mode::NO_RF_LOCK_UNLOCK),
        );
        let o = operate(&mut c, CMD_UNLOCK_DOOR, &[], T0);
        assert_eq!(o.response.unwrap().payload.as_slice(), &[1]);
        assert_eq!(o.action, None);
        c.set(OPERATING_MODE.id, &Value::Enum8(operating_mode::NORMAL));
        c.set_bool(ACTUATOR_ENABLED.id, false);
        assert_eq!(operate(&mut c, CMD_UNLOCK_DOOR, &[], T0).action, None);
        c.set_bool(ACTUATOR_ENABLED.id, true);

        // A PIN is required: refused without one, with an RF event.
        c.set_bool(REQUIRE_PIN_FOR_RF_OPERATION.id, true);
        c.set(RF_OPERATION_EVENT_MASK.id, &bits16(0xffff));
        let o = operate(&mut c, CMD_UNLOCK_DOOR, &[], T0);
        assert_eq!(o.response.unwrap().payload.as_slice(), &[1]);
        let f = o.notify.unwrap();
        let ev = OperationEvent::parse(&f.payload).unwrap();
        assert_eq!(
            (ev.source, ev.code, ev.user_id, ev.local_time),
            (
                source::RF,
                operation_event::UNLOCK_FAILURE_INVALID_PIN,
                NO_USER,
                1234
            )
        );
        assert_eq!(
            set_pin(
                &mut c,
                1,
                user_status::OCCUPIED_ENABLED,
                user_type::UNRESTRICTED,
                b"2468"
            ),
            set_pin_status::SUCCESS
        );
        let o = operate(&mut c, CMD_UNLOCK_DOOR, b"2468", T0);
        assert_eq!(o.action, Some((Action::Unlock, 1)));
        let f = o.notify.unwrap();
        let ev = OperationEvent::parse(&f.payload).unwrap();
        assert_eq!((ev.code, ev.user_id), (operation_event::UNLOCK, 1));
        assert_eq!(ev.pin, &[0xff; 4], "PINs are masked over the air");
        c.set_bool(SEND_PIN_OVER_THE_AIR.id, true);
        let o = operate(&mut c, CMD_LOCK_DOOR, b"2468", T0);
        let f = o.notify.unwrap();
        assert_eq!(OperationEvent::parse(&f.payload).unwrap().pin, b"2468");
        // A disabled user cannot operate; a non-access user neither.
        handle(&mut c, CMD_SET_USER_STATUS, &[1, 0, 3], T0, NO_TIME);
        let o = operate(&mut c, CMD_LOCK_DOOR, b"2468", T0);
        assert_eq!(o.action, None);
        assert_eq!(o.notify, None);
    }

    #[test]
    fn wrong_codes_lock_the_lock_out_and_raise_the_tamper_alarm() {
        let mut c = lock();
        c.set_bool(REQUIRE_PIN_FOR_RF_OPERATION.id, true);
        c.set_u8(WRONG_CODE_ENTRY_LIMIT.id, 2);
        c.set_u8(USER_CODE_TEMPORARY_DISABLE_TIME.id, 10);
        c.set(
            ALARM_MASK.id,
            &bits16(1 << alarm::TAMPER_WRONG_CODE_ENTRY_LIMIT),
        );
        set_pin(
            &mut c,
            0,
            user_status::OCCUPIED_ENABLED,
            user_type::UNRESTRICTED,
            b"1111",
        );
        assert_eq!(operate(&mut c, CMD_LOCK_DOOR, b"0000", T0).alarm, None);
        let o = operate(&mut c, CMD_LOCK_DOOR, b"0000", T0);
        assert_eq!(o.alarm, Some(alarm::TAMPER_WRONG_CODE_ENTRY_LIMIT));
        // Locked out: even the right code fails until the timer expires.
        let t1 = T0.saturating_add(Duration::from_secs(5));
        assert_eq!(operate(&mut c, CMD_LOCK_DOOR, b"1111", t1).action, None);
        assert_eq!(c.tick, Some(T0.saturating_add(Duration::from_secs(10))));
        let t2 = T0.saturating_add(Duration::from_secs(10));
        assert_eq!(tick(&mut c, t2, NO_TIME), None);
        assert_eq!(c.tick, None);
        assert_eq!(
            operate(&mut c, CMD_LOCK_DOOR, b"1111", t2).action,
            Some((Action::Lock, 0))
        );
    }

    #[test]
    fn unlock_with_timeout_and_auto_relock_lock_again() {
        let mut c = lock();
        c.set(MANUAL_OPERATION_EVENT_MASK.id, &bits16(0xffff));
        let mut buf = [0u8; 8];
        buf[..2].copy_from_slice(&30u16.to_le_bytes());
        let o = handle(&mut c, CMD_UNLOCK_WITH_TIMEOUT, &buf[..2], T0, NO_TIME);
        assert_eq!(o.action, Some((Action::Unlock, NO_USER)));
        assert_eq!(
            o.response.unwrap().command,
            CMD_UNLOCK_WITH_TIMEOUT_RESPONSE
        );
        let due = T0.saturating_add(Duration::from_secs(30));
        assert_eq!(c.tick, Some(due));
        assert_eq!(
            tick(&mut c, T0.saturating_add(Duration::from_secs(29)), NO_TIME),
            None
        );
        let (t, frame) = tick(&mut c, due, 77).unwrap();
        assert_eq!(t, Action::Lock);
        let f = frame.unwrap();
        let ev = OperationEvent::parse(&f.payload).unwrap();
        assert_eq!(
            (ev.source, ev.code, ev.local_time),
            (source::MANUAL, operation_event::AUTO_LOCK, 77)
        );
        assert_eq!(c.tick, None);

        c.set(AUTO_RELOCK_TIME.id, &Value::Uint { width: 4, value: 5 });
        operate(&mut c, CMD_UNLOCK_DOOR, &[], T0);
        assert_eq!(c.tick, Some(T0.saturating_add(Duration::from_secs(5))));
        operate(&mut c, CMD_LOCK_DOOR, &[], T0);
        assert_eq!(c.tick, None, "a lock cancels the relock");
    }

    #[test]
    fn pin_user_table_commands() {
        let mut c = lock();
        c.set(RF_PROGRAMMING_EVENT_MASK.id, &bits16(0xffff));
        c.set_bool(SEND_PIN_OVER_THE_AIR.id, true);
        // Out of range user, bad status, short PIN.
        assert_eq!(
            set_pin(&mut c, 4, user_status::OCCUPIED_ENABLED, 0, b"1234"),
            set_pin_status::GENERAL_FAILURE
        );
        assert_eq!(
            set_pin(&mut c, 0, user_status::AVAILABLE, 0, b"1234"),
            set_pin_status::GENERAL_FAILURE
        );
        assert_eq!(
            set_pin(&mut c, 0, user_status::OCCUPIED_ENABLED, 0, b"123"),
            set_pin_status::GENERAL_FAILURE
        );
        let mut buf = [0u8; 16];
        let n = encode_set_pin_code(
            0,
            user_status::OCCUPIED_ENABLED,
            user_type::MASTER,
            b"1234",
            &mut buf,
        )
        .unwrap();
        let o = handle(&mut c, CMD_SET_PIN_CODE, &buf[..n], T0, 5);
        assert_eq!(o.response.unwrap().payload.as_slice(), &[0]);
        let f = o.notify.unwrap();
        let ev = ProgrammingEvent::parse(&f.payload).unwrap();
        assert_eq!(
            (ev.source, ev.code, ev.user_id, ev.pin, ev.kind, ev.status),
            (
                source::RF,
                programming_event::PIN_ADDED,
                0,
                &b"1234"[..],
                user_type::MASTER,
                user_status::OCCUPIED_ENABLED
            )
        );
        // Duplicate in another slot, change in the same slot.
        assert_eq!(
            set_pin(&mut c, 1, user_status::OCCUPIED_ENABLED, 0, b"1234"),
            set_pin_status::DUPLICATE_CODE
        );
        let n = encode_set_pin_code(
            0,
            user_status::OCCUPIED_ENABLED,
            user_type::MASTER,
            b"4321",
            &mut buf,
        )
        .unwrap();
        let o = handle(&mut c, CMD_SET_PIN_CODE, &buf[..n], T0, 5);
        let f = o.notify.unwrap();
        let ev = ProgrammingEvent::parse(&f.payload).unwrap();
        assert_eq!(ev.code, programming_event::PIN_CHANGED);
        // Get PIN Code: existing and empty slots, invalid id.
        let o = handle(&mut c, CMD_GET_PIN_CODE, &[0, 0], T0, NO_TIME);
        let f = o.response.unwrap();
        let r = PinCodeResponse::parse(&f.payload).unwrap();
        assert_eq!(
            (r.user_id, r.status, r.kind, r.code),
            (
                0,
                user_status::OCCUPIED_ENABLED,
                user_type::MASTER,
                &b"4321"[..]
            )
        );
        let o = handle(&mut c, CMD_GET_PIN_CODE, &[2, 0], T0, NO_TIME);
        let f = o.response.unwrap();
        let r = PinCodeResponse::parse(&f.payload).unwrap();
        assert_eq!(
            (r.user_id, r.status, r.kind, r.code),
            (2, user_status::AVAILABLE, user_type::NOT_SUPPORTED, &[][..])
        );
        let o = handle(&mut c, CMD_GET_PIN_CODE, &[9, 0], T0, NO_TIME);
        assert_eq!(o.response, None);
        assert_eq!(o.status, ZclStatus::InvalidField);
        // User status / type.
        let o = handle(
            &mut c,
            CMD_SET_USER_TYPE,
            &[0, 0, user_type::NON_ACCESS],
            T0,
            NO_TIME,
        );
        assert_eq!(o.response.unwrap().payload.as_slice(), &[0]);
        let o = handle(&mut c, CMD_GET_USER_TYPE, &[0, 0], T0, NO_TIME);
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[0, 0, user_type::NON_ACCESS]
        );
        let o = handle(&mut c, CMD_SET_USER_STATUS, &[0, 0, 0], T0, NO_TIME);
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[1],
            "0 not allowed"
        );
        let o = handle(&mut c, CMD_GET_USER_STATUS, &[0, 0], T0, NO_TIME);
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[0, 0, user_status::OCCUPIED_ENABLED]
        );
        // Clear: the slot becomes available with a deletion event.
        let o = handle(&mut c, CMD_CLEAR_PIN_CODE, &[0, 0], T0, NO_TIME);
        assert_eq!(o.response.unwrap().payload.as_slice(), &[0]);
        let f = o.notify.unwrap();
        let ev = ProgrammingEvent::parse(&f.payload).unwrap();
        assert_eq!(
            (ev.code, ev.pin),
            (programming_event::PIN_DELETED, &b"4321"[..])
        );
        assert!(!users(&c)[0].occupied());
        assert_eq!(
            handle(&mut c, CMD_CLEAR_PIN_CODE, &[0, 0], T0, NO_TIME).notify,
            None
        );
        set_pin(&mut c, 3, user_status::OCCUPIED_ENABLED, 0, b"9999");
        handle(&mut c, CMD_CLEAR_ALL_PIN_CODES, &[], T0, NO_TIME);
        assert!(users(&c).iter().all(|u| !u.occupied()));
        // Unsupported commands are refused as such.
        assert_eq!(
            handle(&mut c, CMD_GET_LOG_RECORD, &[0, 0], T0, NO_TIME).status,
            ZclStatus::UnsupportedClusterCommand
        );
    }

    #[test]
    fn scenes_delay_the_operation_and_mode_writes_are_guarded() {
        let mut c = lock();
        set_lock_state(&mut c, lock_state::LOCKED);
        assert_eq!(scene_fields(&c), [lock_state::LOCKED]);
        apply_scene_fields(&mut c, &[lock_state::UNLOCKED], 20, T0);
        let due = T0.saturating_add(Duration::from_secs(2));
        assert_eq!(c.tick, Some(due));
        assert_eq!(tick(&mut c, due, NO_TIME), Some((Action::Unlock, None)));
        apply_scene_fields(&mut c, &[lock_state::NOT_FULLY_LOCKED], 0, T0);
        assert_eq!(c.tick, None);

        assert_eq!(
            guard(
                &c.attributes,
                OPERATING_MODE.id,
                &Value::Enum8(operating_mode::PASSAGE)
            ),
            ZclStatus::InvalidValue,
            "Passage is not in SupportedOperatingModes"
        );
        assert_eq!(
            guard(
                &c.attributes,
                OPERATING_MODE.id,
                &Value::Enum8(operating_mode::VACATION)
            ),
            ZclStatus::Success
        );
    }
}
