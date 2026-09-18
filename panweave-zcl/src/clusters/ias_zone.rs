//! IAS Zone cluster (ZCL8 §8.2): the zone information and settings
//! attributes, the enrolment procedures (Trip-to-Pair, Auto-Enroll-
//! Response, Auto-Enroll-Request, §8.2.2.1.3), Zone Status Change
//! Notifications with the delay field, Zone Enroll Request / Response,
//! and the test mode commands. The server sends its commands to the
//! IAS CIE named by `IAS_CIE_Address` and accepts commands only from
//! the node that wrote that attribute (§8.2.2.1.3).

use panweave_codec::{Reader, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, CommandId, Endpoint, ExtendedAddress, ShortAddress};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0500);
/// `ZoneState` (enum8).
pub const ZONE_STATE: AttributeDef = AttributeDef::new(0x0000, DataType::Enum8, Access::RO);
/// `ZoneType` (enum16).
pub const ZONE_TYPE: AttributeDef = AttributeDef::new(0x0001, DataType::Enum16, Access::RO);
/// `ZoneStatus` (map16).
pub const ZONE_STATUS: AttributeDef = AttributeDef::new(0x0002, DataType::Bitmap(2), Access::RO);
/// `IAS_CIE_Address` (EUI-64, writable).
pub const IAS_CIE_ADDRESS: AttributeDef = AttributeDef::new(0x0010, DataType::Eui64, Access::RW);
/// `ZoneID` (uint8).
pub const ZONE_ID: AttributeDef = AttributeDef::new(0x0011, DataType::Uint(1), Access::RO);
/// `NumberOfZoneSensitivityLevelsSupported` (uint8).
pub const NUMBER_OF_ZONE_SENSITIVITY_LEVELS_SUPPORTED: AttributeDef =
    AttributeDef::new(0x0012, DataType::Uint(1), Access::RO);
/// `CurrentZoneSensitivityLevel` (uint8, writable).
pub const CURRENT_ZONE_SENSITIVITY_LEVEL: AttributeDef =
    AttributeDef::new(0x0013, DataType::Uint(1), Access::RW);

/// `ZoneID` before enrolment.
pub const ZONE_ID_NONE: u8 = 0xff;

/// Client → server: Zone Enroll Response.
pub const CMD_ZONE_ENROLL_RESPONSE: CommandId = CommandId(0x00);
/// Client → server: Initiate Normal Operation Mode.
pub const CMD_INITIATE_NORMAL_OPERATION_MODE: CommandId = CommandId(0x01);
/// Client → server: Initiate Test Mode.
pub const CMD_INITIATE_TEST_MODE: CommandId = CommandId(0x02);
/// Server → client: Zone Status Change Notification.
pub const CMD_ZONE_STATUS_CHANGE_NOTIFICATION: CommandId = CommandId(0x00);
/// Server → client: Zone Enroll Request.
pub const CMD_ZONE_ENROLL_REQUEST: CommandId = CommandId(0x01);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[
        CMD_ZONE_ENROLL_RESPONSE,
        CMD_INITIATE_NORMAL_OPERATION_MODE,
        CMD_INITIATE_TEST_MODE,
    ],
    generated: &[CMD_ZONE_STATUS_CHANGE_NOTIFICATION, CMD_ZONE_ENROLL_REQUEST],
};

/// `ZoneState` values (Table 8-4).
pub mod zone_state {
    /// Not enrolled.
    pub const NOT_ENROLLED: u8 = 0x00;
    /// Enrolled.
    pub const ENROLLED: u8 = 0x01;
}

/// `ZoneType` values (Table 8-5).
pub mod zone_type {
    /// Standard CIE.
    pub const STANDARD_CIE: u16 = 0x0000;
    /// Motion sensor.
    pub const MOTION_SENSOR: u16 = 0x000d;
    /// Contact switch.
    pub const CONTACT_SWITCH: u16 = 0x0015;
    /// Door / window handle.
    pub const DOOR_WINDOW_HANDLE: u16 = 0x0016;
    /// Fire sensor.
    pub const FIRE_SENSOR: u16 = 0x0028;
    /// Water sensor.
    pub const WATER_SENSOR: u16 = 0x002a;
    /// Carbon monoxide sensor.
    pub const CO_SENSOR: u16 = 0x002b;
    /// Personal emergency device.
    pub const PERSONAL_EMERGENCY_DEVICE: u16 = 0x002c;
    /// Vibration / movement sensor.
    pub const VIBRATION_SENSOR: u16 = 0x002d;
    /// Remote control.
    pub const REMOTE_CONTROL: u16 = 0x010f;
    /// Key fob.
    pub const KEY_FOB: u16 = 0x0115;
    /// Keypad.
    pub const KEYPAD: u16 = 0x021d;
    /// Standard warning device.
    pub const STANDARD_WARNING_DEVICE: u16 = 0x0225;
    /// Glass break sensor.
    pub const GLASS_BREAK_SENSOR: u16 = 0x0226;
    /// Security repeater.
    pub const SECURITY_REPEATER: u16 = 0x0229;
    /// Invalid zone type.
    pub const INVALID: u16 = 0xffff;
}

/// `ZoneStatus` bits (Table 8-6).
pub mod zone_status {
    /// Alarm1.
    pub const ALARM1: u16 = 1 << 0;
    /// Alarm2.
    pub const ALARM2: u16 = 1 << 1;
    /// Tamper.
    pub const TAMPER: u16 = 1 << 2;
    /// Low battery.
    pub const BATTERY: u16 = 1 << 3;
    /// Supervision notify (periodic notifications issued).
    pub const SUPERVISION_NOTIFY: u16 = 1 << 4;
    /// Restore notify (alarm-restore notifications issued).
    pub const RESTORE_NOTIFY: u16 = 1 << 5;
    /// Trouble / failure.
    pub const TROUBLE: u16 = 1 << 6;
    /// AC / mains fault.
    pub const AC_MAINS: u16 = 1 << 7;
    /// Test mode.
    pub const TEST: u16 = 1 << 8;
    /// Defective battery.
    pub const BATTERY_DEFECT: u16 = 1 << 9;
}

/// Enroll response codes (Table 8-10).
pub mod enroll_code {
    /// Success.
    pub const SUCCESS: u8 = 0x00;
    /// Zone type not supported by the CIE.
    pub const NOT_SUPPORTED: u8 = 0x01;
    /// The CIE does not permit enrolment now.
    pub const NO_ENROLL_PERMIT: u8 = 0x02;
    /// The CIE reached its zone limit.
    pub const TOO_MANY_ZONES: u8 = 0x03;
}

/// How the server enrols (§8.2.2.1.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EnrollMode {
    /// Trip-to-Pair and Auto-Enroll-Response: a Zone Enroll Request is
    /// sent on a manufacturer-defined trigger (`request_enrollment`) or
    /// a status change while unenrolled; an unsolicited Zone Enroll
    /// Response is accepted.
    TripToPair,
    /// Auto-Enroll-Request: a Zone Enroll Request is sent as soon as the
    /// CIE writes `IAS_CIE_Address`.
    AutoRequest,
}

/// Server state kept by the dispatcher.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct State {
    /// Enrolment mode.
    pub enroll: EnrollMode,
    /// Manufacturer code sent in Zone Enroll Requests.
    pub manufacturer_code: u16,
    /// The node that wrote `IAS_CIE_Address` (short address, endpoint):
    /// commands are accepted from it and sent to it.
    pub cie: Option<(ShortAddress, Endpoint)>,
    /// The `IAS_CIE_Address` value last seen by the dispatcher.
    pub cie_address: u64,
    /// A Zone Enroll Request is due.
    pub enroll_request_due: bool,
    /// A Zone Status Change Notification is due, with the instant of
    /// the change (for the Delay field).
    pub notify_due: Option<Instant>,
    /// Test mode ends at this instant.
    pub test_until: Option<Instant>,
}

/// Builds a server of `zone_type` enrolling per `enroll`;
/// `manufacturer_code` is the node descriptor's, `sensitivity_levels`
/// (≥ 2) adds the sensitivity attributes.
pub fn server<const A: usize>(
    zone_type: u16,
    manufacturer_code: u16,
    enroll: EnrollMode,
    sensitivity_levels: Option<u8>,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(ZONE_STATE, &Value::Enum8(zone_state::NOT_ENROLLED))?;
    c.add_attribute(ZONE_TYPE, &Value::Enum16(zone_type))?;
    c.add_attribute(ZONE_STATUS, &Value::Bits { width: 2, bits: 0 })?;
    c.add_attribute(IAS_CIE_ADDRESS, &Value::Eui64(0))?;
    c.add_attribute(
        ZONE_ID,
        &Value::Uint {
            width: 1,
            value: u64::from(ZONE_ID_NONE),
        },
    )?;
    if let Some(n) = sensitivity_levels {
        if n < 2 {
            return Err(ZclStatus::InvalidValue);
        }
        c.add_attribute(
            NUMBER_OF_ZONE_SENSITIVITY_LEVELS_SUPPORTED,
            &Value::Uint {
                width: 1,
                value: u64::from(n),
            },
        )?;
        c.add_attribute(
            CURRENT_ZONE_SENSITIVITY_LEVEL,
            &Value::Uint { width: 1, value: 0 },
        )?;
    }
    c.state = ClusterState::IasZone(State {
        enroll,
        manufacturer_code,
        cie: None,
        cie_address: 0,
        enroll_request_due: false,
        notify_due: None,
        test_until: None,
    });
    Ok(c)
}

/// Builds a client (CIE) instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

fn state<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut State> {
    match &mut c.state {
        ClusterState::IasZone(s) => Some(s),
        _ => None,
    }
}

/// The server state.
pub fn state_of<const A: usize>(c: &ClusterInstance<A>) -> Option<&State> {
    match &c.state {
        ClusterState::IasZone(s) => Some(s),
        _ => None,
    }
}

/// Whether the zone is enrolled.
pub fn is_enrolled<const A: usize>(c: &ClusterInstance<A>) -> bool {
    c.u8(ZONE_STATE.id) == Some(zone_state::ENROLLED)
}

/// The current `ZoneStatus`.
pub fn status<const A: usize>(c: &ClusterInstance<A>) -> u16 {
    c.u16(ZONE_STATUS.id).unwrap_or(0)
}

fn write_status<const A: usize>(c: &mut ClusterInstance<A>, status: u16, now: Instant) -> bool {
    let changed = c.set(
        ZONE_STATUS.id,
        &Value::Bits {
            width: 2,
            bits: u64::from(status),
        },
    );
    if changed && let Some(s) = state(c) {
        s.notify_due.get_or_insert(now);
        c.tick = Some(now);
    }
    changed
}

/// Sets the zone status from the application (sensor readings, tamper,
/// battery); a change schedules a Zone Status Change Notification, and
/// while unenrolled under Trip-to-Pair also a Zone Enroll Request
/// (§8.2.2.1.3 step 4). The Test bit is owned by the test mode commands
/// and preserved. Returns whether the status changed.
pub fn set_status<const A: usize>(c: &mut ClusterInstance<A>, status: u16, now: Instant) -> bool {
    let test = self::status(c) & zone_status::TEST;
    let changed = write_status(c, (status & !zone_status::TEST) | test, now);
    if changed
        && !is_enrolled(c)
        && let Some(s) = state(c)
        && s.enroll == EnrollMode::TripToPair
        && s.cie.is_some()
    {
        s.enroll_request_due = true;
    }
    changed
}

/// Requests enrolment now (the manufacturer-defined Trip-to-Pair
/// trigger, §8.2.2.1.3 step 4); ignored while enrolled or without a CIE.
pub fn request_enrollment<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> bool {
    if is_enrolled(c) {
        return false;
    }
    match state(c) {
        Some(s) if s.cie.is_some() => {
            s.enroll_request_due = true;
            c.tick = Some(now);
            true
        }
        _ => false,
    }
}

/// Called by the dispatcher after a Write Attributes from `src` /
/// `src_endpoint`: when `IAS_CIE_Address` changed, that node becomes
/// the CIE and, under Auto-Enroll-Request, a Zone Enroll Request is
/// scheduled.
pub fn after_write<const A: usize>(
    c: &mut ClusterInstance<A>,
    src: ShortAddress,
    src_endpoint: Endpoint,
    now: Instant,
) {
    let addr = c.u64(IAS_CIE_ADDRESS.id).unwrap_or(0);
    let Some(s) = state(c) else {
        return;
    };
    if addr == s.cie_address {
        return;
    }
    s.cie_address = addr;
    if addr == 0 || addr == u64::MAX {
        s.cie = None;
        return;
    }
    s.cie = Some((src, src_endpoint));
    if s.enroll == EnrollMode::AutoRequest {
        s.enroll_request_due = true;
        c.tick = Some(now);
    }
}

/// Whether a command from `src` may be acted upon (§8.2.2.2.1.2: only
/// the CIE, once one is configured).
pub fn accepts_from<const A: usize>(c: &ClusterInstance<A>, src: ShortAddress) -> bool {
    match state_of(c) {
        Some(s) => s.cie.is_none_or(|(a, _)| a == src),
        None => false,
    }
}

/// The CIE's IEEE address (`IAS_CIE_Address`), when set.
pub fn cie_address<const A: usize>(c: &ClusterInstance<A>) -> Option<ExtendedAddress> {
    match c.u64(IAS_CIE_ADDRESS.id) {
        Some(0) | None => None,
        Some(v) => Some(ExtendedAddress(v)),
    }
}

/// Result of a received server command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Enrolled with this zone identifier (Default Response applies).
    Enrolled(u8),
    /// The CIE refused enrolment with this code.
    Refused(u8),
    /// Test mode started (`Some(seconds)`) or normal operation resumed
    /// (`None`); a Zone Status Change Notification is scheduled.
    TestMode(Option<u8>),
    /// Not from the CIE: ignored (no response).
    NotAuthorized,
    /// Unknown command.
    Unsupported,
    /// Malformed payload.
    Malformed,
}

/// Handles a received server command from `src`.
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    src: ShortAddress,
    cmd: CommandId,
    payload: &[u8],
    now: Instant,
) -> Outcome {
    if !accepts_from(c, src) {
        return Outcome::NotAuthorized;
    }
    match cmd {
        CMD_ZONE_ENROLL_RESPONSE => {
            let [code, zone_id] = payload else {
                return Outcome::Malformed;
            };
            if *code != enroll_code::SUCCESS {
                return Outcome::Refused(*code);
            }
            c.set(ZONE_STATE.id, &Value::Enum8(zone_state::ENROLLED));
            c.set_u8(ZONE_ID.id, *zone_id);
            if let Some(s) = state(c) {
                s.enroll_request_due = false;
            }
            Outcome::Enrolled(*zone_id)
        }
        CMD_INITIATE_NORMAL_OPERATION_MODE => {
            if let Some(s) = state(c) {
                s.test_until = None;
            }
            let st = status(c) & !zone_status::TEST;
            write_status(c, st, now);
            Outcome::TestMode(None)
        }
        CMD_INITIATE_TEST_MODE => {
            let [duration, sensitivity] = payload else {
                return Outcome::Malformed;
            };
            if c.attributes
                .get(CURRENT_ZONE_SENSITIVITY_LEVEL.id, None)
                .is_some()
            {
                c.set_u8(CURRENT_ZONE_SENSITIVITY_LEVEL.id, *sensitivity);
            }
            if let Some(s) = state(c) {
                s.test_until = Some(now + Duration::from_secs(u64::from(*duration)));
            }
            let st = status(c) | zone_status::TEST;
            write_status(c, st, now);
            Outcome::TestMode(Some(*duration))
        }
        _ => Outcome::Unsupported,
    }
}

/// A command the server must send to the CIE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Send {
    /// Zone Status Change Notification with this payload.
    StatusChange([u8; 6]),
    /// Zone Enroll Request with this payload.
    EnrollRequest([u8; 4]),
}

/// Runs the server's timers: ends an expired test mode, then returns
/// the next command due for the CIE (call until `None`).
pub fn tick<const A: usize>(
    c: &mut ClusterInstance<A>,
    now: Instant,
) -> Option<(Send, (ShortAddress, Endpoint))> {
    let expired = state_of(c)
        .and_then(|s| s.test_until)
        .is_some_and(|t| now.has_reached(t));
    if expired {
        if let Some(s) = state(c) {
            s.test_until = None;
        }
        let st = status(c) & !zone_status::TEST;
        write_status(c, st, now);
    }
    let zone_status = status(c);
    let zone_id = c.u8(ZONE_ID.id).unwrap_or(ZONE_ID_NONE);
    let zone_type = c.u16(ZONE_TYPE.id).unwrap_or(zone_type::INVALID);
    let s = state(c)?;
    let cie = s.cie?;
    if let Some(at) = s.notify_due.take() {
        let delay =
            u16::try_from(now.as_millis().saturating_sub(at.as_millis()) / 250).unwrap_or(u16::MAX);
        let mut p = [0u8; 6];
        let mut w = Writer::new(&mut p);
        let _ = w.u16_le(zone_status);
        let _ = w.u8(0);
        let _ = w.u8(zone_id);
        let _ = w.u16_le(delay);
        c.tick = Some(now);
        return Some((Send::StatusChange(p), cie));
    }
    if s.enroll_request_due {
        s.enroll_request_due = false;
        let mut p = [0u8; 4];
        let mut w = Writer::new(&mut p);
        let _ = w.u16_le(zone_type);
        let _ = w.u16_le(s.manufacturer_code);
        c.tick = Some(now);
        return Some((Send::EnrollRequest(p), cie));
    }
    c.tick = s.test_until;
    None
}

/// Zone Status Change Notification (client side).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StatusChange {
    /// Zone status.
    pub zone_status: u16,
    /// Extended status (0).
    pub extended_status: u8,
    /// Zone identifier.
    pub zone_id: u8,
    /// Delay in quarter seconds.
    pub delay: u16,
}

impl StatusChange {
    /// Parses the payload (a legacy four-octet form without Zone ID and
    /// Delay is accepted).
    pub fn parse(payload: &[u8]) -> Option<Self> {
        let mut r = Reader::new(payload);
        let zone_status = r.u16_le().ok()?;
        let extended_status = r.u8().ok()?;
        let zone_id = r.u8().unwrap_or(ZONE_ID_NONE);
        let delay = r.u16_le().unwrap_or(0);
        Some(StatusChange {
            zone_status,
            extended_status,
            zone_id,
            delay,
        })
    }
}

/// Zone Enroll Request (client side).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EnrollRequest {
    /// Zone type.
    pub zone_type: u16,
    /// Manufacturer code.
    pub manufacturer_code: u16,
}

impl EnrollRequest {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Option<Self> {
        let mut r = Reader::new(payload);
        Some(EnrollRequest {
            zone_type: r.u16_le().ok()?,
            manufacturer_code: r.u16_le().ok()?,
        })
    }
}

/// Zone Enroll Response payload (client side).
pub const fn enroll_response(code: u8, zone_id: u8) -> [u8; 2] {
    [code, zone_id]
}

/// Initiate Test Mode payload (client side).
pub const fn initiate_test_mode(duration_secs: u8, sensitivity: u8) -> [u8; 2] {
    [duration_secs, sensitivity]
}

#[cfg(test)]
mod tests {
    use super::*;

    const CIE: ShortAddress = ShortAddress(0x1234);
    const OTHER: ShortAddress = ShortAddress(0x5678);

    #[test]
    fn auto_enroll_request_flow_and_notifications() {
        let t0 = Instant::from_millis(1000);
        let mut c: ClusterInstance<16> = server(
            zone_type::CONTACT_SWITCH,
            0x1234,
            EnrollMode::AutoRequest,
            Some(3),
        )
        .unwrap();
        // Nothing is sent before the CIE is configured; commands from
        // anyone are refused once it is.
        assert!(tick(&mut c, t0).is_none());
        assert!(set_status(&mut c, zone_status::ALARM1, t0));
        assert!(tick(&mut c, t0).is_none());
        c.set(IAS_CIE_ADDRESS.id, &Value::Eui64(0xAA));
        after_write(&mut c, CIE, Endpoint(1), t0);
        let (send, dst) = tick(&mut c, t0 + Duration::from_millis(500)).unwrap();
        assert_eq!(dst, (CIE, Endpoint(1)));
        // The pending status change goes first (2 quarter seconds late),
        // then the enroll request.
        assert_eq!(
            send,
            Send::StatusChange([0x01, 0x00, 0x00, 0xff, 0x02, 0x00])
        );
        let (send, _) = tick(&mut c, t0 + Duration::from_millis(500)).unwrap();
        assert_eq!(send, Send::EnrollRequest([0x15, 0x00, 0x34, 0x12]));
        assert!(tick(&mut c, t0 + Duration::from_secs(1)).is_none());
        assert_eq!(
            handle(&mut c, OTHER, CMD_ZONE_ENROLL_RESPONSE, &[0, 7], t0),
            Outcome::NotAuthorized
        );
        assert_eq!(
            handle(
                &mut c,
                CIE,
                CMD_ZONE_ENROLL_RESPONSE,
                &[enroll_code::TOO_MANY_ZONES, 0],
                t0
            ),
            Outcome::Refused(enroll_code::TOO_MANY_ZONES)
        );
        assert!(!is_enrolled(&c));
        assert_eq!(
            handle(&mut c, CIE, CMD_ZONE_ENROLL_RESPONSE, &[0, 7], t0),
            Outcome::Enrolled(7)
        );
        assert!(is_enrolled(&c));
        assert_eq!(c.u8(ZONE_ID.id), Some(7));
        // Test mode: Test bit set, sensitivity applied, cleared on expiry.
        assert_eq!(
            handle(
                &mut c,
                CIE,
                CMD_INITIATE_TEST_MODE,
                &initiate_test_mode(10, 2),
                t0
            ),
            Outcome::TestMode(Some(10))
        );
        assert_eq!(c.u8(CURRENT_ZONE_SENSITIVITY_LEVEL.id), Some(2));
        let (send, _) = tick(&mut c, t0).unwrap();
        assert_eq!(
            send,
            Send::StatusChange([0x01, 0x01, 0x00, 0x07, 0x00, 0x00])
        );
        // A status change keeps the Test bit.
        assert!(set_status(&mut c, 0, t0 + Duration::from_secs(2)));
        assert_eq!(status(&c), zone_status::TEST);
        let (send, _) = tick(&mut c, t0 + Duration::from_secs(2)).unwrap();
        assert_eq!(
            send,
            Send::StatusChange([0x00, 0x01, 0x00, 0x07, 0x00, 0x00])
        );
        assert!(tick(&mut c, t0 + Duration::from_secs(9)).is_none());
        assert_eq!(c.tick, Some(t0 + Duration::from_secs(10)));
        let (send, _) = tick(&mut c, t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(
            send,
            Send::StatusChange([0x00, 0x00, 0x00, 0x07, 0x00, 0x00])
        );
        assert_eq!(status(&c), 0);
        // Client codecs.
        assert_eq!(
            StatusChange::parse(&[0x05, 0x00, 0x00, 0x07, 0x02, 0x00]),
            Some(StatusChange {
                zone_status: 5,
                extended_status: 0,
                zone_id: 7,
                delay: 2
            })
        );
        assert_eq!(
            StatusChange::parse(&[0x05, 0x00, 0x00]).unwrap().zone_id,
            ZONE_ID_NONE
        );
        assert_eq!(
            EnrollRequest::parse(&[0x0d, 0x00, 0x34, 0x12]),
            Some(EnrollRequest {
                zone_type: zone_type::MOTION_SENSOR,
                manufacturer_code: 0x1234
            })
        );
    }

    #[test]
    fn trip_to_pair_requests_on_status_change() {
        let t0 = Instant::from_millis(0);
        let mut c: ClusterInstance<16> =
            server(zone_type::MOTION_SENSOR, 1, EnrollMode::TripToPair, None).unwrap();
        c.set(IAS_CIE_ADDRESS.id, &Value::Eui64(0xBB));
        after_write(&mut c, CIE, Endpoint(2), t0);
        // No auto request; a status change while unenrolled triggers it.
        assert!(tick(&mut c, t0).is_none());
        assert!(set_status(&mut c, zone_status::ALARM1, t0));
        let (first, _) = tick(&mut c, t0).unwrap();
        assert!(matches!(first, Send::StatusChange(_)));
        let (second, _) = tick(&mut c, t0).unwrap();
        assert!(matches!(second, Send::EnrollRequest(_)));
        // Auto-Enroll-Response: an unsolicited response enrols.
        assert_eq!(
            handle(&mut c, CIE, CMD_ZONE_ENROLL_RESPONSE, &[0, 1], t0),
            Outcome::Enrolled(1)
        );
        assert!(!request_enrollment(&mut c, t0));
        // Clearing the CIE address forgets the CIE.
        c.set(IAS_CIE_ADDRESS.id, &Value::Eui64(0));
        after_write(&mut c, OTHER, Endpoint(1), t0);
        assert!(state_of(&c).unwrap().cie.is_none());
        assert!(accepts_from(&c, OTHER));
    }
}
