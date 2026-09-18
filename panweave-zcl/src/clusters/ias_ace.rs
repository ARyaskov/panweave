//! IAS ACE cluster (ZCL8 §8.3): the CIE's security panel as seen by
//! keypads and key fobs. The server keeps a bounded zone table, the
//! panel status and the bypass list; the dispatcher answers Get Zone ID
//! Map, Get Zone Information, Get Panel Status, Get Bypassed Zone List
//! and Get Zone Status from that state, validates the arm / disarm code
//! for Arm and Bypass, and hands Arm, Emergency, Fire and Panic to the
//! application as a [`Request`]. The application keeps the table and
//! the panel status current with [`add_zone`], [`set_zone_status`] and
//! [`set_panel_status`], which also produce the Zone Status Changed and
//! Panel Status Changed commands for the bound clients.
//!
//! The arm / disarm code is a credential: [`Code`] redacts its `Debug`
//! output and compares in constant time.

use core::fmt;

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use subtle::ConstantTimeEq;

use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0501);

/// Arm.
pub const CMD_ARM: CommandId = CommandId(0x00);
/// Bypass.
pub const CMD_BYPASS: CommandId = CommandId(0x01);
/// Emergency.
pub const CMD_EMERGENCY: CommandId = CommandId(0x02);
/// Fire.
pub const CMD_FIRE: CommandId = CommandId(0x03);
/// Panic.
pub const CMD_PANIC: CommandId = CommandId(0x04);
/// Get Zone ID Map.
pub const CMD_GET_ZONE_ID_MAP: CommandId = CommandId(0x05);
/// Get Zone Information.
pub const CMD_GET_ZONE_INFORMATION: CommandId = CommandId(0x06);
/// Get Panel Status.
pub const CMD_GET_PANEL_STATUS: CommandId = CommandId(0x07);
/// Get Bypassed Zone List.
pub const CMD_GET_BYPASSED_ZONE_LIST: CommandId = CommandId(0x08);
/// Get Zone Status.
pub const CMD_GET_ZONE_STATUS: CommandId = CommandId(0x09);

/// Arm Response.
pub const CMD_ARM_RESPONSE: CommandId = CommandId(0x00);
/// Get Zone ID Map Response.
pub const CMD_GET_ZONE_ID_MAP_RESPONSE: CommandId = CommandId(0x01);
/// Get Zone Information Response.
pub const CMD_GET_ZONE_INFORMATION_RESPONSE: CommandId = CommandId(0x02);
/// Zone Status Changed.
pub const CMD_ZONE_STATUS_CHANGED: CommandId = CommandId(0x03);
/// Panel Status Changed.
pub const CMD_PANEL_STATUS_CHANGED: CommandId = CommandId(0x04);
/// Get Panel Status Response.
pub const CMD_GET_PANEL_STATUS_RESPONSE: CommandId = CommandId(0x05);
/// Set Bypassed Zone List.
pub const CMD_SET_BYPASSED_ZONE_LIST: CommandId = CommandId(0x06);
/// Bypass Response.
pub const CMD_BYPASS_RESPONSE: CommandId = CommandId(0x07);
/// Get Zone Status Response.
pub const CMD_GET_ZONE_STATUS_RESPONSE: CommandId = CommandId(0x08);

/// Arm Mode values (Table 8-14).
pub mod arm_mode {
    /// Disarm.
    pub const DISARM: u8 = 0x00;
    /// Arm day / home zones only.
    pub const DAY_HOME: u8 = 0x01;
    /// Arm night / sleep zones only.
    pub const NIGHT_SLEEP: u8 = 0x02;
    /// Arm all zones.
    pub const ALL: u8 = 0x03;
}

/// Arm Notification values (Table 8-16).
pub mod arm_notification {
    /// All zones disarmed.
    pub const ALL_ZONES_DISARMED: u8 = 0x00;
    /// Only day / home zones armed.
    pub const DAY_HOME_ARMED: u8 = 0x01;
    /// Only night / sleep zones armed.
    pub const NIGHT_SLEEP_ARMED: u8 = 0x02;
    /// All zones armed.
    pub const ALL_ZONES_ARMED: u8 = 0x03;
    /// Invalid arm / disarm code.
    pub const INVALID_CODE: u8 = 0x04;
    /// Not ready to arm.
    pub const NOT_READY_TO_ARM: u8 = 0x05;
    /// Already disarmed.
    pub const ALREADY_DISARMED: u8 = 0x06;
}

/// Panel Status values (Table 8-17).
pub mod panel_status {
    /// Disarmed and ready to arm.
    pub const DISARMED: u8 = 0x00;
    /// Armed stay.
    pub const ARMED_STAY: u8 = 0x01;
    /// Armed night.
    pub const ARMED_NIGHT: u8 = 0x02;
    /// Armed away.
    pub const ARMED_AWAY: u8 = 0x03;
    /// Exit delay.
    pub const EXIT_DELAY: u8 = 0x04;
    /// Entry delay.
    pub const ENTRY_DELAY: u8 = 0x05;
    /// Not ready to arm.
    pub const NOT_READY_TO_ARM: u8 = 0x06;
    /// In alarm.
    pub const IN_ALARM: u8 = 0x07;
    /// Arming stay.
    pub const ARMING_STAY: u8 = 0x08;
    /// Arming night.
    pub const ARMING_NIGHT: u8 = 0x09;
    /// Arming away.
    pub const ARMING_AWAY: u8 = 0x0a;
}

/// Alarm Status values (Figure 8-16, the IAS WD warning modes).
pub mod alarm_status {
    /// No alarm.
    pub const NONE: u8 = 0x00;
    /// Burglar.
    pub const BURGLAR: u8 = 0x01;
    /// Fire.
    pub const FIRE: u8 = 0x02;
    /// Emergency.
    pub const EMERGENCY: u8 = 0x03;
    /// Police panic.
    pub const POLICE_PANIC: u8 = 0x04;
    /// Fire panic.
    pub const FIRE_PANIC: u8 = 0x05;
    /// Emergency panic.
    pub const EMERGENCY_PANIC: u8 = 0x06;
}

/// Audible Notification values (Figure 8-14).
pub mod audible {
    /// Mute.
    pub const MUTE: u8 = 0x00;
    /// Default sound.
    pub const DEFAULT: u8 = 0x01;
}

/// Bypass Result values (Table 8-18).
pub mod bypass_result {
    /// Zone bypassed.
    pub const BYPASSED: u8 = 0x00;
    /// Zone not bypassed.
    pub const NOT_BYPASSED: u8 = 0x01;
    /// Not allowed.
    pub const NOT_ALLOWED: u8 = 0x02;
    /// Invalid zone identifier.
    pub const INVALID_ZONE_ID: u8 = 0x03;
    /// Unknown zone identifier.
    pub const UNKNOWN_ZONE_ID: u8 = 0x04;
    /// Invalid arm / disarm code.
    pub const INVALID_CODE: u8 = 0x05;
}

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[
        CMD_ARM,
        CMD_BYPASS,
        CMD_EMERGENCY,
        CMD_FIRE,
        CMD_PANIC,
        CMD_GET_ZONE_ID_MAP,
        CMD_GET_ZONE_INFORMATION,
        CMD_GET_PANEL_STATUS,
        CMD_GET_BYPASSED_ZONE_LIST,
        CMD_GET_ZONE_STATUS,
    ],
    generated: &[
        CMD_ARM_RESPONSE,
        CMD_GET_ZONE_ID_MAP_RESPONSE,
        CMD_GET_ZONE_INFORMATION_RESPONSE,
        CMD_ZONE_STATUS_CHANGED,
        CMD_PANEL_STATUS_CHANGED,
        CMD_GET_PANEL_STATUS_RESPONSE,
        CMD_SET_BYPASSED_ZONE_LIST,
        CMD_BYPASS_RESPONSE,
        CMD_GET_ZONE_STATUS_RESPONSE,
    ],
};

/// Zones a panel keeps (the table allows up to 255).
pub const MAX_ZONES: usize = 16;
/// Longest zone label kept (§8.3.2.4.3.2 suggests 16–24).
pub const MAX_LABEL: usize = 24;
/// Longest arm / disarm code kept (§8.3.2.3.1.3 suggests 4–8).
pub const MAX_CODE: usize = 16;
/// Largest response / notification payload.
pub const MAX_PAYLOAD: usize = 2 + 3 * MAX_ZONES;
/// Unallocated zone type.
pub const ZONE_TYPE_NONE: u16 = 0xffff;
/// Unallocated zone address.
pub const ZONE_ADDRESS_NONE: u64 = 0xffff_ffff_ffff_ffff;

/// An arm / disarm code, never printed.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Code(Vec<u8, MAX_CODE>);

impl Code {
    /// Wraps `code`, refusing more than [`MAX_CODE`] octets.
    pub fn new(code: &[u8]) -> Option<Code> {
        Vec::from_slice(code).ok().map(Code)
    }

    /// Constant-time comparison.
    pub fn matches(&self, code: &[u8]) -> bool {
        self.0.len() == code.len() && bool::from(self.0.as_slice().ct_eq(code))
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code(<{} octets redacted>)", self.0.len())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Code {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Code(<{} octets redacted>)", self.0.len());
    }
}

/// A zone table entry (Table 8-12) with its last known status.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Zone {
    /// Zone identifier (0x00–0xfe).
    pub id: u8,
    /// Zone type (IAS Zone Table 8-5).
    pub zone_type: u16,
    /// IEEE address of the zone device.
    pub address: u64,
    /// Last `ZoneStatus`.
    pub status: u16,
    /// Bypassed.
    pub bypassed: bool,
    /// May be bypassed (§8.3.2.4.8.3 "not allowed" otherwise).
    pub bypass_allowed: bool,
    /// Zone label (UTF-8).
    pub label: Vec<u8, MAX_LABEL>,
}

/// Server state kept by the dispatcher.
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Panel {
    /// Enrolled zones.
    pub zones: Vec<Zone, MAX_ZONES>,
    /// Panel status (Table 8-17).
    pub status: u8,
    /// Seconds remaining in an exit / entry delay.
    pub seconds_remaining: u8,
    /// Audible notification for the clients.
    pub audible: u8,
    /// Alarm status (Figure 8-16).
    pub alarm: u8,
    /// Arm / disarm code (`None`: no code required).
    pub code: Option<Code>,
    /// Ready to arm (manufacturer policy, Table 8-16 note).
    pub ready: bool,
}

/// A request the application decides on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Request {
    /// Arm with this mode (code already validated); the dispatcher
    /// answered with the matching notification and set the panel
    /// status.
    Arm {
        /// Arm mode (Table 8-14).
        mode: u8,
        /// Zone identifier of the requesting client.
        zone_id: u8,
    },
    /// Emergency.
    Emergency,
    /// Fire.
    Fire,
    /// Panic.
    Panic,
}

/// A frame the server sends.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Frame {
    /// Command identifier (server to client).
    pub command: CommandId,
    /// Payload.
    pub payload: Vec<u8, MAX_PAYLOAD>,
}

fn frame(
    command: CommandId,
    build: impl FnOnce(&mut Writer<'_>) -> Result<(), CodecError>,
) -> Option<Frame> {
    let mut buf = [0u8; MAX_PAYLOAD];
    let mut w = Writer::new(&mut buf);
    build(&mut w).ok()?;
    let n = w.position();
    Some(Frame {
        command,
        payload: Vec::from_slice(buf.get(..n)?).ok()?,
    })
}

/// Result of a received command.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Outcome {
    /// Cluster-specific response; `None` means a Default Response with
    /// `status`.
    pub response: Option<Frame>,
    /// Default Response status when there is no response frame.
    pub status: ZclStatus,
    /// A request for the application.
    pub request: Option<Request>,
    /// An unsolicited command for the bound clients (the bypass list
    /// after a disarm).
    pub notify: Option<Frame>,
}

impl Outcome {
    fn default_response(status: ZclStatus) -> Outcome {
        Outcome {
            response: None,
            status,
            request: None,
            notify: None,
        }
    }

    fn reply(f: Option<Frame>) -> Outcome {
        Outcome {
            response: f,
            status: ZclStatus::Success,
            request: None,
            notify: None,
        }
    }
}

/// Builds a server whose panel is disarmed and ready, requiring `code`
/// (`None`: none) for Arm and Bypass.
pub fn server<const A: usize>(code: Option<Code>) -> ClusterInstance<A> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.state = ClusterState::IasAce(Panel {
        audible: audible::DEFAULT,
        code,
        ready: true,
        ..Panel::default()
    });
    c
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

fn panel_mut<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut Panel> {
    match &mut c.state {
        ClusterState::IasAce(p) => Some(p),
        _ => None,
    }
}

/// The panel state of a server.
pub fn panel<const A: usize>(c: &ClusterInstance<A>) -> Option<&Panel> {
    match &c.state {
        ClusterState::IasAce(p) => Some(p),
        _ => None,
    }
}

/// Adds or replaces a zone (by identifier); `Err` when the table is
/// full.
pub fn add_zone<const A: usize>(c: &mut ClusterInstance<A>, zone: Zone) -> Result<(), Zone> {
    let Some(p) = panel_mut(c) else {
        return Err(zone);
    };
    if let Some(z) = p.zones.iter_mut().find(|z| z.id == zone.id) {
        *z = zone;
        Ok(())
    } else {
        p.zones.push(zone)
    }
}

/// Removes a zone; returns whether it existed.
pub fn remove_zone<const A: usize>(c: &mut ClusterInstance<A>, id: u8) -> bool {
    let Some(p) = panel_mut(c) else {
        return false;
    };
    let Some(i) = p.zones.iter().position(|z| z.id == id) else {
        return false;
    };
    p.zones.swap_remove(i);
    true
}

/// Records a zone's `ZoneStatus` and returns the Zone Status Changed
/// command for the bound clients (`None` for an unknown zone).
pub fn set_zone_status<const A: usize>(
    c: &mut ClusterInstance<A>,
    id: u8,
    status: u16,
) -> Option<Frame> {
    let p = panel_mut(c)?;
    let audible = p.audible;
    let z = p.zones.iter_mut().find(|z| z.id == id)?;
    z.status = status;
    let label = z.label.clone();
    frame(CMD_ZONE_STATUS_CHANGED, |w| {
        w.u8(id)?;
        w.u16_le(status)?;
        w.u8(audible)?;
        w.u8(u8::try_from(label.len()).unwrap_or(0))?;
        w.bytes(&label)
    })
}

fn panel_status_payload(p: &Panel, w: &mut Writer<'_>) -> Result<(), CodecError> {
    w.u8(p.status)?;
    w.u8(p.seconds_remaining)?;
    w.u8(p.audible)?;
    w.u8(p.alarm)
}

/// Sets the panel status (Table 8-17), the seconds remaining of a delay
/// and the alarm status, and returns the Panel Status Changed command
/// for the bound clients (§8.3.2.4.5). Disarming clears the bypass
/// list (§8.3.2.4.7.4).
pub fn set_panel_status<const A: usize>(
    c: &mut ClusterInstance<A>,
    status: u8,
    seconds_remaining: u8,
    alarm: u8,
) -> Option<Frame> {
    let p = panel_mut(c)?;
    p.status = status;
    p.seconds_remaining = seconds_remaining;
    p.alarm = alarm;
    if status == panel_status::DISARMED {
        for z in p.zones.iter_mut() {
            z.bypassed = false;
        }
    }
    let p = panel(c)?;
    frame(CMD_PANEL_STATUS_CHANGED, |w| panel_status_payload(p, w))
}

/// Marks the panel ready (or not) to arm.
pub fn set_ready<const A: usize>(c: &mut ClusterInstance<A>, ready: bool) {
    if let Some(p) = panel_mut(c) {
        p.ready = ready;
    }
}

fn bypassed_list(p: &Panel) -> Option<Frame> {
    let mut ids: Vec<u8, MAX_ZONES> = p
        .zones
        .iter()
        .filter(|z| z.bypassed)
        .map(|z| z.id)
        .collect();
    ids.sort_unstable();
    frame(CMD_SET_BYPASSED_ZONE_LIST, |w| {
        w.u8(u8::try_from(ids.len()).unwrap_or(0))?;
        w.bytes(&ids)
    })
}

/// The Set Bypassed Zone List command for the current bypass list.
pub fn bypassed_zone_list<const A: usize>(c: &ClusterInstance<A>) -> Option<Frame> {
    bypassed_list(panel(c)?)
}

fn read_string<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let n = r.u8()?;
    if n == 0xff {
        return Ok(&[]);
    }
    r.bytes(usize::from(n))
}

/// Handles a received command (§8.3.2.3).
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
) -> Outcome {
    let mut r = Reader::new(payload);
    match cmd {
        CMD_ARM => {
            let (Ok(mode), Ok(code), Ok(zone_id)) = (r.u8(), read_string(&mut r), r.u8()) else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            if mode > arm_mode::ALL {
                return Outcome::default_response(ZclStatus::InvalidField);
            }
            let Some(p) = panel_mut(c) else {
                return Outcome::default_response(ZclStatus::Failure);
            };
            let code_ok = p.code.as_ref().is_none_or(|k| k.matches(code));
            let armed =
                p.status != panel_status::DISARMED && p.status != panel_status::NOT_READY_TO_ARM;
            let (notification, accepted) = if !code_ok {
                (arm_notification::INVALID_CODE, false)
            } else if mode == arm_mode::DISARM && !armed {
                (arm_notification::ALREADY_DISARMED, false)
            } else if mode != arm_mode::DISARM && !p.ready {
                (arm_notification::NOT_READY_TO_ARM, false)
            } else {
                (mode, true)
            };
            let mut notify = None;
            if accepted {
                p.status = match mode {
                    arm_mode::DAY_HOME => panel_status::ARMED_STAY,
                    arm_mode::NIGHT_SLEEP => panel_status::ARMED_NIGHT,
                    arm_mode::ALL => panel_status::ARMED_AWAY,
                    _ => panel_status::DISARMED,
                };
                p.seconds_remaining = 0;
                if mode == arm_mode::DISARM {
                    p.alarm = alarm_status::NONE;
                    for z in p.zones.iter_mut() {
                        z.bypassed = false;
                    }
                    notify = bypassed_list(p);
                }
            }
            let mut o = Outcome::reply(frame(CMD_ARM_RESPONSE, |w| w.u8(notification)));
            if accepted {
                o.request = Some(Request::Arm { mode, zone_id });
                o.notify = notify;
            }
            o
        }
        CMD_BYPASS => {
            let Ok(n) = r.u8() else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let Ok(ids) = r.bytes(usize::from(n)) else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let Ok(code) = read_string(&mut r) else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            if ids.len() >= MAX_PAYLOAD {
                return Outcome::default_response(ZclStatus::InsufficientSpace);
            }
            let Some(p) = panel_mut(c) else {
                return Outcome::default_response(ZclStatus::Failure);
            };
            let code_ok = p.code.as_ref().is_none_or(|k| k.matches(code));
            let mut results: Vec<u8, MAX_PAYLOAD> = Vec::new();
            for &id in ids {
                let result = if !code_ok {
                    bypass_result::INVALID_CODE
                } else if id == 0xff {
                    bypass_result::INVALID_ZONE_ID
                } else {
                    match p.zones.iter_mut().find(|z| z.id == id) {
                        None => bypass_result::UNKNOWN_ZONE_ID,
                        Some(z) if !z.bypass_allowed => bypass_result::NOT_ALLOWED,
                        Some(z) => {
                            z.bypassed = true;
                            bypass_result::BYPASSED
                        }
                    }
                };
                let _ = results.push(result);
            }
            Outcome::reply(frame(CMD_BYPASS_RESPONSE, |w| {
                w.u8(u8::try_from(results.len()).unwrap_or(0))?;
                w.bytes(&results)
            }))
        }
        CMD_EMERGENCY | CMD_FIRE | CMD_PANIC => {
            let mut o = Outcome::default_response(ZclStatus::Success);
            o.request = Some(match cmd {
                CMD_EMERGENCY => Request::Emergency,
                CMD_FIRE => Request::Fire,
                _ => Request::Panic,
            });
            o
        }
        CMD_GET_ZONE_ID_MAP => {
            let Some(p) = panel(c) else {
                return Outcome::default_response(ZclStatus::Failure);
            };
            let mut sections = [0u16; 16];
            for z in &p.zones {
                if let Some(s) = sections.get_mut(usize::from(z.id / 16)) {
                    *s |= 1 << (z.id % 16);
                }
            }
            Outcome::reply(frame(CMD_GET_ZONE_ID_MAP_RESPONSE, |w| {
                for s in sections {
                    w.u16_le(s)?;
                }
                Ok(())
            }))
        }
        CMD_GET_ZONE_INFORMATION => {
            let Ok(id) = r.u8() else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let Some(p) = panel(c) else {
                return Outcome::default_response(ZclStatus::Failure);
            };
            let z = p.zones.iter().find(|z| z.id == id);
            Outcome::reply(frame(CMD_GET_ZONE_INFORMATION_RESPONSE, |w| {
                w.u8(id)?;
                match z {
                    Some(z) => {
                        w.u16_le(z.zone_type)?;
                        w.u64_le(z.address)?;
                        w.u8(u8::try_from(z.label.len()).unwrap_or(0))?;
                        w.bytes(&z.label)
                    }
                    None => {
                        w.u16_le(ZONE_TYPE_NONE)?;
                        w.u64_le(ZONE_ADDRESS_NONE)?;
                        w.u8(0)
                    }
                }
            }))
        }
        CMD_GET_PANEL_STATUS => {
            let Some(p) = panel(c) else {
                return Outcome::default_response(ZclStatus::Failure);
            };
            Outcome::reply(frame(CMD_GET_PANEL_STATUS_RESPONSE, |w| {
                panel_status_payload(p, w)
            }))
        }
        CMD_GET_BYPASSED_ZONE_LIST => Outcome::reply(bypassed_zone_list(c)),
        CMD_GET_ZONE_STATUS => {
            let (Ok(start), Ok(max), Ok(flag), Ok(mask)) = (r.u8(), r.u8(), r.u8(), r.u16_le())
            else {
                return Outcome::default_response(ZclStatus::MalformedCommand);
            };
            let Some(p) = panel(c) else {
                return Outcome::default_response(ZclStatus::Failure);
            };
            let mut ids: Vec<u8, MAX_ZONES> = p
                .zones
                .iter()
                .filter(|z| z.id >= start && (flag == 0 || z.status & mask != 0))
                .map(|z| z.id)
                .collect();
            ids.sort_unstable();
            let n = usize::from(max).min(ids.len());
            let complete = n == ids.len();
            Outcome::reply(frame(CMD_GET_ZONE_STATUS_RESPONSE, |w| {
                w.u8(u8::from(complete))?;
                w.u8(u8::try_from(n).unwrap_or(0))?;
                for id in ids.iter().take(n) {
                    let status = p.zones.iter().find(|z| z.id == *id).map_or(0, |z| z.status);
                    w.u8(*id)?;
                    w.u16_le(status)?;
                }
                Ok(())
            }))
        }
        _ => Outcome::default_response(ZclStatus::UnsupportedClusterCommand),
    }
}

/// Client-side view of a Panel Status Changed / Get Panel Status
/// Response payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PanelStatus {
    /// Panel status (Table 8-17).
    pub status: u8,
    /// Seconds remaining.
    pub seconds_remaining: u8,
    /// Audible notification.
    pub audible: u8,
    /// Alarm status.
    pub alarm: u8,
}

impl PanelStatus {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(PanelStatus {
            status: r.u8()?,
            seconds_remaining: r.u8()?,
            audible: r.u8()?,
            alarm: r.u8()?,
        })
    }
}

/// Client-side view of a Zone Status Changed payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ZoneStatusChanged<'a> {
    /// Zone identifier.
    pub zone_id: u8,
    /// Zone status.
    pub status: u16,
    /// Audible notification.
    pub audible: u8,
    /// Zone label.
    pub label: &'a [u8],
}

impl<'a> ZoneStatusChanged<'a> {
    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(ZoneStatusChanged {
            zone_id: r.u8()?,
            status: r.u16_le()?,
            audible: r.u8()?,
            label: read_string(&mut r)?,
        })
    }
}

/// Encodes an Arm payload.
pub fn encode_arm(mode: u8, code: &[u8], zone_id: u8, out: &mut [u8]) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    w.u8(mode)?;
    w.u8(u8::try_from(code.len()).map_err(|_| CodecError::Unrepresentable { field: "code" })?)?;
    w.bytes(code)?;
    w.u8(zone_id)?;
    Ok(w.position())
}

/// Encodes a Bypass payload.
pub fn encode_bypass(zones: &[u8], code: &[u8], out: &mut [u8]) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    w.u8(u8::try_from(zones.len()).map_err(|_| CodecError::Unrepresentable { field: "zones" })?)?;
    w.bytes(zones)?;
    w.u8(u8::try_from(code.len()).map_err(|_| CodecError::Unrepresentable { field: "code" })?)?;
    w.bytes(code)?;
    Ok(w.position())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(id: u8, status: u16) -> Zone {
        Zone {
            id,
            zone_type: 0x0015,
            address: 0x00AA_0000_0000_0000 | u64::from(id),
            status,
            bypassed: false,
            bypass_allowed: id != 2,
            label: Vec::from_slice(b"door").unwrap(),
        }
    }

    fn cie() -> ClusterInstance<36> {
        let mut c = server(Some(Code::new(b"1234").unwrap()));
        for (id, status) in [(0, 0), (1, 1), (2, 0), (17, 0x0003)] {
            add_zone(&mut c, zone(id, status)).unwrap();
        }
        c
    }

    fn arm(c: &mut ClusterInstance<36>, mode: u8, code: &[u8]) -> Outcome {
        let mut buf = [0u8; 16];
        let n = encode_arm(mode, code, 0xff, &mut buf).unwrap();
        handle(c, CMD_ARM, &buf[..n])
    }

    #[test]
    fn zone_queries_answer_from_the_table() {
        let mut c = cie();
        let o = handle(&mut c, CMD_GET_ZONE_ID_MAP, &[]);
        let p = o.response.unwrap().payload;
        assert_eq!(&p[..4], &[0x07, 0x00, 0x02, 0x00]);
        assert_eq!(p.len(), 32);

        let o = handle(&mut c, CMD_GET_ZONE_INFORMATION, &[17]);
        let p = o.response.unwrap().payload;
        assert_eq!(p[0], 17);
        assert_eq!(u16::from_le_bytes([p[1], p[2]]), 0x0015);
        assert_eq!(&p[11..], b"\x04door");
        let o = handle(&mut c, CMD_GET_ZONE_INFORMATION, &[5]);
        let p = o.response.unwrap().payload;
        assert_eq!(&p[1..3], &[0xff, 0xff]);
        assert_eq!(&p[3..11], &[0xff; 8]);
        assert_eq!(p[11], 0);

        // All zones from 1, at most 2: incomplete.
        let o = handle(&mut c, CMD_GET_ZONE_STATUS, &[1, 2, 0, 0, 0]);
        let p = o.response.unwrap().payload;
        assert_eq!(p.as_slice(), &[0, 2, 1, 1, 0, 2, 0, 0]);
        // Only alarmed zones (mask 0x0001): 1 and 17, complete.
        let o = handle(&mut c, CMD_GET_ZONE_STATUS, &[0, 10, 1, 1, 0]);
        let p = o.response.unwrap().payload;
        assert_eq!(p.as_slice(), &[1, 2, 1, 1, 0, 17, 3, 0]);

        let o = handle(&mut c, CMD_GET_PANEL_STATUS, &[]);
        let s = PanelStatus::parse(&o.response.unwrap().payload).unwrap();
        assert_eq!(
            s,
            PanelStatus {
                status: panel_status::DISARMED,
                seconds_remaining: 0,
                audible: audible::DEFAULT,
                alarm: alarm_status::NONE
            }
        );
        assert_eq!(
            handle(&mut c, CMD_GET_ZONE_STATUS, &[1]).status,
            ZclStatus::MalformedCommand
        );
    }

    #[test]
    fn arm_validates_the_code_and_tracks_the_panel() {
        let mut c = cie();
        let o = arm(&mut c, arm_mode::ALL, b"0000");
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[arm_notification::INVALID_CODE]
        );
        assert_eq!(o.request, None);
        let o = arm(&mut c, arm_mode::DISARM, b"1234");
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[arm_notification::ALREADY_DISARMED]
        );
        set_ready(&mut c, false);
        let o = arm(&mut c, arm_mode::ALL, b"1234");
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[arm_notification::NOT_READY_TO_ARM]
        );
        set_ready(&mut c, true);
        let o = arm(&mut c, arm_mode::NIGHT_SLEEP, b"1234");
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[arm_notification::NIGHT_SLEEP_ARMED]
        );
        assert_eq!(
            o.request,
            Some(Request::Arm {
                mode: arm_mode::NIGHT_SLEEP,
                zone_id: 0xff
            })
        );
        assert_eq!(panel(&c).unwrap().status, panel_status::ARMED_NIGHT);
        assert_eq!(
            handle(&mut c, CMD_ARM, &[9, 0, 0xff]).status,
            ZclStatus::InvalidField
        );
        // A code-less panel accepts an empty code.
        let mut open: ClusterInstance<36> = server(None);
        let o = arm(&mut open, arm_mode::ALL, &[]);
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[arm_notification::ALL_ZONES_ARMED]
        );
    }

    #[test]
    fn bypass_results_and_the_list_cleared_on_disarm() {
        let mut c = cie();
        let mut buf = [0u8; 16];
        let n = encode_bypass(&[1, 2, 5, 0xff], b"1234", &mut buf).unwrap();
        let o = handle(&mut c, CMD_BYPASS, &buf[..n]);
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[
                4,
                bypass_result::BYPASSED,
                bypass_result::NOT_ALLOWED,
                bypass_result::UNKNOWN_ZONE_ID,
                bypass_result::INVALID_ZONE_ID
            ]
        );
        let n = encode_bypass(&[0], b"9999", &mut buf).unwrap();
        let o = handle(&mut c, CMD_BYPASS, &buf[..n]);
        assert_eq!(
            o.response.unwrap().payload.as_slice(),
            &[1, bypass_result::INVALID_CODE]
        );
        let o = handle(&mut c, CMD_GET_BYPASSED_ZONE_LIST, &[]);
        let f = o.response.unwrap();
        assert_eq!(f.command, CMD_SET_BYPASSED_ZONE_LIST);
        assert_eq!(f.payload.as_slice(), &[1, 1]);
        arm(&mut c, arm_mode::ALL, b"1234");
        let o = arm(&mut c, arm_mode::DISARM, b"1234");
        assert_eq!(
            o.notify.unwrap().payload.as_slice(),
            &[0],
            "disarming clears the bypass list and announces it"
        );
        assert_eq!(
            o.request,
            Some(Request::Arm {
                mode: 0,
                zone_id: 0xff
            })
        );
    }

    #[test]
    fn emergencies_and_status_changes() {
        let mut c = cie();
        let o = handle(&mut c, CMD_FIRE, &[]);
        assert_eq!(
            (o.status, o.request),
            (ZclStatus::Success, Some(Request::Fire))
        );
        assert_eq!(handle(&mut c, CMD_PANIC, &[]).request, Some(Request::Panic));
        assert_eq!(
            handle(&mut c, CMD_EMERGENCY, &[]).request,
            Some(Request::Emergency)
        );
        let f = set_zone_status(&mut c, 17, 0x0021).unwrap();
        assert_eq!(f.command, CMD_ZONE_STATUS_CHANGED);
        let z = ZoneStatusChanged::parse(&f.payload).unwrap();
        assert_eq!(
            (z.zone_id, z.status, z.audible, z.label),
            (17, 0x0021, 1, &b"door"[..])
        );
        assert_eq!(set_zone_status(&mut c, 9, 1), None);
        let f = set_panel_status(&mut c, panel_status::EXIT_DELAY, 30, alarm_status::NONE).unwrap();
        assert_eq!(f.command, CMD_PANEL_STATUS_CHANGED);
        assert_eq!(f.payload.as_slice(), &[4, 30, 1, 0]);
        assert!(remove_zone(&mut c, 17));
        assert!(!remove_zone(&mut c, 17));
        assert_eq!(panel(&c).unwrap().zones.len(), 3);
    }
}
