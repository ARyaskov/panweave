//! Alarms cluster (ZCL8 §3.11): the alarm table, the Reset Alarm /
//! Reset All Alarms / Get Alarm / Reset Alarm Log commands received by
//! the server and the Alarm / Get Alarm Response commands it generates.
//! Alarm conditions themselves belong to the clusters that define them
//! (Power Configuration thresholds, …); they raise an alarm through the
//! dispatcher, which logs it here and notifies the bound clients.

use heapless::Vec;
use panweave_codec::{Reader, Writer};
use panweave_types::{AttributeId, ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0009);
/// `AlarmCount` (uint16).
pub const ALARM_COUNT: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(2), Access::RO);

/// Reset Alarm (received).
pub const CMD_RESET_ALARM: CommandId = CommandId(0x00);
/// Reset All Alarms (received).
pub const CMD_RESET_ALL_ALARMS: CommandId = CommandId(0x01);
/// Get Alarm (received).
pub const CMD_GET_ALARM: CommandId = CommandId(0x02);
/// Reset Alarm Log (received).
pub const CMD_RESET_ALARM_LOG: CommandId = CommandId(0x03);
/// Alarm (generated).
pub const CMD_ALARM: CommandId = CommandId(0x00);
/// Get Alarm Response (generated).
pub const CMD_GET_ALARM_RESPONSE: CommandId = CommandId(0x01);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_RESET_ALARM,
        CMD_RESET_ALL_ALARMS,
        CMD_GET_ALARM,
        CMD_RESET_ALARM_LOG,
    ],
    generated: &[CMD_ALARM, CMD_GET_ALARM_RESPONSE],
};

/// Entries the alarm table holds.
pub const TABLE_SIZE: usize = 8;
/// Time stamp when no time information is available.
pub const NO_TIME: u32 = 0xffff_ffff;

/// An alarm table entry (Table 3-66).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Entry {
    /// Alarm code of the originating cluster.
    pub code: u8,
    /// The originating cluster.
    pub cluster: ClusterId,
    /// UTC time of the alarm, or [`NO_TIME`].
    pub time: u32,
}

/// The alarm table, oldest entry first.
#[derive(Clone, Debug, Default)]
pub struct Table {
    entries: Vec<Entry, TABLE_SIZE>,
}

impl Table {
    /// Logs an alarm; when full the earliest entry is replaced.
    pub fn log(&mut self, e: Entry) {
        if self.entries.is_full() {
            self.entries.remove(0);
        }
        let _ = self.entries.push(e);
    }

    /// Removes and returns the earliest entry.
    pub fn pop_earliest(&mut self) -> Option<Entry> {
        if self.entries.is_empty() {
            None
        } else {
            Some(self.entries.remove(0))
        }
    }

    /// Clears the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Entries, oldest first.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

/// Builds a server instance with an (empty) alarm table.
pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(ALARM_COUNT, &Value::Uint { width: 2, value: 0 })?;
    c.state = ClusterState::Alarms(Table::default());
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

fn table<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut Table> {
    match &mut c.state {
        ClusterState::Alarms(t) => Some(t),
        _ => None,
    }
}

fn update_count<const A: usize>(c: &mut ClusterInstance<A>) {
    let n = match &c.state {
        ClusterState::Alarms(t) => t.entries().len(),
        _ => 0,
    };
    c.set_u16(ALARM_COUNT.id, u16::try_from(n).unwrap_or(u16::MAX));
}

/// Logs an alarm in the table (§3.11.2.3) and returns the Alarm command
/// payload to send to the bound clients.
pub fn log<const A: usize>(c: &mut ClusterInstance<A>, entry: Entry) -> [u8; 3] {
    if let Some(t) = table(c) {
        t.log(entry);
    }
    update_count(c);
    let id = entry.cluster.0.to_le_bytes();
    [entry.code, id[0], id[1]]
}

/// Logged entries, oldest first.
pub fn entries<const A: usize>(c: &ClusterInstance<A>) -> &[Entry] {
    match &c.state {
        ClusterState::Alarms(t) => t.entries(),
        _ => &[],
    }
}

/// Result of a received server command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Reset Alarm: the application clears the condition (`None` for
    /// Reset All Alarms). A Default Response applies.
    Reset(Option<(u8, ClusterId)>),
    /// Get Alarm: unicast a Get Alarm Response with this payload length.
    Response(usize),
    /// The log was cleared; a Default Response applies.
    LogCleared,
    /// Unknown command.
    Unsupported,
    /// Malformed payload.
    Malformed,
}

/// Handles a received server command; a Get Alarm Response is written
/// to `out` (§3.11.2.5.2).
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
    out: &mut [u8],
) -> Outcome {
    match cmd {
        CMD_RESET_ALARM => {
            let mut r = Reader::new(payload);
            match (r.u8(), r.u16_le()) {
                (Ok(code), Ok(cluster)) => Outcome::Reset(Some((code, ClusterId(cluster)))),
                _ => Outcome::Malformed,
            }
        }
        CMD_RESET_ALL_ALARMS => Outcome::Reset(None),
        CMD_GET_ALARM => {
            let earliest = table(c).and_then(Table::pop_earliest);
            update_count(c);
            let mut w = Writer::new(out);
            let written = match earliest {
                Some(e) => w
                    .u8(ZclStatus::Success.raw())
                    .and_then(|()| w.u8(e.code))
                    .and_then(|()| w.u16_le(e.cluster.0))
                    .and_then(|()| w.u32_le(e.time)),
                None => w.u8(ZclStatus::NotFound.raw()),
            };
            match written {
                Ok(()) => Outcome::Response(w.position()),
                Err(_) => Outcome::Malformed,
            }
        }
        CMD_RESET_ALARM_LOG => {
            if let Some(t) = table(c) {
                t.clear();
            }
            update_count(c);
            Outcome::LogCleared
        }
        _ => Outcome::Unsupported,
    }
}

/// Alarm command payload (client side).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Alarm {
    /// Alarm code.
    pub code: u8,
    /// Originating cluster.
    pub cluster: ClusterId,
}

impl Alarm {
    /// Parses an Alarm command payload.
    pub fn parse(payload: &[u8]) -> Option<Self> {
        match payload {
            [code, lo, hi] => Some(Alarm {
                code: *code,
                cluster: ClusterId(u16::from_le_bytes([*lo, *hi])),
            }),
            _ => None,
        }
    }
}

/// Parses a Get Alarm Response: `Ok(Some(entry))`, `Ok(None)` for
/// NOT_FOUND, `Err` when malformed.
pub fn parse_get_alarm_response(
    payload: &[u8],
) -> Result<Option<Entry>, panweave_codec::CodecError> {
    let mut r = Reader::new(payload);
    let status = r.u8()?;
    if status == ZclStatus::Success.raw() {
        let code = r.u8()?;
        let cluster = ClusterId(r.u16_le()?);
        let time = r.u32_le()?;
        Ok(Some(Entry {
            code,
            cluster,
            time,
        }))
    } else {
        Ok(None)
    }
}

/// The attribute identifier of `AlarmCount`.
pub const fn alarm_count_id() -> AttributeId {
    ALARM_COUNT.id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_and_commands() {
        let mut c: ClusterInstance<8> = server().unwrap();
        let p = log(
            &mut c,
            Entry {
                code: 0x10,
                cluster: ClusterId(0x0001),
                time: 5000,
            },
        );
        assert_eq!(p, [0x10, 0x01, 0x00]);
        let _ = log(
            &mut c,
            Entry {
                code: 0x11,
                cluster: ClusterId(0x0001),
                time: NO_TIME,
            },
        );
        assert_eq!(c.u16(ALARM_COUNT.id), Some(2));
        let mut out = [0u8; 16];
        assert_eq!(
            handle(&mut c, CMD_GET_ALARM, &[], &mut out),
            Outcome::Response(8)
        );
        assert_eq!(&out[..8], &[0x00, 0x10, 0x01, 0x00, 0x88, 0x13, 0x00, 0x00]);
        assert_eq!(
            parse_get_alarm_response(&out[..8]),
            Ok(Some(Entry {
                code: 0x10,
                cluster: ClusterId(1),
                time: 5000
            }))
        );
        assert_eq!(c.u16(ALARM_COUNT.id), Some(1));
        assert_eq!(
            handle(&mut c, CMD_RESET_ALARM, &[0x11, 0x01, 0x00], &mut out),
            Outcome::Reset(Some((0x11, ClusterId(1))))
        );
        assert_eq!(
            handle(&mut c, CMD_RESET_ALL_ALARMS, &[], &mut out),
            Outcome::Reset(None)
        );
        assert_eq!(
            handle(&mut c, CMD_RESET_ALARM_LOG, &[], &mut out),
            Outcome::LogCleared
        );
        assert_eq!(c.u16(ALARM_COUNT.id), Some(0));
        assert_eq!(
            handle(&mut c, CMD_GET_ALARM, &[], &mut out),
            Outcome::Response(1)
        );
        assert_eq!(out[0], ZclStatus::NotFound.raw());
        assert_eq!(parse_get_alarm_response(&out[..1]), Ok(None));
        // A full table drops the earliest entry.
        for i in 0..=TABLE_SIZE as u8 {
            let _ = log(
                &mut c,
                Entry {
                    code: i,
                    cluster: ClusterId(9),
                    time: NO_TIME,
                },
            );
        }
        assert_eq!(entries(&c).len(), TABLE_SIZE);
        assert_eq!(entries(&c)[0].code, 1);
        assert_eq!(
            Alarm::parse(&[0x3a, 0x01, 0x00]),
            Some(Alarm {
                code: 0x3a,
                cluster: ClusterId(1)
            })
        );
        assert_eq!(
            handle(&mut c, CommandId(0x09), &[], &mut out),
            Outcome::Unsupported
        );
    }
}
