//! Events cluster (SE 1.4a Annex D.11): PublishEvent, GetEventLog /
//! PublishEventLog paging, ClearEventLog request / response codecs and a
//! bounded server-side [`Log`] keeping the five logs of Table D-186 with
//! most-recent-first retrieval, filtering by log, event id and time
//! window, offset paging and per-log clear permissions.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use panweave_zcl::cluster::ClusterDef;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0709);

/// Server → client: PublishEvent.
pub const CMD_PUBLISH_EVENT: CommandId = CommandId(0x00);
/// Server → client: PublishEventLog.
pub const CMD_PUBLISH_EVENT_LOG: CommandId = CommandId(0x01);
/// Server → client: ClearEventLogResponse.
pub const CMD_CLEAR_EVENT_LOG_RESPONSE: CommandId = CommandId(0x02);
/// Client → server: GetEventLog.
pub const CMD_GET_EVENT_LOG: CommandId = CommandId(0x00);
/// Client → server: ClearEventLogRequest.
pub const CMD_CLEAR_EVENT_LOG_REQUEST: CommandId = CommandId(0x01);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_GET_EVENT_LOG, CMD_CLEAR_EVENT_LOG_REQUEST],
    generated: &[
        CMD_PUBLISH_EVENT,
        CMD_PUBLISH_EVENT_LOG,
        CMD_CLEAR_EVENT_LOG_RESPONSE,
    ],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

/// Log identifiers (Table D-186).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum LogId {
    /// Tamper log.
    Tamper = 1,
    /// Fault log.
    Fault = 2,
    /// General event log.
    General = 3,
    /// Security event log.
    Security = 4,
    /// Network event log.
    Network = 5,
}

impl LogId {
    /// Every log, in identifier order.
    pub const ALL: [LogId; 5] = [
        LogId::Tamper,
        LogId::Fault,
        LogId::General,
        LogId::Security,
        LogId::Network,
    ];

    /// Decodes the low nibble of a Log ID field; `None` for 0 (all
    /// logs) or a reserved value.
    pub const fn from_nibble(v: u8) -> Option<LogId> {
        match v & 0x0f {
            1 => Some(LogId::Tamper),
            2 => Some(LogId::Fault),
            3 => Some(LogId::General),
            4 => Some(LogId::Security),
            5 => Some(LogId::Network),
            _ => None,
        }
    }

    /// The ClearedEventsLogs bit of this log (Table D-191).
    pub const fn cleared_bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// Event Control bit: retrieve full information (Table D-187).
pub const CONTROL_FULL_INFORMATION: u8 = 0x10;
/// Event Action Control bit: report to HAN (Table D-189).
pub const ACTION_REPORT_TO_HAN: u8 = 0x01;
/// Event Action Control bit: report to WAN.
pub const ACTION_REPORT_TO_WAN: u8 = 0x02;
/// ClearedEventsLogs bit: all logs cleared (Table D-191).
pub const CLEARED_ALL: u8 = 0x01;
/// Log Payload Control bit: an event crosses the frame boundary
/// (Table D-190).
pub const PAYLOAD_CROSSES_BOUNDARY: u8 = 0x01;
/// Event ID meaning any event.
pub const ANY_EVENT: u16 = 0x0000;
/// Longest event data kept per entry.
pub const MAX_EVENT_DATA: usize = 16;
/// Wire size of a logged event with `MAX_EVENT_DATA` bytes of data.
const MAX_EVENT_WIRE: usize = 1 + 2 + 4 + 1 + MAX_EVENT_DATA;
/// Payload bytes available to PublishEventLog after its header.
pub const MAX_LOG_PAYLOAD: usize = 4 * MAX_EVENT_WIRE;

/// A logged event.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Event {
    /// The log it belongs to.
    pub log: LogId,
    /// Event identifier (Tables D-176 to D-184).
    pub event_id: u16,
    /// UTC timestamp.
    pub time: u32,
    /// Additional data.
    pub data: Vec<u8, MAX_EVENT_DATA>,
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

/// PublishEvent (D.11.2.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishEvent<'a> {
    /// The log.
    pub log: LogId,
    /// Event identifier.
    pub event_id: u16,
    /// UTC timestamp.
    pub time: u32,
    /// Action control (Table D-189).
    pub control: u8,
    /// Event data.
    pub data: &'a [u8],
}

impl<'a> PublishEvent<'a> {
    /// Parses the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let log =
            LogId::from_nibble(r.u8()?).ok_or(CodecError::Unrepresentable { field: "log id" })?;
        Ok(PublishEvent {
            log,
            event_id: r.u16_le()?,
            time: r.u32_le()?,
            control: r.u8()?,
            data: read_octstr(&mut r)?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.log as u8)?;
        w.u16_le(self.event_id)?;
        w.u32_le(self.time)?;
        w.u8(self.control)?;
        write_octstr(w, self.data)
    }
}

/// GetEventLog (D.11.2.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetEventLog {
    /// The log (`None`: all logs).
    pub log: Option<LogId>,
    /// Whether the full information (event data) is wanted.
    pub full: bool,
    /// Event identifier (`ANY_EVENT` for all).
    pub event_id: u16,
    /// Earliest timestamp (inclusive).
    pub start: u32,
    /// Latest timestamp (exclusive).
    pub end: u32,
    /// Events wanted (0: all).
    pub count: u8,
    /// Events to skip, most recent first.
    pub offset: u16,
}

impl GetEventLog {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let control = r.u8()?;
        Ok(GetEventLog {
            log: LogId::from_nibble(control),
            full: control & CONTROL_FULL_INFORMATION != 0,
            event_id: r.u16_le()?,
            start: r.u32_le()?,
            end: r.u32_le()?,
            count: r.u8()?,
            offset: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let control = self.log.map_or(0, |l| l as u8)
            | if self.full {
                CONTROL_FULL_INFORMATION
            } else {
                0
            };
        w.u8(control)?;
        w.u16_le(self.event_id)?;
        w.u32_le(self.start)?;
        w.u32_le(self.end)?;
        w.u8(self.count)?;
        w.u16_le(self.offset)
    }
}

/// PublishEventLog (D.11.2.4.2).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishEventLog {
    /// Events matching the request in total.
    pub total_matching: u16,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// Log payload control (Table D-190).
    pub payload_control: u8,
    /// The events of this command.
    pub events: Vec<Event, 4>,
}

impl PublishEventLog {
    /// Parses the payload (events crossing frame boundaries are not
    /// reassembled; such a fragment fails with a length error).
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let total_matching = r.u16_le()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let control = r.u8()?;
        let count = control >> 4;
        let mut events = Vec::new();
        for _ in 0..count {
            let log = LogId::from_nibble(r.u8()?)
                .ok_or(CodecError::Unrepresentable { field: "log id" })?;
            let event_id = r.u16_le()?;
            let time = r.u32_le()?;
            let data =
                Vec::from_slice(read_octstr(&mut r)?).map_err(|_| CodecError::Unrepresentable {
                    field: "event data",
                })?;
            events
                .push(Event {
                    log,
                    event_id,
                    time,
                    data,
                })
                .map_err(|_| CodecError::Unrepresentable { field: "events" })?;
        }
        Ok(PublishEventLog {
            total_matching,
            command_index,
            total_commands,
            payload_control: control & 0x0f,
            events,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.total_matching)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        let count = u8::try_from(self.events.len())
            .ok()
            .filter(|n| *n < 16)
            .ok_or(CodecError::Unrepresentable { field: "events" })?;
        w.u8((count << 4) | (self.payload_control & 0x0f))?;
        for e in &self.events {
            w.u8(e.log as u8)?;
            w.u16_le(e.event_id)?;
            w.u32_le(e.time)?;
            write_octstr(w, &e.data)?;
        }
        Ok(())
    }
}

/// ClearEventLogRequest (D.11.2.3.2): the log to clear (`None`: all).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClearEventLogRequest {
    /// The log (`None`: all logs).
    pub log: Option<LogId>,
}

impl ClearEventLogRequest {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ClearEventLogRequest {
            log: LogId::from_nibble(r.u8()?),
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.log.map_or(0, |l| l as u8))
    }
}

/// ClearEventLogResponse (D.11.2.4.3): the ClearedEventsLogs bitmap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClearEventLogResponse {
    /// Cleared logs (Table D-191).
    pub cleared: u8,
}

impl ClearEventLogResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ClearEventLogResponse { cleared: r.u8()? })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.cleared)
    }

    /// Whether `log` was cleared.
    pub const fn contains(&self, log: LogId) -> bool {
        self.cleared & (CLEARED_ALL | log.cleared_bit()) != 0
    }
}

/// Server-side event log: one ring of `N` entries shared by the five
/// logs, oldest evicted first.
#[derive(Clone, Debug)]
pub struct Log<const N: usize> {
    events: Vec<Event, N>,
    /// Logs a client may clear (Table D-191 bits 1–5).
    pub clearable: u8,
}

impl<const N: usize> Default for Log<N> {
    fn default() -> Self {
        Log {
            events: Vec::new(),
            clearable: LogId::ALL.iter().fold(0, |acc, l| acc | l.cleared_bit()),
        }
    }
}

impl<const N: usize> Log<N> {
    /// An empty log where every log may be cleared.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an event, evicting the oldest when full. Publishing it to
    /// bound clients (`ACTION_REPORT_TO_HAN`) is the caller's decision
    /// per the Device Management event configuration.
    pub fn record(&mut self, event: Event) {
        if self.events.is_full() {
            self.events.remove(0);
        }
        let _ = self.events.push(event);
    }

    /// Recorded events, oldest first.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    fn matches(e: &Event, q: &GetEventLog) -> bool {
        q.log.is_none_or(|l| l == e.log)
            && (q.event_id == ANY_EVENT || q.event_id == e.event_id)
            && e.time >= q.start
            && e.time < q.end
    }

    /// Answers a GetEventLog: the matching events most recent first,
    /// skipping `offset` and returning at most `count` (0: all), split
    /// into as many PublishEventLog commands as fit `MAX_LOG_PAYLOAD`
    /// bytes each. `None` when nothing matches (→ NOT_FOUND).
    pub fn query(&self, q: &GetEventLog, out: &mut Vec<PublishEventLog, 8>) -> Option<()> {
        let matching = self.events.iter().rev().filter(|e| Self::matches(e, q));
        let total = matching.clone().count();
        if total == 0 {
            return None;
        }
        let limit = if q.count == 0 {
            usize::MAX
        } else {
            usize::from(q.count)
        };
        let mut pages: Vec<Vec<Event, 4>, 8> = Vec::new();
        let mut used = 0usize;
        for e in matching.skip(usize::from(q.offset)).take(limit) {
            let data: Vec<u8, MAX_EVENT_DATA> = if q.full { e.data.clone() } else { Vec::new() };
            let size = 1 + 2 + 4 + 1 + data.len();
            let entry = Event {
                log: e.log,
                event_id: e.event_id,
                time: e.time,
                data,
            };
            let fits = pages
                .last()
                .is_some_and(|p| !p.is_full() && used + size <= MAX_LOG_PAYLOAD);
            if !fits {
                if pages.push(Vec::new()).is_err() {
                    break;
                }
                used = 0;
            }
            let _ = pages.last_mut().and_then(|p| p.push(entry).ok());
            used += size;
        }
        let total_commands = u8::try_from(pages.len()).unwrap_or(u8::MAX);
        for (i, events) in pages.into_iter().enumerate() {
            let _ = out.push(PublishEventLog {
                total_matching: u16::try_from(total).unwrap_or(u16::MAX),
                command_index: u8::try_from(i).unwrap_or(u8::MAX),
                total_commands,
                payload_control: 0,
                events,
            });
        }
        Some(())
    }

    /// Clears the requested logs where permitted and reports which were
    /// cleared.
    pub fn clear(&mut self, req: &ClearEventLogRequest) -> ClearEventLogResponse {
        let wanted: u8 = match req.log {
            Some(l) => l.cleared_bit(),
            None => LogId::ALL.iter().fold(0, |acc, l| acc | l.cleared_bit()),
        };
        let cleared = wanted & self.clearable;
        self.events.retain(|e| cleared & e.log.cleared_bit() == 0);
        let all = LogId::ALL.iter().all(|l| cleared & l.cleared_bit() != 0);
        ClearEventLogResponse {
            cleared: cleared | if all { CLEARED_ALL } else { 0 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(log: LogId, id: u16, time: u32, data: &[u8]) -> Event {
        Event {
            log,
            event_id: id,
            time,
            data: Vec::from_slice(data).unwrap(),
        }
    }

    #[test]
    fn codecs_round_trip() {
        let mut buf = [0u8; 128];
        let p = PublishEvent {
            log: LogId::Security,
            event_id: 0x1111,
            time: 1000,
            control: ACTION_REPORT_TO_HAN,
            data: b"ab",
        };
        let mut w = Writer::new(&mut buf);
        p.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(
            &buf[..n],
            &[0x04, 0x11, 0x11, 0xe8, 3, 0, 0, 0x01, 2, b'a', b'b']
        );
        assert_eq!(PublishEvent::parse(&buf[..n]).unwrap(), p);

        let g = GetEventLog {
            log: Some(LogId::Tamper),
            full: true,
            event_id: ANY_EVENT,
            start: 0,
            end: u32::MAX,
            count: 2,
            offset: 3,
        };
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(buf[0], 0x11);
        assert_eq!(GetEventLog::parse(&buf[..n]).unwrap(), g);
        assert_eq!(GetEventLog::parse(&[0x00; 14]).unwrap().log, None);

        let mut events = Vec::new();
        events.push(ev(LogId::Fault, 7, 5, b"x")).unwrap();
        events.push(ev(LogId::General, 8, 4, b"")).unwrap();
        let l = PublishEventLog {
            total_matching: 9,
            command_index: 1,
            total_commands: 2,
            payload_control: 0,
            events,
        };
        let mut w = Writer::new(&mut buf);
        l.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(buf[4], 0x20);
        assert_eq!(PublishEventLog::parse(&buf[..n]).unwrap(), l);

        let mut w = Writer::new(&mut buf);
        ClearEventLogRequest { log: None }.encode(&mut w).unwrap();
        assert_eq!(ClearEventLogRequest::parse(&buf[..1]).unwrap().log, None);
        let r = ClearEventLogResponse {
            cleared: LogId::Fault.cleared_bit(),
        };
        assert!(r.contains(LogId::Fault) && !r.contains(LogId::Tamper));
        assert!(
            ClearEventLogResponse {
                cleared: CLEARED_ALL
            }
            .contains(LogId::Network)
        );
        assert!(LogId::from_nibble(0x16).is_none());
    }

    #[test]
    fn log_pages_most_recent_first_and_clears_where_allowed() {
        let mut log: Log<6> = Log::new();
        for i in 0..8u32 {
            let l = if i % 2 == 0 {
                LogId::Security
            } else {
                LogId::General
            };
            log.record(ev(l, 0x1000 + u16::try_from(i).unwrap(), 100 + i, b"data"));
        }
        // Ring kept the last six (times 102..107).
        assert_eq!(log.events().len(), 6);
        assert_eq!(log.events()[0].time, 102);
        let mut out = Vec::new();
        let q = GetEventLog {
            log: Some(LogId::Security),
            full: false,
            event_id: ANY_EVENT,
            start: 0,
            end: 107,
            count: 1,
            offset: 0,
        };
        assert!(log.query(&q, &mut out).is_some());
        let page = &out[0];
        // Security events at 102, 104, 106 match (107 is excluded by
        // the end time): three total, the most recent first, minimal.
        assert_eq!((page.total_matching, page.total_commands), (3, 1));
        assert_eq!(page.events[0].time, 106);
        assert!(page.events[0].data.is_empty());
        out.clear();
        log.query(
            &GetEventLog {
                offset: 1,
                count: 0,
                full: true,
                ..q
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(out[0].events.len(), 2);
        assert_eq!(out[0].events[0].time, 104);
        assert_eq!(&out[0].events[0].data[..], b"data");
        // Specific event id in any log.
        out.clear();
        log.query(
            &GetEventLog {
                log: None,
                event_id: 0x1003,
                end: u32::MAX,
                ..q
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(out[0].events[0].log, LogId::General);
        // Nothing matching.
        out.clear();
        assert!(
            log.query(
                &GetEventLog {
                    log: Some(LogId::Tamper),
                    ..q
                },
                &mut out,
            )
            .is_none()
        );
        // Paging: with everything requested, four events per command.
        out.clear();
        log.query(
            &GetEventLog {
                log: None,
                end: u32::MAX,
                count: 0,
                full: true,
                ..q
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].events.len(), out[1].events.len()), (4, 2));
        assert_eq!((out[1].command_index, out[1].total_commands), (1, 2));
        // Clearing: Security may not be cleared by policy.
        log.clearable &= !LogId::Security.cleared_bit();
        let r = log.clear(&ClearEventLogRequest { log: None });
        assert!(r.contains(LogId::General) && !r.contains(LogId::Security));
        assert_eq!(r.cleared & CLEARED_ALL, 0);
        assert!(log.events().iter().all(|e| e.log == LogId::Security));
        let r = log.clear(&ClearEventLogRequest {
            log: Some(LogId::Security),
        });
        assert_eq!(r.cleared, 0);
        assert_eq!(log.events().len(), 3);
        log.clearable = u8::MAX;
        assert_eq!(
            log.clear(&ClearEventLogRequest { log: None }).cleared & CLEARED_ALL,
            CLEARED_ALL
        );
        assert!(log.events().is_empty());
    }
}
