//! Where a notification goes: how the request for the pending events is
//! built and how the answer is read.
//!
//! The hub engine ([`crate::Hub::prepare_alert_with`],
//! [`crate::Hub::finish_alert_with`]) is independent of the destination:
//! it picks the pending events, runs the attempt and updates the queue
//! from the [`Reply`]. An [`Uplink`] supplies the destination's format.
//! [`Telegram`] is the Bot API (`sendMessage`); a firmware may bring its
//! own for an HTTPS notification server
//! ([`AlertDestination::Server`](crate::protocol::AlertDestination)).
//!
//! An uplink for a server that acknowledges events one by one answers
//! [`Acked::Some`]: only those events leave the queue. A server that
//! deduplicates by [`EventId`] makes an ambiguous attempt harmless.

use heapless::Vec;

use super::Config;
use super::message::{self, Sensor};
use super::queue::{AlertEvent, CAPACITY, EventId, Overflow};
use super::telegram;

/// A pending event with what the hub knows about its sensor.
#[derive(Clone, Copy, Debug)]
pub struct Pending<'a> {
    /// The queued event.
    pub event: &'a AlertEvent,
    /// The sensor's name and current state.
    pub sensor: Sensor<'a>,
}

/// Most devices described in one request ([`Context::devices`]).
pub const MAX_DEVICES: usize = 32;

/// A device as the hub sees it when a request is built: what a server
/// keeps as history and watches for silence and flat batteries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceSnapshot<'a> {
    /// IEEE address.
    pub ieee: u64,
    /// Basic `ModelIdentifier` as the device reported it (may hold
    /// control characters).
    pub model: &'a str,
    /// Category name (`water-leak-sensor`, …).
    pub category: &'static str,
    /// On the network (has not left).
    pub present: bool,
    /// Seconds since the device was last heard (`None`: not since the
    /// hub started).
    pub silent_s: Option<u32>,
    /// BatteryPercentageRemaining, percent.
    pub battery_pct: Option<u8>,
    /// BatteryVoltage, millivolts.
    pub battery_mv: Option<u16>,
    /// The device reports its battery as low.
    pub battery_low: bool,
    /// Its state (`leak`, `dry`, `open`, `closed`, `unknown`).
    pub state: &'static str,
    /// A sleepy end device (receiver off when idle).
    pub sleepy: bool,
    /// Link quality from the neighbour table.
    pub lqi: Option<u8>,
}

/// Everything besides the events that a request may need.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// The settings (destination, token, chat, server host).
    pub config: &'a Config,
    /// The current boot's identifier.
    pub boot: u32,
    /// Milliseconds since the current boot started (the clock of
    /// [`AlertEvent::at_ms`] for events of this boot).
    pub uptime_ms: u64,
    /// Events lost to a full queue and not yet reported.
    pub overflow: Overflow,
    /// The firmware version.
    pub firmware: &'a str,
    /// Every registered device (an uplink may send as many as fit; a
    /// destination without history ignores them).
    pub devices: &'a [DeviceSnapshot<'a>],
}

/// A request built into the caller's buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Built {
    /// Its length.
    pub len: usize,
    /// How many of the pending events (from the oldest) it carries.
    pub events: usize,
    /// The overflow losses it reports.
    pub overflow_reported: u32,
}

/// Why no request could be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuildError {
    /// The output buffer is too small.
    TooLong,
    /// A setting cannot be sent as it is.
    InvalidSetting,
}

/// Which events the destination accepted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Acked {
    /// Every event of the request (and its overflow report).
    All,
    /// These events only; the others stay queued.
    Some(Vec<EventId, CAPACITY>),
}

/// What the destination answered.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reply {
    /// Accepted.
    Delivered {
        /// The events it took.
        acked: Acked,
        /// The destination's identifier of what it published, when it
        /// has one (Telegram's `message_id`).
        message_id: Option<i64>,
    },
    /// Rate limited: try again after this many seconds.
    RetryAfter {
        /// Seconds to wait.
        seconds: u32,
    },
    /// Refused for good (credentials, settings): they must be fixed;
    /// events stay queued.
    Rejected,
    /// A server error: retried later.
    ServerError,
    /// Not an answer this uplink understands. The request may have been
    /// processed: an ambiguous outcome.
    Malformed,
}

/// A destination's request format.
pub trait Uplink {
    /// Builds the request for `pending` (oldest first; empty for a
    /// heartbeat) into `out`.
    ///
    /// # Errors
    ///
    /// [`BuildError`].
    fn build(
        &mut self,
        ctx: &Context<'_>,
        pending: &[Pending<'_>],
        out: &mut [u8],
    ) -> Result<Built, BuildError>;

    /// Reads a complete HTTP response; returns its status (when it is
    /// HTTP) and what it means.
    fn parse(&mut self, response: &[u8]) -> (Option<u16>, Reply);

    /// Whether this destination accepts a request without events (a
    /// heartbeat). Telegram does not.
    fn accepts_heartbeat(&self) -> bool {
        false
    }
}

/// The Telegram Bot API: one `sendMessage` with a text listing the events.
#[derive(Clone, Copy, Debug, Default)]
pub struct Telegram;

impl Uplink for Telegram {
    fn build(
        &mut self,
        ctx: &Context<'_>,
        pending: &[Pending<'_>],
        out: &mut [u8],
    ) -> Result<Built, BuildError> {
        if pending.is_empty() {
            return Err(BuildError::InvalidSetting);
        }
        let events: Vec<AlertEvent, CAPACITY> = pending.iter().map(|p| *p.event).collect();
        let composed = message::compose(&events, ctx.overflow, |ieee| {
            pending.iter().find(|p| p.event.ieee == ieee).map_or(
                Sensor {
                    name: "",
                    state: "unknown",
                },
                |p| p.sensor,
            )
        });
        let len =
            telegram::build_request(&ctx.config.token, &ctx.config.chat_id, &composed.text, out)
                .map_err(|e| match e {
                    telegram::BuildError::TooLong => BuildError::TooLong,
                    telegram::BuildError::InvalidSetting => BuildError::InvalidSetting,
                })?;
        Ok(Built {
            len,
            events: composed.events,
            overflow_reported: composed.overflow_reported,
        })
    }

    fn parse(&mut self, response: &[u8]) -> (Option<u16>, Reply) {
        let mut scratch = [0u8; 512];
        let (status, reply) = telegram::parse_response(response, &mut scratch);
        let reply = match reply {
            telegram::Reply::Delivered { message_id } => Reply::Delivered {
                acked: Acked::All,
                message_id: Some(message_id),
            },
            telegram::Reply::RetryAfter { seconds, .. } => Reply::RetryAfter { seconds },
            telegram::Reply::Rejected { .. } => Reply::Rejected,
            telegram::Reply::ServerError { .. } => Reply::ServerError,
            telegram::Reply::Malformed => Reply::Malformed,
        };
        (status, reply)
    }
}

/// Splits a complete HTTP/1.x response into its status and body,
/// de-chunking a chunked body into `scratch`. `None` when it is not an
/// HTTP response or is cut short. For uplinks of other destinations.
pub fn http_body<'a>(response: &'a [u8], scratch: &'a mut [u8]) -> Option<(u16, &'a [u8])> {
    let status = response
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| response.strip_prefix(b"HTTP/1.0 "))
        .and_then(|r| r.get(..3))
        .and_then(|d| core::str::from_utf8(d).ok())
        .and_then(|d| d.parse::<u16>().ok())?;
    let head_end = telegram::find(response, b"\r\n\r\n")?;
    let head = &response[..head_end];
    let body = &response[head_end + 4..];
    let mut length = None;
    let mut chunked = false;
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"content-length") {
            length = core::str::from_utf8(value)
                .ok()
                .and_then(|v| v.parse::<usize>().ok());
        } else if name.eq_ignore_ascii_case(b"transfer-encoding")
            && value.eq_ignore_ascii_case(b"chunked")
        {
            chunked = true;
        }
    }
    if chunked {
        let n = telegram::dechunk(body, scratch)?;
        return Some((status, &scratch[..n]));
    }
    match length {
        Some(n) => Some((status, body.get(..n)?)),
        None => Some((status, body)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AlertKind;

    #[test]
    fn http_bodies_by_length_and_chunked() {
        let mut s = [0u8; 64];
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(http_body(r, &mut s), Some((200, b"hello".as_slice())));
        let mut s = [0u8; 64];
        let r = b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(http_body(r, &mut s), Some((201, b"abcde".as_slice())));
        let mut s = [0u8; 64];
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort";
        assert_eq!(http_body(r, &mut s), None, "cut short");
        let mut s = [0u8; 64];
        assert_eq!(http_body(b"garbage", &mut s), None);
    }

    #[test]
    fn telegram_needs_events_and_reads_a_message_id() {
        let mut config = Config::default();
        config.token = crate::protocol::Text::from_slice(b"1:abc").unwrap();
        config.chat_id = crate::protocol::Text::from_slice(b"-100").unwrap();
        let ctx = Context {
            config: &config,
            boot: 1,
            uptime_ms: 10_000,
            overflow: Overflow::default(),
            firmware: "0",
            devices: &[],
        };
        let mut out = [0u8; 2048];
        assert_eq!(
            Telegram.build(&ctx, &[], &mut out),
            Err(BuildError::InvalidSetting)
        );
        let e = AlertEvent {
            id: EventId { boot: 1, seq: 1 },
            kind: AlertKind::WaterLeak,
            ieee: 1,
            zone_status: Some(1),
            at_ms: 9_000,
            attempts: 0,
            ambiguous: false,
        };
        let p = [Pending {
            event: &e,
            sensor: Sensor {
                name: "bath",
                state: "leak",
            },
        }];
        let built = Telegram.build(&ctx, &p, &mut out).unwrap();
        assert_eq!(built.events, 1);
        assert!(out[..built.len].starts_with(b"POST /bot1:abc/sendMessage"));

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 39\r\n\r\n{\"ok\":true,\"result\":{\"message_id\":77}}";
        assert_eq!(
            Telegram.parse(resp),
            (
                Some(200),
                Reply::Delivered {
                    acked: Acked::All,
                    message_id: Some(77)
                }
            )
        );
        assert!(!Telegram.accepts_heartbeat());
    }
}
