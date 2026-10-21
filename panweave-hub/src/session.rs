//! One host connection: bytes in, requests executed, responses and
//! events out — independent of the transport carrying the bytes.
//!
//! The session owns the receive decoder and a bounded transmit queue.
//! Responses always have room: events only enter the queue while one
//! maximal frame stays free, so a host that stops reading loses events
//! (counted, then reported by [`Event::EventsDropped`] once it reads
//! again) but never the answer to its next request. Nothing here blocks:
//! the firmware feeds what the transport has, drains what it can send,
//! and the radio loop runs on.

use heapless::Deque;
use panweave_runtime::Stack;
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::CryptoRng;

use crate::diag::{Category, DiagRecord, Severity, code};
use crate::hub::Hub;
pub use crate::protocol::Access;
use crate::protocol::frame::{FrameDecoder, FrameError, MAX_WIRE};
use crate::protocol::{ErrorCode, Message, ProtocolError, QueueUsage, Request, Response};

/// Counters of one session.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkStats {
    /// Frames received intact.
    pub frames_rx: u32,
    /// Frames queued for transmission.
    pub frames_tx: u32,
    /// Frames rejected for a CRC or COBS error.
    pub corrupt: u32,
    /// Frames rejected for their size.
    pub oversize: u32,
    /// Frames that were not a decodable request.
    pub malformed: u32,
    /// Requests refused for lack of access.
    pub unauthorized: u32,
    /// Responses dropped for lack of room.
    pub responses_dropped: u32,
    /// Bytes discarded from the transmit queue (host gone).
    pub discarded: u32,
    /// Times the transmit queue was discarded.
    pub discard_events: u32,
    /// Most octets ever queued for transmission.
    pub tx_high_water: u32,
}

/// A host session with a transmit queue of `TX` octets.
pub struct Session<const TX: usize = 4096> {
    decoder: FrameDecoder,
    tx: Deque<u8, TX>,
    access: Access,
    next_event: u16,
    /// Counters.
    pub stats: LinkStats,
}

impl<const TX: usize> core::fmt::Debug for Session<TX> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("access", &self.access)
            .field("tx", &self.tx.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<const TX: usize> Session<TX> {
    /// A session granted `access`. The transport decides: a wired local
    /// link (USB) is trusted with [`Access::Admin`]; a transport anyone
    /// in radio range can reach must start at [`Access::Monitor`] and
    /// raise it only after authenticating the peer.
    pub const fn new(access: Access) -> Self {
        Session {
            decoder: FrameDecoder::new(),
            tx: Deque::new(),
            access,
            next_event: 0,
            stats: LinkStats {
                frames_rx: 0,
                frames_tx: 0,
                corrupt: 0,
                oversize: 0,
                malformed: 0,
                unauthorized: 0,
                responses_dropped: 0,
                discarded: 0,
                discard_events: 0,
                tx_high_water: 0,
            },
        }
    }

    /// The access granted.
    pub const fn access(&self) -> Access {
        self.access
    }

    /// Feeds received bytes: every complete frame is decoded and, when a
    /// request, executed. Returns the number of requests handled.
    pub fn receive<C: BlockCipher, R: CryptoRng, S: Storage, HS: Storage>(
        &mut self,
        bytes: &[u8],
        hub: &mut Hub<HS>,
        stack: &mut Stack<C, R, S>,
    ) -> usize {
        let mut handled = 0;
        let mut body = [0u8; crate::protocol::frame::MAX_BODY];
        for &b in bytes {
            let n = match self.decoder.push(b) {
                None => continue,
                Some(Ok(frame)) => {
                    let n = frame.len().min(body.len());
                    body[..n].copy_from_slice(&frame[..n]);
                    n
                }
                Some(Err(FrameError::TooLarge)) => {
                    self.stats.oversize += 1;
                    hub.log(DiagRecord::new(
                        Category::Usb,
                        Severity::Warning,
                        code::USB_FRAME_OVERSIZE,
                    ));
                    continue;
                }
                Some(Err(_)) => {
                    self.stats.corrupt += 1;
                    hub.log(DiagRecord::new(
                        Category::Usb,
                        Severity::Warning,
                        code::USB_FRAME_CORRUPT,
                    ));
                    continue;
                }
            };
            self.stats.frames_rx += 1;
            if self.on_body(&body[..n], hub, stack) {
                handled += 1;
            }
        }
        handled
    }

    fn on_body<C: BlockCipher, R: CryptoRng, S: Storage, HS: Storage>(
        &mut self,
        body: &[u8],
        hub: &mut Hub<HS>,
        stack: &mut Stack<C, R, S>,
    ) -> bool {
        match Message::decode(body) {
            Ok(Message::Request { id, request }) => {
                let response = if request.required_access() > self.access {
                    self.stats.unauthorized += 1;
                    hub.log(
                        DiagRecord::new(Category::Usb, Severity::Warning, code::USB_UNAUTHORIZED)
                            .arg(u32::from(id)),
                    );
                    Response::Error(ErrorCode::Unauthorized)
                } else {
                    let mut r = hub.handle(stack, &request);
                    if let (Request::GetDiagnostics, Response::Diagnostics(d)) = (&request, &mut r)
                    {
                        d.frames_rx = self.stats.frames_rx;
                        d.frames_tx = self.stats.frames_tx;
                        d.frames_corrupt = self.stats.corrupt;
                        d.frames_oversize = self.stats.oversize;
                        d.frames_malformed = self.stats.malformed;
                        d.unauthorized = self.stats.unauthorized;
                        d.responses_dropped = self.stats.responses_dropped;
                    }
                    if let (Request::GetRuntimeDiagnostics, Response::RuntimeDiagnostics(d)) =
                        (&request, &mut r)
                    {
                        d.session_tx = QueueUsage {
                            len: u16::try_from(self.tx.len()).unwrap_or(u16::MAX),
                            capacity: u16::try_from(TX).unwrap_or(u16::MAX),
                            high_water: u16::try_from(self.stats.tx_high_water).unwrap_or(u16::MAX),
                        };
                        d.usb_discards = self.stats.discard_events;
                    }
                    r
                };
                if !self.respond(id, response) {
                    hub.log(DiagRecord::new(
                        Category::Usb,
                        Severity::Error,
                        code::USB_RESPONSE_DROPPED,
                    ));
                }
                true
            }
            Ok(_) => {
                // Hosts send requests only.
                self.stats.malformed += 1;
                hub.log(
                    DiagRecord::new(Category::Usb, Severity::Warning, code::USB_REQUEST_REJECTED)
                        .status(ErrorCode::Malformed.code()),
                );
                false
            }
            Err(e) => {
                self.stats.malformed += 1;
                let (id, code) = match e {
                    ProtocolError::UnsupportedVersion { id, .. } => {
                        (id, ErrorCode::UnsupportedVersion)
                    }
                    ProtocolError::UnknownTag(_) => {
                        (Message::request_id(body), ErrorCode::UnknownRequest)
                    }
                    _ => (Message::request_id(body), ErrorCode::Malformed),
                };
                hub.log(
                    DiagRecord::new(Category::Usb, Severity::Warning, code::USB_REQUEST_REJECTED)
                        .status(code.code()),
                );
                if let Some(id) = id {
                    self.respond(id, Response::Error(code));
                }
                false
            }
        }
    }

    fn enqueue(&mut self, frame: &[u8]) -> bool {
        if TX - self.tx.len() < frame.len() {
            return false;
        }
        for &b in frame {
            let _ = self.tx.push_back(b);
        }
        self.stats.frames_tx += 1;
        let queued = u32::try_from(self.tx.len()).unwrap_or(u32::MAX);
        self.stats.tx_high_water = self.stats.tx_high_water.max(queued);
        true
    }

    /// Queues a response; `false` when it had to be dropped.
    fn respond(&mut self, id: u16, response: Response) -> bool {
        let mut wire = [0u8; MAX_WIRE];
        let msg = Message::Response { id, response };
        let n = match msg.encode_frame(&mut wire) {
            Ok(n) => n,
            Err(_) => {
                // Cannot happen with the bounded types; answer anyway.
                let fallback = Message::Response {
                    id,
                    response: Response::Error(ErrorCode::Busy),
                };
                fallback.encode_frame(&mut wire).unwrap_or(0)
            }
        };
        if !self.enqueue(&wire[..n]) {
            self.stats.responses_dropped += 1;
            return false;
        }
        true
    }

    /// Moves hub events into the transmit queue while room remains for a
    /// response; returns the number moved.
    pub fn pump_events<HS: Storage>(&mut self, hub: &mut Hub<HS>) -> usize {
        let mut moved = 0;
        let mut wire = [0u8; MAX_WIRE];
        while let Some(event) = hub.peek_event() {
            let msg = Message::Event {
                seq: self.next_event,
                event: event.clone(),
            };
            let Ok(n) = msg.encode_frame(&mut wire) else {
                // Unencodable (cannot happen with the bounded types): drop.
                let _ = hub.next_event();
                continue;
            };
            if TX - self.tx.len() < n + MAX_WIRE {
                break;
            }
            let _ = hub.next_event();
            self.enqueue(&wire[..n]);
            self.next_event = self.next_event.wrapping_add(1);
            moved += 1;
        }
        moved
    }

    /// Octets waiting for the transport.
    pub fn tx_len(&self) -> usize {
        self.tx.len()
    }

    /// Hands queued octets to `write` until it refuses one; returns the
    /// number written.
    pub fn transmit(&mut self, mut write: impl FnMut(u8) -> bool) -> usize {
        let mut n = 0;
        while let Some(&b) = self.tx.front() {
            if !write(b) {
                break;
            }
            let _ = self.tx.pop_front();
            n += 1;
        }
        n
    }

    /// Drops everything queued (the host went away); a reconnecting host
    /// then starts at a frame boundary. Returns the octets dropped.
    pub fn discard_tx(&mut self) -> usize {
        let n = self.tx.len();
        if n > 0 {
            self.stats.discard_events = self.stats.discard_events.saturating_add(1);
        }
        self.stats.discarded = self
            .stats
            .discarded
            .saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
        self.tx.clear();
        n
    }

    /// Forgets a partially received frame (after a transport reset).
    pub fn reset_rx(&mut self) {
        self.decoder.reset();
    }
}
