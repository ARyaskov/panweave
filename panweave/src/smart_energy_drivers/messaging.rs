//! Messaging cluster drivers (SE 1.4a Annex D.5): the client (In-Home
//! Display and the like) holding the single current message, and the
//! server (ESI) publishing messages and gathering confirmations.

use heapless::Vec;
use panweave_aps::layer::Destination;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_smart_energy::clusters::messaging::{
    self, CancelMessage, Display, DisplayMessage, ImplementationTime,
    MAX_CONFIRMATION_RESPONSE_LEN, MessageConfirmation, Outcome, Server, message_control,
};
use panweave_storage::Storage;
use panweave_types::time::Instant;
use panweave_types::{CryptoRng, Endpoint, ShortAddress};
use panweave_zcl::ZclStatus;
use panweave_zcl::frame::Direction;

use super::{UtcClock, command_for, default_response, reply, send, utc_now};

/// What a [`MessagingClient`] reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessagingEvent {
    /// A message arrived (render [`MessagingClient::display`]).
    Displayed {
        /// Message ID.
        message_id: u32,
        /// Display Protected Message (PIN protected).
        protected: bool,
        /// New, or the known message updated.
        outcome: Outcome,
    },
    /// The current message is gone (cancelled, cancelled for all,
    /// expired, or none was current on Get Last Message).
    Cleared,
}

/// The client driver on `endpoint`.
pub struct MessagingClient {
    endpoint: Endpoint,
    /// The current message.
    pub display: Display,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
    pending_cancel_all: Option<u32>,
}

impl MessagingClient {
    /// A client with no message.
    pub const fn new(endpoint: Endpoint) -> Self {
        MessagingClient {
            endpoint,
            display: Display::new(),
            clock: UtcClock::new(),
            pending_cancel_all: None,
        }
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<MessagingEvent> {
        let (origin, payload) =
            command_for(event, self.endpoint, messaging::ID, Direction::ToClient)?;
        let origin = *origin;
        let now = utc_now(stack, self.endpoint, &self.clock);
        match origin.header.command {
            messaging::CMD_DISPLAY_MESSAGE | messaging::CMD_DISPLAY_PROTECTED_MESSAGE => {
                let protected = origin.header.command == messaging::CMD_DISPLAY_PROTECTED_MESSAGE;
                let Ok(m) = DisplayMessage::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                // D.5.2.3.1.1.1: inter-PAN-only messages are refused.
                if m.message_control & message_control::TRANSMISSION_MASK
                    == message_control::TRANSMISSION_INTER_PAN_ONLY
                {
                    default_response(stack, &origin, ZclStatus::InvalidField);
                    return None;
                }
                let outcome = self.display.on_display(&m, protected, now);
                default_response(
                    stack,
                    &origin,
                    if outcome == Outcome::TooLong {
                        ZclStatus::InsufficientSpace
                    } else {
                        ZclStatus::Success
                    },
                );
                (outcome != Outcome::TooLong).then_some(MessagingEvent::Displayed {
                    message_id: m.message_id,
                    protected,
                    outcome,
                })
            }
            messaging::CMD_CANCEL_MESSAGE => {
                let Ok(c) = CancelMessage::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let cleared = self.display.on_cancel(&c);
                default_response(
                    stack,
                    &origin,
                    if cleared {
                        ZclStatus::Success
                    } else {
                        ZclStatus::NotFound
                    },
                );
                cleared.then_some(MessagingEvent::Cleared)
            }
            messaging::CMD_CANCEL_ALL_MESSAGES => {
                let Ok(t) = ImplementationTime::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                default_response(stack, &origin, ZclStatus::Success);
                let at = if t.time == 0 { now } else { t.time };
                if self.display.on_cancel_all(at, now) {
                    self.pending_cancel_all = None;
                    Some(MessagingEvent::Cleared)
                } else {
                    if self.display.current().is_some() {
                        self.pending_cancel_all = Some(at);
                    }
                    None
                }
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }

    /// Drops an expired message or one whose Cancel All Messages time
    /// came.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        _now: Instant,
    ) -> Option<MessagingEvent> {
        let now = utc_now(stack, self.endpoint, &self.clock);
        if let Some(at) = self.pending_cancel_all
            && self.display.on_cancel_all(at, now)
        {
            self.pending_cancel_all = None;
            return Some(MessagingEvent::Cleared);
        }
        self.display.poll(now).then_some(MessagingEvent::Cleared)
    }

    /// Asks the server for its current message (Get Last Message); the
    /// answer arrives as a Display Message.
    pub fn request_last_message<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        server: Destination,
    ) -> bool {
        send(
            stack,
            self.endpoint,
            server,
            messaging::ID,
            messaging::CMD_GET_LAST_MESSAGE,
            Direction::ToServer,
            &[],
        )
    }

    /// The user confirmed the current message: sends the Message
    /// Confirmation (with `control` / `response` for an enhanced
    /// confirmation). False when no confirmation is due.
    pub fn confirm<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        server: Destination,
        control: u8,
        response: &[u8],
    ) -> bool {
        let now = utc_now(stack, self.endpoint, &self.clock);
        let Some(c) = self.display.confirm(now, control, response) else {
            return false;
        };
        let mut buf = [0u8; 32];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if c.encode(&mut w).is_err() {
            return false;
        }
        let n = w.position();
        send(
            stack,
            self.endpoint,
            server,
            messaging::ID,
            messaging::CMD_MESSAGE_CONFIRMATION,
            Direction::ToServer,
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Asks the server whether a Cancel All Messages is scheduled from
    /// `earliest` on (GetMessageCancellation).
    pub fn request_message_cancellation<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        server: Destination,
        earliest: u32,
    ) -> bool {
        let mut buf = [0u8; 4];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if (ImplementationTime { time: earliest })
            .encode(&mut w)
            .is_err()
        {
            return false;
        }
        send(
            stack,
            self.endpoint,
            server,
            messaging::ID,
            messaging::CMD_GET_MESSAGE_CANCELLATION,
            Direction::ToServer,
            &buf,
        )
    }
}

/// What a [`MessagingServer`] reports.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MessagingServerEvent {
    /// A client confirmed the current message.
    Confirmed {
        /// The client.
        client: ShortAddress,
        /// Message ID.
        message_id: u32,
        /// Confirmation time (UTC seconds).
        time: u32,
        /// Message Confirmation Control (enhanced confirmations).
        control: u8,
        /// Response text (enhanced confirmations).
        response: Vec<u8, MAX_CONFIRMATION_RESPONSE_LEN>,
    },
    /// A client asked for the last message and was answered (or told
    /// NOT_FOUND when `answered` is false).
    LastMessageRequested {
        /// The client.
        client: ShortAddress,
        /// A message was sent.
        answered: bool,
    },
}

/// The server driver on `endpoint`.
pub struct MessagingServer {
    endpoint: Endpoint,
    /// The published message and pending cancellation.
    pub server: Server,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
}

impl MessagingServer {
    /// A server with no message.
    pub const fn new(endpoint: Endpoint) -> Self {
        MessagingServer {
            endpoint,
            server: Server::new(),
            clock: UtcClock::new(),
        }
    }

    fn encode_display(m: &DisplayMessage<'_>) -> Option<Vec<u8, 160>> {
        let mut out: Vec<u8, 160> = Vec::new();
        out.resize(12 + m.message.len() + 1, 0).ok()?;
        let mut w = panweave_codec::Writer::new(&mut out);
        m.encode(&mut w).ok()?;
        let n = w.position();
        out.truncate(n);
        Some(out)
    }

    /// Publishes `m` (a start time of 0 is resolved to now) and sends it
    /// to `clients` as Display Message or Display Protected Message.
    pub fn publish<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        clients: Destination,
        m: &DisplayMessage<'_>,
        protected: bool,
    ) -> bool {
        let now = utc_now(stack, self.endpoint, &self.clock);
        if !self.server.publish(m, protected, now) {
            return false;
        }
        let Some(published) = self.server.last_message(now) else {
            return false;
        };
        let Some(payload) = Self::encode_display(&published.display()) else {
            return false;
        };
        send(
            stack,
            self.endpoint,
            clients,
            messaging::ID,
            if protected {
                messaging::CMD_DISPLAY_PROTECTED_MESSAGE
            } else {
                messaging::CMD_DISPLAY_MESSAGE
            },
            Direction::ToClient,
            &payload,
        )
    }

    /// Cancels the message `message_id` on the server and at `clients`.
    pub fn cancel<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        clients: Destination,
        message_id: u32,
        message_control: u8,
    ) -> bool {
        self.server.cancel(message_id);
        let mut buf = [0u8; 5];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if (CancelMessage {
            message_id,
            message_control,
        })
        .encode(&mut w)
        .is_err()
        {
            return false;
        }
        send(
            stack,
            self.endpoint,
            clients,
            messaging::ID,
            messaging::CMD_CANCEL_MESSAGE,
            Direction::ToClient,
            &buf,
        )
    }

    /// Cancels every message at `implementation_time` (0: now) on the
    /// server and at `clients`.
    pub fn cancel_all<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        clients: Destination,
        implementation_time: u32,
    ) -> bool {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.server.cancel_all(implementation_time, now);
        let mut buf = [0u8; 4];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if (ImplementationTime {
            time: implementation_time,
        })
        .encode(&mut w)
        .is_err()
        {
            return false;
        }
        send(
            stack,
            self.endpoint,
            clients,
            messaging::ID,
            messaging::CMD_CANCEL_ALL_MESSAGES,
            Direction::ToClient,
            &buf,
        )
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<MessagingServerEvent> {
        let (origin, payload) =
            command_for(event, self.endpoint, messaging::ID, Direction::ToServer)?;
        let origin = *origin;
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.server.poll(now);
        match origin.header.command {
            messaging::CMD_GET_LAST_MESSAGE => {
                let answer = self.server.last_message(now).and_then(|p| {
                    Self::encode_display(&p.display()).map(|payload| (p.protected, payload))
                });
                let answered = match answer {
                    Some((protected, payload)) => reply(
                        stack,
                        &origin,
                        if protected {
                            messaging::CMD_DISPLAY_PROTECTED_MESSAGE
                        } else {
                            messaging::CMD_DISPLAY_MESSAGE
                        },
                        &payload,
                    ),
                    None => {
                        default_response(stack, &origin, ZclStatus::NotFound);
                        false
                    }
                };
                Some(MessagingServerEvent::LastMessageRequested {
                    client: origin.src,
                    answered,
                })
            }
            messaging::CMD_MESSAGE_CONFIRMATION => {
                let Ok(c) = MessageConfirmation::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let known = self.server.on_confirmation(origin.src.0, &c);
                default_response(
                    stack,
                    &origin,
                    if known {
                        ZclStatus::Success
                    } else {
                        ZclStatus::NotFound
                    },
                );
                let response = Vec::from_slice(c.response).ok()?;
                known.then_some(MessagingServerEvent::Confirmed {
                    client: origin.src,
                    message_id: c.message_id,
                    time: c.confirmation_time,
                    control: c.control,
                    response,
                })
            }
            messaging::CMD_GET_MESSAGE_CANCELLATION => {
                let Ok(t) = ImplementationTime::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                match self.server.message_cancellation(t.time) {
                    Some(at) => {
                        let mut buf = [0u8; 4];
                        let mut w = panweave_codec::Writer::new(&mut buf);
                        if at.encode(&mut w).is_ok() {
                            reply(stack, &origin, messaging::CMD_CANCEL_ALL_MESSAGES, &buf);
                        }
                    }
                    None => default_response(stack, &origin, ZclStatus::NotFound),
                }
                None
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }

    /// Advances the server's time (a due Cancel All, an expired message).
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        _now: Instant,
    ) {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.server.poll(now);
    }
}
