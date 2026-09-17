//! Messaging cluster (SE 1.4a Annex D.5): Display Message / Cancel
//! Message / Display Protected Message / Cancel All Messages from the
//! server (ESI), Get Last Message / Message Confirmation /
//! GetMessageCancellation from the client, and a client-side message
//! store applying the replacement and confirmation rules of D.5.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use panweave_zcl::cluster::ClusterDef;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0703);

/// Server → client: Display Message.
pub const CMD_DISPLAY_MESSAGE: CommandId = CommandId(0x00);
/// Server → client: Cancel Message.
pub const CMD_CANCEL_MESSAGE: CommandId = CommandId(0x01);
/// Server → client: Display Protected Message.
pub const CMD_DISPLAY_PROTECTED_MESSAGE: CommandId = CommandId(0x02);
/// Server → client: Cancel All Messages (provisional).
pub const CMD_CANCEL_ALL_MESSAGES: CommandId = CommandId(0x03);
/// Client → server: Get Last Message.
pub const CMD_GET_LAST_MESSAGE: CommandId = CommandId(0x00);
/// Client → server: Message Confirmation.
pub const CMD_MESSAGE_CONFIRMATION: CommandId = CommandId(0x01);
/// Client → server: GetMessageCancellation (provisional).
pub const CMD_GET_MESSAGE_CANCELLATION: CommandId = CommandId(0x02);

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_DISPLAY_MESSAGE,
        CMD_CANCEL_MESSAGE,
        CMD_DISPLAY_PROTECTED_MESSAGE,
        CMD_CANCEL_ALL_MESSAGES,
    ],
    generated: &[
        CMD_GET_LAST_MESSAGE,
        CMD_MESSAGE_CONFIRMATION,
        CMD_GET_MESSAGE_CANCELLATION,
    ],
};

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_GET_LAST_MESSAGE,
        CMD_MESSAGE_CONFIRMATION,
        CMD_GET_MESSAGE_CANCELLATION,
    ],
    generated: &[
        CMD_DISPLAY_MESSAGE,
        CMD_CANCEL_MESSAGE,
        CMD_DISPLAY_PROTECTED_MESSAGE,
        CMD_CANCEL_ALL_MESSAGES,
    ],
};

/// Largest message text held (the unfragmented budget of D.5.2.3.1.1.1
/// is 59 octets; fragmented messages may be longer).
pub const MAX_MESSAGE_LEN: usize = 128;
/// Largest confirmation response text (1–21 octets incl. length).
pub const MAX_CONFIRMATION_RESPONSE_LEN: usize = 20;

/// Message Control bits (Table D-117).
pub mod message_control {
    /// Bits 0–1: transmission (normal only).
    pub const TRANSMISSION_NORMAL: u8 = 0;
    /// Bits 0–1: normal and inter-PAN (deprecated).
    pub const TRANSMISSION_NORMAL_AND_INTER_PAN: u8 = 1;
    /// Bits 0–1: inter-PAN only (deprecated: dropped with INVALID_FIELD).
    pub const TRANSMISSION_INTER_PAN_ONLY: u8 = 2;
    /// Mask of the transmission bits.
    pub const TRANSMISSION_MASK: u8 = 0x03;
    /// Bits 2–3: importance.
    pub const IMPORTANCE_MASK: u8 = 0x0C;
    /// Importance shift.
    pub const IMPORTANCE_SHIFT: u8 = 2;
    /// Bit 5: enhanced confirmation required.
    pub const ENHANCED_CONFIRMATION_REQUIRED: u8 = 0x20;
    /// Bit 7: message confirmation required.
    pub const CONFIRMATION_REQUIRED: u8 = 0x80;
}

/// Importance levels (Table D-117 bits 2–3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Importance {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// Extended Message Control bit 0: the message has been confirmed.
pub const EXTENDED_CONFIRMED: u8 = 0x01;
/// Message Confirmation Control bit 0: the answer is NO.
pub const CONFIRMATION_NO: u8 = 0x01;
/// Message Confirmation Control bit 1: the answer is YES.
pub const CONFIRMATION_YES: u8 = 0x02;
/// Duration "until changed".
pub const DURATION_UNTIL_CHANGED: u16 = 0xFFFF;

/// Display Message / Display Protected Message payload (Figure D-93).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisplayMessage<'a> {
    /// Message ID.
    pub message_id: u32,
    /// Message Control bitmap.
    pub message_control: u8,
    /// Start time (UTC seconds; 0 = now).
    pub start_time: u32,
    /// Duration in minutes (0xFFFF = until changed).
    pub duration_minutes: u16,
    /// UTF-8 message text.
    pub message: &'a [u8],
    /// Extended Message Control (absent in legacy frames).
    pub extended_control: Option<u8>,
}

impl<'a> DisplayMessage<'a> {
    /// Parses the payload; a message for "inter-PAN transmission only"
    /// is refused (D.5.2.3.1.1.1: INVALID_FIELD).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let message_id = r.u32_le()?;
        let message_control = r.u8()?;
        let start_time = r.u32_le()?;
        let duration_minutes = r.u16_le()?;
        let len = usize::from(r.u8()?);
        let message = if len == 0xFF { &[][..] } else { r.bytes(len)? };
        let extended_control = if r.remaining() >= 1 {
            Some(r.u8()?)
        } else {
            None
        };
        if message_control & message_control::TRANSMISSION_MASK
            == message_control::TRANSMISSION_INTER_PAN_ONLY
        {
            return Err(CodecError::InvalidField {
                field: "Message Control",
                value: u32::from(message_control),
            });
        }
        Ok(DisplayMessage {
            message_id,
            message_control,
            start_time,
            duration_minutes,
            message,
            extended_control,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let len = u8::try_from(self.message.len())
            .ok()
            .filter(|l| *l < 0xFF)
            .ok_or(CodecError::InvalidField {
                field: "Message",
                value: 0,
            })?;
        w.u32_le(self.message_id)?;
        w.u8(self.message_control)?;
        w.u32_le(self.start_time)?;
        w.u16_le(self.duration_minutes)?;
        w.u8(len)?;
        w.bytes(self.message)?;
        if let Some(x) = self.extended_control {
            w.u8(x)?;
        }
        Ok(())
    }

    /// Importance of the message.
    pub const fn importance(&self) -> Importance {
        match (self.message_control & message_control::IMPORTANCE_MASK)
            >> message_control::IMPORTANCE_SHIFT
        {
            0 => Importance::Low,
            1 => Importance::Medium,
            2 => Importance::High,
            _ => Importance::Critical,
        }
    }

    /// Whether the user must confirm the message.
    pub const fn confirmation_required(&self) -> bool {
        self.message_control & message_control::CONFIRMATION_REQUIRED != 0
    }

    /// Whether the confirmation carries an answer / text.
    pub const fn enhanced_confirmation_required(&self) -> bool {
        self.message_control & message_control::ENHANCED_CONFIRMATION_REQUIRED != 0
    }

    /// Whether the server marked the message as already confirmed.
    pub const fn confirmed(&self) -> bool {
        matches!(self.extended_control, Some(x) if x & EXTENDED_CONFIRMED != 0)
    }

    /// End time, `None` for "until changed".
    pub const fn end_time(&self, now: u32) -> Option<u32> {
        if self.duration_minutes == DURATION_UNTIL_CHANGED {
            None
        } else {
            let start = if self.start_time == 0 {
                now
            } else {
                self.start_time
            };
            Some(start.saturating_add((self.duration_minutes as u32).saturating_mul(60)))
        }
    }
}

/// Cancel Message payload (Figure D-94).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CancelMessage {
    /// Message ID.
    pub message_id: u32,
    /// Message Control (deprecated, 0).
    pub message_control: u8,
}

impl CancelMessage {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(CancelMessage {
            message_id: r.u32_le()?,
            message_control: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.message_id)?;
        w.u8(self.message_control)
    }
}

/// Message Confirmation payload (Figure D-96).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MessageConfirmation<'a> {
    /// Message ID.
    pub message_id: u32,
    /// Confirmation time (UTC seconds).
    pub confirmation_time: u32,
    /// Message Confirmation Control (NO / YES bits); 0 when absent.
    pub control: u8,
    /// Optional response text (UTF-8).
    pub response: &'a [u8],
}

impl<'a> MessageConfirmation<'a> {
    /// Parses the payload; the optional fields default to 0 / empty.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let message_id = r.u32_le()?;
        let confirmation_time = r.u32_le()?;
        let control = if r.remaining() >= 1 { r.u8()? } else { 0 };
        let response = if r.remaining() >= 1 {
            let len = usize::from(r.u8()?);
            if len == 0xFF { &[][..] } else { r.bytes(len)? }
        } else {
            &[]
        };
        Ok(MessageConfirmation {
            message_id,
            confirmation_time,
            control,
            response,
        })
    }

    /// Encodes the payload; the control and response are written when
    /// either is non-default.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.message_id)?;
        w.u32_le(self.confirmation_time)?;
        if self.control != 0 || !self.response.is_empty() {
            let len = u8::try_from(self.response.len())
                .ok()
                .filter(|l| usize::from(*l) <= MAX_CONFIRMATION_RESPONSE_LEN)
                .ok_or(CodecError::InvalidField {
                    field: "Message Confirmation Response",
                    value: 0,
                })?;
            w.u8(self.control)?;
            w.u8(len)?;
            w.bytes(self.response)?;
        }
        Ok(())
    }
}

/// A message held by a client.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Stored {
    /// Message ID.
    pub message_id: u32,
    /// Message Control.
    pub message_control: u8,
    /// Effective start (UTC seconds).
    pub start: u32,
    /// End, `None` for "until changed".
    pub end: Option<u32>,
    /// Text.
    pub text: Vec<u8, MAX_MESSAGE_LEN>,
    /// Whether the message has been confirmed (locally or by another
    /// client, per the Extended Message Control).
    pub confirmed: bool,
    /// Protected (PIN) message.
    pub protected: bool,
}

impl Stored {
    /// Whether the message needs a confirmation that has not been given.
    pub const fn awaiting_confirmation(&self) -> bool {
        self.message_control & message_control::CONFIRMATION_REQUIRED != 0 && !self.confirmed
    }

    /// Whether the message is being displayed at `now`.
    pub fn displayed(&self, now: u32) -> bool {
        now >= self.start && self.end.is_none_or(|e| now < e)
    }
}

/// What a client does with a received message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// A new message replaced the previous one (or none).
    Replaced,
    /// The known message was re-sent (confirmation state updated).
    Updated,
    /// The message text was too long to hold; the message was dropped.
    TooLong,
}

/// The client's current message (D.5.1: one active message, replaced
/// by each new one).
#[derive(Clone, Debug, Default)]
pub struct Display {
    current: Option<Stored>,
}

impl Display {
    /// No message.
    pub const fn new() -> Self {
        Display { current: None }
    }

    /// The current message.
    pub const fn current(&self) -> Option<&Stored> {
        self.current.as_ref()
    }

    /// Handles Display Message / Display Protected Message.
    pub fn on_display(&mut self, m: &DisplayMessage<'_>, protected: bool, now: u32) -> Outcome {
        if let Some(c) = &mut self.current
            && c.message_id == m.message_id
        {
            c.confirmed |= m.confirmed();
            c.message_control = m.message_control;
            return Outcome::Updated;
        }
        let mut text = Vec::new();
        if text.extend_from_slice(m.message).is_err() {
            return Outcome::TooLong;
        }
        self.current = Some(Stored {
            message_id: m.message_id,
            message_control: m.message_control,
            start: if m.start_time == 0 { now } else { m.start_time },
            end: m.end_time(now),
            text,
            confirmed: m.confirmed(),
            protected,
        });
        Outcome::Replaced
    }

    /// Handles Cancel Message: true when the current message was
    /// cancelled.
    pub fn on_cancel(&mut self, c: &CancelMessage) -> bool {
        if self
            .current
            .as_ref()
            .is_some_and(|m| m.message_id == c.message_id)
        {
            self.current = None;
            true
        } else {
            false
        }
    }

    /// Handles Cancel All Messages: clears the message once the
    /// implementation time is reached.
    pub fn on_cancel_all(&mut self, implementation_time: u32, now: u32) -> bool {
        if now >= implementation_time && self.current.is_some() {
            self.current = None;
            true
        } else {
            false
        }
    }

    /// Drops an expired message; returns true when something changed.
    pub fn poll(&mut self, now: u32) -> bool {
        if self
            .current
            .as_ref()
            .is_some_and(|m| m.end.is_some_and(|e| now >= e))
        {
            self.current = None;
            true
        } else {
            false
        }
    }

    /// The user confirms the current message; returns the Message
    /// Confirmation to send (with the answer bits and text when the
    /// server asked for an enhanced confirmation).
    pub fn confirm<'a>(
        &mut self,
        now: u32,
        control: u8,
        response: &'a [u8],
    ) -> Option<MessageConfirmation<'a>> {
        let m = self.current.as_mut()?;
        if !m.awaiting_confirmation() {
            return None;
        }
        m.confirmed = true;
        let enhanced = m.message_control & message_control::ENHANCED_CONFIRMATION_REQUIRED != 0;
        Some(MessageConfirmation {
            message_id: m.message_id,
            confirmation_time: now,
            control: if enhanced { control } else { 0 },
            response: if enhanced { response } else { &[] },
        })
    }
}

/// Cancel All Messages / GetMessageCancellation payload (Figures D-95
/// and D-97): an implementation time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ImplementationTime {
    /// UTC seconds (0: now).
    pub time: u32,
}

impl ImplementationTime {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(ImplementationTime { time: r.u32_le()? })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.time)
    }
}

/// A message the server holds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Published {
    /// Message ID.
    pub message_id: u32,
    /// Message Control.
    pub message_control: u8,
    /// Extended Message Control.
    pub extended_control: u8,
    /// Start time (UTC seconds, resolved).
    pub start_time: u32,
    /// Duration in minutes (0xFFFF: until changed).
    pub duration_minutes: u16,
    /// Text.
    pub message: Vec<u8, MAX_MESSAGE_LEN>,
    /// Protected (PIN) message.
    pub protected: bool,
    /// Confirmations received (client short address, time).
    pub confirmations: Vec<(u16, u32), 8>,
}

impl Published {
    /// The Display Message payload of this message.
    pub fn display(&self) -> DisplayMessage<'_> {
        DisplayMessage {
            message_id: self.message_id,
            message_control: self.message_control,
            start_time: self.start_time,
            duration_minutes: self.duration_minutes,
            message: &self.message,
            extended_control: Some(self.extended_control),
        }
    }

    /// Whether the message is still current at `now`.
    pub fn is_current(&self, now: u32) -> bool {
        self.duration_minutes == DURATION_UNTIL_CHANGED
            || now
                < self
                    .start_time
                    .saturating_add(u32::from(self.duration_minutes) * 60)
    }
}

/// Server-side (ESI) message store (D.5.2): the single current message
/// answering Get Last Message, the confirmations gathered for it and a
/// pending Cancel All Messages answering GetMessageCancellation.
#[derive(Clone, Debug, Default)]
pub struct Server {
    current: Option<Published>,
    cancel_all: Option<u32>,
}

impl Server {
    /// No message.
    pub const fn new() -> Self {
        Server {
            current: None,
            cancel_all: None,
        }
    }

    /// Publishes a message (the Display Message the ESI sends to its
    /// bound clients); a start time of 0 is resolved to `now`. Replaces
    /// the previous message and clears a pending cancel-all.
    pub fn publish(&mut self, m: &DisplayMessage<'_>, protected: bool, now: u32) -> bool {
        let Ok(message) = Vec::from_slice(m.message) else {
            return false;
        };
        self.current = Some(Published {
            message_id: m.message_id,
            message_control: m.message_control,
            extended_control: m.extended_control.unwrap_or(0),
            start_time: if m.start_time == 0 { now } else { m.start_time },
            duration_minutes: m.duration_minutes,
            message,
            protected,
            confirmations: Vec::new(),
        });
        self.cancel_all = None;
        true
    }

    /// Cancels the current message by id (Cancel Message).
    pub fn cancel(&mut self, message_id: u32) -> bool {
        if self
            .current
            .as_ref()
            .is_some_and(|m| m.message_id == message_id)
        {
            self.current = None;
            return true;
        }
        false
    }

    /// Records a Cancel All Messages for `implementation_time` (0: now,
    /// dropping the current message at once).
    pub fn cancel_all(&mut self, implementation_time: u32, now: u32) {
        if implementation_time == 0 || implementation_time <= now {
            self.current = None;
            self.cancel_all = None;
        } else {
            self.cancel_all = Some(implementation_time);
        }
    }

    /// Advances time: a due cancel-all removes the message, an expired
    /// message is dropped.
    pub fn poll(&mut self, now: u32) {
        if self.cancel_all.is_some_and(|t| now >= t) {
            self.current = None;
            self.cancel_all = None;
        }
        if self.current.as_ref().is_some_and(|m| !m.is_current(now)) {
            self.current = None;
        }
    }

    /// Answers Get Last Message (D.5.3.3.1.1): the current message to
    /// send as Display (Protected) Message, or `None` for NOT_FOUND.
    pub fn last_message(&self, now: u32) -> Option<&Published> {
        self.current.as_ref().filter(|m| m.is_current(now))
    }

    /// Records a Message Confirmation from `client` (D.5.3.3.2); `false`
    /// when it names another message.
    pub fn on_confirmation(&mut self, client: u16, c: &MessageConfirmation<'_>) -> bool {
        let Some(m) = self.current.as_mut() else {
            return false;
        };
        if m.message_id != c.message_id {
            return false;
        }
        if let Some(e) = m.confirmations.iter_mut().find(|(a, _)| *a == client) {
            e.1 = c.confirmation_time;
        } else if m.confirmations.is_full() {
            m.confirmations.remove(0);
            let _ = m.confirmations.push((client, c.confirmation_time));
        } else {
            let _ = m.confirmations.push((client, c.confirmation_time));
        }
        true
    }

    /// Answers GetMessageCancellation (D.5.3.3.3): the pending Cancel
    /// All Messages with an implementation time at or after
    /// `earliest`, or `None` for NOT_FOUND.
    pub fn message_cancellation(&self, earliest: u32) -> Option<ImplementationTime> {
        self.cancel_all
            .filter(|t| *t >= earliest)
            .map(|time| ImplementationTime { time })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_and_display() {
        let m = DisplayMessage {
            message_id: 0x0102_0304,
            message_control: message_control::CONFIRMATION_REQUIRED
                | message_control::ENHANCED_CONFIRMATION_REQUIRED
                | (2 << message_control::IMPORTANCE_SHIFT),
            start_time: 0,
            duration_minutes: 30,
            message: b"Peak pricing at 5pm",
            extended_control: Some(0),
        };
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        m.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 12 + 19 + 1);
        assert_eq!(DisplayMessage::parse(&buf[..n]).unwrap(), m);
        assert_eq!(m.importance(), Importance::High);
        assert_eq!(m.end_time(1000), Some(2800));
        // Legacy frame without the extended control.
        let legacy = DisplayMessage::parse(&buf[..n - 1]).unwrap();
        assert_eq!(legacy.extended_control, None);
        // Inter-PAN only is refused.
        buf[4] = message_control::TRANSMISSION_INTER_PAN_ONLY;
        assert!(DisplayMessage::parse(&buf[..n]).is_err());
        buf[4] = m.message_control;

        let mut d = Display::new();
        assert_eq!(d.on_display(&m, false, 1000), Outcome::Replaced);
        assert!(d.current().unwrap().awaiting_confirmation());
        assert!(d.current().unwrap().displayed(1500));
        // Another client confirmed: the re-sent message carries the flag.
        let again = DisplayMessage {
            extended_control: Some(EXTENDED_CONFIRMED),
            ..m
        };
        assert_eq!(d.on_display(&again, false, 1100), Outcome::Updated);
        assert!(!d.current().unwrap().awaiting_confirmation());
        assert!(d.confirm(1200, CONFIRMATION_YES, b"ok").is_none());
        // A new message replaces it; the user confirms with YES.
        let m2 = DisplayMessage {
            message_id: 9,
            message: b"Second",
            ..m
        };
        assert_eq!(d.on_display(&m2, false, 1300), Outcome::Replaced);
        let c = d.confirm(1400, CONFIRMATION_YES, b"ok").unwrap();
        assert_eq!(c.message_id, 9);
        assert_eq!(c.control, CONFIRMATION_YES);
        let mut w = Writer::new(&mut buf);
        c.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 4 + 4 + 1 + 1 + 2);
        assert_eq!(MessageConfirmation::parse(&buf[..n]).unwrap(), c);
        // A basic confirmation (no control): 8 octets, parsed with defaults.
        let basic = MessageConfirmation {
            message_id: 9,
            confirmation_time: 1400,
            control: 0,
            response: &[],
        };
        let mut w = Writer::new(&mut buf);
        basic.encode(&mut w).unwrap();
        assert_eq!(w.position(), 8);
        assert_eq!(MessageConfirmation::parse(&buf[..8]).unwrap(), basic);
        // Expiry and cancellation.
        assert!(!d.poll(2000));
        assert!(d.poll(1300 + 1800));
        assert!(d.current().is_none());
        assert_eq!(d.on_display(&m2, true, 5000), Outcome::Replaced);
        assert!(d.current().unwrap().protected);
        assert!(!d.on_cancel(&CancelMessage {
            message_id: 1,
            message_control: 0
        }));
        assert!(d.on_cancel(&CancelMessage {
            message_id: 9,
            message_control: 0
        }));
        assert_eq!(d.on_display(&m2, false, 5000), Outcome::Replaced);
        assert!(!d.on_cancel_all(6000, 5500));
        assert!(d.on_cancel_all(6000, 6000));
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;

    fn msg(id: u32, start: u32, minutes: u16) -> DisplayMessage<'static> {
        DisplayMessage {
            message_id: id,
            message_control: message_control::CONFIRMATION_REQUIRED,
            start_time: start,
            duration_minutes: minutes,
            message: b"Hello",
            extended_control: None,
        }
    }

    #[test]
    fn server_store_answers_get_last_message_and_cancellation() {
        let mut s = Server::new();
        let now = 5000;
        assert!(s.last_message(now).is_none());
        assert!(s.publish(&msg(1, 0, 10), false, now));
        let m = s.last_message(now).unwrap();
        assert_eq!((m.message_id, m.start_time), (1, now));
        assert_eq!(m.display().message, b"Hello");
        // Confirmation from two clients, the second twice.
        let c = MessageConfirmation {
            message_id: 1,
            confirmation_time: now + 5,
            control: 0,
            response: &[],
        };
        assert!(s.on_confirmation(0x1234, &c));
        assert!(s.on_confirmation(0x5678, &c));
        assert!(s.on_confirmation(
            0x5678,
            &MessageConfirmation {
                confirmation_time: now + 9,
                ..c
            }
        ));
        assert!(!s.on_confirmation(0x9999, &MessageConfirmation { message_id: 2, ..c }));
        let conf = &s.last_message(now).unwrap().confirmations;
        assert_eq!(conf.as_slice(), &[(0x1234, now + 5), (0x5678, now + 9)]);
        // Expiry after ten minutes.
        s.poll(now + 600);
        assert!(s.last_message(now + 600).is_none());
        // Cancel all at a later time: pending until due, reported to
        // GetMessageCancellation, then applied.
        assert!(s.publish(&msg(2, 0, DURATION_UNTIL_CHANGED), true, now));
        s.cancel_all(now + 100, now);
        assert!(s.last_message(now).is_some());
        assert_eq!(
            s.message_cancellation(now),
            Some(ImplementationTime { time: now + 100 })
        );
        assert_eq!(s.message_cancellation(now + 101), None);
        s.poll(now + 100);
        assert!(s.last_message(now + 100).is_none());
        assert_eq!(s.message_cancellation(0), None);
        // Cancel by id; immediate cancel-all.
        s.publish(&msg(3, 0, DURATION_UNTIL_CHANGED), false, now);
        assert!(!s.cancel(4) && s.cancel(3));
        s.publish(&msg(5, 0, DURATION_UNTIL_CHANGED), false, now);
        s.cancel_all(0, now);
        assert!(s.last_message(now).is_none());
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        ImplementationTime { time: 7 }.encode(&mut w).unwrap();
        assert_eq!(ImplementationTime::parse(&buf).unwrap().time, 7);
    }
}
