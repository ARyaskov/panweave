//! The notification text: pending events in order, each with its stable
//! identifier, so that a duplicate (after an ambiguous attempt) can be
//! recognized by a reader.
//!
//! No wall-clock time is invented: an event's time is its boot and the
//! monotonic time since that boot started.

use core::fmt::Write as _;

use heapless::String;

use super::queue::{AlertEvent, Overflow};

/// Longest text composed (Telegram allows 4096 characters; a smaller
/// bound keeps the request buffer small). Events that do not fit stay
/// queued for the next message.
pub const MAX_TEXT: usize = 1024;

/// What the hub knows about a sensor when the message is composed.
#[derive(Clone, Copy, Debug)]
pub struct Sensor<'a> {
    /// Manufacturer and model (or empty).
    pub name: &'a str,
    /// Its state now (`"leak"`, `"dry"`, `"open"`, `"closed"`,
    /// `"unknown"`…).
    pub state: &'a str,
}

/// A composed message.
#[derive(Clone, Debug)]
pub struct Composed {
    /// The text.
    pub text: String<MAX_TEXT>,
    /// How many of the events (from the front) it contains.
    pub events: usize,
    /// Overflow losses it reports.
    pub overflow_reported: u32,
}

fn ieee_text(ieee: u64) -> String<23> {
    let mut s = String::new();
    for (i, b) in ieee.to_be_bytes().iter().enumerate() {
        if i > 0 {
            let _ = s.push(':');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn line(e: &AlertEvent, sensor: Sensor<'_>) -> String<256> {
    let mut l = String::new();
    let _ = write!(l, "{}", e.kind.sentence());
    if e.ieee != 0 {
        let name = if sensor.name.is_empty() {
            "unknown model"
        } else {
            sensor.name
        };
        let _ = write!(l, " Sensor: {} ({}).", name, ieee_text(e.ieee));
    }
    let _ = write!(
        l,
        " Event: #{}.{}. Occurred at: boot {} +{}.{} s (no wall-clock time).",
        e.id.boot,
        e.id.seq,
        e.id.boot,
        e.at_ms / 1000,
        (e.at_ms % 1000) / 100
    );
    if e.ieee != 0 {
        let _ = write!(l, " Current state: {}.", sensor.state);
    }
    if e.ambiguous {
        let _ = l.push_str(" [possible repeat]");
    }
    l
}

/// Composes the message for `events` (oldest first). Always includes at
/// least the first event.
pub fn compose<'a>(
    events: &[AlertEvent],
    overflow: Overflow,
    sensor: impl Fn(u64) -> Sensor<'a>,
) -> Composed {
    let mut text: String<MAX_TEXT> = String::new();
    let any_repeat = events.iter().any(|e| e.ambiguous);
    let _ = write!(text, "Panweave hub");
    if any_repeat {
        let _ = text.push_str(" (may repeat an earlier message)");
    }
    let _ = text.push(':');
    let mut overflow_reported = 0;
    if overflow.count > 0 {
        let mut note: String<160> = String::new();
        let _ = write!(
            note,
            "\nWarning: {} event(s) were not stored (queue full)",
            overflow.count
        );
        if let (Some(f), Some(l)) = (overflow.first, overflow.last) {
            let _ = write!(note, ", #{}.{} to #{}.{}", f.boot, f.seq, l.boot, l.seq);
        }
        let _ = note.push('.');
        if text.push_str(&note).is_ok() {
            overflow_reported = overflow.count;
        }
    }
    let mut included = 0;
    for e in events {
        let l = line(e, sensor(e.ieee));
        if text.len() + 1 + l.len() > MAX_TEXT {
            break;
        }
        let _ = text.push('\n');
        let _ = text.push_str(&l);
        included += 1;
    }
    Composed {
        text,
        events: included,
        overflow_reported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::queue::EventId;
    use crate::protocol::AlertKind;

    fn ev(seq: u32, kind: AlertKind, at_ms: u64) -> AlertEvent {
        AlertEvent {
            id: EventId { boot: 3, seq },
            kind,
            ieee: 0x54EF_4410_0000_0001,
            zone_status: Some(1),
            at_ms,
            attempts: 0,
            ambiguous: false,
        }
    }

    fn aqara(_: u64) -> Sensor<'static> {
        Sensor {
            name: "LUMI lumi.flood.agl02",
            state: "dry",
        }
    }

    #[test]
    fn an_alarm_and_its_recovery_are_both_reported_in_order_with_identifiers() {
        let events = [
            ev(17, AlertKind::WaterLeak, 1_234_567),
            ev(18, AlertKind::WaterLeakCleared, 1_240_000),
        ];
        let m = compose(&events, Overflow::default(), aqara);
        assert_eq!(m.events, 2);
        assert_eq!(
            m.text.as_str(),
            "Panweave hub:\n\
             Water leak detected. Sensor: LUMI lumi.flood.agl02 (54:ef:44:10:00:00:00:01). Event: #3.17. Occurred at: boot 3 +1234.5 s (no wall-clock time). Current state: dry.\n\
             Water leak cleared. Sensor: LUMI lumi.flood.agl02 (54:ef:44:10:00:00:00:01). Event: #3.18. Occurred at: boot 3 +1240.0 s (no wall-clock time). Current state: dry."
        );
    }

    #[test]
    fn repeats_and_overflow_are_announced() {
        let mut e = ev(1, AlertKind::WaterLeak, 0);
        e.ambiguous = true;
        let o = Overflow {
            count: 4,
            first: Some(EventId { boot: 3, seq: 20 }),
            last: Some(EventId { boot: 3, seq: 23 }),
        };
        let m = compose(&[e], o, aqara);
        assert!(
            m.text
                .starts_with("Panweave hub (may repeat an earlier message):")
        );
        assert!(
            m.text
                .contains("Warning: 4 event(s) were not stored (queue full), #3.20 to #3.23.")
        );
        assert!(m.text.contains("[possible repeat]"));
        assert_eq!(m.overflow_reported, 4);
    }

    #[test]
    fn events_that_do_not_fit_are_left_for_the_next_message() {
        let events: Vec<_> = (0..16)
            .map(|i| ev(i, AlertKind::ContactOpened, 0))
            .collect();
        let m = compose(&events, Overflow::default(), aqara);
        assert!(m.events >= 1 && m.events < 16);
        assert!(m.text.len() <= MAX_TEXT);
        assert!(m.text.contains(&format!("#3.{}.", m.events - 1)));
        assert!(!m.text.contains(&format!("#3.{}.", m.events)));
    }

    #[test]
    fn a_test_notification_has_no_sensor() {
        let mut e = ev(0, AlertKind::Test, 5_000);
        e.ieee = 0;
        let m = compose(&[e], Overflow::default(), aqara);
        assert!(m.text.ends_with(
            "Test notification. Event: #3.0. Occurred at: boot 3 +5.0 s (no wall-clock time)."
        ));
    }
}
