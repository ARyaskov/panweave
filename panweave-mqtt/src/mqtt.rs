//! The MQTT 3.1.1 packets the bridge uses (OASIS MQTT 3.1.1), sans-I/O:
//! CONNECT with a last will and credentials, CONNACK, PUBLISH at QoS 0
//! and 1, PUBACK, SUBSCRIBE / SUBACK, PINGREQ / PINGRESP and DISCONNECT.
//! [`Decoder`] splits a byte stream into packets and bounds what it
//! buffers.

/// Largest packet [`Decoder`] accepts (remaining length); larger ones
/// are a protocol error and the connection should be dropped.
pub const MAX_PACKET: usize = 256 * 1024;

/// Why a packet could not be encoded or decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MqttError {
    /// The remaining length is longer than four octets or than
    /// [`MAX_PACKET`].
    TooLarge,
    /// A string or field runs past the end of the packet, or a string
    /// is not UTF-8.
    Malformed,
    /// The server sent a packet a client never receives.
    Unexpected(u8),
}

/// CONNECT parameters (§3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Connect<'a> {
    /// Client identifier.
    pub client_id: &'a str,
    /// Keep alive, seconds.
    pub keep_alive: u16,
    /// Last will: published retained at QoS 0 when the connection is
    /// lost.
    pub will: Option<(&'a str, &'a [u8])>,
    /// User name.
    pub username: Option<&'a str>,
    /// Password (sent only with a user name, §3.1.2.9).
    pub password: Option<&'a [u8]>,
}

/// A packet received from the server.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Packet {
    /// CONNACK: `code` 0 accepted, else refused (§3.2.2.3).
    ConnAck {
        /// The session was resumed.
        session_present: bool,
        /// Return code.
        code: u8,
    },
    /// PUBLISH.
    Publish {
        /// Topic name.
        topic: String,
        /// Application payload.
        payload: Vec<u8>,
        /// Retained message.
        retain: bool,
        /// QoS 0–2.
        qos: u8,
        /// Packet identifier (QoS 1 and 2).
        packet_id: Option<u16>,
    },
    /// PUBACK.
    PubAck(u16),
    /// SUBACK: one return code per filter (0x80 refused).
    SubAck {
        /// Packet identifier.
        packet_id: u16,
        /// Granted QoS per filter.
        codes: Vec<u8>,
    },
    /// PINGRESP.
    PingResp,
}

/// The text of a refused CONNACK code.
pub const fn connack_reason(code: u8) -> &'static str {
    match code {
        0 => "accepted",
        1 => "unacceptable protocol version",
        2 => "identifier rejected",
        3 => "server unavailable",
        4 => "bad user name or password",
        5 => "not authorized",
        _ => "refused",
    }
}

fn put_len(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let mut b = u8::try_from(len % 128).unwrap_or(0);
        len /= 128;
        if len > 0 {
            b |= 0x80;
        }
        out.push(b);
        if len == 0 {
            break;
        }
    }
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    let n = u16::try_from(s.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&s[..usize::from(n)]);
}

fn packet(header: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(header);
    put_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// A CONNECT packet (clean session).
pub fn connect(c: &Connect<'_>) -> Vec<u8> {
    let mut body = Vec::new();
    put_str(&mut body, b"MQTT");
    body.push(4); // protocol level 3.1.1
    let mut flags = 0x02; // clean session
    if c.will.is_some() {
        flags |= 0x04 | 0x20; // will, will retain (QoS 0)
    }
    if c.username.is_some() {
        flags |= 0x80;
        if c.password.is_some() {
            flags |= 0x40;
        }
    }
    body.push(flags);
    body.extend_from_slice(&c.keep_alive.to_be_bytes());
    put_str(&mut body, c.client_id.as_bytes());
    if let Some((topic, message)) = c.will {
        put_str(&mut body, topic.as_bytes());
        put_str(&mut body, message);
    }
    if let Some(u) = c.username {
        put_str(&mut body, u.as_bytes());
        if let Some(p) = c.password {
            put_str(&mut body, p);
        }
    }
    packet(0x10, &body)
}

/// A PUBLISH packet at QoS 0.
pub fn publish(topic: &str, payload: &[u8], retain: bool) -> Vec<u8> {
    let mut body = Vec::with_capacity(topic.len() + payload.len() + 2);
    put_str(&mut body, topic.as_bytes());
    body.extend_from_slice(payload);
    packet(0x30 | u8::from(retain), &body)
}

/// A PUBACK for a QoS 1 PUBLISH received.
pub fn puback(packet_id: u16) -> Vec<u8> {
    packet(0x40, &packet_id.to_be_bytes())
}

/// A SUBSCRIBE packet, every filter at QoS 0.
pub fn subscribe(packet_id: u16, filters: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    for f in filters {
        put_str(&mut body, f.as_bytes());
        body.push(0);
    }
    packet(0x82, &body)
}

/// PINGREQ.
pub fn pingreq() -> Vec<u8> {
    vec![0xc0, 0]
}

/// DISCONNECT.
pub fn disconnect() -> Vec<u8> {
    vec![0xe0, 0]
}

/// Whether a topic `filter` with `+` and `#` wildcards matches `topic`
/// (§4.7).
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, MqttError> {
    match b.get(at..at + 2) {
        Some(&[h, l]) => Ok(u16::from_be_bytes([h, l])),
        _ => Err(MqttError::Malformed),
    }
}

fn decode(header: u8, body: &[u8]) -> Result<Packet, MqttError> {
    match header >> 4 {
        2 => Ok(Packet::ConnAck {
            session_present: body.first().ok_or(MqttError::Malformed)? & 1 != 0,
            code: *body.get(1).ok_or(MqttError::Malformed)?,
        }),
        3 => {
            let qos = (header >> 1) & 3;
            let n = usize::from(u16_at(body, 0)?);
            let topic = body.get(2..2 + n).ok_or(MqttError::Malformed)?;
            let topic = core::str::from_utf8(topic).map_err(|_| MqttError::Malformed)?;
            let mut at = 2 + n;
            let packet_id = if qos > 0 {
                let id = u16_at(body, at)?;
                at += 2;
                Some(id)
            } else {
                None
            };
            Ok(Packet::Publish {
                topic: topic.to_string(),
                payload: body.get(at..).ok_or(MqttError::Malformed)?.to_vec(),
                retain: header & 1 != 0,
                qos,
                packet_id,
            })
        }
        4 => Ok(Packet::PubAck(u16_at(body, 0)?)),
        9 => Ok(Packet::SubAck {
            packet_id: u16_at(body, 0)?,
            codes: body.get(2..).unwrap_or_default().to_vec(),
        }),
        13 => Ok(Packet::PingResp),
        t => Err(MqttError::Unexpected(t)),
    }
}

/// Splits a byte stream into packets.
#[derive(Default, Debug)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    /// An empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends received octets.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete packet, `Ok(None)` when more octets are needed.
    /// After an error the stream is out of step: drop the connection.
    pub fn next_packet(&mut self) -> Result<Option<Packet>, MqttError> {
        let Some(&header) = self.buf.first() else {
            return Ok(None);
        };
        let mut len = 0usize;
        let mut shift = 0;
        let mut at = 1;
        loop {
            let Some(&b) = self.buf.get(at) else {
                return Ok(None);
            };
            len |= usize::from(b & 0x7f) << shift;
            at += 1;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if at > 4 {
                return Err(MqttError::TooLarge);
            }
        }
        if len > MAX_PACKET {
            return Err(MqttError::TooLarge);
        }
        if self.buf.len() < at + len {
            return Ok(None);
        }
        let packet = decode(header, &self.buf[at..at + len]);
        self.buf.drain(..at + len);
        packet.map(Some)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    #[test]
    fn connect_carries_will_and_credentials() {
        let p = connect(&Connect {
            client_id: "pw",
            keep_alive: 60,
            will: Some(("pw/bridge/state", b"offline")),
            username: Some("u"),
            password: Some(b"p"),
        });
        assert_eq!(p[0], 0x10);
        assert_eq!(usize::from(p[1]), p.len() - 2);
        assert_eq!(&p[2..9], b"\x00\x04MQTT\x04");
        assert_eq!(p[9], 0x80 | 0x40 | 0x20 | 0x04 | 0x02);
        assert_eq!(&p[10..12], &[0, 60]);
        assert!(p.ends_with(b"\x00\x01u\x00\x01p"));
    }

    #[test]
    fn long_payloads_use_multi_octet_lengths() {
        let payload = vec![7u8; 300];
        let p = publish("a/b", &payload, true);
        assert_eq!(p[0], 0x31);
        // 2 + 3 + 300 = 305 = 0xb1 0x02
        assert_eq!(&p[1..3], &[0xb1, 0x02]);
        let mut d = Decoder::new();
        // A server never sends our own PUBLISH back unless subscribed;
        // the decoder reads it all the same.
        d.push(&p[..10]);
        assert_eq!(d.next_packet(), Ok(None));
        d.push(&p[10..]);
        match d.next_packet().unwrap().unwrap() {
            Packet::Publish {
                topic,
                payload: got,
                retain,
                qos,
                packet_id,
            } => {
                assert_eq!(topic, "a/b");
                assert_eq!(got, payload);
                assert!(retain);
                assert_eq!((qos, packet_id), (0, None));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(d.next_packet(), Ok(None));
    }

    #[test]
    fn server_packets_decode() {
        let mut d = Decoder::new();
        d.push(&[0x20, 2, 0, 5]);
        d.push(&[0x90, 4, 0, 1, 0, 0x80]);
        d.push(&[0xd0, 0]);
        // QoS 1 PUBLISH with packet id 9.
        d.push(&[0x32, 7, 0, 1, b't', 0, 9, b'h', b'i']);
        assert_eq!(
            d.next_packet(),
            Ok(Some(Packet::ConnAck {
                session_present: false,
                code: 5
            }))
        );
        assert_eq!(
            d.next_packet(),
            Ok(Some(Packet::SubAck {
                packet_id: 1,
                codes: vec![0, 0x80]
            }))
        );
        assert_eq!(d.next_packet(), Ok(Some(Packet::PingResp)));
        assert_eq!(
            d.next_packet(),
            Ok(Some(Packet::Publish {
                topic: "t".into(),
                payload: b"hi".to_vec(),
                retain: false,
                qos: 1,
                packet_id: Some(9)
            }))
        );
        assert_eq!(connack_reason(5), "not authorized");
    }

    #[test]
    fn oversized_and_broken_packets_are_errors() {
        let mut d = Decoder::new();
        d.push(&[0x30, 0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(d.next_packet(), Err(MqttError::TooLarge));
        let mut d = Decoder::new();
        d.push(&[0x30, 0x80, 0x80, 0x80, 0x80, 0x01]);
        assert_eq!(d.next_packet(), Err(MqttError::TooLarge));
        let mut d = Decoder::new();
        d.push(&[0x30, 3, 0, 9, b'x']);
        assert_eq!(d.next_packet(), Err(MqttError::Malformed));
        let mut d = Decoder::new();
        d.push(&[0x10, 0]);
        assert_eq!(d.next_packet(), Err(MqttError::Unexpected(1)));
    }

    #[test]
    fn filters_match_topics() {
        assert!(topic_matches("pw/+/set", "pw/0x1/set"));
        assert!(!topic_matches("pw/+/set", "pw/0x1/get"));
        assert!(!topic_matches("pw/+/set", "pw/a/b/set"));
        assert!(topic_matches("pw/bridge/#", "pw/bridge/request/remove"));
        assert!(topic_matches("ha/status", "ha/status"));
        assert!(!topic_matches("ha/status", "ha/status/x"));
    }

    #[test]
    fn subscribe_and_small_packets() {
        let s = subscribe(3, &["a/+", "b"]);
        assert_eq!(
            s,
            vec![0x82, 12, 0, 3, 0, 3, b'a', b'/', b'+', 0, 0, 1, b'b', 0]
        );
        assert_eq!(puback(0x0102), vec![0x40, 2, 1, 2]);
        assert_eq!(pingreq(), vec![0xc0, 0]);
        assert_eq!(disconnect(), vec![0xe0, 0]);
    }
}
