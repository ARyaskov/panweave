//! Payloads of the GPD commissioning commands (GP Basic 1.1.2 §A.4.2.1):
//! GPD Commissioning (0xE0), Commissioning Reply (0xF0), Channel Request
//! (0xE3) and Channel Configuration (0xF3).

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{ClusterId, PanId};

use crate::gpdf::MIC_LEN;
use crate::security::KeyType;

/// A GPD key as carried over the air: in the clear, or protected with
/// the gpLinkKey together with its MIC (§A.3.7.1.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyField {
    /// Key octets (ciphertext when `mic` is present).
    pub bytes: [u8; 16],
    /// GPDkeyMIC when the key is TC-LK protected.
    pub mic: Option<[u8; MIC_LEN]>,
}

/// Extended Options of the GPD Commissioning command (Figure 110).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityCapabilities {
    /// SecurityLevelCapabilities (raw 2-bit value of Table 11).
    pub level: u8,
    /// KeyType the GPD is configured with.
    pub key_type: KeyType,
    /// GPDkeyEncryption: the key is / can be TC-LK protected.
    pub key_encryption: bool,
}

/// Switch information of a generic switch GPD (Figure 114).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SwitchInfo {
    /// Number of contacts (0–8).
    pub contacts: u8,
    /// Switch type (Table 57): 0 unknown, 1 button, 2 rocker.
    pub switch_type: u8,
    /// Current contact status.
    pub contact_status: u8,
}

/// Application information of the GPD Commissioning command (Figure
/// 111 and the fields it announces).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ApplicationInfo<'a> {
    /// ManufacturerID.
    pub manufacturer_id: Option<u16>,
    /// ModelID.
    pub model_id: Option<u16>,
    /// GPD CommandID list.
    pub commands: Option<&'a [u8]>,
    /// Cluster list: server ClusterIDs then client ClusterIDs, each as
    /// little-endian pairs.
    pub clusters: Option<ClusterList<'a>>,
    /// Switch information.
    pub switch: Option<SwitchInfo>,
    /// A GPD Application Description command follows.
    pub description_follows: bool,
}

/// The Cluster List field (Figure 112).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClusterList<'a> {
    /// Number of server clusters.
    pub servers: u8,
    /// Number of client clusters.
    pub clients: u8,
    /// `2 × (servers + clients)` octets.
    pub bytes: &'a [u8],
}

impl ClusterList<'_> {
    fn ids(&self, skip: usize, n: usize) -> impl Iterator<Item = ClusterId> + '_ {
        self.bytes
            .chunks_exact(2)
            .skip(skip)
            .take(n)
            .map(|c| ClusterId(u16::from_le_bytes([c[0], c[1]])))
    }

    /// Server clusters.
    pub fn server_ids(&self) -> impl Iterator<Item = ClusterId> + '_ {
        self.ids(0, usize::from(self.servers))
    }

    /// Client clusters.
    pub fn client_ids(&self) -> impl Iterator<Item = ClusterId> + '_ {
        self.ids(usize::from(self.servers), usize::from(self.clients))
    }
}

/// GPD Commissioning command payload (§A.4.2.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commissioning<'a> {
    /// GPD DeviceID.
    pub device_id: u8,
    /// MACsequenceNumberCapability (incremental sequence numbers).
    pub sequence_number_capable: bool,
    /// RxOnCapability.
    pub rx_on_capable: bool,
    /// PANId request.
    pub pan_id_request: bool,
    /// GPsecurityKeyRequest.
    pub key_request: bool,
    /// FixedLocation.
    pub fixed_location: bool,
    /// Extended Options.
    pub security: Option<SecurityCapabilities>,
    /// GPDkey (with its MIC when protected).
    pub key: Option<KeyField>,
    /// GPDoutgoingCounter.
    pub outgoing_counter: Option<u32>,
    /// Application information.
    pub application: Option<ApplicationInfo<'a>>,
}

impl Commissioning<'_> {
    /// SecurityLevelCapabilities, 0 when the Extended Options are absent
    /// (with the §A.4.2.1.1.3 default of 0b01 for a bare key request).
    pub fn level_capabilities(&self) -> u8 {
        match self.security {
            Some(s) => s.level,
            None if self.key_request => 0b01,
            None => 0b00,
        }
    }

    /// KeyType announced by the GPD (`None` without Extended Options).
    pub fn key_type(&self) -> KeyType {
        self.security.map_or(KeyType::None, |s| s.key_type)
    }

    /// True when the GPD can protect an exchanged key with the gpLinkKey.
    pub fn key_encryption(&self) -> bool {
        self.security.is_some_and(|s| s.key_encryption)
    }

    fn options(&self) -> u8 {
        u8::from(self.sequence_number_capable)
            | (u8::from(self.rx_on_capable) << 1)
            | (u8::from(self.application.is_some()) << 2)
            | (u8::from(self.pan_id_request) << 4)
            | (u8::from(self.key_request) << 5)
            | (u8::from(self.fixed_location) << 6)
            | (u8::from(self.security.is_some()) << 7)
    }
}

impl Encode for Commissioning<'_> {
    fn encoded_len(&self) -> usize {
        let mut n = 2 + usize::from(self.security.is_some());
        if let Some(k) = &self.key {
            n += 16 + if k.mic.is_some() { MIC_LEN } else { 0 };
        }
        if self.outgoing_counter.is_some() {
            n += 4;
        }
        if let Some(a) = &self.application {
            n += 1;
            n += if a.manufacturer_id.is_some() { 2 } else { 0 };
            n += if a.model_id.is_some() { 2 } else { 0 };
            n += a.commands.map_or(0, |c| 1 + c.len());
            n += a.clusters.map_or(0, |c| 1 + c.bytes.len());
            n += if a.switch.is_some() { 3 } else { 0 };
        }
        n
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.device_id)?;
        w.u8(self.options())?;
        if let Some(s) = &self.security {
            let key_encrypted = s.key_encryption;
            w.u8((s.level & 0x03)
                | (s.key_type.raw() << 2)
                | (u8::from(self.key.is_some()) << 5)
                | (u8::from(key_encrypted) << 6)
                | (u8::from(self.outgoing_counter.is_some()) << 7))?;
        }
        if let Some(k) = &self.key {
            w.bytes(&k.bytes)?;
            if let Some(m) = &k.mic {
                w.bytes(m)?;
            }
        }
        if let Some(c) = self.outgoing_counter {
            w.u32_le(c)?;
        }
        if let Some(a) = &self.application {
            w.u8(u8::from(a.manufacturer_id.is_some())
                | (u8::from(a.model_id.is_some()) << 1)
                | (u8::from(a.commands.is_some()) << 2)
                | (u8::from(a.clusters.is_some()) << 3)
                | (u8::from(a.switch.is_some()) << 4)
                | (u8::from(a.description_follows) << 5))?;
            if let Some(m) = a.manufacturer_id {
                w.u16_le(m)?;
            }
            if let Some(m) = a.model_id {
                w.u16_le(m)?;
            }
            if let Some(c) = a.commands {
                w.u8(
                    u8::try_from(c.len()).map_err(|_| CodecError::Unrepresentable {
                        field: "command list",
                    })?,
                )?;
                w.bytes(c)?;
            }
            if let Some(c) = &a.clusters {
                if c.servers > 15 || c.clients > 15 {
                    return Err(CodecError::Unrepresentable {
                        field: "cluster list",
                    });
                }
                w.u8(c.servers | (c.clients << 4))?;
                w.bytes(c.bytes)?;
            }
            if let Some(s) = &a.switch {
                w.u8(2)?;
                w.u8((s.contacts & 0x0f) | ((s.switch_type & 0x03) << 4))?;
                w.u8(s.contact_status)?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Commissioning<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let device_id = r.u8()?;
        let o = r.u8()?;
        let mut security = None;
        let mut key_present = false;
        let mut key_encrypted = false;
        let mut counter_present = false;
        if o & 0x80 != 0 {
            let e = r.u8()?;
            let level = e & 0x03;
            // §A.4.2.1.1.3: with no security capability the key fields
            // are ignored.
            let key_type = if level == 0 {
                KeyType::None
            } else {
                KeyType::from_raw((e >> 2) & 0x07).ok_or(CodecError::InvalidField {
                    field: "key type",
                    value: u32::from((e >> 2) & 0x07),
                })?
            };
            key_present = level != 0 && e & 0x20 != 0;
            key_encrypted = e & 0x40 != 0;
            counter_present = level != 0 && e & 0x80 != 0;
            security = Some(SecurityCapabilities {
                level,
                key_type,
                key_encryption: key_encrypted,
            });
        }
        let key = if key_present {
            let bytes = r.array::<16>()?;
            let mic = if key_encrypted {
                Some(r.array::<MIC_LEN>()?)
            } else {
                None
            };
            Some(KeyField { bytes, mic })
        } else {
            None
        };
        let outgoing_counter = if counter_present {
            Some(r.u32_le()?)
        } else {
            None
        };
        let application = if o & 0x04 != 0 {
            let a = r.u8()?;
            let manufacturer_id = if a & 0x01 != 0 {
                Some(r.u16_le()?)
            } else {
                None
            };
            let model_id = if a & 0x02 != 0 {
                Some(r.u16_le()?)
            } else {
                None
            };
            let commands = if a & 0x04 != 0 {
                let n = usize::from(r.u8()?);
                Some(r.bytes(n)?)
            } else {
                None
            };
            let clusters = if a & 0x08 != 0 {
                let len = r.u8()?;
                let servers = len & 0x0f;
                let clients = len >> 4;
                let bytes = r.bytes(2 * usize::from(servers + clients))?;
                Some(ClusterList {
                    servers,
                    clients,
                    bytes,
                })
            } else {
                None
            };
            let switch = if a & 0x10 != 0 {
                let len = usize::from(r.u8()?);
                let mut sub = r.sub(len)?;
                let cfg = sub.u8()?;
                let contact_status = sub.u8()?;
                Some(SwitchInfo {
                    contacts: cfg & 0x0f,
                    switch_type: (cfg >> 4) & 0x03,
                    contact_status,
                })
            } else {
                None
            };
            Some(ApplicationInfo {
                manufacturer_id,
                model_id,
                commands,
                clusters,
                switch,
                description_follows: a & 0x20 != 0,
            })
        } else {
            None
        };
        // §A.4.2.1.1: trailing fields of later versions are ignored.
        let _ = r.take_rest();
        Ok(Commissioning {
            device_id,
            sequence_number_capable: o & 0x01 != 0,
            rx_on_capable: o & 0x02 != 0,
            pan_id_request: o & 0x10 != 0,
            key_request: o & 0x20 != 0,
            fixed_location: o & 0x40 != 0,
            security,
            key,
            outgoing_counter,
            application,
        })
    }
}

/// GPD Commissioning Reply command payload (§A.4.2.1.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommissioningReply {
    /// PANId, when requested.
    pub pan_id: Option<PanId>,
    /// SecurityLevel the GPD is to use (raw).
    pub security_level: u8,
    /// KeyType the GPD is to use.
    pub key_type: KeyType,
    /// The delivered key; the MIC is present when TC-LK protected.
    pub key: Option<KeyField>,
    /// Frame Counter used for the key protection (present with the MIC).
    pub frame_counter: Option<u32>,
}

impl CommissioningReply {
    fn options(&self) -> u8 {
        let encrypted = self.key.is_some_and(|k| k.mic.is_some());
        u8::from(self.pan_id.is_some())
            | (u8::from(self.key.is_some()) << 1)
            | (u8::from(encrypted) << 2)
            | ((self.security_level & 0x03) << 3)
            | (self.key_type.raw() << 5)
    }
}

impl Encode for CommissioningReply {
    fn encoded_len(&self) -> usize {
        1 + if self.pan_id.is_some() { 2 } else { 0 }
            + self
                .key
                .map_or(0, |k| 16 + if k.mic.is_some() { MIC_LEN + 4 } else { 0 })
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.options())?;
        if let Some(p) = self.pan_id {
            w.u16_le(p.0)?;
        }
        if let Some(k) = &self.key {
            w.bytes(&k.bytes)?;
            if let Some(m) = &k.mic {
                w.bytes(m)?;
                w.u32_le(self.frame_counter.ok_or(CodecError::Unrepresentable {
                    field: "frame counter",
                })?)?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for CommissioningReply {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        let pan_id = if o & 0x01 != 0 {
            Some(PanId(r.u16_le()?))
        } else {
            None
        };
        let security_level = (o >> 3) & 0x03;
        let key_type = if security_level == 0 {
            KeyType::None
        } else {
            KeyType::from_raw(o >> 5).ok_or(CodecError::InvalidField {
                field: "key type",
                value: u32::from(o >> 5),
            })?
        };
        let mut frame_counter = None;
        let key = if o & 0x02 != 0 {
            let bytes = r.array::<16>()?;
            let mic = if o & 0x04 != 0 {
                let m = r.array::<MIC_LEN>()?;
                frame_counter = Some(r.u32_le()?);
                Some(m)
            } else {
                None
            };
            Some(KeyField { bytes, mic })
        } else {
            None
        };
        Ok(CommissioningReply {
            pan_id,
            security_level,
            key_type,
            key,
            frame_counter,
        })
    }
}

/// Converts a channel number (11–26) to the 4-bit form of the Channel
/// Request / Configuration payloads and back.
pub const fn channel_to_nibble(channel: u8) -> u8 {
    channel.saturating_sub(11) & 0x0f
}

/// The channel number of a 4-bit channel field.
pub const fn nibble_to_channel(nibble: u8) -> u8 {
    (nibble & 0x0f) + 11
}

/// GPD Channel Request command payload (§A.4.2.1.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelRequest {
    /// Rx channel (11–26) in the next attempt.
    pub next: u8,
    /// Rx channel in the second next attempt.
    pub second_next: u8,
}

impl Encode for ChannelRequest {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(channel_to_nibble(self.next) | (channel_to_nibble(self.second_next) << 4))
    }
}

impl<'a> Decode<'a> for ChannelRequest {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let v = r.u8()?;
        Ok(ChannelRequest {
            next: nibble_to_channel(v),
            second_next: nibble_to_channel(v >> 4),
        })
    }
}

/// GPD Channel Configuration command payload (§A.4.2.1.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelConfiguration {
    /// Operational channel (11–26).
    pub channel: u8,
    /// Basic: the sender does not support bidirectional operation.
    pub basic: bool,
}

impl Encode for ChannelConfiguration {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(channel_to_nibble(self.channel) | (u8::from(self.basic) << 4))
    }
}

impl<'a> Decode<'a> for ChannelConfiguration {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let v = r.u8()?;
        Ok(ChannelConfiguration {
            channel: nibble_to_channel(v),
            basic: v & 0x10 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commissioning_command_round_trips() {
        // Unidirectional, secured GPD with a clear OOB key and a counter,
        // application information with two commands and a cluster list.
        let clusters = [0x06, 0x00, 0x08, 0x00, 0x02, 0x04];
        let c = Commissioning {
            device_id: 0x02,
            sequence_number_capable: true,
            rx_on_capable: false,
            pan_id_request: false,
            key_request: false,
            fixed_location: true,
            security: Some(SecurityCapabilities {
                level: 0b10,
                key_type: KeyType::Individual,
                key_encryption: false,
            }),
            key: Some(KeyField {
                bytes: [0x42; 16],
                mic: None,
            }),
            outgoing_counter: Some(0x0000_0010),
            application: Some(ApplicationInfo {
                manufacturer_id: Some(0x1234),
                model_id: None,
                commands: Some(&[0x20, 0x21]),
                clusters: Some(ClusterList {
                    servers: 2,
                    clients: 1,
                    bytes: &clusters,
                }),
                switch: Some(SwitchInfo {
                    contacts: 2,
                    switch_type: 1,
                    contact_status: 0x01,
                }),
                description_follows: false,
            }),
        };
        let mut buf = [0u8; 64];
        let len = c.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, c.encoded_len());
        // Options: seq caps, app info, fixed location, extended options.
        assert_eq!(buf[1], 0x01 | 0x04 | 0x40 | 0x80);
        // Extended: level 0b10, key type 0b100, key present, counter present.
        assert_eq!(buf[2], 0b10 | (0b100 << 2) | 0x20 | 0x80);
        let back = Commissioning::decode_exact(&buf[..len]).unwrap();
        assert_eq!(back, c);
        let list = back.application.unwrap().clusters.unwrap();
        assert_eq!(
            list.server_ids().collect::<heapless::Vec<_, 4>>(),
            [ClusterId(0x0006), ClusterId(0x0008)]
        );
        assert_eq!(
            list.client_ids().collect::<heapless::Vec<_, 4>>(),
            [ClusterId(0x0402)]
        );
        assert_eq!(back.level_capabilities(), 0b10);
        // Bidirectional with a TC-LK protected key: the MIC follows the
        // key; trailing octets are ignored.
        let b = Commissioning {
            device_id: 0x07,
            sequence_number_capable: false,
            rx_on_capable: true,
            pan_id_request: true,
            key_request: true,
            fixed_location: false,
            security: Some(SecurityCapabilities {
                level: 0b11,
                key_type: KeyType::Individual,
                key_encryption: true,
            }),
            key: Some(KeyField {
                bytes: [0x11; 16],
                mic: Some([1, 2, 3, 4]),
            }),
            outgoing_counter: Some(5),
            application: None,
        };
        let len = b.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, 3 + 16 + 4 + 4);
        buf[len] = 0xEE;
        assert_eq!(Commissioning::decode_exact(&buf[..=len]).unwrap(), b);
        // No extended options and a key request: level 0b01 by default.
        let plain = Commissioning::decode_exact(&[0x02, 0x20]).unwrap();
        assert_eq!(plain.level_capabilities(), 0b01);
        assert!(plain.security.is_none());
        assert_eq!(
            Commissioning::decode_exact(&[0x02, 0x00])
                .unwrap()
                .level_capabilities(),
            0
        );
    }

    #[test]
    fn commissioning_reply_and_channel_commands() {
        let r = CommissioningReply {
            pan_id: Some(PanId(0x1A62)),
            security_level: 0b10,
            key_type: KeyType::Individual,
            key: Some(KeyField {
                bytes: [0x55; 16],
                mic: Some([9, 9, 9, 9]),
            }),
            frame_counter: Some(0x0000_0007),
        };
        let mut buf = [0u8; 32];
        let len = r.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, 1 + 2 + 16 + 4 + 4);
        assert_eq!(buf[0], 0x01 | 0x02 | 0x04 | (0b10 << 3) | (0b100 << 5));
        assert_eq!(CommissioningReply::decode_exact(&buf[..len]).unwrap(), r);
        // Options only: level and key type still carried.
        let bare = CommissioningReply {
            pan_id: None,
            security_level: 0b11,
            key_type: KeyType::NwkKey,
            key: None,
            frame_counter: None,
        };
        let len = bare.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, 1);
        assert_eq!(CommissioningReply::decode_exact(&buf[..len]).unwrap(), bare);
        let q = ChannelRequest {
            next: 15,
            second_next: 20,
        };
        let len = q.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x94]);
        assert_eq!(ChannelRequest::decode_exact(&buf[..len]).unwrap(), q);
        let cfg = ChannelConfiguration {
            channel: 11,
            basic: true,
        };
        let len = cfg.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x10]);
        assert_eq!(
            ChannelConfiguration::decode_exact(&buf[..len]).unwrap(),
            cfg
        );
    }
}
