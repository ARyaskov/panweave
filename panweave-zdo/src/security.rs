//! Security client / server services (R23.2 §2.4.3.4, §2.4.4.4): the
//! ZDP frames of the key negotiation, authentication token, authentication
//! level, configuration, key update, decommission and challenge commands
//! and their message-local TLVs.
//!
//! Requests carry only TLVs (except Security_Get_Configuration_req);
//! responses carry a status octet followed by TLVs.

use heapless::Vec;
use panweave_codec::tlv::{Tlv, TlvSet, write_tlv};
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::ExtendedAddress;

use crate::zdp::ZdpStatus;

/// Encapsulation check for the security services: no message-local
/// encapsulation TLVs are defined.
fn no_encapsulation(_tag: u8) -> bool {
    false
}

/// Validates a TLV list per the general processing rules (Annex I.2.7),
/// mapping failures to the ZDP status of §2.4.6.
pub fn validate(tlvs: &[u8]) -> Result<TlvSet<'_>, ZdpStatus> {
    TlvSet::validate(tlvs, no_encapsulation).map_err(|_| ZdpStatus::InvalidTlv)
}

macro_rules! tlvs_only {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct $name<'a> {
            /// TLVs.
            pub tlvs: &'a [u8],
        }

        impl<'a> Decode<'a> for $name<'a> {
            fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
                Ok($name { tlvs: r.take_rest() })
            }
        }

        impl Encode for $name<'_> {
            fn encoded_len(&self) -> usize {
                self.tlvs.len()
            }

            fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
                w.bytes(self.tlvs)
            }
        }
    };
}

macro_rules! status_and_tlvs {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct $name<'a> {
            /// Status.
            pub status: ZdpStatus,
            /// TLVs.
            pub tlvs: &'a [u8],
        }

        impl<'a> Decode<'a> for $name<'a> {
            fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
                Ok($name {
                    status: ZdpStatus::from_raw(r.u8()?),
                    tlvs: r.take_rest(),
                })
            }
        }

        impl Encode for $name<'_> {
            fn encoded_len(&self) -> usize {
                1 + self.tlvs.len()
            }

            fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
                w.u8(self.status.raw())?;
                w.bytes(self.tlvs)
            }
        }
    };
}

tlvs_only!(
    /// Security_Start_Key_Negotiation_req (§2.4.3.4.1).
    StartKeyNegotiationReq
);
status_and_tlvs!(
    /// Security_Start_Key_Negotiation_rsp (§2.4.4.4.1).
    StartKeyNegotiationRsp
);
tlvs_only!(
    /// Security_Retrieve_Authentication_Token_req (§2.4.3.4.2).
    RetrieveAuthenticationTokenReq
);
status_and_tlvs!(
    /// Security_Retrieve_Authentication_Token_rsp (§2.4.4.4.2).
    RetrieveAuthenticationTokenRsp
);
tlvs_only!(
    /// Security_Get_Authentication_Level_req (§2.4.3.4.3).
    GetAuthenticationLevelReq
);
status_and_tlvs!(
    /// Security_Get_Authentication_Level_rsp (§2.4.4.4.3).
    GetAuthenticationLevelRsp
);
tlvs_only!(
    /// Security_Set_Configuration_req (§2.4.3.4.4).
    SetConfigurationReq
);
status_and_tlvs!(
    /// Security_Set_Configuration_rsp (§2.4.4.4.4).
    SetConfigurationRsp
);
status_and_tlvs!(
    /// Security_Get_Configuration_rsp (§2.4.4.4.5).
    GetConfigurationRsp
);
tlvs_only!(
    /// Security_Start_Key_Update_req (§2.4.3.4.6).
    StartKeyUpdateReq
);
tlvs_only!(
    /// Security_Decommission_req (§2.4.3.4.7).
    DecommissionReq
);
tlvs_only!(
    /// Security_Challenge_req (§2.4.3.4.8).
    ChallengeReq
);
status_and_tlvs!(
    /// Security_Challenge_rsp (§2.4.4.4.8): the status octet carries the
    /// SUCCESS / MISSING_TLV / NO_MATCH results named by §2.4.3.4.8.4
    /// and §4.6.3.8.4 (ADR-0009).
    ChallengeRsp
);

/// Security_Get_Configuration_req (§2.4.3.4.5): the global TLV
/// identifiers whose values are requested.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GetConfigurationReq<'a> {
    /// Requested TLV identifiers.
    pub tlv_ids: &'a [u8],
}

impl<'a> Decode<'a> for GetConfigurationReq<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let n = usize::from(r.u8()?);
        Ok(GetConfigurationReq {
            tlv_ids: r.bytes(n)?,
        })
    }
}

impl Encode for GetConfigurationReq<'_> {
    fn encoded_len(&self) -> usize {
        1 + self.tlv_ids.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(u8::try_from(self.tlv_ids.len())
            .map_err(|_| CodecError::Unrepresentable { field: "tlv count" })?)?;
        w.bytes(self.tlv_ids)
    }
}

/// Message-local TLV tags of the security services (each command defines
/// one local TLV with tag 0).
pub const LOCAL_TAG: u8 = 0;

/// Curve25519 Public Point local TLV (§2.4.3.4.1.2, §2.4.4.4.1.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicPoint {
    /// Device that generated the point.
    pub device: ExtendedAddress,
    /// The 32-octet point.
    pub point: [u8; 32],
}

impl PublicPoint {
    /// Encoded TLV length.
    pub const TLV_LEN: usize = 2 + 8 + 32;

    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Option<Self> {
        let mut r = Reader::new(t.value);
        let device = ExtendedAddress(r.u64_le().ok()?);
        let point = r.array::<32>().ok()?;
        Some(PublicPoint { device, point })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut v = [0u8; 40];
        v[..8].copy_from_slice(&self.device.to_le_bytes());
        v[8..].copy_from_slice(&self.point);
        write_tlv(w, LOCAL_TAG, &v)
    }

    /// Finds the single public point TLV of a request or response; `None`
    /// when absent or present more than once (§2.4.4.4.1.4 step 3).
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        let mut it = set.iter().filter(|t| t.tag == LOCAL_TAG);
        let first = it.next()?;
        if it.next().is_some() {
            return None;
        }
        Self::parse(&first)
    }
}

/// Selected Key Negotiation Method local TLV (§2.4.3.4.6.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SelectedKeyNegotiationMethod {
    /// Selected Key Negotiation Protocol Enumeration (Table 2-80).
    pub protocol: u8,
    /// Selected Pre-shared Secret Enumeration (Table 2-81).
    pub secret: u8,
    /// Sending device.
    pub sender: ExtendedAddress,
}

impl SelectedKeyNegotiationMethod {
    /// Protocol 0: reserved (Zigbee 3.0 mechanism).
    pub const PROTOCOL_ZIGBEE_3_0: u8 = 0;
    /// Protocol 1: SPEKE / Curve25519 / AES-MMO-128.
    pub const PROTOCOL_SPEKE_AES_MMO: u8 = 1;
    /// Protocol 2: SPEKE / Curve25519 / SHA-256.
    pub const PROTOCOL_SPEKE_SHA256: u8 = 2;
    /// Secret 0: symmetric authentication token.
    pub const SECRET_AUTH_TOKEN: u8 = 0;
    /// Secret 1: install-code derived link key.
    pub const SECRET_INSTALL_CODE: u8 = 1;
    /// Secret 2: variable-length pass code.
    pub const SECRET_PASSCODE: u8 = 2;
    /// Secret 3: basic authorization key.
    pub const SECRET_BASIC_AUTHORIZATION: u8 = 3;
    /// Secret 4: administrative authorization key.
    pub const SECRET_ADMIN_AUTHORIZATION: u8 = 4;
    /// Secret 255: anonymous well-known secret.
    pub const SECRET_ANONYMOUS: u8 = 255;

    /// Parses the TLV value.
    pub fn parse(t: &Tlv<'_>) -> Option<Self> {
        let mut r = Reader::new(t.value);
        Some(SelectedKeyNegotiationMethod {
            protocol: r.u8().ok()?,
            secret: r.u8().ok()?,
            sender: ExtendedAddress(r.u64_le().ok()?),
        })
    }

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut v = [0u8; 10];
        v[0] = self.protocol;
        v[1] = self.secret;
        v[2..].copy_from_slice(&self.sender.to_le_bytes());
        write_tlv(w, LOCAL_TAG, &v)
    }

    /// Finds the TLV.
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        set.find(LOCAL_TAG).and_then(|t| Self::parse(&t))
    }
}

/// Authentication Token ID local TLV (§2.4.3.4.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthenticationTokenId(pub u8);

impl AuthenticationTokenId {
    /// Writes the TLV.
    pub fn write(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        write_tlv(w, LOCAL_TAG, &[self.0])
    }

    /// Finds the TLV.
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        set.value(LOCAL_TAG)
            .and_then(|v| v.first())
            .map(|b| AuthenticationTokenId(*b))
    }
}

/// Target IEEE Address local TLV (§2.4.3.4.3.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TargetIeee(pub ExtendedAddress);

impl TargetIeee {
    /// Writes the TLV.
    pub fn write(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        write_tlv(w, LOCAL_TAG, &self.0.to_le_bytes())
    }

    /// Finds the TLV.
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        let v = set.value(LOCAL_TAG)?;
        Reader::new(v)
            .u64_le()
            .ok()
            .map(|a| TargetIeee(ExtendedAddress(a)))
    }
}

/// Device Authentication Level local TLV (§2.4.4.4.3.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceAuthenticationLevel {
    /// Device inquired about.
    pub device: ExtendedAddress,
    /// Initial join method (Table 2-121).
    pub initial_join_method: u8,
    /// Active link key type (Table 2-121).
    pub active_link_key_type: u8,
}

impl DeviceAuthenticationLevel {
    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut v = [0u8; 10];
        v[..8].copy_from_slice(&self.device.to_le_bytes());
        v[8] = self.initial_join_method;
        v[9] = self.active_link_key_type;
        write_tlv(w, LOCAL_TAG, &v)
    }

    /// Finds the TLV.
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        let v = set.value(LOCAL_TAG)?;
        let mut r = Reader::new(v);
        Some(DeviceAuthenticationLevel {
            device: ExtendedAddress(r.u64_le().ok()?),
            initial_join_method: r.u8().ok()?,
            active_link_key_type: r.u8().ok()?,
        })
    }
}

/// Maximum EUI-64 entries handled in a Device EUI64 List TLV.
pub const MAX_EUI64_LIST: usize = 8;

/// Device EUI64 List local TLV (§2.4.3.4.7.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Eui64List(pub Vec<ExtendedAddress, MAX_EUI64_LIST>);

impl Eui64List {
    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut v = [0u8; 1 + 8 * MAX_EUI64_LIST];
        v[0] = u8::try_from(self.0.len()).unwrap_or(u8::MAX);
        for (i, a) in self.0.iter().enumerate() {
            v[1 + 8 * i..9 + 8 * i].copy_from_slice(&a.to_le_bytes());
        }
        write_tlv(w, LOCAL_TAG, &v[..=8 * self.0.len()])
    }

    /// Finds the TLV (entries beyond the capacity are ignored).
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        let v = set.value(LOCAL_TAG)?;
        let mut r = Reader::new(v);
        let n = r.u8().ok()?;
        let mut out = Vec::new();
        for _ in 0..n {
            let a = ExtendedAddress(r.u64_le().ok()?);
            if out.push(a).is_err() {
                break;
            }
        }
        Some(Eui64List(out))
    }
}

/// Processing Status local TLV of Security_Set_Configuration_rsp
/// (§2.4.4.4.4.1.1): (tag, status) pairs.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProcessingStatus(pub Vec<(u8, ZdpStatus), 8>);

impl ProcessingStatus {
    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut v = [0u8; 17];
        v[0] = u8::try_from(self.0.len()).unwrap_or(u8::MAX);
        for (i, (tag, status)) in self.0.iter().enumerate() {
            v[1 + 2 * i] = *tag;
            v[2 + 2 * i] = status.raw();
        }
        write_tlv(w, LOCAL_TAG, &v[..=2 * self.0.len()])
    }

    /// Finds the TLV.
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        let v = set.value(LOCAL_TAG)?;
        let mut r = Reader::new(v);
        let n = r.u8().ok()?;
        let mut out = Vec::new();
        for _ in 0..n {
            let tag = r.u8().ok()?;
            let status = ZdpStatus::from_raw(r.u8().ok()?);
            if out.push((tag, status)).is_err() {
                break;
            }
        }
        Some(ProcessingStatus(out))
    }
}

/// APS Frame Counter Challenge local TLV (§2.4.3.4.8.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameCounterChallenge {
    /// Device generating the challenge.
    pub sender: ExtendedAddress,
    /// Random challenge value.
    pub challenge: u64,
}

impl FrameCounterChallenge {
    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut v = [0u8; 16];
        v[..8].copy_from_slice(&self.sender.to_le_bytes());
        v[8..].copy_from_slice(&self.challenge.to_le_bytes());
        write_tlv(w, LOCAL_TAG, &v)
    }

    /// Finds the TLV.
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        let v = set.value(LOCAL_TAG)?;
        let mut r = Reader::new(v);
        Some(FrameCounterChallenge {
            sender: ExtendedAddress(r.u64_le().ok()?),
            challenge: r.u64_le().ok()?,
        })
    }
}

/// APS Frame Counter Response local TLV (§2.4.4.4.8.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameCounterResponse {
    /// Responding device.
    pub responder: ExtendedAddress,
    /// The challenge received.
    pub challenge: u64,
    /// Responder's current outgoing APS frame counter.
    pub aps_frame_counter: u32,
    /// Frame counter used to compute the MIC.
    pub challenge_frame_counter: u32,
    /// 64-bit MIC over tag, length and the preceding fields except the
    /// challenge frame counter.
    pub mic: [u8; 8],
}

impl FrameCounterResponse {
    /// Length of the TLV value.
    pub const VALUE_LEN: usize = 8 + 8 + 4 + 4 + 8;

    /// Writes the TLV.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut v = [0u8; Self::VALUE_LEN];
        v[..8].copy_from_slice(&self.responder.to_le_bytes());
        v[8..16].copy_from_slice(&self.challenge.to_le_bytes());
        v[16..20].copy_from_slice(&self.aps_frame_counter.to_le_bytes());
        v[20..24].copy_from_slice(&self.challenge_frame_counter.to_le_bytes());
        v[24..].copy_from_slice(&self.mic);
        write_tlv(w, LOCAL_TAG, &v)
    }

    /// Finds the TLV.
    pub fn find(set: &TlvSet<'_>) -> Option<Self> {
        let v = set.value(LOCAL_TAG)?;
        let mut r = Reader::new(v);
        Some(FrameCounterResponse {
            responder: ExtendedAddress(r.u64_le().ok()?),
            challenge: r.u64_le().ok()?,
            aps_frame_counter: r.u32_le().ok()?,
            challenge_frame_counter: r.u32_le().ok()?,
            mic: r.array::<8>().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_point_round_trip_and_duplicates() {
        let p = PublicPoint {
            device: ExtendedAddress(0x1122_3344_5566_7788),
            point: [7u8; 32],
        };
        let mut buf = [0u8; 96];
        let mut w = Writer::new(&mut buf);
        p.write(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, PublicPoint::TLV_LEN);
        let set = validate(&buf[..n]).unwrap();
        assert_eq!(PublicPoint::find(&set), Some(p));
        // Two points: rejected.
        let mut w = Writer::new(&mut buf);
        p.write(&mut w).unwrap();
        let _ = write_tlv(&mut w, 1, &[0; 40]);
        let n = w.position();
        let set = validate(&buf[..n]).unwrap();
        assert_eq!(PublicPoint::find(&set), Some(p));
        let rsp = StartKeyNegotiationRsp {
            status: ZdpStatus::Success,
            tlvs: &buf[..n],
        };
        let mut out = [0u8; 100];
        let m = rsp.encode_to_slice(&mut out).unwrap();
        let back = StartKeyNegotiationRsp::decode_exact(&out[..m]).unwrap();
        assert_eq!(back, rsp);
    }

    #[test]
    fn selected_method_and_lists() {
        let m = SelectedKeyNegotiationMethod {
            protocol: SelectedKeyNegotiationMethod::PROTOCOL_SPEKE_AES_MMO,
            secret: SelectedKeyNegotiationMethod::SECRET_ANONYMOUS,
            sender: ExtendedAddress(9),
        };
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        m.write(&mut w).unwrap();
        let n = w.position();
        assert_eq!(
            SelectedKeyNegotiationMethod::find(&validate(&buf[..n]).unwrap()),
            Some(m)
        );
        let mut list = Eui64List(Vec::new());
        list.0.push(ExtendedAddress(1)).unwrap();
        list.0.push(ExtendedAddress(2)).unwrap();
        let mut w = Writer::new(&mut buf);
        list.write(&mut w).unwrap();
        let n = w.position();
        assert_eq!(Eui64List::find(&validate(&buf[..n]).unwrap()), Some(list));
        let mut ps = ProcessingStatus::default();
        ps.0.push((75, ZdpStatus::Success)).unwrap();
        let mut w = Writer::new(&mut buf);
        ps.write(&mut w).unwrap();
        let n = w.position();
        assert_eq!(
            ProcessingStatus::find(&validate(&buf[..n]).unwrap()),
            Some(ps)
        );
        let req = GetConfigurationReq { tlv_ids: &[66, 75] };
        let m = req.encode_to_slice(&mut buf).unwrap();
        assert_eq!(GetConfigurationReq::decode_exact(&buf[..m]).unwrap(), req);
    }
}
