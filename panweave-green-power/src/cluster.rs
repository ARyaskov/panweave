//! Green Power cluster (0x0021, GP Basic 1.1.2 §A.3): identifiers, the
//! sink (server) and proxy (client) attributes and the codecs of the
//! commands a Basic Proxy or Basic Combo generates or receives — GP
//! Notification, GP Commissioning Notification, GP Pairing, GP Proxy /
//! Sink Commissioning Mode, GP Response, GP Proxy / Sink Table Request
//! and Response.

use heapless::Vec;
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{ClusterId, Endpoint, ExtendedAddress, Key128, ProfileId, ShortAddress};

use crate::gpdf::{ApplicationId, GpdId, MIC_LEN, SecurityLevel};
use crate::security::KeyType;
use crate::sink_table::SinkEntry;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0021);
/// The Green Power EndPoint (§A.3.1).
pub const ENDPOINT: Endpoint = Endpoint(242);
/// The Green Power profile (§A.3.1).
pub const PROFILE: ProfileId = ProfileId(0xA1E0);
/// Cluster revision (Table 30).
pub const REVISION: u16 = 0x0002;

/// Client (proxy) attribute identifiers (Table 39), server (sink) ones
/// (Table 30) and the shared ones.
pub mod attr {
    /// `gpsMaxSinkTableEntries`.
    pub const MAX_SINK_TABLE_ENTRIES: u16 = 0x0000;
    /// `SinkTable`.
    pub const SINK_TABLE: u16 = 0x0001;
    /// `gpsCommunicationMode`.
    pub const COMMUNICATION_MODE: u16 = 0x0002;
    /// `gpsCommissioningExitMode`.
    pub const COMMISSIONING_EXIT_MODE: u16 = 0x0003;
    /// `gpsCommissioningWindow`.
    pub const COMMISSIONING_WINDOW: u16 = 0x0004;
    /// `gpsSecurityLevel`.
    pub const SECURITY_LEVEL: u16 = 0x0005;
    /// `gpsFunctionality`.
    pub const SINK_FUNCTIONALITY: u16 = 0x0006;
    /// `gpsActiveFunctionality`.
    pub const SINK_ACTIVE_FUNCTIONALITY: u16 = 0x0007;
    /// `gppMaxProxyTableEntries`.
    pub const MAX_PROXY_TABLE_ENTRIES: u16 = 0x0010;
    /// `ProxyTable`.
    pub const PROXY_TABLE: u16 = 0x0011;
    /// `gppNotificationRetryNumber`.
    pub const NOTIFICATION_RETRY_NUMBER: u16 = 0x0012;
    /// `gppNotificationRetryTimer`.
    pub const NOTIFICATION_RETRY_TIMER: u16 = 0x0013;
    /// `gppMaxSearchCounter`.
    pub const MAX_SEARCH_COUNTER: u16 = 0x0014;
    /// `gppBlockedGPDID`.
    pub const BLOCKED_GPD_ID: u16 = 0x0015;
    /// `gppFunctionality`.
    pub const FUNCTIONALITY: u16 = 0x0016;
    /// `gppActiveFunctionality`.
    pub const ACTIVE_FUNCTIONALITY: u16 = 0x0017;
    /// `gpSharedSecurityKeyType`.
    pub const SHARED_SECURITY_KEY_TYPE: u16 = 0x0020;
    /// `gpSharedSecurityKey`.
    pub const SHARED_SECURITY_KEY: u16 = 0x0021;
    /// `gpLinkKey`.
    pub const LINK_KEY: u16 = 0x0022;
}

/// `gppFunctionality` of a Basic Proxy (Table 43): GP feature, direct
/// communication, derived and pre-commissioned groupcast, lightweight
/// unicast, GP and CT-based commissioning, security levels 0b00 / 0b10 /
/// 0b11, GPD IEEE address.
pub const BASIC_PROXY_FUNCTIONALITY: u32 = (1 << 0)
    | (1 << 1)
    | (1 << 2)
    | (1 << 3)
    | (1 << 5)
    | (1 << 10)
    | (1 << 11)
    | (1 << 13)
    | (1 << 15)
    | (1 << 16)
    | (1 << 19);
/// `gppActiveFunctionality`: all supported functionality enabled
/// (§A.3.4.2.8).
pub const BASIC_PROXY_ACTIVE_FUNCTIONALITY: u32 = 0x00FF_FFFF;
/// `gpsFunctionality` of a Basic Combo sink (Table 28): GP feature,
/// direct communication, derived and pre-commissioned groupcast,
/// lightweight unicast, proximity and multi-hop commissioning, security
/// levels 0b00 / 0b10 / 0b11, GPD IEEE address.
pub const BASIC_SINK_FUNCTIONALITY: u32 = (1 << 0)
    | (1 << 1)
    | (1 << 2)
    | (1 << 3)
    | (1 << 5)
    | (1 << 9)
    | (1 << 10)
    | (1 << 13)
    | (1 << 15)
    | (1 << 16)
    | (1 << 19);
/// `gpsActiveFunctionality` (Table 29): GP feature on, the rest fixed.
pub const BASIC_SINK_ACTIVE_FUNCTIONALITY: u32 = 0x00FF_FFFF;

/// `gpsCommissioningExitMode` flags (Figure 22).
pub mod exit_mode {
    /// On CommissioningWindow expiration.
    pub const ON_WINDOW_EXPIRATION: u8 = 1 << 0;
    /// On first Pairing success.
    pub const ON_FIRST_PAIRING: u8 = 1 << 1;
    /// On GP Proxy Commissioning Mode (exit).
    pub const ON_EXIT_COMMAND: u8 = 1 << 2;
}

/// `gpsSecurityLevel` (Figure 23).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SinkSecurityLevel {
    /// Minimal GPD SecurityLevel (raw 2-bit value).
    pub minimum: u8,
    /// Protection with gpLinkKey required.
    pub link_key_protection: bool,
    /// Involve TC: no commissioning by the sink itself.
    pub involve_tc: bool,
}

impl SinkSecurityLevel {
    /// The certifiable default (§A.3.9.1 step 13e): level 0b10 with
    /// link-key protection, TC not involved.
    pub const DEFAULT: SinkSecurityLevel = SinkSecurityLevel {
        minimum: 0b10,
        link_key_protection: true,
        involve_tc: false,
    };

    /// Raw attribute value.
    pub const fn raw(self) -> u8 {
        (self.minimum & 0x03)
            | if self.link_key_protection { 0x04 } else { 0 }
            | if self.involve_tc { 0x08 } else { 0 }
    }

    /// From the raw attribute value.
    pub const fn from_raw(v: u8) -> Self {
        SinkSecurityLevel {
            minimum: v & 0x03,
            link_key_protection: v & 0x04 != 0,
            involve_tc: v & 0x08 != 0,
        }
    }
}

/// Commands generated by the proxy / received by the sink (Table 45).
pub mod client_cmd {
    use panweave_types::CommandId;
    /// GP Notification.
    pub const NOTIFICATION: CommandId = CommandId(0x00);
    /// GP Pairing Search.
    pub const PAIRING_SEARCH: CommandId = CommandId(0x01);
    /// GP Tunneling Stop.
    pub const TUNNELING_STOP: CommandId = CommandId(0x03);
    /// GP Commissioning Notification.
    pub const COMMISSIONING_NOTIFICATION: CommandId = CommandId(0x04);
    /// GP Sink Commissioning Mode.
    pub const SINK_COMMISSIONING_MODE: CommandId = CommandId(0x05);
    /// GP Pairing Configuration.
    pub const PAIRING_CONFIGURATION: CommandId = CommandId(0x09);
    /// GP Sink Table Request.
    pub const SINK_TABLE_REQUEST: CommandId = CommandId(0x0a);
    /// GP Proxy Table Response.
    pub const PROXY_TABLE_RESPONSE: CommandId = CommandId(0x0b);
}

/// Commands received by the proxy / generated by the sink (Table 44).
pub mod server_cmd {
    use panweave_types::CommandId;
    /// GP Notification Response.
    pub const NOTIFICATION_RESPONSE: CommandId = CommandId(0x00);
    /// GP Pairing.
    pub const PAIRING: CommandId = CommandId(0x01);
    /// GP Proxy Commissioning Mode.
    pub const PROXY_COMMISSIONING_MODE: CommandId = CommandId(0x02);
    /// GP Response.
    pub const RESPONSE: CommandId = CommandId(0x06);
    /// GP Sink Table Response.
    pub const SINK_TABLE_RESPONSE: CommandId = CommandId(0x0a);
    /// GP Proxy Table Request.
    pub const PROXY_TABLE_REQUEST: CommandId = CommandId(0x0b);
}

/// Sink communication mode (Table 27).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommunicationMode {
    /// 0b00: full unicast.
    FullUnicast,
    /// 0b01: groupcast to the derived group (DGroupID).
    DerivedGroupcast,
    /// 0b10: groupcast to a pre-commissioned group.
    CommissionedGroupcast,
    /// 0b11: lightweight unicast.
    LightweightUnicast,
}

impl CommunicationMode {
    /// Raw 2-bit value.
    pub const fn raw(self) -> u8 {
        match self {
            CommunicationMode::FullUnicast => 0b00,
            CommunicationMode::DerivedGroupcast => 0b01,
            CommunicationMode::CommissionedGroupcast => 0b10,
            CommunicationMode::LightweightUnicast => 0b11,
        }
    }

    /// From the raw value.
    pub const fn from_raw(v: u8) -> Self {
        match v & 0x03 {
            0b00 => CommunicationMode::FullUnicast,
            0b01 => CommunicationMode::DerivedGroupcast,
            0b10 => CommunicationMode::CommissionedGroupcast,
            _ => CommunicationMode::LightweightUnicast,
        }
    }
}

/// GPP-GPD link field (Figure 27): RSSI in 2 dBm steps from −109 dBm and
/// a 2-bit link quality.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GppGpdLink(pub u8);

impl GppGpdLink {
    /// Encodes an RSSI in dBm (capped to +8 … −109) and a link quality
    /// derived from the LQI (0–255 mapped to the four Table 32 classes).
    pub fn new(rssi_dbm: i8, lqi: u8) -> Self {
        let capped = rssi_dbm.clamp(-109, 8);
        let rssi = u8::try_from(i16::midpoint(i16::from(capped), 110)).unwrap_or(0) & 0x3F;
        let quality = lqi >> 6;
        GppGpdLink(rssi | (quality << 6))
    }

    /// Link quality (0 poor … 3 excellent).
    pub const fn quality(self) -> u8 {
        self.0 >> 6
    }

    /// RSSI in dBm.
    pub fn rssi_dbm(self) -> i16 {
        i16::from(self.0 & 0x3F) * 2 - 110
    }
}

/// Largest GPD command payload carried in a notification (the MAC MTU
/// minus the GPDF overhead).
pub const MAX_GPD_PAYLOAD: usize = 64;

/// GP Notification (§A.3.3.4.1) — the fields a Basic Proxy fills.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Notification<'a> {
    /// GPD identity (with the endpoint for IEEE identities).
    pub gpd: GpdId,
    /// Also Unicast / Also Derived Group / Also Commissioned Group.
    pub also_unicast: bool,
    /// Also Derived Group.
    pub also_derived_group: bool,
    /// Also Commissioned Group.
    pub also_commissioned_group: bool,
    /// SecurityLevel of the GPDF.
    pub security_level: SecurityLevel,
    /// Key type used for the security processing.
    pub key_type: KeyType,
    /// RxAfterTx copied from the GPDF.
    pub rx_after_tx: bool,
    /// gpTxQueueFull (always set by a Basic Proxy).
    pub tx_queue_full: bool,
    /// BidirectionalCapability (clear for a Basic Proxy).
    pub bidirectional: bool,
    /// GPD security frame counter (MAC sequence for unprotected frames).
    pub frame_counter: u32,
    /// GPD CommandID.
    pub command_id: u8,
    /// GPD Command payload.
    pub payload: &'a [u8],
    /// Proxy info: the proxy's short address and the GPP-GPD link.
    pub proxy: Option<(ShortAddress, GppGpdLink)>,
}

impl Notification<'_> {
    fn options(&self) -> u16 {
        u16::from(self.gpd.application_id().raw())
            | (u16::from(self.also_unicast) << 3)
            | (u16::from(self.also_derived_group) << 4)
            | (u16::from(self.also_commissioned_group) << 5)
            | (u16::from(self.security_level.raw()) << 6)
            | (u16::from(self.key_type.raw()) << 8)
            | (u16::from(self.rx_after_tx) << 11)
            | (u16::from(self.tx_queue_full) << 12)
            | (u16::from(self.bidirectional) << 13)
            | (u16::from(self.proxy.is_some()) << 14)
    }
}

impl Encode for Notification<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.gpd.encoded_len_with_endpoint()
            + 4
            + 1
            + 1
            + self.payload.len()
            + if self.proxy.is_some() { 3 } else { 0 }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.options())?;
        self.gpd.write_with_endpoint(w)?;
        w.u32_le(self.frame_counter)?;
        w.u8(self.command_id)?;
        w.u8(u8::try_from(self.payload.len())
            .map_err(|_| CodecError::Unrepresentable { field: "payload" })?)?;
        w.bytes(self.payload)?;
        if let Some((short, link)) = self.proxy {
            w.u16_le(short.0)?;
            w.u8(link.0)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Notification<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let options = r.u16_le()?;
        let app =
            ApplicationId::from_raw((options & 0x07) as u8).ok_or(CodecError::InvalidField {
                field: "application id",
                value: u32::from(options & 0x07),
            })?;
        let gpd = GpdId::read_with_endpoint(r, app)?;
        let frame_counter = r.u32_le()?;
        let command_id = r.u8()?;
        let len = r.u8()?;
        let payload = if len == 0xff {
            &[][..]
        } else {
            r.bytes(usize::from(len))?
        };
        let proxy = if options & (1 << 14) != 0 {
            Some((ShortAddress(r.u16_le()?), GppGpdLink(r.u8()?)))
        } else {
            None
        };
        Ok(Notification {
            gpd,
            also_unicast: options & (1 << 3) != 0,
            also_derived_group: options & (1 << 4) != 0,
            also_commissioned_group: options & (1 << 5) != 0,
            security_level: SecurityLevel::from_raw(((options >> 6) & 0x03) as u8).ok_or(
                CodecError::InvalidField {
                    field: "security level",
                    value: u32::from((options >> 6) & 0x03),
                },
            )?,
            key_type: KeyType::from_raw(((options >> 8) & 0x07) as u8).ok_or(
                CodecError::InvalidField {
                    field: "key type",
                    value: u32::from((options >> 8) & 0x07),
                },
            )?,
            rx_after_tx: options & (1 << 11) != 0,
            tx_queue_full: options & (1 << 12) != 0,
            bidirectional: options & (1 << 13) != 0,
            frame_counter,
            command_id,
            payload,
            proxy,
        })
    }
}

/// GP Commissioning Notification (§A.3.3.4.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommissioningNotification<'a> {
    /// GPD identity; `SrcId(0)` for Maintenance frames.
    pub gpd: GpdId,
    /// RxAfterTx copied from the GPDF.
    pub rx_after_tx: bool,
    /// SecurityLevel of the GPDF.
    pub security_level: SecurityLevel,
    /// Key type used, or the mapped default when processing failed.
    pub key_type: KeyType,
    /// SecurityProcessingFailed: the MIC is present and the command is
    /// still protected.
    pub security_failed: bool,
    /// BidirectionalCapability (clear for a Basic Proxy).
    pub bidirectional: bool,
    /// GPD security frame counter (MAC sequence for unprotected frames).
    pub frame_counter: u32,
    /// GPD CommandID.
    pub command_id: u8,
    /// GPD Command payload.
    pub payload: &'a [u8],
    /// Proxy info.
    pub proxy: Option<(ShortAddress, GppGpdLink)>,
    /// MIC of the GPDF when `security_failed`.
    pub mic: Option<[u8; MIC_LEN]>,
}

impl CommissioningNotification<'_> {
    fn options(&self) -> u16 {
        u16::from(self.gpd.application_id().raw())
            | (u16::from(self.rx_after_tx) << 3)
            | (u16::from(self.security_level.raw()) << 4)
            | (u16::from(self.key_type.raw()) << 6)
            | (u16::from(self.security_failed) << 9)
            | (u16::from(self.bidirectional) << 10)
            | (u16::from(self.proxy.is_some()) << 11)
    }
}

impl Encode for CommissioningNotification<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.gpd.encoded_len_with_endpoint()
            + 4
            + 1
            + 1
            + self.payload.len()
            + if self.proxy.is_some() { 3 } else { 0 }
            + if self.security_failed { MIC_LEN } else { 0 }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.options())?;
        self.gpd.write_with_endpoint(w)?;
        w.u32_le(self.frame_counter)?;
        w.u8(self.command_id)?;
        w.u8(u8::try_from(self.payload.len())
            .map_err(|_| CodecError::Unrepresentable { field: "payload" })?)?;
        w.bytes(self.payload)?;
        if let Some((short, link)) = self.proxy {
            w.u16_le(short.0)?;
            w.u8(link.0)?;
        }
        if self.security_failed {
            w.bytes(&self.mic.unwrap_or([0; MIC_LEN]))?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for CommissioningNotification<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let options = r.u16_le()?;
        let app =
            ApplicationId::from_raw((options & 0x07) as u8).ok_or(CodecError::InvalidField {
                field: "application id",
                value: u32::from(options & 0x07),
            })?;
        let gpd = GpdId::read_with_endpoint(r, app)?;
        let frame_counter = r.u32_le()?;
        let command_id = r.u8()?;
        let len = r.u8()?;
        let payload = if len == 0xff {
            &[][..]
        } else {
            r.bytes(usize::from(len))?
        };
        let proxy = if options & (1 << 11) != 0 {
            Some((ShortAddress(r.u16_le()?), GppGpdLink(r.u8()?)))
        } else {
            None
        };
        let security_failed = options & (1 << 9) != 0;
        let mic = if security_failed {
            let mut m = [0u8; MIC_LEN];
            m.copy_from_slice(r.bytes(MIC_LEN)?);
            Some(m)
        } else {
            None
        };
        Ok(CommissioningNotification {
            gpd,
            rx_after_tx: options & (1 << 3) != 0,
            security_level: SecurityLevel::from_raw(((options >> 4) & 0x03) as u8).ok_or(
                CodecError::InvalidField {
                    field: "security level",
                    value: u32::from((options >> 4) & 0x03),
                },
            )?,
            key_type: KeyType::from_raw(((options >> 6) & 0x07) as u8).ok_or(
                CodecError::InvalidField {
                    field: "key type",
                    value: u32::from((options >> 6) & 0x07),
                },
            )?,
            security_failed,
            bidirectional: options & (1 << 10) != 0,
            frame_counter,
            command_id,
            payload,
            proxy,
            mic,
        })
    }
}

/// Sink addressing of a GP Pairing (Table 38).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SinkAddress {
    /// Unicast (full or lightweight): the sink's IEEE and NWK addresses.
    Unicast(ExtendedAddress, ShortAddress),
    /// Groupcast (derived or commissioned): the group.
    Group(u16),
}

/// GP Pairing (§A.3.3.5.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pairing {
    /// GPD identity.
    pub gpd: GpdId,
    /// AddSink (a pairing is added; false removes one).
    pub add_sink: bool,
    /// RemoveGPD (the GPD leaves the network; no optional fields).
    pub remove_gpd: bool,
    /// Communication mode of the pairing.
    pub mode: CommunicationMode,
    /// GPD Fixed.
    pub gpd_fixed: bool,
    /// GPD MAC sequence number capabilities (incremental).
    pub sequence_number_capable: bool,
    /// SecurityLevel (raw; 0b01 is carried so that the proxy can refuse
    /// it, §A.3.5.2.3).
    pub security_level_raw: u8,
    /// SecurityKeyType.
    pub key_type: KeyType,
    /// Sink address when not removing the GPD.
    pub sink: Option<SinkAddress>,
    /// DeviceID (present when adding).
    pub device_id: Option<u8>,
    /// GPD security frame counter.
    pub frame_counter: Option<u32>,
    /// GPD key.
    pub key: Option<Key128>,
    /// Assigned alias.
    pub assigned_alias: Option<ShortAddress>,
    /// Groupcast radius.
    pub groupcast_radius: Option<u8>,
}

impl Pairing {
    /// SecurityLevel as an enum (`None` for the reserved 0b01).
    pub const fn security_level(&self) -> Option<SecurityLevel> {
        SecurityLevel::from_raw(self.security_level_raw)
    }

    fn options(&self) -> u32 {
        u32::from(self.gpd.application_id().raw())
            | (u32::from(self.add_sink) << 3)
            | (u32::from(self.remove_gpd) << 4)
            | (u32::from(self.mode.raw()) << 5)
            | (u32::from(self.gpd_fixed) << 7)
            | (u32::from(self.sequence_number_capable) << 8)
            | (u32::from(self.security_level_raw & 0x03) << 9)
            | (u32::from(self.key_type.raw()) << 11)
            | (u32::from(self.frame_counter.is_some()) << 14)
            | (u32::from(self.key.is_some()) << 15)
            | (u32::from(self.assigned_alias.is_some()) << 16)
            | (u32::from(self.groupcast_radius.is_some()) << 17)
    }
}

impl Encode for Pairing {
    fn encoded_len(&self) -> usize {
        3 + self.gpd.encoded_len_with_endpoint()
            + match self.sink {
                Some(SinkAddress::Unicast(..)) => 10,
                Some(SinkAddress::Group(_)) => 2,
                None => 0,
            }
            + usize::from(self.device_id.is_some())
            + if self.frame_counter.is_some() { 4 } else { 0 }
            + if self.key.is_some() { 16 } else { 0 }
            + if self.assigned_alias.is_some() { 2 } else { 0 }
            + usize::from(self.groupcast_radius.is_some())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let o = self.options();
        w.u8((o & 0xff) as u8)?;
        w.u8(((o >> 8) & 0xff) as u8)?;
        w.u8(((o >> 16) & 0xff) as u8)?;
        self.gpd.write_with_endpoint(w)?;
        match self.sink {
            Some(SinkAddress::Unicast(ieee, short)) => {
                w.u64_le(ieee.0)?;
                w.u16_le(short.0)?;
            }
            Some(SinkAddress::Group(g)) => w.u16_le(g)?,
            None => {}
        }
        if let Some(d) = self.device_id {
            w.u8(d)?;
        }
        if let Some(c) = self.frame_counter {
            w.u32_le(c)?;
        }
        if let Some(k) = &self.key {
            w.bytes(k.as_bytes())?;
        }
        if let Some(a) = self.assigned_alias {
            w.u16_le(a.0)?;
        }
        if let Some(r) = self.groupcast_radius {
            w.u8(r)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Pairing {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = u32::from(r.u8()?) | (u32::from(r.u8()?) << 8) | (u32::from(r.u8()?) << 16);
        let app = ApplicationId::from_raw((o & 0x07) as u8).ok_or(CodecError::InvalidField {
            field: "application id",
            value: o & 0x07,
        })?;
        let gpd = GpdId::read_with_endpoint(r, app)?;
        let add_sink = o & (1 << 3) != 0;
        let remove_gpd = o & (1 << 4) != 0;
        let mode = CommunicationMode::from_raw(((o >> 5) & 0x03) as u8);
        let sink = if remove_gpd {
            None
        } else {
            Some(match mode {
                CommunicationMode::FullUnicast | CommunicationMode::LightweightUnicast => {
                    let ieee = ExtendedAddress(r.u64_le()?);
                    SinkAddress::Unicast(ieee, ShortAddress(r.u16_le()?))
                }
                _ => SinkAddress::Group(r.u16_le()?),
            })
        };
        let adding = add_sink && !remove_gpd;
        let device_id = if adding { Some(r.u8()?) } else { None };
        let frame_counter = if adding && o & (1 << 14) != 0 {
            Some(r.u32_le()?)
        } else {
            None
        };
        let key = if adding && o & (1 << 15) != 0 {
            let mut k = [0u8; 16];
            k.copy_from_slice(r.bytes(16)?);
            Some(Key128::from_bytes(k))
        } else {
            None
        };
        let assigned_alias = if adding && o & (1 << 16) != 0 {
            Some(ShortAddress(r.u16_le()?))
        } else {
            None
        };
        let groupcast_radius = if adding && o & (1 << 17) != 0 {
            Some(r.u8()?)
        } else {
            None
        };
        Ok(Pairing {
            gpd,
            add_sink,
            remove_gpd,
            mode,
            gpd_fixed: o & (1 << 7) != 0,
            sequence_number_capable: o & (1 << 8) != 0,
            security_level_raw: ((o >> 9) & 0x03) as u8,
            key_type: KeyType::from_raw(((o >> 11) & 0x07) as u8).ok_or(
                CodecError::InvalidField {
                    field: "key type",
                    value: (o >> 11) & 0x07,
                },
            )?,
            sink,
            device_id,
            frame_counter,
            key,
            assigned_alias,
            groupcast_radius,
        })
    }
}

/// GP Proxy Commissioning Mode (§A.3.3.5.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProxyCommissioningMode {
    /// Enter (true) or exit (false) commissioning mode.
    pub enter: bool,
    /// Exit on the first GP Pairing.
    pub exit_on_first_pairing: bool,
    /// Exit on GP Proxy Commissioning Mode (exit).
    pub exit_on_command: bool,
    /// Send GP Commissioning Notifications in unicast to the originator.
    pub unicast: bool,
    /// Commissioning window in seconds, overriding the proxy default.
    pub window_secs: Option<u16>,
    /// Channel (always absent in this version).
    pub channel: Option<u8>,
}

impl Encode for ProxyCommissioningMode {
    fn encoded_len(&self) -> usize {
        1 + if self.window_secs.is_some() { 2 } else { 0 } + usize::from(self.channel.is_some())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let o = u8::from(self.enter)
            | (u8::from(self.window_secs.is_some()) << 1)
            | (u8::from(self.exit_on_first_pairing) << 2)
            | (u8::from(self.exit_on_command) << 3)
            | (u8::from(self.channel.is_some()) << 4)
            | (u8::from(self.unicast) << 5);
        w.u8(o)?;
        if let Some(s) = self.window_secs {
            w.u16_le(s)?;
        }
        if let Some(c) = self.channel {
            w.u8(c)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ProxyCommissioningMode {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        let window_secs = if o & 0x02 != 0 {
            Some(r.u16_le()?)
        } else {
            None
        };
        let channel = if o & 0x10 != 0 { Some(r.u8()?) } else { None };
        Ok(ProxyCommissioningMode {
            enter: o & 0x01 != 0,
            exit_on_first_pairing: o & 0x04 != 0,
            exit_on_command: o & 0x08 != 0,
            unicast: o & 0x20 != 0,
            window_secs,
            channel,
        })
    }
}

/// GP Sink Commissioning Mode (§A.3.3.4.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SinkCommissioningMode {
    /// Enter (true) or exit (false) commissioning mode.
    pub enter: bool,
    /// Involve GPM in security (must be clear in this version).
    pub gpm_security: bool,
    /// Involve GPM in pairing (must be clear in this version).
    pub gpm_pairing: bool,
    /// Involve proxies: send GP Proxy Commissioning Mode.
    pub involve_proxies: bool,
    /// GPM address for security (0xffff in this version).
    pub gpm_security_address: ShortAddress,
    /// GPM address for pairing (0xffff in this version).
    pub gpm_pairing_address: ShortAddress,
    /// Sink endpoint to commission (0xff: all).
    pub endpoint: u8,
}

impl SinkCommissioningMode {
    /// The GPM fields as this version requires them (§A.3.3.4.8.2).
    pub const fn gpm_fields_valid(&self) -> bool {
        !self.gpm_security
            && !self.gpm_pairing
            && self.gpm_security_address.0 == 0xffff
            && self.gpm_pairing_address.0 == 0xffff
    }
}

impl Encode for SinkCommissioningMode {
    fn encoded_len(&self) -> usize {
        6
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(u8::from(self.enter)
            | (u8::from(self.gpm_security) << 1)
            | (u8::from(self.gpm_pairing) << 2)
            | (u8::from(self.involve_proxies) << 3))?;
        w.u16_le(self.gpm_security_address.0)?;
        w.u16_le(self.gpm_pairing_address.0)?;
        w.u8(self.endpoint)
    }
}

impl<'a> Decode<'a> for SinkCommissioningMode {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        Ok(SinkCommissioningMode {
            enter: o & 0x01 != 0,
            gpm_security: o & 0x02 != 0,
            gpm_pairing: o & 0x04 != 0,
            involve_proxies: o & 0x08 != 0,
            gpm_security_address: ShortAddress(r.u16_le()?),
            gpm_pairing_address: ShortAddress(r.u16_le()?),
            endpoint: r.u8()?,
        })
    }
}

/// GP Response (§A.3.3.5.4): the GPD command a SelectedSender is to
/// transmit to the GPD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Response<'a> {
    /// GPD identity (`SrcId(0)` for Maintenance frames).
    pub gpd: GpdId,
    /// Transmit on endpoint match (IEEE GPDs).
    pub endpoint_match: bool,
    /// SelectedSender short address.
    pub selected_sender: ShortAddress,
    /// SelectedSender Tx channel (11–26).
    pub tx_channel: u8,
    /// GPD CommandID.
    pub command_id: u8,
    /// GPD Command payload (`None` = 0xff unspecified).
    pub payload: Option<&'a [u8]>,
}

impl Encode for Response<'_> {
    fn encoded_len(&self) -> usize {
        1 + 2
            + 1
            + self.gpd.encoded_len_with_endpoint()
            + 1
            + 1
            + self.payload.map_or(0, <[u8]>::len)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.gpd.application_id().raw() | (u8::from(self.endpoint_match) << 3))?;
        w.u16_le(self.selected_sender.0)?;
        w.u8(self.tx_channel.saturating_sub(11) & 0x0f)?;
        self.gpd.write_with_endpoint(w)?;
        w.u8(self.command_id)?;
        match self.payload {
            Some(p) => {
                w.u8(u8::try_from(p.len())
                    .ok()
                    .filter(|n| *n < 0xff)
                    .ok_or(CodecError::Unrepresentable { field: "payload" })?)?;
                w.bytes(p)
            }
            None => w.u8(0xff),
        }
    }
}

impl<'a> Decode<'a> for Response<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        let app = ApplicationId::from_raw(o & 0x07).ok_or(CodecError::InvalidField {
            field: "application id",
            value: u32::from(o & 0x07),
        })?;
        let selected_sender = ShortAddress(r.u16_le()?);
        let tx_channel = (r.u8()? & 0x0f) + 11;
        let gpd = GpdId::read_with_endpoint(r, app)?;
        let command_id = r.u8()?;
        let payload = match r.u8()? {
            0xff => None,
            n => Some(r.bytes(usize::from(n))?),
        };
        Ok(Response {
            gpd,
            endpoint_match: o & 0x08 != 0,
            selected_sender,
            tx_channel,
            command_id,
            payload,
        })
    }
}

/// Action of a GP Pairing Configuration (Table 34).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigurationAction {
    /// 0b000: no action.
    NoAction,
    /// 0b001: extend the Sink Table entry.
    Extend,
    /// 0b010: replace the Sink Table entry.
    Replace,
    /// 0b011: remove a pairing.
    RemovePairing,
    /// 0b100: remove the GPD.
    RemoveGpd,
    /// 0b101: application description.
    ApplicationDescription,
}

impl ConfigurationAction {
    /// Raw 3-bit value.
    pub const fn raw(self) -> u8 {
        match self {
            ConfigurationAction::NoAction => 0,
            ConfigurationAction::Extend => 1,
            ConfigurationAction::Replace => 2,
            ConfigurationAction::RemovePairing => 3,
            ConfigurationAction::RemoveGpd => 4,
            ConfigurationAction::ApplicationDescription => 5,
        }
    }

    /// From the raw value (0b110–0b111 reserved).
    pub const fn from_raw(v: u8) -> Option<Self> {
        Some(match v & 0x07 {
            0 => ConfigurationAction::NoAction,
            1 => ConfigurationAction::Extend,
            2 => ConfigurationAction::Replace,
            3 => ConfigurationAction::RemovePairing,
            4 => ConfigurationAction::RemoveGpd,
            5 => ConfigurationAction::ApplicationDescription,
            _ => return None,
        })
    }
}

/// The Number of paired endpoints field of a GP Pairing Configuration
/// (§A.3.3.4.6.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PairedEndpoints<'a> {
    /// 0x00 / 0xfd: not for local execution.
    None,
    /// 0xff: all matching endpoints.
    All,
    /// 0xfe: derived by the sink.
    Derived,
    /// An explicit list of local endpoints.
    List(&'a [u8]),
}

/// GP Pairing Configuration (§A.3.3.4.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PairingConfiguration<'a> {
    /// Action.
    pub action: ConfigurationAction,
    /// Send GP Pairing after handling.
    pub send_pairing: bool,
    /// The Sink Table entry carried (GPD ID, endpoint, DeviceID, group
    /// list, alias, radius, security).
    pub entry: SinkEntry,
    /// Paired local endpoints.
    pub paired_endpoints: PairedEndpoints<'a>,
    /// Application information (raw, in the §A.4.2.1.1.4 layout).
    pub application_info: Option<&'a [u8]>,
    /// Report descriptors of an Application description action: total
    /// number of reports, number in this command, descriptors.
    pub reports: Option<(u8, u8, &'a [u8])>,
}

impl PairingConfiguration<'_> {
    fn options(&self) -> u16 {
        let e = &self.entry;
        u16::from(e.gpd.application_id().raw())
            | (u16::from(e.mode.raw()) << 3)
            | (u16::from(e.sequence_number_capable) << 5)
            | (u16::from(e.rx_on_capable) << 6)
            | (u16::from(e.fixed_location) << 7)
            | (u16::from(e.assigned_alias.is_some()) << 8)
            | (u16::from(e.security.is_some()) << 9)
            | (u16::from(self.application_info.is_some()) << 10)
    }
}

impl Encode for PairingConfiguration<'_> {
    fn encoded_len(&self) -> usize {
        // The entry's own options are replaced by the command's.
        1 + self.entry.encoded_len()
            + 1
            + match self.paired_endpoints {
                PairedEndpoints::List(l) => l.len(),
                _ => 0,
            }
            + self.application_info.map_or(0, <[u8]>::len)
            + self.reports.map_or(0, |(_, _, d)| 2 + d.len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.action.raw() | (u8::from(self.send_pairing) << 3))?;
        w.u16_le(self.options())?;
        // The entry body: encode the whole entry and drop its options.
        let mut buf = [0u8; 80];
        let mut ew = Writer::new(&mut buf);
        self.entry.encode(&mut ew)?;
        let n = ew.position();
        w.bytes(buf.get(2..n).ok_or(CodecError::Unrepresentable {
            field: "sink table entry",
        })?)?;
        match self.paired_endpoints {
            PairedEndpoints::None => w.u8(0x00)?,
            PairedEndpoints::All => w.u8(0xff)?,
            PairedEndpoints::Derived => w.u8(0xfe)?,
            PairedEndpoints::List(l) => {
                let n = u8::try_from(l.len())
                    .ok()
                    .filter(|n| *n < 0xfd && *n > 0)
                    .ok_or(CodecError::Unrepresentable {
                        field: "paired endpoints",
                    })?;
                w.u8(n)?;
                w.bytes(l)?;
            }
        }
        if let Some(a) = self.application_info {
            w.bytes(a)?;
        }
        if let Some((total, count, descriptors)) = self.reports {
            w.u8(total)?;
            w.u8(count)?;
            w.bytes(descriptors)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for PairingConfiguration<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let actions = r.u8()?;
        let action =
            ConfigurationAction::from_raw(actions & 0x07).ok_or(CodecError::InvalidField {
                field: "action",
                value: u32::from(actions & 0x07),
            })?;
        let options = r.u16_le()?;
        let entry = SinkEntry::decode_body(options & 0x03ff, r)?;
        let paired_endpoints = match r.u8()? {
            0x00 | 0xfd => PairedEndpoints::None,
            0xff => PairedEndpoints::All,
            0xfe => PairedEndpoints::Derived,
            n => PairedEndpoints::List(r.bytes(usize::from(n))?),
        };
        let application_info = if options & (1 << 10) != 0 {
            Some(application_info_field(r)?)
        } else {
            None
        };
        let reports = if action == ConfigurationAction::ApplicationDescription {
            let total = r.u8()?;
            let count = r.u8()?;
            Some((total, count, r.take_rest()))
        } else {
            None
        };
        Ok(PairingConfiguration {
            action,
            send_pairing: actions & 0x08 != 0,
            entry,
            paired_endpoints,
            application_info,
            reports,
        })
    }
}

/// Consumes an Application information field (§A.4.2.1.1.4 layout) and
/// returns its raw octets.
fn application_info_field<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let start = r.consumed().len();
    let a = r.u8()?;
    if a & 0x01 != 0 {
        r.u16_le()?;
    }
    if a & 0x02 != 0 {
        r.u16_le()?;
    }
    if a & 0x04 != 0 {
        let n = usize::from(r.u8()?);
        r.bytes(n)?;
    }
    if a & 0x08 != 0 {
        let len = r.u8()?;
        r.bytes(2 * usize::from((len & 0x0f) + (len >> 4)))?;
    }
    if a & 0x10 != 0 {
        let n = usize::from(r.u8()?);
        r.bytes(n)?;
    }
    let end = r.consumed().len();
    r.consumed()
        .get(start..end)
        .ok_or(CodecError::Unrepresentable {
            field: "application information",
        })
}

/// GP Sink Table Request (§A.3.3.4.7): the same form as the Proxy Table
/// Request.
pub type SinkTableRequest = ProxyTableRequest;
/// GP Sink Table Response (§A.3.3.5.6): the same form as the Proxy Table
/// Response, with Sink Table entries.
pub type SinkTableResponse<'a> = ProxyTableResponse<'a>;

/// GP Proxy Table Request (§A.3.4.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ProxyTableRequest {
    /// By GPD ID (and endpoint).
    ByGpd(GpdId),
    /// By index.
    ByIndex(u8),
}

impl Encode for ProxyTableRequest {
    fn encoded_len(&self) -> usize {
        match self {
            ProxyTableRequest::ByGpd(g) => 1 + g.encoded_len_with_endpoint(),
            ProxyTableRequest::ByIndex(_) => 2,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            ProxyTableRequest::ByGpd(g) => {
                w.u8(g.application_id().raw())?;
                g.write_with_endpoint(w)
            }
            ProxyTableRequest::ByIndex(i) => {
                w.u8(0x08)?;
                w.u8(*i)
            }
        }
    }
}

impl<'a> Decode<'a> for ProxyTableRequest {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        match (o >> 3) & 0x03 {
            0b00 => {
                let app = ApplicationId::from_raw(o & 0x07).ok_or(CodecError::InvalidField {
                    field: "application id",
                    value: u32::from(o & 0x07),
                })?;
                Ok(ProxyTableRequest::ByGpd(GpdId::read_with_endpoint(r, app)?))
            }
            0b01 => Ok(ProxyTableRequest::ByIndex(r.u8()?)),
            v => Err(CodecError::InvalidField {
                field: "request type",
                value: u32::from(v),
            }),
        }
    }
}

/// Status of a GP Proxy Table Response (§A.3.4.4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TableStatus {
    /// SUCCESS.
    Success,
    /// NOT_FOUND.
    NotFound,
}

impl TableStatus {
    /// ZCL status octet.
    pub const fn raw(self) -> u8 {
        match self {
            TableStatus::Success => 0x00,
            TableStatus::NotFound => 0x8b,
        }
    }
}

/// GP Proxy Table Response header (§A.3.4.4.2); the entries follow in the
/// OTA format of §A.3.4.2.2.1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProxyTableResponse<'a> {
    /// Status.
    pub status: TableStatus,
    /// Total number of non-empty entries.
    pub total: u8,
    /// Start index (0xff for a request by GPD ID).
    pub start_index: u8,
    /// Number of entries included.
    pub count: u8,
    /// Encoded entries.
    pub entries: &'a [u8],
}

impl Encode for ProxyTableResponse<'_> {
    fn encoded_len(&self) -> usize {
        4 + self.entries.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u8(self.total)?;
        w.u8(self.start_index)?;
        w.u8(self.count)?;
        w.bytes(self.entries)
    }
}

impl<'a> Decode<'a> for ProxyTableResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = match r.u8()? {
            0x00 => TableStatus::Success,
            0x8b => TableStatus::NotFound,
            v => {
                return Err(CodecError::InvalidField {
                    field: "status",
                    value: u32::from(v),
                });
            }
        };
        Ok(ProxyTableResponse {
            status,
            total: r.u8()?,
            start_index: r.u8()?,
            count: r.u8()?,
            entries: r.take_rest(),
        })
    }
}

/// A fixed-capacity list of sink group entries (Table 26).
pub type GroupList = Vec<(u16, ShortAddress), 2>;
/// A fixed-capacity list of lightweight unicast sinks (Table 41).
pub type SinkList = Vec<(ExtendedAddress, ShortAddress), 2>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_round_trip() {
        let n = Notification {
            gpd: GpdId::SrcId(0x8765_4321),
            also_unicast: false,
            also_derived_group: true,
            also_commissioned_group: false,
            security_level: SecurityLevel::Mic,
            key_type: KeyType::NwkDerivedGroupKey,
            rx_after_tx: false,
            tx_queue_full: true,
            bidirectional: false,
            frame_counter: 2,
            command_id: 0x20,
            payload: &[],
            proxy: Some((ShortAddress(0x1234), GppGpdLink::new(-60, 200))),
        };
        let mut buf = [0u8; 32];
        let len = n.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, n.encoded_len());
        // Options: app 0, also derived (bit 4), level 0b10 (bits 6-7),
        // key type 0b011 (bits 8-10), queue full (12), proxy info (14).
        assert_eq!(&buf[..2], &[0x90, 0x53]);
        assert_eq!(&buf[2..6], &[0x21, 0x43, 0x65, 0x87]);
        assert_eq!(buf[10], 0x20);
        assert_eq!(buf[11], 0x00);
        let back = Notification::decode_exact(&buf[..len]).unwrap();
        assert_eq!(back, n);
        assert_eq!(back.proxy.unwrap().1.rssi_dbm(), -60);
        assert_eq!(back.proxy.unwrap().1.quality(), 3);
    }

    #[test]
    fn commissioning_notification_with_failed_security() {
        let c = CommissioningNotification {
            gpd: GpdId::Ieee {
                address: ExtendedAddress(0x1122_3344_5566_7788),
                endpoint: 1,
            },
            rx_after_tx: true,
            security_level: SecurityLevel::EncryptedMic,
            key_type: KeyType::None,
            security_failed: true,
            bidirectional: false,
            frame_counter: 0x4433_2211,
            command_id: 0xE0,
            payload: &[1, 2, 3],
            proxy: Some((ShortAddress(1), GppGpdLink(0xC0))),
            mic: Some([9, 8, 7, 6]),
        };
        let mut buf = [0u8; 48];
        let len = c.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, c.encoded_len());
        let back = CommissioningNotification::decode_exact(&buf[..len]).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn pairing_forms() {
        // Add a derived-groupcast pairing with a key and counter.
        let p = Pairing {
            gpd: GpdId::SrcId(0x0000_0042),
            add_sink: true,
            remove_gpd: false,
            mode: CommunicationMode::DerivedGroupcast,
            gpd_fixed: false,
            sequence_number_capable: true,
            security_level_raw: 0b10,
            key_type: KeyType::Individual,
            sink: Some(SinkAddress::Group(0x0042)),
            device_id: Some(0x02),
            frame_counter: Some(7),
            key: Some(Key128::from_bytes([0x11; 16])),
            assigned_alias: None,
            groupcast_radius: Some(0),
        };
        let mut buf = [0u8; 64];
        let len = p.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, p.encoded_len());
        assert_eq!(Pairing::decode_exact(&buf[..len]).unwrap(), p);
        // Remove GPD: nothing but options and the identity.
        let r = Pairing {
            add_sink: false,
            remove_gpd: true,
            sink: None,
            device_id: None,
            frame_counter: None,
            key: None,
            groupcast_radius: None,
            ..p.clone()
        };
        let len = r.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, 7);
        assert_eq!(Pairing::decode_exact(&buf[..len]).unwrap(), r);
        // Remove a lightweight unicast sink.
        let u = Pairing {
            add_sink: false,
            remove_gpd: false,
            mode: CommunicationMode::LightweightUnicast,
            sink: Some(SinkAddress::Unicast(ExtendedAddress(5), ShortAddress(6))),
            device_id: None,
            frame_counter: None,
            key: None,
            groupcast_radius: None,
            ..p
        };
        let len = u.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, 17);
        assert_eq!(Pairing::decode_exact(&buf[..len]).unwrap(), u);
    }

    #[test]
    fn sink_commissioning_mode_and_response() {
        let m = SinkCommissioningMode {
            enter: true,
            gpm_security: false,
            gpm_pairing: false,
            involve_proxies: true,
            gpm_security_address: ShortAddress(0xffff),
            gpm_pairing_address: ShortAddress(0xffff),
            endpoint: 0xff,
        };
        let mut buf = [0u8; 32];
        let len = m.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x09, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let back = SinkCommissioningMode::decode_exact(&buf[..len]).unwrap();
        assert_eq!(back, m);
        assert!(back.gpm_fields_valid());
        assert!(
            !SinkCommissioningMode::decode_exact(&[0x03, 0xff, 0xff, 0xff, 0xff, 1])
                .unwrap()
                .gpm_fields_valid()
        );
        let r = Response {
            gpd: GpdId::SrcId(0x42),
            endpoint_match: false,
            selected_sender: ShortAddress(0x1234),
            tx_channel: 15,
            command_id: 0xF0,
            payload: Some(&[0x50]),
        };
        let len = r.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, r.encoded_len());
        assert_eq!(
            &buf[..len],
            &[0x00, 0x34, 0x12, 0x04, 0x42, 0, 0, 0, 0xF0, 0x01, 0x50]
        );
        assert_eq!(Response::decode_exact(&buf[..len]).unwrap(), r);
        let bare = Response { payload: None, ..r };
        let len = bare.encode_to_slice(&mut buf).unwrap();
        assert_eq!(buf[len - 1], 0xff);
        assert_eq!(Response::decode_exact(&buf[..len]).unwrap(), bare);
        assert_eq!(SinkSecurityLevel::from_raw(0x06).raw(), 0x06);
        assert_eq!(SinkSecurityLevel::DEFAULT.raw(), 0x06);
    }

    #[test]
    fn pairing_configuration_round_trips() {
        use crate::proxy_table::SecurityOptions;
        let mut entry = SinkEntry::new(
            GpdId::SrcId(0x0000_1234),
            CommunicationMode::CommissionedGroupcast,
            0x02,
        );
        entry.sequence_number_capable = true;
        entry.groups.push((0x0010, ShortAddress(0xffff))).unwrap();
        entry.groupcast_radius = 4;
        entry.security = Some(SecurityOptions {
            level: SecurityLevel::Mic,
            key_type: KeyType::Individual,
            key: Some(Key128::from_bytes([0x77; 16])),
        });
        entry.frame_counter = 9;
        let app = [0x05, 0x34, 0x12, 0x02, 0x20, 0x21];
        let c = PairingConfiguration {
            action: ConfigurationAction::Extend,
            send_pairing: true,
            entry: entry.clone(),
            paired_endpoints: PairedEndpoints::List(&[1, 2]),
            application_info: Some(&app),
            reports: None,
        };
        let mut buf = [0u8; 96];
        let len = c.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, c.encoded_len());
        // Actions: extend + send pairing; Options: mode 0b10, seq caps,
        // security use, application info.
        assert_eq!(buf[0], 0x09);
        assert_eq!(
            u16::from_le_bytes([buf[1], buf[2]]),
            (0b10 << 3) | (1 << 5) | (1 << 9) | (1 << 10)
        );
        let back = PairingConfiguration::decode_exact(&buf[..len]).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.entry.groups[0], (0x0010, ShortAddress(0xffff)));
        // Remove GPD: nothing but the identity and the mandatory fields.
        let r = PairingConfiguration {
            action: ConfigurationAction::RemoveGpd,
            send_pairing: true,
            entry: SinkEntry::new(GpdId::SrcId(0x1234), CommunicationMode::FullUnicast, 0),
            paired_endpoints: PairedEndpoints::None,
            application_info: None,
            reports: None,
        };
        let len = r.encode_to_slice(&mut buf).unwrap();
        assert_eq!(len, 1 + 2 + 4 + 1 + 1 + 1);
        assert_eq!(PairingConfiguration::decode_exact(&buf[..len]).unwrap(), r);
        // Application description carries report descriptors.
        let d = PairingConfiguration {
            action: ConfigurationAction::ApplicationDescription,
            send_pairing: false,
            entry: SinkEntry::new(GpdId::SrcId(0x1234), CommunicationMode::FullUnicast, 0),
            paired_endpoints: PairedEndpoints::Derived,
            application_info: None,
            reports: Some((2, 1, &[0x00, 0x03, 0xAA, 0xBB, 0xCC])),
        };
        let len = d.encode_to_slice(&mut buf).unwrap();
        let back = PairingConfiguration::decode_exact(&buf[..len]).unwrap();
        assert_eq!(back, d);
        assert_eq!(back.paired_endpoints, PairedEndpoints::Derived);
        // A reserved action is refused.
        buf[0] = 0x06;
        assert!(PairingConfiguration::decode_exact(&buf[..len]).is_err());
    }

    #[test]
    fn commissioning_mode_and_table_request() {
        let m = ProxyCommissioningMode {
            enter: true,
            exit_on_first_pairing: true,
            exit_on_command: false,
            unicast: true,
            window_secs: Some(60),
            channel: None,
        };
        let mut buf = [0u8; 8];
        let len = m.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x27, 60, 0]);
        assert_eq!(
            ProxyCommissioningMode::decode_exact(&buf[..len]).unwrap(),
            m
        );
        let q = ProxyTableRequest::ByIndex(3);
        let len = q.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x08, 3]);
        assert_eq!(ProxyTableRequest::decode_exact(&buf[..len]).unwrap(), q);
        let q = ProxyTableRequest::ByGpd(GpdId::SrcId(1));
        let len = q.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x00, 1, 0, 0, 0]);
    }
}
