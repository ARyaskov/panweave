//! The Zigbee Direct Commissioning Service (ZD 1.1 §7.7.2): the local
//! TLVs of Table 27 / Table 44, the payloads of the Form Network, Join
//! Network, Permit Joining, Leave Network, Commissioning Status, Manage
//! Joiners, Identify and Finding & Binding characteristics, and the ZDD
//! side that turns writes into stack operations through the [`Zdd`]
//! trait and reports through Commissioning Status notifications.

use heapless::Vec;
use panweave_codec::Writer;
use panweave_codec::tlv::{TlvSet, write_tlv};
use panweave_types::{
    ChannelMask, ChannelPage, Endpoint, ExtendedAddress, Key128, PanId, ShortAddress,
};

use crate::auth::Level;

/// Largest characteristic payload handled here.
pub const MAX_PAYLOAD: usize = 128;

/// Commissioning TLV identifiers (Table 27).
pub mod tag {
    /// Extended PAN ID (EUI-64).
    pub const EXTENDED_PAN_ID: u8 = 0x00;
    /// Short PAN ID.
    pub const SHORT_PAN_ID: u8 = 0x01;
    /// Network Channel (Channel List Structure).
    pub const NETWORK_CHANNEL: u8 = 0x02;
    /// Network Key.
    pub const NETWORK_KEY: u8 = 0x03;
    /// Link Key (flags + key).
    pub const LINK_KEY: u8 = 0x04;
    /// Device Type.
    pub const DEVICE_TYPE: u8 = 0x05;
    /// NWK Address.
    pub const NWK_ADDRESS: u8 = 0x06;
    /// Joining Method.
    pub const JOINING_METHOD: u8 = 0x07;
    /// IEEE Address.
    pub const IEEE_ADDRESS: u8 = 0x08;
    /// Trust Center Address.
    pub const TRUST_CENTER_ADDRESS: u8 = 0x09;
    /// Network Status Map.
    pub const NETWORK_STATUS_MAP: u8 = 0x0a;
    /// NWK Update ID.
    pub const NWK_UPDATE_ID: u8 = 0x0b;
    /// NWK Active Key Seq Number.
    pub const ACTIVE_KEY_SEQUENCE: u8 = 0x0c;
    /// Admin Key.
    pub const ADMIN_KEY: u8 = 0x0d;
    /// Status Code (domain, status).
    pub const STATUS_CODE: u8 = 0x0e;
    /// Extended Status Code.
    pub const EXTENDED_STATUS_CODE: u8 = 0x0f;
}

/// Manage Joiners TLV identifiers (Table 44).
pub mod joiners_tag {
    /// Provisional Link Key.
    pub const PROVISIONAL_LINK_KEY: u8 = 0x00;
    /// IEEE Address.
    pub const IEEE_ADDRESS: u8 = 0x01;
    /// Manage Joiners Command.
    pub const COMMAND: u8 = 0x02;
}

/// Device Type TLV values (Table 28).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DeviceType {
    /// Zigbee coordinator.
    Coordinator,
    /// Zigbee router.
    Router,
    /// Zigbee end device.
    EndDevice,
}

impl DeviceType {
    /// Raw value.
    pub const fn raw(self) -> u8 {
        match self {
            DeviceType::Coordinator => 0,
            DeviceType::Router => 1,
            DeviceType::EndDevice => 2,
        }
    }
}

/// Joining Method TLV values (Table 29).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoiningMethod {
    /// MAC association.
    Association,
    /// Secure NWK rejoin with the key.
    Rejoin,
    /// Out-of-band commissioning with the provided parameters.
    OutOfBand,
}

impl JoiningMethod {
    /// Raw value.
    pub const fn raw(self) -> u8 {
        match self {
            JoiningMethod::Association => 0,
            JoiningMethod::Rejoin => 1,
            JoiningMethod::OutOfBand => 2,
        }
    }

    const fn from_raw(v: u8) -> Option<Self> {
        match v {
            0 => Some(JoiningMethod::Association),
            1 => Some(JoiningMethod::Rejoin),
            2 => Some(JoiningMethod::OutOfBand),
            _ => None,
        }
    }
}

/// Joined Status of the Network Status Map (Table 30).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinedStatus {
    /// Not commissioned.
    NotCommissioned,
    /// Commissioning in progress.
    InProgress,
    /// Commissioned.
    Commissioned,
}

/// Network Status Map TLV (Table 30).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkStatus {
    /// Joined Status.
    pub joined: JoinedStatus,
    /// The network is open for joining.
    pub open: bool,
    /// Centralized (true) or distributed security.
    pub centralized: bool,
}

impl NetworkStatus {
    /// Raw octet.
    pub const fn raw(self) -> u8 {
        let j = match self.joined {
            JoinedStatus::NotCommissioned => 0,
            JoinedStatus::InProgress => 1,
            JoinedStatus::Commissioned => 2,
        };
        j | if self.open { 0x08 } else { 0 } | if self.centralized { 0x10 } else { 0 }
    }

    /// From the raw octet.
    pub const fn from_raw(v: u8) -> Option<Self> {
        let joined = match v & 0x07 {
            0 => JoinedStatus::NotCommissioned,
            1 => JoinedStatus::InProgress,
            2 => JoinedStatus::Commissioned,
            _ => return None,
        };
        Some(NetworkStatus {
            joined,
            open: v & 0x08 != 0,
            centralized: v & 0x10 != 0,
        })
    }
}

/// Status Code TLV domains (Table 33).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Domain {
    /// General.
    General,
    /// Form Network.
    FormNetwork,
    /// Join Network.
    JoinNetwork,
    /// Permit Joining.
    PermitJoining,
    /// Leave Network.
    LeaveNetwork,
    /// Manage Joiners.
    ManageJoiners,
    /// Identify.
    Identify,
    /// Finding & Binding.
    FindingBinding,
}

impl Domain {
    /// Raw value.
    pub const fn raw(self) -> u8 {
        match self {
            Domain::General => 0,
            Domain::FormNetwork => 1,
            Domain::JoinNetwork => 2,
            Domain::PermitJoining => 3,
            Domain::LeaveNetwork => 4,
            Domain::ManageJoiners => 5,
            Domain::Identify => 6,
            Domain::FindingBinding => 7,
        }
    }
}

/// Status code SUCCESS.
pub const STATUS_SUCCESS: u8 = 0;
/// Generic failure status used when no more specific code applies.
pub const STATUS_FAILURE: u8 = 1;

/// A link key handed over with its flags (Table 35).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkKey {
    /// Unique (true) or global key.
    pub unique: bool,
    /// Provisional (true) or permanent key.
    pub provisional: bool,
    /// The key.
    pub key: Key128,
}

/// Parameters of a Form Network write (Table 36).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FormNetwork {
    /// Distributed security when the Trust Center Address is all ones.
    pub distributed: bool,
    /// Extended PAN ID.
    pub extended_pan_id: Option<ExtendedAddress>,
    /// Short PAN ID.
    pub pan_id: Option<PanId>,
    /// Channels (page 0) to form on; one channel skips the energy scan.
    pub channels: Option<ChannelMask>,
    /// Network key.
    pub network_key: Option<Key128>,
    /// Link key.
    pub link_key: Option<LinkKey>,
    /// NWK address (distributed networks).
    pub nwk_address: Option<ShortAddress>,
    /// NWK update ID.
    pub update_id: Option<u8>,
    /// Admin key.
    pub admin_key: Option<Key128>,
}

/// Parameters of a Join Network write (§7.7.2.7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JoinNetwork {
    /// Joining method.
    pub method: JoiningMethod,
    /// Extended PAN ID.
    pub extended_pan_id: Option<ExtendedAddress>,
    /// Short PAN ID.
    pub pan_id: Option<PanId>,
    /// Channels.
    pub channels: Option<ChannelMask>,
    /// Network key (rejoin / out-of-band).
    pub network_key: Option<Key128>,
    /// Link key.
    pub link_key: Option<LinkKey>,
    /// NWK address (out-of-band).
    pub nwk_address: Option<ShortAddress>,
    /// Trust Center address (all ones for distributed).
    pub trust_center: Option<ExtendedAddress>,
    /// NWK update ID.
    pub update_id: Option<u8>,
    /// Active key sequence number.
    pub key_sequence: Option<u8>,
    /// Admin key.
    pub admin_key: Option<Key128>,
}

fn write_link_key(w: &mut Writer<'_>, lk: &LinkKey) -> Result<(), panweave_codec::CodecError> {
    let mut v = [0u8; 17];
    v[0] = u8::from(lk.unique) | (u8::from(lk.provisional) << 1);
    v[1..].copy_from_slice(lk.key.as_bytes());
    write_tlv(w, tag::LINK_KEY, &v)
}

impl FormNetwork {
    /// Encodes a Form Network write (ZVD side); returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, panweave_codec::CodecError> {
        let mut w = Writer::new(out);
        if let Some(e) = self.extended_pan_id {
            write_tlv(&mut w, tag::EXTENDED_PAN_ID, &e.0.to_le_bytes())?;
        }
        if let Some(p) = self.pan_id {
            write_tlv(&mut w, tag::SHORT_PAN_ID, &p.0.to_le_bytes())?;
        }
        if let Some(c) = self.channels {
            write_channels(&mut w, c)?;
        }
        if let Some(k) = &self.network_key {
            write_tlv(&mut w, tag::NETWORK_KEY, k.as_bytes())?;
        }
        if let Some(lk) = &self.link_key {
            write_link_key(&mut w, lk)?;
        }
        if let Some(a) = self.nwk_address {
            write_tlv(&mut w, tag::NWK_ADDRESS, &a.0.to_le_bytes())?;
        }
        if self.distributed {
            write_tlv(&mut w, tag::TRUST_CENTER_ADDRESS, &[0xff; 8])?;
        }
        if let Some(u) = self.update_id {
            write_tlv(&mut w, tag::NWK_UPDATE_ID, &[u])?;
        }
        if let Some(k) = &self.admin_key {
            write_tlv(&mut w, tag::ADMIN_KEY, k.as_bytes())?;
        }
        Ok(w.position())
    }
}

impl JoinNetwork {
    /// Encodes a Join Network write (ZVD side); returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, panweave_codec::CodecError> {
        let mut w = Writer::new(out);
        if let Some(e) = self.extended_pan_id {
            write_tlv(&mut w, tag::EXTENDED_PAN_ID, &e.0.to_le_bytes())?;
        }
        if let Some(p) = self.pan_id {
            write_tlv(&mut w, tag::SHORT_PAN_ID, &p.0.to_le_bytes())?;
        }
        if let Some(c) = self.channels {
            write_channels(&mut w, c)?;
        }
        if let Some(k) = &self.network_key {
            write_tlv(&mut w, tag::NETWORK_KEY, k.as_bytes())?;
        }
        if let Some(lk) = &self.link_key {
            write_link_key(&mut w, lk)?;
        }
        if let Some(a) = self.nwk_address {
            write_tlv(&mut w, tag::NWK_ADDRESS, &a.0.to_le_bytes())?;
        }
        write_tlv(&mut w, tag::JOINING_METHOD, &[self.method.raw()])?;
        if let Some(t) = self.trust_center {
            write_tlv(&mut w, tag::TRUST_CENTER_ADDRESS, &t.0.to_le_bytes())?;
        }
        if let Some(u) = self.update_id {
            write_tlv(&mut w, tag::NWK_UPDATE_ID, &[u])?;
        }
        if let Some(s) = self.key_sequence {
            write_tlv(&mut w, tag::ACTIVE_KEY_SEQUENCE, &[s])?;
        }
        if let Some(k) = &self.admin_key {
            write_tlv(&mut w, tag::ADMIN_KEY, k.as_bytes())?;
        }
        Ok(w.position())
    }
}

/// Manage Joiners commands (Table 45).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ManageJoiners {
    /// Drop every provisional link key.
    DropAll,
    /// Add (or replace) a joiner's provisional link key.
    Add {
        /// Joiner.
        ieee: ExtendedAddress,
        /// Provisional link key.
        key: Key128,
    },
    /// Remove a joiner's provisional link key.
    Remove {
        /// Joiner.
        ieee: ExtendedAddress,
    },
}

/// Parse errors of characteristic payloads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ParseError {
    /// Malformed TLVs or fixed fields.
    Malformed,
    /// A required TLV is missing.
    MissingTlv(u8),
    /// A TLV is invalid for the operation.
    InvalidTlv(u8),
    /// A value is out of range.
    OutOfRange(u8),
}

fn eui64(set: &TlvSet<'_>, tag: u8) -> Result<Option<ExtendedAddress>, ParseError> {
    match set.find(tag) {
        None => Ok(None),
        Some(t) => {
            let b: [u8; 8] = t.value.try_into().map_err(|_| ParseError::Malformed)?;
            Ok(Some(ExtendedAddress(u64::from_le_bytes(b))))
        }
    }
}

fn u16_le(set: &TlvSet<'_>, tag: u8) -> Result<Option<u16>, ParseError> {
    match set.find(tag) {
        None => Ok(None),
        Some(t) => {
            let b: [u8; 2] = t.value.try_into().map_err(|_| ParseError::Malformed)?;
            Ok(Some(u16::from_le_bytes(b)))
        }
    }
}

fn u8_value(set: &TlvSet<'_>, tag: u8) -> Result<Option<u8>, ParseError> {
    match set.find(tag) {
        None => Ok(None),
        Some(t) => match t.value {
            [v] => Ok(Some(*v)),
            _ => Err(ParseError::Malformed),
        },
    }
}

fn key(set: &TlvSet<'_>, tag: u8) -> Result<Option<Key128>, ParseError> {
    match set.find(tag) {
        None => Ok(None),
        Some(t) => {
            let b: [u8; 16] = t.value.try_into().map_err(|_| ParseError::Malformed)?;
            Ok(Some(Key128::from_bytes(b)))
        }
    }
}

fn link_key(set: &TlvSet<'_>) -> Result<Option<LinkKey>, ParseError> {
    match set.find(tag::LINK_KEY) {
        None => Ok(None),
        Some(t) => {
            let (flags, k) = t.value.split_first().ok_or(ParseError::Malformed)?;
            let b: [u8; 16] = k.try_into().map_err(|_| ParseError::Malformed)?;
            Ok(Some(LinkKey {
                unique: flags & 0x01 != 0,
                provisional: flags & 0x02 != 0,
                key: Key128::from_bytes(b),
            }))
        }
    }
}

/// Reads the Network Channel TLV (Channel List Structure, R23.2
/// §3.2.2.2.1): the page-0 mask, or the first page present.
fn channels(set: &TlvSet<'_>) -> Result<Option<ChannelMask>, ParseError> {
    let Some(t) = set.find(tag::NETWORK_CHANNEL) else {
        return Ok(None);
    };
    let (count, rest) = t.value.split_first().ok_or(ParseError::Malformed)?;
    if rest.len() != usize::from(*count) * 4 {
        return Err(ParseError::Malformed);
    }
    let mut first = None;
    for chunk in rest.chunks_exact(4) {
        let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let mask = ChannelMask(raw);
        if mask.page() == ChannelPage(0) {
            return Ok(Some(mask));
        }
        first.get_or_insert(mask);
    }
    Ok(first)
}

/// Writes a Network Channel TLV with one page.
pub fn write_channels(
    w: &mut Writer<'_>,
    mask: ChannelMask,
) -> Result<(), panweave_codec::CodecError> {
    let mut v = [0u8; 5];
    v[0] = 1;
    v[1..].copy_from_slice(&mask.raw().to_le_bytes());
    write_tlv(w, tag::NETWORK_CHANNEL, &v)
}

impl FormNetwork {
    /// Parses a Form Network write (an empty write means "all defaults",
    /// centralized).
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        let set = TlvSet::validate(payload, |_| false).map_err(|_| ParseError::Malformed)?;
        if set.find(tag::ACTIVE_KEY_SEQUENCE).is_some() {
            return Err(ParseError::InvalidTlv(tag::ACTIVE_KEY_SEQUENCE));
        }
        let tc = eui64(&set, tag::TRUST_CENTER_ADDRESS)?;
        let distributed = match tc {
            None => false,
            Some(ExtendedAddress(0xFFFF_FFFF_FFFF_FFFF)) => true,
            // A centralized formation never names another Trust Center.
            Some(_) => return Err(ParseError::InvalidTlv(tag::TRUST_CENTER_ADDRESS)),
        };
        let extended_pan_id = eui64(&set, tag::EXTENDED_PAN_ID)?;
        if extended_pan_id.is_some_and(|e| e.0 == 0 || e.0 == 0xFFFF_FFFF_FFFF_FFFF) {
            return Err(ParseError::OutOfRange(tag::EXTENDED_PAN_ID));
        }
        let pan_id = u16_le(&set, tag::SHORT_PAN_ID)?.map(PanId);
        if pan_id.is_some_and(|p| p.0 == 0 || p.0 == 0xFFFF) {
            return Err(ParseError::OutOfRange(tag::SHORT_PAN_ID));
        }
        let nwk_address = u16_le(&set, tag::NWK_ADDRESS)?.map(ShortAddress);
        if nwk_address.is_some_and(|a| a.0 > 0xFFF7) {
            return Err(ParseError::OutOfRange(tag::NWK_ADDRESS));
        }
        Ok(FormNetwork {
            distributed,
            extended_pan_id,
            pan_id,
            channels: channels(&set)?,
            network_key: key(&set, tag::NETWORK_KEY)?,
            link_key: link_key(&set)?,
            nwk_address,
            update_id: u8_value(&set, tag::NWK_UPDATE_ID)?,
            admin_key: key(&set, tag::ADMIN_KEY)?,
        })
    }
}

impl JoinNetwork {
    /// Parses a Join Network write and checks the TLV usage of Tables
    /// 39–41 for the joining method.
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        let set = TlvSet::validate(payload, |_| false).map_err(|_| ParseError::Malformed)?;
        let method = u8_value(&set, tag::JOINING_METHOD)?
            .ok_or(ParseError::MissingTlv(tag::JOINING_METHOD))
            .and_then(|m| {
                JoiningMethod::from_raw(m).ok_or(ParseError::OutOfRange(tag::JOINING_METHOD))
            })?;
        for invalid in [tag::DEVICE_TYPE, tag::IEEE_ADDRESS, tag::NETWORK_STATUS_MAP] {
            if set.find(invalid).is_some() {
                return Err(ParseError::InvalidTlv(invalid));
            }
        }
        let extended_pan_id = eui64(&set, tag::EXTENDED_PAN_ID)?;
        let pan_id = u16_le(&set, tag::SHORT_PAN_ID)?.map(PanId);
        let chans = channels(&set)?;
        let network_key = key(&set, tag::NETWORK_KEY)?;
        let nwk_address = u16_le(&set, tag::NWK_ADDRESS)?.map(ShortAddress);
        let update_id = u8_value(&set, tag::NWK_UPDATE_ID)?;
        let key_sequence = u8_value(&set, tag::ACTIVE_KEY_SEQUENCE)?;
        match method {
            JoiningMethod::Association => {
                for (present, t) in [
                    (pan_id.is_some(), tag::SHORT_PAN_ID),
                    (network_key.is_some(), tag::NETWORK_KEY),
                    (update_id.is_some(), tag::NWK_UPDATE_ID),
                    (key_sequence.is_some(), tag::ACTIVE_KEY_SEQUENCE),
                ] {
                    if present {
                        return Err(ParseError::InvalidTlv(t));
                    }
                }
            }
            JoiningMethod::Rejoin => {
                if extended_pan_id.is_none() {
                    return Err(ParseError::MissingTlv(tag::EXTENDED_PAN_ID));
                }
                for (present, t) in [
                    (pan_id.is_some(), tag::SHORT_PAN_ID),
                    (nwk_address.is_some(), tag::NWK_ADDRESS),
                    (update_id.is_some(), tag::NWK_UPDATE_ID),
                    (key_sequence.is_some(), tag::ACTIVE_KEY_SEQUENCE),
                ] {
                    if present {
                        return Err(ParseError::InvalidTlv(t));
                    }
                }
            }
            JoiningMethod::OutOfBand => {
                for (present, t) in [
                    (extended_pan_id.is_some(), tag::EXTENDED_PAN_ID),
                    (pan_id.is_some(), tag::SHORT_PAN_ID),
                    (chans.is_some(), tag::NETWORK_CHANNEL),
                    (network_key.is_some(), tag::NETWORK_KEY),
                ] {
                    if !present {
                        return Err(ParseError::MissingTlv(t));
                    }
                }
            }
        }
        Ok(JoinNetwork {
            method,
            extended_pan_id,
            pan_id,
            channels: chans,
            network_key,
            link_key: link_key(&set)?,
            nwk_address,
            trust_center: eui64(&set, tag::TRUST_CENTER_ADDRESS)?,
            update_id,
            key_sequence,
            admin_key: key(&set, tag::ADMIN_KEY)?,
        })
    }
}

impl ManageJoiners {
    /// Parses a Manage Joiners write (Table 46).
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        let set = TlvSet::validate(payload, |_| false).map_err(|_| ParseError::Malformed)?;
        let command = u8_value(&set, joiners_tag::COMMAND)?
            .ok_or(ParseError::MissingTlv(joiners_tag::COMMAND))?;
        let ieee = eui64(&set, joiners_tag::IEEE_ADDRESS)?;
        let key = key(&set, joiners_tag::PROVISIONAL_LINK_KEY)?;
        match command {
            0 => Ok(ManageJoiners::DropAll),
            1 => Ok(ManageJoiners::Add {
                ieee: ieee.ok_or(ParseError::MissingTlv(joiners_tag::IEEE_ADDRESS))?,
                key: key.ok_or(ParseError::MissingTlv(joiners_tag::PROVISIONAL_LINK_KEY))?,
            }),
            2 => Ok(ManageJoiners::Remove {
                ieee: ieee.ok_or(ParseError::MissingTlv(joiners_tag::IEEE_ADDRESS))?,
            }),
            _ => Err(ParseError::OutOfRange(joiners_tag::COMMAND)),
        }
    }
}

impl ManageJoiners {
    /// Encodes a Manage Joiners write (ZVD side); returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, panweave_codec::CodecError> {
        let mut w = Writer::new(out);
        match self {
            ManageJoiners::DropAll => write_tlv(&mut w, joiners_tag::COMMAND, &[0])?,
            ManageJoiners::Add { ieee, key } => {
                write_tlv(&mut w, joiners_tag::PROVISIONAL_LINK_KEY, key.as_bytes())?;
                write_tlv(&mut w, joiners_tag::IEEE_ADDRESS, &ieee.0.to_le_bytes())?;
                write_tlv(&mut w, joiners_tag::COMMAND, &[1])?;
            }
            ManageJoiners::Remove { ieee } => {
                write_tlv(&mut w, joiners_tag::IEEE_ADDRESS, &ieee.0.to_le_bytes())?;
                write_tlv(&mut w, joiners_tag::COMMAND, &[2])?;
            }
        }
        Ok(w.position())
    }
}

/// Leave Network write (Table 42).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeaveNetwork {
    /// Remove the children too.
    pub remove_children: bool,
    /// Rejoin afterwards.
    pub rejoin: bool,
}

impl LeaveNetwork {
    /// The two-octet payload.
    pub const fn encode(self) -> [u8; 2] {
        [self.remove_children as u8, self.rejoin as u8]
    }

    /// Parses the two-octet payload.
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        match payload {
            [rc, rj] if *rc <= 1 && *rj <= 1 => Ok(LeaveNetwork {
                remove_children: *rc == 1,
                rejoin: *rj == 1,
            }),
            _ => Err(ParseError::Malformed),
        }
    }
}

/// Finding & Binding write (Table 49).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FindingBinding {
    /// Endpoint.
    pub endpoint: Endpoint,
    /// Initiator (true) or target.
    pub initiator: bool,
}

impl FindingBinding {
    /// The two-octet payload.
    pub const fn encode(self) -> [u8; 2] {
        [self.endpoint.0, self.initiator as u8]
    }

    /// Parses the two-octet payload.
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        match payload {
            [ep, flags] if *flags & 0xFE == 0 => Ok(FindingBinding {
                endpoint: Endpoint(*ep),
                initiator: *flags & 0x01 != 0,
            }),
            _ => Err(ParseError::Malformed),
        }
    }
}

/// What the ZDD reports in the Commissioning Status characteristic
/// (Table 43).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StatusReport {
    /// Network Status Map.
    pub status: NetworkStatus,
    /// The ZDD's IEEE address.
    pub ieee: ExtendedAddress,
    /// Network parameters when joined.
    pub network: Option<NetworkInfo>,
}

/// Network parameters of a joined ZDD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetworkInfo {
    /// Operating channel mask (one bit).
    pub channel: ChannelMask,
    /// Extended PAN ID.
    pub extended_pan_id: ExtendedAddress,
    /// PAN ID.
    pub pan_id: PanId,
    /// NWK address.
    pub nwk_address: ShortAddress,
    /// Trust Center (all ones for distributed).
    pub trust_center: ExtendedAddress,
    /// Device type.
    pub device_type: DeviceType,
    /// NWK update ID.
    pub update_id: u8,
    /// Active key sequence number.
    pub key_sequence: u8,
}

/// Encodes a Commissioning Status payload; `code` adds a Status Code
/// TLV (notifications only).
pub fn encode_status(
    report: Option<&StatusReport>,
    code: Option<(Domain, u8)>,
    out: &mut [u8],
) -> Result<usize, panweave_codec::CodecError> {
    let mut w = Writer::new(out);
    if let Some(r) = report {
        write_tlv(&mut w, tag::NETWORK_STATUS_MAP, &[r.status.raw()])?;
        if let Some(n) = &r.network {
            write_channels(&mut w, n.channel)?;
            write_tlv(
                &mut w,
                tag::EXTENDED_PAN_ID,
                &n.extended_pan_id.0.to_le_bytes(),
            )?;
            write_tlv(&mut w, tag::SHORT_PAN_ID, &n.pan_id.0.to_le_bytes())?;
            write_tlv(&mut w, tag::NWK_ADDRESS, &n.nwk_address.0.to_le_bytes())?;
        }
        write_tlv(&mut w, tag::IEEE_ADDRESS, &r.ieee.0.to_le_bytes())?;
        if let Some(n) = &r.network {
            write_tlv(
                &mut w,
                tag::TRUST_CENTER_ADDRESS,
                &n.trust_center.0.to_le_bytes(),
            )?;
            write_tlv(&mut w, tag::DEVICE_TYPE, &[n.device_type.raw()])?;
            write_tlv(&mut w, tag::NWK_UPDATE_ID, &[n.update_id])?;
            write_tlv(&mut w, tag::ACTIVE_KEY_SEQUENCE, &[n.key_sequence])?;
        }
    }
    if let Some((d, s)) = code {
        write_tlv(&mut w, tag::STATUS_CODE, &[d.raw(), s])?;
    }
    Ok(w.position())
}

/// A decoded Commissioning Status payload: the report and the
/// `(domain, status)` code, whichever are present.
pub type DecodedStatus = (Option<StatusReport>, Option<(u8, u8)>);

/// Decodes a Commissioning Status payload (ZVD side).
pub fn decode_status(payload: &[u8]) -> Result<DecodedStatus, ParseError> {
    let set = TlvSet::validate(payload, |_| false).map_err(|_| ParseError::Malformed)?;
    let code = match set.find(tag::STATUS_CODE) {
        Some(t) => match t.value {
            [d, s] => Some((*d, *s)),
            _ => return Err(ParseError::Malformed),
        },
        None => None,
    };
    let status = u8_value(&set, tag::NETWORK_STATUS_MAP)?;
    let ieee = eui64(&set, tag::IEEE_ADDRESS)?;
    let report = match (status, ieee) {
        (Some(s), Some(ieee)) => {
            let status = NetworkStatus::from_raw(s)
                .ok_or(ParseError::OutOfRange(tag::NETWORK_STATUS_MAP))?;
            let network = match (
                channels(&set)?,
                eui64(&set, tag::EXTENDED_PAN_ID)?,
                u16_le(&set, tag::SHORT_PAN_ID)?,
                u16_le(&set, tag::NWK_ADDRESS)?,
                eui64(&set, tag::TRUST_CENTER_ADDRESS)?,
                u8_value(&set, tag::DEVICE_TYPE)?,
            ) {
                (Some(channel), Some(epid), Some(pan), Some(addr), Some(tc), Some(dt)) => {
                    let device_type = match dt {
                        0 => DeviceType::Coordinator,
                        1 => DeviceType::Router,
                        2 => DeviceType::EndDevice,
                        _ => return Err(ParseError::OutOfRange(tag::DEVICE_TYPE)),
                    };
                    Some(NetworkInfo {
                        channel,
                        extended_pan_id: epid,
                        pan_id: PanId(pan),
                        nwk_address: ShortAddress(addr),
                        trust_center: tc,
                        device_type,
                        update_id: u8_value(&set, tag::NWK_UPDATE_ID)?.unwrap_or(0),
                        key_sequence: u8_value(&set, tag::ACTIVE_KEY_SEQUENCE)?.unwrap_or(0),
                    })
                }
                _ => None,
            };
            Some(StatusReport {
                status,
                ieee,
                network,
            })
        }
        _ => None,
    };
    Ok((report, code))
}

/// The stack operations the Commissioning Service drives; every method
/// returns a status code (0 = SUCCESS) for the Status Code TLV.
pub trait Zdd {
    /// Current report (Table 43).
    fn status(&self) -> StatusReport;
    /// Whether this ZDD can act as coordinator / Trust Center.
    fn can_be_coordinator(&self) -> bool;
    /// Form a network; the result is reported later through
    /// [`Commissioning::report`].
    fn form_network(&mut self, params: &FormNetwork) -> u8;
    /// Join a network.
    fn join_network(&mut self, params: &JoinNetwork) -> u8;
    /// Permit joining for `seconds` (0 closes) and broadcast
    /// Mgmt_Permit_Joining_req.
    fn permit_joining(&mut self, seconds: u8) -> u8;
    /// Leave the network, erasing its parameters.
    fn leave_network(&mut self, params: LeaveNetwork) -> u8;
    /// Manage provisional link keys (Trust Center only).
    fn manage_joiners(&mut self, cmd: &ManageJoiners) -> u8;
    /// Identify for `seconds` (0 stops).
    fn identify(&mut self, seconds: u16) -> u8;
    /// Remaining identify time.
    fn identify_time(&self) -> u16;
    /// Start finding & binding.
    fn finding_binding(&mut self, params: FindingBinding) -> u8;
}

/// A characteristic of the Commissioning Service.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Characteristic {
    /// Form Network.
    FormNetwork,
    /// Join Network.
    JoinNetwork,
    /// Permit Joining.
    PermitJoining,
    /// Leave Network.
    LeaveNetwork,
    /// Commissioning Status.
    CommissioningStatus,
    /// Manage Joiners.
    ManageJoiners,
    /// Identify.
    Identify,
    /// Finding & Binding.
    FindingBinding,
}

/// Result of a characteristic access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Access {
    /// Accepted.
    Ok,
    /// The session's authorization level is insufficient (§6.4.7.4):
    /// answer with the Zigbee Direct application error.
    Unauthorized,
    /// Reads of write-only / writes of read-only characteristics.
    NotPermitted,
}

/// A pending Commissioning Status notification.
pub type Notification = Vec<u8, MAX_PAYLOAD>;

/// ZDD side of the Commissioning Service for one connection.
pub struct Commissioning {
    level: Level,
    provisioned: bool,
    notifications: Vec<Notification, 4>,
}

impl Commissioning {
    /// A service instance for a connection at `level`; `provisioned`
    /// tells whether the ZDD is on a network (the Commissioning Service
    /// of a provisioned ZDD needs Admin access except for status reads).
    pub const fn new(level: Level, provisioned: bool) -> Self {
        Commissioning {
            level,
            provisioned,
            notifications: Vec::new(),
        }
    }

    /// Updates the provisioned state (after joining / leaving).
    pub fn set_provisioned(&mut self, provisioned: bool) {
        self.provisioned = provisioned;
    }

    /// Next pending notification for the Commissioning Status
    /// characteristic.
    pub fn next_notification(&mut self) -> Option<Notification> {
        if self.notifications.is_empty() {
            None
        } else {
            Some(self.notifications.remove(0))
        }
    }

    fn notify(&mut self, report: Option<&StatusReport>, code: Option<(Domain, u8)>) {
        let mut buf = [0u8; MAX_PAYLOAD];
        if let Ok(n) = encode_status(report, code, &mut buf) {
            let mut v = Vec::new();
            if v.extend_from_slice(buf.get(..n).unwrap_or(&[])).is_ok() {
                if self.notifications.is_full() {
                    self.notifications.remove(0);
                }
                let _ = self.notifications.push(v);
            }
        }
    }

    /// Reports a completed operation (the stack calls this when a
    /// formation / join / leave finishes): a full Table 43 notification,
    /// plus the Status Code on failure.
    pub fn report(&mut self, zdd: &impl Zdd, domain: Domain, status: u8) {
        let r = zdd.status();
        self.provisioned = r.status.joined == JoinedStatus::Commissioned;
        if status == STATUS_SUCCESS {
            self.notify(Some(&r), None);
        } else {
            self.notify(Some(&r), Some((domain, status)));
        }
    }

    /// Authorization required by a write (Table 26).
    fn write_allowed(&self, c: Characteristic) -> bool {
        match c {
            Characteristic::FormNetwork
            | Characteristic::JoinNetwork
            | Characteristic::PermitJoining
            | Characteristic::LeaveNetwork => {
                (!self.provisioned && self.level == Level::Provisioning)
                    || self.level == Level::Admin
            }
            Characteristic::ManageJoiners => self.level == Level::Admin,
            Characteristic::Identify => {
                !self.provisioned || matches!(self.level, Level::Basic | Level::Admin)
            }
            Characteristic::FindingBinding => matches!(self.level, Level::Basic | Level::Admin),
            Characteristic::CommissioningStatus => false,
        }
    }

    /// A write to `c` with `payload` (already decrypted).
    pub fn write(&mut self, zdd: &mut impl Zdd, c: Characteristic, payload: &[u8]) -> Access {
        if c == Characteristic::CommissioningStatus {
            return Access::NotPermitted;
        }
        if !self.write_allowed(c) {
            // A provisioned ZDD reports Identify during a provisioning
            // session as an error notification (§7.7.2.11).
            if c == Characteristic::Identify {
                self.notify(None, Some((Domain::Identify, STATUS_FAILURE)));
            }
            return Access::Unauthorized;
        }
        let joined = zdd.status().status.joined == JoinedStatus::Commissioned;
        match c {
            Characteristic::FormNetwork => {
                let status = match FormNetwork::parse(payload) {
                    Ok(p) if joined => {
                        let _ = p;
                        STATUS_FAILURE
                    }
                    Ok(p) if !p.distributed && !zdd.can_be_coordinator() => STATUS_FAILURE,
                    Ok(p) => zdd.form_network(&p),
                    Err(_) => STATUS_FAILURE,
                };
                if status != STATUS_SUCCESS {
                    self.notify(None, Some((Domain::FormNetwork, status)));
                }
            }
            Characteristic::JoinNetwork => {
                let status = match JoinNetwork::parse(payload) {
                    Ok(_) if joined => STATUS_FAILURE,
                    Ok(p) => zdd.join_network(&p),
                    Err(_) => STATUS_FAILURE,
                };
                if status != STATUS_SUCCESS {
                    self.notify(None, Some((Domain::JoinNetwork, status)));
                }
            }
            Characteristic::PermitJoining => {
                let status = match payload {
                    [s] if joined => zdd.permit_joining(if *s == 0xff { 0xfe } else { *s }),
                    _ => STATUS_FAILURE,
                };
                if status == STATUS_SUCCESS {
                    let r = zdd.status();
                    self.notify(Some(&r), None);
                } else {
                    self.notify(None, Some((Domain::PermitJoining, status)));
                }
            }
            Characteristic::LeaveNetwork => {
                let status = match LeaveNetwork::parse(payload) {
                    Ok(p) if joined => zdd.leave_network(p),
                    _ => STATUS_FAILURE,
                };
                if status != STATUS_SUCCESS {
                    self.notify(None, Some((Domain::LeaveNetwork, status)));
                }
            }
            Characteristic::ManageJoiners => {
                let status = match ManageJoiners::parse(payload) {
                    Ok(cmd) => zdd.manage_joiners(&cmd),
                    Err(_) => STATUS_FAILURE,
                };
                self.notify(None, Some((Domain::ManageJoiners, status)));
            }
            Characteristic::Identify => {
                let status = match payload {
                    [lo, hi] => zdd.identify(u16::from_le_bytes([*lo, *hi])),
                    _ => STATUS_FAILURE,
                };
                if status != STATUS_SUCCESS {
                    self.notify(None, Some((Domain::Identify, status)));
                }
            }
            Characteristic::FindingBinding => {
                let status = match FindingBinding::parse(payload) {
                    Ok(p) if joined => zdd.finding_binding(p),
                    _ => STATUS_FAILURE,
                };
                if status != STATUS_SUCCESS {
                    self.notify(None, Some((Domain::FindingBinding, status)));
                }
            }
            Characteristic::CommissioningStatus => {}
        }
        Access::Ok
    }

    /// A read of `c` into `out`; returns the length or the access
    /// result.
    pub fn read(&self, zdd: &impl Zdd, c: Characteristic, out: &mut [u8]) -> Result<usize, Access> {
        match c {
            // Readable with a provisioning session, the Basic or Admin key.
            Characteristic::CommissioningStatus => {
                encode_status(Some(&zdd.status()), None, out).map_err(|_| Access::NotPermitted)
            }
            Characteristic::Identify => {
                if !self.write_allowed(c) {
                    return Err(Access::Unauthorized);
                }
                let t = zdd.identify_time().to_le_bytes();
                let o = out.get_mut(..2).ok_or(Access::NotPermitted)?;
                o.copy_from_slice(&t);
                Ok(2)
            }
            _ => Err(Access::NotPermitted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_network_tlv_usage_rules() {
        // Rejoin needs the extended PAN ID; a PAN ID is invalid.
        let mut buf = [0u8; 96];
        let mut w = Writer::new(&mut buf);
        write_tlv(&mut w, tag::JOINING_METHOD, &[1]).unwrap();
        let n = w.position();
        assert_eq!(
            JoinNetwork::parse(&buf[..n]),
            Err(ParseError::MissingTlv(tag::EXTENDED_PAN_ID))
        );
        let mut w = Writer::new(&mut buf);
        write_tlv(&mut w, tag::JOINING_METHOD, &[1]).unwrap();
        write_tlv(&mut w, tag::EXTENDED_PAN_ID, &1u64.to_le_bytes()).unwrap();
        write_tlv(&mut w, tag::SHORT_PAN_ID, &[0x34, 0x12]).unwrap();
        let n = w.position();
        assert_eq!(
            JoinNetwork::parse(&buf[..n]),
            Err(ParseError::InvalidTlv(tag::SHORT_PAN_ID))
        );
        // Out-of-band with everything.
        let mut w = Writer::new(&mut buf);
        write_tlv(&mut w, tag::JOINING_METHOD, &[2]).unwrap();
        write_tlv(&mut w, tag::EXTENDED_PAN_ID, &0xABCDu64.to_le_bytes()).unwrap();
        write_tlv(&mut w, tag::SHORT_PAN_ID, &[0x34, 0x12]).unwrap();
        write_channels(&mut w, ChannelMask(1 << 15)).unwrap();
        write_tlv(&mut w, tag::NETWORK_KEY, &[0x11; 16]).unwrap();
        let mut lk = [0u8; 17];
        lk[0] = 0x03;
        lk[1..].copy_from_slice(&[0x22; 16]);
        write_tlv(&mut w, tag::LINK_KEY, &lk).unwrap();
        write_tlv(&mut w, tag::NWK_ADDRESS, &[0x01, 0x00]).unwrap();
        let n = w.position();
        let j = JoinNetwork::parse(&buf[..n]).unwrap();
        assert_eq!(j.method, JoiningMethod::OutOfBand);
        assert_eq!(j.pan_id, Some(PanId(0x1234)));
        assert_eq!(j.channels, Some(ChannelMask(1 << 15)));
        assert_eq!(j.nwk_address, Some(ShortAddress(1)));
        let lk = j.link_key.as_ref().unwrap();
        assert!(lk.unique && lk.provisional);
        assert_eq!(lk.key.as_bytes(), &[0x22; 16]);
        let mut enc = [0u8; 96];
        let n = j.encode(&mut enc).unwrap();
        assert_eq!(JoinNetwork::parse(&enc[..n]).unwrap(), j);
        for cmd in [
            ManageJoiners::DropAll,
            ManageJoiners::Add {
                ieee: ExtendedAddress(7),
                key: Key128::from_bytes([9; 16]),
            },
            ManageJoiners::Remove {
                ieee: ExtendedAddress(7),
            },
        ] {
            let n = cmd.encode(&mut enc).unwrap();
            assert_eq!(ManageJoiners::parse(&enc[..n]).unwrap(), cmd);
        }
        let f = FormNetwork {
            distributed: true,
            channels: Some(ChannelMask(1 << 25)),
            nwk_address: Some(ShortAddress(0x1234)),
            ..FormNetwork::default()
        };
        let n = f.encode(&mut enc).unwrap();
        assert_eq!(FormNetwork::parse(&enc[..n]).unwrap(), f);
        let l = LeaveNetwork {
            remove_children: true,
            rejoin: false,
        };
        assert_eq!(LeaveNetwork::parse(&l.encode()), Ok(l));
        let fb = FindingBinding {
            endpoint: Endpoint(3),
            initiator: true,
        };
        assert_eq!(FindingBinding::parse(&fb.encode()), Ok(fb));
        // Form Network: another Trust Center is invalid; all ones means
        // distributed.
        let mut w = Writer::new(&mut buf);
        write_tlv(&mut w, tag::TRUST_CENTER_ADDRESS, &0x55u64.to_le_bytes()).unwrap();
        let n = w.position();
        assert_eq!(
            FormNetwork::parse(&buf[..n]),
            Err(ParseError::InvalidTlv(tag::TRUST_CENTER_ADDRESS))
        );
        let mut w = Writer::new(&mut buf);
        write_tlv(&mut w, tag::TRUST_CENTER_ADDRESS, &[0xff; 8]).unwrap();
        let n = w.position();
        assert!(FormNetwork::parse(&buf[..n]).unwrap().distributed);
        assert_eq!(FormNetwork::parse(&[]).unwrap(), FormNetwork::default());
    }

    #[test]
    fn status_round_trip() {
        let r = StatusReport {
            status: NetworkStatus {
                joined: JoinedStatus::Commissioned,
                open: true,
                centralized: true,
            },
            ieee: ExtendedAddress(0x00AA_0000_0000_0001),
            network: Some(NetworkInfo {
                channel: ChannelMask(1 << 20),
                extended_pan_id: ExtendedAddress(0x1234),
                pan_id: PanId(0x5678),
                nwk_address: ShortAddress(0x0001),
                trust_center: ExtendedAddress(0x00AA_0000_0000_0002),
                device_type: DeviceType::Router,
                update_id: 3,
                key_sequence: 1,
            }),
        };
        let mut buf = [0u8; 96];
        let n = encode_status(Some(&r), Some((Domain::JoinNetwork, 0)), &mut buf).unwrap();
        let (report, code) = decode_status(&buf[..n]).unwrap();
        assert_eq!(report, Some(r));
        assert_eq!(code, Some((2, 0)));
        // Status-only notification.
        let n = encode_status(None, Some((Domain::Identify, 1)), &mut buf).unwrap();
        assert_eq!(&buf[..n], &[tag::STATUS_CODE, 1, 6, 1]);
        assert_eq!(decode_status(&buf[..n]).unwrap(), (None, Some((6, 1))));
    }

    struct Fake {
        joined: bool,
        formed: Option<FormNetwork>,
        permit: Option<u8>,
        identify: u16,
    }

    impl Zdd for Fake {
        fn status(&self) -> StatusReport {
            StatusReport {
                status: NetworkStatus {
                    joined: if self.joined {
                        JoinedStatus::Commissioned
                    } else {
                        JoinedStatus::NotCommissioned
                    },
                    open: self.permit.is_some_and(|p| p > 0),
                    centralized: true,
                },
                ieee: ExtendedAddress(1),
                network: self.joined.then_some(NetworkInfo {
                    channel: ChannelMask(1 << 11),
                    extended_pan_id: ExtendedAddress(2),
                    pan_id: PanId(3),
                    nwk_address: ShortAddress(0),
                    trust_center: ExtendedAddress(1),
                    device_type: DeviceType::Coordinator,
                    update_id: 0,
                    key_sequence: 0,
                }),
            }
        }
        fn can_be_coordinator(&self) -> bool {
            true
        }
        fn form_network(&mut self, params: &FormNetwork) -> u8 {
            self.formed = Some(params.clone());
            0
        }
        fn join_network(&mut self, _: &JoinNetwork) -> u8 {
            0
        }
        fn permit_joining(&mut self, seconds: u8) -> u8 {
            self.permit = Some(seconds);
            0
        }
        fn leave_network(&mut self, _: LeaveNetwork) -> u8 {
            self.joined = false;
            0
        }
        fn manage_joiners(&mut self, _: &ManageJoiners) -> u8 {
            0
        }
        fn identify(&mut self, seconds: u16) -> u8 {
            self.identify = seconds;
            0
        }
        fn identify_time(&self) -> u16 {
            self.identify
        }
        fn finding_binding(&mut self, _: FindingBinding) -> u8 {
            0
        }
    }

    #[test]
    fn zdd_side_authorization_and_flow() {
        let mut zdd = Fake {
            joined: false,
            formed: None,
            permit: None,
            identify: 0,
        };
        // Unprovisioned ZDD, provisioning session: Form Network allowed,
        // Permit Joining refused while not joined.
        let mut svc = Commissioning::new(Level::Provisioning, false);
        assert_eq!(
            svc.write(&mut zdd, Characteristic::FormNetwork, &[]),
            Access::Ok
        );
        assert!(zdd.formed.is_some());
        assert!(svc.next_notification().is_none(), "reported on completion");
        assert_eq!(
            svc.write(&mut zdd, Characteristic::PermitJoining, &[60]),
            Access::Ok
        );
        let n = svc.next_notification().unwrap();
        assert_eq!(decode_status(&n).unwrap().1, Some((3, STATUS_FAILURE)));
        // Formation completes: the full report is notified.
        zdd.joined = true;
        svc.report(&zdd, Domain::FormNetwork, STATUS_SUCCESS);
        let n = svc.next_notification().unwrap();
        let (report, code) = decode_status(&n).unwrap();
        assert!(code.is_none());
        assert_eq!(report.unwrap().status.joined, JoinedStatus::Commissioned);
        // Now provisioned: a provisioning session may only read the
        // status; Identify is answered with an error notification.
        assert_eq!(
            svc.write(&mut zdd, Characteristic::PermitJoining, &[60]),
            Access::Unauthorized
        );
        assert_eq!(
            svc.write(&mut zdd, Characteristic::Identify, &[5, 0]),
            Access::Unauthorized
        );
        let n = svc.next_notification().unwrap();
        assert_eq!(decode_status(&n).unwrap().1, Some((6, STATUS_FAILURE)));
        let mut out = [0u8; 96];
        assert!(
            svc.read(&zdd, Characteristic::CommissioningStatus, &mut out)
                .is_ok()
        );
        // Admin session: permit joining and identify work.
        let mut admin = Commissioning::new(Level::Admin, true);
        assert_eq!(
            admin.write(&mut zdd, Characteristic::PermitJoining, &[0xff]),
            Access::Ok
        );
        assert_eq!(zdd.permit, Some(0xfe));
        let n = admin.next_notification().unwrap();
        assert!(decode_status(&n).unwrap().0.unwrap().status.open);
        assert_eq!(
            admin.write(&mut zdd, Characteristic::Identify, &[5, 0]),
            Access::Ok
        );
        assert_eq!(admin.read(&zdd, Characteristic::Identify, &mut out), Ok(2));
        assert_eq!(&out[..2], &[5, 0]);
        // Basic session: no Manage Joiners.
        let mut basic = Commissioning::new(Level::Basic, true);
        assert_eq!(
            basic.write(&mut zdd, Characteristic::ManageJoiners, &[2, 0, 0]),
            Access::Unauthorized
        );
        assert_eq!(
            basic.write(&mut zdd, Characteristic::FindingBinding, &[1, 1]),
            Access::Ok
        );
    }
}
