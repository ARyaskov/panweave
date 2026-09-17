//! Zigbee Device Profile frames (R23.2 §2.4): cluster identifiers, the
//! ZDP status enumeration (§2.4.5, Table 2-129), client requests (§2.4.3)
//! and server responses (§2.4.4).
//!
//! Every ZDP frame is a transaction sequence number followed by the
//! transaction data (§2.4.2.8). Lists are kept as borrowed byte slices
//! with typed iterators so that decoding never allocates.

use panweave_aps::tables::BindingDestination;
use panweave_codec::tlv::TlvSet;
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{
    ChannelMask, ClusterId, Endpoint, ExtendedAddress, MacCapability, ProfileId, ShortAddress,
    TransactionSequence,
};

use crate::descriptor::{NodeDescriptor, PowerDescriptor, ServerMask};

/// ZDP cluster identifiers (Tables 2-43, 2-54, 2-58, 2-84, 2-86, 2-96,
/// 2-100, 2-110). A response identifier is the request identifier with
/// bit 15 set.
pub mod cluster {
    use panweave_types::ClusterId;

    /// NWK_addr_req.
    pub const NWK_ADDR_REQ: ClusterId = ClusterId(0x0000);
    /// IEEE_addr_req.
    pub const IEEE_ADDR_REQ: ClusterId = ClusterId(0x0001);
    /// Node_Desc_req.
    pub const NODE_DESC_REQ: ClusterId = ClusterId(0x0002);
    /// Power_Desc_req.
    pub const POWER_DESC_REQ: ClusterId = ClusterId(0x0003);
    /// Simple_Desc_req.
    pub const SIMPLE_DESC_REQ: ClusterId = ClusterId(0x0004);
    /// Active_EP_req.
    pub const ACTIVE_EP_REQ: ClusterId = ClusterId(0x0005);
    /// Match_Desc_req.
    pub const MATCH_DESC_REQ: ClusterId = ClusterId(0x0006);
    /// Device_annce.
    pub const DEVICE_ANNCE: ClusterId = ClusterId(0x0013);
    /// System_Server_Discovery_req.
    pub const SYSTEM_SERVER_DISCOVERY_REQ: ClusterId = ClusterId(0x0015);
    /// Parent_annce.
    pub const PARENT_ANNCE: ClusterId = ClusterId(0x001F);
    /// Bind_req.
    pub const BIND_REQ: ClusterId = ClusterId(0x0021);
    /// Unbind_req.
    pub const UNBIND_REQ: ClusterId = ClusterId(0x0022);
    /// Clear_All_Bindings_req.
    pub const CLEAR_ALL_BINDINGS_REQ: ClusterId = ClusterId(0x002B);
    /// Mgmt_Lqi_req.
    pub const MGMT_LQI_REQ: ClusterId = ClusterId(0x0031);
    /// Mgmt_Rtg_req.
    pub const MGMT_RTG_REQ: ClusterId = ClusterId(0x0032);
    /// Mgmt_Bind_req.
    pub const MGMT_BIND_REQ: ClusterId = ClusterId(0x0033);
    /// Mgmt_Leave_req.
    pub const MGMT_LEAVE_REQ: ClusterId = ClusterId(0x0034);
    /// Mgmt_Permit_Joining_req.
    pub const MGMT_PERMIT_JOINING_REQ: ClusterId = ClusterId(0x0036);
    /// Mgmt_NWK_Update_req.
    pub const MGMT_NWK_UPDATE_REQ: ClusterId = ClusterId(0x0038);
    /// Mgmt_NWK_Enhanced_Update_req.
    pub const MGMT_NWK_ENHANCED_UPDATE_REQ: ClusterId = ClusterId(0x0039);
    /// Mgmt_NWK_IEEE_Joining_List_req.
    pub const MGMT_NWK_IEEE_JOINING_LIST_REQ: ClusterId = ClusterId(0x003A);
    /// Mgmt_NWK_Unsolicited_Enhanced_Update_notify.
    pub const MGMT_NWK_UNSOLICITED_ENHANCED_UPDATE_NOTIFY: ClusterId = ClusterId(0x003B);
    /// Mgmt_NWK_Beacon_Survey_req.
    pub const MGMT_NWK_BEACON_SURVEY_REQ: ClusterId = ClusterId(0x003C);
    /// Security_Start_Key_Negotiation_req.
    pub const SECURITY_START_KEY_NEGOTIATION_REQ: ClusterId = ClusterId(0x0040);
    /// Security_Retrieve_Authentication_Token_req.
    pub const SECURITY_RETRIEVE_AUTHENTICATION_TOKEN_REQ: ClusterId = ClusterId(0x0041);
    /// Security_Get_Authentication_Level_req.
    pub const SECURITY_GET_AUTHENTICATION_LEVEL_REQ: ClusterId = ClusterId(0x0042);
    /// Security_Set_Configuration_req.
    pub const SECURITY_SET_CONFIGURATION_REQ: ClusterId = ClusterId(0x0043);
    /// Security_Get_Configuration_req.
    pub const SECURITY_GET_CONFIGURATION_REQ: ClusterId = ClusterId(0x0044);
    /// Security_Start_Key_Update_req.
    pub const SECURITY_START_KEY_UPDATE_REQ: ClusterId = ClusterId(0x0045);
    /// Security_Decommission_req.
    pub const SECURITY_DECOMMISSION_REQ: ClusterId = ClusterId(0x0046);
    /// Security_Challenge_req.
    pub const SECURITY_CHALLENGE_REQ: ClusterId = ClusterId(0x0047);

    /// Response bit.
    pub const RESPONSE_BIT: u16 = 0x8000;

    /// The response cluster for a request (§2.4.4.1).
    #[inline]
    pub const fn response_of(req: ClusterId) -> ClusterId {
        ClusterId(req.0 | RESPONSE_BIT)
    }

    /// True for response identifiers.
    #[inline]
    pub const fn is_response(c: ClusterId) -> bool {
        c.0 & RESPONSE_BIT != 0
    }

    /// The request cluster for a response.
    #[inline]
    pub const fn request_of(rsp: ClusterId) -> ClusterId {
        ClusterId(rsp.0 & !RESPONSE_BIT)
    }
}

/// ZDP status (§2.4.5, Table 2-129).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ZdpStatus {
    /// SUCCESS.
    Success,
    /// INV_REQUESTTYPE.
    InvalidRequestType,
    /// DEVICE_NOT_FOUND.
    DeviceNotFound,
    /// INVALID_EP.
    InvalidEndpoint,
    /// NOT_ACTIVE.
    NotActive,
    /// NOT_SUPPORTED.
    NotSupported,
    /// TIMEOUT.
    Timeout,
    /// NO_MATCH.
    NoMatch,
    /// NO_ENTRY.
    NoEntry,
    /// NO_DESCRIPTOR.
    NoDescriptor,
    /// INSUFFICIENT_SPACE.
    InsufficientSpace,
    /// NOT_PERMITTED.
    NotPermitted,
    /// TABLE_FULL.
    TableFull,
    /// NOT_AUTHORIZED.
    NotAuthorized,
    /// DEVICE_BINDING_TABLE_FULL.
    DeviceBindingTableFull,
    /// INVALID_INDEX.
    InvalidIndex,
    /// FRAME_TOO_LARGE.
    FrameTooLarge,
    /// BAD_KEY_NEGOTIATION_METHOD.
    BadKeyNegotiationMethod,
    /// TEMPORARY_FAILURE.
    TemporaryFailure,
    /// Any other value (including NWK/APS status codes relayed in
    /// management responses).
    Unknown(u8),
}

impl ZdpStatus {
    /// Parses the octet.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x00 => ZdpStatus::Success,
            0x80 => ZdpStatus::InvalidRequestType,
            0x81 => ZdpStatus::DeviceNotFound,
            0x82 => ZdpStatus::InvalidEndpoint,
            0x83 => ZdpStatus::NotActive,
            0x84 => ZdpStatus::NotSupported,
            0x85 => ZdpStatus::Timeout,
            0x86 => ZdpStatus::NoMatch,
            0x88 => ZdpStatus::NoEntry,
            0x89 => ZdpStatus::NoDescriptor,
            0x8A => ZdpStatus::InsufficientSpace,
            0x8B => ZdpStatus::NotPermitted,
            0x8C => ZdpStatus::TableFull,
            0x8D => ZdpStatus::NotAuthorized,
            0x8E => ZdpStatus::DeviceBindingTableFull,
            0x8F => ZdpStatus::InvalidIndex,
            0x90 => ZdpStatus::FrameTooLarge,
            0x91 => ZdpStatus::BadKeyNegotiationMethod,
            0x92 => ZdpStatus::TemporaryFailure,
            other => ZdpStatus::Unknown(other),
        }
    }

    /// The octet.
    pub const fn raw(self) -> u8 {
        match self {
            ZdpStatus::Success => 0x00,
            ZdpStatus::InvalidRequestType => 0x80,
            ZdpStatus::DeviceNotFound => 0x81,
            ZdpStatus::InvalidEndpoint => 0x82,
            ZdpStatus::NotActive => 0x83,
            ZdpStatus::NotSupported => 0x84,
            ZdpStatus::Timeout => 0x85,
            ZdpStatus::NoMatch => 0x86,
            ZdpStatus::NoEntry => 0x88,
            ZdpStatus::NoDescriptor => 0x89,
            ZdpStatus::InsufficientSpace => 0x8A,
            ZdpStatus::NotPermitted => 0x8B,
            ZdpStatus::TableFull => 0x8C,
            ZdpStatus::NotAuthorized => 0x8D,
            ZdpStatus::DeviceBindingTableFull => 0x8E,
            ZdpStatus::InvalidIndex => 0x8F,
            ZdpStatus::FrameTooLarge => 0x90,
            ZdpStatus::BadKeyNegotiationMethod => 0x91,
            ZdpStatus::TemporaryFailure => 0x92,
            ZdpStatus::Unknown(v) => v,
        }
    }

    /// True for SUCCESS.
    #[inline]
    pub const fn is_success(self) -> bool {
        matches!(self, ZdpStatus::Success)
    }
}

impl<'a> Decode<'a> for ZdpStatus {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(ZdpStatus::from_raw(r.u8()?))
    }
}

impl Encode for ZdpStatus {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.raw())
    }
}

/// A ZDP frame: transaction sequence number and transaction data
/// (§2.4.2.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ZdpFrame<'a> {
    /// Transaction sequence number.
    pub seq: TransactionSequence,
    /// Transaction data.
    pub data: &'a [u8],
}

impl<'a> Decode<'a> for ZdpFrame<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(ZdpFrame {
            seq: TransactionSequence(r.u8()?),
            data: r.take_rest(),
        })
    }
}

impl Encode for ZdpFrame<'_> {
    fn encoded_len(&self) -> usize {
        1 + self.data.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.seq.0)?;
        w.bytes(self.data)
    }
}

/// Request type of NWK_addr_req / IEEE_addr_req (Tables 2-44, 2-45).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddrRequestType {
    /// Single device response.
    Single,
    /// Extended response with associated devices.
    Extended,
    /// Reserved value.
    Reserved(u8),
}

impl AddrRequestType {
    const fn from_raw(v: u8) -> Self {
        match v {
            0 => AddrRequestType::Single,
            1 => AddrRequestType::Extended,
            other => AddrRequestType::Reserved(other),
        }
    }

    const fn raw(self) -> u8 {
        match self {
            AddrRequestType::Single => 0,
            AddrRequestType::Extended => 1,
            AddrRequestType::Reserved(v) => v,
        }
    }
}

/// A borrowed list of little-endian 16-bit values (cluster or address
/// lists).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U16List<'a>(pub &'a [u8]);

impl<'a> U16List<'a> {
    /// Number of elements.
    #[inline]
    pub const fn len(&self) -> usize {
        self.0.len() / 2
    }

    /// True when empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0.len() < 2
    }

    /// Iterates the values.
    pub fn iter(&self) -> impl Iterator<Item = u16> + 'a {
        self.0
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
    }

    /// Iterates as cluster identifiers.
    pub fn clusters(&self) -> impl Iterator<Item = ClusterId> + 'a {
        self.iter().map(ClusterId)
    }

    /// Iterates as network addresses.
    pub fn addresses(&self) -> impl Iterator<Item = ShortAddress> + 'a {
        self.iter().map(ShortAddress)
    }

    fn decode_counted(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let n = usize::from(r.u8()?);
        Ok(U16List(r.bytes(n * 2)?))
    }

    fn encode_counted(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if !self.0.len().is_multiple_of(2) || self.len() > 255 {
            return Err(CodecError::Unrepresentable { field: "list" });
        }
        #[allow(clippy::cast_possible_truncation)]
        w.u8(self.len() as u8)?;
        w.bytes(self.0)
    }
}

/// A borrowed list of IEEE addresses (8 octets each).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Eui64List<'a>(pub &'a [u8]);

impl<'a> Eui64List<'a> {
    /// Number of addresses.
    #[inline]
    pub const fn len(&self) -> usize {
        self.0.len() / 8
    }

    /// True when empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0.len() < 8
    }

    /// Iterates the addresses.
    pub fn iter(&self) -> impl Iterator<Item = ExtendedAddress> + 'a {
        self.0.chunks_exact(8).map(|c| {
            let mut b = [0u8; 8];
            b.copy_from_slice(c);
            ExtendedAddress::from_le_bytes(b)
        })
    }
}

macro_rules! simple_frames {
    ($(
        $(#[$m:meta])*
        $name:ident { $( $(#[$fm:meta])* $field:ident : $ty:ty ),* $(,)? }
    )*) => {$(
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct $name { $( $(#[$fm])* pub $field: $ty, )* }

        impl<'a> Decode<'a> for $name {
            fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
                Ok($name { $( $field: <$ty as Decode>::decode(r)?, )* })
            }
        }

        impl Encode for $name {
            fn encoded_len(&self) -> usize {
                0 $( + self.$field.encoded_len() )*
            }
            fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
                $( self.$field.encode(w)?; )*
                Ok(())
            }
        }
    )*};
}

simple_frames! {
    /// Power_Desc_req (§2.4.3.1.4).
    PowerDescReq {
        /// NWKAddrOfInterest.
        addr: ShortAddress,
    }
    /// Simple_Desc_req (§2.4.3.1.5).
    SimpleDescReq {
        /// NWKAddrOfInterest.
        addr: ShortAddress,
        /// Endpoint.
        endpoint: Endpoint,
    }
    /// Active_EP_req (§2.4.3.1.6).
    ActiveEpReq {
        /// NWKAddrOfInterest.
        addr: ShortAddress,
    }
    /// Device_annce (§2.4.3.1.11).
    DeviceAnnce {
        /// NWKAddr.
        short: ShortAddress,
        /// IEEEAddr.
        ieee: ExtendedAddress,
        /// Capability.
        capability: MacCapability,
    }
    /// Mgmt_Lqi_req (§2.4.3.3.2).
    MgmtLqiReq {
        /// StartIndex.
        start_index: u8,
    }
    /// Mgmt_Rtg_req (§2.4.3.3.3).
    MgmtRtgReq {
        /// StartIndex.
        start_index: u8,
    }
    /// Mgmt_Bind_req (§2.4.3.3.4).
    MgmtBindReq {
        /// StartIndex.
        start_index: u8,
    }
    /// Power_Desc_rsp header (§2.4.4.2.4); the descriptor follows only on
    /// SUCCESS.
    PowerDescRspHeader {
        /// Status.
        status: ZdpStatus,
        /// NWKAddrOfInterest.
        addr: ShortAddress,
    }
    /// A response consisting of a status only (Bind_rsp, Unbind_rsp,
    /// Clear_All_Bindings_rsp, Mgmt_Leave_rsp, Mgmt_Permit_Joining_rsp).
    StatusRsp {
        /// Status.
        status: ZdpStatus,
    }
}

/// NWK_addr_req (§2.4.3.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NwkAddrReq {
    /// IEEEAddr to match.
    pub ieee: ExtendedAddress,
    /// RequestType.
    pub request_type: AddrRequestType,
    /// StartIndex for extended responses.
    pub start_index: u8,
}

impl<'a> Decode<'a> for NwkAddrReq {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(NwkAddrReq {
            ieee: ExtendedAddress(r.u64_le()?),
            request_type: AddrRequestType::from_raw(r.u8()?),
            start_index: r.u8()?,
        })
    }
}

impl Encode for NwkAddrReq {
    fn encoded_len(&self) -> usize {
        10
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.ieee.0)?;
        w.u8(self.request_type.raw())?;
        w.u8(self.start_index)
    }
}

/// IEEE_addr_req (§2.4.3.1.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IeeeAddrReq {
    /// NWKAddrOfInterest.
    pub addr: ShortAddress,
    /// RequestType.
    pub request_type: AddrRequestType,
    /// StartIndex for extended responses.
    pub start_index: u8,
}

impl<'a> Decode<'a> for IeeeAddrReq {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(IeeeAddrReq {
            addr: ShortAddress(r.u16_le()?),
            request_type: AddrRequestType::from_raw(r.u8()?),
            start_index: r.u8()?,
        })
    }
}

impl Encode for IeeeAddrReq {
    fn encoded_len(&self) -> usize {
        4
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.addr.0)?;
        w.u8(self.request_type.raw())?;
        w.u8(self.start_index)
    }
}

/// NWK_addr_rsp / IEEE_addr_rsp (§2.4.4.2.1, §2.4.4.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddrRsp<'a> {
    /// Status.
    pub status: ZdpStatus,
    /// IEEEAddrRemoteDev.
    pub ieee: ExtendedAddress,
    /// NWKAddrRemoteDev.
    pub short: ShortAddress,
    /// Extended response: StartIndex and the associated device list.
    pub associated: Option<(u8, U16List<'a>)>,
}

impl<'a> Decode<'a> for AddrRsp<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZdpStatus::decode(r)?;
        let ieee = ExtendedAddress(r.u64_le()?);
        let short = ShortAddress(r.u16_le()?);
        let associated = if r.remaining() >= 2 {
            let n = usize::from(r.u8()?);
            let start = r.u8()?;
            Some((start, U16List(r.bytes(n * 2)?)))
        } else {
            None
        };
        Ok(AddrRsp {
            status,
            ieee,
            short,
            associated,
        })
    }
}

impl Encode for AddrRsp<'_> {
    fn encoded_len(&self) -> usize {
        1 + 8 + 2 + self.associated.map_or(0, |(_, l)| 2 + l.0.len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u64_le(self.ieee.0)?;
        w.u16_le(self.short.0)?;
        if let Some((start, list)) = self.associated {
            if !list.0.len().is_multiple_of(2) || list.len() > 255 {
                return Err(CodecError::Unrepresentable { field: "list" });
            }
            #[allow(clippy::cast_possible_truncation)]
            w.u8(list.len() as u8)?;
            w.u8(start)?;
            w.bytes(list.0)?;
        }
        Ok(())
    }
}

/// Node_Desc_req (§2.4.3.1.3): address plus TLVs (the Fragmentation
/// Parameters global TLV is mandatory on transmission).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeDescReq<'a> {
    /// NWKAddrOfInterest.
    pub addr: ShortAddress,
    /// TLVs.
    pub tlvs: &'a [u8],
}

impl<'a> Decode<'a> for NodeDescReq<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let addr = ShortAddress(r.u16_le()?);
        let tlvs = r.take_rest();
        Ok(NodeDescReq { addr, tlvs })
    }
}

impl Encode for NodeDescReq<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.addr.0)?;
        w.bytes(self.tlvs)
    }
}

/// Node_Desc_rsp (§2.4.4.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeDescRsp<'a> {
    /// Status.
    pub status: ZdpStatus,
    /// NWKAddrOfInterest.
    pub addr: ShortAddress,
    /// The descriptor (SUCCESS only).
    pub descriptor: Option<NodeDescriptor>,
    /// TLVs (may be empty when sent by pre-R23 devices).
    pub tlvs: &'a [u8],
}

impl<'a> Decode<'a> for NodeDescRsp<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZdpStatus::decode(r)?;
        let addr = ShortAddress(r.u16_le()?);
        let descriptor = if status.is_success() {
            Some(NodeDescriptor::decode(r)?)
        } else {
            None
        };
        let tlvs = r.take_rest();
        Ok(NodeDescRsp {
            status,
            addr,
            descriptor,
            tlvs,
        })
    }
}

impl Encode for NodeDescRsp<'_> {
    fn encoded_len(&self) -> usize {
        1 + 2 + self.descriptor.map_or(0, |_| NodeDescriptor::LEN) + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u16_le(self.addr.0)?;
        if let Some(d) = &self.descriptor {
            d.encode(w)?;
        }
        w.bytes(self.tlvs)
    }
}

/// Power_Desc_rsp (§2.4.4.2.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PowerDescRsp {
    /// Status.
    pub status: ZdpStatus,
    /// NWKAddrOfInterest.
    pub addr: ShortAddress,
    /// The descriptor (SUCCESS only).
    pub descriptor: Option<PowerDescriptor>,
}

impl<'a> Decode<'a> for PowerDescRsp {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let h = PowerDescRspHeader::decode(r)?;
        let descriptor = if h.status.is_success() {
            Some(PowerDescriptor::decode(r)?)
        } else {
            None
        };
        Ok(PowerDescRsp {
            status: h.status,
            addr: h.addr,
            descriptor,
        })
    }
}

impl Encode for PowerDescRsp {
    fn encoded_len(&self) -> usize {
        3 + self.descriptor.map_or(0, |_| 2)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u16_le(self.addr.0)?;
        if let Some(d) = &self.descriptor {
            d.encode(w)?;
        }
        Ok(())
    }
}

/// Simple_Desc_rsp (§2.4.4.2.5). The descriptor is kept as its wire
/// bytes; decode it with [`crate::descriptor::SimpleDescriptor`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SimpleDescRsp<'a> {
    /// Status.
    pub status: ZdpStatus,
    /// NWKAddrOfInterest.
    pub addr: ShortAddress,
    /// Encoded simple descriptor (SUCCESS only).
    pub descriptor: Option<&'a [u8]>,
}

impl<'a> Decode<'a> for SimpleDescRsp<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZdpStatus::decode(r)?;
        let addr = ShortAddress(r.u16_le()?);
        let len = usize::from(r.u8()?);
        let descriptor = if status.is_success() && len > 0 {
            Some(r.bytes(len)?)
        } else {
            None
        };
        Ok(SimpleDescRsp {
            status,
            addr,
            descriptor,
        })
    }
}

impl Encode for SimpleDescRsp<'_> {
    fn encoded_len(&self) -> usize {
        4 + self.descriptor.map_or(0, <[u8]>::len)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u16_le(self.addr.0)?;
        match self.descriptor {
            Some(d) if d.len() <= 255 => {
                #[allow(clippy::cast_possible_truncation)]
                w.u8(d.len() as u8)?;
                w.bytes(d)
            }
            Some(_) => Err(CodecError::Unrepresentable {
                field: "simple descriptor",
            }),
            None => w.u8(0),
        }
    }
}

/// Active_EP_rsp (§2.4.4.2.6) and Match_Desc_rsp (§2.4.4.2.7): status,
/// address and an endpoint list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EndpointListRsp<'a> {
    /// Status.
    pub status: ZdpStatus,
    /// NWKAddrOfInterest.
    pub addr: ShortAddress,
    /// Endpoints.
    pub endpoints: &'a [u8],
}

impl EndpointListRsp<'_> {
    /// Iterates the endpoints.
    pub fn iter(&self) -> impl Iterator<Item = Endpoint> + '_ {
        self.endpoints.iter().map(|e| Endpoint(*e))
    }
}

impl<'a> Decode<'a> for EndpointListRsp<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZdpStatus::decode(r)?;
        let addr = ShortAddress(r.u16_le()?);
        let n = usize::from(r.u8()?);
        let endpoints = r.bytes(n)?;
        Ok(EndpointListRsp {
            status,
            addr,
            endpoints,
        })
    }
}

impl Encode for EndpointListRsp<'_> {
    fn encoded_len(&self) -> usize {
        4 + self.endpoints.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if self.endpoints.len() > 255 {
            return Err(CodecError::Unrepresentable { field: "endpoints" });
        }
        w.u8(self.status.raw())?;
        w.u16_le(self.addr.0)?;
        #[allow(clippy::cast_possible_truncation)]
        w.u8(self.endpoints.len() as u8)?;
        w.bytes(self.endpoints)
    }
}

/// Match_Desc_req (§2.4.3.1.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MatchDescReq<'a> {
    /// NWKAddrOfInterest (0xfffd when broadcast).
    pub addr: ShortAddress,
    /// ProfileID (0xffff wildcard).
    pub profile: ProfileId,
    /// InClusterList: clusters the remote must serve.
    pub input: U16List<'a>,
    /// OutClusterList: clusters the remote must be a client of.
    pub output: U16List<'a>,
}

impl<'a> Decode<'a> for MatchDescReq<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let addr = ShortAddress(r.u16_le()?);
        let profile = ProfileId(r.u16_le()?);
        let input = U16List::decode_counted(r)?;
        let output = U16List::decode_counted(r)?;
        Ok(MatchDescReq {
            addr,
            profile,
            input,
            output,
        })
    }
}

impl Encode for MatchDescReq<'_> {
    fn encoded_len(&self) -> usize {
        2 + 2 + 1 + self.input.0.len() + 1 + self.output.0.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.addr.0)?;
        w.u16_le(self.profile.0)?;
        self.input.encode_counted(w)?;
        self.output.encode_counted(w)
    }
}

/// Parent_annce (§2.4.3.1.12): the announcing router's end-device
/// children.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParentAnnce<'a> {
    /// ChildInfo list (IEEE addresses).
    pub children: Eui64List<'a>,
}

impl<'a> Decode<'a> for ParentAnnce<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let n = usize::from(r.u8()?);
        Ok(ParentAnnce {
            children: Eui64List(r.bytes(n * 8)?),
        })
    }
}

impl Encode for ParentAnnce<'_> {
    fn encoded_len(&self) -> usize {
        1 + self.children.0.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if !self.children.0.len().is_multiple_of(8) || self.children.len() > 255 {
            return Err(CodecError::Unrepresentable { field: "children" });
        }
        #[allow(clippy::cast_possible_truncation)]
        w.u8(self.children.len() as u8)?;
        w.bytes(self.children.0)
    }
}

/// Parent_annce_rsp (§2.4.4.2.19).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParentAnnceRsp<'a> {
    /// Status.
    pub status: ZdpStatus,
    /// Children this router also claims.
    pub children: Eui64List<'a>,
}

impl<'a> Decode<'a> for ParentAnnceRsp<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZdpStatus::decode(r)?;
        let n = usize::from(r.u8()?);
        Ok(ParentAnnceRsp {
            status,
            children: Eui64List(r.bytes(n * 8)?),
        })
    }
}

impl Encode for ParentAnnceRsp<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.children.0.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if !self.children.0.len().is_multiple_of(8) || self.children.len() > 255 {
            return Err(CodecError::Unrepresentable { field: "children" });
        }
        w.u8(self.status.raw())?;
        #[allow(clippy::cast_possible_truncation)]
        w.u8(self.children.len() as u8)?;
        w.bytes(self.children.0)
    }
}

/// System_Server_Discovery_req (§2.4.3.1.14).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SystemServerDiscoveryReq {
    /// ServerMask.
    pub mask: ServerMask,
}

impl<'a> Decode<'a> for SystemServerDiscoveryReq {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(SystemServerDiscoveryReq {
            mask: ServerMask(r.u16_le()?),
        })
    }
}

impl Encode for SystemServerDiscoveryReq {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.mask.0)
    }
}

/// System_Server_Discovery_rsp (§2.4.4.2.10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SystemServerDiscoveryRsp {
    /// Status.
    pub status: ZdpStatus,
    /// Matching server bits.
    pub mask: ServerMask,
}

impl<'a> Decode<'a> for SystemServerDiscoveryRsp {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(SystemServerDiscoveryRsp {
            status: ZdpStatus::decode(r)?,
            mask: ServerMask(r.u16_le()?),
        })
    }
}

impl Encode for SystemServerDiscoveryRsp {
    fn encoded_len(&self) -> usize {
        3
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u16_le(self.mask.0)
    }
}

/// Bind_req / Unbind_req (§2.4.3.2.2, §2.4.3.2.3) and the binding table
/// record of Mgmt_Bind_rsp (Table 2-106).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BindReq {
    /// SrcAddress.
    pub src: ExtendedAddress,
    /// SrcEndp.
    pub src_endpoint: Endpoint,
    /// ClusterID.
    pub cluster: ClusterId,
    /// Destination (DstAddrMode 0x01 group or 0x03 extended + endpoint).
    pub destination: BindingDestination,
}

impl<'a> Decode<'a> for BindReq {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let src = ExtendedAddress(r.u64_le()?);
        let src_endpoint = Endpoint(r.u8()?);
        let cluster = ClusterId(r.u16_le()?);
        let mode = r.u8()?;
        let destination = match mode {
            0x01 => BindingDestination::Group(panweave_types::GroupAddress(r.u16_le()?)),
            0x03 => BindingDestination::Unicast {
                address: ExtendedAddress(r.u64_le()?),
                endpoint: Endpoint(r.u8()?),
            },
            v => {
                return Err(CodecError::InvalidField {
                    field: "DstAddrMode",
                    value: u32::from(v),
                });
            }
        };
        Ok(BindReq {
            src,
            src_endpoint,
            cluster,
            destination,
        })
    }
}

impl Encode for BindReq {
    fn encoded_len(&self) -> usize {
        8 + 1
            + 2
            + 1
            + match self.destination {
                BindingDestination::Group(_) => 2,
                BindingDestination::Unicast { .. } => 9,
            }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.src.0)?;
        w.u8(self.src_endpoint.0)?;
        w.u16_le(self.cluster.0)?;
        match self.destination {
            BindingDestination::Group(g) => {
                w.u8(0x01)?;
                w.u16_le(g.0)
            }
            BindingDestination::Unicast { address, endpoint } => {
                w.u8(0x03)?;
                w.u64_le(address.0)?;
                w.u8(endpoint.0)
            }
        }
    }
}

/// Tag of the Clear All Bindings Req EUI64 local TLV (§2.4.3.2.12.2).
pub const TLV_CLEAR_ALL_BINDINGS_EUI64: u8 = 0x00;

/// Clear_All_Bindings_req (§2.4.3.2.12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClearAllBindingsReq<'a> {
    /// The TLVs.
    pub tlvs: &'a [u8],
}

impl<'a> ClearAllBindingsReq<'a> {
    /// The EUI64 list from the mandatory local TLV, if present and well
    /// formed.
    pub fn eui64s(&self) -> Option<Eui64List<'a>> {
        let set = TlvSet::validate(self.tlvs, |_| false).ok()?;
        let v = set.value(TLV_CLEAR_ALL_BINDINGS_EUI64)?;
        let n = usize::from(*v.first()?);
        let bytes = v.get(1..1 + n * 8)?;
        Some(Eui64List(bytes))
    }

    /// Encodes the request TLV for `eui64s` into `buf`, returning the
    /// used length.
    pub fn build(eui64s: &[ExtendedAddress], buf: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(buf);
        let len = 1 + 8 * eui64s.len();
        if eui64s.len() > 255 || len > 256 {
            return Err(CodecError::Unrepresentable { field: "eui64s" });
        }
        w.u8(TLV_CLEAR_ALL_BINDINGS_EUI64)?;
        #[allow(clippy::cast_possible_truncation)]
        w.u8((len - 1) as u8)?;
        #[allow(clippy::cast_possible_truncation)]
        w.u8(eui64s.len() as u8)?;
        for e in eui64s {
            w.u64_le(e.0)?;
        }
        Ok(w.position())
    }
}

impl<'a> Decode<'a> for ClearAllBindingsReq<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(ClearAllBindingsReq {
            tlvs: r.take_rest(),
        })
    }
}

impl Encode for ClearAllBindingsReq<'_> {
    fn encoded_len(&self) -> usize {
        self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.bytes(self.tlvs)
    }
}

/// Mgmt_Leave_req (§2.4.3.3.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MgmtLeaveReq {
    /// DeviceAddress (zero = the receiving device).
    pub device: ExtendedAddress,
    /// Remove Children.
    pub remove_children: bool,
    /// Rejoin.
    pub rejoin: bool,
}

impl<'a> Decode<'a> for MgmtLeaveReq {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let device = ExtendedAddress(r.u64_le()?);
        let flags = r.u8()?;
        Ok(MgmtLeaveReq {
            device,
            remove_children: flags & 0x40 != 0,
            rejoin: flags & 0x80 != 0,
        })
    }
}

impl Encode for MgmtLeaveReq {
    fn encoded_len(&self) -> usize {
        9
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.device.0)?;
        w.u8((u8::from(self.remove_children) << 6) | (u8::from(self.rejoin) << 7))
    }
}

/// Mgmt_Permit_Joining_req (§2.4.3.3.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MgmtPermitJoiningReq<'a> {
    /// PermitDuration (0xff is treated as 0xfe).
    pub duration: u8,
    /// TC_Significance (always treated as 1).
    pub tc_significance: bool,
    /// TLV Data (R23).
    pub tlvs: &'a [u8],
}

impl<'a> Decode<'a> for MgmtPermitJoiningReq<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let duration = r.u8()?;
        let tc_significance = r.u8()? != 0;
        let tlvs = r.take_rest();
        Ok(MgmtPermitJoiningReq {
            duration,
            tc_significance,
            tlvs,
        })
    }
}

impl Encode for MgmtPermitJoiningReq<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.duration)?;
        w.u8(u8::from(self.tc_significance))?;
        w.bytes(self.tlvs)
    }
}

/// Mgmt_NWK_Update_req (§2.4.3.3.9). `scan_duration` 0x00–0x05 requests
/// energy scans, 0xfe a channel change, 0xff a channel mask / manager
/// update.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MgmtNwkUpdateReq {
    /// ScanChannels.
    pub scan_channels: ChannelMask,
    /// ScanDuration.
    pub scan_duration: u8,
    /// ScanCount (energy scans only).
    pub scan_count: Option<u8>,
    /// nwkUpdateId (0xfe / 0xff only).
    pub update_id: Option<u8>,
    /// nwkManagerAddr (0xff only).
    pub manager: Option<ShortAddress>,
}

impl MgmtNwkUpdateReq {
    /// ScanDuration value requesting a channel change.
    pub const CHANNEL_CHANGE: u8 = 0xFE;
    /// ScanDuration value requesting a mask / manager update.
    pub const ATTRIBUTE_CHANGE: u8 = 0xFF;
}

impl<'a> Decode<'a> for MgmtNwkUpdateReq {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let scan_channels = ChannelMask(r.u32_le()?);
        let scan_duration = r.u8()?;
        let (scan_count, update_id, manager) = match scan_duration {
            0..=0x05 => (Some(r.u8()?), None, None),
            Self::CHANNEL_CHANGE => (None, Some(r.u8()?), None),
            Self::ATTRIBUTE_CHANGE => (None, Some(r.u8()?), Some(ShortAddress(r.u16_le()?))),
            v => {
                return Err(CodecError::InvalidField {
                    field: "ScanDuration",
                    value: u32::from(v),
                });
            }
        };
        Ok(MgmtNwkUpdateReq {
            scan_channels,
            scan_duration,
            scan_count,
            update_id,
            manager,
        })
    }
}

impl Encode for MgmtNwkUpdateReq {
    fn encoded_len(&self) -> usize {
        5 + match self.scan_duration {
            0..=0x05 => 1,
            Self::CHANNEL_CHANGE => 1,
            _ => 3,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.scan_channels.0)?;
        w.u8(self.scan_duration)?;
        match self.scan_duration {
            0..=0x05 => w.u8(self.scan_count.unwrap_or(1)),
            Self::CHANNEL_CHANGE => w.u8(self.update_id.unwrap_or(0)),
            _ => {
                w.u8(self.update_id.unwrap_or(0))?;
                w.u16_le(self.manager.unwrap_or(ShortAddress::COORDINATOR).0)
            }
        }
    }
}

/// Mgmt_NWK_Update_notify (§2.4.4.3.9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MgmtNwkUpdateNotify<'a> {
    /// Status.
    pub status: ZdpStatus,
    /// ScannedChannels.
    pub scanned_channels: ChannelMask,
    /// TotalTransmissions.
    pub total_transmissions: u16,
    /// TransmissionFailures.
    pub transmission_failures: u16,
    /// EnergyValues, one per scanned channel in ascending order.
    pub energy: &'a [u8],
}

impl<'a> Decode<'a> for MgmtNwkUpdateNotify<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZdpStatus::decode(r)?;
        let scanned_channels = ChannelMask(r.u32_le()?);
        let total_transmissions = r.u16_le()?;
        let transmission_failures = r.u16_le()?;
        let n = usize::from(r.u8()?);
        let energy = r.bytes(n)?;
        Ok(MgmtNwkUpdateNotify {
            status,
            scanned_channels,
            total_transmissions,
            transmission_failures,
            energy,
        })
    }
}

impl Encode for MgmtNwkUpdateNotify<'_> {
    fn encoded_len(&self) -> usize {
        1 + 4 + 2 + 2 + 1 + self.energy.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if self.energy.len() > 255 {
            return Err(CodecError::Unrepresentable { field: "energy" });
        }
        w.u8(self.status.raw())?;
        w.u32_le(self.scanned_channels.0)?;
        w.u16_le(self.total_transmissions)?;
        w.u16_le(self.transmission_failures)?;
        #[allow(clippy::cast_possible_truncation)]
        w.u8(self.energy.len() as u8)?;
        w.bytes(self.energy)
    }
}

/// Device type in a neighbor table record (Table 2-102).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NeighborDeviceType {
    /// Coordinator.
    Coordinator,
    /// Router.
    Router,
    /// End device.
    EndDevice,
    /// Unknown.
    Unknown,
}

/// Relationship in a neighbor table record (Table 2-102).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NeighborRelationship {
    /// The neighbor is the parent.
    Parent,
    /// The neighbor is a child.
    Child,
    /// The neighbor is a sibling.
    Sibling,
    /// None of the above.
    None,
    /// Reserved value.
    Reserved(u8),
}

/// Tri-state field (rx-on-when-idle, permit joining) of Table 2-102.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TriState {
    /// False / off.
    No,
    /// True / on.
    Yes,
    /// Unknown.
    Unknown,
}

impl TriState {
    const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => TriState::No,
            1 => TriState::Yes,
            _ => TriState::Unknown,
        }
    }

    const fn bits(self) -> u8 {
        match self {
            TriState::No => 0,
            TriState::Yes => 1,
            TriState::Unknown => 2,
        }
    }
}

/// A Mgmt_Lqi_rsp neighbor table record (Table 2-102, 22 octets).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighborRecord {
    /// Extended PAN identifier.
    pub extended_pan_id: ExtendedAddress,
    /// IEEE address (all ones when unknown).
    pub ieee: ExtendedAddress,
    /// Network address.
    pub short: ShortAddress,
    /// Device type.
    pub device_type: NeighborDeviceType,
    /// Rx on when idle.
    pub rx_on_when_idle: TriState,
    /// Relationship.
    pub relationship: NeighborRelationship,
    /// Permit joining.
    pub permit_joining: TriState,
    /// Tree depth.
    pub depth: u8,
    /// LQA.
    pub lqa: u8,
}

impl NeighborRecord {
    /// Encoded size.
    pub const LEN: usize = 22;
}

impl<'a> Decode<'a> for NeighborRecord {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let extended_pan_id = ExtendedAddress(r.u64_le()?);
        let ieee = ExtendedAddress(r.u64_le()?);
        let short = ShortAddress(r.u16_le()?);
        let b = r.u8()?;
        let device_type = match b & 0x3 {
            0 => NeighborDeviceType::Coordinator,
            1 => NeighborDeviceType::Router,
            2 => NeighborDeviceType::EndDevice,
            _ => NeighborDeviceType::Unknown,
        };
        let rx_on_when_idle = TriState::from_bits(b >> 2);
        let relationship = match (b >> 4) & 0x7 {
            0 => NeighborRelationship::Parent,
            1 => NeighborRelationship::Child,
            2 => NeighborRelationship::Sibling,
            3 => NeighborRelationship::None,
            v => NeighborRelationship::Reserved(v),
        };
        let permit_joining = TriState::from_bits(r.u8()?);
        let depth = r.u8()?;
        let lqa = r.u8()?;
        Ok(NeighborRecord {
            extended_pan_id,
            ieee,
            short,
            device_type,
            rx_on_when_idle,
            relationship,
            permit_joining,
            depth,
            lqa,
        })
    }
}

impl Encode for NeighborRecord {
    fn encoded_len(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.extended_pan_id.0)?;
        w.u64_le(self.ieee.0)?;
        w.u16_le(self.short.0)?;
        let dt = match self.device_type {
            NeighborDeviceType::Coordinator => 0,
            NeighborDeviceType::Router => 1,
            NeighborDeviceType::EndDevice => 2,
            NeighborDeviceType::Unknown => 3,
        };
        let rel = match self.relationship {
            NeighborRelationship::Parent => 0,
            NeighborRelationship::Child => 1,
            NeighborRelationship::Sibling => 2,
            NeighborRelationship::None => 3,
            NeighborRelationship::Reserved(v) => v & 0x7,
        };
        w.u8(dt | (self.rx_on_when_idle.bits() << 2) | (rel << 4))?;
        w.u8(self.permit_joining.bits())?;
        w.u8(self.depth)?;
        w.u8(self.lqa)
    }
}

/// Route status in a routing table record (Table 2-104).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RouteRecordStatus {
    /// ACTIVE.
    Active,
    /// DISCOVERY_UNDERWAY.
    DiscoveryUnderway,
    /// DISCOVERY_FAILED.
    DiscoveryFailed,
    /// INACTIVE.
    Inactive,
    /// Reserved.
    Reserved(u8),
}

/// A Mgmt_Rtg_rsp routing table record (Table 2-104, 5 octets).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteRecord {
    /// Destination address.
    pub destination: ShortAddress,
    /// Status.
    pub status: RouteRecordStatus,
    /// Memory constrained concentrator.
    pub memory_constrained: bool,
    /// Many-to-one route.
    pub many_to_one: bool,
    /// Route record required.
    pub route_record_required: bool,
    /// Next hop.
    pub next_hop: ShortAddress,
}

impl RouteRecord {
    /// Encoded size.
    pub const LEN: usize = 5;
}

impl<'a> Decode<'a> for RouteRecord {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let destination = ShortAddress(r.u16_le()?);
        let b = r.u8()?;
        let status = match b & 0x7 {
            0 => RouteRecordStatus::Active,
            1 => RouteRecordStatus::DiscoveryUnderway,
            2 => RouteRecordStatus::DiscoveryFailed,
            3 => RouteRecordStatus::Inactive,
            v => RouteRecordStatus::Reserved(v),
        };
        let next_hop = ShortAddress(r.u16_le()?);
        Ok(RouteRecord {
            destination,
            status,
            memory_constrained: b & 0x08 != 0,
            many_to_one: b & 0x10 != 0,
            route_record_required: b & 0x20 != 0,
            next_hop,
        })
    }
}

impl Encode for RouteRecord {
    fn encoded_len(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.destination.0)?;
        let st = match self.status {
            RouteRecordStatus::Active => 0,
            RouteRecordStatus::DiscoveryUnderway => 1,
            RouteRecordStatus::DiscoveryFailed => 2,
            RouteRecordStatus::Inactive => 3,
            RouteRecordStatus::Reserved(v) => v & 0x7,
        };
        w.u8(st
            | (u8::from(self.memory_constrained) << 3)
            | (u8::from(self.many_to_one) << 4)
            | (u8::from(self.route_record_required) << 5))?;
        w.u16_le(self.next_hop.0)
    }
}

/// Mgmt_Lqi_rsp, Mgmt_Rtg_rsp and Mgmt_Bind_rsp (§2.4.4.3.2–§2.4.4.3.4):
/// status, total entries, start index and a counted list of records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TableRsp<'a> {
    /// Status.
    pub status: ZdpStatus,
    /// Total number of entries in the table.
    pub total: u8,
    /// StartIndex.
    pub start_index: u8,
    /// Number of records in `records`.
    pub count: u8,
    /// Encoded records.
    pub records: &'a [u8],
}

impl<'a> TableRsp<'a> {
    /// Decodes the records as `T` (fixed-size records).
    pub fn iter<T: Decode<'a>>(&self) -> impl Iterator<Item = Result<T, CodecError>> + 'a {
        let mut r = Reader::new(self.records);
        let count = self.count;
        (0..count).map(move |_| T::decode(&mut r))
    }
}

impl<'a> Decode<'a> for TableRsp<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let status = ZdpStatus::decode(r)?;
        let total = r.u8()?;
        let start_index = r.u8()?;
        let count = r.u8()?;
        let records = r.take_rest();
        Ok(TableRsp {
            status,
            total,
            start_index,
            count,
            records,
        })
    }
}

impl Encode for TableRsp<'_> {
    fn encoded_len(&self) -> usize {
        4 + self.records.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u8(self.total)?;
        w.u8(self.start_index)?;
        w.u8(self.count)?;
        w.bytes(self.records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<'a, T: Decode<'a> + Encode + PartialEq + core::fmt::Debug>(
        v: &T,
        buf: &'a mut [u8],
    ) -> &'a [u8] {
        let n = v.encode_to_slice(buf).unwrap();
        assert_eq!(n, v.encoded_len());
        let out = &buf[..n];
        assert_eq!(&T::decode_exact(out).unwrap(), v);
        out
    }

    #[test]
    fn cluster_helpers_and_status() {
        assert_eq!(
            cluster::response_of(cluster::NODE_DESC_REQ),
            ClusterId(0x8002)
        );
        assert!(cluster::is_response(ClusterId(0x8031)));
        assert_eq!(
            cluster::request_of(ClusterId(0x8031)),
            cluster::MGMT_LQI_REQ
        );
        for v in 0..=255u8 {
            assert_eq!(ZdpStatus::from_raw(v).raw(), v);
        }
    }

    #[test]
    fn address_requests_and_responses() {
        let mut buf = [0u8; 64];
        let b = rt(
            &NwkAddrReq {
                ieee: ExtendedAddress(0x0102_0304_0506_0708),
                request_type: AddrRequestType::Extended,
                start_index: 2,
            },
            &mut buf,
        );
        assert_eq!(b, &[8, 7, 6, 5, 4, 3, 2, 1, 1, 2]);
        rt(
            &IeeeAddrReq {
                addr: ShortAddress(0x1234),
                request_type: AddrRequestType::Single,
                start_index: 0,
            },
            &mut buf,
        );
        let list = [0x01u8, 0x00, 0x02, 0x00];
        let rsp = AddrRsp {
            status: ZdpStatus::Success,
            ieee: ExtendedAddress(7),
            short: ShortAddress(0x0001),
            associated: Some((0, U16List(&list))),
        };
        let mut buf2 = [0u8; 64];
        let b = rt(&rsp, &mut buf2);
        assert_eq!(b.len(), 1 + 8 + 2 + 2 + 4);
        let d = AddrRsp::decode_exact(b).unwrap();
        let addrs: heapless::Vec<ShortAddress, 4> = d.associated.unwrap().1.addresses().collect();
        assert_eq!(addrs.as_slice(), &[ShortAddress(1), ShortAddress(2)]);
        let short = AddrRsp {
            associated: None,
            ..rsp
        };
        assert_eq!(rt(&short, &mut buf2).len(), 11);
    }

    #[test]
    fn descriptor_requests_and_responses() {
        let mut buf = [0u8; 64];
        rt(
            &NodeDescReq {
                addr: ShortAddress(1),
                tlvs: &[0x44, 0x03, 0x01, 0x00, 0x01],
            },
            &mut buf,
        );
        let rsp = NodeDescRsp {
            status: ZdpStatus::DeviceNotFound,
            addr: ShortAddress(1),
            descriptor: None,
            tlvs: &[],
        };
        assert_eq!(rt(&rsp, &mut buf), &[0x81, 1, 0]);
        rt(
            &PowerDescRsp {
                status: ZdpStatus::Success,
                addr: ShortAddress(1),
                descriptor: Some(PowerDescriptor::MAINS),
            },
            &mut buf,
        );
        rt(
            &SimpleDescRsp {
                status: ZdpStatus::Success,
                addr: ShortAddress(1),
                descriptor: Some(&[1, 4, 1, 0, 1, 0, 0, 0]),
            },
            &mut buf,
        );
        assert_eq!(
            rt(
                &SimpleDescRsp {
                    status: ZdpStatus::NotActive,
                    addr: ShortAddress(1),
                    descriptor: None,
                },
                &mut buf
            ),
            &[0x83, 1, 0, 0]
        );
        rt(
            &EndpointListRsp {
                status: ZdpStatus::Success,
                addr: ShortAddress(1),
                endpoints: &[1, 2, 242],
            },
            &mut buf,
        );
        let inp = [6u8, 0, 8, 0];
        let out = [0x19u8, 0];
        let m = MatchDescReq {
            addr: ShortAddress::BROADCAST_RX_ON,
            profile: ProfileId::WILDCARD,
            input: U16List(&inp),
            output: U16List(&out),
        };
        let b = rt(&m, &mut buf);
        assert_eq!(b, &[0xFD, 0xFF, 0xFF, 0xFF, 2, 6, 0, 8, 0, 1, 0x19, 0]);
    }

    #[test]
    fn announce_and_binding_frames() {
        let mut buf = [0u8; 64];
        let b = rt(
            &DeviceAnnce {
                short: ShortAddress(0x1234),
                ieee: ExtendedAddress(1),
                capability: MacCapability::ROUTER,
            },
            &mut buf,
        );
        assert_eq!(b.len(), 11);
        let kids = [1u8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        let p = ParentAnnce {
            children: Eui64List(&kids),
        };
        let b = rt(&p, &mut buf);
        assert_eq!(b[0], 2);
        let kids2: heapless::Vec<_, 2> = ParentAnnce::decode_exact(b)
            .unwrap()
            .children
            .iter()
            .collect();
        assert_eq!(kids2.as_slice(), &[ExtendedAddress(1), ExtendedAddress(2)]);
        rt(
            &ParentAnnceRsp {
                status: ZdpStatus::Success,
                children: Eui64List(&kids[..8]),
            },
            &mut buf,
        );
        let bind = BindReq {
            src: ExtendedAddress(5),
            src_endpoint: Endpoint(1),
            cluster: ClusterId(6),
            destination: BindingDestination::Unicast {
                address: ExtendedAddress(9),
                endpoint: Endpoint(2),
            },
        };
        assert_eq!(rt(&bind, &mut buf).len(), 21);
        let gbind = BindReq {
            destination: BindingDestination::Group(panweave_types::GroupAddress(3)),
            ..bind
        };
        assert_eq!(rt(&gbind, &mut buf).len(), 14);
        // Reserved DstAddrMode.
        assert!(BindReq::decode_exact(&[0; 12]).is_err());

        let mut tlv = [0u8; 32];
        let n = ClearAllBindingsReq::build(&[ExtendedAddress::BROADCAST], &mut tlv).unwrap();
        let req = ClearAllBindingsReq { tlvs: &tlv[..n] };
        let list: heapless::Vec<_, 2> = req.eui64s().unwrap().iter().collect();
        assert_eq!(list.as_slice(), &[ExtendedAddress::BROADCAST]);
        assert!(ClearAllBindingsReq { tlvs: &[] }.eui64s().is_none());
    }

    #[test]
    fn management_frames() {
        let mut buf = [0u8; 64];
        let b = rt(
            &MgmtLeaveReq {
                device: ExtendedAddress::ZERO,
                remove_children: true,
                rejoin: true,
            },
            &mut buf,
        );
        assert_eq!(b[8], 0xC0);
        rt(
            &MgmtPermitJoiningReq {
                duration: 180,
                tc_significance: true,
                tlvs: &[],
            },
            &mut buf,
        );
        let scan = MgmtNwkUpdateReq {
            scan_channels: ChannelMask::ALL_2_4GHZ,
            scan_duration: 3,
            scan_count: Some(1),
            update_id: None,
            manager: None,
        };
        assert_eq!(rt(&scan, &mut buf).len(), 6);
        let change = MgmtNwkUpdateReq {
            scan_channels: ChannelMask(1 << 15),
            scan_duration: MgmtNwkUpdateReq::CHANNEL_CHANGE,
            scan_count: None,
            update_id: Some(4),
            manager: None,
        };
        assert_eq!(rt(&change, &mut buf).len(), 6);
        let attrs = MgmtNwkUpdateReq {
            scan_channels: ChannelMask::ALL_2_4GHZ,
            scan_duration: MgmtNwkUpdateReq::ATTRIBUTE_CHANGE,
            scan_count: None,
            update_id: Some(0),
            manager: Some(ShortAddress(0)),
        };
        assert_eq!(rt(&attrs, &mut buf).len(), 8);
        assert!(MgmtNwkUpdateReq::decode_exact(&[0, 0, 0, 0, 0x10, 1]).is_err());
        rt(
            &MgmtNwkUpdateNotify {
                status: ZdpStatus::Success,
                scanned_channels: ChannelMask::ALL_2_4GHZ,
                total_transmissions: 10,
                transmission_failures: 1,
                energy: &[0x40; 16],
            },
            &mut buf,
        );

        let n1 = NeighborRecord {
            extended_pan_id: ExtendedAddress(0xEE),
            ieee: ExtendedAddress(0x11),
            short: ShortAddress(0x22),
            device_type: NeighborDeviceType::EndDevice,
            rx_on_when_idle: TriState::No,
            relationship: NeighborRelationship::Child,
            permit_joining: TriState::Unknown,
            depth: 1,
            lqa: 200,
        };
        let mut rec = [0u8; 22];
        rt(&n1, &mut rec);
        assert_eq!(rec[18], 0x12);
        assert_eq!(rec[19], 0x02);
        let rsp = TableRsp {
            status: ZdpStatus::Success,
            total: 1,
            start_index: 0,
            count: 1,
            records: &rec,
        };
        let b = rt(&rsp, &mut buf);
        let d = TableRsp::decode_exact(b).unwrap();
        let recs: heapless::Vec<NeighborRecord, 2> =
            d.iter::<NeighborRecord>().map(Result::unwrap).collect();
        assert_eq!(recs.as_slice(), &[n1]);

        let r1 = RouteRecord {
            destination: ShortAddress(1),
            status: RouteRecordStatus::Active,
            memory_constrained: false,
            many_to_one: true,
            route_record_required: false,
            next_hop: ShortAddress(2),
        };
        let mut rr = [0u8; 5];
        assert_eq!(rt(&r1, &mut rr), &[1, 0, 0x10, 2, 0]);
    }
}
