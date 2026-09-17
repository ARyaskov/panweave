//! NWK command frames (R23.2 §3.4, Table 3-54).
//!
//! Each command is represented as a borrowed struct with a strict decoder
//! and a deterministic encoder. Unknown command identifiers are preserved
//! as [`NwkCommand::Unknown`] so that the receiver can apply the
//! "unknown command" rule (§3.6.13) instead of silently mis-parsing.

use panweave_codec::tlv::TlvSet;
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{ExtendedAddress, MacCapability, MacStatus, PanId, ShortAddress};

/// NWK command identifiers (Table 3-54).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NwkCommandId {
    /// Route Request (0x01).
    RouteRequest,
    /// Route Reply (0x02).
    RouteReply,
    /// Network Status (0x03).
    NetworkStatus,
    /// Leave (0x04).
    Leave,
    /// Route Record (0x05).
    RouteRecord,
    /// Rejoin Request (0x06).
    RejoinRequest,
    /// Rejoin Response (0x07).
    RejoinResponse,
    /// Link Status (0x08).
    LinkStatus,
    /// Network Report (0x09).
    NetworkReport,
    /// Network Update (0x0A).
    NetworkUpdate,
    /// End Device Timeout Request (0x0B).
    EndDeviceTimeoutRequest,
    /// End Device Timeout Response (0x0C).
    EndDeviceTimeoutResponse,
    /// Link Power Delta (0x0D).
    LinkPowerDelta,
    /// Network Commissioning Request (0x0E).
    CommissioningRequest,
    /// Network Commissioning Response (0x0F).
    CommissioningResponse,
    /// Any other identifier.
    Unknown(u8),
}

impl NwkCommandId {
    /// Wire value.
    pub const fn raw(self) -> u8 {
        match self {
            NwkCommandId::RouteRequest => 0x01,
            NwkCommandId::RouteReply => 0x02,
            NwkCommandId::NetworkStatus => 0x03,
            NwkCommandId::Leave => 0x04,
            NwkCommandId::RouteRecord => 0x05,
            NwkCommandId::RejoinRequest => 0x06,
            NwkCommandId::RejoinResponse => 0x07,
            NwkCommandId::LinkStatus => 0x08,
            NwkCommandId::NetworkReport => 0x09,
            NwkCommandId::NetworkUpdate => 0x0A,
            NwkCommandId::EndDeviceTimeoutRequest => 0x0B,
            NwkCommandId::EndDeviceTimeoutResponse => 0x0C,
            NwkCommandId::LinkPowerDelta => 0x0D,
            NwkCommandId::CommissioningRequest => 0x0E,
            NwkCommandId::CommissioningResponse => 0x0F,
            NwkCommandId::Unknown(v) => v,
        }
    }

    /// Parses a wire value.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x01 => NwkCommandId::RouteRequest,
            0x02 => NwkCommandId::RouteReply,
            0x03 => NwkCommandId::NetworkStatus,
            0x04 => NwkCommandId::Leave,
            0x05 => NwkCommandId::RouteRecord,
            0x06 => NwkCommandId::RejoinRequest,
            0x07 => NwkCommandId::RejoinResponse,
            0x08 => NwkCommandId::LinkStatus,
            0x09 => NwkCommandId::NetworkReport,
            0x0A => NwkCommandId::NetworkUpdate,
            0x0B => NwkCommandId::EndDeviceTimeoutRequest,
            0x0C => NwkCommandId::EndDeviceTimeoutResponse,
            0x0D => NwkCommandId::LinkPowerDelta,
            0x0E => NwkCommandId::CommissioningRequest,
            0x0F => NwkCommandId::CommissioningResponse,
            other => NwkCommandId::Unknown(other),
        }
    }

    /// True when NWK encryption is required for this command
    /// (Table 3-54: Route Record is optional; Rejoin Request /
    /// Commissioning Request may be unsecured for TC rejoins / initial
    /// joins; everything else is required).
    pub const fn requires_security(self) -> bool {
        !matches!(
            self,
            NwkCommandId::RouteRecord
                | NwkCommandId::RejoinRequest
                | NwkCommandId::RejoinResponse
                | NwkCommandId::CommissioningRequest
                | NwkCommandId::CommissioningResponse
                | NwkCommandId::Unknown(_)
        )
    }
}

/// Many-to-one sub-field of the Route Request options (Table 3-55).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ManyToOne {
    /// Not a many-to-one request.
    No,
    /// Many-to-one; the concentrator keeps a route record table.
    WithRouteCache,
    /// Many-to-one; the concentrator has no route record table.
    NoRouteCache,
    /// Reserved value 3.
    Reserved,
}

impl ManyToOne {
    const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => ManyToOne::No,
            1 => ManyToOne::WithRouteCache,
            2 => ManyToOne::NoRouteCache,
            _ => ManyToOne::Reserved,
        }
    }

    const fn bits(self) -> u8 {
        match self {
            ManyToOne::No => 0,
            ManyToOne::WithRouteCache => 1,
            ManyToOne::NoRouteCache => 2,
            ManyToOne::Reserved => 3,
        }
    }

    /// True for either many-to-one variant.
    pub const fn is_many_to_one(self) -> bool {
        matches!(self, ManyToOne::WithRouteCache | ManyToOne::NoRouteCache)
    }
}

/// Route Request command (§3.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteRequest<'a> {
    /// Many-to-one sub-field.
    pub many_to_one: ManyToOne,
    /// Route request identifier.
    pub id: u8,
    /// Destination address (a broadcast address for many-to-one).
    pub dst: ShortAddress,
    /// Accumulated path cost.
    pub path_cost: u8,
    /// Destination IEEE address, when known.
    pub dst_ieee: Option<ExtendedAddress>,
    /// Trailing TLVs (unvalidated raw bytes; empty when none).
    pub tlvs: &'a [u8],
}

impl<'a> Decode<'a> for RouteRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let options = r.u8()?;
        let many_to_one = ManyToOne::from_bits(options >> 3);
        let id = r.u8()?;
        let dst = ShortAddress(r.u16_le()?);
        let path_cost = r.u8()?;
        let dst_ieee = if options & 0x20 != 0 {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        Ok(RouteRequest {
            many_to_one,
            id,
            dst,
            path_cost,
            dst_ieee,
            tlvs: r.take_rest(),
        })
    }
}

impl Encode for RouteRequest<'_> {
    fn encoded_len(&self) -> usize {
        5 + self.dst_ieee.map_or(0, |_| 8) + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let options = (self.many_to_one.bits() << 3) | (u8::from(self.dst_ieee.is_some()) << 5);
        w.u8(options)?;
        w.u8(self.id)?;
        w.u16_le(self.dst.0)?;
        w.u8(self.path_cost)?;
        if let Some(a) = self.dst_ieee {
            w.u64_le(a.0)?;
        }
        w.bytes(self.tlvs)
    }
}

/// Route Reply command (§3.4.2). Both IEEE addresses are always present
/// on transmit (§3.4.2.3.1) but tolerated absent on receive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteReply<'a> {
    /// Route request identifier being answered.
    pub id: u8,
    /// Originator of the route request.
    pub originator: ShortAddress,
    /// Responder (destination of the request).
    pub responder: ShortAddress,
    /// Accumulated path cost.
    pub path_cost: u8,
    /// Originator IEEE address.
    pub originator_ieee: Option<ExtendedAddress>,
    /// Responder IEEE address.
    pub responder_ieee: Option<ExtendedAddress>,
    /// Trailing TLVs.
    pub tlvs: &'a [u8],
}

impl<'a> Decode<'a> for RouteReply<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let options = r.u8()?;
        let id = r.u8()?;
        let originator = ShortAddress(r.u16_le()?);
        let responder = ShortAddress(r.u16_le()?);
        let path_cost = r.u8()?;
        let originator_ieee = if options & 0x10 != 0 {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        let responder_ieee = if options & 0x20 != 0 {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        Ok(RouteReply {
            id,
            originator,
            responder,
            path_cost,
            originator_ieee,
            responder_ieee,
            tlvs: r.take_rest(),
        })
    }
}

impl Encode for RouteReply<'_> {
    fn encoded_len(&self) -> usize {
        7 + self.originator_ieee.map_or(0, |_| 8)
            + self.responder_ieee.map_or(0, |_| 8)
            + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let options = (u8::from(self.originator_ieee.is_some()) << 4)
            | (u8::from(self.responder_ieee.is_some()) << 5);
        w.u8(options)?;
        w.u8(self.id)?;
        w.u16_le(self.originator.0)?;
        w.u16_le(self.responder.0)?;
        w.u8(self.path_cost)?;
        if let Some(a) = self.originator_ieee {
            w.u64_le(a.0)?;
        }
        if let Some(a) = self.responder_ieee {
            w.u64_le(a.0)?;
        }
        w.bytes(self.tlvs)
    }
}

/// Network Status command status codes (Table 3-56).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkStatusCode {
    /// Legacy no route available (0x00); treated as link failure.
    LegacyNoRoute,
    /// Legacy link failure (0x01); treated as link failure.
    LegacyLinkFailure,
    /// Link failure (0x02).
    LinkFailure,
    /// Parent link failure (0x09), local use only.
    ParentLinkFailure,
    /// Source route failure (0x0B).
    SourceRouteFailure,
    /// Many-to-one route failure (0x0C).
    ManyToOneRouteFailure,
    /// Address conflict (0x0D).
    AddressConflict,
    /// PAN identifier update (0x0F), local use only.
    PanIdUpdate,
    /// Network address update (0x10), local use only.
    NetworkAddressUpdate,
    /// Unknown command (0x13).
    UnknownCommand,
    /// PAN ID conflict report (0x14), local use only.
    PanIdConflictReport,
    /// Deprecated or reserved value.
    Other(u8),
}

impl NetworkStatusCode {
    /// Wire value.
    pub const fn raw(self) -> u8 {
        match self {
            NetworkStatusCode::LegacyNoRoute => 0x00,
            NetworkStatusCode::LegacyLinkFailure => 0x01,
            NetworkStatusCode::LinkFailure => 0x02,
            NetworkStatusCode::ParentLinkFailure => 0x09,
            NetworkStatusCode::SourceRouteFailure => 0x0B,
            NetworkStatusCode::ManyToOneRouteFailure => 0x0C,
            NetworkStatusCode::AddressConflict => 0x0D,
            NetworkStatusCode::PanIdUpdate => 0x0F,
            NetworkStatusCode::NetworkAddressUpdate => 0x10,
            NetworkStatusCode::UnknownCommand => 0x13,
            NetworkStatusCode::PanIdConflictReport => 0x14,
            NetworkStatusCode::Other(v) => v,
        }
    }

    /// Parses a wire value.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x00 => NetworkStatusCode::LegacyNoRoute,
            0x01 => NetworkStatusCode::LegacyLinkFailure,
            0x02 => NetworkStatusCode::LinkFailure,
            0x09 => NetworkStatusCode::ParentLinkFailure,
            0x0B => NetworkStatusCode::SourceRouteFailure,
            0x0C => NetworkStatusCode::ManyToOneRouteFailure,
            0x0D => NetworkStatusCode::AddressConflict,
            0x0F => NetworkStatusCode::PanIdUpdate,
            0x10 => NetworkStatusCode::NetworkAddressUpdate,
            0x13 => NetworkStatusCode::UnknownCommand,
            0x14 => NetworkStatusCode::PanIdConflictReport,
            other => NetworkStatusCode::Other(other),
        }
    }

    /// True for the three codes that all mean "link failure" on receipt
    /// (§3.4.3.3.1, §3.6.4.8.1).
    pub const fn is_link_failure(self) -> bool {
        matches!(
            self,
            NetworkStatusCode::LegacyNoRoute
                | NetworkStatusCode::LegacyLinkFailure
                | NetworkStatusCode::LinkFailure
        )
    }
}

/// Network Status command (§3.4.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkStatus<'a> {
    /// Status code.
    pub status: NetworkStatusCode,
    /// The address the status refers to.
    pub dst: ShortAddress,
    /// Trailing TLVs.
    pub tlvs: &'a [u8],
}

impl<'a> Decode<'a> for NetworkStatus<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(NetworkStatus {
            status: NetworkStatusCode::from_raw(r.u8()?),
            dst: ShortAddress(r.u16_le()?),
            tlvs: r.take_rest(),
        })
    }
}

impl Encode for NetworkStatus<'_> {
    fn encoded_len(&self) -> usize {
        3 + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u16_le(self.dst.0)?;
        w.bytes(self.tlvs)
    }
}

/// Leave command (§3.4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Leave {
    /// The leaving device intends to rejoin.
    pub rejoin: bool,
    /// This is a request for the recipient to leave (1) rather than an
    /// announcement that the sender is leaving (0).
    pub request: bool,
    /// Children of the leaving device must also leave.
    pub remove_children: bool,
}

impl<'a> Decode<'a> for Leave {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        Ok(Leave {
            rejoin: o & 0x20 != 0,
            request: o & 0x40 != 0,
            remove_children: o & 0x80 != 0,
        })
    }
}

impl Encode for Leave {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8((u8::from(self.rejoin) << 5)
            | (u8::from(self.request) << 6)
            | (u8::from(self.remove_children) << 7))
    }
}

/// Route Record command (§3.4.5): relay list accumulated toward the
/// concentrator (raw little-endian 16-bit addresses).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteRecord<'a> {
    relays: &'a [u8],
}

impl<'a> RouteRecord<'a> {
    /// Builds from a raw relay list (must be a multiple of 2 bytes).
    pub const fn from_raw(relays: &'a [u8]) -> Self {
        RouteRecord { relays }
    }

    /// Raw relay bytes.
    pub const fn raw(&self) -> &'a [u8] {
        self.relays
    }

    /// Number of relays.
    pub fn relay_count(&self) -> usize {
        self.relays.len() / 2
    }

    /// Iterates relays in the order they were appended (first relay after
    /// the originator first).
    pub fn relays(&self) -> impl Iterator<Item = ShortAddress> + '_ {
        self.relays
            .chunks_exact(2)
            .map(|c| ShortAddress(u16::from_le_bytes([c[0], c[1]])))
    }
}

impl<'a> Decode<'a> for RouteRecord<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let count = usize::from(r.u8()?);
        let relays = r.bytes(count * 2)?;
        Ok(RouteRecord { relays })
    }
}

impl Encode for RouteRecord<'_> {
    fn encoded_len(&self) -> usize {
        1 + self.relays.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let count = u8::try_from(self.relay_count()).map_err(|_| CodecError::Unrepresentable {
            field: "relay count",
        })?;
        w.u8(count)?;
        w.bytes(self.relays)
    }
}

/// Rejoin Request command (§3.4.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RejoinRequest {
    /// Capability information of the rejoining device.
    pub capability: MacCapability,
}

impl<'a> Decode<'a> for RejoinRequest {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(RejoinRequest {
            capability: MacCapability::from_raw(r.u8()?),
        })
    }
}

impl Encode for RejoinRequest {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.capability.raw())
    }
}

/// Rejoin Response command (§3.4.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RejoinResponse {
    /// Network address assigned (or confirmed) for the child.
    pub address: ShortAddress,
    /// Association status (`0xF0` = address conflict for commissioning
    /// responses, §3.4.15.2.1.2).
    pub status: MacStatus,
}

impl<'a> Decode<'a> for RejoinResponse {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(RejoinResponse {
            address: ShortAddress(r.u16_le()?),
            status: MacStatus::from_raw(r.u8()?),
        })
    }
}

impl Encode for RejoinResponse {
    fn encoded_len(&self) -> usize {
        3
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.address.0)?;
        w.u8(self.status.raw())
    }
}

/// One entry of a Link Status list (§3.4.8.3.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkStatusEntry {
    /// Neighbor network address.
    pub address: ShortAddress,
    /// Incoming cost (1–7) as measured by the sender.
    pub incoming_cost: u8,
    /// Outgoing cost as reported by the neighbor (0 = unknown).
    pub outgoing_cost: u8,
}

/// Link Status command (§3.4.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkStatus<'a> {
    /// First frame of the sender's link status.
    pub first_frame: bool,
    /// Last frame of the sender's link status.
    pub last_frame: bool,
    /// Raw entries (3 octets each).
    entries: &'a [u8],
}

impl<'a> LinkStatus<'a> {
    /// Maximum entries per frame (5-bit count).
    pub const MAX_ENTRIES: usize = 31;

    /// Builds from raw entry bytes (3 octets per entry).
    pub const fn from_raw(first_frame: bool, last_frame: bool, entries: &'a [u8]) -> Self {
        LinkStatus {
            first_frame,
            last_frame,
            entries,
        }
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len() / 3
    }

    /// Iterates entries.
    pub fn entries(&self) -> impl Iterator<Item = LinkStatusEntry> + '_ {
        self.entries.chunks_exact(3).map(|c| LinkStatusEntry {
            address: ShortAddress(u16::from_le_bytes([c[0], c[1]])),
            incoming_cost: c[2] & 0x7,
            outgoing_cost: (c[2] >> 4) & 0x7,
        })
    }

    /// Serialises one entry into three octets.
    pub fn encode_entry(e: &LinkStatusEntry) -> [u8; 3] {
        let a = e.address.0.to_le_bytes();
        [
            a[0],
            a[1],
            (e.incoming_cost & 0x7) | ((e.outgoing_cost & 0x7) << 4),
        ]
    }
}

impl<'a> Decode<'a> for LinkStatus<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        let count = usize::from(o & 0x1F);
        let entries = r.bytes(count * 3)?;
        Ok(LinkStatus {
            first_frame: o & 0x20 != 0,
            last_frame: o & 0x40 != 0,
            entries,
        })
    }
}

impl Encode for LinkStatus<'_> {
    fn encoded_len(&self) -> usize {
        1 + self.entries.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let count = self.entry_count();
        if count > Self::MAX_ENTRIES {
            return Err(CodecError::Unrepresentable {
                field: "link status entry count",
            });
        }
        #[allow(clippy::cast_possible_truncation)]
        let o =
            (count as u8) | (u8::from(self.first_frame) << 5) | (u8::from(self.last_frame) << 6);
        w.u8(o)?;
        w.bytes(self.entries)
    }
}

/// Network Report command (§3.4.9). Only the PAN identifier conflict
/// report (identifier 0) is defined.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkReport<'a> {
    /// Report command identifier (0 = PAN ID conflict).
    pub report_id: u8,
    /// Extended PAN ID of the reporting device's network.
    pub epid: ExtendedAddress,
    /// Raw report information; for PAN ID conflict reports a list of
    /// conflicting PAN IDs (2 octets each).
    pub info: &'a [u8],
}

impl NetworkReport<'_> {
    /// Report identifier for PAN ID conflicts.
    pub const PAN_ID_CONFLICT: u8 = 0;

    /// Iterates conflicting PAN identifiers (for `PAN_ID_CONFLICT`).
    pub fn pan_ids(&self) -> impl Iterator<Item = PanId> + '_ {
        self.info
            .chunks_exact(2)
            .map(|c| PanId(u16::from_le_bytes([c[0], c[1]])))
    }
}

impl<'a> Decode<'a> for NetworkReport<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        let count = usize::from(o & 0x1F);
        let report_id = o >> 5;
        let epid = ExtendedAddress(r.u64_le()?);
        let info = if report_id == Self::PAN_ID_CONFLICT {
            r.bytes(count * 2)?
        } else {
            r.take_rest()
        };
        Ok(NetworkReport {
            report_id,
            epid,
            info,
        })
    }
}

impl Encode for NetworkReport<'_> {
    fn encoded_len(&self) -> usize {
        9 + self.info.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let count = if self.report_id == Self::PAN_ID_CONFLICT {
            self.info.len() / 2
        } else {
            0
        };
        if count > 0x1F {
            return Err(CodecError::Unrepresentable {
                field: "report count",
            });
        }
        #[allow(clippy::cast_possible_truncation)]
        w.u8((count as u8) | (self.report_id << 5))?;
        w.u64_le(self.epid.0)?;
        w.bytes(self.info)
    }
}

/// Network Update command (§3.4.10). Only the PAN identifier update
/// (identifier 0) is defined.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkUpdate {
    /// Update command identifier (0 = PAN ID update).
    pub update_id: u8,
    /// Extended PAN ID of the network being updated.
    pub epid: ExtendedAddress,
    /// The new `nwkUpdateId`.
    pub nwk_update_id: u8,
    /// New PAN identifier (for update identifier 0).
    pub new_pan_id: PanId,
}

impl NetworkUpdate {
    /// Update identifier for PAN ID changes.
    pub const PAN_ID_UPDATE: u8 = 0;
}

impl<'a> Decode<'a> for NetworkUpdate {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        let count = o & 0x1F;
        let update_id = o >> 5;
        let epid = ExtendedAddress(r.u64_le()?);
        let nwk_update_id = r.u8()?;
        if update_id != Self::PAN_ID_UPDATE || count != 1 {
            return Err(CodecError::Unsupported {
                what: "network update information type",
            });
        }
        let new_pan_id = PanId(r.u16_le()?);
        Ok(NetworkUpdate {
            update_id,
            epid,
            nwk_update_id,
            new_pan_id,
        })
    }
}

impl Encode for NetworkUpdate {
    fn encoded_len(&self) -> usize {
        12
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(1 | (self.update_id << 5))?;
        w.u64_le(self.epid.0)?;
        w.u8(self.nwk_update_id)?;
        w.u16_le(self.new_pan_id.0)
    }
}

/// Requested timeout enumeration (Table 3-58).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimeoutIndex(pub u8);

impl TimeoutIndex {
    /// Highest valid enumeration value.
    pub const MAX: u8 = 14;
    /// Default `nwkEndDeviceTimeoutDefault` (index 8 = 256 minutes).
    pub const DEFAULT: TimeoutIndex = TimeoutIndex(8);

    /// Actual timeout in seconds, or `None` for invalid values.
    pub const fn seconds(self) -> Option<u32> {
        match self.0 {
            0 => Some(10),
            1..=14 => Some(60 * (1u32 << self.0)),
            _ => None,
        }
    }

    /// True for a defined enumeration value.
    pub const fn is_valid(self) -> bool {
        self.0 <= Self::MAX
    }
}

/// End Device Timeout Request command (§3.4.11).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EndDeviceTimeoutRequest {
    /// Requested timeout.
    pub timeout: TimeoutIndex,
    /// End device configuration bitmask (no bits defined in R23.2).
    pub configuration: u8,
}

impl<'a> Decode<'a> for EndDeviceTimeoutRequest {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(EndDeviceTimeoutRequest {
            timeout: TimeoutIndex(r.u8()?),
            configuration: r.u8()?,
        })
    }
}

impl Encode for EndDeviceTimeoutRequest {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.timeout.0)?;
        w.u8(self.configuration)
    }
}

/// End Device Timeout Response status (Table 3-61).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeoutResponseStatus {
    /// Accepted.
    Success,
    /// Timeout value out of range.
    IncorrectValue,
    /// A requested configuration feature is unsupported.
    UnsupportedFeature,
    /// Reserved.
    Other(u8),
}

impl TimeoutResponseStatus {
    /// Wire value.
    pub const fn raw(self) -> u8 {
        match self {
            TimeoutResponseStatus::Success => 0,
            TimeoutResponseStatus::IncorrectValue => 1,
            TimeoutResponseStatus::UnsupportedFeature => 2,
            TimeoutResponseStatus::Other(v) => v,
        }
    }

    /// Parses a wire value.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0 => TimeoutResponseStatus::Success,
            1 => TimeoutResponseStatus::IncorrectValue,
            2 => TimeoutResponseStatus::UnsupportedFeature,
            other => TimeoutResponseStatus::Other(other),
        }
    }
}

/// Parent information bitmask (Table 3-62), stored in
/// `nwkParentInformation`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ParentInformation(pub u8);

impl ParentInformation {
    /// Bit 0: MAC data poll keepalive supported.
    pub const MAC_DATA_POLL_KEEPALIVE: u8 = 1 << 0;
    /// Bit 1: End Device Timeout Request keepalive supported.
    pub const TIMEOUT_REQUEST_KEEPALIVE: u8 = 1 << 1;
    /// Bit 2: Power negotiation supported.
    pub const POWER_NEGOTIATION: u8 = 1 << 2;

    /// MAC data poll keepalive supported.
    pub const fn mac_data_poll_keepalive(self) -> bool {
        self.0 & Self::MAC_DATA_POLL_KEEPALIVE != 0
    }

    /// Timeout request keepalive supported.
    pub const fn timeout_request_keepalive(self) -> bool {
        self.0 & Self::TIMEOUT_REQUEST_KEEPALIVE != 0
    }

    /// Power negotiation supported.
    pub const fn power_negotiation(self) -> bool {
        self.0 & Self::POWER_NEGOTIATION != 0
    }
}

/// End Device Timeout Response command (§3.4.12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EndDeviceTimeoutResponse {
    /// Status.
    pub status: TimeoutResponseStatus,
    /// Parent information bitmask.
    pub parent_info: ParentInformation,
}

impl<'a> Decode<'a> for EndDeviceTimeoutResponse {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(EndDeviceTimeoutResponse {
            status: TimeoutResponseStatus::from_raw(r.u8()?),
            parent_info: ParentInformation(r.u8()?),
        })
    }
}

impl Encode for EndDeviceTimeoutResponse {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        w.u8(self.parent_info.0)
    }
}

/// Link Power Delta command type (Table 3-63).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LinkPowerDeltaType {
    /// Notification.
    Notification,
    /// Request.
    Request,
    /// Response.
    Response,
    /// Reserved.
    Reserved,
}

/// Link Power Delta command (§3.4.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkPowerDelta<'a> {
    /// Command type.
    pub kind: LinkPowerDeltaType,
    /// Raw power list: 3 octets per entry (address, signed delta).
    entries: &'a [u8],
}

impl<'a> LinkPowerDelta<'a> {
    /// Builds from a raw entry list.
    pub const fn from_raw(kind: LinkPowerDeltaType, entries: &'a [u8]) -> Self {
        LinkPowerDelta { kind, entries }
    }

    /// Iterates `(address, power delta dB)` pairs.
    pub fn entries(&self) -> impl Iterator<Item = (ShortAddress, i8)> + '_ {
        self.entries.chunks_exact(3).map(|c| {
            (
                ShortAddress(u16::from_le_bytes([c[0], c[1]])),
                i8::from_le_bytes([c[2]]),
            )
        })
    }
}

impl<'a> Decode<'a> for LinkPowerDelta<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let o = r.u8()?;
        let kind = match o & 0x3 {
            0 => LinkPowerDeltaType::Notification,
            1 => LinkPowerDeltaType::Request,
            2 => LinkPowerDeltaType::Response,
            _ => LinkPowerDeltaType::Reserved,
        };
        let count = usize::from(r.u8()?);
        let entries = r.bytes(count * 3)?;
        Ok(LinkPowerDelta { kind, entries })
    }
}

impl Encode for LinkPowerDelta<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.entries.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let count =
            u8::try_from(self.entries.len() / 3).map_err(|_| CodecError::Unrepresentable {
                field: "power list count",
            })?;
        w.u8(match self.kind {
            LinkPowerDeltaType::Notification => 0,
            LinkPowerDeltaType::Request => 1,
            LinkPowerDeltaType::Response => 2,
            LinkPowerDeltaType::Reserved => 3,
        })?;
        w.u8(count)?;
        w.bytes(self.entries)
    }
}

/// Network Commissioning type (Table 3-64).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommissioningType {
    /// Initial join (with key negotiation).
    InitialJoin,
    /// Rejoin.
    Rejoin,
    /// Establish trusted link (Zigbee Direct).
    EstablishTrustedLink,
    /// Reserved.
    Other(u8),
}

impl CommissioningType {
    const fn raw(self) -> u8 {
        match self {
            CommissioningType::InitialJoin => 0,
            CommissioningType::Rejoin => 1,
            CommissioningType::EstablishTrustedLink => 2,
            CommissioningType::Other(v) => v,
        }
    }

    const fn from_raw(v: u8) -> Self {
        match v {
            0 => CommissioningType::InitialJoin,
            1 => CommissioningType::Rejoin,
            2 => CommissioningType::EstablishTrustedLink,
            other => CommissioningType::Other(other),
        }
    }
}

/// Network Commissioning Request command (§3.4.14).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommissioningRequest<'a> {
    /// Commissioning type.
    pub kind: CommissioningType,
    /// Capability information.
    pub capability: MacCapability,
    /// TLVs (raw; validated by the receiver with [`TlvSet::validate`]).
    pub tlvs: &'a [u8],
}

impl<'a> CommissioningRequest<'a> {
    /// Validates the TLVs per Annex I general processing.
    pub fn tlv_set(&self) -> Result<TlvSet<'a>, panweave_codec::error::TlvError> {
        TlvSet::validate(self.tlvs, |_| false)
    }
}

impl<'a> Decode<'a> for CommissioningRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(CommissioningRequest {
            kind: CommissioningType::from_raw(r.u8()?),
            capability: MacCapability::from_raw(r.u8()?),
            tlvs: r.take_rest(),
        })
    }
}

impl Encode for CommissioningRequest<'_> {
    fn encoded_len(&self) -> usize {
        2 + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.kind.raw())?;
        w.u8(self.capability.raw())?;
        w.bytes(self.tlvs)
    }
}

/// Network Commissioning Response command (§3.4.15).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommissioningResponse<'a> {
    /// Assigned / confirmed network address.
    pub address: ShortAddress,
    /// Association status; `0xF0` indicates an address conflict.
    pub status: MacStatus,
    /// TLVs.
    pub tlvs: &'a [u8],
}

impl CommissioningResponse<'_> {
    /// The special status value for a short address conflict.
    pub const STATUS_ADDRESS_CONFLICT: u8 = 0xF0;
}

impl<'a> Decode<'a> for CommissioningResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        Ok(CommissioningResponse {
            address: ShortAddress(r.u16_le()?),
            status: MacStatus::from_raw(r.u8()?),
            tlvs: r.take_rest(),
        })
    }
}

impl Encode for CommissioningResponse<'_> {
    fn encoded_len(&self) -> usize {
        3 + self.tlvs.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.address.0)?;
        w.u8(self.status.raw())?;
        w.bytes(self.tlvs)
    }
}

/// A decoded NWK command payload (identifier plus fields).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NwkCommand<'a> {
    /// Route Request.
    RouteRequest(RouteRequest<'a>),
    /// Route Reply.
    RouteReply(RouteReply<'a>),
    /// Network Status.
    NetworkStatus(NetworkStatus<'a>),
    /// Leave.
    Leave(Leave),
    /// Route Record.
    RouteRecord(RouteRecord<'a>),
    /// Rejoin Request.
    RejoinRequest(RejoinRequest),
    /// Rejoin Response.
    RejoinResponse(RejoinResponse),
    /// Link Status.
    LinkStatus(LinkStatus<'a>),
    /// Network Report.
    NetworkReport(NetworkReport<'a>),
    /// Network Update.
    NetworkUpdate(NetworkUpdate),
    /// End Device Timeout Request.
    EndDeviceTimeoutRequest(EndDeviceTimeoutRequest),
    /// End Device Timeout Response.
    EndDeviceTimeoutResponse(EndDeviceTimeoutResponse),
    /// Link Power Delta.
    LinkPowerDelta(LinkPowerDelta<'a>),
    /// Network Commissioning Request.
    CommissioningRequest(CommissioningRequest<'a>),
    /// Network Commissioning Response.
    CommissioningResponse(CommissioningResponse<'a>),
    /// Unknown command identifier with its raw payload.
    Unknown {
        /// Identifier.
        id: u8,
        /// Payload.
        payload: &'a [u8],
    },
}

impl NwkCommand<'_> {
    /// Command identifier.
    pub const fn id(&self) -> NwkCommandId {
        match self {
            NwkCommand::RouteRequest(_) => NwkCommandId::RouteRequest,
            NwkCommand::RouteReply(_) => NwkCommandId::RouteReply,
            NwkCommand::NetworkStatus(_) => NwkCommandId::NetworkStatus,
            NwkCommand::Leave(_) => NwkCommandId::Leave,
            NwkCommand::RouteRecord(_) => NwkCommandId::RouteRecord,
            NwkCommand::RejoinRequest(_) => NwkCommandId::RejoinRequest,
            NwkCommand::RejoinResponse(_) => NwkCommandId::RejoinResponse,
            NwkCommand::LinkStatus(_) => NwkCommandId::LinkStatus,
            NwkCommand::NetworkReport(_) => NwkCommandId::NetworkReport,
            NwkCommand::NetworkUpdate(_) => NwkCommandId::NetworkUpdate,
            NwkCommand::EndDeviceTimeoutRequest(_) => NwkCommandId::EndDeviceTimeoutRequest,
            NwkCommand::EndDeviceTimeoutResponse(_) => NwkCommandId::EndDeviceTimeoutResponse,
            NwkCommand::LinkPowerDelta(_) => NwkCommandId::LinkPowerDelta,
            NwkCommand::CommissioningRequest(_) => NwkCommandId::CommissioningRequest,
            NwkCommand::CommissioningResponse(_) => NwkCommandId::CommissioningResponse,
            NwkCommand::Unknown { id, .. } => NwkCommandId::Unknown(*id),
        }
    }
}

impl<'a> Decode<'a> for NwkCommand<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let id = r.u8()?;
        Ok(match NwkCommandId::from_raw(id) {
            NwkCommandId::RouteRequest => NwkCommand::RouteRequest(RouteRequest::decode(r)?),
            NwkCommandId::RouteReply => NwkCommand::RouteReply(RouteReply::decode(r)?),
            NwkCommandId::NetworkStatus => NwkCommand::NetworkStatus(NetworkStatus::decode(r)?),
            NwkCommandId::Leave => NwkCommand::Leave(Leave::decode(r)?),
            NwkCommandId::RouteRecord => NwkCommand::RouteRecord(RouteRecord::decode(r)?),
            NwkCommandId::RejoinRequest => NwkCommand::RejoinRequest(RejoinRequest::decode(r)?),
            NwkCommandId::RejoinResponse => NwkCommand::RejoinResponse(RejoinResponse::decode(r)?),
            NwkCommandId::LinkStatus => NwkCommand::LinkStatus(LinkStatus::decode(r)?),
            NwkCommandId::NetworkReport => NwkCommand::NetworkReport(NetworkReport::decode(r)?),
            NwkCommandId::NetworkUpdate => NwkCommand::NetworkUpdate(NetworkUpdate::decode(r)?),
            NwkCommandId::EndDeviceTimeoutRequest => {
                NwkCommand::EndDeviceTimeoutRequest(EndDeviceTimeoutRequest::decode(r)?)
            }
            NwkCommandId::EndDeviceTimeoutResponse => {
                NwkCommand::EndDeviceTimeoutResponse(EndDeviceTimeoutResponse::decode(r)?)
            }
            NwkCommandId::LinkPowerDelta => NwkCommand::LinkPowerDelta(LinkPowerDelta::decode(r)?),
            NwkCommandId::CommissioningRequest => {
                NwkCommand::CommissioningRequest(CommissioningRequest::decode(r)?)
            }
            NwkCommandId::CommissioningResponse => {
                NwkCommand::CommissioningResponse(CommissioningResponse::decode(r)?)
            }
            NwkCommandId::Unknown(id) => NwkCommand::Unknown {
                id,
                payload: r.take_rest(),
            },
        })
    }
}

impl Encode for NwkCommand<'_> {
    fn encoded_len(&self) -> usize {
        1 + match self {
            NwkCommand::RouteRequest(c) => c.encoded_len(),
            NwkCommand::RouteReply(c) => c.encoded_len(),
            NwkCommand::NetworkStatus(c) => c.encoded_len(),
            NwkCommand::Leave(c) => c.encoded_len(),
            NwkCommand::RouteRecord(c) => c.encoded_len(),
            NwkCommand::RejoinRequest(c) => c.encoded_len(),
            NwkCommand::RejoinResponse(c) => c.encoded_len(),
            NwkCommand::LinkStatus(c) => c.encoded_len(),
            NwkCommand::NetworkReport(c) => c.encoded_len(),
            NwkCommand::NetworkUpdate(c) => c.encoded_len(),
            NwkCommand::EndDeviceTimeoutRequest(c) => c.encoded_len(),
            NwkCommand::EndDeviceTimeoutResponse(c) => c.encoded_len(),
            NwkCommand::LinkPowerDelta(c) => c.encoded_len(),
            NwkCommand::CommissioningRequest(c) => c.encoded_len(),
            NwkCommand::CommissioningResponse(c) => c.encoded_len(),
            NwkCommand::Unknown { payload, .. } => payload.len(),
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.id().raw())?;
        match self {
            NwkCommand::RouteRequest(c) => c.encode(w),
            NwkCommand::RouteReply(c) => c.encode(w),
            NwkCommand::NetworkStatus(c) => c.encode(w),
            NwkCommand::Leave(c) => c.encode(w),
            NwkCommand::RouteRecord(c) => c.encode(w),
            NwkCommand::RejoinRequest(c) => c.encode(w),
            NwkCommand::RejoinResponse(c) => c.encode(w),
            NwkCommand::LinkStatus(c) => c.encode(w),
            NwkCommand::NetworkReport(c) => c.encode(w),
            NwkCommand::NetworkUpdate(c) => c.encode(w),
            NwkCommand::EndDeviceTimeoutRequest(c) => c.encode(w),
            NwkCommand::EndDeviceTimeoutResponse(c) => c.encode(w),
            NwkCommand::LinkPowerDelta(c) => c.encode(w),
            NwkCommand::CommissioningRequest(c) => c.encode(w),
            NwkCommand::CommissioningResponse(c) => c.encode(w),
            NwkCommand::Unknown { payload, .. } => w.bytes(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(c: NwkCommand<'_>) {
        let mut buf = [0u8; 96];
        let n = c.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, c.encoded_len(), "{c:?}");
        let d = NwkCommand::decode_exact(&buf[..n]).unwrap();
        assert_eq!(d, c);
        for len in 0..n {
            let _ = NwkCommand::decode_exact(&buf[..len]);
        }
    }

    #[test]
    fn route_request_and_reply() {
        round_trip(NwkCommand::RouteRequest(RouteRequest {
            many_to_one: ManyToOne::No,
            id: 9,
            dst: ShortAddress(0x1234),
            path_cost: 3,
            dst_ieee: Some(ExtendedAddress(0xAABB)),
            tlvs: &[],
        }));
        round_trip(NwkCommand::RouteRequest(RouteRequest {
            many_to_one: ManyToOne::WithRouteCache,
            id: 1,
            dst: ShortAddress::BROADCAST_ROUTERS,
            path_cost: 0,
            dst_ieee: None,
            tlvs: &[64, 1, 0x34, 0x12],
        }));
        let mut buf = [0u8; 16];
        NwkCommand::RouteRequest(RouteRequest {
            many_to_one: ManyToOne::NoRouteCache,
            id: 2,
            dst: ShortAddress(0xFFFC),
            path_cost: 0,
            dst_ieee: None,
            tlvs: &[],
        })
        .encode_to_slice(&mut buf)
        .unwrap();
        assert_eq!(&buf[..6], &[0x01, 0x10, 0x02, 0xFC, 0xFF, 0x00]);
        round_trip(NwkCommand::RouteReply(RouteReply {
            id: 9,
            originator: ShortAddress(1),
            responder: ShortAddress(2),
            path_cost: 4,
            originator_ieee: Some(ExtendedAddress(1)),
            responder_ieee: Some(ExtendedAddress(2)),
            tlvs: &[],
        }));
    }

    #[test]
    fn status_leave_rejoin_record() {
        round_trip(NwkCommand::NetworkStatus(NetworkStatus {
            status: NetworkStatusCode::LinkFailure,
            dst: ShortAddress(0x0042),
            tlvs: &[],
        }));
        assert!(NetworkStatusCode::LegacyNoRoute.is_link_failure());
        assert!(!NetworkStatusCode::AddressConflict.is_link_failure());
        round_trip(NwkCommand::Leave(Leave {
            rejoin: true,
            request: true,
            remove_children: false,
        }));
        let mut buf = [0u8; 4];
        NwkCommand::Leave(Leave {
            rejoin: true,
            request: false,
            remove_children: true,
        })
        .encode_to_slice(&mut buf)
        .unwrap();
        assert_eq!(&buf[..2], &[0x04, 0xA0]);
        round_trip(NwkCommand::RejoinRequest(RejoinRequest {
            capability: MacCapability::SLEEPY_END_DEVICE,
        }));
        round_trip(NwkCommand::RejoinResponse(RejoinResponse {
            address: ShortAddress(0x7788),
            status: MacStatus::Success,
        }));
        round_trip(NwkCommand::RouteRecord(RouteRecord::from_raw(&[
            1, 0, 2, 0,
        ])));
        let rr = RouteRecord::from_raw(&[1, 0, 2, 0]);
        assert_eq!(rr.relays().count(), 2);
        assert!(NwkCommand::decode_exact(&[0x05, 3, 1, 0]).is_err());
    }

    #[test]
    fn link_status_entries() {
        let a = LinkStatus::encode_entry(&LinkStatusEntry {
            address: ShortAddress(0x0001),
            incoming_cost: 1,
            outgoing_cost: 3,
        });
        let b = LinkStatus::encode_entry(&LinkStatusEntry {
            address: ShortAddress(0x0002),
            incoming_cost: 7,
            outgoing_cost: 0,
        });
        let raw = [a[0], a[1], a[2], b[0], b[1], b[2]];
        let ls = LinkStatus::from_raw(true, true, &raw);
        round_trip(NwkCommand::LinkStatus(ls));
        let mut buf = [0u8; 16];
        let n = NwkCommand::LinkStatus(ls)
            .encode_to_slice(&mut buf)
            .unwrap();
        assert_eq!(buf[1], 0x62);
        let d = NwkCommand::decode_exact(&buf[..n]).unwrap();
        let NwkCommand::LinkStatus(d) = d else {
            panic!()
        };
        let e: [LinkStatusEntry; 2] = [d.entries().next().unwrap(), d.entries().nth(1).unwrap()];
        assert_eq!(e[0].incoming_cost, 1);
        assert_eq!(e[0].outgoing_cost, 3);
        assert_eq!(e[1].address, ShortAddress(2));
        assert_eq!(e[1].incoming_cost, 7);
    }

    #[test]
    fn report_update_and_timeouts() {
        round_trip(NwkCommand::NetworkReport(NetworkReport {
            report_id: 0,
            epid: ExtendedAddress(0x1234),
            info: &[0x01, 0x00, 0x02, 0x00],
        }));
        let nr = NetworkReport {
            report_id: 0,
            epid: ExtendedAddress(0),
            info: &[0x01, 0x00, 0x02, 0x00],
        };
        assert_eq!(nr.pan_ids().count(), 2);
        round_trip(NwkCommand::NetworkUpdate(NetworkUpdate {
            update_id: 0,
            epid: ExtendedAddress(0x1234),
            nwk_update_id: 5,
            new_pan_id: PanId(0xBEEF),
        }));
        round_trip(NwkCommand::EndDeviceTimeoutRequest(
            EndDeviceTimeoutRequest {
                timeout: TimeoutIndex(8),
                configuration: 0,
            },
        ));
        round_trip(NwkCommand::EndDeviceTimeoutResponse(
            EndDeviceTimeoutResponse {
                status: TimeoutResponseStatus::Success,
                parent_info: ParentInformation(0x03),
            },
        ));
        assert_eq!(TimeoutIndex(0).seconds(), Some(10));
        assert_eq!(TimeoutIndex(1).seconds(), Some(120));
        assert_eq!(TimeoutIndex(8).seconds(), Some(256 * 60));
        assert_eq!(TimeoutIndex(14).seconds(), Some(16384 * 60));
        assert_eq!(TimeoutIndex(15).seconds(), None);
        assert!(ParentInformation(0x3).mac_data_poll_keepalive());
    }

    #[test]
    fn power_delta_and_commissioning() {
        round_trip(NwkCommand::LinkPowerDelta(LinkPowerDelta::from_raw(
            LinkPowerDeltaType::Notification,
            &[0x01, 0x00, 0xFE],
        )));
        let lpd = LinkPowerDelta::from_raw(LinkPowerDeltaType::Request, &[0x01, 0x00, 0xFE]);
        assert_eq!(lpd.entries().next(), Some((ShortAddress(1), -2)));
        round_trip(NwkCommand::CommissioningRequest(CommissioningRequest {
            kind: CommissioningType::InitialJoin,
            capability: MacCapability::ROUTER,
            tlvs: &[72, 6, 71, 4, 0, 0, 0, 0, 0],
        }));
        let cr = CommissioningRequest {
            kind: CommissioningType::Rejoin,
            capability: MacCapability::ROUTER,
            tlvs: &[72, 6, 71, 4, 0, 0, 0, 0, 0],
        };
        assert!(cr.tlv_set().is_ok());
        round_trip(NwkCommand::CommissioningResponse(CommissioningResponse {
            address: ShortAddress(0x1111),
            status: MacStatus::from_raw(0xF0),
            tlvs: &[],
        }));
        round_trip(NwkCommand::Unknown {
            id: 0x7F,
            payload: &[1, 2, 3],
        });
        assert_eq!(NwkCommandId::from_raw(0x7F), NwkCommandId::Unknown(0x7F));
        assert!(NwkCommandId::RouteRequest.requires_security());
        assert!(!NwkCommandId::RejoinRequest.requires_security());
    }
}
