//! IEEE 802.15.4 MAC frame codec.
//!
//! Supports frame versions 0 (2003), 1 (2006) and 2 (2015, needed only for
//! enhanced beacons per R23.2 Annex D.11). MAC security (auxiliary security
//! header) is not used by Zigbee and is rejected with
//! [`CodecError::Unsupported`]; frames carrying it are dropped by the
//! caller.
//!
//! All multi-octet fields are little-endian. The FCS is handled by the PHY
//! and never appears in the slices this module sees.

use core::fmt;

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{ExtendedAddress, MacCapability, MacStatus, PanId, ShortAddress};

/// MAC frame type (frame control bits 0–2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameType {
    /// Beacon frame.
    Beacon,
    /// Data frame.
    Data,
    /// Acknowledgement frame.
    Ack,
    /// MAC command frame.
    Command,
    /// Reserved (4), multipurpose (5), fragment (6), extended (7).
    Other(u8),
}

impl FrameType {
    const fn from_bits(b: u16) -> Self {
        // Only the low three bits are passed in.
        #[allow(clippy::cast_possible_truncation)]
        match b & 0x7 {
            0 => FrameType::Beacon,
            1 => FrameType::Data,
            2 => FrameType::Ack,
            3 => FrameType::Command,
            v => FrameType::Other(v as u8),
        }
    }

    const fn bits(self) -> u16 {
        match self {
            FrameType::Beacon => 0,
            FrameType::Data => 1,
            FrameType::Ack => 2,
            FrameType::Command => 3,
            FrameType::Other(v) => (v & 0x7) as u16,
        }
    }
}

/// Frame version (frame control bits 12–13).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameVersion {
    /// IEEE 802.15.4-2003.
    V2003,
    /// IEEE 802.15.4-2006.
    V2006,
    /// IEEE 802.15.4-2015 (and later).
    V2015,
    /// Reserved value 3.
    Reserved,
}

impl FrameVersion {
    const fn from_bits(b: u16) -> Self {
        match b & 0x3 {
            0 => FrameVersion::V2003,
            1 => FrameVersion::V2006,
            2 => FrameVersion::V2015,
            _ => FrameVersion::Reserved,
        }
    }

    const fn bits(self) -> u16 {
        match self {
            FrameVersion::V2003 => 0,
            FrameVersion::V2006 => 1,
            FrameVersion::V2015 => 2,
            FrameVersion::Reserved => 3,
        }
    }
}

/// Addressing mode (frame control bits 10–11 / 14–15).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddressMode {
    /// No address present.
    None,
    /// Reserved value 1.
    Reserved,
    /// 16-bit short address.
    Short,
    /// 64-bit extended address.
    Extended,
}

impl AddressMode {
    const fn from_bits(b: u16) -> Self {
        match b & 0x3 {
            0 => AddressMode::None,
            1 => AddressMode::Reserved,
            2 => AddressMode::Short,
            _ => AddressMode::Extended,
        }
    }

    const fn bits(self) -> u16 {
        match self {
            AddressMode::None => 0,
            AddressMode::Reserved => 1,
            AddressMode::Short => 2,
            AddressMode::Extended => 3,
        }
    }
}

/// A MAC address field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacAddress {
    /// Not present.
    None,
    /// Short address.
    Short(ShortAddress),
    /// Extended address.
    Extended(ExtendedAddress),
}

impl MacAddress {
    /// The addressing mode this value encodes as.
    #[inline]
    pub const fn mode(self) -> AddressMode {
        match self {
            MacAddress::None => AddressMode::None,
            MacAddress::Short(_) => AddressMode::Short,
            MacAddress::Extended(_) => AddressMode::Extended,
        }
    }

    /// Encoded length in octets.
    #[inline]
    pub const fn encoded_len(self) -> usize {
        match self {
            MacAddress::None => 0,
            MacAddress::Short(_) => 2,
            MacAddress::Extended(_) => 8,
        }
    }

    /// True for the short broadcast address `0xFFFF`.
    #[inline]
    pub const fn is_broadcast(self) -> bool {
        matches!(self, MacAddress::Short(ShortAddress(0xFFFF)))
    }

    /// Returns the short address if present.
    #[inline]
    pub const fn short(self) -> Option<ShortAddress> {
        match self {
            MacAddress::Short(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the extended address if present.
    #[inline]
    pub const fn extended(self) -> Option<ExtendedAddress> {
        match self {
            MacAddress::Extended(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ShortAddress> for MacAddress {
    fn from(v: ShortAddress) -> Self {
        MacAddress::Short(v)
    }
}

impl From<ExtendedAddress> for MacAddress {
    fn from(v: ExtendedAddress) -> Self {
        MacAddress::Extended(v)
    }
}

/// The 16-bit frame control field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FrameControl(pub u16);

impl FrameControl {
    const SECURITY_ENABLED: u16 = 1 << 3;
    const FRAME_PENDING: u16 = 1 << 4;
    const ACK_REQUEST: u16 = 1 << 5;
    const PAN_ID_COMPRESSION: u16 = 1 << 6;
    const SEQ_SUPPRESSION: u16 = 1 << 8;
    const IE_PRESENT: u16 = 1 << 9;

    /// Builds a frame control value.
    pub const fn new(frame_type: FrameType, version: FrameVersion) -> Self {
        FrameControl(frame_type.bits() | (version.bits() << 12))
    }

    /// Frame type.
    #[inline]
    pub const fn frame_type(self) -> FrameType {
        FrameType::from_bits(self.0)
    }

    /// Frame version.
    #[inline]
    pub const fn version(self) -> FrameVersion {
        FrameVersion::from_bits(self.0 >> 12)
    }

    /// Security enabled bit (MAC security; unsupported by Zigbee).
    #[inline]
    pub const fn security_enabled(self) -> bool {
        self.0 & Self::SECURITY_ENABLED != 0
    }

    /// Frame pending bit.
    #[inline]
    pub const fn frame_pending(self) -> bool {
        self.0 & Self::FRAME_PENDING != 0
    }

    /// Acknowledgement request bit.
    #[inline]
    pub const fn ack_request(self) -> bool {
        self.0 & Self::ACK_REQUEST != 0
    }

    /// PAN ID compression bit.
    #[inline]
    pub const fn pan_id_compression(self) -> bool {
        self.0 & Self::PAN_ID_COMPRESSION != 0
    }

    /// Sequence number suppression (version 2 only).
    #[inline]
    pub const fn seq_suppression(self) -> bool {
        self.0 & Self::SEQ_SUPPRESSION != 0
    }

    /// Information elements present (version 2 only).
    #[inline]
    pub const fn ie_present(self) -> bool {
        self.0 & Self::IE_PRESENT != 0
    }

    /// Destination addressing mode.
    #[inline]
    pub const fn dst_mode(self) -> AddressMode {
        AddressMode::from_bits(self.0 >> 10)
    }

    /// Source addressing mode.
    #[inline]
    pub const fn src_mode(self) -> AddressMode {
        AddressMode::from_bits(self.0 >> 14)
    }

    /// Sets the frame pending bit.
    #[inline]
    pub const fn with_frame_pending(self, v: bool) -> Self {
        self.with_bit(Self::FRAME_PENDING, v)
    }

    /// Sets the acknowledgement request bit.
    #[inline]
    pub const fn with_ack_request(self, v: bool) -> Self {
        self.with_bit(Self::ACK_REQUEST, v)
    }

    /// Sets the PAN ID compression bit.
    #[inline]
    pub const fn with_pan_id_compression(self, v: bool) -> Self {
        self.with_bit(Self::PAN_ID_COMPRESSION, v)
    }

    /// Sets the sequence number suppression bit.
    #[inline]
    pub const fn with_seq_suppression(self, v: bool) -> Self {
        self.with_bit(Self::SEQ_SUPPRESSION, v)
    }

    /// Sets the IE present bit.
    #[inline]
    pub const fn with_ie_present(self, v: bool) -> Self {
        self.with_bit(Self::IE_PRESENT, v)
    }

    /// Sets the destination addressing mode.
    #[inline]
    pub const fn with_dst_mode(self, m: AddressMode) -> Self {
        FrameControl((self.0 & !(0x3 << 10)) | (m.bits() << 10))
    }

    /// Sets the source addressing mode.
    #[inline]
    pub const fn with_src_mode(self, m: AddressMode) -> Self {
        FrameControl((self.0 & !(0x3 << 14)) | (m.bits() << 14))
    }

    #[inline]
    const fn with_bit(self, bit: u16, v: bool) -> Self {
        if v {
            FrameControl(self.0 | bit)
        } else {
            FrameControl(self.0 & !bit)
        }
    }
}

impl fmt::Debug for FrameControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameControl")
            .field("raw", &format_args!("0x{:04x}", self.0))
            .field("type", &self.frame_type())
            .field("version", &self.version())
            .field("ack_request", &self.ack_request())
            .field("frame_pending", &self.frame_pending())
            .field("pan_id_compression", &self.pan_id_compression())
            .field("dst_mode", &self.dst_mode())
            .field("src_mode", &self.src_mode())
            .finish()
    }
}

/// A parsed MAC header (without security header; without IEs, which are
/// exposed raw).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header<'a> {
    /// Frame control.
    pub frame_control: FrameControl,
    /// Sequence number, absent only when suppressed in version 2 frames.
    pub sequence: Option<u8>,
    /// Destination PAN identifier when present.
    pub dst_pan: Option<PanId>,
    /// Destination address.
    pub dst: MacAddress,
    /// Source PAN identifier when present.
    pub src_pan: Option<PanId>,
    /// Source address.
    pub src: MacAddress,
    /// Raw header information elements (version 2 frames), empty
    /// otherwise. Includes the terminating HT1/HT2 element if present.
    pub header_ies: &'a [u8],
}

impl<'a> Header<'a> {
    /// Builds a frame-version-0 header with automatic PAN ID compression.
    ///
    /// R23.2 Annex D.6 requires transmitted unsecured MAC frames to carry
    /// frame version 0 for backwards compatibility (reception accepts any
    /// non-reserved version). When both addresses are present and the PAN
    /// IDs are equal, the source PAN is omitted and the compression bit set
    /// (intra-PAN).
    pub fn new(
        frame_type: FrameType,
        sequence: u8,
        dst_pan: PanId,
        dst: MacAddress,
        src_pan: PanId,
        src: MacAddress,
    ) -> Self {
        let mut fc = FrameControl::new(frame_type, FrameVersion::V2003)
            .with_dst_mode(dst.mode())
            .with_src_mode(src.mode());
        let both = dst.mode() != AddressMode::None && src.mode() != AddressMode::None;
        let compress = both && dst_pan == src_pan;
        fc = fc.with_pan_id_compression(compress);
        let (dst_pan, src_pan) = match (dst.mode(), src.mode()) {
            (AddressMode::None, AddressMode::None) => (None, None),
            (_, AddressMode::None) => (Some(dst_pan), None),
            (AddressMode::None, _) => (None, Some(src_pan)),
            _ if compress => (Some(dst_pan), None),
            _ => (Some(dst_pan), Some(src_pan)),
        };
        Header {
            frame_control: fc,
            sequence: Some(sequence),
            dst_pan,
            dst,
            src_pan,
            src,
            header_ies: &[],
        }
    }

    /// Builds an acknowledgement header for `sequence`.
    pub const fn ack(sequence: u8, frame_pending: bool) -> Header<'static> {
        Header {
            frame_control: FrameControl::new(FrameType::Ack, FrameVersion::V2003)
                .with_frame_pending(frame_pending),
            sequence: Some(sequence),
            dst_pan: None,
            dst: MacAddress::None,
            src_pan: None,
            src: MacAddress::None,
            header_ies: &[],
        }
    }

    /// The PAN identifier that applies to the destination (explicit or
    /// compressed from the source).
    #[inline]
    pub fn effective_dst_pan(&self) -> Option<PanId> {
        self.dst_pan.or(self.src_pan)
    }

    /// The PAN identifier that applies to the source.
    #[inline]
    pub fn effective_src_pan(&self) -> Option<PanId> {
        self.src_pan.or(self.dst_pan)
    }

    /// Whether PAN IDs are present for version 0/1 frames.
    const fn pan_presence_legacy(
        dst: AddressMode,
        src: AddressMode,
        compression: bool,
    ) -> (bool, bool) {
        match (dst, src) {
            (AddressMode::None, AddressMode::None) => (false, false),
            (_, AddressMode::None) => (true, false),
            (AddressMode::None, _) => (false, true),
            _ => (true, !compression),
        }
    }

    /// PAN ID presence for version 2 frames (IEEE 802.15.4-2015
    /// Table 7-2).
    const fn pan_presence_v2(
        dst: AddressMode,
        src: AddressMode,
        compression: bool,
    ) -> (bool, bool) {
        use AddressMode::{Extended as E, None as N, Short as S};
        match (dst, src, compression) {
            (N, N, false) => (false, false),
            (N, N, true) => (true, false),
            (S | E, N, false) => (true, false),
            (S | E, N, true) => (false, false),
            (N, S | E, false) => (false, true),
            (N, S | E, true) => (false, false),
            (E, E, false) => (true, false),
            (E, E, true) => (false, false),
            (S, S, false) | (S, E, false) | (E, S, false) => (true, true),
            (S, S, true) | (S, E, true) | (E, S, true) => (true, false),
            // Reserved addressing modes never reach here (rejected earlier).
            _ => (false, false),
        }
    }

    fn pan_presence(fc: FrameControl) -> (bool, bool) {
        match fc.version() {
            FrameVersion::V2015 => {
                Self::pan_presence_v2(fc.dst_mode(), fc.src_mode(), fc.pan_id_compression())
            }
            _ => Self::pan_presence_legacy(fc.dst_mode(), fc.src_mode(), fc.pan_id_compression()),
        }
    }

    fn decode_address(r: &mut Reader<'a>, mode: AddressMode) -> Result<MacAddress, CodecError> {
        Ok(match mode {
            AddressMode::None => MacAddress::None,
            AddressMode::Short => MacAddress::Short(ShortAddress(r.u16_le()?)),
            AddressMode::Extended => MacAddress::Extended(ExtendedAddress(r.u64_le()?)),
            AddressMode::Reserved => {
                return Err(CodecError::InvalidField {
                    field: "mac address mode",
                    value: 1,
                });
            }
        })
    }

    fn encode_address(w: &mut Writer<'_>, a: MacAddress) -> Result<(), CodecError> {
        match a {
            MacAddress::None => Ok(()),
            MacAddress::Short(s) => w.u16_le(s.0),
            MacAddress::Extended(e) => w.u64_le(e.0),
        }
    }

    /// Length of the header IE list starting at `bytes`, including the
    /// terminating HT1/HT2 element. Header IEs are `length(7) | id(8) |
    /// type(1)` followed by `length` bytes; HT1 (id 0x7E) and HT2 (0x7F)
    /// terminate the list.
    fn header_ie_list_len(bytes: &[u8]) -> Result<usize, CodecError> {
        let mut pos = 0usize;
        loop {
            let (Some(lo), Some(hi)) = (bytes.get(pos), bytes.get(pos + 1)) else {
                return Err(CodecError::Truncated {
                    needed: 2,
                    available: bytes.len().saturating_sub(pos),
                });
            };
            let word = u16::from_le_bytes([*lo, *hi]);
            let len = usize::from(word & 0x7F);
            let id = (word >> 7) & 0xFF;
            let next = pos + 2 + len;
            if next > bytes.len() {
                return Err(CodecError::Truncated {
                    needed: len,
                    available: bytes.len().saturating_sub(pos + 2),
                });
            }
            pos = next;
            if id == 0x7E || id == 0x7F {
                return Ok(pos);
            }
        }
    }

    /// Serialised header length.
    pub fn encoded_len(&self) -> usize {
        2 + usize::from(self.sequence.is_some())
            + self.dst_pan.map_or(0, |_| 2)
            + self.dst.encoded_len()
            + self.src_pan.map_or(0, |_| 2)
            + self.src.encoded_len()
            + self.header_ies.len()
    }
}

impl<'a> Decode<'a> for Header<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let fc = FrameControl(r.u16_le()?);
        if matches!(fc.dst_mode(), AddressMode::Reserved)
            || matches!(fc.src_mode(), AddressMode::Reserved)
        {
            return Err(CodecError::InvalidField {
                field: "mac address mode",
                value: 1,
            });
        }
        if matches!(fc.version(), FrameVersion::Reserved) {
            return Err(CodecError::InvalidField {
                field: "mac frame version",
                value: 3,
            });
        }
        let seq_suppressed = fc.version() == FrameVersion::V2015 && fc.seq_suppression();
        let sequence = if seq_suppressed { None } else { Some(r.u8()?) };
        let (dst_pan_present, src_pan_present) = Self::pan_presence(fc);
        let dst_pan = if dst_pan_present {
            Some(PanId(r.u16_le()?))
        } else {
            None
        };
        let dst = Self::decode_address(r, fc.dst_mode())?;
        let src_pan = if src_pan_present {
            Some(PanId(r.u16_le()?))
        } else {
            None
        };
        let src = Self::decode_address(r, fc.src_mode())?;
        if fc.security_enabled() {
            return Err(CodecError::Unsupported {
                what: "MAC security",
            });
        }
        let header_ies = if fc.version() == FrameVersion::V2015 && fc.ie_present() {
            let n = Self::header_ie_list_len(r.peek_rest())?;
            r.bytes(n)?
        } else {
            &[]
        };
        Ok(Header {
            frame_control: fc,
            sequence,
            dst_pan,
            dst,
            src_pan,
            src,
            header_ies,
        })
    }
}

impl Encode for Header<'_> {
    fn encoded_len(&self) -> usize {
        Header::encoded_len(self)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.frame_control.0)?;
        if let Some(s) = self.sequence {
            w.u8(s)?;
        }
        if let Some(p) = self.dst_pan {
            w.u16_le(p.0)?;
        }
        Self::encode_address(w, self.dst)?;
        if let Some(p) = self.src_pan {
            w.u16_le(p.0)?;
        }
        Self::encode_address(w, self.src)?;
        w.bytes(self.header_ies)
    }
}

/// A complete MAC frame: header plus raw payload (MSDU, beacon body or
/// command).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Frame<'a> {
    /// Parsed header.
    pub header: Header<'a>,
    /// Frame payload after the header (and IEs).
    pub payload: &'a [u8],
}

impl<'a> Decode<'a> for Frame<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let header = Header::decode(r)?;
        let payload = r.take_rest();
        Ok(Frame { header, payload })
    }
}

impl Encode for Frame<'_> {
    fn encoded_len(&self) -> usize {
        self.header.encoded_len() + self.payload.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        self.header.encode(w)?;
        w.bytes(self.payload)
    }
}

/// Superframe specification field of a beacon.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SuperframeSpec {
    /// Beacon order (15 for non-beacon PANs).
    pub beacon_order: u8,
    /// Superframe order (15 for non-beacon PANs).
    pub superframe_order: u8,
    /// Final CAP slot.
    pub final_cap_slot: u8,
    /// Battery life extension.
    pub battery_life_extension: bool,
    /// Set when the sender is the PAN coordinator.
    pub pan_coordinator: bool,
    /// Set when the sender accepts association requests.
    pub association_permit: bool,
}

impl SuperframeSpec {
    /// Non-beacon superframe specification as used by Zigbee routers and
    /// coordinators.
    pub const fn non_beacon(pan_coordinator: bool, association_permit: bool) -> Self {
        SuperframeSpec {
            beacon_order: 15,
            superframe_order: 15,
            final_cap_slot: 15,
            battery_life_extension: false,
            pan_coordinator,
            association_permit,
        }
    }

    /// Wire encoding.
    pub const fn to_raw(self) -> u16 {
        (self.beacon_order as u16 & 0xF)
            | ((self.superframe_order as u16 & 0xF) << 4)
            | ((self.final_cap_slot as u16 & 0xF) << 8)
            | ((self.battery_life_extension as u16) << 12)
            | ((self.pan_coordinator as u16) << 14)
            | ((self.association_permit as u16) << 15)
    }

    /// Parses the wire encoding (bit 13 is reserved and ignored).
    pub const fn from_raw(v: u16) -> Self {
        // Each extracted field is at most 4 bits wide.
        #[allow(clippy::cast_possible_truncation)]
        SuperframeSpec {
            beacon_order: (v & 0xF) as u8,
            superframe_order: ((v >> 4) & 0xF) as u8,
            final_cap_slot: ((v >> 8) & 0xF) as u8,
            battery_life_extension: (v >> 12) & 1 != 0,
            pan_coordinator: (v >> 14) & 1 != 0,
            association_permit: (v >> 15) & 1 != 0,
        }
    }
}

/// A beacon frame body (IEEE 802.15.4-2015 §7.3.1.1).
///
/// GTS and pending-address lists are parsed for length only: Zigbee never
/// uses GTS and the beacon pending-address list is empty on non-beacon
/// PANs (indirect data is signalled via the frame-pending bit instead).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Beacon<'a> {
    /// Superframe specification.
    pub superframe: SuperframeSpec,
    /// Number of pending short addresses advertised.
    pub pending_short: u8,
    /// Number of pending extended addresses advertised.
    pub pending_extended: u8,
    /// Beacon payload (the Zigbee NWK beacon payload).
    pub payload: &'a [u8],
}

impl<'a> Beacon<'a> {
    /// Builds a non-beacon-PAN beacon with a payload.
    pub const fn non_beacon(
        pan_coordinator: bool,
        association_permit: bool,
        payload: &'a [u8],
    ) -> Self {
        Beacon {
            superframe: SuperframeSpec::non_beacon(pan_coordinator, association_permit),
            pending_short: 0,
            pending_extended: 0,
            payload,
        }
    }
}

impl<'a> Decode<'a> for Beacon<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let superframe = SuperframeSpec::from_raw(r.u16_le()?);
        let gts = r.u8()?;
        let gts_count = usize::from(gts & 0x7);
        if gts_count > 0 {
            // GTS directions octet + 3 octets per descriptor.
            r.skip(1 + 3 * gts_count)?;
        }
        let pending = r.u8()?;
        let pending_short = pending & 0x7;
        let pending_extended = (pending >> 4) & 0x7;
        r.skip(2 * usize::from(pending_short) + 8 * usize::from(pending_extended))?;
        let payload = r.take_rest();
        Ok(Beacon {
            superframe,
            pending_short,
            pending_extended,
            payload,
        })
    }
}

impl Encode for Beacon<'_> {
    fn encoded_len(&self) -> usize {
        4 + self.payload.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if self.pending_short != 0 || self.pending_extended != 0 {
            return Err(CodecError::Unsupported {
                what: "beacon pending address list",
            });
        }
        w.u16_le(self.superframe.to_raw())?;
        w.u8(0)?; // GTS specification: none, permit = 0
        w.u8(0)?; // pending address specification: none
        w.bytes(self.payload)
    }
}

/// MAC command identifiers (IEEE 802.15.4-2015 Table 7-49).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacCommandId {
    /// Association request.
    AssociationRequest,
    /// Association response.
    AssociationResponse,
    /// Disassociation notification.
    DisassociationNotification,
    /// Data request.
    DataRequest,
    /// PAN ID conflict notification.
    PanIdConflictNotification,
    /// Orphan notification.
    OrphanNotification,
    /// Beacon request.
    BeaconRequest,
    /// Coordinator realignment.
    CoordinatorRealignment,
    /// GTS request.
    GtsRequest,
    /// Any other identifier (reserved or 2015 additions).
    Other(u8),
}

impl MacCommandId {
    /// Wire value.
    pub const fn raw(self) -> u8 {
        match self {
            MacCommandId::AssociationRequest => 0x01,
            MacCommandId::AssociationResponse => 0x02,
            MacCommandId::DisassociationNotification => 0x03,
            MacCommandId::DataRequest => 0x04,
            MacCommandId::PanIdConflictNotification => 0x05,
            MacCommandId::OrphanNotification => 0x06,
            MacCommandId::BeaconRequest => 0x07,
            MacCommandId::CoordinatorRealignment => 0x08,
            MacCommandId::GtsRequest => 0x09,
            MacCommandId::Other(v) => v,
        }
    }

    /// Parses a wire value.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x01 => MacCommandId::AssociationRequest,
            0x02 => MacCommandId::AssociationResponse,
            0x03 => MacCommandId::DisassociationNotification,
            0x04 => MacCommandId::DataRequest,
            0x05 => MacCommandId::PanIdConflictNotification,
            0x06 => MacCommandId::OrphanNotification,
            0x07 => MacCommandId::BeaconRequest,
            0x08 => MacCommandId::CoordinatorRealignment,
            0x09 => MacCommandId::GtsRequest,
            other => MacCommandId::Other(other),
        }
    }
}

/// Disassociation reasons.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DisassociationReason {
    /// The coordinator wishes the device to leave.
    CoordinatorWishesDeviceToLeave,
    /// The device wishes to leave.
    DeviceWishesToLeave,
    /// Reserved or unknown value.
    Other(u8),
}

impl DisassociationReason {
    const fn raw(self) -> u8 {
        match self {
            DisassociationReason::CoordinatorWishesDeviceToLeave => 1,
            DisassociationReason::DeviceWishesToLeave => 2,
            DisassociationReason::Other(v) => v,
        }
    }

    const fn from_raw(v: u8) -> Self {
        match v {
            1 => DisassociationReason::CoordinatorWishesDeviceToLeave,
            2 => DisassociationReason::DeviceWishesToLeave,
            other => DisassociationReason::Other(other),
        }
    }
}

/// A decoded MAC command payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacCommand<'a> {
    /// Association request with capability information.
    AssociationRequest {
        /// Joiner capability.
        capability: MacCapability,
    },
    /// Association response with allocated address and status.
    AssociationResponse {
        /// Allocated short address (`0xFFFE` when none allocated).
        short_address: ShortAddress,
        /// Association status.
        status: MacStatus,
    },
    /// Disassociation notification.
    DisassociationNotification {
        /// Reason.
        reason: DisassociationReason,
    },
    /// Data request (poll).
    DataRequest,
    /// PAN ID conflict notification.
    PanIdConflictNotification,
    /// Orphan notification.
    OrphanNotification,
    /// Beacon request.
    BeaconRequest,
    /// Coordinator realignment.
    CoordinatorRealignment {
        /// PAN identifier.
        pan_id: PanId,
        /// Coordinator short address.
        coordinator_short: ShortAddress,
        /// Logical channel.
        channel: u8,
        /// Short address assigned to the orphaned device.
        short_address: ShortAddress,
        /// Channel page (present in 2006+ frames only).
        channel_page: Option<u8>,
    },
    /// Any other command, carried raw.
    Other {
        /// Command identifier.
        id: u8,
        /// Payload bytes.
        payload: &'a [u8],
    },
}

impl MacCommand<'_> {
    /// Command identifier of this command.
    pub const fn id(&self) -> MacCommandId {
        match self {
            MacCommand::AssociationRequest { .. } => MacCommandId::AssociationRequest,
            MacCommand::AssociationResponse { .. } => MacCommandId::AssociationResponse,
            MacCommand::DisassociationNotification { .. } => {
                MacCommandId::DisassociationNotification
            }
            MacCommand::DataRequest => MacCommandId::DataRequest,
            MacCommand::PanIdConflictNotification => MacCommandId::PanIdConflictNotification,
            MacCommand::OrphanNotification => MacCommandId::OrphanNotification,
            MacCommand::BeaconRequest => MacCommandId::BeaconRequest,
            MacCommand::CoordinatorRealignment { .. } => MacCommandId::CoordinatorRealignment,
            MacCommand::Other { id, .. } => MacCommandId::Other(*id),
        }
    }
}

impl<'a> Decode<'a> for MacCommand<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let id = r.u8()?;
        Ok(match MacCommandId::from_raw(id) {
            MacCommandId::AssociationRequest => MacCommand::AssociationRequest {
                capability: MacCapability::from_raw(r.u8()?),
            },
            MacCommandId::AssociationResponse => MacCommand::AssociationResponse {
                short_address: ShortAddress(r.u16_le()?),
                status: MacStatus::from_raw(r.u8()?),
            },
            MacCommandId::DisassociationNotification => MacCommand::DisassociationNotification {
                reason: DisassociationReason::from_raw(r.u8()?),
            },
            MacCommandId::DataRequest => MacCommand::DataRequest,
            MacCommandId::PanIdConflictNotification => MacCommand::PanIdConflictNotification,
            MacCommandId::OrphanNotification => MacCommand::OrphanNotification,
            MacCommandId::BeaconRequest => MacCommand::BeaconRequest,
            MacCommandId::CoordinatorRealignment => {
                let pan_id = PanId(r.u16_le()?);
                let coordinator_short = ShortAddress(r.u16_le()?);
                let channel = r.u8()?;
                let short_address = ShortAddress(r.u16_le()?);
                let channel_page = if r.is_empty() { None } else { Some(r.u8()?) };
                MacCommand::CoordinatorRealignment {
                    pan_id,
                    coordinator_short,
                    channel,
                    short_address,
                    channel_page,
                }
            }
            MacCommandId::GtsRequest | MacCommandId::Other(_) => MacCommand::Other {
                id,
                payload: r.take_rest(),
            },
        })
    }
}

impl Encode for MacCommand<'_> {
    fn encoded_len(&self) -> usize {
        1 + match self {
            MacCommand::AssociationRequest { .. }
            | MacCommand::DisassociationNotification { .. } => 1,
            MacCommand::AssociationResponse { .. } => 3,
            MacCommand::DataRequest
            | MacCommand::PanIdConflictNotification
            | MacCommand::OrphanNotification
            | MacCommand::BeaconRequest => 0,
            MacCommand::CoordinatorRealignment { channel_page, .. } => {
                7 + usize::from(channel_page.is_some())
            }
            MacCommand::Other { payload, .. } => payload.len(),
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.id().raw())?;
        match self {
            MacCommand::AssociationRequest { capability } => w.u8(capability.raw()),
            MacCommand::AssociationResponse {
                short_address,
                status,
            } => {
                w.u16_le(short_address.0)?;
                w.u8(status.raw())
            }
            MacCommand::DisassociationNotification { reason } => w.u8(reason.raw()),
            MacCommand::DataRequest
            | MacCommand::PanIdConflictNotification
            | MacCommand::OrphanNotification
            | MacCommand::BeaconRequest => Ok(()),
            MacCommand::CoordinatorRealignment {
                pan_id,
                coordinator_short,
                channel,
                short_address,
                channel_page,
            } => {
                w.u16_le(pan_id.0)?;
                w.u16_le(coordinator_short.0)?;
                w.u8(*channel)?;
                w.u16_le(short_address.0)?;
                if let Some(p) = channel_page {
                    w.u8(*p)?;
                }
                Ok(())
            }
            MacCommand::Other { payload, .. } => w.bytes(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_header(h: &Header<'_>) -> Header<'static> {
        let mut buf = [0u8; 64];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, h.encoded_len());
        let decoded = Header::decode_exact(&buf[..n]).unwrap();
        // Copy out fields (header_ies is empty so 'static is fine).
        Header {
            frame_control: decoded.frame_control,
            sequence: decoded.sequence,
            dst_pan: decoded.dst_pan,
            dst: decoded.dst,
            src_pan: decoded.src_pan,
            src: decoded.src,
            header_ies: &[],
        }
    }

    #[test]
    fn intra_pan_data_header_compresses_source_pan() {
        let h = Header::new(
            FrameType::Data,
            0x42,
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0001)),
            PanId(0x1234),
            MacAddress::Short(ShortAddress(0x0000)),
        );
        assert!(h.frame_control.pan_id_compression());
        assert_eq!(h.src_pan, None);
        assert_eq!(h.encoded_len(), 2 + 1 + 2 + 2 + 2);
        let d = round_trip_header(&h);
        assert_eq!(d, h);
        assert_eq!(d.effective_src_pan(), Some(PanId(0x1234)));
        let mut buf = [0u8; 16];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            &[0x41, 0x88, 0x42, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn inter_pan_and_extended_addresses() {
        let h = Header::new(
            FrameType::Command,
            7,
            PanId(0xAAAA),
            MacAddress::Short(ShortAddress(0xFFFF)),
            PanId(0xFFFF),
            MacAddress::Extended(ExtendedAddress(0x0102_0304_0506_0708)),
        );
        assert!(!h.frame_control.pan_id_compression());
        assert_eq!(h.encoded_len(), 2 + 1 + 2 + 2 + 2 + 8);
        assert_eq!(round_trip_header(&h), h);
        // Source-only (beacon request style has dst only; test src only).
        let h2 = Header::new(
            FrameType::Data,
            1,
            PanId(1),
            MacAddress::None,
            PanId(2),
            MacAddress::Short(ShortAddress(5)),
        );
        assert_eq!(h2.dst_pan, None);
        assert_eq!(h2.src_pan, Some(PanId(2)));
        assert_eq!(round_trip_header(&h2), h2);
    }

    #[test]
    fn ack_frame_round_trip() {
        let h = Header::ack(9, true);
        let mut buf = [0u8; 8];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x12, 0x00, 0x09]);
        let d = Header::decode_exact(&buf[..n]).unwrap();
        assert_eq!(d.frame_control.frame_type(), FrameType::Ack);
        assert!(d.frame_control.frame_pending());
        assert_eq!(d.sequence, Some(9));
    }

    #[test]
    fn rejects_reserved_modes_and_security() {
        // dst mode = 1 (reserved)
        assert!(Header::decode_exact(&[0x01, 0x04, 0x00]).is_err());
        // security enabled with no addresses
        assert!(matches!(
            Header::decode_exact(&[0x09, 0x00, 0x00]),
            Err(CodecError::Unsupported { .. })
        ));
        // frame version 3
        assert!(Header::decode_exact(&[0x01, 0x30, 0x00]).is_err());
        // truncated
        assert!(Header::decode_exact(&[0x41, 0x88, 0x42, 0x34]).is_err());
    }

    #[test]
    fn v2015_header_with_ies_and_seq_suppression() {
        // Frame version 2, seq suppression, IE present, dst short, src none,
        // PAN compression = 0 → dst PAN present.
        let fc = FrameControl::new(FrameType::Data, FrameVersion::V2015)
            .with_dst_mode(AddressMode::Short)
            .with_seq_suppression(true)
            .with_ie_present(true);
        // Header IE: length 1, id 0x2A (arbitrary) then HT1 terminator (id 0x7E, len 0).
        let ie1 = 1u16 | (0x2Au16 << 7);
        let ht1 = 0x7Eu16 << 7;
        let mut bytes = [0u8; 16];
        let mut w = Writer::new(&mut bytes);
        w.u16_le(fc.0).unwrap();
        w.u16_le(0xBEEF).unwrap();
        w.u16_le(0x0001).unwrap();
        w.u16_le(ie1).unwrap();
        w.u8(0x55).unwrap();
        w.u16_le(ht1).unwrap();
        w.bytes(&[0xDE, 0xAD]).unwrap();
        let n = w.position();
        let f = Frame::decode_exact(&bytes[..n]).unwrap();
        assert_eq!(f.header.sequence, None);
        assert_eq!(f.header.dst_pan, Some(PanId(0xBEEF)));
        assert_eq!(f.header.dst, MacAddress::Short(ShortAddress(1)));
        assert_eq!(f.header.header_ies.len(), 5);
        assert_eq!(f.payload, &[0xDE, 0xAD]);
        // Truncated IE list is an error, not a panic.
        assert!(Frame::decode_exact(&bytes[..n - 4]).is_err());
    }

    #[test]
    fn beacon_round_trip() {
        let b = Beacon::non_beacon(true, true, &[1, 2, 3]);
        let mut buf = [0u8; 16];
        let n = b.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0xFF, 0xCF, 0x00, 0x00, 1, 2, 3]);
        let d = Beacon::decode_exact(&buf[..n]).unwrap();
        assert_eq!(d, b);
        assert!(d.superframe.pan_coordinator);
        assert!(d.superframe.association_permit);
        assert_eq!(d.superframe.beacon_order, 15);
        // Beacon with a pending short address list is skipped correctly.
        let with_pending = [0xFF, 0x4F, 0x00, 0x01, 0x34, 0x12, 0xAA];
        let d2 = Beacon::decode_exact(&with_pending).unwrap();
        assert_eq!(d2.pending_short, 1);
        assert_eq!(d2.payload, &[0xAA]);
        assert!(!d2.superframe.association_permit);
        assert!(Beacon::decode_exact(&[0xFF, 0x4F, 0x00, 0x01, 0x34]).is_err());
    }

    #[test]
    fn mac_commands_round_trip() {
        let cmds = [
            MacCommand::AssociationRequest {
                capability: MacCapability::ROUTER,
            },
            MacCommand::AssociationResponse {
                short_address: ShortAddress(0x1234),
                status: MacStatus::Success,
            },
            MacCommand::DisassociationNotification {
                reason: DisassociationReason::DeviceWishesToLeave,
            },
            MacCommand::DataRequest,
            MacCommand::BeaconRequest,
            MacCommand::OrphanNotification,
            MacCommand::PanIdConflictNotification,
            MacCommand::CoordinatorRealignment {
                pan_id: PanId(1),
                coordinator_short: ShortAddress(0),
                channel: 15,
                short_address: ShortAddress(0xFFFE),
                channel_page: Some(0),
            },
            MacCommand::Other {
                id: 0x20,
                payload: &[1, 2],
            },
        ];
        for c in cmds {
            let mut buf = [0u8; 32];
            let n = c.encode_to_slice(&mut buf).unwrap();
            assert_eq!(n, c.encoded_len());
            assert_eq!(MacCommand::decode_exact(&buf[..n]).unwrap(), c);
        }
        assert_eq!(
            MacCommand::decode_exact(&[0x01]).unwrap_err(),
            CodecError::Truncated {
                needed: 1,
                available: 0
            }
        );
        assert!(MacCommand::decode_exact(&[]).is_err());
    }
}
