//! NWK frame format (R23.2 §3.3).
//!
//! The NPDU header is: frame control (2), destination address (2), source
//! address (2), radius (1), sequence number (1), optional destination IEEE
//! address (8), optional source IEEE address (8), optional source route
//! subframe. A secured frame carries the auxiliary security header
//! immediately after the NWK header; it is handled by
//! [`crate::security`], not here.

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{ExtendedAddress, ShortAddress};

/// `nwkcProtocolVersion` for Zigbee PRO (R23.2 §1.2.5, Table 3-65).
pub const PROTOCOL_VERSION: u8 = 0x02;

/// Protocol version used by Green Power device frames.
pub const PROTOCOL_VERSION_GREEN_POWER: u8 = 0x03;

/// Maximum number of relays in a source route subframe
/// (`nwkMaxSourceRoute` default 0x0c).
pub const MAX_SOURCE_ROUTE_RELAYS: usize = 12;

/// NWK frame type (frame control bits 0–1, Table 3-52).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameType {
    /// Data frame.
    Data,
    /// NWK command frame.
    Command,
    /// Reserved value 2.
    Reserved,
    /// Inter-PAN (stub NWK header, Annex G).
    InterPan,
}

impl FrameType {
    const fn from_bits(b: u16) -> Self {
        match b & 0x3 {
            0 => FrameType::Data,
            1 => FrameType::Command,
            2 => FrameType::Reserved,
            _ => FrameType::InterPan,
        }
    }

    const fn bits(self) -> u16 {
        match self {
            FrameType::Data => 0,
            FrameType::Command => 1,
            FrameType::Reserved => 2,
            FrameType::InterPan => 3,
        }
    }
}

/// Discover route sub-field (Table 3-53).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DiscoverRoute {
    /// Suppress route discovery.
    Suppress,
    /// Enable route discovery.
    Enable,
    /// Reserved values 2 and 3.
    Reserved(u8),
}

impl DiscoverRoute {
    const fn from_bits(b: u16) -> Self {
        match b & 0x3 {
            0 => DiscoverRoute::Suppress,
            1 => DiscoverRoute::Enable,
            // Two-bit field.
            #[allow(clippy::cast_possible_truncation)]
            v => DiscoverRoute::Reserved(v as u8),
        }
    }

    const fn bits(self) -> u16 {
        match self {
            DiscoverRoute::Suppress => 0,
            DiscoverRoute::Enable => 1,
            DiscoverRoute::Reserved(v) => (v & 0x3) as u16,
        }
    }
}

/// The 16-bit NWK frame control field (§3.3.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FrameControl(pub u16);

impl FrameControl {
    const MULTICAST: u16 = 1 << 8;
    const SECURITY: u16 = 1 << 9;
    const SOURCE_ROUTE: u16 = 1 << 10;
    const DST_IEEE: u16 = 1 << 11;
    const SRC_IEEE: u16 = 1 << 12;
    const END_DEVICE_INITIATOR: u16 = 1 << 13;
    const RESERVED: u16 = 0xC000;

    /// Builds a frame control for `frame_type` with protocol version 2 and
    /// all flags clear.
    pub const fn new(frame_type: FrameType) -> Self {
        FrameControl(frame_type.bits() | ((PROTOCOL_VERSION as u16) << 2))
    }

    /// Frame type.
    #[inline]
    pub const fn frame_type(self) -> FrameType {
        FrameType::from_bits(self.0)
    }

    /// Protocol version (4 bits).
    #[inline]
    pub const fn protocol_version(self) -> u8 {
        // Four-bit field.
        #[allow(clippy::cast_possible_truncation)]
        {
            ((self.0 >> 2) & 0xF) as u8
        }
    }

    /// Discover route sub-field.
    #[inline]
    pub const fn discover_route(self) -> DiscoverRoute {
        DiscoverRoute::from_bits(self.0 >> 6)
    }

    /// Deprecated multicast flag (§3.3.1.1, R23 deprecates NWK multicast).
    #[inline]
    pub const fn multicast(self) -> bool {
        self.0 & Self::MULTICAST != 0
    }

    /// Security sub-field.
    #[inline]
    pub const fn security(self) -> bool {
        self.0 & Self::SECURITY != 0
    }

    /// Source route subframe present.
    #[inline]
    pub const fn source_route(self) -> bool {
        self.0 & Self::SOURCE_ROUTE != 0
    }

    /// Destination IEEE address present.
    #[inline]
    pub const fn dst_ieee(self) -> bool {
        self.0 & Self::DST_IEEE != 0
    }

    /// Source IEEE address present.
    #[inline]
    pub const fn src_ieee(self) -> bool {
        self.0 & Self::SRC_IEEE != 0
    }

    /// End device initiator flag.
    #[inline]
    pub const fn end_device_initiator(self) -> bool {
        self.0 & Self::END_DEVICE_INITIATOR != 0
    }

    /// True when reserved bits 14–15 are zero.
    #[inline]
    pub const fn reserved_clear(self) -> bool {
        self.0 & Self::RESERVED == 0
    }

    /// Sets the discover route sub-field.
    #[inline]
    pub const fn with_discover_route(self, d: DiscoverRoute) -> Self {
        FrameControl((self.0 & !(0x3 << 6)) | (d.bits() << 6))
    }

    /// Sets the security bit.
    #[inline]
    pub const fn with_security(self, v: bool) -> Self {
        self.with_bit(Self::SECURITY, v)
    }

    /// Sets the end device initiator bit.
    #[inline]
    pub const fn with_end_device_initiator(self, v: bool) -> Self {
        self.with_bit(Self::END_DEVICE_INITIATOR, v)
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

impl core::fmt::Debug for FrameControl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameControl")
            .field("raw", &format_args!("0x{:04x}", self.0))
            .field("type", &self.frame_type())
            .field("version", &self.protocol_version())
            .field("discover_route", &self.discover_route())
            .field("security", &self.security())
            .field("source_route", &self.source_route())
            .field("dst_ieee", &self.dst_ieee())
            .field("src_ieee", &self.src_ieee())
            .field("end_device_initiator", &self.end_device_initiator())
            .finish()
    }
}

/// Source route subframe (§3.3.1.8): relay list ordered nearest the
/// destination first, plus the index of the next relay.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SourceRoute<'a> {
    /// Index of the next relay in `relays` (initialised to `count - 1` and
    /// decremented per hop).
    pub relay_index: u8,
    /// Raw relay list bytes (2 octets per relay, little-endian).
    relays: &'a [u8],
}

impl<'a> SourceRoute<'a> {
    /// Number of relays.
    #[inline]
    pub fn relay_count(&self) -> usize {
        self.relays.len() / 2
    }

    /// Relay address at `index`.
    pub fn relay(&self, index: usize) -> Option<ShortAddress> {
        let off = index.checked_mul(2)?;
        let lo = *self.relays.get(off)?;
        let hi = *self.relays.get(off + 1)?;
        Some(ShortAddress(u16::from_le_bytes([lo, hi])))
    }

    /// Iterates relays nearest-destination first.
    pub fn relays(&self) -> impl Iterator<Item = ShortAddress> + '_ {
        (0..self.relay_count()).filter_map(|i| self.relay(i))
    }

    /// The relay the frame must be forwarded to next.
    pub fn next_relay(&self) -> Option<ShortAddress> {
        self.relay(usize::from(self.relay_index))
    }

    /// Encoded length including count and index octets.
    #[inline]
    pub fn encoded_len(&self) -> usize {
        2 + self.relays.len()
    }
}

/// The parsed NWK header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header<'a> {
    /// Frame control.
    pub frame_control: FrameControl,
    /// Destination network address.
    pub dst: ShortAddress,
    /// Source network address.
    pub src: ShortAddress,
    /// Radius.
    pub radius: u8,
    /// Sequence number.
    pub sequence: u8,
    /// Destination IEEE address, when present.
    pub dst_ieee: Option<ExtendedAddress>,
    /// Source IEEE address, when present.
    pub src_ieee: Option<ExtendedAddress>,
    /// Source route subframe, when present.
    pub source_route: Option<SourceRoute<'a>>,
}

impl<'a> Header<'a> {
    /// Builds a header with no optional fields.
    pub const fn new(
        frame_type: FrameType,
        dst: ShortAddress,
        src: ShortAddress,
        radius: u8,
        sequence: u8,
    ) -> Self {
        Header {
            frame_control: FrameControl::new(frame_type),
            dst,
            src,
            radius,
            sequence,
            dst_ieee: None,
            src_ieee: None,
            source_route: None,
        }
    }

    /// Adds the source IEEE address.
    pub const fn with_src_ieee(mut self, addr: ExtendedAddress) -> Self {
        self.src_ieee = Some(addr);
        self.frame_control = self.frame_control.with_bit(FrameControl::SRC_IEEE, true);
        self
    }

    /// Adds the destination IEEE address.
    pub const fn with_dst_ieee(mut self, addr: ExtendedAddress) -> Self {
        self.dst_ieee = Some(addr);
        self.frame_control = self.frame_control.with_bit(FrameControl::DST_IEEE, true);
        self
    }

    /// Adds a source route subframe. `relays` is the raw little-endian
    /// relay list nearest-destination first; `relay_index` is usually
    /// `count - 1`.
    pub const fn with_source_route(mut self, relay_index: u8, relays: &'a [u8]) -> Self {
        self.source_route = Some(SourceRoute {
            relay_index,
            relays,
        });
        self.frame_control = self
            .frame_control
            .with_bit(FrameControl::SOURCE_ROUTE, true);
        self
    }

    /// Sets the security bit (the auxiliary header is written by the
    /// security module).
    pub const fn secured(mut self, v: bool) -> Self {
        self.frame_control = self.frame_control.with_security(v);
        self
    }

    /// Sets the discover route sub-field.
    pub const fn with_discover_route(mut self, d: DiscoverRoute) -> Self {
        self.frame_control = self.frame_control.with_discover_route(d);
        self
    }

    /// Sets the end device initiator bit.
    pub const fn with_end_device_initiator(mut self, v: bool) -> Self {
        self.frame_control = self.frame_control.with_end_device_initiator(v);
        self
    }

    /// True for broadcast destinations.
    #[inline]
    pub const fn is_broadcast(&self) -> bool {
        self.dst.is_broadcast()
    }

    /// Decodes a header from the start of `bytes`, returning it with the
    /// number of bytes it occupies.
    pub fn decode_prefix(bytes: &'a [u8]) -> Result<(Self, usize), CodecError> {
        let mut r = Reader::new(bytes);
        let h = Header::decode(&mut r)?;
        Ok((h, r.position()))
    }

    /// Serialised header length.
    pub fn encoded_len(&self) -> usize {
        8 + self.dst_ieee.map_or(0, |_| 8)
            + self.src_ieee.map_or(0, |_| 8)
            + self.source_route.map_or(0, |s| s.encoded_len())
    }
}

impl<'a> Decode<'a> for Header<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let frame_control = FrameControl(r.u16_le()?);
        let dst = ShortAddress(r.u16_le()?);
        let src = ShortAddress(r.u16_le()?);
        let radius = r.u8()?;
        let sequence = r.u8()?;
        let dst_ieee = if frame_control.dst_ieee() {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        let src_ieee = if frame_control.src_ieee() {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        let source_route = if frame_control.source_route() {
            let count = usize::from(r.u8()?);
            let relay_index = r.u8()?;
            if usize::from(relay_index) >= count && count != 0 {
                return Err(CodecError::InvalidField {
                    field: "relay index",
                    value: u32::from(relay_index),
                });
            }
            let relays = r.bytes(count * 2)?;
            Some(SourceRoute {
                relay_index,
                relays,
            })
        } else {
            None
        };
        Ok(Header {
            frame_control,
            dst,
            src,
            radius,
            sequence,
            dst_ieee,
            src_ieee,
            source_route,
        })
    }
}

impl Encode for Header<'_> {
    fn encoded_len(&self) -> usize {
        Header::encoded_len(self)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        if self.frame_control.dst_ieee() != self.dst_ieee.is_some()
            || self.frame_control.src_ieee() != self.src_ieee.is_some()
            || self.frame_control.source_route() != self.source_route.is_some()
        {
            return Err(CodecError::InvalidField {
                field: "nwk frame control presence flags",
                value: u32::from(self.frame_control.0),
            });
        }
        w.u16_le(self.frame_control.0)?;
        w.u16_le(self.dst.0)?;
        w.u16_le(self.src.0)?;
        w.u8(self.radius)?;
        w.u8(self.sequence)?;
        if let Some(a) = self.dst_ieee {
            w.u64_le(a.0)?;
        }
        if let Some(a) = self.src_ieee {
            w.u64_le(a.0)?;
        }
        if let Some(sr) = &self.source_route {
            let count =
                u8::try_from(sr.relay_count()).map_err(|_| CodecError::Unrepresentable {
                    field: "relay count",
                })?;
            w.u8(count)?;
            w.u8(sr.relay_index)?;
            w.bytes(sr.relays)?;
        }
        Ok(())
    }
}

/// A NWK frame: header plus the (possibly still secured) payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Frame<'a> {
    /// Parsed header.
    pub header: Header<'a>,
    /// Bytes after the header: for secured frames the auxiliary header,
    /// secured payload and MIC; otherwise the NWK payload.
    pub payload: &'a [u8],
}

impl<'a> Decode<'a> for Frame<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let header = Header::decode(r)?;
        Ok(Frame {
            header,
            payload: r.take_rest(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_header_round_trip() {
        let h = Header::new(
            FrameType::Data,
            ShortAddress(0x1234),
            ShortAddress(0x0000),
            30,
            7,
        )
        .with_discover_route(DiscoverRoute::Enable)
        .secured(true);
        assert_eq!(h.encoded_len(), 8);
        let mut buf = [0u8; 16];
        let n = h.encode_to_slice(&mut buf).unwrap();
        // fc: type 0, version 2 (bits 2-5 → 0x08), discover route 1 (bit 6 →
        // 0x40), security (bit 9 → 0x0200) = 0x0248.
        assert_eq!(&buf[..n], &[0x48, 0x02, 0x34, 0x12, 0x00, 0x00, 30, 7]);
        let d = Header::decode_exact(&buf[..n]).unwrap();
        assert_eq!(d, h);
        assert_eq!(d.frame_control.protocol_version(), 2);
        assert!(d.frame_control.reserved_clear());
    }

    #[test]
    fn command_header_with_ieee_addresses() {
        let h = Header::new(
            FrameType::Command,
            ShortAddress::BROADCAST_ROUTERS,
            ShortAddress(0x0001),
            1,
            200,
        )
        .with_src_ieee(ExtendedAddress(0x1122_3344_5566_7788))
        .with_dst_ieee(ExtendedAddress(0x0102_0304_0506_0708));
        assert_eq!(h.encoded_len(), 24);
        let mut buf = [0u8; 32];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(buf[0], 0x09);
        assert_eq!(buf[1], 0x18);
        let d = Header::decode_exact(&buf[..n]).unwrap();
        assert_eq!(d, h);
        assert_eq!(d.frame_control.frame_type(), FrameType::Command);
        assert!(d.is_broadcast());
    }

    #[test]
    fn source_route_subframe() {
        let relays = [0x03, 0x00, 0x02, 0x00, 0x01, 0x00];
        let h = Header::new(FrameType::Data, ShortAddress(4), ShortAddress(0), 30, 1)
            .with_source_route(2, &relays);
        let mut buf = [0u8; 32];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, 8 + 2 + 6);
        let d = Header::decode_exact(&buf[..n]).unwrap();
        let sr = d.source_route.unwrap();
        assert_eq!(sr.relay_count(), 3);
        assert_eq!(sr.relay_index, 2);
        assert_eq!(sr.next_relay(), Some(ShortAddress(1)));
        assert_eq!(sr.relay(0), Some(ShortAddress(3)));
        assert_eq!(sr.relays().count(), 3);
        // Relay index out of range is rejected.
        let mut bad = buf;
        bad[9] = 3;
        assert!(Header::decode_exact(&bad[..n]).is_err());
        // Truncated relay list is rejected.
        assert!(Header::decode_exact(&buf[..n - 1]).is_err());
    }

    #[test]
    fn presence_flag_mismatch_is_rejected_on_encode() {
        let mut h = Header::new(FrameType::Data, ShortAddress(1), ShortAddress(2), 1, 1);
        h.frame_control = FrameControl(h.frame_control.0 | 0x1000);
        let mut buf = [0u8; 16];
        assert!(h.encode_to_slice(&mut buf).is_err());
    }

    #[test]
    fn frame_payload_is_borrowed() {
        let bytes = [0x08, 0x02, 0x01, 0x00, 0x02, 0x00, 5, 6, 0xAA, 0xBB];
        let f = Frame::decode_exact(&bytes).unwrap();
        assert_eq!(f.header.dst, ShortAddress(1));
        assert_eq!(f.payload, &[0xAA, 0xBB]);
        for len in 0..bytes.len() {
            let _ = Frame::decode_exact(&bytes[..len]);
        }
    }
}
