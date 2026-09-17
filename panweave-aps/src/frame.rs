//! APS frame format (R23.2 §2.2.5).
//!
//! The general APDU is: frame control (1), destination endpoint (0/1),
//! group address (0/2), cluster identifier (0/2), profile identifier
//! (0/2), source endpoint (0/1), APS counter (1), extended header (0/1/2)
//! followed by the payload. A secured frame carries the auxiliary
//! security header (§4.4.10) between the header and the payload; it is
//! handled by [`crate::security`].

use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::{ClusterId, Endpoint, GroupAddress, ProfileId};

/// APS frame type (frame control bits 0–1, Table 2-20).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameType {
    /// Data frame.
    Data,
    /// APS command frame.
    Command,
    /// Acknowledgement frame.
    Ack,
    /// Inter-PAN APS frame (Annex G).
    InterPan,
}

impl FrameType {
    const fn from_bits(b: u8) -> Self {
        match b & 0x3 {
            0 => FrameType::Data,
            1 => FrameType::Command,
            2 => FrameType::Ack,
            _ => FrameType::InterPan,
        }
    }

    const fn bits(self) -> u8 {
        match self {
            FrameType::Data => 0,
            FrameType::Command => 1,
            FrameType::Ack => 2,
            FrameType::InterPan => 3,
        }
    }
}

/// Delivery mode (frame control bits 2–3, Table 2-21).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DeliveryMode {
    /// Normal unicast delivery.
    Unicast,
    /// Reserved value 1.
    Reserved,
    /// Broadcast.
    Broadcast,
    /// Group addressing.
    Group,
}

impl DeliveryMode {
    const fn from_bits(b: u8) -> Self {
        match b & 0x3 {
            0 => DeliveryMode::Unicast,
            1 => DeliveryMode::Reserved,
            2 => DeliveryMode::Broadcast,
            _ => DeliveryMode::Group,
        }
    }

    const fn bits(self) -> u8 {
        match self {
            DeliveryMode::Unicast => 0,
            DeliveryMode::Reserved => 1,
            DeliveryMode::Broadcast => 2,
            DeliveryMode::Group => 3,
        }
    }
}

/// The frame control octet (§2.2.5.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FrameControl {
    /// Frame type.
    pub frame_type: FrameType,
    /// Delivery mode.
    pub delivery_mode: DeliveryMode,
    /// ACK format: 1 for an acknowledgement of an APS command frame
    /// (no addressing fields), 0 for a data-frame acknowledgement
    /// (§2.2.5.1.1.3).
    pub ack_format: bool,
    /// Security sub-field: the auxiliary header follows the APS header.
    pub security: bool,
    /// Acknowledgement request.
    pub ack_request: bool,
    /// Extended header present.
    pub extended_header: bool,
}

impl FrameControl {
    /// Parses the octet.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        FrameControl {
            frame_type: FrameType::from_bits(v),
            delivery_mode: DeliveryMode::from_bits(v >> 2),
            ack_format: v & 0x10 != 0,
            security: v & 0x20 != 0,
            ack_request: v & 0x40 != 0,
            extended_header: v & 0x80 != 0,
        }
    }

    /// Encodes the octet.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.frame_type.bits()
            | (self.delivery_mode.bits() << 2)
            | ((self.ack_format as u8) << 4)
            | ((self.security as u8) << 5)
            | ((self.ack_request as u8) << 6)
            | ((self.extended_header as u8) << 7)
    }
}

/// Fragmentation sub-field of the extended frame control (Table 2-22).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Fragmentation {
    /// Not fragmented.
    None,
    /// First fragment; the block number is the total block count.
    First,
    /// Subsequent fragment; the block number is the block index (1 for
    /// the second block).
    Part,
}

/// The extended header sub-frame (§2.2.5.1.8).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExtendedHeader {
    /// Fragmentation state.
    pub fragmentation: Fragmentation,
    /// Block number (block count in the first fragment, block index
    /// otherwise; lowest block of the window in an acknowledgement).
    /// Absent when not fragmented.
    pub block_number: u8,
    /// ACK bitfield, present only in acknowledgements of fragmented
    /// transmissions.
    pub ack_bitfield: Option<u8>,
}

impl ExtendedHeader {
    /// Extended header signalling "not fragmented".
    pub const NOT_FRAGMENTED: ExtendedHeader = ExtendedHeader {
        fragmentation: Fragmentation::None,
        block_number: 0,
        ack_bitfield: None,
    };

    /// Encoded length.
    #[inline]
    pub const fn encoded_len(&self) -> usize {
        match self.fragmentation {
            Fragmentation::None => 1,
            _ => 1 + 1 + if self.ack_bitfield.is_some() { 1 } else { 0 },
        }
    }

    fn decode(r: &mut Reader<'_>, is_ack: bool) -> Result<Self, CodecError> {
        let ctrl = r.u8()?;
        let fragmentation = match ctrl & 0x3 {
            0 => Fragmentation::None,
            1 => Fragmentation::First,
            2 => Fragmentation::Part,
            v => {
                return Err(CodecError::InvalidField {
                    field: "fragmentation",
                    value: u32::from(v),
                });
            }
        };
        if fragmentation == Fragmentation::None {
            return Ok(ExtendedHeader::NOT_FRAGMENTED);
        }
        let block_number = r.u8()?;
        let ack_bitfield = if is_ack { Some(r.u8()?) } else { None };
        Ok(ExtendedHeader {
            fragmentation,
            block_number,
            ack_bitfield,
        })
    }

    fn encode(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let bits = match self.fragmentation {
            Fragmentation::None => 0,
            Fragmentation::First => 1,
            Fragmentation::Part => 2,
        };
        w.u8(bits)?;
        if self.fragmentation != Fragmentation::None {
            w.u8(self.block_number)?;
            if let Some(b) = self.ack_bitfield {
                w.u8(b)?;
            }
        }
        Ok(())
    }
}

/// Destination addressing carried in the APS header.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Addressing {
    /// Unicast or broadcast delivery to an endpoint (0xff = all active
    /// endpoints for broadcasts).
    Endpoint(Endpoint),
    /// Group delivery.
    Group(GroupAddress),
}

/// The APS header (§2.2.5.1) for data and acknowledgement frames.
///
/// Command frames carry only the frame control and counter; see
/// [`Header::command`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    /// Frame control.
    pub control: FrameControl,
    /// Destination endpoint or group (data frames and data-frame
    /// acknowledgements).
    pub destination: Option<Addressing>,
    /// Cluster identifier (data frames and data-frame acknowledgements).
    pub cluster: Option<ClusterId>,
    /// Profile identifier (data frames and data-frame acknowledgements).
    pub profile: Option<ProfileId>,
    /// Source endpoint (data frames and data-frame acknowledgements).
    pub src_endpoint: Option<Endpoint>,
    /// APS counter.
    pub counter: u8,
    /// Extended header, present iff `control.extended_header`.
    pub extended: Option<ExtendedHeader>,
}

impl Header {
    /// Builds a data frame header for unicast, broadcast or group
    /// delivery.
    pub const fn data(
        destination: Addressing,
        cluster: ClusterId,
        profile: ProfileId,
        src_endpoint: Endpoint,
        counter: u8,
    ) -> Self {
        let delivery_mode = match destination {
            Addressing::Endpoint(_) => DeliveryMode::Unicast,
            Addressing::Group(_) => DeliveryMode::Group,
        };
        Header {
            control: FrameControl {
                frame_type: FrameType::Data,
                delivery_mode,
                ack_format: false,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            destination: Some(destination),
            cluster: Some(cluster),
            profile: Some(profile),
            src_endpoint: Some(src_endpoint),
            counter,
            extended: None,
        }
    }

    /// Builds an APS command frame header (§4.4.11): unicast or
    /// broadcast delivery, ACK format 0.
    pub const fn command(counter: u8, broadcast: bool) -> Self {
        Header {
            control: FrameControl {
                frame_type: FrameType::Command,
                delivery_mode: if broadcast {
                    DeliveryMode::Broadcast
                } else {
                    DeliveryMode::Unicast
                },
                ack_format: false,
                security: false,
                ack_request: false,
                extended_header: false,
            },
            destination: None,
            cluster: None,
            profile: None,
            src_endpoint: None,
            counter,
            extended: None,
        }
    }

    /// Builds the acknowledgement for the frame with header `of`
    /// (§2.2.5.2.3.1): endpoints swapped, same cluster/profile/counter;
    /// command acknowledgements carry the ACK format bit and no
    /// addressing fields. `extended` is the acknowledgement's extended
    /// header (the caller sets the block number and bitfield for
    /// fragmented transmissions).
    pub fn ack_for(of: &Header, extended: Option<ExtendedHeader>) -> Self {
        let is_command = of.control.frame_type == FrameType::Command;
        let dst = match (of.src_endpoint, is_command) {
            (Some(ep), false) => Some(Addressing::Endpoint(ep)),
            _ => None,
        };
        let src = match (of.destination, is_command) {
            (Some(Addressing::Endpoint(ep)), false) => Some(ep),
            // Group-addressed frames are never acknowledged; keep the
            // header well-formed anyway.
            (Some(Addressing::Group(_)), false) => Some(Endpoint(0)),
            _ => None,
        };
        Header {
            control: FrameControl {
                frame_type: FrameType::Ack,
                delivery_mode: DeliveryMode::Unicast,
                ack_format: is_command,
                security: false,
                ack_request: false,
                extended_header: extended.is_some(),
            },
            destination: dst,
            cluster: if is_command { None } else { of.cluster },
            profile: if is_command { None } else { of.profile },
            src_endpoint: src,
            counter: of.counter,
            extended,
        }
    }

    /// Sets the delivery mode to broadcast (destination endpoint form).
    pub const fn broadcast(mut self) -> Self {
        self.control.delivery_mode = DeliveryMode::Broadcast;
        self
    }

    /// Sets the acknowledgement request bit.
    pub const fn with_ack_request(mut self, ack: bool) -> Self {
        self.control.ack_request = ack;
        self
    }

    /// Sets the security bit.
    pub const fn secured(mut self, secured: bool) -> Self {
        self.control.security = secured;
        self
    }

    /// Attaches an extended header.
    pub const fn with_extended(mut self, ext: ExtendedHeader) -> Self {
        self.control.extended_header = true;
        self.extended = Some(ext);
        self
    }

    /// True for APS command frames.
    #[inline]
    pub const fn is_command(&self) -> bool {
        matches!(self.control.frame_type, FrameType::Command)
    }

    /// The destination endpoint, if endpoint-addressed.
    #[inline]
    pub const fn dst_endpoint(&self) -> Option<Endpoint> {
        match self.destination {
            Some(Addressing::Endpoint(ep)) => Some(ep),
            _ => None,
        }
    }

    /// The group address, if group-addressed.
    #[inline]
    pub const fn group(&self) -> Option<GroupAddress> {
        match self.destination {
            Some(Addressing::Group(g)) => Some(g),
            _ => None,
        }
    }

    /// Fragmentation state of the frame.
    #[inline]
    pub fn fragmentation(&self) -> Fragmentation {
        self.extended
            .map_or(Fragmentation::None, |e| e.fragmentation)
    }

    fn has_addressing(control: FrameControl) -> bool {
        match control.frame_type {
            FrameType::Data | FrameType::InterPan => true,
            FrameType::Ack => !control.ack_format,
            FrameType::Command => false,
        }
    }

    /// Decodes the header at the start of `bytes`, returning it and its
    /// encoded length. The remaining bytes are the auxiliary header (if
    /// secured) and payload.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Header, usize), CodecError> {
        let mut r = Reader::new(bytes);
        let h = Header::decode(&mut r)?;
        Ok((h, r.position()))
    }
}

impl<'a> Decode<'a> for Header {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let control = FrameControl::from_raw(r.u8()?);
        if control.delivery_mode == DeliveryMode::Reserved {
            return Err(CodecError::InvalidField {
                field: "delivery mode",
                value: 1,
            });
        }
        let (destination, cluster, profile, src_endpoint) = if Header::has_addressing(control) {
            let destination = match control.delivery_mode {
                DeliveryMode::Group => Addressing::Group(GroupAddress(r.u16_le()?)),
                _ => Addressing::Endpoint(Endpoint(r.u8()?)),
            };
            let cluster = ClusterId(r.u16_le()?);
            let profile = ProfileId(r.u16_le()?);
            let src = Endpoint(r.u8()?);
            (Some(destination), Some(cluster), Some(profile), Some(src))
        } else {
            (None, None, None, None)
        };
        let counter = r.u8()?;
        let extended = if control.extended_header {
            Some(ExtendedHeader::decode(
                r,
                control.frame_type == FrameType::Ack,
            )?)
        } else {
            None
        };
        Ok(Header {
            control,
            destination,
            cluster,
            profile,
            src_endpoint,
            counter,
            extended,
        })
    }
}

impl Encode for Header {
    fn encoded_len(&self) -> usize {
        let mut n = 1;
        if Header::has_addressing(self.control) {
            n += match self.destination {
                Some(Addressing::Group(_)) => 2,
                _ => 1,
            };
            n += 2 + 2 + 1;
        }
        n += 1;
        if let Some(e) = &self.extended {
            n += e.encoded_len();
        }
        n
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let mut control = self.control;
        control.extended_header = self.extended.is_some();
        w.u8(control.raw())?;
        if Header::has_addressing(control) {
            match self.destination {
                Some(Addressing::Group(g)) => w.u16_le(g.0)?,
                Some(Addressing::Endpoint(ep)) => w.u8(ep.0)?,
                None => {
                    return Err(CodecError::Unrepresentable {
                        field: "destination",
                    });
                }
            }
            w.u16_le(
                self.cluster
                    .ok_or(CodecError::Unrepresentable { field: "cluster" })?
                    .0,
            )?;
            w.u16_le(
                self.profile
                    .ok_or(CodecError::Unrepresentable { field: "profile" })?
                    .0,
            )?;
            w.u8(self
                .src_endpoint
                .ok_or(CodecError::Unrepresentable {
                    field: "source endpoint",
                })?
                .0)?;
        }
        w.u8(self.counter)?;
        if let Some(e) = &self.extended {
            e.encode(w)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_control_round_trip() {
        for v in 0..=255u8 {
            let fc = FrameControl::from_raw(v);
            assert_eq!(fc.raw(), v);
        }
    }

    #[test]
    fn data_header_round_trip() {
        let h = Header::data(
            Addressing::Endpoint(Endpoint(1)),
            ClusterId(0x0006),
            ProfileId::HOME_AUTOMATION,
            Endpoint(2),
            0x5A,
        )
        .with_ack_request(true);
        let mut buf = [0u8; 16];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&buf[..n], &[0x40, 1, 0x06, 0x00, 0x04, 0x01, 2, 0x5A]);
        let (d, len) = Header::decode_prefix(&buf[..n]).unwrap();
        assert_eq!(len, n);
        assert_eq!(d, h);
    }

    #[test]
    fn group_header_round_trip() {
        let h = Header::data(
            Addressing::Group(GroupAddress(0x1234)),
            ClusterId(0x0008),
            ProfileId::HOME_AUTOMATION,
            Endpoint(3),
            7,
        );
        let mut buf = [0u8; 16];
        let n = h.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x0C, 0x34, 0x12, 0x08, 0x00, 0x04, 0x01, 3, 7]);
        let (d, _) = Header::decode_prefix(&buf[..n]).unwrap();
        assert_eq!(d.group(), Some(GroupAddress(0x1234)));
        assert_eq!(d.dst_endpoint(), None);
    }

    #[test]
    fn command_and_ack_headers() {
        let c = Header::command(9, false)
            .with_ack_request(true)
            .secured(true);
        let mut buf = [0u8; 8];
        let n = c.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x61, 9]);
        let ack = Header::ack_for(&c, None);
        let n = ack.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x12, 9]);
        let (d, _) = Header::decode_prefix(&buf[..n]).unwrap();
        assert_eq!(d, ack);

        let data = Header::data(
            Addressing::Endpoint(Endpoint(1)),
            ClusterId(0x0006),
            ProfileId::HOME_AUTOMATION,
            Endpoint(2),
            0x5A,
        );
        let ack = Header::ack_for(&data, None);
        assert_eq!(ack.dst_endpoint(), Some(Endpoint(2)));
        assert_eq!(ack.src_endpoint, Some(Endpoint(1)));
        let n = ack.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x02, 2, 0x06, 0x00, 0x04, 0x01, 1, 0x5A]);
    }

    #[test]
    fn fragmented_headers() {
        let data = Header::data(
            Addressing::Endpoint(Endpoint(1)),
            ClusterId(0),
            ProfileId::ZDP,
            Endpoint(0),
            1,
        )
        .with_extended(ExtendedHeader {
            fragmentation: Fragmentation::First,
            block_number: 3,
            ack_bitfield: None,
        });
        let mut buf = [0u8; 16];
        let n = data.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[n - 2..n], &[0x01, 3]);
        let (d, _) = Header::decode_prefix(&buf[..n]).unwrap();
        assert_eq!(d.fragmentation(), Fragmentation::First);

        let ack = Header::ack_for(
            &data,
            Some(ExtendedHeader {
                fragmentation: Fragmentation::First,
                block_number: 0,
                ack_bitfield: Some(0xFF),
            }),
        );
        let n = ack.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[n - 3..n], &[0x01, 0, 0xFF]);
        let (d, _) = Header::decode_prefix(&buf[..n]).unwrap();
        assert_eq!(d.extended.unwrap().ack_bitfield, Some(0xFF));
    }

    #[test]
    fn malformed_headers_are_rejected() {
        assert!(Header::decode_prefix(&[]).is_err());
        // Reserved delivery mode.
        assert!(Header::decode_prefix(&[0x04, 1, 0, 0, 0, 0, 1, 1]).is_err());
        // Truncated addressing.
        assert!(Header::decode_prefix(&[0x00, 1, 0]).is_err());
        // Reserved fragmentation value.
        assert!(Header::decode_prefix(&[0x81, 1, 0x03]).is_err());
    }
}
