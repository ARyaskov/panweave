//! Inter-PAN frames (R23.2 §3.6.5 stub NWK header, §2.2.9 inter-PAN
//! APS header; ZCL8 §13.3.4.5): the two headers that carry a ZCL frame
//! between devices that do not share a PAN. The MAC frame around them
//! is built by the MAC service (destination PAN 0xffff or the target's,
//! extended source address, no security); this module encodes and
//! decodes what follows the MAC header.

use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, GroupAddress, ProfileId};

/// NWK frame type of an inter-PAN frame (R23.2 Table 3-45).
pub const NWK_FRAME_TYPE_INTER_PAN: u8 = 0b11;
/// APS frame type of an inter-PAN frame (R23.2 Table 2-20).
pub const APS_FRAME_TYPE_INTER_PAN: u8 = 0b11;
/// `nwkcProtocolVersion`.
pub const PROTOCOL_VERSION: u8 = 2;

/// Delivery mode of an inter-PAN APS frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterPanDelivery {
    /// Unicast.
    Unicast,
    /// Broadcast.
    Broadcast,
    /// Group addressed.
    Group(GroupAddress),
}

/// The inter-PAN headers preceding a ZCL frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterPanHeader {
    /// Delivery mode.
    pub delivery: InterPanDelivery,
    /// Cluster identifier.
    pub cluster: ClusterId,
    /// Profile identifier.
    pub profile: ProfileId,
}

impl InterPanHeader {
    /// Whether `bytes` (a MAC payload) starts with a stub NWK header,
    /// i.e. is an inter-PAN frame rather than a NWK frame.
    pub fn is_inter_pan(bytes: &[u8]) -> bool {
        bytes
            .first()
            .is_some_and(|b| b & 0x03 == NWK_FRAME_TYPE_INTER_PAN)
    }

    /// Encoded length.
    pub const fn encoded_len(&self) -> usize {
        2 + 1
            + if matches!(self.delivery, InterPanDelivery::Group(_)) {
                2
            } else {
                0
            }
            + 4
    }

    /// Encodes the stub NWK header and the inter-PAN APS header.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(u16::from(
            NWK_FRAME_TYPE_INTER_PAN | (PROTOCOL_VERSION << 2),
        ))?;
        let (mode, group) = match self.delivery {
            InterPanDelivery::Unicast => (0b00, None),
            InterPanDelivery::Group(g) => (0b01, Some(g)),
            InterPanDelivery::Broadcast => (0b10, None),
        };
        w.u8(APS_FRAME_TYPE_INTER_PAN | (mode << 2))?;
        if let Some(g) = group {
            w.u16_le(g.0)?;
        }
        w.u16_le(self.cluster.0)?;
        w.u16_le(self.profile.0)
    }

    /// Decodes the headers, returning them and the ZCL frame that
    /// follows.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        let mut r = Reader::new(bytes);
        let nwk = r.u16_le()?;
        if nwk & 0x03 != u16::from(NWK_FRAME_TYPE_INTER_PAN) {
            return Err(CodecError::InvalidField {
                field: "NWK frame type",
                value: u32::from(nwk & 0x03),
            });
        }
        let aps = r.u8()?;
        if aps & 0x03 != APS_FRAME_TYPE_INTER_PAN {
            return Err(CodecError::InvalidField {
                field: "APS frame type",
                value: u32::from(aps & 0x03),
            });
        }
        let delivery = match (aps >> 2) & 0x03 {
            0b00 => InterPanDelivery::Unicast,
            0b01 => InterPanDelivery::Group(GroupAddress(r.u16_le()?)),
            0b10 => InterPanDelivery::Broadcast,
            other => {
                return Err(CodecError::InvalidField {
                    field: "inter-PAN delivery mode",
                    value: u32::from(other),
                });
            }
        };
        let cluster = ClusterId(r.u16_le()?);
        let profile = ProfileId(r.u16_le()?);
        Ok((
            InterPanHeader {
                delivery,
                cluster,
                profile,
            },
            r.take_rest(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_detects_inter_pan() {
        let h = InterPanHeader {
            delivery: InterPanDelivery::Broadcast,
            cluster: ClusterId(0x1000),
            profile: ProfileId(0xc05e),
        };
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        h.encode(&mut w).unwrap();
        w.bytes(&[0x11, 0x22]).unwrap();
        let n = w.position();
        assert_eq!(n, h.encoded_len() + 2);
        assert_eq!(&buf[..3], &[0x0b, 0x00, 0x0b]);
        assert!(InterPanHeader::is_inter_pan(&buf[..n]));
        assert!(!InterPanHeader::is_inter_pan(&[0x08, 0x00]));
        let (d, rest) = InterPanHeader::decode(&buf[..n]).unwrap();
        assert_eq!(d, h);
        assert_eq!(rest, &[0x11, 0x22]);
        let g = InterPanHeader {
            delivery: InterPanDelivery::Group(GroupAddress(0x1234)),
            ..h
        };
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 9);
        assert_eq!(InterPanHeader::decode(&buf[..n]).unwrap().0, g);
        assert!(InterPanHeader::decode(&[0x08, 0x00, 0x0b, 0, 0, 0, 0]).is_err());
    }
}
