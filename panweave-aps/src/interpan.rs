//! Inter-PAN frames (R23.2 Annex G: stub NWK header §G.3.2.1, inter-PAN
//! APS header §G.3.3; ZCL8 §13.3.4.5; SE 1.4a Annex B "enhanced"
//! inter-PAN): the two headers that carry an application frame between
//! devices that do not share a PAN. The MAC frame around them is built
//! by the MAC service (destination PAN 0xffff or the target's, extended
//! source address, no MAC security); this module encodes and decodes
//! what follows the MAC header.
//!
//! The APS frame control of the stub header carries the same Security,
//! ACK Request and Extended Header Present bits as a normal APS data
//! frame (§G.3.3, SE Figure B-7): an ACK request adds the APS counter, a
//! fragmented message adds the extended header, and a secured frame is
//! followed by the APS auxiliary header and ends with the MIC. Securing
//! uses the ordinary APS link-key procedure of §4.4.1.1 through
//! [`secure`] / [`unsecure`]; the stub NWK header is not part of the
//! authenticated data (the APS frame starts at the APS frame control,
//! as for a networked frame), which is how the touchlink and SE frames
//! seen in the field are laid out.

use panweave_codec::{CodecError, Reader, Writer};
use panweave_security::aux_header::{KeyIdentifier, SecurityLevel};
use panweave_security::cipher::BlockCipher;
use panweave_security::frame::SecurityError;
use panweave_types::{ClusterId, ExtendedAddress, GroupAddress, ProfileId};

use crate::security::{ApsSecurity, ApsUnsecured, SecureError};

/// NWK frame type of an inter-PAN frame (R23.2 Table 3-45).
pub const NWK_FRAME_TYPE_INTER_PAN: u8 = 0b11;
/// APS frame type of an inter-PAN frame (R23.2 Table 2-20).
pub const APS_FRAME_TYPE_INTER_PAN: u8 = 0b11;
/// `nwkcProtocolVersion`.
pub const PROTOCOL_VERSION: u8 = 2;
/// Length of the stub NWK header.
pub const STUB_NWK_LEN: usize = 2;
/// Security bit of the APS frame control.
const FC_SECURITY: u8 = 0x20;
/// ACK request bit of the APS frame control.
const FC_ACK_REQUEST: u8 = 0x40;
/// Extended header present bit of the APS frame control.
const FC_EXTENDED: u8 = 0x80;

/// Delivery mode of an inter-PAN APS frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterPanDelivery {
    /// Unicast.
    Unicast,
    /// Broadcast.
    Broadcast,
    /// Group addressed (delivery mode 0b11, §G.3.3).
    Group(GroupAddress),
}

/// Fragmentation state carried by the extended header (§2.2.5.1.1.9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Fragment {
    /// First block of a fragmented message (the block number then holds
    /// the block count) or a later one.
    pub first: bool,
    /// Block number (or block count on the first block).
    pub block: u8,
}

/// The inter-PAN headers preceding the application frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterPanHeader {
    /// Delivery mode.
    pub delivery: InterPanDelivery,
    /// Cluster identifier.
    pub cluster: ClusterId,
    /// Profile identifier.
    pub profile: ProfileId,
    /// Security bit: an auxiliary header follows the stub APS header
    /// and the payload is protected.
    pub secured: bool,
    /// APS counter, present when an acknowledgement is requested.
    pub counter: Option<u8>,
    /// Extended header, present when the message is fragmented.
    pub fragment: Option<Fragment>,
}

impl InterPanHeader {
    /// A plain (unsecured, unacknowledged) header.
    pub const fn new(delivery: InterPanDelivery, cluster: ClusterId, profile: ProfileId) -> Self {
        InterPanHeader {
            delivery,
            cluster,
            profile,
            secured: false,
            counter: None,
            fragment: None,
        }
    }

    /// Whether `bytes` (a MAC payload) starts with a stub NWK header,
    /// i.e. is an inter-PAN frame rather than a NWK frame.
    pub fn is_inter_pan(bytes: &[u8]) -> bool {
        bytes
            .first()
            .is_some_and(|b| b & 0x03 == NWK_FRAME_TYPE_INTER_PAN)
    }

    /// Length of the stub APS header alone (from the APS frame control
    /// to the end of the extended header).
    pub const fn aps_header_len(&self) -> usize {
        1 + if matches!(self.delivery, InterPanDelivery::Group(_)) {
            2
        } else {
            0
        } + 4
            + if self.counter.is_some() { 1 } else { 0 }
            + match self.fragment {
                Some(_) => 2,
                None => 0,
            }
    }

    /// Encoded length of both stub headers.
    pub const fn encoded_len(&self) -> usize {
        STUB_NWK_LEN + self.aps_header_len()
    }

    /// Encodes the stub NWK header and the inter-PAN APS header.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(u16::from(
            NWK_FRAME_TYPE_INTER_PAN | (PROTOCOL_VERSION << 2),
        ))?;
        let (mode, group) = match self.delivery {
            InterPanDelivery::Unicast => (0b00, None),
            InterPanDelivery::Broadcast => (0b10, None),
            InterPanDelivery::Group(g) => (0b11, Some(g)),
        };
        let mut fc = APS_FRAME_TYPE_INTER_PAN | (mode << 2);
        if self.secured {
            fc |= FC_SECURITY;
        }
        if self.counter.is_some() {
            fc |= FC_ACK_REQUEST;
        }
        if self.fragment.is_some() {
            fc |= FC_EXTENDED;
        }
        w.u8(fc)?;
        if let Some(g) = group {
            w.u16_le(g.0)?;
        }
        w.u16_le(self.cluster.0)?;
        w.u16_le(self.profile.0)?;
        if let Some(c) = self.counter {
            w.u8(c)?;
        }
        if let Some(f) = self.fragment {
            w.u8(if f.first { 0b01 } else { 0b10 })?;
            w.u8(f.block)?;
        }
        Ok(())
    }

    /// Decodes the headers, returning them and what follows (the
    /// application frame, or the auxiliary header, protected payload
    /// and MIC of a secured frame; see [`unsecure`]).
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
            0b10 => InterPanDelivery::Broadcast,
            0b11 => InterPanDelivery::Group(GroupAddress(r.u16_le()?)),
            other => {
                return Err(CodecError::InvalidField {
                    field: "inter-PAN delivery mode",
                    value: u32::from(other),
                });
            }
        };
        let cluster = ClusterId(r.u16_le()?);
        let profile = ProfileId(r.u16_le()?);
        let counter = if aps & FC_ACK_REQUEST != 0 {
            Some(r.u8()?)
        } else {
            None
        };
        let fragment = if aps & FC_EXTENDED != 0 {
            let ext = r.u8()?;
            match ext & 0x03 {
                0b00 => None,
                0b01 => Some(Fragment {
                    first: true,
                    block: r.u8()?,
                }),
                0b10 => Some(Fragment {
                    first: false,
                    block: r.u8()?,
                }),
                other => {
                    return Err(CodecError::InvalidField {
                        field: "fragmentation",
                        value: u32::from(other),
                    });
                }
            }
        } else {
            None
        };
        Ok((
            InterPanHeader {
                delivery,
                cluster,
                profile,
                secured: aps & FC_SECURITY != 0,
                counter,
                fragment,
            },
            r.take_rest(),
        ))
    }
}

/// Builds a secured inter-PAN frame in `buf` (SE Annex B.4, §4.4.1.1):
/// writes the stub headers with the Security bit set, reserves the
/// auxiliary header, copies `payload` and protects it with the link key
/// shared with `partner` (extended nonce, so the receiver can look the
/// key up from the frame alone). Returns the total frame length.
pub fn secure<C: BlockCipher, const N: usize>(
    security: &mut ApsSecurity<C, N>,
    buf: &mut [u8],
    header: &InterPanHeader,
    payload: &[u8],
    level: SecurityLevel,
    partner: ExtendedAddress,
    local_ieee: ExtendedAddress,
) -> Result<usize, SecureError> {
    let header = InterPanHeader {
        secured: true,
        ..*header
    };
    let aps_len = header.aps_header_len();
    let aux_len = ApsSecurity::<C, N>::aux_header_len(true);
    let payload_start = STUB_NWK_LEN + aps_len + aux_len;
    let total = payload_start + payload.len() + level.mic_len();
    if buf.len() < total {
        return Err(SecureError::Security(SecurityError::Malformed));
    }
    let mut w = Writer::new(buf);
    header
        .encode(&mut w)
        .map_err(|_| SecureError::Security(SecurityError::Malformed))?;
    buf[payload_start..payload_start + payload.len()].copy_from_slice(payload);
    let aps_frame = buf
        .get_mut(STUB_NWK_LEN..)
        .ok_or(SecureError::Security(SecurityError::Malformed))?;
    let n = security.secure_outgoing(
        aps_frame,
        aps_len,
        payload.len(),
        level,
        partner,
        KeyIdentifier::Data,
        local_ieee,
        true,
    )?;
    Ok(STUB_NWK_LEN + n)
}

/// Unprotects a received secured inter-PAN frame in place. `buf` is
/// the MAC payload (stub headers first); `sender` is the MAC source
/// address, used when the auxiliary header carries no extended nonce.
/// Returns the decoded header, the security result and the range of the
/// application frame within `buf`.
pub fn unsecure<C: BlockCipher, const N: usize>(
    security: &mut ApsSecurity<C, N>,
    buf: &mut [u8],
    level: SecurityLevel,
    sender: Option<ExtendedAddress>,
) -> Result<(InterPanHeader, ApsUnsecured, core::ops::Range<usize>), SecurityError> {
    let (header, _) = InterPanHeader::decode(buf).map_err(|_| SecurityError::Malformed)?;
    if !header.secured {
        return Err(SecurityError::PolicyRejected);
    }
    let aps_len = header.aps_header_len();
    let aps_frame = buf
        .get_mut(STUB_NWK_LEN..)
        .ok_or(SecurityError::Malformed)?;
    let u = security.unsecure_incoming(aps_frame, aps_len, level, sender, None)?;
    let range = STUB_NWK_LEN + u.payload_start..STUB_NWK_LEN + u.payload_end;
    Ok((header, u, range))
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;
    use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
    use panweave_types::{Key128, KeyAttributes};

    #[test]
    fn round_trips_and_detects_inter_pan() {
        let h = InterPanHeader::new(
            InterPanDelivery::Broadcast,
            ClusterId(0x1000),
            ProfileId(0xc05e),
        );
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
        // Group delivery is 0b11 with the group address (§G.3.3).
        let g = InterPanHeader {
            delivery: InterPanDelivery::Group(GroupAddress(0x1234)),
            ..h
        };
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 9);
        assert_eq!(buf[2], 0x0f);
        assert_eq!(InterPanHeader::decode(&buf[..n]).unwrap().0, g);
        assert!(InterPanHeader::decode(&[0x08, 0x00, 0x0b, 0, 0, 0, 0]).is_err());
        assert!(InterPanHeader::decode(&[0x0b, 0x00, 0x07, 0, 0, 0, 0]).is_err());
        // ACK request carries the APS counter; a fragment the extended
        // header; the security bit is preserved.
        let e = InterPanHeader {
            delivery: InterPanDelivery::Unicast,
            secured: true,
            counter: Some(0x42),
            fragment: Some(Fragment {
                first: true,
                block: 3,
            }),
            ..h
        };
        let mut w = Writer::new(&mut buf);
        e.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, e.encoded_len());
        assert_eq!(n, 2 + 1 + 4 + 1 + 2);
        assert_eq!(buf[2], 0x03 | FC_SECURITY | FC_ACK_REQUEST | FC_EXTENDED);
        assert_eq!(&buf[7..10], &[0x42, 0x01, 3]);
        assert_eq!(InterPanHeader::decode(&buf[..n]).unwrap().0, e);
    }

    #[test]
    fn secured_frames_round_trip_between_link_key_holders() {
        const A: ExtendedAddress = ExtendedAddress(0x00aa);
        const B: ExtendedAddress = ExtendedAddress(0x00bb);
        let key = Key128::from_bytes([7; 16]);
        let armed = |partner| {
            let mut s = ApsSecurity::<SoftwareAes, 4>::new();
            let mut e = LinkKeyEntry::provisional(partner, key.clone(), LinkKeyKind::Unique);
            e.attributes = KeyAttributes::VerifiedKey;
            s.install(e).unwrap();
            let (p, r) = s.start_counter_reservation().unwrap();
            s.commit_counter_reservation(p, r);
            s
        };
        let mut tx = armed(B);
        let mut rx = armed(A);
        let header = InterPanHeader::new(
            InterPanDelivery::Unicast,
            ClusterId(0x0700),
            ProfileId(0x0109),
        );
        let payload = [0x09, 0x01, 0x00, 0xaa, 0xbb];
        let mut buf = [0u8; 64];
        let n = secure(
            &mut tx,
            &mut buf,
            &header,
            &payload,
            SecurityLevel::EncMic32,
            B,
            A,
        )
        .unwrap();
        assert_eq!(n, 2 + 5 + 13 + payload.len() + 4);
        let (h, _) = InterPanHeader::decode(&buf[..n]).unwrap();
        assert!(h.secured);
        assert_ne!(&buf[n - 4 - payload.len()..n - 4], &payload);
        let (h, u, range) =
            unsecure(&mut rx, &mut buf[..n], SecurityLevel::EncMic32, Some(A)).unwrap();
        assert_eq!(h.cluster, ClusterId(0x0700));
        assert_eq!(u.partner, A);
        assert_eq!(&buf[range], &payload);
        // Replay is refused; an unsecured frame is refused by policy.
        let n2 = secure(
            &mut tx,
            &mut buf,
            &header,
            &payload,
            SecurityLevel::EncMic32,
            B,
            A,
        )
        .unwrap();
        let mut copy = [0u8; 64];
        copy[..n2].copy_from_slice(&buf[..n2]);
        unsecure(&mut rx, &mut buf[..n2], SecurityLevel::EncMic32, Some(A)).unwrap();
        assert!(unsecure(&mut rx, &mut copy[..n2], SecurityLevel::EncMic32, Some(A)).is_err());
        let mut plain = [0u8; 16];
        let mut w = Writer::new(&mut plain);
        header.encode(&mut w).unwrap();
        let m = w.position();
        assert_eq!(
            unsecure(&mut rx, &mut plain[..m], SecurityLevel::EncMic32, Some(A)).err(),
            Some(SecurityError::PolicyRejected)
        );
    }
}
