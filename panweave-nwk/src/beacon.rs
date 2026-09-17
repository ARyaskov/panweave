//! Zigbee beacon payload (R23.2 §3.6.8, Table 3-83, Figure 3-53) and the
//! R23 beacon appendix.
//!
//! Layout of the 15-octet beacon info field (bit numbers from Figure 3-53):
//! protocol id (8), stack profile (4), protocol version (4), reserved (2),
//! router capacity (1), device depth (4, deprecated), end device capacity
//! (1), extended PAN id (64), tx offset (24), update id (8).

use panweave_codec::tlv::TlvSet;
use panweave_codec::{CodecError, Decode, Encode, Reader, Writer};
use panweave_types::ExtendedAddress;

use crate::frame::PROTOCOL_VERSION;

/// Protocol identifier for Zigbee beacons (always 0).
pub const PROTOCOL_ID_ZIGBEE: u8 = 0x00;

/// Stack profile for Zigbee PRO.
pub const STACK_PROFILE_PRO: u8 = 0x02;

/// Tx offset value in beaconless networks.
pub const TX_OFFSET_NONE: u32 = 0x00FF_FFFF;

/// Length of the beacon info field.
pub const BEACON_INFO_LEN: usize = 15;

/// Zigbee beacon payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BeaconPayload<'a> {
    /// Protocol identifier (must be 0).
    pub protocol_id: u8,
    /// Stack profile (2 for Zigbee PRO).
    pub stack_profile: u8,
    /// NWK protocol version (2).
    pub protocol_version: u8,
    /// Router capacity available.
    pub router_capacity: bool,
    /// Device depth (deprecated; transmitted as 0, accepted as anything).
    pub device_depth: u8,
    /// End device capacity available.
    pub end_device_capacity: bool,
    /// Extended PAN identifier.
    pub extended_pan_id: ExtendedAddress,
    /// Tx offset (24 bits).
    pub tx_offset: u32,
    /// `nwkUpdateId`.
    pub update_id: u8,
    /// Beacon appendix TLVs (raw; may be empty).
    pub appendix: &'a [u8],
}

impl<'a> BeaconPayload<'a> {
    /// Builds a Zigbee PRO beacon payload.
    pub const fn new(
        extended_pan_id: ExtendedAddress,
        router_capacity: bool,
        end_device_capacity: bool,
        update_id: u8,
        appendix: &'a [u8],
    ) -> Self {
        BeaconPayload {
            protocol_id: PROTOCOL_ID_ZIGBEE,
            stack_profile: STACK_PROFILE_PRO,
            protocol_version: PROTOCOL_VERSION,
            router_capacity,
            device_depth: 0,
            end_device_capacity,
            extended_pan_id,
            tx_offset: TX_OFFSET_NONE,
            update_id,
            appendix,
        }
    }

    /// True when this beacon describes a joinable Zigbee PRO network per
    /// §3.6.1.5.1 steps 2–3 (protocol version 2, stack profile 2).
    pub const fn is_zigbee_pro(&self) -> bool {
        self.protocol_id == PROTOCOL_ID_ZIGBEE
            && self.protocol_version == PROTOCOL_VERSION
            && self.stack_profile == STACK_PROFILE_PRO
    }

    /// Validated beacon appendix TLVs; `None` when absent or malformed
    /// (malformed appendices are ignored, §3.6.8.1).
    pub fn appendix_tlvs(&self) -> Option<TlvSet<'a>> {
        if self.appendix.is_empty() {
            return None;
        }
        TlvSet::validate(self.appendix, |_| false).ok()
    }

    /// True when the sender advertises R23 capabilities via a beacon
    /// appendix (used to select the Network Commissioning attach
    /// mechanism, §3.6.1.6.1.1).
    pub fn has_appendix(&self) -> bool {
        self.appendix_tlvs().is_some()
    }
}

impl<'a> Decode<'a> for BeaconPayload<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, CodecError> {
        let protocol_id = r.u8()?;
        let b1 = r.u8()?;
        let b2 = r.u8()?;
        let extended_pan_id = ExtendedAddress(r.u64_le()?);
        let tx_offset = r.u24_le()?;
        let update_id = r.u8()?;
        Ok(BeaconPayload {
            protocol_id,
            stack_profile: b1 & 0x0F,
            protocol_version: b1 >> 4,
            router_capacity: b2 & 0x04 != 0,
            device_depth: (b2 >> 3) & 0x0F,
            end_device_capacity: b2 & 0x80 != 0,
            extended_pan_id,
            tx_offset,
            update_id,
            appendix: r.take_rest(),
        })
    }
}

impl Encode for BeaconPayload<'_> {
    fn encoded_len(&self) -> usize {
        BEACON_INFO_LEN + self.appendix.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.protocol_id)?;
        w.u8((self.stack_profile & 0x0F) | (self.protocol_version << 4))?;
        w.u8((u8::from(self.router_capacity) << 2)
            | ((self.device_depth & 0x0F) << 3)
            | (u8::from(self.end_device_capacity) << 7))?;
        w.u64_le(self.extended_pan_id.0)?;
        w.u24_le(self.tx_offset)?;
        w.u8(self.update_id)?;
        w.bytes(self.appendix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_payload_round_trip_and_bit_layout() {
        let appendix = [70, 1, 0x21, 0x00];
        let b = BeaconPayload::new(
            ExtendedAddress(0x0011_2233_4455_6677),
            true,
            true,
            9,
            &appendix,
        );
        let mut buf = [0u8; 32];
        let n = b.encode_to_slice(&mut buf).unwrap();
        assert_eq!(n, 19);
        assert_eq!(&buf[..3], &[0x00, 0x22, 0x84]);
        assert_eq!(&buf[11..14], &[0xFF, 0xFF, 0xFF]);
        assert_eq!(buf[14], 9);
        let d = BeaconPayload::decode_exact(&buf[..n]).unwrap();
        assert_eq!(d, b);
        assert!(d.is_zigbee_pro());
        assert!(d.has_appendix());
        assert!(d.appendix_tlvs().unwrap().find(70).is_some());
        // Legacy beacon without appendix.
        let d2 = BeaconPayload::decode_exact(&buf[..15]).unwrap();
        assert!(!d2.has_appendix());
        // Non-PRO beacon is not joinable.
        let mut other = buf;
        other[1] = 0x21;
        assert!(
            !BeaconPayload::decode_exact(&other[..15])
                .unwrap()
                .is_zigbee_pro()
        );
        // Malformed appendix is ignored rather than rejected.
        let mut bad = buf;
        bad[16] = 9;
        let d3 = BeaconPayload::decode_exact(&bad[..n]).unwrap();
        assert!(d3.appendix_tlvs().is_none());
        assert!(BeaconPayload::decode_exact(&buf[..14]).is_err());
    }
}
