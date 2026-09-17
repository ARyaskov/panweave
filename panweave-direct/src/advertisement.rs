//! The Zigbee Direct extension to the BLE advertisement (ZD 1.1 §7.6.3,
//! Table 24): a Service Data AD structure for the Commissioning Service
//! carrying the version, flags, PAN ID and NWK address of the ZDD.

use panweave_types::{PanId, ShortAddress};

use crate::gatt::COMMISSIONING_SERVICE_16;

/// AD type Service Data - 16-bit UUID.
pub const AD_TYPE_SERVICE_DATA_16: u8 = 0x16;
/// AD length of the extension (type + UUID + 5 octets).
pub const AD_LENGTH: u8 = 0x08;
/// Encoded length including the AD length octet.
pub const ENCODED_LEN: usize = 9;
/// ZD version of this specification.
pub const VERSION: u8 = 0x1;

/// The advertised state of a ZDD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Advertisement {
    /// The ZDD supports the Tunnel Service (ZDTS flag).
    pub tunnel_service: bool,
    /// Permit joining status (0 when not joined).
    pub permit_join: bool,
    /// PAN ID (0xffff when not joined).
    pub pan_id: PanId,
    /// NWK address (0xffff when not joined).
    pub nwk_address: ShortAddress,
}

impl Advertisement {
    /// A factory-new ZDD.
    pub const NOT_JOINED: Advertisement = Advertisement {
        tunnel_service: false,
        permit_join: false,
        pan_id: PanId::BROADCAST,
        nwk_address: ShortAddress::BROADCAST_ALL,
    };

    /// True when the ZDD is on a network.
    pub const fn joined(&self) -> bool {
        self.pan_id.0 != 0xFFFF && self.nwk_address.0 != 0xFFFF
    }

    /// Encodes the AD structure (AD length, AD type, data).
    pub fn encode(&self) -> [u8; ENCODED_LEN] {
        let flags = (u8::from(self.tunnel_service) << 4)
            | (u8::from(self.permit_join && self.joined()) << 5);
        let pan = if self.joined() { self.pan_id.0 } else { 0xFFFF };
        let nwk = if self.joined() {
            self.nwk_address.0
        } else {
            0xFFFF
        };
        [
            AD_LENGTH,
            AD_TYPE_SERVICE_DATA_16,
            (COMMISSIONING_SERVICE_16 & 0xff) as u8,
            (COMMISSIONING_SERVICE_16 >> 8) as u8,
            VERSION | flags,
            (pan & 0xff) as u8,
            (pan >> 8) as u8,
            (nwk & 0xff) as u8,
            (nwk >> 8) as u8,
        ]
    }

    /// Finds and decodes the extension in an advertisement's AD
    /// structures; `None` when absent or of another version.
    pub fn find(ad: &[u8]) -> Option<Self> {
        let mut rest = ad;
        while let Some((&len, tail)) = rest.split_first() {
            let len = usize::from(len);
            if len == 0 {
                break;
            }
            let (structure, next) = tail.split_at_checked(len)?;
            rest = next;
            let (&ty, data) = structure.split_first()?;
            if ty != AD_TYPE_SERVICE_DATA_16 || data.len() < 7 {
                continue;
            }
            let uuid = u16::from_le_bytes([data[0], data[1]]);
            if uuid != COMMISSIONING_SERVICE_16 || data[2] & 0x0F != VERSION {
                continue;
            }
            let flags = data[2];
            return Some(Advertisement {
                tunnel_service: flags & 0x10 != 0,
                permit_join: flags & 0x20 != 0,
                pan_id: PanId(u16::from_le_bytes([data[3], data[4]])),
                nwk_address: ShortAddress(u16::from_le_bytes([data[5], data[6]])),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_not_joined_defaults() {
        let a = Advertisement {
            tunnel_service: true,
            permit_join: true,
            pan_id: PanId(0x1A62),
            nwk_address: ShortAddress(0x0001),
        };
        let bytes = a.encode();
        assert_eq!(
            bytes,
            [0x08, 0x16, 0xF7, 0xFF, 0x31, 0x62, 0x1A, 0x01, 0x00]
        );
        // Preceded by a Flags AD structure.
        let mut ad = [0u8; 12];
        ad[..3].copy_from_slice(&[0x02, 0x01, 0x06]);
        ad[3..].copy_from_slice(&bytes);
        assert_eq!(Advertisement::find(&ad), Some(a));
        let f = Advertisement::NOT_JOINED.encode();
        assert_eq!(&f[4..], &[0x01, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Permit join is never advertised while not joined.
        let mut n = Advertisement::NOT_JOINED;
        n.permit_join = true;
        assert_eq!(n.encode()[4], 0x01);
        assert_eq!(Advertisement::find(&[0x03, 0x16, 0xF7, 0xFF]), None);
    }
}
