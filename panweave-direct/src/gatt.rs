//! GATT identifiers of the Zigbee Direct services (ZD 1.1 §6.5, §7.7):
//! 128-bit UUIDs in RFC 4122 byte order, and the 16-bit Commissioning
//! Service UUID expanded with the Bluetooth Base UUID.

use crate::secure::{Uuid, expand_uuid16};

/// Zigbee Direct Security Service (§6.5): 29144AF4-0000-4481-BFE9-6D0299B429E3.
pub const SECURITY_SERVICE: Uuid = security_uuid(0x0000);
/// Zigbee Direct Commissioning Service 16-bit UUID (§7.7.2).
pub const COMMISSIONING_SERVICE_16: u16 = 0xFFF7;
/// Zigbee Direct Commissioning Service as a 128-bit UUID.
pub const COMMISSIONING_SERVICE: Uuid = expand_uuid16(COMMISSIONING_SERVICE_16);
/// Zigbee Direct Tunnel Service (§7.7.3): 8BD178FD-0000-45F4-8120-B2378BD5313F.
pub const TUNNEL_SERVICE: Uuid = tunnel_uuid(0x0000);

/// UUID of the security service family with the given second group.
pub const fn security_uuid(group: u16) -> Uuid {
    [
        0x29,
        0x14,
        0x4A,
        0xF4,
        (group >> 8) as u8,
        (group & 0xff) as u8,
        0x44,
        0x81,
        0xBF,
        0xE9,
        0x6D,
        0x02,
        0x99,
        0xB4,
        0x29,
        0xE3,
    ]
}

/// UUID of the commissioning service family (7072377D-xxxx-421C-B163-491C27333A61).
pub const fn commissioning_uuid(group: u16) -> Uuid {
    [
        0x70,
        0x72,
        0x37,
        0x7D,
        (group >> 8) as u8,
        (group & 0xff) as u8,
        0x42,
        0x1C,
        0xB1,
        0x63,
        0x49,
        0x1C,
        0x27,
        0x33,
        0x3A,
        0x61,
    ]
}

/// UUID of the tunnel service family (8BD178FD-xxxx-45F4-8120-B2378BD5313F).
pub const fn tunnel_uuid(group: u16) -> Uuid {
    [
        0x8B,
        0xD1,
        0x78,
        0xFD,
        (group >> 8) as u8,
        (group & 0xff) as u8,
        0x45,
        0xF4,
        0x81,
        0x20,
        0xB2,
        0x37,
        0x8B,
        0xD5,
        0x31,
        0x3F,
    ]
}

/// Security service characteristics (Table 5).
pub mod security {
    use super::{Uuid, security_uuid};
    /// Authenticate SPEKE/Curve25519/AES-MMO-128/HMAC-AES-MMO-128.
    pub const AUTHENTICATE_CURVE25519_AES_MMO: Uuid = security_uuid(0x0001);
    /// Authenticate SPEKE/Curve25519/SHA-256/HMAC-SHA-256-128 (reserved).
    pub const AUTHENTICATE_CURVE25519_SHA256: Uuid = security_uuid(0x0002);
    /// Authenticate ECDHE-PSK/P-256/SHA-256/HMAC-SHA-256-128.
    pub const AUTHENTICATE_P256_SHA256: Uuid = security_uuid(0x0003);
}

/// Commissioning service characteristics (Table 26).
pub mod commissioning {
    use super::{Uuid, commissioning_uuid};
    /// Form Network.
    pub const FORM_NETWORK: Uuid = commissioning_uuid(0x0001);
    /// Join Network.
    pub const JOIN_NETWORK: Uuid = commissioning_uuid(0x0002);
    /// Permit Joining.
    pub const PERMIT_JOINING: Uuid = commissioning_uuid(0x0003);
    /// Leave Network.
    pub const LEAVE_NETWORK: Uuid = commissioning_uuid(0x0004);
    /// Commissioning Status.
    pub const COMMISSIONING_STATUS: Uuid = commissioning_uuid(0x0005);
    /// Manage Joiners.
    pub const MANAGE_JOINERS: Uuid = commissioning_uuid(0x0006);
    /// Identify.
    pub const IDENTIFY: Uuid = commissioning_uuid(0x0007);
    /// Finding & Binding.
    pub const FINDING_AND_BINDING: Uuid = commissioning_uuid(0x0008);
}

/// Tunnel service characteristics (§7.7.3).
pub mod tunnel {
    use super::{Uuid, tunnel_uuid};
    /// ZDTS NPDU.
    pub const NPDU: Uuid = tunnel_uuid(0x0001);
}

/// BLE ATT application error code for Zigbee Direct (§6.4.7).
pub const ATT_ERROR_ZIGBEE_DIRECT: u8 = 0x80;
