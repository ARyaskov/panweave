//! Generic Tunnel (ZCL8 §9.2, cluster 0x0600) and BACnet Protocol Tunnel
//! (§9.3, cluster 0x0601): a protocol-specific tunnel cluster on an
//! endpoint is found by its protocol address through the Generic Tunnel
//! server beside it (Match Protocol Address, answered when the address
//! equals `ProtocolAddress`; Advertise Protocol Address on start-up and
//! change), and BACnet NPDUs cross the BACnet tunnel as Transfer NPDU
//! commands (the BACnet network layer is the application's). The ISO
//! 7816 Protocol Tunnel (§9.5, cluster 0x0615) carries smart card APDUs
//! both ways once a client inserted its card (`Status` BUSY) and until
//! it extracted it.

use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId, ExtendedAddress};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Generic Tunnel cluster identifier.
pub const GENERIC_TUNNEL: ClusterId = ClusterId(0x0600);
/// BACnet Protocol Tunnel cluster identifier.
pub const BACNET_PROTOCOL_TUNNEL: ClusterId = ClusterId(0x0601);
/// ISO 7816 Protocol Tunnel cluster identifier.
pub const ISO7816_TUNNEL: ClusterId = ClusterId(0x0615);

/// ISO 7816 Tunnel `Status` (uint8: FREE / BUSY, Table 9-26).
pub const ISO7816_STATUS: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(1), Access::RO);
/// `Status`: no client connected.
pub const ISO7816_FREE: u8 = 0x00;
/// `Status`: a client's smart card is inserted.
pub const ISO7816_BUSY: u8 = 0x01;
/// Transfer APDU (both directions).
pub const CMD_TRANSFER_APDU: CommandId = CommandId(0x00);
/// Insert Smart Card (client → server).
pub const CMD_INSERT_SMART_CARD: CommandId = CommandId(0x01);
/// Extract Smart Card (client → server).
pub const CMD_EXTRACT_SMART_CARD: CommandId = CommandId(0x02);

/// ISO 7816 Protocol Tunnel cluster definition.
pub const ISO7816_TUNNEL_DEF: ClusterDef = ClusterDef {
    id: ISO7816_TUNNEL,
    revision: 1,
    received: &[
        CMD_TRANSFER_APDU,
        CMD_INSERT_SMART_CARD,
        CMD_EXTRACT_SMART_CARD,
    ],
    generated: &[CMD_TRANSFER_APDU],
};

/// Transfer APDU (§9.5.5.3.1): an ISO 7816 APDU as an octet string.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransferApdu<'a> {
    /// The APDU.
    pub apdu: &'a [u8],
}

impl<'a> TransferApdu<'a> {
    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(TransferApdu {
            apdu: read_octets(&mut r)?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        write_octets(w, self.apdu)
    }
}

/// Builds an ISO 7816 Tunnel server, FREE.
pub fn iso7816_tunnel_server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(ISO7816_TUNNEL_DEF, Role::Server);
    c.add_attribute(
        ISO7816_STATUS,
        &Value::Uint {
            width: 1,
            value: u64::from(ISO7816_FREE),
        },
    )?;
    Ok(c)
}

/// Builds an ISO 7816 Tunnel client.
pub fn iso7816_tunnel_client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(ISO7816_TUNNEL_DEF.mirrored(), Role::Client)
}

/// Whether the ISO 7816 server is BUSY (a card inserted).
pub fn iso7816_busy<const A: usize>(c: &ClusterInstance<A>) -> bool {
    c.u8(ISO7816_STATUS.id) == Some(ISO7816_BUSY)
}

/// Insert Smart Card at the server (§9.5.5.3.2.3): BUSY is a FAILURE,
/// FREE becomes BUSY with SUCCESS.
pub fn iso7816_insert<const A: usize>(c: &mut ClusterInstance<A>) -> ZclStatus {
    if iso7816_busy(c) {
        return ZclStatus::Failure;
    }
    c.set_u8(ISO7816_STATUS.id, ISO7816_BUSY);
    ZclStatus::Success
}

/// Extract Smart Card at the server (§9.5.5.3.3.3): FREE is a FAILURE,
/// BUSY becomes FREE with SUCCESS.
pub fn iso7816_extract<const A: usize>(c: &mut ClusterInstance<A>) -> ZclStatus {
    if !iso7816_busy(c) {
        return ZclStatus::Failure;
    }
    c.set_u8(ISO7816_STATUS.id, ISO7816_FREE);
    ZclStatus::Success
}

/// Longest protocol address (`ProtocolAddress` is an octet string of
/// up to 255 octets; a BACnet device identifier is three).
pub const MAX_PROTOCOL_ADDRESS: usize = 32;

/// `MaximumIncomingTransferSize` (uint16 octets).
pub const MAXIMUM_INCOMING_TRANSFER_SIZE: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
/// `MaximumOutgoingTransferSize` (uint16 octets).
pub const MAXIMUM_OUTGOING_TRANSFER_SIZE: AttributeDef =
    AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
/// `ProtocolAddress` (octstr).
pub const PROTOCOL_ADDRESS: AttributeDef =
    AttributeDef::new(0x0003, DataType::OctetString, Access::RW);

/// The `ProtocolAddress` of a BACnet device not yet commissioned
/// (§9.3.2.1).
pub const BACNET_UNCOMMISSIONED: [u8; 3] = [0x3F, 0xFF, 0xFF];
/// The transfer sizes a BACnet tunnel's Generic Tunnel needs at least
/// (§9.3.2.1).
pub const BACNET_MIN_TRANSFER_SIZE: u16 = 504;

/// Match Protocol Address (client → Generic Tunnel server).
pub const CMD_MATCH_PROTOCOL_ADDRESS: CommandId = CommandId(0x00);
/// Match Protocol Address Response (server → client).
pub const CMD_MATCH_PROTOCOL_ADDRESS_RESPONSE: CommandId = CommandId(0x00);
/// Advertise Protocol Address (server → client).
pub const CMD_ADVERTISE_PROTOCOL_ADDRESS: CommandId = CommandId(0x01);
/// Transfer NPDU (client → BACnet Protocol Tunnel server).
pub const CMD_TRANSFER_NPDU: CommandId = CommandId(0x00);

/// Generic Tunnel cluster definition.
pub const GENERIC_TUNNEL_DEF: ClusterDef = ClusterDef {
    id: GENERIC_TUNNEL,
    revision: 1,
    received: &[CMD_MATCH_PROTOCOL_ADDRESS],
    generated: &[
        CMD_MATCH_PROTOCOL_ADDRESS_RESPONSE,
        CMD_ADVERTISE_PROTOCOL_ADDRESS,
    ],
};

/// BACnet Protocol Tunnel cluster definition.
pub const BACNET_PROTOCOL_TUNNEL_DEF: ClusterDef = ClusterDef {
    id: BACNET_PROTOCOL_TUNNEL,
    revision: 1,
    received: &[CMD_TRANSFER_NPDU],
    generated: &[],
};

/// Match Protocol Address Response (§9.2.2.4.1).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MatchProtocolAddressResponse<'a> {
    /// The responding device.
    pub device: ExtendedAddress,
    /// The matched protocol address.
    pub protocol_address: &'a [u8],
}

impl<'a> MatchProtocolAddressResponse<'a> {
    /// Parses the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let device = ExtendedAddress(r.u64_le()?);
        let protocol_address = read_octets(&mut r)?;
        Ok(MatchProtocolAddressResponse {
            device,
            protocol_address,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.device.0)?;
        write_octets(w, self.protocol_address)
    }
}

/// The octet-string payload of Match Protocol Address and Advertise
/// Protocol Address (a length-prefixed protocol address).
pub fn parse_protocol_address(payload: &[u8]) -> Result<&[u8], CodecError> {
    let mut r = Reader::new(payload);
    read_octets(&mut r)
}

/// Encodes a protocol address payload.
pub fn encode_protocol_address(address: &[u8], w: &mut Writer<'_>) -> Result<(), CodecError> {
    write_octets(w, address)
}

fn read_octets<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let n = r.u8()?;
    if n == 0xFF {
        return Err(CodecError::InvalidField {
            field: "protocol address",
            value: 0xFF,
        });
    }
    r.bytes(usize::from(n))
}

fn write_octets(w: &mut Writer<'_>, bytes: &[u8]) -> Result<(), CodecError> {
    let n = u8::try_from(bytes.len())
        .ok()
        .filter(|n| *n != 0xFF)
        .ok_or(CodecError::Unrepresentable {
            field: "protocol address",
        })?;
    w.u8(n)?;
    w.bytes(bytes)
}

/// Transfer NPDU (§9.3.2.3.1): the BACnet NPDU as a sequence of octets
/// filling the payload.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransferNpdu<'a> {
    /// The NPDU.
    pub npdu: &'a [u8],
}

impl<'a> TransferNpdu<'a> {
    /// Parses the payload.
    pub const fn parse(payload: &'a [u8]) -> Self {
        TransferNpdu { npdu: payload }
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.bytes(self.npdu)
    }
}

/// Builds a Generic Tunnel server with the transfer sizes and protocol
/// address given.
pub fn generic_tunnel_server<const A: usize>(
    incoming: u16,
    outgoing: u16,
    protocol_address: &[u8],
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(GENERIC_TUNNEL_DEF, Role::Server);
    c.add_attribute(
        MAXIMUM_INCOMING_TRANSFER_SIZE,
        &Value::Uint {
            width: 2,
            value: u64::from(incoming),
        },
    )?;
    c.add_attribute(
        MAXIMUM_OUTGOING_TRANSFER_SIZE,
        &Value::Uint {
            width: 2,
            value: u64::from(outgoing),
        },
    )?;
    c.add_attribute(
        PROTOCOL_ADDRESS,
        &Value::String {
            ty: DataType::OctetString,
            bytes: Some(protocol_address),
        },
    )?;
    Ok(c)
}

/// Builds a Generic Tunnel client.
pub fn generic_tunnel_client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(GENERIC_TUNNEL_DEF.mirrored(), Role::Client)
}

/// Builds a BACnet Protocol Tunnel server (the Generic Tunnel server
/// beside it carries the device identifier as its protocol address,
/// §9.3.2.1).
pub fn bacnet_tunnel_server<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(BACNET_PROTOCOL_TUNNEL_DEF, Role::Server)
}

/// Builds a BACnet Protocol Tunnel client.
pub fn bacnet_tunnel_client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(BACNET_PROTOCOL_TUNNEL_DEF.mirrored(), Role::Client)
}

/// The server's `ProtocolAddress`, copied out (empty when unset).
pub fn protocol_address<const A: usize>(
    c: &ClusterInstance<A>,
) -> heapless::Vec<u8, MAX_PROTOCOL_ADDRESS> {
    let mut out = heapless::Vec::new();
    if let Some(Value::String { bytes: Some(b), .. }) = c.attributes.value(PROTOCOL_ADDRESS.id) {
        let _ = out.extend_from_slice(b);
    }
    out
}

/// Sets the server's `ProtocolAddress`; the application advertises it
/// afterwards (§9.2.2.4.4). Returns whether it changed.
pub fn set_protocol_address<const A: usize>(c: &mut ClusterInstance<A>, address: &[u8]) -> bool {
    c.set(
        PROTOCOL_ADDRESS.id,
        &Value::String {
            ty: DataType::OctetString,
            bytes: Some(address),
        },
    )
}

/// A Match Protocol Address at the server (§9.2.2.3.3): the response
/// when the address equals `ProtocolAddress`, otherwise nothing.
pub fn handle_match<const A: usize>(
    c: &ClusterInstance<A>,
    device: ExtendedAddress,
    payload: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CodecError> {
    let asked = parse_protocol_address(payload)?;
    let mine = protocol_address(c);
    if mine.as_slice() != asked || asked.is_empty() {
        return Ok(None);
    }
    let mut w = Writer::new(out);
    MatchProtocolAddressResponse {
        device,
        protocol_address: asked,
    }
    .encode(&mut w)?;
    Ok(Some(w.position()))
}

/// The Advertise Protocol Address payload of the server (§9.2.2.4.3).
pub fn advertise<const A: usize>(
    c: &ClusterInstance<A>,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let mine = protocol_address(c);
    let mut w = Writer::new(out);
    write_octets(&mut w, &mine)?;
    Ok(w.position())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generic_tunnel_matches_and_advertises_its_address() {
        let mut c: ClusterInstance<8> =
            generic_tunnel_server(504, 504, &BACNET_UNCOMMISSIONED).unwrap();
        assert_eq!(protocol_address(&c).as_slice(), &BACNET_UNCOMMISSIONED);
        assert!(set_protocol_address(&mut c, &[0x00, 0x00, 0x2A]));
        assert!(!set_protocol_address(&mut c, &[0x00, 0x00, 0x2A]));
        let device = ExtendedAddress(0x00DD_0000_0000_0001);
        let mut out = [0u8; 32];
        // The wrong address: nothing; the right one: the response.
        let mut req = [0u8; 8];
        let mut w = Writer::new(&mut req);
        encode_protocol_address(&[0x00, 0x00, 0x2B], &mut w).unwrap();
        let n = w.position();
        assert_eq!(handle_match(&c, device, &req[..n], &mut out).unwrap(), None);
        let mut w = Writer::new(&mut req);
        encode_protocol_address(&[0x00, 0x00, 0x2A], &mut w).unwrap();
        let n = w.position();
        let m = handle_match(&c, device, &req[..n], &mut out)
            .unwrap()
            .unwrap();
        let r = MatchProtocolAddressResponse::parse(&out[..m]).unwrap();
        assert_eq!(
            (r.device, r.protocol_address),
            (device, &[0x00, 0x00, 0x2A][..])
        );
        assert_eq!(m, 8 + 1 + 3);
        // An empty request never matches; an invalid string is an error.
        assert_eq!(handle_match(&c, device, &[0], &mut out).unwrap(), None);
        assert!(handle_match(&c, device, &[0xFF], &mut out).is_err());
        // Advertise carries the attribute.
        let a = advertise(&c, &mut out).unwrap();
        assert_eq!(&out[..a], &[3, 0x00, 0x00, 0x2A]);
        assert_eq!(
            parse_protocol_address(&out[..a]).unwrap(),
            &[0x00, 0x00, 0x2A]
        );
        // The BACnet tunnel carries the NPDU as is.
        let t = TransferNpdu::parse(&[0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF]);
        let mut w = Writer::new(&mut out);
        t.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(&out[..n], &[0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF]);
        let s: ClusterInstance<4> = bacnet_tunnel_server();
        assert_eq!(s.def.id, BACNET_PROTOCOL_TUNNEL);
        let gc: ClusterInstance<4> = generic_tunnel_client();
        assert_eq!(gc.role, Role::Client);
        let bc: ClusterInstance<4> = bacnet_tunnel_client();
        assert_eq!(bc.role, Role::Client);
    }

    #[test]
    fn the_iso7816_tunnel_takes_one_card_at_a_time() {
        let mut c: ClusterInstance<4> = iso7816_tunnel_server().unwrap();
        assert!(!iso7816_busy(&c));
        assert_eq!(iso7816_extract(&mut c), ZclStatus::Failure);
        assert_eq!(iso7816_insert(&mut c), ZclStatus::Success);
        assert!(iso7816_busy(&c));
        assert_eq!(iso7816_insert(&mut c), ZclStatus::Failure);
        assert_eq!(iso7816_extract(&mut c), ZclStatus::Success);
        assert!(!iso7816_busy(&c));
        let a = TransferApdu {
            apdu: &[0x00, 0xA4, 0x04, 0x00],
        };
        let mut out = [0u8; 8];
        let mut w = Writer::new(&mut out);
        a.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(&out[..n], &[4, 0x00, 0xA4, 0x04, 0x00]);
        assert_eq!(TransferApdu::parse(&out[..n]).unwrap(), a);
        let ic: ClusterInstance<4> = iso7816_tunnel_client();
        assert_eq!(ic.role, Role::Client);
    }
}
