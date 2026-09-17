//! Tunneling cluster (SE 1.4a Annex D.6): the command codecs
//! (RequestTunnel / Response, CloseTunnel, TransferData,
//! TransferDataError, AckTransferData, ReadyData, Get Supported Tunnel
//! Protocols / Response, TunnelClosureNotification) and a server-side
//! tunnel table [`Server`] that allocates identifiers, binds each tunnel
//! to its requesting device, enforces the transfer size and the
//! `CloseTunnelTimeout` inactivity rule, and answers the client
//! commands. Flow control (`AckTransferData` / `ReadyData`) is tracked
//! per tunnel when negotiated; the data itself is the application's.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId, Endpoint, ShortAddress};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::cluster::ClusterDef;
use panweave_zcl::types::DataType;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0704);

/// `CloseTunnelTimeout` (uint16 seconds, read only, default 0xffff).
pub const CLOSE_TUNNEL_TIMEOUT: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(2), Access::RO);

/// Client → server: RequestTunnel.
pub const CMD_REQUEST_TUNNEL: CommandId = CommandId(0x00);
/// Client → server: CloseTunnel.
pub const CMD_CLOSE_TUNNEL: CommandId = CommandId(0x01);
/// Client → server: TransferData.
pub const CMD_TRANSFER_DATA: CommandId = CommandId(0x02);
/// Client → server: TransferDataError.
pub const CMD_TRANSFER_DATA_ERROR: CommandId = CommandId(0x03);
/// Client → server: AckTransferData.
pub const CMD_ACK_TRANSFER_DATA: CommandId = CommandId(0x04);
/// Client → server: ReadyData.
pub const CMD_READY_DATA: CommandId = CommandId(0x05);
/// Client → server: Get Supported Tunnel Protocols.
pub const CMD_GET_SUPPORTED_TUNNEL_PROTOCOLS: CommandId = CommandId(0x06);

/// Server → client: RequestTunnelResponse.
pub const CMD_REQUEST_TUNNEL_RESPONSE: CommandId = CommandId(0x00);
/// Server → client: TransferData.
pub const CMD_SERVER_TRANSFER_DATA: CommandId = CommandId(0x01);
/// Server → client: TransferDataError.
pub const CMD_SERVER_TRANSFER_DATA_ERROR: CommandId = CommandId(0x02);
/// Server → client: AckTransferData.
pub const CMD_SERVER_ACK_TRANSFER_DATA: CommandId = CommandId(0x03);
/// Server → client: ReadyData.
pub const CMD_SERVER_READY_DATA: CommandId = CommandId(0x04);
/// Server → client: Supported Tunnel Protocols Response.
pub const CMD_SUPPORTED_TUNNEL_PROTOCOLS_RESPONSE: CommandId = CommandId(0x05);
/// Server → client: TunnelClosureNotification.
pub const CMD_TUNNEL_CLOSURE_NOTIFICATION: CommandId = CommandId(0x06);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_REQUEST_TUNNEL,
        CMD_CLOSE_TUNNEL,
        CMD_TRANSFER_DATA,
        CMD_TRANSFER_DATA_ERROR,
        CMD_ACK_TRANSFER_DATA,
        CMD_READY_DATA,
        CMD_GET_SUPPORTED_TUNNEL_PROTOCOLS,
    ],
    generated: &[
        CMD_REQUEST_TUNNEL_RESPONSE,
        CMD_SERVER_TRANSFER_DATA,
        CMD_SERVER_TRANSFER_DATA_ERROR,
        CMD_SERVER_ACK_TRANSFER_DATA,
        CMD_SERVER_READY_DATA,
        CMD_SUPPORTED_TUNNEL_PROTOCOLS_RESPONSE,
        CMD_TUNNEL_CLOSURE_NOTIFICATION,
    ],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

/// ProtocolID values (Table D-124).
pub mod protocol {
    /// DLMS/COSEM (IEC 62056).
    pub const DLMS_COSEM: u8 = 0;
    /// IEC 61107.
    pub const IEC_61107: u8 = 1;
    /// ANSI C12.
    pub const ANSI_C12: u8 = 2;
    /// M-Bus.
    pub const M_BUS: u8 = 3;
    /// SML.
    pub const SML: u8 = 4;
    /// ClimateTalk.
    pub const CLIMATE_TALK: u8 = 5;
    /// GB-HRGP.
    pub const GB_HRGP: u8 = 6;
    /// IPv4.
    pub const IPV4: u8 = 7;
    /// IPv6.
    pub const IPV6: u8 = 8;
    /// First manufacturer-defined protocol.
    pub const MANUFACTURER_FIRST: u8 = 200;
    /// Last manufacturer-defined protocol.
    pub const MANUFACTURER_LAST: u8 = 254;
    /// Manufacturer code of a standard protocol.
    pub const NO_MANUFACTURER: u16 = 0xffff;
}

/// TunnelStatus values (Table D-127).
pub mod tunnel_status {
    /// Success.
    pub const SUCCESS: u8 = 0x00;
    /// Busy.
    pub const BUSY: u8 = 0x01;
    /// No more tunnel identifiers.
    pub const NO_MORE_TUNNEL_IDS: u8 = 0x02;
    /// Protocol not supported.
    pub const PROTOCOL_NOT_SUPPORTED: u8 = 0x03;
    /// Flow control not supported.
    pub const FLOW_CONTROL_NOT_SUPPORTED: u8 = 0x04;
}

/// TransferDataStatus values (Table D-125).
pub mod transfer_status {
    /// No such tunnel.
    pub const NO_SUCH_TUNNEL: u8 = 0x00;
    /// Wrong device.
    pub const WRONG_DEVICE: u8 = 0x01;
    /// Data overflow.
    pub const DATA_OVERFLOW: u8 = 0x02;
}

/// Invalid tunnel identifier (returned on failure).
pub const NO_TUNNEL: u16 = 0xffff;
/// Default `MaximumIncomingTransferSize`.
pub const DEFAULT_MAX_TRANSFER: u16 = 1500;

/// RequestTunnel (D.6.2.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RequestTunnel {
    /// Protocol identifier.
    pub protocol: u8,
    /// Manufacturer code (ignored below protocol 200; 0xffff none).
    pub manufacturer: u16,
    /// Flow control requested.
    pub flow_control: bool,
    /// The client's maximum incoming transfer size.
    pub max_incoming: u16,
}

impl RequestTunnel {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(RequestTunnel {
            protocol: r.u8()?,
            manufacturer: r.u16_le()?,
            flow_control: r.u8()? != 0,
            max_incoming: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.protocol)?;
        w.u16_le(self.manufacturer)?;
        w.u8(u8::from(self.flow_control))?;
        w.u16_le(self.max_incoming)
    }
}

/// RequestTunnelResponse (D.6.2.5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RequestTunnelResponse {
    /// Tunnel identifier ([`NO_TUNNEL`] on failure).
    pub tunnel: u16,
    /// Status (Table D-127).
    pub status: u8,
    /// The server's maximum incoming transfer size.
    pub max_incoming: u16,
}

impl RequestTunnelResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(RequestTunnelResponse {
            tunnel: r.u16_le()?,
            status: r.u8()?,
            max_incoming: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.tunnel)?;
        w.u8(self.status)?;
        w.u16_le(self.max_incoming)
    }
}

/// TransferData in either direction (D.6.2.4.3 / D.6.2.5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransferData<'a> {
    /// Tunnel identifier.
    pub tunnel: u16,
    /// Protocol data.
    pub data: &'a [u8],
}

impl<'a> TransferData<'a> {
    /// Parses the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(TransferData {
            tunnel: r.u16_le()?,
            data: r.take_rest(),
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.tunnel)?;
        w.bytes(self.data)
    }
}

/// TransferDataError (D.6.2.4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransferDataError {
    /// Tunnel identifier.
    pub tunnel: u16,
    /// Status (Table D-125).
    pub status: u8,
}

impl TransferDataError {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(TransferDataError {
            tunnel: r.u16_le()?,
            status: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.tunnel)?;
        w.u8(self.status)
    }
}

/// AckTransferData / ReadyData (D.6.2.4.5 / .6): a tunnel and a number
/// of octets the receiver can take.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FlowControl {
    /// Tunnel identifier.
    pub tunnel: u16,
    /// Octets the receiver can still accept (0: stop).
    pub octets_left: u16,
}

impl FlowControl {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(FlowControl {
            tunnel: r.u16_le()?,
            octets_left: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.tunnel)?;
        w.u16_le(self.octets_left)
    }
}

/// Reads a tunnel-identifier-only payload (CloseTunnel,
/// TunnelClosureNotification).
pub fn parse_tunnel_id(bytes: &[u8]) -> Result<u16, CodecError> {
    Reader::new(bytes).u16_le()
}

/// A supported protocol (Figure D-112).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Protocol {
    /// Manufacturer code (0xffff for standard protocols).
    pub manufacturer: u16,
    /// Protocol identifier.
    pub protocol: u8,
}

impl Protocol {
    /// A standard protocol.
    pub const fn standard(protocol: u8) -> Protocol {
        Protocol {
            manufacturer: protocol::NO_MANUFACTURER,
            protocol,
        }
    }

    /// Whether a request matches this protocol (the manufacturer code
    /// is ignored for standard protocols).
    pub const fn matches(&self, request: &RequestTunnel) -> bool {
        self.protocol == request.protocol
            && (request.protocol < protocol::MANUFACTURER_FIRST
                || self.manufacturer == request.manufacturer)
    }
}

/// Protocols per Supported Tunnel Protocols Response (D.6.2.5.6).
pub const MAX_PROTOCOLS_PER_RESPONSE: usize = 16;

/// Supported Tunnel Protocols Response (D.6.2.5.6).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedProtocols {
    /// The list is complete.
    pub complete: bool,
    /// Protocols.
    pub protocols: Vec<Protocol, MAX_PROTOCOLS_PER_RESPONSE>,
}

impl SupportedProtocols {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let complete = r.u8()? != 0;
        let n = r.u8()?;
        let mut protocols = Vec::new();
        for _ in 0..n {
            let p = Protocol {
                manufacturer: r.u16_le()?,
                protocol: r.u8()?,
            };
            protocols.push(p).map_err(|_| CodecError::Unrepresentable {
                field: "protocol count",
            })?;
        }
        Ok(SupportedProtocols {
            complete,
            protocols,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(u8::from(self.complete))?;
        w.u8(u8::try_from(self.protocols.len()).unwrap_or(0))?;
        for p in &self.protocols {
            w.u16_le(p.manufacturer)?;
            w.u8(p.protocol)?;
        }
        Ok(())
    }
}

/// The requesting device of a tunnel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Peer {
    /// Network address.
    pub address: ShortAddress,
    /// Endpoint.
    pub endpoint: Endpoint,
}

/// An open tunnel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Tunnel {
    /// Identifier.
    pub id: u16,
    /// The client.
    pub peer: Peer,
    /// Protocol.
    pub protocol: Protocol,
    /// Flow control in use.
    pub flow_control: bool,
    /// Octets the client can currently take (flow control), or its
    /// maximum incoming transfer size.
    pub peer_window: u16,
    /// Seconds since the last activity.
    pub idle_secs: u16,
}

/// A frame the server sends.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reply {
    /// Command (server → client).
    pub command: CommandId,
    /// Payload.
    pub payload: Vec<u8, 56>,
}

fn reply(
    command: CommandId,
    build: impl FnOnce(&mut Writer<'_>) -> Result<(), CodecError>,
) -> Option<Reply> {
    let mut buf = [0u8; 56];
    let mut w = Writer::new(&mut buf);
    build(&mut w).ok()?;
    let n = w.position();
    Some(Reply {
        command,
        payload: Vec::from_slice(buf.get(..n)?).ok()?,
    })
}

/// What a received client command produced.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome<'a> {
    /// Send this reply to the requester.
    Reply(Reply),
    /// Protocol data arrived on `tunnel` (the reply, if any, is the
    /// flow-control acknowledgement).
    Data {
        /// Tunnel identifier.
        tunnel: u16,
        /// The data.
        data: &'a [u8],
        /// Acknowledgement to send when flow control is on.
        ack: Option<Reply>,
    },
    /// The client reported a transfer error on `tunnel`.
    Error {
        /// Tunnel identifier.
        tunnel: u16,
        /// Status.
        status: u8,
    },
    /// The client updated its window on `tunnel` (AckTransferData or
    /// ReadyData); `octets_left` 0 means stop sending.
    Window {
        /// Tunnel identifier.
        tunnel: u16,
        /// Octets the client can take.
        octets_left: u16,
    },
    /// A tunnel was closed by the client.
    Closed(u16),
    /// A Default Response with this ZCL status (as raw octet).
    Default(u8),
}

/// ZCL NOT_FOUND.
const ZCL_NOT_FOUND: u8 = 0x8b;
/// ZCL MALFORMED_COMMAND.
const ZCL_MALFORMED: u8 = 0x80;
/// ZCL UNSUP_CLUSTER_COMMAND.
const ZCL_UNSUPPORTED: u8 = 0x81;
/// ZCL SUCCESS.
const ZCL_SUCCESS: u8 = 0x00;

/// The server-side tunnel table.
#[derive(Clone, Debug)]
pub struct Server<const N: usize> {
    /// Supported protocols.
    pub protocols: Vec<Protocol, MAX_PROTOCOLS_PER_RESPONSE>,
    /// Whether flow control can be provided.
    pub flow_control: bool,
    /// Own maximum incoming transfer size.
    pub max_incoming: u16,
    /// `CloseTunnelTimeout` in seconds.
    pub close_timeout: u16,
    tunnels: Vec<Tunnel, N>,
    next_id: u16,
}

impl<const N: usize> Server<N> {
    /// A server for `protocols` with `close_timeout` seconds of
    /// inactivity tolerance.
    pub fn new(protocols: &[Protocol], flow_control: bool, close_timeout: u16) -> Self {
        Server {
            protocols: Vec::from_slice(protocols).unwrap_or_default(),
            flow_control,
            max_incoming: DEFAULT_MAX_TRANSFER,
            close_timeout: close_timeout.max(1),
            tunnels: Vec::new(),
            next_id: 0,
        }
    }

    /// The open tunnels.
    pub fn tunnels(&self) -> &[Tunnel] {
        &self.tunnels
    }

    /// The tunnel with `id`.
    pub fn tunnel(&self, id: u16) -> Option<&Tunnel> {
        self.tunnels.iter().find(|t| t.id == id)
    }

    fn allocate_id(&mut self) -> Option<u16> {
        for _ in 0..=u16::MAX {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if id != NO_TUNNEL && self.tunnel(id).is_none() {
                return Some(id);
            }
        }
        None
    }

    /// Handles a client command from `peer`.
    pub fn handle<'a>(&mut self, peer: Peer, command: CommandId, payload: &'a [u8]) -> Outcome<'a> {
        match command {
            CMD_REQUEST_TUNNEL => {
                let Ok(req) = RequestTunnel::parse(payload) else {
                    return Outcome::Default(ZCL_MALFORMED);
                };
                let status = if !self.protocols.iter().any(|p| p.matches(&req)) {
                    tunnel_status::PROTOCOL_NOT_SUPPORTED
                } else if req.flow_control && !self.flow_control {
                    tunnel_status::FLOW_CONTROL_NOT_SUPPORTED
                } else if self.tunnels.is_full() {
                    tunnel_status::NO_MORE_TUNNEL_IDS
                } else {
                    tunnel_status::SUCCESS
                };
                let mut id = NO_TUNNEL;
                if status == tunnel_status::SUCCESS {
                    match self.allocate_id() {
                        Some(new) => {
                            id = new;
                            let t = Tunnel {
                                id,
                                peer,
                                protocol: Protocol {
                                    manufacturer: req.manufacturer,
                                    protocol: req.protocol,
                                },
                                flow_control: req.flow_control,
                                peer_window: req.max_incoming,
                                idle_secs: 0,
                            };
                            let _ = self.tunnels.push(t);
                        }
                        None => {
                            return self
                                .request_reply(NO_TUNNEL, tunnel_status::NO_MORE_TUNNEL_IDS);
                        }
                    }
                }
                self.request_reply(id, status)
            }
            CMD_CLOSE_TUNNEL => {
                let Ok(id) = parse_tunnel_id(payload) else {
                    return Outcome::Default(ZCL_MALFORMED);
                };
                match self
                    .tunnels
                    .iter()
                    .position(|t| t.id == id && t.peer == peer)
                {
                    Some(i) => {
                        self.tunnels.swap_remove(i);
                        Outcome::Closed(id)
                    }
                    None => Outcome::Default(ZCL_NOT_FOUND),
                }
            }
            CMD_TRANSFER_DATA => {
                let Ok(td) = TransferData::parse(payload) else {
                    return Outcome::Default(ZCL_MALFORMED);
                };
                let max = usize::from(self.max_incoming);
                let Some(t) = self.tunnels.iter_mut().find(|t| t.id == td.tunnel) else {
                    return Outcome::Reply(transfer_error(
                        td.tunnel,
                        transfer_status::NO_SUCH_TUNNEL,
                    ));
                };
                if t.peer != peer {
                    return Outcome::Reply(transfer_error(
                        td.tunnel,
                        transfer_status::WRONG_DEVICE,
                    ));
                }
                if td.data.len() > max {
                    return Outcome::Reply(transfer_error(
                        td.tunnel,
                        transfer_status::DATA_OVERFLOW,
                    ));
                }
                t.idle_secs = 0;
                let ack = t.flow_control.then(|| {
                    reply(CMD_SERVER_ACK_TRANSFER_DATA, |w| {
                        FlowControl {
                            tunnel: td.tunnel,
                            octets_left: self.max_incoming,
                        }
                        .encode(w)
                    })
                });
                Outcome::Data {
                    tunnel: td.tunnel,
                    data: td.data,
                    ack: ack.flatten(),
                }
            }
            CMD_TRANSFER_DATA_ERROR => {
                let Ok(e) = TransferDataError::parse(payload) else {
                    return Outcome::Default(ZCL_MALFORMED);
                };
                Outcome::Error {
                    tunnel: e.tunnel,
                    status: e.status,
                }
            }
            CMD_ACK_TRANSFER_DATA | CMD_READY_DATA => {
                let Ok(f) = FlowControl::parse(payload) else {
                    return Outcome::Default(ZCL_MALFORMED);
                };
                let Some(t) = self
                    .tunnels
                    .iter_mut()
                    .find(|t| t.id == f.tunnel && t.peer == peer)
                else {
                    return Outcome::Default(ZCL_NOT_FOUND);
                };
                t.idle_secs = 0;
                t.peer_window = f.octets_left;
                Outcome::Window {
                    tunnel: f.tunnel,
                    octets_left: f.octets_left,
                }
            }
            CMD_GET_SUPPORTED_TUNNEL_PROTOCOLS => {
                let offset = usize::from(payload.first().copied().unwrap_or(0));
                let rest = self.protocols.iter().skip(offset);
                let mut protocols = Vec::new();
                for p in rest {
                    if protocols.push(*p).is_err() {
                        break;
                    }
                }
                let complete = offset + protocols.len() >= self.protocols.len();
                let list = SupportedProtocols {
                    complete,
                    protocols,
                };
                match reply(CMD_SUPPORTED_TUNNEL_PROTOCOLS_RESPONSE, |w| list.encode(w)) {
                    Some(r) => Outcome::Reply(r),
                    None => Outcome::Default(ZCL_SUCCESS),
                }
            }
            _ => Outcome::Default(ZCL_UNSUPPORTED),
        }
    }

    fn request_reply(&self, id: u16, status: u8) -> Outcome<'static> {
        let max = self.max_incoming;
        match reply(CMD_REQUEST_TUNNEL_RESPONSE, |w| {
            RequestTunnelResponse {
                tunnel: id,
                status,
                max_incoming: max,
            }
            .encode(w)
        }) {
            Some(r) => Outcome::Reply(r),
            None => Outcome::Default(ZCL_SUCCESS),
        }
    }

    /// Builds a TransferData towards the client of `id`, refusing data
    /// beyond its window; `None` for an unknown tunnel or too much data.
    pub fn transfer(&mut self, id: u16, data: &[u8]) -> Option<(Peer, Reply)> {
        let t = self.tunnels.iter_mut().find(|t| t.id == id)?;
        if data.len() > usize::from(t.peer_window) {
            return None;
        }
        t.idle_secs = 0;
        let peer = t.peer;
        let r = reply(CMD_SERVER_TRANSFER_DATA, |w| {
            TransferData { tunnel: id, data }.encode(w)
        })?;
        Some((peer, r))
    }

    /// One second passed: closes tunnels idle for `CloseTunnelTimeout`
    /// and returns their closure notifications with the peers to notify.
    pub fn tick_second(&mut self, out: &mut Vec<(Peer, Reply), N>) {
        let timeout = self.close_timeout;
        let mut i = 0;
        while i < self.tunnels.len() {
            let Some(t) = self.tunnels.get_mut(i) else {
                break;
            };
            t.idle_secs = t.idle_secs.saturating_add(1);
            if t.idle_secs >= timeout {
                let (id, peer) = (t.id, t.peer);
                self.tunnels.swap_remove(i);
                if let Some(r) = reply(CMD_TUNNEL_CLOSURE_NOTIFICATION, |w| w.u16_le(id)) {
                    let _ = out.push((peer, r));
                }
            } else {
                i += 1;
            }
        }
    }
}

fn transfer_error(tunnel: u16, status: u8) -> Reply {
    reply(CMD_SERVER_TRANSFER_DATA_ERROR, |w| {
        TransferDataError { tunnel, status }.encode(w)
    })
    .unwrap_or(Reply {
        command: CMD_SERVER_TRANSFER_DATA_ERROR,
        payload: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: Peer = Peer {
        address: ShortAddress(0x1234),
        endpoint: Endpoint(1),
    };
    const OTHER: Peer = Peer {
        address: ShortAddress(0x5678),
        endpoint: Endpoint(1),
    };

    fn request(protocol: u8, flow: bool) -> [u8; 6] {
        let mut buf = [0u8; 6];
        let mut w = Writer::new(&mut buf);
        RequestTunnel {
            protocol,
            manufacturer: protocol::NO_MANUFACTURER,
            flow_control: flow,
            max_incoming: 100,
        }
        .encode(&mut w)
        .unwrap();
        buf
    }

    fn open(s: &mut Server<2>, peer: Peer) -> u16 {
        let req = request(protocol::DLMS_COSEM, false);
        let o = s.handle(peer, CMD_REQUEST_TUNNEL, &req);
        let Outcome::Reply(r) = o else {
            panic!("{o:?}")
        };
        let rsp = RequestTunnelResponse::parse(&r.payload).unwrap();
        assert_eq!(rsp.status, tunnel_status::SUCCESS);
        rsp.tunnel
    }

    #[test]
    fn request_close_and_status_codes() {
        let mut s: Server<2> = Server::new(&[Protocol::standard(protocol::DLMS_COSEM)], false, 30);
        let id = open(&mut s, PEER);
        assert_eq!(s.tunnel(id).unwrap().peer, PEER);
        // Unsupported protocol, flow control, table full.
        let req = request(protocol::M_BUS, false);
        let o = s.handle(PEER, CMD_REQUEST_TUNNEL, &req);
        let Outcome::Reply(r) = o else { panic!() };
        let rsp = RequestTunnelResponse::parse(&r.payload).unwrap();
        assert_eq!(
            (rsp.status, rsp.tunnel),
            (tunnel_status::PROTOCOL_NOT_SUPPORTED, NO_TUNNEL)
        );
        let req = request(protocol::DLMS_COSEM, true);
        let o = s.handle(PEER, CMD_REQUEST_TUNNEL, &req);
        let Outcome::Reply(r) = o else { panic!() };
        assert_eq!(
            RequestTunnelResponse::parse(&r.payload).unwrap().status,
            tunnel_status::FLOW_CONTROL_NOT_SUPPORTED
        );
        let _ = open(&mut s, OTHER);
        let req = request(protocol::DLMS_COSEM, false);
        let o = s.handle(PEER, CMD_REQUEST_TUNNEL, &req);
        let Outcome::Reply(r) = o else { panic!() };
        assert_eq!(
            RequestTunnelResponse::parse(&r.payload).unwrap().status,
            tunnel_status::NO_MORE_TUNNEL_IDS
        );
        // Close: only the owner may, unknown is NOT_FOUND.
        assert_eq!(
            s.handle(OTHER, CMD_CLOSE_TUNNEL, &id.to_le_bytes()),
            Outcome::Default(ZCL_NOT_FOUND)
        );
        assert_eq!(
            s.handle(PEER, CMD_CLOSE_TUNNEL, &id.to_le_bytes()),
            Outcome::Closed(id)
        );
        assert_eq!(
            s.handle(PEER, CMD_CLOSE_TUNNEL, &id.to_le_bytes()),
            Outcome::Default(ZCL_NOT_FOUND)
        );
        assert_eq!(s.tunnels().len(), 1);
    }

    #[test]
    fn data_transfer_errors_and_flow_control() {
        let mut s: Server<2> = Server::new(&[Protocol::standard(protocol::IEC_61107)], true, 30);
        s.max_incoming = 8;
        let req = request(protocol::IEC_61107, true);
        let o = s.handle(PEER, CMD_REQUEST_TUNNEL, &req);
        let Outcome::Reply(r) = o else { panic!() };
        let id = RequestTunnelResponse::parse(&r.payload).unwrap().tunnel;
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        TransferData {
            tunnel: id,
            data: b"hello",
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        let o = s.handle(PEER, CMD_TRANSFER_DATA, &buf[..n]);
        let Outcome::Data { tunnel, data, ack } = o else {
            panic!("{o:?}")
        };
        assert_eq!((tunnel, data), (id, &b"hello"[..]));
        let ack = ack.unwrap();
        assert_eq!(ack.command, CMD_SERVER_ACK_TRANSFER_DATA);
        assert_eq!(FlowControl::parse(&ack.payload).unwrap().octets_left, 8);
        // Wrong device, unknown tunnel, overflow.
        let o = s.handle(OTHER, CMD_TRANSFER_DATA, &buf[..n]);
        let Outcome::Reply(r) = o else { panic!() };
        assert_eq!(
            TransferDataError::parse(&r.payload).unwrap().status,
            transfer_status::WRONG_DEVICE
        );
        let mut bad = buf;
        bad[0] ^= 0x55;
        let o = s.handle(PEER, CMD_TRANSFER_DATA, &bad[..n]);
        let Outcome::Reply(r) = o else { panic!() };
        assert_eq!(
            TransferDataError::parse(&r.payload).unwrap().status,
            transfer_status::NO_SUCH_TUNNEL
        );
        let mut w = Writer::new(&mut buf);
        TransferData {
            tunnel: id,
            data: b"0123456789",
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        let o = s.handle(PEER, CMD_TRANSFER_DATA, &buf[..n]);
        let Outcome::Reply(r) = o else { panic!() };
        assert_eq!(
            TransferDataError::parse(&r.payload).unwrap().status,
            transfer_status::DATA_OVERFLOW
        );
        // The client's window governs what the server may send.
        let mut w = Writer::new(&mut buf);
        FlowControl {
            tunnel: id,
            octets_left: 3,
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        assert_eq!(
            s.handle(PEER, CMD_ACK_TRANSFER_DATA, &buf[..n]),
            Outcome::Window {
                tunnel: id,
                octets_left: 3
            }
        );
        assert!(s.transfer(id, b"abcd").is_none());
        let (peer, r) = s.transfer(id, b"abc").unwrap();
        assert_eq!(peer, PEER);
        assert_eq!(r.command, CMD_SERVER_TRANSFER_DATA);
        assert_eq!(TransferData::parse(&r.payload).unwrap().data, b"abc");
        let mut w = Writer::new(&mut buf);
        FlowControl {
            tunnel: id,
            octets_left: 100,
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        assert!(matches!(
            s.handle(PEER, CMD_READY_DATA, &buf[..n]),
            Outcome::Window {
                octets_left: 100,
                ..
            }
        ));
        assert!(s.transfer(id, b"abcd").is_some());
    }

    #[test]
    fn idle_tunnels_close_with_a_notification() {
        let mut s: Server<2> = Server::new(&[Protocol::standard(protocol::SML)], false, 3);
        let req = request(protocol::SML, false);
        let o = s.handle(PEER, CMD_REQUEST_TUNNEL, &req);
        let Outcome::Reply(r) = o else { panic!() };
        let id = RequestTunnelResponse::parse(&r.payload).unwrap().tunnel;
        let mut out = Vec::new();
        s.tick_second(&mut out);
        s.tick_second(&mut out);
        assert!(out.is_empty());
        // Activity restarts the timer.
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        TransferData {
            tunnel: id,
            data: b"x",
        }
        .encode(&mut w)
        .unwrap();
        let n = w.position();
        s.handle(PEER, CMD_TRANSFER_DATA, &buf[..n]);
        s.tick_second(&mut out);
        s.tick_second(&mut out);
        assert!(out.is_empty());
        s.tick_second(&mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, PEER);
        assert_eq!(out[0].1.command, CMD_TUNNEL_CLOSURE_NOTIFICATION);
        assert_eq!(parse_tunnel_id(&out[0].1.payload).unwrap(), id);
        assert!(s.tunnels().is_empty());
    }

    #[test]
    fn supported_protocols_pages() {
        let list: Vec<Protocol, 16> = (0..9).map(Protocol::standard).collect();
        let mut s: Server<2> = Server::new(&list, false, 30);
        let o = s.handle(PEER, CMD_GET_SUPPORTED_TUNNEL_PROTOCOLS, &[0]);
        let Outcome::Reply(r) = o else { panic!() };
        let p = SupportedProtocols::parse(&r.payload).unwrap();
        assert!(p.complete);
        assert_eq!(p.protocols.len(), 9);
        let o = s.handle(PEER, CMD_GET_SUPPORTED_TUNNEL_PROTOCOLS, &[7]);
        let Outcome::Reply(r) = o else { panic!() };
        let p = SupportedProtocols::parse(&r.payload).unwrap();
        assert_eq!(p.protocols.len(), 2);
        assert_eq!(p.protocols[0], Protocol::standard(protocol::IPV4));
        let m = Protocol {
            manufacturer: 0x1234,
            protocol: 200,
        };
        assert!(m.matches(&RequestTunnel {
            protocol: 200,
            manufacturer: 0x1234,
            flow_control: false,
            max_incoming: 1
        }));
        assert!(!m.matches(&RequestTunnel {
            protocol: 200,
            manufacturer: 0x9999,
            flow_control: false,
            max_incoming: 1
        }));
    }
}
