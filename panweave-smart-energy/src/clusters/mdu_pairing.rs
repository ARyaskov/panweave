//! MDU Pairing cluster (SE 1.4a Annex D.13, provisional): the Pairing
//! Request / Pairing Response codecs, a server-side [`respond`] that
//! fragments a household's `virtual HAN` list and applies the
//! version-match / not-yet-available rules, and a client-side
//! [`Assembler`] that collects the fragments before the list is used.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId, ExtendedAddress};
use panweave_zcl::cluster::ClusterDef;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x070A);

/// Server → client: PairingResponse.
pub const CMD_PAIRING_RESPONSE: CommandId = CommandId(0x00);
/// Client → server: PairingRequest.
pub const CMD_PAIRING_REQUEST: CommandId = CommandId(0x00);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_PAIRING_REQUEST],
    generated: &[CMD_PAIRING_RESPONSE],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

/// Local pairing information version of a device without any.
pub const NO_VERSION: u32 = 0;
/// Devices per PairingResponse fragment (8 octets each).
pub const DEVICES_PER_COMMAND: usize = 8;
/// Devices a virtual HAN may hold.
pub const MAX_DEVICES: usize = 32;
/// Fragments of one response.
pub const MAX_COMMANDS: usize = MAX_DEVICES.div_ceil(DEVICES_PER_COMMAND);

/// PairingRequest (D.13.3.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PairingRequest {
    /// Version held by the requester (`NO_VERSION` when none).
    pub local_version: u32,
    /// The requesting device.
    pub requester: ExtendedAddress,
}

impl PairingRequest {
    /// Encoded length.
    pub const LEN: usize = 12;

    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(PairingRequest {
            local_version: r.u32_le()?,
            requester: ExtendedAddress(r.u64_le()?),
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.local_version)?;
        w.u64_le(self.requester.0)
    }
}

/// PairingResponse (D.13.2.3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PairingResponse {
    /// Pairing information version (never 0).
    pub version: u32,
    /// Devices in the virtual HAN, including the requester.
    pub total_devices: u8,
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// The devices carried by this command.
    pub devices: Vec<ExtendedAddress, DEVICES_PER_COMMAND>,
}

impl PairingResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let version = r.u32_le()?;
        let total_devices = r.u8()?;
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let mut devices = Vec::new();
        while !r.is_empty() {
            devices
                .push(ExtendedAddress(r.u64_le()?))
                .map_err(|_| CodecError::Unrepresentable { field: "devices" })?;
        }
        Ok(PairingResponse {
            version,
            total_devices,
            command_index,
            total_commands,
            devices,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.version)?;
        w.u8(self.total_devices)?;
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        for d in &self.devices {
            w.u64_le(d.0)?;
        }
        Ok(())
    }
}

/// Why the server answers with a Default Response instead
/// (D.13.3.3.1.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Refusal {
    /// The requester already holds this version, or the information is
    /// not available yet: WAIT_FOR_DATA.
    WaitForData,
    /// Not an MDU Trust Center: UNSUP_CLUSTER_COMMAND.
    NotMdu,
}

/// Builds the PairingResponse fragments for a requester. `household`
/// is the version and member list the Trust Center holds for it
/// (`None` when unknown yet); the list must include the requester.
pub fn respond(
    request: &PairingRequest,
    household: Option<(u32, &[ExtendedAddress])>,
) -> Result<Vec<PairingResponse, MAX_COMMANDS>, Refusal> {
    let Some((version, devices)) = household else {
        return Err(Refusal::WaitForData);
    };
    if version == NO_VERSION || request.local_version == version {
        return Err(Refusal::WaitForData);
    }
    let total_devices = u8::try_from(devices.len()).map_err(|_| Refusal::WaitForData)?;
    let chunks = devices.chunks(DEVICES_PER_COMMAND);
    let total_commands = u8::try_from(chunks.len().max(1)).map_err(|_| Refusal::WaitForData)?;
    let mut out = Vec::new();
    if devices.is_empty() {
        let _ = out.push(PairingResponse {
            version,
            total_devices,
            command_index: 0,
            total_commands,
            devices: Vec::new(),
        });
        return Ok(out);
    }
    for (i, chunk) in chunks.enumerate() {
        out.push(PairingResponse {
            version,
            total_devices,
            command_index: u8::try_from(i).map_err(|_| Refusal::WaitForData)?,
            total_commands,
            devices: Vec::from_slice(chunk).map_err(|_| Refusal::WaitForData)?,
        })
        .map_err(|_| Refusal::WaitForData)?;
    }
    Ok(out)
}

/// A complete virtual HAN as received.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VirtualHan {
    /// Pairing information version.
    pub version: u32,
    /// Members, including this device.
    pub devices: Vec<ExtendedAddress, MAX_DEVICES>,
}

impl VirtualHan {
    /// Whether service discovery and binding with `device` is allowed.
    pub fn allows(&self, device: ExtendedAddress) -> bool {
        self.devices.contains(&device)
    }
}

/// Client-side fragment assembler: collects the PairingResponse
/// commands of one version and yields the list once every fragment
/// arrived (D.13.2.3.1.4).
#[derive(Clone, Debug, Default)]
pub struct Assembler {
    pending: Option<VirtualHan>,
    expected: u8,
    received: u16,
}

impl Assembler {
    /// An empty assembler.
    pub const fn new() -> Self {
        Assembler {
            pending: None,
            expected: 0,
            received: 0,
        }
    }

    /// Feeds a fragment; `Some` with the complete list when all
    /// fragments of the version arrived. Fragments of another version
    /// restart the assembly; a fragment index outside the announced
    /// total is dropped.
    pub fn feed(&mut self, r: &PairingResponse) -> Option<VirtualHan> {
        if r.version == NO_VERSION || r.command_index >= r.total_commands.max(1) {
            return None;
        }
        let restart = self.pending.as_ref().is_none_or(|p| p.version != r.version)
            || self.expected != r.total_commands;
        if restart {
            self.pending = Some(VirtualHan {
                version: r.version,
                devices: Vec::new(),
            });
            self.expected = r.total_commands.max(1);
            self.received = 0;
        }
        let bit = 1u16 << (r.command_index & 0x0f);
        if self.received & bit != 0 {
            return None;
        }
        let p = self.pending.as_mut()?;
        if p.devices.extend_from_slice(&r.devices).is_err() {
            self.pending = None;
            return None;
        }
        self.received |= bit;
        let all = (0..self.expected).all(|i| self.received & (1 << (i & 0x0f)) != 0);
        if all && p.devices.len() == usize::from(r.total_devices) {
            self.received = 0;
            self.expected = 0;
            return self.pending.take();
        }
        if all {
            // Count mismatch: discard and wait for a retransmission.
            self.pending = None;
            self.received = 0;
            self.expected = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eui(n: u64) -> ExtendedAddress {
        ExtendedAddress(0x00aa_0000_0000_0000 | n)
    }

    #[test]
    fn codecs_round_trip() {
        let req = PairingRequest {
            local_version: 3,
            requester: eui(1),
        };
        let mut buf = [0u8; 80];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(w.position(), PairingRequest::LEN);
        assert_eq!(PairingRequest::parse(&buf[..12]).unwrap(), req);
        let mut devices = Vec::new();
        devices.push(eui(1)).unwrap();
        devices.push(eui(2)).unwrap();
        let resp = PairingResponse {
            version: 4,
            total_devices: 2,
            command_index: 0,
            total_commands: 1,
            devices,
        };
        let mut w = Writer::new(&mut buf);
        resp.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 7 + 16);
        assert_eq!(PairingResponse::parse(&buf[..n]).unwrap(), resp);
    }

    #[test]
    fn server_fragments_and_client_reassembles() {
        let members: Vec<ExtendedAddress, MAX_DEVICES> = (1..=11).map(eui).collect();
        let req = PairingRequest {
            local_version: NO_VERSION,
            requester: eui(1),
        };
        assert_eq!(respond(&req, None), Err(Refusal::WaitForData));
        assert_eq!(
            respond(
                &PairingRequest {
                    local_version: 5,
                    ..req
                },
                Some((5, &members))
            ),
            Err(Refusal::WaitForData)
        );
        let frags = respond(&req, Some((5, &members))).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!((frags[0].devices.len(), frags[1].devices.len()), (8, 3));
        assert!(
            frags
                .iter()
                .all(|f| f.total_devices == 11 && f.total_commands == 2)
        );
        assert_eq!(frags[1].command_index, 1);

        let mut a = Assembler::new();
        // Out of order, with a duplicate.
        assert!(a.feed(&frags[1]).is_none());
        assert!(a.feed(&frags[1]).is_none());
        let han = a.feed(&frags[0]).unwrap();
        assert_eq!((han.version, han.devices.len()), (5, 11));
        assert!(han.allows(eui(7)) && !han.allows(eui(12)));
        // A newer version restarts the assembly.
        let newer = respond(
            &PairingRequest {
                local_version: 5,
                ..req
            },
            Some((6, &members[..2])),
        )
        .unwrap();
        assert!(a.feed(&frags[0]).is_none());
        let han = a.feed(&newer[0]).unwrap();
        assert_eq!((han.version, han.devices.len()), (6, 2));
        // Index beyond the total is dropped; version 0 is invalid.
        assert!(
            a.feed(&PairingResponse {
                command_index: 3,
                ..newer[0].clone()
            })
            .is_none()
        );
        assert!(
            a.feed(&PairingResponse {
                version: 0,
                ..newer[0].clone()
            })
            .is_none()
        );
    }
}
