//! Discovery of the OTA upgrade server (ZCL8 §11.8): a client
//! preprogrammed with the server's IEEE address resolves its network
//! address with NWK_addr_req; otherwise it broadcasts a Match_Desc_req
//! naming the OTA cluster as the only input cluster, takes the first
//! Match_Desc_rsp, resolves the IEEE address of that node with
//! IEEE_addr_req and stores it in `UpgradeServerID`. A server other
//! than the Trust Center needs an application link key, which is
//! requested once the server is known.

use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    CryptoRng, Endpoint, ExtendedAddress, NwkStatus, ShortAddress, TransactionSequence,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::ota;
use panweave_zcl::types::Value;
use panweave_zdo::zdp::{
    AddrRequestType, AddrRsp, EndpointListRsp, IeeeAddrReq, MatchDescReq, NwkAddrReq, U16List,
    ZdpStatus, cluster,
};

use crate::stack::{Phase, Stack, StackEvent};

/// Time allowed for the responses to a broadcast discovery.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// `UpgradeServerID` before discovery (§11.10.1: all ones).
pub const NO_SERVER: ExtendedAddress = ExtendedAddress(u64::MAX);

/// An outstanding discovery.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OtaDiscovery {
    /// The client endpoint.
    endpoint: Endpoint,
    /// Where the discovery stands.
    stage: Stage,
    /// The outstanding ZDP transaction.
    seq: TransactionSequence,
    /// When it is given up.
    deadline: Instant,
}

#[derive(Clone, Copy, Debug)]
enum Stage {
    /// Match_Desc_req broadcast, awaiting the first response.
    Matching,
    /// IEEE_addr_req sent to the matched server.
    Identifying {
        server: ShortAddress,
        server_endpoint: Endpoint,
    },
    /// NWK_addr_req broadcast for a preprogrammed server.
    Locating { ieee: ExtendedAddress },
}

impl OtaDiscovery {
    /// The timer.
    pub const fn deadline(&self) -> Option<Instant> {
        Some(self.deadline)
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Discovers the upgrade server of the OTA client on `endpoint`
    /// (ZCL8 §11.8). With `UpgradeServerID` preprogrammed the server's
    /// network address is resolved; otherwise the first OTA server to
    /// answer a Match_Desc_req is taken and its IEEE address stored.
    /// The result is [`StackEvent::OtaServer`] or
    /// [`StackEvent::OtaServerNotFound`]; a server that is not the
    /// Trust Center also gets an application link key requested.
    pub fn discover_ota_server(&mut self, endpoint: Endpoint) -> Result<(), NwkStatus> {
        if self.phase != Phase::Operating {
            return Err(NwkStatus::InvalidRequest);
        }
        if self.ota_discovery.is_some() {
            return Err(NwkStatus::AlreadyPresent);
        }
        let ep = self
            .zcl
            .endpoint(endpoint)
            .ok_or(NwkStatus::InvalidRequest)?;
        let profile = ep.profile;
        let client = ep
            .cluster(ota::ID, Role::Client)
            .ok_or(NwkStatus::InvalidRequest)?;
        let preset = client
            .u64(ota::UPGRADE_SERVER_ID.id)
            .map(ExtendedAddress)
            .filter(|s| *s != NO_SERVER && *s != ExtendedAddress::ZERO);
        let (stage, seq) = match preset {
            Some(ieee) => {
                let req = NwkAddrReq {
                    ieee,
                    request_type: AddrRequestType::Single,
                    start_index: 0,
                };
                let seq = self
                    .zdo
                    .request(ShortAddress::BROADCAST_RX_ON, cluster::NWK_ADDR_REQ, &req)
                    .map_err(|_| NwkStatus::InvalidRequest)?;
                (Stage::Locating { ieee }, seq)
            }
            None => {
                let input = ota::ID.0.to_le_bytes();
                let req = MatchDescReq {
                    addr: ShortAddress::BROADCAST_RX_ON,
                    profile,
                    input: U16List(&input),
                    output: U16List(&[]),
                };
                let seq = self
                    .zdo
                    .request(ShortAddress::BROADCAST_RX_ON, cluster::MATCH_DESC_REQ, &req)
                    .map_err(|_| NwkStatus::InvalidRequest)?;
                (Stage::Matching, seq)
            }
        };
        self.ota_discovery = Some(OtaDiscovery {
            endpoint,
            stage,
            seq,
            deadline: self.now + DISCOVERY_TIMEOUT,
        });
        self.pump();
        Ok(())
    }

    /// Gives a discovery up at its deadline.
    pub(crate) fn poll_ota_discovery(&mut self, now: Instant) {
        if let Some(d) = self.ota_discovery
            && now.has_reached(d.deadline)
        {
            self.ota_discovery = None;
            self.push_event(StackEvent::OtaServerNotFound {
                endpoint: d.endpoint,
            });
        }
    }

    /// A ZDP response that may belong to the discovery; returns whether
    /// it was consumed.
    pub(crate) fn on_ota_discovery_response(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        cluster: panweave_types::ClusterId,
        data: &[u8],
    ) -> bool {
        let Some(d) = self.ota_discovery else {
            return false;
        };
        if d.seq != seq {
            return false;
        }
        match d.stage {
            Stage::Matching if cluster == cluster::response_of(cluster::MATCH_DESC_REQ) => {
                // §11.8: the first response wins.
                let server_endpoint = panweave_codec::Decode::decode_exact(data)
                    .ok()
                    .filter(|r: &EndpointListRsp<'_>| r.status == ZdpStatus::Success)
                    .and_then(|r| r.iter().next());
                let Some(server_endpoint) = server_endpoint else {
                    return true;
                };
                let req = IeeeAddrReq {
                    addr: src,
                    request_type: AddrRequestType::Single,
                    start_index: 0,
                };
                match self.zdo.request(src, cluster::IEEE_ADDR_REQ, &req) {
                    Ok(seq) => {
                        self.ota_discovery = Some(OtaDiscovery {
                            stage: Stage::Identifying {
                                server: src,
                                server_endpoint,
                            },
                            seq,
                            ..d
                        });
                    }
                    Err(_) => {
                        self.ota_discovery = None;
                        self.push_event(StackEvent::OtaServerNotFound {
                            endpoint: d.endpoint,
                        });
                    }
                }
                true
            }
            Stage::Identifying {
                server,
                server_endpoint,
            } if cluster == cluster::response_of(cluster::IEEE_ADDR_REQ) => {
                let rsp = panweave_codec::Decode::decode_exact(data)
                    .ok()
                    .filter(|r: &AddrRsp<'_>| r.status == ZdpStatus::Success && r.short == server);
                self.ota_discovery = None;
                match rsp {
                    Some(r) => self.ota_server_found(d.endpoint, server, server_endpoint, r.ieee),
                    None => self.push_event(StackEvent::OtaServerNotFound {
                        endpoint: d.endpoint,
                    }),
                }
                true
            }
            Stage::Locating { ieee } if cluster == cluster::response_of(cluster::NWK_ADDR_REQ) => {
                let rsp = panweave_codec::Decode::decode_exact(data)
                    .ok()
                    .filter(|r: &AddrRsp<'_>| r.status == ZdpStatus::Success && r.ieee == ieee);
                let Some(r) = rsp else {
                    return true;
                };
                self.ota_discovery = None;
                let _ = self.nwk.address_map.record(ieee, r.short);
                // The server's OTA endpoint is not known from an address
                // response; the client learns it from the first frame.
                self.ota_server_found(d.endpoint, r.short, Endpoint(0), ieee);
                true
            }
            _ => false,
        }
    }

    /// Records the server and asks for the application link key when
    /// the server is not the Trust Center (§11.8).
    fn ota_server_found(
        &mut self,
        endpoint: Endpoint,
        server: ShortAddress,
        server_endpoint: Endpoint,
        ieee: ExtendedAddress,
    ) {
        if let Some(c) = self.zcl.cluster_mut(endpoint, ota::ID, Role::Client) {
            c.set(ota::UPGRADE_SERVER_ID.id, &Value::Eui64(ieee.0));
        }
        let is_tc = ieee == self.aps.aib.trust_center_address;
        let has_key = self.aps.security.entry(ieee).is_some();
        let key_requested = !is_tc
            && !has_key
            && !self.aps.aib.is_distributed()
            && self.request_application_link_key(ieee).is_ok();
        self.push_event(StackEvent::OtaServer {
            endpoint,
            server,
            server_endpoint,
            ieee,
            key_requested,
        });
    }
}
