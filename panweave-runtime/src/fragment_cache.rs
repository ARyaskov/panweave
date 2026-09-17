//! Fragmentation discovery and caching (R23.2 §2.2.8.4.5.1): before an
//! ASDU that needs fragmenting goes to a unicast destination, the
//! destination's Node Descriptor tells whether it reassembles fragments
//! and how large an ASDU it accepts (`MaximumIncomingTransferSize`, or
//! the Fragmentation Parameters TLV of R23 nodes). The answers live in
//! `apsFragmentationCacheTable`; a message the peer cannot take is
//! confirmed as failed to the application instead of being sent.

use heapless::Vec;
use panweave_aps::layer::{DataRequest, Destination, TxOptions};
use panweave_codec::Decode;
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, CryptoRng, Endpoint, ProfileId, ShortAddress, TransactionSequence,
};
use panweave_zdo::zdp::{NodeDescReq, NodeDescRsp, ZdpStatus, cluster};

use crate::context::AddrView;
use crate::stack::{Stack, StackEvent};

/// Cache entries (`apsFragmentationCacheTableSize`; a Trust Center is
/// expected to hold one per link key pair).
pub const CACHE_SIZE: usize = 16;
/// Messages held while a peer's parameters are being discovered.
const PENDING: usize = 2;
/// Time allowed for the Node_Desc_rsp.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// What is known about a peer's reassembly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FragmentationEntry {
    /// The peer.
    pub addr: ShortAddress,
    /// The peer reassembles fragmented transmissions.
    pub supported: bool,
    /// Largest ASDU it accepts (`apsMaxSizeASDU` of the peer).
    pub max_incoming: u16,
}

/// A message waiting for the peer's parameters.
#[derive(Clone, Debug)]
pub(crate) struct PendingFragmented {
    dst: ShortAddress,
    dst_endpoint: Endpoint,
    profile: ProfileId,
    cluster: ClusterId,
    src_endpoint: Endpoint,
    asdu: Vec<u8, { panweave_aps::MAX_ASDU }>,
    options: TxOptions,
    seq: TransactionSequence,
    deadline: Instant,
}

/// `apsFragmentationCacheTable` and the messages awaiting it.
#[derive(Clone, Debug, Default)]
pub(crate) struct FragmentationCache {
    entries: Vec<FragmentationEntry, CACHE_SIZE>,
    pending: Vec<PendingFragmented, PENDING>,
}

impl FragmentationCache {
    /// The cached entry for `addr`.
    pub fn get(&self, addr: ShortAddress) -> Option<FragmentationEntry> {
        self.entries.iter().find(|e| e.addr == addr).copied()
    }

    fn insert(&mut self, entry: FragmentationEntry) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.addr == entry.addr) {
            *e = entry;
            return;
        }
        if self.entries.is_full() {
            self.entries.remove(0);
        }
        let _ = self.entries.push(entry);
    }

    /// Forgets `addr` (its address or capabilities changed).
    pub fn forget(&mut self, addr: ShortAddress) {
        self.entries.retain(|e| e.addr != addr);
    }

    /// Earliest discovery deadline.
    pub fn deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .map(|p| p.deadline)
            .min_by_key(|t| t.as_millis())
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// The fragmentation parameters cached for `addr`, if discovered.
    pub fn fragmentation_entry(&self, addr: ShortAddress) -> Option<FragmentationEntry> {
        self.fragmentation.get(addr)
    }

    /// Records a peer's parameters (the application may seed the cache
    /// from its own discovery).
    pub fn cache_fragmentation(&mut self, entry: FragmentationEntry) {
        self.fragmentation.insert(entry);
    }

    /// Sends an ASDU, discovering the peer's fragmentation parameters
    /// first when the ASDU must be fragmented to a unicast destination
    /// whose parameters are not cached (§2.2.8.4.5.1). Returns whether
    /// the request was handled here (held or refused).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn send_with_fragmentation_check(
        &mut self,
        destination: Destination,
        profile: ProfileId,
        cluster: ClusterId,
        src_endpoint: Endpoint,
        asdu: &[u8],
        options: TxOptions,
    ) -> bool {
        let Destination::Short {
            address: dst,
            endpoint: dst_endpoint,
        } = destination
        else {
            return false;
        };
        if !dst.is_unicast() || !options.fragmentation_permitted || !options.ack {
            return false;
        }
        if asdu.len() <= self.aps.single_frame_capacity(options.security) {
            return false;
        }
        match self.fragmentation.get(dst) {
            Some(e) if e.supported && usize::from(e.max_incoming) >= asdu.len() => false,
            Some(_) => {
                self.push_event(StackEvent::FragmentationRefused {
                    dst,
                    cluster,
                    len: asdu.len(),
                });
                true
            }
            None => {
                let Ok(asdu) = Vec::from_slice(asdu) else {
                    return false;
                };
                let already = self.fragmentation.pending.iter().find(|p| p.dst == dst);
                let seq = match already {
                    Some(p) => p.seq,
                    None => {
                        let req = NodeDescReq {
                            addr: dst,
                            tlvs: &[],
                        };
                        match self.zdo.request(dst, cluster::NODE_DESC_REQ, &req) {
                            Ok(seq) => seq,
                            Err(_) => {
                                self.push_event(StackEvent::FragmentationRefused {
                                    dst,
                                    cluster,
                                    len: asdu.len(),
                                });
                                return true;
                            }
                        }
                    }
                };
                let pending = PendingFragmented {
                    dst,
                    dst_endpoint,
                    profile,
                    cluster,
                    src_endpoint,
                    asdu,
                    options,
                    seq,
                    deadline: self.now + DISCOVERY_TIMEOUT,
                };
                if self.fragmentation.pending.push(pending).is_err() {
                    self.push_event(StackEvent::FragmentationRefused {
                        dst,
                        cluster,
                        len: 0,
                    });
                }
                true
            }
        }
    }

    /// A Node_Desc_rsp that may complete a discovery; returns whether it
    /// was consumed.
    pub(crate) fn on_fragmentation_node_desc(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        data: &[u8],
    ) -> bool {
        if !self
            .fragmentation
            .pending
            .iter()
            .any(|p| p.seq == seq && p.dst == src)
        {
            return false;
        }
        let entry = NodeDescRsp::decode_exact(data)
            .ok()
            .filter(|r| r.status == ZdpStatus::Success)
            .and_then(|r| {
                let d = r.descriptor?;
                // R23 nodes also carry the Fragmentation Parameters TLV
                // (Annex I, Table I-7); the descriptor's own fields are
                // what pre-R23 nodes offer.
                let tlv = {
                    use panweave_nwk::tlv::GlobalTlvs as _;
                    panweave_codec::tlv::TlvSet::validate(r.tlvs, |_| false)
                        .ok()
                        .and_then(|set| set.fragmentation_parameters())
                };
                Some(match tlv {
                    Some(p) => FragmentationEntry {
                        addr: src,
                        supported: p.options & 0x01 != 0 || d.fragmentation_supported,
                        max_incoming: p
                            .max_incoming_transfer_unit
                            .max(d.max_incoming_transfer_size),
                    },
                    None => FragmentationEntry {
                        addr: src,
                        supported: d.fragmentation_supported,
                        max_incoming: d.max_incoming_transfer_size,
                    },
                })
            })
            .unwrap_or(FragmentationEntry {
                addr: src,
                supported: false,
                max_incoming: 0,
            });
        self.fragmentation.insert(entry);
        self.flush_pending_fragmented(src);
        true
    }

    /// Sends or refuses the messages held for `dst` now that its
    /// parameters are known (or the discovery failed).
    fn flush_pending_fragmented(&mut self, dst: ShortAddress) {
        let entry = self.fragmentation.get(dst);
        let mut held: Vec<PendingFragmented, PENDING> = Vec::new();
        let mut rest: Vec<PendingFragmented, PENDING> = Vec::new();
        for p in self.fragmentation.pending.drain(..) {
            if p.dst == dst {
                let _ = held.push(p);
            } else {
                let _ = rest.push(p);
            }
        }
        self.fragmentation.pending = rest;
        for p in held {
            let ok =
                entry.is_some_and(|e| e.supported && usize::from(e.max_incoming) >= p.asdu.len());
            if ok {
                let req = DataRequest {
                    destination: Destination::Short {
                        address: p.dst,
                        endpoint: p.dst_endpoint,
                    },
                    profile: p.profile,
                    cluster: p.cluster,
                    src_endpoint: p.src_endpoint,
                    asdu: &p.asdu,
                    options: p.options,
                    radius: None,
                    alias: None,
                };
                let view = AddrView(&self.nwk);
                let _ = self.aps.data_request(&req, &view);
            } else {
                self.push_event(StackEvent::FragmentationRefused {
                    dst: p.dst,
                    cluster: p.cluster,
                    len: p.asdu.len(),
                });
            }
        }
    }

    /// Discoveries that timed out: the peer is taken as not supporting
    /// fragmentation for now.
    pub(crate) fn poll_fragmentation(&mut self, now: Instant) {
        let expired: Vec<ShortAddress, PENDING> = self
            .fragmentation
            .pending
            .iter()
            .filter(|p| now.has_reached(p.deadline))
            .map(|p| p.dst)
            .collect();
        for dst in expired {
            self.fragmentation.insert(FragmentationEntry {
                addr: dst,
                supported: false,
                max_incoming: 0,
            });
            self.flush_pending_fragmented(dst);
        }
    }
}
