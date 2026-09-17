//! Trust Center keep-alive (ZCL8 §3.18.4, BDB 3.1 §6.4): a router on a
//! centralized network locates the Trust Center's Keep-Alive server with
//! Match_Desc_req and then reads `TCKeepAliveBase` / `TCKeepAliveJitter`
//! with an APS-encrypted Read Attributes at every jittered interval.
//! A Trust Center without a Keep-Alive server is polled with
//! Node_Desc_req instead (BDB 3.1 §7.3.3) at the default pacing. Three
//! successive failures mean the Trust Center is no longer reachable:
//! the application is told and may start a Trust Center search; the
//! mechanism stops until the next join.

use panweave_aps::Destination;
use panweave_aps::layer::{NwkView, TxOptions};
use panweave_security::cipher::BlockCipher;

use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, CryptoRng, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
    TransactionSequence,
};
use panweave_zcl::clusters::keep_alive;
use panweave_zcl::frame::{Direction, Header};
use panweave_zcl::global::{ReadAttributeStatus, Records, command};
use panweave_zdo::zdp::{EndpointListRsp, MatchDescReq, NodeDescReq, U16List, ZdpStatus, cluster};

use crate::context::AddrView;
use crate::stack::{Phase, Stack, StackEvent};

/// Time allowed for a Read Attributes Response (covers the APS
/// retries of a unicast).
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the Match_Desc_rsp.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Keep-alive client state.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct KeepAlive {
    stage: Stage,
    /// The Trust Center's Keep-Alive server endpoint.
    endpoint: Option<Endpoint>,
    /// Next read (or discovery retry).
    next: Option<Instant>,
    /// Outstanding transaction and its deadline.
    pending: Option<(TransactionSequence, Instant)>,
    /// Successive failures.
    failures: u8,
    base_minutes: u8,
    jitter_seconds: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum Stage {
    #[default]
    Off,
    Discovering,
    Running,
    /// No Keep-Alive server: Node_Desc_req polling (BDB 3.1 §7.3.3).
    NodeDescriptor,
}

impl KeepAlive {
    /// Earliest timer.
    pub const fn deadline(&self) -> Option<Instant> {
        match (self.next, self.pending) {
            (Some(n), Some((_, d))) => Some(if n.as_millis() < d.as_millis() { n } else { d }),
            (Some(n), None) => Some(n),
            (None, Some((_, d))) => Some(d),
            (None, None) => None,
        }
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Starts the keep-alive mechanism after joining a centralized
    /// network as a router (§3.18.4: end devices may, routers shall).
    pub(crate) fn start_keep_alive(&mut self) {
        let enabled = self.config.keep_alive
            && self.config.role == LogicalDeviceType::Router
            && !self.aps.config.is_trust_center
            && !self.aps.aib.is_distributed();
        if !enabled {
            self.keep_alive = KeepAlive::default();
            return;
        }
        self.keep_alive = KeepAlive {
            stage: Stage::Discovering,
            base_minutes: keep_alive::DEFAULT_BASE_MINUTES,
            jitter_seconds: keep_alive::DEFAULT_JITTER_SECONDS,
            next: Some(self.now),
            ..KeepAlive::default()
        };
    }

    /// Stops the mechanism (leave, Trust Center lost).
    pub(crate) fn stop_keep_alive(&mut self) {
        self.keep_alive = KeepAlive::default();
    }

    /// The Trust Center's network address as far as this device knows
    /// it (the coordinator's when unknown).
    pub fn trust_center_short(&self) -> ShortAddress {
        AddrView(&self.nwk)
            .short_of(self.aps.aib.trust_center_address)
            .unwrap_or(ShortAddress::COORDINATOR)
    }

    /// The IEEE address known for `short` (neighbour table or address
    /// map).
    pub fn ieee_of(&self, short: ShortAddress) -> Option<ExtendedAddress> {
        AddrView(&self.nwk).ieee_of(short)
    }

    /// Runs the keep-alive timers.
    pub(crate) fn poll_keep_alive(&mut self, now: Instant) {
        if self.keep_alive.stage == Stage::Off || self.phase != Phase::Operating {
            return;
        }
        if let Some((_, deadline)) = self.keep_alive.pending
            && now.has_reached(deadline)
        {
            self.keep_alive.pending = None;
            self.keep_alive_failure();
            return;
        }
        if let Some(t) = self.keep_alive.next
            && now.has_reached(t)
            && self.keep_alive.pending.is_none()
        {
            self.keep_alive.next = None;
            match self.keep_alive.stage {
                Stage::Discovering => self.keep_alive_discover(),
                Stage::Running => self.keep_alive_read(),
                Stage::NodeDescriptor => self.keep_alive_node_desc(),
                Stage::Off => {}
            }
        }
    }

    fn keep_alive_discover(&mut self) {
        let tc = self.trust_center_short();
        let input = keep_alive::ID.0.to_le_bytes();
        let req = MatchDescReq {
            addr: tc,
            profile: ProfileId::HOME_AUTOMATION,
            input: U16List(&input),
            output: U16List(&[]),
        };
        match self.zdo.request(tc, cluster::MATCH_DESC_REQ, &req) {
            Ok(seq) => {
                self.keep_alive.pending = Some((seq, self.now + DISCOVERY_TIMEOUT));
            }
            Err(_) => self.keep_alive.next = Some(self.now + Duration::from_secs(5)),
        }
    }

    /// Match_Desc_rsp from the Trust Center for the discovery request.
    pub(crate) fn on_keep_alive_match(&mut self, seq: TransactionSequence, data: &[u8]) -> bool {
        let Some((pending, _)) = self.keep_alive.pending else {
            return false;
        };
        if self.keep_alive.stage != Stage::Discovering || pending != seq {
            return false;
        }
        self.keep_alive.pending = None;
        let endpoint = panweave_codec::Decode::decode_exact(data)
            .ok()
            .filter(|r: &EndpointListRsp<'_>| r.status == ZdpStatus::Success)
            .and_then(|r| r.iter().next());
        match endpoint {
            Some(ep) => {
                self.keep_alive.endpoint = Some(ep);
                self.keep_alive.stage = Stage::Running;
                self.keep_alive.failures = 0;
                self.schedule_keep_alive_read();
            }
            // No Keep-Alive server: verify connectivity with the node
            // descriptor instead (BDB 3.1 §7.3.3).
            None => {
                self.keep_alive.stage = Stage::NodeDescriptor;
                self.keep_alive.failures = 0;
                self.schedule_keep_alive_read();
            }
        }
        true
    }

    /// Node_Desc_req to the Trust Center as the keep-alive (§7.3.3).
    fn keep_alive_node_desc(&mut self) {
        let tc = self.trust_center_short();
        let req = NodeDescReq {
            addr: tc,
            tlvs: &[],
        };
        match self.zdo.request(tc, cluster::NODE_DESC_REQ, &req) {
            Ok(seq) => self.keep_alive.pending = Some((seq, self.now + READ_TIMEOUT)),
            Err(_) => self.keep_alive_failure(),
        }
    }

    /// Node_Desc_rsp from the Trust Center; returns whether it answered
    /// the outstanding keep-alive poll.
    pub(crate) fn on_keep_alive_node_desc(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
    ) -> bool {
        let Some((pending, _)) = self.keep_alive.pending else {
            return false;
        };
        if self.keep_alive.stage != Stage::NodeDescriptor
            || pending != seq
            || src != self.trust_center_short()
        {
            return false;
        }
        self.keep_alive.pending = None;
        self.keep_alive.failures = 0;
        self.schedule_keep_alive_read();
        true
    }

    fn schedule_keep_alive_read(&mut self) {
        let base = Duration::from_secs(60 * u64::from(self.keep_alive.base_minutes.max(1)));
        let jitter = u64::from(self.keep_alive.jitter_seconds);
        let extra = if jitter == 0 {
            0
        } else {
            u64::from(self.nwk.rng().next_u32()) % (jitter + 1)
        };
        self.keep_alive.next = Some(self.now + base + Duration::from_secs(extra));
    }

    fn keep_alive_read(&mut self) {
        let Some(tc_ep) = self.keep_alive.endpoint else {
            return;
        };
        let Some(src_ep) = self.zcl.endpoints().first().map(|e| e.endpoint) else {
            // No application endpoint to send from: retry later.
            self.keep_alive.next = Some(self.now + Duration::from_secs(60));
            return;
        };
        let tc = self.trust_center_short();
        let seq = self.zcl.next_seq();
        let header = Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer);
        let mut payload = [0u8; 4];
        let mut w = panweave_codec::Writer::new(&mut payload);
        let _ = panweave_zcl::global::write_attribute_ids(
            &mut w,
            &[
                keep_alive::TC_KEEP_ALIVE_BASE.id,
                keep_alive::TC_KEEP_ALIVE_JITTER.id,
            ],
        );
        let sent = self.zcl.send(
            Destination::Short {
                address: tc,
                endpoint: tc_ep,
            },
            ProfileId::HOME_AUTOMATION,
            keep_alive::ID,
            src_ep,
            &header,
            &payload,
            TxOptions {
                security: true,
                ..TxOptions::ACKED
            },
        );
        match sent {
            Ok(()) => self.keep_alive.pending = Some((seq, self.now + READ_TIMEOUT)),
            Err(_) => self.keep_alive.next = Some(self.now + Duration::from_secs(5)),
        }
    }

    /// A Read Attributes Response on the Keep-Alive cluster; returns
    /// whether it answered the outstanding keep-alive read.
    pub(crate) fn on_keep_alive_response(
        &mut self,
        src: ShortAddress,
        seq: TransactionSequence,
        aps_secured: bool,
        payload: &[u8],
    ) -> bool {
        let Some((pending, _)) = self.keep_alive.pending else {
            return false;
        };
        if self.keep_alive.stage != Stage::Running
            || pending != seq
            || src != self.trust_center_short()
        {
            return false;
        }
        self.keep_alive.pending = None;
        // §3.18.4: only an APS-encrypted response counts.
        if !aps_secured {
            self.keep_alive_failure();
            return true;
        }
        for rec in Records::<ReadAttributeStatus>::new(payload).flatten() {
            let Some(v) = rec.value.as_ref().and_then(|v| v.as_u64()) else {
                continue;
            };
            if rec.id == keep_alive::TC_KEEP_ALIVE_BASE.id {
                self.keep_alive.base_minutes = u8::try_from(v).unwrap_or(u8::MAX).max(1);
            } else if rec.id == keep_alive::TC_KEEP_ALIVE_JITTER.id {
                self.keep_alive.jitter_seconds = u16::try_from(v).unwrap_or(u16::MAX);
            }
        }
        self.keep_alive.failures = 0;
        self.schedule_keep_alive_read();
        true
    }

    fn keep_alive_failure(&mut self) {
        self.keep_alive.failures = self.keep_alive.failures.saturating_add(1);
        if self.keep_alive.failures >= keep_alive::MAX_FAILURES {
            self.keep_alive = KeepAlive::default();
            self.push_event(StackEvent::TrustCenterLost);
        } else if self.keep_alive.stage == Stage::Discovering {
            self.keep_alive.next = Some(self.now + Duration::from_secs(30));
        } else {
            self.schedule_keep_alive_read();
        }
    }
}

/// The Keep-Alive cluster identifier as seen by the pump.
pub(crate) const CLUSTER: ClusterId = keep_alive::ID;
