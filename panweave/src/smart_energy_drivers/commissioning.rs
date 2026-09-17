//! The Smart Energy device life-cycle (SE 1.4a §5.5.5) driven over a
//! [`Stack`]: auto-joining on the §5.5.5.1 scan schedule, Key
//! Establishment through [`CbkeDriver`], discovery of the Energy Service
//! Interfaces by Match_Desc_req and binding to them, steady operation
//! with periodic rediscovery, and rejoin-and-recovery when the Trust
//! Center is lost — the `Lifecycle` machine of
//! `panweave_smart_energy::commissioning` decides, this driver acts.

use heapless::Vec;
use panweave_codec::Decode;
use panweave_runtime::{JoinMode, Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_smart_energy::PROFILE_ID;
use panweave_smart_energy::commissioning::{Action, Event, LeaveSource, Lifecycle, Phase};
use panweave_smart_energy::key_establishment::{Ecmqv, IssuerPolicy, Status, Timing};
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, CryptoRng, Endpoint, ExtendedAddress, LogicalDeviceType, NwkStatus, ShortAddress,
    TransactionSequence,
};
use panweave_zdo::zdp::{
    AddrRequestType, AddrRsp, BindReq, EndpointListRsp, IeeeAddrReq, MatchDescReq, U16List,
    ZdpStatus, cluster as zdp,
};

use crate::cbke::{CbkeDriver, CbkeOutcome};

/// Energy Service Interfaces remembered.
pub const MAX_ESIS: usize = 4;
/// Client clusters bound to every ESI.
pub const MAX_CLUSTERS: usize = 8;
/// How long Match_Desc responses are collected (§5.5.5.3 leaves it to
/// the device; broadcasts propagate within
/// nwkNetworkBroadcastDeliveryTime).
pub const DISCOVERY_WINDOW: Duration = Duration::from_secs(10);
/// Bind_req / IEEE_addr_req response wait.
pub const BIND_TIMEOUT: Duration = Duration::from_secs(8);

/// What the driver reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeCommissioningEvent {
    /// On the network with the network key; Key Establishment follows.
    Joined,
    /// The link key with the Trust Center was established.
    KeyEstablished,
    /// Key Establishment failed (the machine retries or pauses); the
    /// Terminate status when the peer sent one.
    KeyEstablishmentFailed {
        /// The Terminate status (`None` on a timeout).
        status: Option<Status>,
    },
    /// An ESI answered the service discovery.
    EsiFound {
        /// The ESI.
        address: ShortAddress,
        /// Its Smart Energy endpoint.
        endpoint: Endpoint,
    },
    /// Every discovered ESI holds a binding to this device for every
    /// cluster it serves (`bindings` succeeded); the device operates.
    Steady {
        /// Bindings established.
        bindings: u8,
    },
    /// The Trust Center was lost; recovery started.
    Recovering,
    /// A replacement Trust Center took over during the recovery
    /// (§5.4.2.2.3.5): Key Establishment with it follows.
    TrustCenterSwapped {
        /// The replacement.
        new: ExtendedAddress,
    },
    /// The device left the network and reset its commissioning.
    Left,
}

/// An ESI: address, endpoint, IEEE address once known.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Esi {
    /// NWK address.
    pub address: ShortAddress,
    /// Smart Energy endpoint.
    pub endpoint: Endpoint,
    /// IEEE address.
    pub ieee: Option<ExtendedAddress>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Idle,
    /// Scan (join) due at the instant.
    ScanAt(Instant),
    Joining,
    /// CBKE due at the instant.
    KeyEstablishmentAt(Instant),
    KeyEstablishment,
    /// Collecting Match_Desc responses until the instant.
    Discovering(Instant),
    /// Binding: the next (ESI index, cluster index) to bind, and the
    /// outstanding request.
    Binding {
        esi: u8,
        cluster: u8,
        pending: Option<(TransactionSequence, Instant)>,
    },
    /// Steady; rediscovery due at the instant.
    Steady(Instant),
    /// A rejoin is running (`scanning`: the channel scan for the PAN
    /// rather than a rejoin on the current channel).
    Rejoining {
        scanning: bool,
    },
    /// Recovery attempt due at the instant.
    RecoveryAt(Instant),
}

/// The driver: one Smart Energy endpoint, the client clusters it binds
/// and the CBKE driver it uses.
pub struct SeCommissioning<E: Ecmqv, I: IssuerPolicy = ExtendedAddress> {
    lifecycle: Lifecycle,
    /// The Key Establishment driver (also usable directly).
    pub cbke: CbkeDriver<E, I>,
    endpoint: Endpoint,
    clusters: Vec<ClusterId, MAX_CLUSTERS>,
    esis: Vec<Esi, MAX_ESIS>,
    state: State,
    discovery_seq: Option<TransactionSequence>,
    bindings: u8,
    /// A swap-out was detected during the current rejoin: CBKE with
    /// the replacement precedes the rediscovery (step 13), with one
    /// retry (step 14).
    swap: Option<(ExtendedAddress, u8)>,
}

impl<E: Ecmqv, I: IssuerPolicy> SeCommissioning<E, I> {
    /// A driver for `endpoint` binding `clusters` (the device's client
    /// clusters the ESIs serve) with the given CBKE primitive, issuer
    /// policy and timing; `rediscovery` / `recovery_period` as in
    /// `Lifecycle::new`.
    pub fn new(
        ecmqv: E,
        endpoint: Endpoint,
        issuers: I,
        timing: Timing,
        clusters: &[ClusterId],
        rediscovery: Duration,
        recovery_period: Duration,
    ) -> Self {
        let mut list = Vec::new();
        for c in clusters.iter().take(MAX_CLUSTERS) {
            let _ = list.push(*c);
        }
        SeCommissioning {
            lifecycle: Lifecycle::new(rediscovery, recovery_period),
            cbke: CbkeDriver::new(ecmqv, endpoint, issuers, timing),
            endpoint,
            clusters: list,
            esis: Vec::new(),
            state: State::Idle,
            discovery_seq: None,
            bindings: 0,
            swap: None,
        }
    }

    /// The life-cycle phase.
    pub fn phase(&self) -> Phase {
        self.lifecycle.phase()
    }

    /// The ESIs discovered.
    pub fn esis(&self) -> &[Esi] {
        &self.esis
    }

    /// Starts auto-joining (power-up with startup control 2, or the
    /// user's action).
    pub fn start<C: BlockCipher, R: CryptoRng, S: Storage>(&mut self, stack: &mut Stack<C, R, S>) {
        let now = stack.now();
        let action = self.lifecycle.on_event(Event::Start, now, random(stack));
        self.apply(stack, action);
    }

    /// The earliest instant [`Self::poll`] has something to do.
    pub fn deadline(&self) -> Option<Instant> {
        let mine = match self.state {
            State::ScanAt(t)
            | State::KeyEstablishmentAt(t)
            | State::Discovering(t)
            | State::Steady(t)
            | State::RecoveryAt(t) => Some(t),
            State::Binding {
                pending: Some((_, t)),
                ..
            } => Some(t),
            _ => None,
        };
        match (mine, self.cbke.deadline()) {
            (Some(a), Some(b)) => Some(if a.as_millis() < b.as_millis() { a } else { b }),
            (a, None) => a,
            (None, b) => b,
        }
    }

    fn apply<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        action: Action,
    ) -> Option<SeCommissioningEvent> {
        let now = stack.now();
        match action {
            Action::Scan { delay } => {
                self.state = State::ScanAt(now + delay);
                None
            }
            Action::JoinNext => {
                self.state = State::ScanAt(now);
                None
            }
            Action::KeyEstablishment { delay } => {
                self.state = State::KeyEstablishmentAt(now + delay);
                None
            }
            Action::DiscoverServices => {
                self.discover(stack);
                None
            }
            Action::Steady { rediscover } => {
                self.state = State::Steady(now + rediscover);
                Some(SeCommissioningEvent::Steady {
                    bindings: self.bindings,
                })
            }
            Action::Continue | Action::Ignore => None,
            Action::Rejoin => {
                self.state = State::Rejoining { scanning: false };
                if stack.join(JoinMode::TrustCenterRejoin).is_err() {
                    let a = self
                        .lifecycle
                        .on_event(Event::RejoinFailed, now, random(stack));
                    return self.apply(stack, a);
                }
                Some(SeCommissioningEvent::Recovering)
            }
            Action::ScanForPan => {
                // The rejoin scans every configured channel for the
                // extended PAN ID; the runtime reports the outcome as a
                // join or a failure.
                self.state = State::Rejoining { scanning: true };
                if stack.join(JoinMode::SecuredRejoin).is_err() {
                    let a = self
                        .lifecycle
                        .on_event(Event::PanNotFound, now, random(stack));
                    return self.apply(stack, a);
                }
                None
            }
            Action::WaitOnOriginalChannel { delay } => {
                self.state = State::RecoveryAt(now + delay);
                None
            }
            Action::LeaveAndReset => {
                let _ = stack.leave(false);
                self.esis.clear();
                self.bindings = 0;
                self.swap = None;
                self.state = State::Idle;
                Some(SeCommissioningEvent::Left)
            }
        }
    }

    fn discover<C: BlockCipher, R: CryptoRng, S: Storage>(&mut self, stack: &mut Stack<C, R, S>) {
        self.esis.clear();
        self.bindings = 0;
        let mut input: Vec<u8, { 2 * MAX_CLUSTERS }> = Vec::new();
        for c in &self.clusters {
            let _ = input.extend_from_slice(&c.0.to_le_bytes());
        }
        let req = MatchDescReq {
            addr: ShortAddress::BROADCAST_RX_ON,
            profile: PROFILE_ID,
            input: U16List(&input),
            output: U16List(&[]),
        };
        self.discovery_seq = stack
            .zdo
            .request(ShortAddress::BROADCAST_RX_ON, zdp::MATCH_DESC_REQ, &req)
            .ok();
        stack.flush();
        self.state = State::Discovering(stack.now() + DISCOVERY_WINDOW);
    }

    /// Sends the next Bind_req (or the IEEE_addr_req it needs); when
    /// every binding was tried the machine hears `DiscoveryDone`.
    fn bind_next<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
    ) -> Option<SeCommissioningEvent> {
        loop {
            let State::Binding { esi, cluster, .. } = self.state else {
                return None;
            };
            let Some(target) = self.esis.get(usize::from(esi)).copied() else {
                let now = stack.now();
                let a = self
                    .lifecycle
                    .on_event(Event::DiscoveryDone, now, random(stack));
                return self.apply(stack, a);
            };
            let Some(&cluster_id) = self.clusters.get(usize::from(cluster)) else {
                self.state = State::Binding {
                    esi: esi + 1,
                    cluster: 0,
                    pending: None,
                };
                continue;
            };
            let deadline = stack.now() + BIND_TIMEOUT;
            let ieee = target.ieee.or_else(|| stack.ieee_of(target.address));
            let request = match ieee {
                Some(ieee) => {
                    if let Some(e) = self.esis.get_mut(usize::from(esi)) {
                        e.ieee = Some(ieee);
                    }
                    let req = BindReq {
                        src: ieee,
                        src_endpoint: target.endpoint,
                        cluster: cluster_id,
                        destination: panweave_aps::tables::BindingDestination::Unicast {
                            address: stack.config.ieee,
                            endpoint: self.endpoint,
                        },
                    };
                    stack.zdo.request(target.address, zdp::BIND_REQ, &req)
                }
                None => {
                    let req = IeeeAddrReq {
                        addr: target.address,
                        request_type: AddrRequestType::Single,
                        start_index: 0,
                    };
                    stack.zdo.request(target.address, zdp::IEEE_ADDR_REQ, &req)
                }
            };
            stack.flush();
            match request {
                Ok(seq) => {
                    self.state = State::Binding {
                        esi,
                        cluster,
                        pending: Some((seq, deadline)),
                    };
                    return None;
                }
                Err(_) => {
                    self.state = State::Binding {
                        esi,
                        cluster: cluster + 1,
                        pending: None,
                    };
                }
            }
        }
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<SeCommissioningEvent> {
        let now = stack.now();
        // Key Establishment runs through the CBKE driver whatever the
        // phase (the responder side serves peers at any time).
        if let Some(outcome) = self.cbke.on_event(stack, event)
            && self.state == State::KeyEstablishment
        {
            return self.on_cbke(stack, outcome);
        }
        match event {
            StackEvent::TrustCenterSwapped { new, .. } => {
                if self.lifecycle.phase() == Phase::RejoinRecovery {
                    self.swap = Some((*new, 0));
                    return Some(SeCommissioningEvent::TrustCenterSwapped { new: *new });
                }
                None
            }
            StackEvent::Joined { rejoin, .. } => {
                if *rejoin && self.lifecycle.phase() == Phase::RejoinRecovery {
                    if self.swap.is_some() {
                        // Step 13: establish a key with the replacement
                        // before going back to service discovery.
                        self.state = State::KeyEstablishmentAt(now);
                        return None;
                    }
                    let a = self
                        .lifecycle
                        .on_event(Event::RejoinSucceeded, now, random(stack));
                    return self.apply(stack, a);
                }
                if !*rejoin && self.state == State::Joining {
                    let a = self
                        .lifecycle
                        .on_event(Event::JoinedWithKey, now, random(stack));
                    self.apply(stack, a);
                    return Some(SeCommissioningEvent::Joined);
                }
                None
            }
            StackEvent::JoinFailed(status) => match self.state {
                State::Joining => {
                    // The runtime scans and joins in one step: no PAN
                    // found is a scan without joinable networks (the
                    // §5.5.5.1 schedule), anything else a failed join.
                    let e = if *status == NwkStatus::NoNetworks {
                        Event::ScanDone { joinable: 0 }
                    } else {
                        Event::JoinFailed
                    };
                    let a = self.lifecycle.on_event(e, now, random(stack));
                    self.apply(stack, a)
                }
                State::Rejoining { scanning } => {
                    let e = match (self.lifecycle.phase(), scanning) {
                        (Phase::RejoinRecovery, true) => Event::PanNotFound,
                        (Phase::RejoinRecovery, false) => Event::RejoinFailed,
                        _ => Event::JoinFailed,
                    };
                    let a = self.lifecycle.on_event(e, now, random(stack));
                    self.apply(stack, a)
                }
                _ => None,
            },
            StackEvent::TrustCenterLost => {
                // The runtime reports the Trust Center lost after three
                // failed keep-alive exchanges (ZCL8 §3.18.4); §5.5.5.3
                // item 3 lets the device start rejoin and recovery before
                // the 24-hour limit.
                match self.lifecycle.phase() {
                    Phase::Steady | Phase::ServiceDiscovery => {
                        let a = self.lifecycle.enter_recovery();
                        self.apply(stack, a)
                    }
                    _ => None,
                }
            }
            StackEvent::Left { rejoin } => {
                if matches!(self.state, State::Idle) {
                    return None;
                }
                let source = if *rejoin {
                    LeaveSource::NwkLeaveFromParent
                } else {
                    LeaveSource::NwkLeaveOther
                };
                let a = self
                    .lifecycle
                    .on_event(Event::Leave(source), now, random(stack));
                self.apply(stack, a)
            }
            StackEvent::Zdp(z) => self.on_zdp(stack, z.src, z.seq, z.cluster, &z.data),
            StackEvent::ZdpTimeout { seq, .. } => {
                if let State::Binding {
                    esi,
                    cluster,
                    pending: Some((s, _)),
                } = self.state
                    && s == *seq
                {
                    self.state = State::Binding {
                        esi,
                        cluster: cluster + 1,
                        pending: None,
                    };
                    return self.bind_next(stack);
                }
                None
            }
            _ => None,
        }
    }

    fn on_cbke<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        outcome: CbkeOutcome,
    ) -> Option<SeCommissioningEvent> {
        let now = stack.now();
        if let Some((new, attempts)) = self.swap {
            // Steps 13–14 of the swap-out: on success the device is back
            // in business (rediscovery); one retry, then the candidate
            // is left and the device starts over.
            return match outcome {
                CbkeOutcome::Established { .. } => {
                    self.swap = None;
                    let a = self
                        .lifecycle
                        .on_event(Event::RejoinSucceeded, now, random(stack));
                    self.apply(stack, a);
                    Some(SeCommissioningEvent::KeyEstablished)
                }
                CbkeOutcome::Failed { status, .. } if attempts < 1 => {
                    self.swap = Some((new, attempts + 1));
                    self.state = State::KeyEstablishmentAt(now);
                    Some(SeCommissioningEvent::KeyEstablishmentFailed { status })
                }
                CbkeOutcome::Failed { .. } => {
                    self.swap = None;
                    let a = self.lifecycle.on_event(
                        Event::Leave(LeaveSource::User),
                        now,
                        random(stack),
                    );
                    self.apply(stack, a)
                }
            };
        }
        match outcome {
            CbkeOutcome::Established { .. } => {
                let a = self
                    .lifecycle
                    .on_event(Event::KeyEstablished, now, random(stack));
                self.apply(stack, a);
                Some(SeCommissioningEvent::KeyEstablished)
            }
            CbkeOutcome::Failed { status, .. } => {
                let a = self
                    .lifecycle
                    .on_event(Event::KeyEstablishmentFailed, now, random(stack));
                self.apply(stack, a);
                Some(SeCommissioningEvent::KeyEstablishmentFailed { status })
            }
        }
    }

    fn on_zdp<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        src: ShortAddress,
        seq: TransactionSequence,
        cluster: ClusterId,
        data: &[u8],
    ) -> Option<SeCommissioningEvent> {
        if cluster == zdp::response_of(zdp::MATCH_DESC_REQ)
            && matches!(self.state, State::Discovering(_))
            && self.discovery_seq == Some(seq)
        {
            let Ok(rsp) = EndpointListRsp::decode_exact(data) else {
                return None;
            };
            if rsp.status != ZdpStatus::Success {
                return None;
            }
            let endpoint = rsp.iter().next()?;
            let address = if rsp.addr.is_unicast() { rsp.addr } else { src };
            if self.esis.iter().any(|e| e.address == address) {
                return None;
            }
            let _ = self.esis.push(Esi {
                address,
                endpoint,
                ieee: stack.ieee_of(address),
            });
            return Some(SeCommissioningEvent::EsiFound { address, endpoint });
        }
        let State::Binding {
            esi,
            cluster: ci,
            pending: Some((s, _)),
        } = self.state
        else {
            return None;
        };
        if s != seq {
            return None;
        }
        if cluster == zdp::response_of(zdp::IEEE_ADDR_REQ) {
            if let Ok(r) = AddrRsp::decode_exact(data)
                && r.status == ZdpStatus::Success
                && let Some(e) = self.esis.get_mut(usize::from(esi))
            {
                e.ieee = Some(r.ieee);
                self.state = State::Binding {
                    esi,
                    cluster: ci,
                    pending: None,
                };
            } else {
                // No IEEE address: skip this ESI.
                self.state = State::Binding {
                    esi: esi + 1,
                    cluster: 0,
                    pending: None,
                };
            }
            return self.bind_next(stack);
        }
        if cluster == zdp::response_of(zdp::BIND_REQ) {
            if data.first().copied() == Some(ZdpStatus::Success.raw()) {
                self.bindings = self.bindings.saturating_add(1);
            }
            self.state = State::Binding {
                esi,
                cluster: ci + 1,
                pending: None,
            };
            return self.bind_next(stack);
        }
        None
    }

    /// Runs the timers: the scan schedule, the CBKE start, the
    /// discovery window, binding timeouts, rediscovery and recovery.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        now: Instant,
    ) -> Option<SeCommissioningEvent> {
        if let Some(outcome) = self.cbke.poll(stack, now)
            && self.state == State::KeyEstablishment
        {
            return self.on_cbke(stack, outcome);
        }
        match self.state {
            State::ScanAt(t) if now.has_reached(t) => {
                self.state = State::Joining;
                if stack.join(JoinMode::Association).is_err() {
                    let a = self
                        .lifecycle
                        .on_event(Event::JoinFailed, now, random(stack));
                    return self.apply(stack, a);
                }
                None
            }
            State::KeyEstablishmentAt(t) if now.has_reached(t) => {
                self.state = State::KeyEstablishment;
                if stack.config.role == LogicalDeviceType::Coordinator
                    || stack.aps.aib.is_distributed()
                {
                    // Nothing to establish with: the device is the Trust
                    // Center (or the network has none).
                    return self.on_cbke(
                        stack,
                        CbkeOutcome::Established {
                            partner: stack.config.ieee,
                        },
                    );
                }
                let tc = stack.aps.aib.trust_center_address;
                let dst = stack.trust_center_short();
                if self.cbke.start(stack, dst, tc).is_err() {
                    let a =
                        self.lifecycle
                            .on_event(Event::KeyEstablishmentFailed, now, random(stack));
                    return self.apply(stack, a);
                }
                None
            }
            State::Discovering(t) if now.has_reached(t) => {
                self.state = State::Binding {
                    esi: 0,
                    cluster: 0,
                    pending: None,
                };
                self.bind_next(stack)
            }
            State::Binding {
                esi,
                cluster,
                pending: Some((_, t)),
            } if now.has_reached(t) => {
                self.state = State::Binding {
                    esi,
                    cluster: cluster + 1,
                    pending: None,
                };
                self.bind_next(stack)
            }
            State::Steady(t) if now.has_reached(t) => {
                self.discover(stack);
                None
            }
            State::RecoveryAt(t) if now.has_reached(t) => {
                let a = self.lifecycle.enter_recovery();
                self.apply(stack, a)
            }
            _ => None,
        }
    }
}

/// The jitter source of the life-cycle machine: the stack's RNG.
fn random<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &mut Stack<C, R, S>,
) -> impl FnMut(u32) -> u32 + '_ {
    move |n| {
        if n == 0 {
            0
        } else {
            stack.nwk.rng().next_u32() % n
        }
    }
}
