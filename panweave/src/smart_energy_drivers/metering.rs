//! Metering cluster drivers (SE 1.4a Annex D.3): the server (meter)
//! answering Get Profile, fast poll, sampling, snapshot and supply
//! control requests from the models the application feeds with readings,
//! and the client (ESI / display) issuing those requests, assembling the
//! answers and — on an ESI — hosting mirrors.

use heapless::Vec;
use panweave_aps::layer::Destination;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_smart_energy::clusters::metering::extended::{
    self as ext, ChangeSupply, ConfigureMirror, FastPoll, FastPollModeResponse, GetSampledData,
    GetSnapshot, LocalChangeSupply, MirrorRemoved, MirrorTable, PublishSnapshot,
    RequestFastPollMode, RequestMirrorResponse, SampledDataResponse, Sampler, Snapshot,
    SnapshotAssembler, Snapshots, StartSampling, StartSamplingResponse, SupplyControl,
    SupplyOutcome, SupplyStatusResponse, TakeSnapshot, TakeSnapshotResponse,
};
use panweave_smart_energy::clusters::metering::{
    self, GetProfile, GetProfileResponse, IntervalPeriod, MAX_PERIODS_DELIVERED, ProfileLog,
    ProfileStatus,
};
use panweave_storage::Storage;
use panweave_types::time::Instant;
use panweave_types::{CryptoRng, Endpoint, ShortAddress};
use panweave_zcl::ZclStatus;
use panweave_zcl::frame::Direction;

use super::{UtcClock, command_for, default_response, reply, send, utc_now};

/// Interval channels a server logs.
pub const PROFILE_CHANNELS: usize = 4;
/// Intervals kept per channel.
pub const PROFILE_INTERVALS: usize = 48;
/// Sampling sessions a server keeps.
pub const SAMPLING_SESSIONS: usize = 4;
/// Snapshots a server keeps.
pub const SNAPSHOTS: usize = 4;

/// What a [`MeteringServer`] reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MeteringServerEvent {
    /// Fast poll mode was requested: report the attributes at
    /// `period` seconds until `end` (UTC).
    FastPoll {
        /// The client.
        client: ShortAddress,
        /// Applied update period, seconds.
        period: u8,
        /// End of the mode (UTC seconds).
        end: u32,
    },
    /// A sampling session started (feed it with
    /// [`MeteringServer::sample`]); `sample_id` 0xFFFF means it was
    /// refused for lack of space.
    SamplingStarted {
        /// Sample id.
        sample_id: u16,
        /// Sample type.
        sample_type: u8,
    },
    /// A snapshot was taken on request.
    SnapshotTaken {
        /// Snapshot id.
        snapshot_id: u32,
        /// Cause.
        cause: u32,
    },
    /// The supply status changed (apply it to the hardware).
    SupplyChanged {
        /// New status.
        status: u8,
    },
    /// A supply change was scheduled for `at` (UTC seconds).
    SupplyScheduled {
        /// Implementation time.
        at: u32,
    },
    /// A client read a profile block.
    ProfileRequested {
        /// The client.
        client: ShortAddress,
        /// The status answered.
        status: ProfileStatus,
    },
}

/// The server driver on `endpoint`.
pub struct MeteringServer {
    endpoint: Endpoint,
    /// Interval logs, one per channel.
    pub profiles: Vec<ProfileLog<PROFILE_INTERVALS>, PROFILE_CHANNELS>,
    /// Fast poll mode.
    pub fast_poll: FastPoll,
    /// Sampling sessions.
    pub sampler: Sampler<SAMPLING_SESSIONS>,
    /// Snapshots.
    pub snapshots: Snapshots<SNAPSHOTS>,
    /// Snapshot causes the meter supports (bitmask), payload type and
    /// the current snapshot payload the application keeps up to date.
    pub snapshot_causes: u32,
    /// Snapshot payload type (Table D-56).
    pub snapshot_payload_type: u8,
    /// Current snapshot sub-payload.
    pub snapshot_payload: Vec<u8, { ext::MAX_SNAPSHOT_PAYLOAD }>,
    /// Supply control.
    pub supply: SupplyControl,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
    /// The last client that changed the supply (for the scheduled
    /// status response).
    supply_client: Option<(ShortAddress, Endpoint)>,
}

impl MeteringServer {
    /// A server with no profile data, default fast poll periods, no
    /// snapshot support and an uncontrollable supply.
    pub fn new(endpoint: Endpoint) -> Self {
        MeteringServer {
            endpoint,
            profiles: Vec::new(),
            fast_poll: FastPoll::new(5, 30),
            sampler: Sampler::new(),
            snapshots: Snapshots::new(),
            snapshot_causes: 0,
            snapshot_payload_type: 0,
            snapshot_payload: Vec::new(),
            supply: SupplyControl::new(ext::supply_status::ON, false, false),
            clock: UtcClock::new(),
            supply_client: None,
        }
    }

    /// Adds an interval channel (Table D-64) with its period and the
    /// most periods delivered per response.
    pub fn add_profile_channel(
        &mut self,
        channel: u8,
        period: IntervalPeriod,
        max_periods: u8,
    ) -> bool {
        if self.profiles.iter().any(|p| p.channel == channel) {
            return false;
        }
        self.profiles
            .push(ProfileLog::new(
                channel,
                period,
                max_periods.min(u8::try_from(MAX_PERIODS_DELIVERED).unwrap_or(u8::MAX)),
            ))
            .is_ok()
    }

    /// Records the interval of `channel` that ended at `end_time`.
    pub fn record_interval(&mut self, channel: u8, value: u32, end_time: u32) {
        if let Some(p) = self.profiles.iter_mut().find(|p| p.channel == channel) {
            p.record(value, end_time);
        }
    }

    /// Feeds a reading of `sample_type` to the sampling sessions due at
    /// `now`.
    pub fn sample<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        sample_type: u8,
        value: u32,
    ) {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.sampler.sample(sample_type, value, now);
    }

    /// Takes a snapshot of the current payload for `cause` (the meter's
    /// own schedule or trigger); the id when stored.
    pub fn take_snapshot<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        cause: u32,
    ) -> Option<u32> {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.snapshots.take(
            cause,
            self.snapshot_payload_type,
            &self.snapshot_payload,
            now,
        )
    }

    fn send_supply_status<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        r: &SupplyStatusResponse,
    ) {
        let Some((client, endpoint)) = self.supply_client else {
            return;
        };
        let mut buf = [0u8; 13];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if r.encode(&mut w).is_ok() {
            send(
                stack,
                self.endpoint,
                Destination::Short {
                    address: client,
                    endpoint,
                },
                metering::ID,
                ext::CMD_SUPPLY_STATUS_RESPONSE,
                Direction::ToClient,
                &buf,
            );
        }
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<MeteringServerEvent> {
        let (origin, payload) =
            command_for(event, self.endpoint, metering::ID, Direction::ToServer)?;
        let origin = *origin;
        let now = utc_now(stack, self.endpoint, &self.clock);
        match origin.header.command {
            metering::CMD_GET_PROFILE => {
                let Ok(req) = GetProfile::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let (end, status, intervals, period) =
                    match self.profiles.iter().find(|p| p.channel == req.channel) {
                        Some(p) => {
                            let (e, s, iv) = p.get(&req);
                            (e, s, iv, p.period)
                        }
                        None => (
                            req.end_time,
                            if req.channel > 3 {
                                ProfileStatus::UndefinedChannel
                            } else {
                                ProfileStatus::ChannelNotSupported
                            },
                            Vec::new(),
                            self.profiles
                                .first()
                                .map_or(IntervalPeriod::Minutes30, |p| p.period),
                        ),
                    };
                let mut buf = [0u8; 7 + 3 * MAX_PERIODS_DELIVERED];
                let mut w = panweave_codec::Writer::new(&mut buf);
                if GetProfileResponse::encode(&mut w, end, status, period.raw(), &intervals).is_ok()
                {
                    let n = w.position();
                    reply(
                        stack,
                        &origin,
                        metering::CMD_GET_PROFILE_RESPONSE,
                        buf.get(..n).unwrap_or(&[]),
                    );
                }
                Some(MeteringServerEvent::ProfileRequested {
                    client: origin.src,
                    status,
                })
            }
            ext::CMD_REQUEST_FAST_POLL_MODE => {
                let Ok(req) = RequestFastPollMode::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let r = self.fast_poll.request(&req, now);
                let mut buf = [0u8; 5];
                let mut w = panweave_codec::Writer::new(&mut buf);
                if r.encode(&mut w).is_ok() {
                    reply(
                        stack,
                        &origin,
                        ext::CMD_REQUEST_FAST_POLL_MODE_RESPONSE,
                        &buf,
                    );
                }
                Some(MeteringServerEvent::FastPoll {
                    client: origin.src,
                    period: r.applied_update_period,
                    end: r.end_time,
                })
            }
            ext::CMD_START_SAMPLING => {
                let Ok(req) = StartSampling::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                match self.sampler.start(&req, now) {
                    Some(r) => {
                        let mut buf = [0u8; 2];
                        let mut w = panweave_codec::Writer::new(&mut buf);
                        if r.encode(&mut w).is_ok() {
                            reply(stack, &origin, ext::CMD_START_SAMPLING_RESPONSE, &buf);
                        }
                        Some(MeteringServerEvent::SamplingStarted {
                            sample_id: r.sample_id,
                            sample_type: req.sample_type,
                        })
                    }
                    None => {
                        default_response(stack, &origin, ZclStatus::NotFound);
                        None
                    }
                }
            }
            ext::CMD_GET_SAMPLED_DATA => {
                let Ok(req) = GetSampledData::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                match self.sampler.sampled_data(&req) {
                    Some(r) => {
                        let mut buf = [0u8; 11 + 3 * ext::MAX_SAMPLES_PER_COMMAND];
                        let mut w = panweave_codec::Writer::new(&mut buf);
                        if r.encode(&mut w).is_ok() {
                            let n = w.position();
                            reply(
                                stack,
                                &origin,
                                ext::CMD_GET_SAMPLED_DATA_RESPONSE,
                                buf.get(..n).unwrap_or(&[]),
                            );
                        }
                    }
                    None => default_response(stack, &origin, ZclStatus::NotFound),
                }
                None
            }
            ext::CMD_TAKE_SNAPSHOT => {
                let Ok(req) = TakeSnapshot::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let supported = self.snapshot_causes & req.cause != 0 || req.cause == 0;
                let r: TakeSnapshotResponse = self.snapshots.on_take_snapshot(
                    &req,
                    supported,
                    self.snapshot_payload_type,
                    &self.snapshot_payload,
                    now,
                );
                let mut buf = [0u8; 5];
                let mut w = panweave_codec::Writer::new(&mut buf);
                if r.encode(&mut w).is_ok() {
                    reply(stack, &origin, ext::CMD_TAKE_SNAPSHOT_RESPONSE, &buf);
                }
                (r.confirmation == ext::snapshot_confirmation::ACCEPTED).then_some(
                    MeteringServerEvent::SnapshotTaken {
                        snapshot_id: r.snapshot_id,
                        cause: req.cause,
                    },
                )
            }
            ext::CMD_GET_SNAPSHOT => {
                let Ok(req) = GetSnapshot::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let mut out: Vec<PublishSnapshot, 4> = Vec::new();
                match self.snapshots.get(&req, &mut out) {
                    Some(()) => {
                        for p in &out {
                            let mut buf = [0u8; 16 + ext::MAX_SNAPSHOT_PAYLOAD];
                            let mut w = panweave_codec::Writer::new(&mut buf);
                            if p.encode(&mut w).is_ok() {
                                let n = w.position();
                                reply(
                                    stack,
                                    &origin,
                                    ext::CMD_PUBLISH_SNAPSHOT,
                                    buf.get(..n).unwrap_or(&[]),
                                );
                            }
                        }
                    }
                    None => default_response(stack, &origin, ZclStatus::NotFound),
                }
                None
            }
            ext::CMD_CHANGE_SUPPLY => {
                let Ok(cmd) = ChangeSupply::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                self.supply_client = Some((origin.src, origin.src_endpoint));
                match self.supply.change(&cmd, now) {
                    SupplyOutcome::Applied(ack) => {
                        default_response(stack, &origin, ZclStatus::Success);
                        if let Some(r) = ack {
                            self.send_supply_status(stack, &r);
                        }
                        Some(MeteringServerEvent::SupplyChanged {
                            status: self.supply.status,
                        })
                    }
                    SupplyOutcome::Scheduled => {
                        default_response(stack, &origin, ZclStatus::Success);
                        Some(MeteringServerEvent::SupplyScheduled {
                            at: cmd.implementation_time,
                        })
                    }
                    SupplyOutcome::Cancelled => {
                        default_response(stack, &origin, ZclStatus::Success);
                        None
                    }
                    SupplyOutcome::NotFound => {
                        default_response(stack, &origin, ZclStatus::NotFound);
                        None
                    }
                    SupplyOutcome::Unsupported => {
                        default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                        None
                    }
                    SupplyOutcome::NotAuthorized => {
                        default_response(stack, &origin, ZclStatus::NotAuthorized);
                        None
                    }
                }
            }
            ext::CMD_LOCAL_CHANGE_SUPPLY => {
                let Ok(cmd) = LocalChangeSupply::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                match self.supply.local_change(&cmd) {
                    SupplyOutcome::Applied(_) => {
                        default_response(stack, &origin, ZclStatus::Success);
                        Some(MeteringServerEvent::SupplyChanged {
                            status: self.supply.status,
                        })
                    }
                    SupplyOutcome::Unsupported => {
                        default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                        None
                    }
                    _ => {
                        default_response(stack, &origin, ZclStatus::NotAuthorized);
                        None
                    }
                }
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }

    /// Applies a scheduled supply change whose time came, sending the
    /// Supply Status Response when it was asked for.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        _now: Instant,
    ) -> Option<MeteringServerEvent> {
        let now = utc_now(stack, self.endpoint, &self.clock);
        let ack = self.supply.poll(now)?;
        if let Some(r) = ack {
            self.send_supply_status(stack, &r);
        }
        Some(MeteringServerEvent::SupplyChanged {
            status: self.supply.status,
        })
    }

    /// Sends a Request Mirror to the ESI hosting mirrors (a sleepy
    /// meter's request, D.3.2.3.1.2).
    pub fn request_mirror<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        esi: Destination,
    ) -> bool {
        send(
            stack,
            self.endpoint,
            esi,
            metering::ID,
            ext::CMD_REQUEST_MIRROR,
            Direction::ToClient,
            &[],
        )
    }

    /// Asks the ESI to drop the mirror.
    pub fn remove_mirror<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        esi: Destination,
    ) -> bool {
        send(
            stack,
            self.endpoint,
            esi,
            metering::ID,
            ext::CMD_REMOVE_MIRROR,
            Direction::ToClient,
            &[],
        )
    }

    /// Configures the mirror the ESI allocated (Configure Mirror).
    pub fn configure_mirror<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        mirror: Destination,
        cfg: &ConfigureMirror,
    ) -> bool {
        let mut buf = [0u8; 10];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if cfg.encode_wire(&mut w).is_err() {
            return false;
        }
        let n = w.position();
        send(
            stack,
            self.endpoint,
            mirror,
            metering::ID,
            ext::CMD_CONFIGURE_MIRROR,
            Direction::ToClient,
            buf.get(..n).unwrap_or(&[]),
        )
    }
}

/// What a [`MeteringClient`] reports.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MeteringEvent {
    /// A Get Profile Response.
    Profile {
        /// The meter.
        meter: ShortAddress,
        /// End time of the newest interval.
        end_time: u32,
        /// Status.
        status: ProfileStatus,
        /// Interval period.
        period: Option<IntervalPeriod>,
        /// Intervals, newest first.
        intervals: Vec<u32, MAX_PERIODS_DELIVERED>,
    },
    /// The meter granted fast poll mode.
    FastPoll(FastPollModeResponse),
    /// The meter started (or refused, id 0xFFFF) a sampling session.
    SamplingStarted(StartSamplingResponse),
    /// Sampled data arrived.
    SampledData(SampledDataResponse),
    /// The meter answered Take Snapshot.
    SnapshotTaken(TakeSnapshotResponse),
    /// A complete snapshot was assembled from its Publish Snapshot
    /// fragments.
    Snapshot(Snapshot),
    /// A Supply Status Response.
    SupplyStatus(SupplyStatusResponse),
    /// A meter asked this ESI for a mirror and was given `endpoint`
    /// (0xFFFF: none free).
    MirrorRequested {
        /// The meter.
        meter: ShortAddress,
        /// Mirror endpoint.
        endpoint: u16,
    },
    /// A meter's mirror was removed.
    MirrorRemoved {
        /// The meter.
        meter: ShortAddress,
    },
    /// A meter configured its mirror.
    MirrorConfigured {
        /// The meter.
        meter: ShortAddress,
        /// The configuration.
        config: ConfigureMirror,
    },
}

/// The client driver on `endpoint`; `MIRRORS` bounds the mirrors an ESI
/// hosts.
pub struct MeteringClient<const MIRRORS: usize = 4> {
    endpoint: Endpoint,
    /// Publish Snapshot fragments being assembled.
    pub assembler: SnapshotAssembler,
    /// Mirrors hosted (ESI).
    pub mirrors: MirrorTable<MIRRORS>,
    /// Notification schemes this ESI supports for mirrors.
    pub mirror_schemes_supported: bool,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
}

impl<const MIRRORS: usize> MeteringClient<MIRRORS> {
    /// A client hosting mirrors on `mirror_endpoints` (empty for a
    /// device that hosts none).
    pub fn new(endpoint: Endpoint, mirror_endpoints: &'static [u8]) -> Self {
        MeteringClient {
            endpoint,
            assembler: SnapshotAssembler::default(),
            mirrors: MirrorTable::new(mirror_endpoints),
            mirror_schemes_supported: true,
            clock: UtcClock::new(),
        }
    }

    fn request<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        command: panweave_types::CommandId,
        payload: &[u8],
    ) -> bool {
        send(
            stack,
            self.endpoint,
            meter,
            metering::ID,
            command,
            Direction::ToServer,
            payload,
        )
    }

    /// Get Profile.
    pub fn get_profile<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        req: &GetProfile,
    ) -> bool {
        let mut buf = [0u8; 6];
        let mut w = panweave_codec::Writer::new(&mut buf);
        req.encode(&mut w).is_ok() && self.request(stack, meter, metering::CMD_GET_PROFILE, &buf)
    }

    /// Request Fast Poll Mode.
    pub fn request_fast_poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        req: &RequestFastPollMode,
    ) -> bool {
        let mut buf = [0u8; 2];
        let mut w = panweave_codec::Writer::new(&mut buf);
        req.encode(&mut w).is_ok()
            && self.request(stack, meter, ext::CMD_REQUEST_FAST_POLL_MODE, &buf)
    }

    /// Start Sampling.
    pub fn start_sampling<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        req: &StartSampling,
    ) -> bool {
        let mut buf = [0u8; 13];
        let mut w = panweave_codec::Writer::new(&mut buf);
        req.encode(&mut w).is_ok() && self.request(stack, meter, ext::CMD_START_SAMPLING, &buf)
    }

    /// Get Sampled Data.
    pub fn get_sampled_data<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        req: &GetSampledData,
    ) -> bool {
        let mut buf = [0u8; 9];
        let mut w = panweave_codec::Writer::new(&mut buf);
        req.encode(&mut w).is_ok() && self.request(stack, meter, ext::CMD_GET_SAMPLED_DATA, &buf)
    }

    /// Take Snapshot.
    pub fn take_snapshot<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        cause: u32,
    ) -> bool {
        self.request(stack, meter, ext::CMD_TAKE_SNAPSHOT, &cause.to_le_bytes())
    }

    /// Get Snapshot.
    pub fn get_snapshot<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        req: &GetSnapshot,
    ) -> bool {
        let mut buf = [0u8; 13];
        let mut w = panweave_codec::Writer::new(&mut buf);
        req.encode(&mut w).is_ok() && self.request(stack, meter, ext::CMD_GET_SNAPSHOT, &buf)
    }

    /// Change Supply.
    pub fn change_supply<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        cmd: &ChangeSupply,
    ) -> bool {
        let mut buf = [0u8; 18];
        let mut w = panweave_codec::Writer::new(&mut buf);
        cmd.encode(&mut w).is_ok() && self.request(stack, meter, ext::CMD_CHANGE_SUPPLY, &buf)
    }

    /// Local Change Supply.
    pub fn local_change_supply<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        meter: Destination,
        proposed_status: u8,
    ) -> bool {
        self.request(
            stack,
            meter,
            ext::CMD_LOCAL_CHANGE_SUPPLY,
            &[proposed_status],
        )
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<MeteringEvent> {
        let (origin, payload) =
            command_for(event, self.endpoint, metering::ID, Direction::ToClient)?;
        let origin = *origin;
        let ok = |stack: &mut Stack<C, R, S>| default_response(stack, &origin, ZclStatus::Success);
        match origin.header.command {
            metering::CMD_GET_PROFILE_RESPONSE => {
                let Ok(r) = GetProfileResponse::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                ok(stack);
                Some(MeteringEvent::Profile {
                    meter: origin.src,
                    end_time: r.end_time,
                    status: r.status,
                    period: IntervalPeriod::from_raw(r.interval_period),
                    intervals: r.iter().take(MAX_PERIODS_DELIVERED).collect(),
                })
            }
            ext::CMD_REQUEST_FAST_POLL_MODE_RESPONSE => {
                let r = FastPollModeResponse::parse(payload).ok();
                default_response(
                    stack,
                    &origin,
                    if r.is_some() {
                        ZclStatus::Success
                    } else {
                        ZclStatus::MalformedCommand
                    },
                );
                r.map(MeteringEvent::FastPoll)
            }
            ext::CMD_START_SAMPLING_RESPONSE => {
                let r = StartSamplingResponse::parse(payload).ok();
                ok(stack);
                r.map(MeteringEvent::SamplingStarted)
            }
            ext::CMD_GET_SAMPLED_DATA_RESPONSE => {
                let r = SampledDataResponse::parse(payload).ok();
                ok(stack);
                r.map(MeteringEvent::SampledData)
            }
            ext::CMD_TAKE_SNAPSHOT_RESPONSE => {
                let r = TakeSnapshotResponse::parse(payload).ok();
                ok(stack);
                r.map(MeteringEvent::SnapshotTaken)
            }
            ext::CMD_PUBLISH_SNAPSHOT => {
                let Ok(p) = PublishSnapshot::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                ok(stack);
                self.assembler.feed(&p).map(MeteringEvent::Snapshot)
            }
            ext::CMD_SUPPLY_STATUS_RESPONSE => {
                let r = SupplyStatusResponse::parse(payload).ok();
                ok(stack);
                r.map(MeteringEvent::SupplyStatus)
            }
            ext::CMD_REQUEST_MIRROR => {
                let r: RequestMirrorResponse = self.mirrors.request(origin.src.0);
                let mut buf = [0u8; 2];
                let mut w = panweave_codec::Writer::new(&mut buf);
                if r.encode(&mut w).is_ok() {
                    reply(stack, &origin, ext::CMD_REQUEST_MIRROR_RESPONSE, &buf);
                }
                Some(MeteringEvent::MirrorRequested {
                    meter: origin.src,
                    endpoint: r.endpoint,
                })
            }
            ext::CMD_REMOVE_MIRROR => {
                let removed: Option<MirrorRemoved> = self
                    .mirrors
                    .mirrors()
                    .iter()
                    .find(|m| m.meter == origin.src.0)
                    .map(|m| m.endpoint)
                    .and_then(|ep| self.mirrors.remove(origin.src.0, ep));
                match removed {
                    Some(r) => {
                        let mut buf = [0u8; 2];
                        let mut w = panweave_codec::Writer::new(&mut buf);
                        if r.encode(&mut w).is_ok() {
                            reply(stack, &origin, ext::CMD_MIRROR_REMOVED, &buf);
                        }
                        Some(MeteringEvent::MirrorRemoved { meter: origin.src })
                    }
                    None => {
                        default_response(stack, &origin, ZclStatus::NotFound);
                        None
                    }
                }
            }
            ext::CMD_CONFIGURE_MIRROR => {
                let Ok(cfg) = ConfigureMirror::parse_wire(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let accepted =
                    self.mirrors
                        .configure(origin.endpoint.0, &cfg, self.mirror_schemes_supported);
                default_response(
                    stack,
                    &origin,
                    if accepted {
                        ZclStatus::Success
                    } else {
                        ZclStatus::NotFound
                    },
                );
                accepted.then_some(MeteringEvent::MirrorConfigured {
                    meter: origin.src,
                    config: cfg,
                })
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }
}
