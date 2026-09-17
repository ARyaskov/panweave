//! Demand Response and Load Control drivers (SE 1.4a Annex D.2): the
//! client scheduling the events it is addressed by and reporting their
//! status back to the issuing ESI, and the server issuing events and
//! answering Get Scheduled Events.

use heapless::Vec;
use panweave_aps::layer::Destination;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_smart_energy::clusters::drlc::{
    self, CancelLoadControlEvent, EventStore, GetScheduledEvents, LoadControlEvent, Report,
    ReportEventStatus, Scheduled, Scheduler, report_delay_ms,
};
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{CryptoRng, Endpoint, ShortAddress};
use panweave_zcl::frame::Direction;
use panweave_zcl::{Role, ZclStatus};

use super::{UtcClock, command_for, default_response, reply, send, utc_now};

/// Reports waiting for their 0–5 s delay.
const PENDING_REPORTS: usize = 8;

/// What a [`DrlcClient`] reports.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DrlcEvent {
    /// Statuses changed (received, started, completed, cancelled, opted
    /// out …), in order; each Report Event Status goes to the server
    /// after its random delay. Inspect [`DrlcClient::scheduler`] for the
    /// load to shed.
    Status(Vec<Report, 8>),
}

#[derive(Clone, Copy, Debug)]
struct PendingReport {
    at: Instant,
    to: ShortAddress,
    to_endpoint: Endpoint,
    report: ReportEventStatus,
}

/// The client driver on `endpoint`, holding up to `N` events.
pub struct DrlcClient<const N: usize = 8> {
    endpoint: Endpoint,
    /// The scheduled and active events.
    pub scheduler: Scheduler<N>,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
    /// The server reports go to when the event's origin is unknown
    /// (opt-outs, polls): the last issuing ESI, else the bindings.
    server: Option<(ShortAddress, Endpoint)>,
    pending: Vec<PendingReport, PENDING_REPORTS>,
}

impl<const N: usize> DrlcClient<N> {
    /// A client for a device of `device_class` bits.
    pub const fn new(endpoint: Endpoint, device_class: u16) -> Self {
        DrlcClient {
            endpoint,
            scheduler: Scheduler::new(device_class),
            clock: UtcClock::new(),
            server: None,
            pending: Vec::new(),
        }
    }

    /// Copies the writable client attributes (`UtilityEnrollmentGroup`,
    /// the randomization minutes, `DeviceClassValue`) from the cluster
    /// instance into the scheduler, so that a Trust Center's writes take
    /// effect.
    fn sync_attributes<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
    ) {
        let Some(c) = stack
            .zcl
            .endpoint(self.endpoint)
            .and_then(|e| e.cluster(drlc::ID, Role::Client))
        else {
            return;
        };
        if let Some(g) = c.u8(drlc::UTILITY_ENROLLMENT_GROUP.id) {
            self.scheduler.enrollment_group = g;
        }
        if let Some(m) = c.u8(drlc::START_RANDOMIZATION_MINUTES.id) {
            self.scheduler.start_randomization_minutes = m;
        }
        if let Some(m) = c.u8(drlc::DURATION_RANDOMIZATION_MINUTES.id) {
            self.scheduler.duration_randomization_minutes = m;
        }
        if let Some(d) = c.u16(drlc::DEVICE_CLASS_VALUE.id) {
            self.scheduler.device_class = d;
        }
    }

    fn queue_reports<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        reports: &[Report],
        to: (ShortAddress, Endpoint),
        now: u32,
    ) -> Option<DrlcEvent> {
        if reports.is_empty() {
            return None;
        }
        let mut out: Vec<Report, 8> = Vec::new();
        for r in reports {
            let delay = report_delay_ms(|n| stack.nwk.rng().next_u32() % n);
            let report = status_report(r, now);
            let p = PendingReport {
                at: stack.now() + Duration::from_millis(u64::from(delay)),
                to: to.0,
                to_endpoint: to.1,
                report,
            };
            if self.pending.push(p).is_err() {
                self.pending.remove(0);
                let _ = self.pending.push(p);
            }
            let _ = out.push(*r);
        }
        Some(DrlcEvent::Status(out))
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<DrlcEvent> {
        let (origin, payload) = command_for(event, self.endpoint, drlc::ID, Direction::ToClient)?;
        let origin = *origin;
        self.sync_attributes(stack);
        let now = utc_now(stack, self.endpoint, &self.clock);
        let server = (origin.src, origin.src_endpoint);
        self.server = Some(server);
        match origin.header.command {
            drlc::CMD_LOAD_CONTROL_EVENT => {
                let Ok(e) = LoadControlEvent::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let reports = self.scheduler.on_event(&e, now, |max| {
                    u8::try_from(stack.nwk.rng().next_u32() % (u32::from(max) + 1)).unwrap_or(0)
                });
                default_response(stack, &origin, ZclStatus::Success);
                let reports = reports?;
                self.queue_reports(stack, &reports, server, now)
            }
            drlc::CMD_CANCEL_LOAD_CONTROL_EVENT => {
                let Ok(c) = CancelLoadControlEvent::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let report = self.scheduler.on_cancel(&c, now);
                default_response(
                    stack,
                    &origin,
                    if report.is_some() {
                        ZclStatus::Success
                    } else {
                        ZclStatus::NotFound
                    },
                );
                let r = report?;
                self.queue_reports(stack, &[r], server, now)
            }
            drlc::CMD_CANCEL_ALL_LOAD_CONTROL_EVENTS => {
                let use_randomization = payload.first().is_some_and(|b| b & 0x01 != 0);
                let reports = self.scheduler.on_cancel_all(use_randomization, now);
                default_response(stack, &origin, ZclStatus::Success);
                self.queue_reports(stack, &reports, server, now)
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }

    /// The user opts out of (or back into) an event.
    pub fn set_opt_out<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        issuer_event_id: u32,
        opt_out: bool,
    ) -> Option<DrlcEvent> {
        let now = utc_now(stack, self.endpoint, &self.clock);
        let r = self.scheduler.set_opt_out(issuer_event_id, opt_out, now)?;
        let server = self.server?;
        self.queue_reports(stack, &[r], server, now)
    }

    /// Asks `server` for its scheduled events (Get Scheduled Events).
    pub fn request_scheduled_events<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        server: Destination,
        req: &GetScheduledEvents,
    ) -> bool {
        let mut buf = [0u8; 9];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if req.encode(&mut w).is_err() {
            return false;
        }
        let n = w.position();
        send(
            stack,
            self.endpoint,
            server,
            drlc::ID,
            drlc::CMD_GET_SCHEDULED_EVENTS,
            Direction::ToServer,
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Starts and completes events whose time came and sends the
    /// reports whose delay elapsed.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        now: Instant,
    ) -> Option<DrlcEvent> {
        let utc = utc_now(stack, self.endpoint, &self.clock);
        let reports = self.scheduler.poll(utc);
        let event = match self.server {
            Some(server) => self.queue_reports(stack, &reports, server, utc),
            None if reports.is_empty() => None,
            None => Some(DrlcEvent::Status(reports.iter().copied().take(8).collect())),
        };
        let mut i = 0;
        while i < self.pending.len() {
            if now.has_reached(self.pending.get(i).map_or(now, |p| p.at)) {
                let p = self.pending.remove(i);
                let mut buf = [0u8; ReportEventStatus::LEN];
                let mut w = panweave_codec::Writer::new(&mut buf);
                if p.report.encode(&mut w).is_ok() {
                    send(
                        stack,
                        self.endpoint,
                        Destination::Short {
                            address: p.to,
                            endpoint: p.to_endpoint,
                        },
                        drlc::ID,
                        drlc::CMD_REPORT_EVENT_STATUS,
                        Direction::ToServer,
                        &buf,
                    );
                }
            } else {
                i += 1;
            }
        }
        event
    }

    /// The earliest time [`Self::poll`] has something to do (a pending
    /// report; event boundaries are checked at every poll).
    pub fn deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .map(|p| p.at)
            .min_by_key(|t| t.as_millis())
    }

    /// The running event the device should shed for, if any.
    pub fn active(&self) -> Option<&Scheduled> {
        self.scheduler.active()
    }
}

/// The Report Event Status for `r` at `now`, carrying the applied
/// values of the event when known (D.2.3.3.1).
fn status_report(r: &Report, now: u32) -> ReportEventStatus {
    let mut s = ReportEventStatus::new(r.issuer_event_id, r.status, now);
    if let Some(e) = r.event {
        s.criticality_level_applied = e.criticality_level;
        s.cooling_temperature_set_point_applied = e.cooling_temperature_set_point;
        s.heating_temperature_set_point_applied = e.heating_temperature_set_point;
        s.average_load_adjustment_percentage_applied = e.average_load_adjustment_percentage;
        s.duty_cycle_applied = e.duty_cycle;
        s.event_control = e.event_control;
    }
    s
}

/// What a [`DrlcServer`] reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DrlcServerEvent {
    /// A client reported an event status.
    Status {
        /// The client.
        client: ShortAddress,
        /// The report.
        report: ReportEventStatus,
    },
    /// A client asked for the scheduled events and got `count` of them
    /// (NOT_FOUND when zero).
    ScheduledEventsRequested {
        /// The client.
        client: ShortAddress,
        /// Events sent.
        count: usize,
    },
}

/// Device class and enrollment group of a client, as learnt by the ESI
/// (by reading its attributes); unknown clients get every event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClientProfile {
    /// The client.
    pub client: ShortAddress,
    /// `DeviceClassValue`.
    pub device_class: u16,
    /// `UtilityEnrollmentGroup`.
    pub enrollment_group: u8,
}

/// The server driver on `endpoint`, holding up to `N` events.
pub struct DrlcServer<const N: usize = 16> {
    endpoint: Endpoint,
    /// The issued events.
    pub store: EventStore<N>,
    /// UTC reference when the endpoint has no Time server.
    pub clock: UtcClock,
    clients: Vec<ClientProfile, 8>,
}

impl<const N: usize> DrlcServer<N> {
    /// A server with no events.
    pub const fn new(endpoint: Endpoint) -> Self {
        DrlcServer {
            endpoint,
            store: EventStore::new(),
            clock: UtcClock::new(),
            clients: Vec::new(),
        }
    }

    /// Records what a client is (for Get Scheduled Events filtering).
    pub fn set_client_profile(&mut self, profile: ClientProfile) {
        if let Some(p) = self.clients.iter_mut().find(|p| p.client == profile.client) {
            *p = profile;
        } else if self.clients.push(profile).is_err() {
            self.clients.remove(0);
            let _ = self.clients.push(profile);
        }
    }

    fn profile_of(&self, client: ShortAddress) -> (u16, u8) {
        self.clients
            .iter()
            .find(|p| p.client == client)
            .map_or((0xFFFF, 0), |p| (p.device_class, p.enrollment_group))
    }

    /// Issues `event` (a start time of 0 is resolved to now) to
    /// `clients`.
    pub fn issue<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        clients: Destination,
        event: LoadControlEvent,
    ) -> bool {
        let now = utc_now(stack, self.endpoint, &self.clock);
        if !self.store.issue(event, now) {
            return false;
        }
        let mut buf = [0u8; LoadControlEvent::LEN];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if event.encode(&mut w).is_err() {
            return false;
        }
        send(
            stack,
            self.endpoint,
            clients,
            drlc::ID,
            drlc::CMD_LOAD_CONTROL_EVENT,
            Direction::ToClient,
            &buf,
        )
    }

    /// Cancels an event at `clients`.
    pub fn cancel<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        clients: Destination,
        cancel: &CancelLoadControlEvent,
    ) -> bool {
        self.store.cancel(cancel.issuer_event_id);
        let mut buf = [0u8; 12];
        let mut w = panweave_codec::Writer::new(&mut buf);
        if cancel.encode(&mut w).is_err() {
            return false;
        }
        send(
            stack,
            self.endpoint,
            clients,
            drlc::ID,
            drlc::CMD_CANCEL_LOAD_CONTROL_EVENT,
            Direction::ToClient,
            &buf,
        )
    }

    /// Cancels every event at `clients`.
    pub fn cancel_all<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        clients: Destination,
        use_randomization: bool,
    ) -> bool {
        self.store.cancel_all();
        send(
            stack,
            self.endpoint,
            clients,
            drlc::ID,
            drlc::CMD_CANCEL_ALL_LOAD_CONTROL_EVENTS,
            Direction::ToClient,
            &[u8::from(use_randomization)],
        )
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<DrlcServerEvent> {
        let (origin, payload) = command_for(event, self.endpoint, drlc::ID, Direction::ToServer)?;
        let origin = *origin;
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.store.expire(now);
        match origin.header.command {
            drlc::CMD_REPORT_EVENT_STATUS => {
                let Ok(report) = ReportEventStatus::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                default_response(stack, &origin, ZclStatus::Success);
                Some(DrlcServerEvent::Status {
                    client: origin.src,
                    report,
                })
            }
            drlc::CMD_GET_SCHEDULED_EVENTS => {
                let Ok(req) = GetScheduledEvents::parse(payload) else {
                    default_response(stack, &origin, ZclStatus::MalformedCommand);
                    return None;
                };
                let (class, group) = self.profile_of(origin.src);
                let mut events: Vec<LoadControlEvent, N> = Vec::new();
                self.store.scheduled(&req, now, class, group, &mut events);
                if events.is_empty() {
                    default_response(stack, &origin, ZclStatus::NotFound);
                } else {
                    for e in &events {
                        let mut buf = [0u8; LoadControlEvent::LEN];
                        let mut w = panweave_codec::Writer::new(&mut buf);
                        if e.encode(&mut w).is_ok() {
                            reply(stack, &origin, drlc::CMD_LOAD_CONTROL_EVENT, &buf);
                        }
                    }
                }
                Some(DrlcServerEvent::ScheduledEventsRequested {
                    client: origin.src,
                    count: events.len(),
                })
            }
            _ => {
                default_response(stack, &origin, ZclStatus::UnsupportedClusterCommand);
                None
            }
        }
    }

    /// Drops completed events.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        _now: Instant,
    ) {
        let now = utc_now(stack, self.endpoint, &self.clock);
        self.store.expire(now);
    }
}
