//! The device interview: what a device is and how to talk to it, learnt
//! from the device itself.
//!
//! Stages, in order ([`InterviewStage`]):
//!
//! 1. Node descriptor — logical type, receiver-on-when-idle, mains power,
//!    manufacturer code (optional).
//! 2. Active endpoints (mandatory).
//! 3. Simple descriptor of each endpoint (mandatory; an endpoint whose
//!    descriptor cannot be read is kept without clusters).
//! 4. Basic attributes: ManufacturerName and ModelIdentifier, then
//!    SWBuildID and PowerSource.
//! 5. IAS Zone, when an endpoint serves it: ZoneState, ZoneType,
//!    ZoneStatus and IAS_CIE_Address are read; the hub's address is
//!    written when it is not the CIE yet; a Zone Enroll Request is
//!    answered when it comes ([`Hub::on_stack_event`]), and after
//!    [`HubConfig::enroll_wait`] without one the zone is enrolled with an
//!    unsolicited Zone Enroll Response (the Auto-Enroll-Response method of
//!    ZCL8 §8.2.2.1.3); ZoneState is read back to confirm.
//! 6. Bind_req of each reportable cluster to the hub's endpoint.
//! 7. Configure Reporting of those clusters' attributes.
//! 8. Reads of the current state.
//!
//! Every request has [`HubConfig::response_timeout`] to be answered and
//! [`HubConfig::max_attempts`] attempts. A sleepy device receives
//! requests only when it polls, so silence is not failure: a mandatory
//! stage that runs out of attempts *stalls* the interview, which resumes
//! as soon as the device is heard again; an optional step that runs out
//! is skipped and the interview finishes as partial.
//!
//! [`HubConfig::enroll_wait`]: crate::HubConfig::enroll_wait
//! [`HubConfig::response_timeout`]: crate::HubConfig::response_timeout
//! [`HubConfig::max_attempts`]: crate::HubConfig::max_attempts

use heapless::Vec;
use panweave_codec::{Decode, Reader};
use panweave_runtime::Stack;
use panweave_security::cipher::BlockCipher;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{CryptoRng, LogicalDeviceType, ShortAddress};
use panweave_zcl::FrameType;
use panweave_zcl::global::{
    ConfigureReportingStatus, DefaultResponse, Records, WriteAttributeStatus, command as global,
};
use panweave_zdo::descriptor::SimpleDescriptor;
use panweave_zdo::zdp::{
    ActiveEpReq, EndpointListRsp, NodeDescReq, NodeDescRsp, SimpleDescReq, SimpleDescRsp,
    StatusRsp, cluster as zdp,
};

use crate::diag::{Category, DiagRecord, Severity, code};
use crate::hub::{Hub, Owner, Reply, SLEEPY_SPACING, Wait};
use crate::model::{InterviewStage, InterviewStatus, LogicalType, PowerSource};
use crate::protocol::{EndpointDescriptor, ErrorCode, Event, ZoneInfo};
use crate::registry::{Device, Interview, NO_SHORT, cluster, talks_zcl};
use crate::zcl::{self, ias_attr, ias_cmd};

/// What an interview step does.
enum Step {
    /// A request went out: await it.
    Sent(Wait),
    /// The step needs nothing: go to the next step now.
    Next,
    /// Go to the next step at the instant.
    NextAt(Instant),
    /// The stage is complete.
    Advance,
    /// The stack could not take the request: try again shortly.
    Busy,
    /// Go back to an earlier step of the stage at the instant.
    Goto(u8, Instant),
}

/// Unsolicited Zone Enroll Responses sent when the read-back shows the
/// zone still unenrolled.
const ENROLL_RETRIES: u8 = 2;

/// Reportable clusters the device serves, with their endpoints.
fn report_list(d: &Device) -> Vec<(u8, u16), 8> {
    let mut l = Vec::new();
    for c in zcl::TRACKED {
        if zcl::reports_of(c).is_empty() {
            continue;
        }
        if let Some(ep) = d.endpoint_serving(c) {
            let _ = l.push((ep, c));
        }
    }
    l
}

/// Clusters whose state is read at the end of the interview (the IAS
/// zone's was read by its own stage).
fn state_list(d: &Device) -> Vec<(u8, u16), 8> {
    let mut l = Vec::new();
    for c in zcl::TRACKED {
        if c == cluster::IAS_ZONE || zcl::state_attributes(c).is_empty() {
            continue;
        }
        if let Some(ep) = d.endpoint_serving(c) {
            let _ = l.push((ep, c));
        }
    }
    l
}

const fn uses_zdp(stage: InterviewStage) -> bool {
    matches!(
        stage,
        InterviewStage::NodeDescriptor
            | InterviewStage::ActiveEndpoints
            | InterviewStage::SimpleDescriptors
            | InterviewStage::Bindings
    )
}

/// Stages made of several steps (a failed step skips to the next one).
const fn has_steps(stage: InterviewStage) -> bool {
    matches!(
        stage,
        InterviewStage::SimpleDescriptors
            | InterviewStage::BasicAttributes
            | InterviewStage::IasZone
            | InterviewStage::Bindings
            | InterviewStage::Reporting
            | InterviewStage::InitialState
    )
}

/// The `arg` of interview records: the stage code and the step.
pub(crate) fn stage_arg(d: &Device) -> u32 {
    (u32::from(d.interview.stage.code()) << 8) | u32::from(d.interview.step)
}

/// The endpoint and cluster the current step addresses (the ZDP request
/// cluster for descriptor stages).
fn step_target(d: &Device) -> (Option<u8>, u16) {
    let step = usize::from(d.interview.step);
    match d.interview.stage {
        InterviewStage::NodeDescriptor => (None, zdp::NODE_DESC_REQ.0),
        InterviewStage::ActiveEndpoints => (None, zdp::ACTIVE_EP_REQ.0),
        InterviewStage::SimpleDescriptors => (
            d.endpoints.get(step).map(|e| e.endpoint),
            zdp::SIMPLE_DESC_REQ.0,
        ),
        InterviewStage::BasicAttributes => (d.endpoint_serving(cluster::BASIC), cluster::BASIC),
        InterviewStage::IasZone => (d.zone.map(|z| z.endpoint), cluster::IAS_ZONE),
        InterviewStage::Bindings | InterviewStage::Reporting => report_list(d)
            .get(step)
            .map_or((None, 0), |&(ep, c)| (Some(ep), c)),
        InterviewStage::InitialState => state_list(d)
            .get(step)
            .map_or((None, 0), |&(ep, c)| (Some(ep), c)),
        InterviewStage::Done => (None, 0),
    }
}

impl<HS: Storage> Hub<HS> {
    /// Logs an interview record for device `i` with its stage and step.
    fn log_interview(
        &mut self,
        i: usize,
        which: u16,
        severity: Severity,
        extra: impl FnOnce(DiagRecord) -> DiagRecord,
    ) {
        if !self.trace_wants(Category::Interview, severity) {
            return;
        }
        let Some(d) = self.registry.at(i) else {
            return;
        };
        let rec = DiagRecord::new(Category::Interview, severity, which)
            .ieee(d.ieee)
            .short(d.short)
            .arg(stage_arg(d));
        self.log(extra(rec));
    }

    /// Restarts a device's interview from the node descriptor.
    pub(crate) fn restart_interview(&mut self, ieee: u64) -> Result<(), ErrorCode> {
        let now = self.now;
        let d = self
            .registry
            .get_mut(ieee)
            .ok_or(ErrorCode::UnknownDevice)?;
        if !d.present || d.short == NO_SHORT {
            return Err(ErrorCode::Unreachable);
        }
        d.interview = Interview {
            status: InterviewStatus::InProgress,
            due: Some(now),
            ..Interview::default()
        };
        d.endpoints.clear();
        d.endpoints_truncated = false;
        d.enroll_answered = false;
        d.enroll_retries = 0;
        d.dirty = true;
        let short = d.short;
        self.pending.retain(|p| p.owner != Owner::Interview(ieee));
        self.schedule_persist();
        self.log(
            DiagRecord::new(Category::Interview, Severity::Info, code::INTERVIEW_STARTED)
                .ieee(ieee)
                .short(short),
        );
        Ok(())
    }

    /// Starts the interview steps that are due.
    pub(crate) fn run_interviews<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
    ) {
        let now = self.now;
        let mut active = self.registry.iter().filter(|d| d.interview.busy).count();
        for i in 0..self.registry.len() {
            if active >= self.config.max_interviews {
                return;
            }
            let Some(d) = self.registry.at(i) else {
                continue;
            };
            let iv = d.interview;
            if iv.status != InterviewStatus::InProgress
                || iv.busy
                || !iv.due.is_some_and(|t| now.has_reached(t))
                || !d.present
                || d.short == NO_SHORT
                || !self.has_room(uses_zdp(iv.stage))
            {
                continue;
            }
            self.interview_step(stack, i);
            if self.registry.at(i).is_some_and(|d| d.interview.busy) {
                active += 1;
            }
        }
    }

    /// Runs device `i`'s interview until a request is out or a wait
    /// begins.
    fn interview_step<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        i: usize,
    ) {
        // Bounded: every iteration advances a step or a stage.
        for _ in 0..64 {
            let now = self.now;
            let step = self.step_action(stack, i);
            let Some(d) = self.registry.at_mut(i) else {
                return;
            };
            let (ieee, short) = (d.ieee, d.short);
            match step {
                Step::Sent(wait) => {
                    d.interview.busy = true;
                    d.interview.due = None;
                    let (ep, cl) = step_target(d);
                    let attempt = d.interview.attempts.saturating_add(1);
                    let tsn = match wait {
                        Wait::Zdp(t) | Wait::Zcl(t) => t,
                    };
                    self.log_interview(i, code::INTERVIEW_REQUEST, Severity::Debug, |r| {
                        let r = r.tsn(tsn).cluster(cl).status(attempt);
                        match ep {
                            Some(e) => r.endpoint(e),
                            None => r,
                        }
                    });
                    if !self.track(Owner::Interview(ieee), short, wait)
                        && let Some(d) = self.registry.at_mut(i)
                    {
                        // Untracked, the answer would be lost: ask again
                        // once a slot is free.
                        d.interview.busy = false;
                        d.interview.due = Some(now.saturating_add(Duration::from_millis(500)));
                    }
                    return;
                }
                Step::Next => {
                    d.interview.step = d.interview.step.saturating_add(1);
                    d.interview.attempts = 0;
                }
                Step::NextAt(t) => {
                    d.interview.step = d.interview.step.saturating_add(1);
                    d.interview.attempts = 0;
                    d.interview.due = Some(t);
                    return;
                }
                Step::Advance => {
                    if !self.advance(i) {
                        return;
                    }
                }
                Step::Busy => {
                    d.interview.due = Some(now.saturating_add(Duration::from_millis(500)));
                    self.log_interview(i, code::INTERVIEW_SEND_DEFERRED, Severity::Debug, |r| r);
                    return;
                }
                Step::Goto(step, t) => {
                    d.interview.step = step;
                    d.interview.due = Some(t);
                    return;
                }
            }
        }
    }

    /// Moves device `i` to its next stage; returns `false` when the
    /// interview finished.
    fn advance(&mut self, i: usize) -> bool {
        let now = self.now;
        let free_zone = self.registry.free_zone_id();
        let Some(d) = self.registry.at_mut(i) else {
            return false;
        };
        let leaving = d.interview.stage;
        if leaving == InterviewStage::SimpleDescriptors {
            // The clusters are known: set up the IAS zone, keeping the
            // identifier and type a previous interview found.
            d.zone = d.endpoint_serving(cluster::IAS_ZONE).map(|endpoint| {
                let old = d.zone;
                ZoneInfo {
                    endpoint,
                    zone_type: old.and_then(|z| z.zone_type),
                    zone_id: old.and_then(|z| z.zone_id).or(free_zone),
                    enrolled: false,
                }
            });
            d.classify();
        }
        d.interview.stage = leaving.next();
        d.interview.step = 0;
        d.interview.attempts = 0;
        d.interview.due = Some(now);
        d.dirty = true;
        let done = d.interview.stage == InterviewStage::Done;
        self.schedule_persist();
        if done {
            self.finish_interview(i);
            return false;
        }
        true
    }

    fn finish_interview(&mut self, i: usize) {
        let now = self.now;
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        d.classify();
        d.interview.status = if d.interview.partial {
            InterviewStatus::Partial
        } else {
            InterviewStatus::Complete
        };
        d.interview.due = None;
        d.needs_sync = false;
        d.last_sync = Some(now);
        d.dirty = true;
        let e = Event::DeviceInterviewCompleted {
            ieee: d.ieee,
            category: d.category,
            capabilities: d.capabilities,
            partial: d.interview.partial,
        };
        let partial = d.interview.partial;
        self.schedule_persist();
        self.log_interview(i, code::INTERVIEW_COMPLETED, Severity::Info, |r| {
            r.status(u8::from(partial))
        });
        self.emit(e);
    }

    /// What device `i`'s current step does, sending its request.
    fn step_action<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        i: usize,
    ) -> Step {
        let Some(d) = self.registry.at(i) else {
            return Step::Busy;
        };
        let short = d.short;
        let addr = ShortAddress(short);
        let step = usize::from(d.interview.step);
        let zdp_sent = |r: Option<u8>| match r {
            Some(seq) => Step::Sent(Wait::Zdp(seq)),
            None => Step::Busy,
        };
        let zcl_sent = |r: Option<u8>| match r {
            Some(seq) => Step::Sent(Wait::Zcl(seq)),
            None => Step::Busy,
        };
        match d.interview.stage {
            InterviewStage::NodeDescriptor => zdp_sent(
                stack
                    .zdp_request(addr, zdp::NODE_DESC_REQ, &NodeDescReq { addr, tlvs: &[] })
                    .ok()
                    .map(|s| s.0),
            ),
            InterviewStage::ActiveEndpoints => zdp_sent(
                stack
                    .zdp_request(addr, zdp::ACTIVE_EP_REQ, &ActiveEpReq { addr })
                    .ok()
                    .map(|s| s.0),
            ),
            InterviewStage::SimpleDescriptors => match d.endpoints.get(step) {
                Some(e) => zdp_sent(
                    stack
                        .zdp_request(
                            addr,
                            zdp::SIMPLE_DESC_REQ,
                            &SimpleDescReq {
                                addr,
                                endpoint: panweave_types::Endpoint(e.endpoint),
                            },
                        )
                        .ok()
                        .map(|s| s.0),
                ),
                None => Step::Advance,
            },
            InterviewStage::BasicAttributes => {
                let ep = d.endpoint_serving(cluster::BASIC).or_else(|| {
                    d.endpoints
                        .iter()
                        .find(|e| talks_zcl(e))
                        .map(|e| e.endpoint)
                });
                match (ep, zcl::BASIC_GROUPS.get(step)) {
                    (Some(ep), Some(attrs)) => {
                        zcl_sent(self.send_read(stack, short, ep, cluster::BASIC, attrs))
                    }
                    _ => Step::Advance,
                }
            }
            InterviewStage::IasZone => self.ias_step(stack, i),
            InterviewStage::Bindings => match report_list(d).get(step) {
                Some(&(ep, c)) => zdp_sent(self.send_bind(stack, d.ieee, short, ep, c)),
                None => Step::Advance,
            },
            InterviewStage::Reporting => match report_list(d).get(step) {
                Some(&(ep, c)) => {
                    let payload = zcl::configure_payload(zcl::reports_of(c));
                    zcl_sent(self.send_global(
                        stack,
                        short,
                        ep,
                        c,
                        global::CONFIGURE_REPORTING,
                        &payload,
                    ))
                }
                None => Step::Advance,
            },
            InterviewStage::InitialState => match state_list(d).get(step) {
                Some(&(ep, c)) => {
                    zcl_sent(self.send_read(stack, short, ep, c, zcl::state_attributes(c)))
                }
                None => Step::Advance,
            },
            InterviewStage::Done => Step::Advance,
        }
    }

    /// The IAS Zone stage's steps: 0 read the zone, 1 write the CIE
    /// address, 2 wait for an enrol request, 3 enrol unsolicited, 4 read
    /// the zone state back.
    fn ias_step<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        i: usize,
    ) -> Step {
        let now = self.now;
        let hub = stack.config.ieee.0;
        let Some(d) = self.registry.at(i) else {
            return Step::Busy;
        };
        let Some(zone) = d.zone else {
            return Step::Advance;
        };
        let short = d.short;
        let ep = zone.endpoint;
        let sent = |r: Option<u8>| match r {
            Some(seq) => Step::Sent(Wait::Zcl(seq)),
            None => Step::Busy,
        };
        match d.interview.step {
            0 => sent(self.send_read(
                stack,
                short,
                ep,
                cluster::IAS_ZONE,
                &[
                    ias_attr::ZONE_STATE,
                    ias_attr::ZONE_TYPE,
                    ias_attr::ZONE_STATUS,
                    ias_attr::CIE_ADDRESS,
                ],
            )),
            1 if d.cie_address == Some(hub) => Step::Next,
            1 => {
                // Write Attributes: IAS_CIE_Address (EUI-64) = the hub.
                let mut p = [0u8; 11];
                p[..2].copy_from_slice(&ias_attr::CIE_ADDRESS.to_le_bytes());
                p[2] = 0xf0;
                p[3..].copy_from_slice(&hub.to_le_bytes());
                sent(self.send_global(
                    stack,
                    short,
                    ep,
                    cluster::IAS_ZONE,
                    global::WRITE_ATTRIBUTES,
                    &p,
                ))
            }
            2 if zone.enrolled || d.enroll_answered => Step::Next,
            2 => Step::NextAt(now.saturating_add(self.config.enroll_wait)),
            3 if zone.enrolled || d.enroll_answered => Step::Next,
            3 => {
                // No Zone Enroll Request came: enrol unsolicited.
                let id = zone.zone_id.unwrap_or(0xff);
                let ieee = d.ieee;
                self.log(
                    DiagRecord::new(
                        Category::IasZone,
                        Severity::Info,
                        code::IAS_ENROLL_UNSOLICITED,
                    )
                    .ieee(ieee)
                    .short(short)
                    .endpoint(ep)
                    .arg(u32::from(id)),
                );
                match self.send_cluster_command(
                    stack,
                    short,
                    ep,
                    cluster::IAS_ZONE,
                    ias_cmd::ENROLL_RESPONSE,
                    &[0x00, id],
                    false,
                ) {
                    Some(_) => Step::NextAt(now.saturating_add(Duration::from_secs(1))),
                    None => Step::Busy,
                }
            }
            4 => sent(self.send_read(
                stack,
                short,
                ep,
                cluster::IAS_ZONE,
                &[ias_attr::ZONE_STATE, ias_attr::ZONE_STATUS],
            )),
            _ => Step::Advance,
        }
    }

    /// An answer (or a timeout) for device `ieee`'s interview request.
    pub(crate) fn interview_reply<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: u64,
        reply: Reply<'_>,
    ) {
        let Some(i) = self.registry.index_of(ieee) else {
            return;
        };
        let now = self.now;
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        d.interview.busy = false;
        let stage = d.interview.stage;
        let step = d.interview.step;
        let outcome = match reply {
            Reply::Timeout => Err((ErrorCode::Timeout, 0)),
            Reply::Zdp(z) => Self::zdp_outcome(d, stage, &z.data),
            Reply::Zcl(f) => Self::zcl_outcome(d, stage, f, now),
        };
        self.log_reply(i, stage, step, reply);
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        match outcome {
            Ok(next) => {
                d.interview.attempts = 0;
                d.interview.due = Some(now);
                match next {
                    Step::Advance => {
                        self.advance(i);
                    }
                    Step::Goto(step, t) => {
                        d.interview.step = step;
                        d.interview.due = Some(t);
                    }
                    _ => d.interview.step = d.interview.step.saturating_add(1),
                }
            }
            Err((error, status)) => self.step_failed(i, error, status),
        }
        self.run_interviews(stack);
    }

    /// Logs an interview answer with its protocol status, and what it
    /// means for IAS enrolment and reporting.
    fn log_reply(&mut self, i: usize, stage: InterviewStage, step: u8, reply: Reply<'_>) {
        let arg = (u32::from(stage.code()) << 8) | u32::from(step);
        match reply {
            Reply::Timeout => {}
            Reply::Zdp(z) => {
                let status = z.data.first().copied().unwrap_or(0xff);
                let severity = if status == 0 {
                    Severity::Debug
                } else {
                    Severity::Warning
                };
                self.log_interview(i, code::INTERVIEW_ANSWER, severity, |r| {
                    r.tsn(z.seq.0).cluster(z.cluster.0).status(status).arg(arg)
                });
            }
            Reply::Zcl(f) => {
                let h = &f.origin.header;
                let status = if h.command == global::DEFAULT_RESPONSE {
                    DefaultResponse::decode_exact(&f.payload).map_or(0xff, |r| r.status.raw())
                } else {
                    0
                };
                let severity = if status == 0 {
                    Severity::Debug
                } else {
                    Severity::Warning
                };
                let (ep, cl, tsn) = (f.origin.src_endpoint.0, f.origin.cluster.0, h.seq.0);
                self.log_interview(i, code::INTERVIEW_ANSWER, severity, |r| {
                    r.tsn(tsn).cluster(cl).endpoint(ep).status(status).arg(arg)
                });
                if stage == InterviewStage::Reporting
                    && h.command == global::CONFIGURE_REPORTING_RESPONSE
                {
                    let ieee = self.registry.at(i).map_or(0, |d| d.ieee);
                    for r in Records::<ConfigureReportingStatus>::new(&f.payload)
                        .map_while(Result::ok)
                        .filter(|r| !r.status.is_success())
                    {
                        let severity = if matches!(r.status.raw(), 0x86 | 0x8c) {
                            Severity::Debug
                        } else {
                            Severity::Warning
                        };
                        let mut rec =
                            DiagRecord::new(Category::Zcl, severity, code::ZCL_REPORTING_REFUSED)
                                .ieee(ieee)
                                .short(f.origin.src.0)
                                .endpoint(ep)
                                .cluster(cl)
                                .tsn(tsn)
                                .status(r.status.raw());
                        if let Some((_, id)) = r.target {
                            rec = rec.arg(u32::from(id.0));
                        }
                        self.log(rec);
                    }
                }
                if stage == InterviewStage::IasZone {
                    self.log_ias_answer(i, step, status, f);
                }
            }
        }
    }

    fn log_ias_answer(&mut self, i: usize, step: u8, status: u8, f: &panweave_runtime::ZclFrame) {
        let Some(d) = self.registry.at(i) else {
            return;
        };
        let zone = d.zone;
        let base = |c: u16, sev: Severity| {
            DiagRecord::new(Category::IasZone, sev, c)
                .ieee(d.ieee)
                .short(d.short)
                .endpoint(f.origin.src_endpoint.0)
                .tsn(f.origin.header.seq.0)
        };
        let rec = match step {
            0 => {
                let mut r = base(code::IAS_ZONE_READ, Severity::Info)
                    .status(u8::from(zone.is_some_and(|z| z.enrolled)));
                if let Some(t) = zone.and_then(|z| z.zone_type) {
                    r = r.arg(u32::from(t));
                }
                r
            }
            1 => {
                let ok = f.origin.header.command == global::WRITE_ATTRIBUTES_RESPONSE
                    && Records::<WriteAttributeStatus>::new(&f.payload)
                        .map_while(Result::ok)
                        .all(|r| r.status.is_success());
                let sev = if ok {
                    Severity::Info
                } else {
                    Severity::Warning
                };
                base(code::IAS_CIE_WRITTEN, sev).status(if ok { 0 } else { status.max(1) })
            }
            4 if zone.is_some_and(|z| z.enrolled) => {
                base(code::IAS_ENROLL_CONFIRMED, Severity::Info)
            }
            4 => base(code::IAS_NOT_ENROLLED, Severity::Warning).status(d.enroll_retries),
            _ => return,
        };
        self.log(rec);
    }

    fn zdp_outcome(
        d: &mut Device,
        stage: InterviewStage,
        data: &[u8],
    ) -> Result<Step, (ErrorCode, u8)> {
        match stage {
            InterviewStage::NodeDescriptor => {
                let rsp = NodeDescRsp::decode(&mut Reader::new(data))
                    .map_err(|_| (ErrorCode::ZdoFailure, 0xff))?;
                let desc = rsp
                    .descriptor
                    .filter(|_| rsp.status.is_success())
                    .ok_or((ErrorCode::ZdoFailure, rsp.status.raw()))?;
                d.logical_type = Some(match desc.logical_type {
                    LogicalDeviceType::Coordinator => LogicalType::Coordinator,
                    LogicalDeviceType::Router => LogicalType::Router,
                    LogicalDeviceType::EndDevice => LogicalType::EndDevice,
                });
                d.rx_on_when_idle = Some(desc.mac_capability.rx_on_when_idle());
                if desc.mac_capability.is_mains_powered()
                    && d.power_source == PowerSource::Unknown
                    && !d.ignores_mac_mains_claim()
                {
                    d.power_source = PowerSource::Mains;
                }
                d.manufacturer_code = Some(desc.manufacturer_code.0);
                d.dirty = true;
                Ok(Step::Advance)
            }
            InterviewStage::ActiveEndpoints => {
                let rsp = EndpointListRsp::decode(&mut Reader::new(data))
                    .map_err(|_| (ErrorCode::ZdoFailure, 0xff))?;
                if !rsp.status.is_success() {
                    return Err((ErrorCode::ZdoFailure, rsp.status.raw()));
                }
                d.endpoints.clear();
                d.endpoints_truncated = false;
                for ep in rsp.iter() {
                    let e = EndpointDescriptor {
                        endpoint: ep.0,
                        ..EndpointDescriptor::default()
                    };
                    if d.endpoints.push(e).is_err() {
                        d.endpoints_truncated = true;
                        d.interview.partial = true;
                    }
                }
                d.dirty = true;
                Ok(Step::Advance)
            }
            InterviewStage::SimpleDescriptors => {
                let index = usize::from(d.interview.step);
                let rsp = SimpleDescRsp::decode(&mut Reader::new(data))
                    .map_err(|_| (ErrorCode::ZdoFailure, 0xff))?;
                let desc = rsp
                    .descriptor
                    .filter(|_| rsp.status.is_success())
                    .and_then(|b| SimpleDescriptor::decode_exact(b).ok());
                let Some(desc) = desc else {
                    // An endpoint without a readable descriptor stays
                    // listed without clusters.
                    d.interview.partial = true;
                    return Ok(Step::Next);
                };
                if let Some(e) = d.endpoints.get_mut(index) {
                    e.profile = desc.profile.0;
                    e.device_id = desc.device.0;
                    e.inputs.clear();
                    e.outputs.clear();
                    for c in &desc.input_clusters {
                        if e.inputs.push(c.0).is_err() {
                            d.endpoints_truncated = true;
                        }
                    }
                    for c in &desc.output_clusters {
                        if e.outputs.push(c.0).is_err() {
                            d.endpoints_truncated = true;
                        }
                    }
                }
                d.dirty = true;
                Ok(Step::Next)
            }
            InterviewStage::Bindings => {
                match StatusRsp::decode(&mut Reader::new(data)) {
                    Ok(s) if s.status.is_success() => {}
                    // NOT_SUPPORTED, TABLE_FULL, …: reports for this
                    // cluster will not come; the interview goes on.
                    _ => d.interview.partial = true,
                }
                Ok(Step::Next)
            }
            // A late answer for an earlier stage: ignore it.
            _ => Ok(Step::Next),
        }
    }

    fn zcl_outcome(
        d: &mut Device,
        stage: InterviewStage,
        f: &panweave_runtime::ZclFrame,
        now: Instant,
    ) -> Result<Step, (ErrorCode, u8)> {
        let h = &f.origin.header;
        if h.control.frame_type != FrameType::Global {
            return Ok(Step::Next);
        }
        if h.command == global::DEFAULT_RESPONSE {
            // A Default Response answering a request is a refusal
            // (unsupported cluster or command): the step cannot succeed.
            let status = DefaultResponse::decode_exact(&f.payload)
                .map(|r| r.status.raw())
                .unwrap_or(0xff);
            if status != 0 {
                d.interview.partial = true;
            }
            return Ok(Step::Next);
        }
        match stage {
            InterviewStage::IasZone if h.command == global::WRITE_ATTRIBUTES_RESPONSE => {
                let ok = Records::<WriteAttributeStatus>::new(&f.payload)
                    .map_while(Result::ok)
                    .all(|r| r.status.is_success());
                if !ok {
                    d.interview.partial = true;
                }
            }
            InterviewStage::IasZone
                if d.interview.step == 4 && !d.zone.is_some_and(|z| z.enrolled) =>
            {
                // Read back: not enrolled. The response may have been
                // lost on the way to a sleepy device: enrol again
                // (unsolicited) a few times before giving up. Notifications
                // may still come (some zones notify without enrolment) but
                // the CIE side is then not confirmed.
                if d.enroll_retries < ENROLL_RETRIES {
                    d.enroll_retries += 1;
                    d.enroll_answered = false;
                    return Ok(Step::Goto(3, now.saturating_add(SLEEPY_SPACING)));
                }
                d.interview.partial = true;
            }
            InterviewStage::Reporting => {
                // An attribute the device does not have or cannot report
                // (UNSUPPORTED_ATTRIBUTE, UNREPORTABLE_ATTRIBUTE) is not a
                // failure: the hub asks for every attribute it could use.
                let failed = Records::<ConfigureReportingStatus>::new(&f.payload)
                    .map_while(Result::ok)
                    .any(|r| !r.status.is_success() && !matches!(r.status.raw(), 0x86 | 0x8c));
                if failed {
                    d.interview.partial = true;
                }
            }
            // Read responses were applied to the device on arrival.
            _ => {}
        }
        Ok(Step::Next)
    }

    /// A step failed: retry, skip it, or stall the interview.
    fn step_failed(&mut self, i: usize, error: ErrorCode, status: u8) {
        let now = self.now;
        let max = self.config.max_attempts;
        let retry_delay = self.config.retry_delay;
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        d.interview.attempts = d.interview.attempts.saturating_add(1);
        let attempts = d.interview.attempts;
        let stage = d.interview.stage;
        if error == ErrorCode::Timeout {
            let (ep, cl) = step_target(d);
            self.log_interview(i, code::INTERVIEW_TIMEOUT, Severity::Warning, |r| {
                let r = r.cluster(cl).status(attempts);
                match ep {
                    Some(e) => r.endpoint(e),
                    None => r,
                }
            });
        }
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        if error == ErrorCode::Timeout && d.interview.attempts < max {
            d.interview.due = Some(now.saturating_add(retry_delay));
            return;
        }
        self.counters.interview_failures = self.counters.interview_failures.saturating_add(1);
        if stage.is_mandatory() {
            d.interview.status = InterviewStatus::Stalled;
            d.interview.due = None;
            d.dirty = true;
            let ieee = d.ieee;
            self.schedule_persist();
            self.log_interview(i, code::INTERVIEW_STALLED, Severity::Error, |r| {
                r.status(if error == ErrorCode::Timeout {
                    0xff
                } else {
                    status
                })
            });
            self.emit(Event::DeviceInterviewFailed { ieee, stage, error });
            return;
        }
        self.log_interview(i, code::INTERVIEW_STEP_SKIPPED, Severity::Warning, |r| {
            r.status(if error == ErrorCode::Timeout {
                0xff
            } else {
                status
            })
        });
        let Some(d) = self.registry.at_mut(i) else {
            return;
        };
        d.interview.partial = true;
        d.interview.attempts = 0;
        d.interview.due = Some(now);
        if has_steps(stage) {
            d.interview.step = d.interview.step.saturating_add(1);
        } else {
            self.advance(i);
        }
    }
}
