//! One delivery attempt: hand the radio from IEEE 802.15.4 to Wi-Fi,
//! send the request, and hand it back — under one shared deadline.
//!
//! The firmware implements [`RadioSwitch`] and [`Network`]; [`run`]
//! orders the stages, checks the deadline before each, records every
//! stage's duration, and **always** stops Wi-Fi and restores IEEE
//! 802.15.4 reception, whatever happened (success, failure, cancellation,
//! timeout). Downtime is measured from the start of
//! [`RadioSwitch::suspend_zigbee`] (reception is lost there) to the end
//! of a successful [`RadioSwitch::resume_zigbee`].
//!
//! The network stages share `deadline.network_end = start + budget −
//! reserve`: the reserve is kept for Wi-Fi shutdown and the 802.15.4
//! restoration. A stage receives the deadline and must return by it; a
//! stage that blocks longer (a driver call that cannot be interrupted)
//! is not hidden — its real duration is recorded and the attempt is
//! reported over budget.

use crate::protocol::AlertStage;
use crate::protocol::alerts::STAGES;

/// Time kept from the budget for Wi-Fi shutdown and the 802.15.4
/// restoration, milliseconds.
pub const RESTORE_RESERVE_MS: u32 = 300;
/// Attempts at restoring 802.15.4 reception before giving up.
pub const RESTORE_TRIES: u8 = 3;

/// A monotonic millisecond clock.
pub trait Clock {
    /// Milliseconds since an arbitrary origin.
    fn now_ms(&mut self) -> u64;
}

/// The radio could not be released or restored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RadioSwitchError;

/// Hands the shared radio between IEEE 802.15.4 and Wi-Fi.
pub trait RadioSwitch {
    /// Stops 802.15.4 reception and releases every radio resource the
    /// 802.15.4 driver holds, so that Wi-Fi may initialize. The Zigbee
    /// stack's state (keys, counters, tables) is not touched.
    ///
    /// # Errors
    ///
    /// When the radio could not be released; nothing else is attempted.
    fn suspend_zigbee(&mut self) -> Result<(), RadioSwitchError>;

    /// Re-initializes the 802.15.4 driver with the stack's configuration
    /// (channel, PAN, addresses) and restarts reception.
    ///
    /// # Errors
    ///
    /// When reception could not be restored.
    fn resume_zigbee(&mut self) -> Result<(), RadioSwitchError>;
}

/// Why a network stage failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetError {
    /// The stage failed (refused, not found, verification failure…).
    Failed,
    /// The stage ran out of time.
    Timeout,
}

/// The attempt's shared deadline (monotonic milliseconds).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Deadline {
    /// When the attempt started (802.15.4 reception stopped).
    pub start: u64,
    /// When the network stages must have ended.
    pub network_end: u64,
    /// When 802.15.4 reception must be back (`start + budget`).
    pub end: u64,
}

impl Deadline {
    /// Milliseconds left for network work at `now`.
    pub fn network_remaining(&self, now: u64) -> u64 {
        self.network_end.saturating_sub(now)
    }
}

/// The network side of an attempt, stage by stage. Every stage must
/// honour `deadline.network_end`.
pub trait Network {
    /// Starts the Wi-Fi driver.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn wifi_start(&mut self, deadline: Deadline) -> Result<(), NetError>;
    /// Finds and joins the access point (WPA2 handshake).
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn associate(&mut self, deadline: Deadline) -> Result<(), NetError>;
    /// Obtains an address (DHCP or a static configuration).
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn obtain_ip(&mut self, deadline: Deadline) -> Result<(), NetError>;
    /// Resolves `host`.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn resolve(&mut self, host: &str, deadline: Deadline) -> Result<[u8; 4], NetError>;
    /// Opens a TCP connection.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn connect(&mut self, addr: [u8; 4], port: u16, deadline: Deadline) -> Result<(), NetError>;
    /// TLS handshake, verifying the certificate chain and that it names
    /// `host`.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn tls_handshake(&mut self, host: &str, deadline: Deadline) -> Result<(), NetError>;
    /// Sends the request. Once called, the server may have received it.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn send(&mut self, request: &[u8], deadline: Deadline) -> Result<(), NetError>;
    /// Receives the complete response into `buf`; returns its length.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn receive(&mut self, buf: &mut [u8], deadline: Deadline) -> Result<usize, NetError>;
    /// Closes everything and stops the Wi-Fi driver, releasing the radio.
    /// Called after every attempt, including when `wifi_start` failed.
    fn wifi_stop(&mut self);
    /// Surveys the access points in range (the radio-switch experiment
    /// only, between `wifi_start` and `associate`). The firmware keeps
    /// what it heard; a failure does not end the experiment. The default
    /// does nothing.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    fn scan(&mut self, _deadline: Deadline) -> Result<(), NetError> {
        Ok(())
    }
}

/// How an attempt ended (before the response is interpreted).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// A response of this many octets.
    Response(usize),
    /// A stage before the request failed: nothing was sent.
    Failed {
        /// The stage.
        stage: AlertStage,
        /// It timed out (rather than failed).
        timed_out: bool,
    },
    /// The deadline expired before `stage`: nothing was sent.
    Cancelled {
        /// The stage that was not started.
        stage: AlertStage,
    },
    /// The request may have been received but no complete response came.
    Ambiguous {
        /// The stage that failed or was cancelled.
        stage: AlertStage,
    },
    /// The radio could not be released from 802.15.4.
    SuspendFailed,
}

/// What an attempt did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    /// How it ended.
    pub outcome: Outcome,
    /// Duration of each stage (`None`: not reached).
    pub stage_ms: [Option<u32>; STAGES],
    /// Zigbee downtime, milliseconds.
    pub downtime_ms: u32,
    /// 802.15.4 reception was restored.
    pub restored: bool,
    /// The budget the attempt ran with.
    pub budget_ms: u32,
}

impl Report {
    /// The downtime exceeded the budget.
    pub const fn over_budget(&self) -> bool {
        self.downtime_ms > self.budget_ms
    }
}

fn ms(a: u64, b: u64) -> u32 {
    u32::try_from(b.saturating_sub(a)).unwrap_or(u32::MAX)
}

struct Timer<'c, C: Clock> {
    clock: &'c mut C,
    stage_ms: [Option<u32>; STAGES],
}

impl<C: Clock> Timer<'_, C> {
    fn time<T>(&mut self, stage: AlertStage, f: impl FnOnce() -> T) -> T {
        let t0 = self.clock.now_ms();
        let r = f();
        let t1 = self.clock.now_ms();
        let prev = self.stage_ms[stage.index()].unwrap_or(0);
        self.stage_ms[stage.index()] = Some(prev.saturating_add(ms(t0, t1)));
        r
    }
}

/// What an attempt does on the network.
enum Job<'a> {
    /// Start Wi-Fi and associate, nothing more (the radio-switch
    /// experiment, [`run_probe`]).
    Probe,
    /// Send `request` to `host:port` and receive into `response`.
    Deliver {
        host: &'a str,
        port: u16,
        request: &'a [u8],
        response: &'a mut [u8],
    },
}

fn network_stages<C: Clock, N: Network>(
    timer: &mut Timer<'_, C>,
    net: &mut N,
    d: Deadline,
    job: Job<'_>,
) -> Outcome {
    use AlertStage as S;
    let mut sent = false;
    macro_rules! stage {
        ($stage:expr, $call:expr) => {{
            if timer.clock.now_ms() >= d.network_end {
                return if sent {
                    Outcome::Ambiguous { stage: $stage }
                } else {
                    Outcome::Cancelled { stage: $stage }
                };
            }
            match timer.time($stage, || $call) {
                Ok(v) => v,
                Err(e) => {
                    return if sent || $stage == S::Request {
                        Outcome::Ambiguous { stage: $stage }
                    } else {
                        Outcome::Failed {
                            stage: $stage,
                            timed_out: e == NetError::Timeout,
                        }
                    };
                }
            }
        }};
    }
    stage!(S::WifiStart, net.wifi_start(d));
    if matches!(job, Job::Probe) && timer.clock.now_ms() < d.network_end {
        // Diagnostic only: what is heard does not decide the outcome.
        let _ = timer.time(S::Scan, || net.scan(d));
    }
    stage!(S::Associate, net.associate(d));
    let Job::Deliver {
        host,
        port,
        request,
        response,
    } = job
    else {
        return Outcome::Response(0);
    };
    stage!(S::ObtainIp, net.obtain_ip(d));
    let addr = stage!(S::Resolve, net.resolve(host, d));
    stage!(S::Connect, net.connect(addr, port, d));
    stage!(S::Tls, net.tls_handshake(host, d));
    stage!(S::Request, net.send(request, d));
    sent = true;
    let n = stage!(S::Response, net.receive(response, d));
    Outcome::Response(n)
}

/// Runs one attempt with a Zigbee downtime budget of `budget_ms`.
/// `request` is sent to `host:port` after a verified TLS handshake;
/// the response lands in `response`.
pub fn run<C: Clock, R: RadioSwitch, N: Network>(
    clock: &mut C,
    radio: &mut R,
    net: &mut N,
    budget_ms: u32,
    host: &str,
    port: u16,
    request: &[u8],
    response: &mut [u8],
) -> Report {
    run_job(
        clock,
        radio,
        net,
        budget_ms,
        Job::Deliver {
            host,
            port,
            request,
            response,
        },
    )
}

/// The radio-switch experiment: the same hand-over and restoration as
/// [`run`], under the same deadline, but the network part stops once the
/// access point is joined. Nothing is sent. A successful probe ends with
/// [`Outcome::Response`]`(0)`.
pub fn run_probe<C: Clock, R: RadioSwitch, N: Network>(
    clock: &mut C,
    radio: &mut R,
    net: &mut N,
    budget_ms: u32,
) -> Report {
    run_job(clock, radio, net, budget_ms, Job::Probe)
}

fn run_job<C: Clock, R: RadioSwitch, N: Network>(
    clock: &mut C,
    radio: &mut R,
    net: &mut N,
    budget_ms: u32,
    job: Job<'_>,
) -> Report {
    let start = clock.now_ms();
    let reserve = RESTORE_RESERVE_MS.min(budget_ms / 2);
    let deadline = Deadline {
        start,
        network_end: start + u64::from(budget_ms - reserve),
        end: start + u64::from(budget_ms),
    };
    let mut timer = Timer {
        clock,
        stage_ms: [None; STAGES],
    };
    let suspended = timer.time(AlertStage::StopZigbee, || radio.suspend_zigbee());
    let outcome = if suspended.is_ok() {
        let o = network_stages(&mut timer, net, deadline, job);
        timer.time(AlertStage::WifiStop, || net.wifi_stop());
        o
    } else {
        Outcome::SuspendFailed
    };
    let mut restored = false;
    for _ in 0..RESTORE_TRIES {
        if timer
            .time(AlertStage::RestoreZigbee, || radio.resume_zigbee())
            .is_ok()
        {
            restored = true;
            break;
        }
    }
    let end = timer.clock.now_ms();
    Report {
        outcome,
        stage_ms: timer.stage_ms,
        downtime_ms: ms(start, end),
        restored,
        budget_ms,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::vec::Vec;

    /// A clock the mocks advance.
    #[derive(Default)]
    pub(crate) struct FakeClock(pub u64);

    impl Clock for FakeClock {
        fn now_ms(&mut self) -> u64 {
            self.0
        }
    }

    /// Shared time: the network and radio mocks advance it.
    pub(crate) struct World {
        pub now: core::cell::Cell<u64>,
    }

    pub(crate) struct WorldClock<'a>(pub &'a World);
    impl Clock for WorldClock<'_> {
        fn now_ms(&mut self) -> u64 {
            self.0.now.get()
        }
    }

    pub(crate) struct MockRadio<'a> {
        pub world: &'a World,
        pub zigbee_on: bool,
        pub suspends: u32,
        pub resumes: u32,
        pub resume_failures: u32,
        pub suspend_fails: bool,
    }

    impl<'a> MockRadio<'a> {
        pub fn new(world: &'a World) -> Self {
            MockRadio {
                world,
                zigbee_on: true,
                suspends: 0,
                resumes: 0,
                resume_failures: 0,
                suspend_fails: false,
            }
        }
    }

    impl RadioSwitch for MockRadio<'_> {
        fn suspend_zigbee(&mut self) -> Result<(), RadioSwitchError> {
            self.world.now.set(self.world.now.get() + 5);
            self.suspends += 1;
            if self.suspend_fails {
                return Err(RadioSwitchError);
            }
            self.zigbee_on = false;
            Ok(())
        }
        fn resume_zigbee(&mut self) -> Result<(), RadioSwitchError> {
            self.world.now.set(self.world.now.get() + 10);
            self.resumes += 1;
            if self.resume_failures > 0 {
                self.resume_failures -= 1;
                return Err(RadioSwitchError);
            }
            self.zigbee_on = true;
            Ok(())
        }
    }

    /// Per stage: (duration, result). Missing stages succeed in 10 ms.
    pub(crate) struct MockNet<'a> {
        pub world: &'a World,
        pub script: Vec<(AlertStage, u64, Result<(), NetError>)>,
        pub response: &'static [u8],
        pub wifi_on: bool,
        pub stops: u32,
        pub sent: Vec<u8>,
        pub calls: Vec<AlertStage>,
    }

    impl<'a> MockNet<'a> {
        pub fn new(world: &'a World, response: &'static [u8]) -> Self {
            MockNet {
                world,
                script: Vec::new(),
                response,
                wifi_on: false,
                stops: 0,
                sent: Vec::new(),
                calls: Vec::new(),
            }
        }

        fn step(&mut self, stage: AlertStage, d: Deadline) -> Result<(), NetError> {
            self.calls.push(stage);
            let (dur, r) = self
                .script
                .iter()
                .find(|(s, _, _)| *s == stage)
                .map_or((10, Ok(())), |(_, d, r)| (*d, *r));
            let now = self.world.now.get();
            // A well-behaved stage gives up at the deadline.
            let limit = d.network_end.max(now);
            if r.is_ok() && now + dur > limit && stage != AlertStage::WifiStart {
                self.world.now.set(limit);
                return Err(NetError::Timeout);
            }
            self.world.now.set(now + dur);
            r
        }
    }

    impl Network for MockNet<'_> {
        fn wifi_start(&mut self, d: Deadline) -> Result<(), NetError> {
            assert!(!self.wifi_on);
            self.step(AlertStage::WifiStart, d)?;
            self.wifi_on = true;
            Ok(())
        }
        fn associate(&mut self, d: Deadline) -> Result<(), NetError> {
            self.step(AlertStage::Associate, d)
        }
        fn obtain_ip(&mut self, d: Deadline) -> Result<(), NetError> {
            self.step(AlertStage::ObtainIp, d)
        }
        fn resolve(&mut self, host: &str, d: Deadline) -> Result<[u8; 4], NetError> {
            assert_eq!(host, "api.telegram.org");
            self.step(AlertStage::Resolve, d)
                .map(|()| [149, 154, 167, 220])
        }
        fn connect(&mut self, _: [u8; 4], port: u16, d: Deadline) -> Result<(), NetError> {
            assert_eq!(port, 443);
            self.step(AlertStage::Connect, d)
        }
        fn tls_handshake(&mut self, _: &str, d: Deadline) -> Result<(), NetError> {
            self.step(AlertStage::Tls, d)
        }
        fn send(&mut self, request: &[u8], d: Deadline) -> Result<(), NetError> {
            self.sent.extend_from_slice(request);
            self.step(AlertStage::Request, d)
        }
        fn receive(&mut self, buf: &mut [u8], d: Deadline) -> Result<usize, NetError> {
            self.step(AlertStage::Response, d)?;
            buf[..self.response.len()].copy_from_slice(self.response);
            Ok(self.response.len())
        }
        fn wifi_stop(&mut self) {
            self.world.now.set(self.world.now.get() + 20);
            self.stops += 1;
            self.wifi_on = false;
        }
    }

    fn attempt(radio: &mut MockRadio<'_>, net: &mut MockNet<'_>, budget: u32) -> Report {
        let world = radio.world;
        let mut clock = WorldClock(world);
        let mut buf = [0u8; 512];
        run(
            &mut clock,
            radio,
            net,
            budget,
            "api.telegram.org",
            443,
            b"REQ",
            &mut buf,
        )
    }

    fn world() -> World {
        World {
            now: core::cell::Cell::new(1_000),
        }
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true,\"result\":{\"message_id\":1}}";

    #[test]
    fn a_successful_attempt_records_every_stage_and_restores_zigbee() {
        let w = world();
        let mut radio = MockRadio::new(&w);
        let mut net = MockNet::new(&w, OK);
        let r = attempt(&mut radio, &mut net, 2_000);
        assert_eq!(r.outcome, Outcome::Response(OK.len()));
        // Every stage but the experiment's scan.
        for (stage, ms) in AlertStage::ALL.iter().zip(r.stage_ms) {
            assert_eq!(ms.is_some(), *stage != AlertStage::Scan, "{stage:?}");
        }
        // 5 + 8 × 10 + 20 + 10
        assert_eq!(r.downtime_ms, 115);
        assert!(r.restored && radio.zigbee_on && !net.wifi_on);
        assert!(!r.over_budget());
        assert_eq!(net.sent, b"REQ");
    }

    #[test]
    fn every_stage_failure_before_the_request_sends_nothing_and_restores_zigbee() {
        use AlertStage as S;
        for stage in [
            S::WifiStart,
            S::Associate,
            S::ObtainIp,
            S::Resolve,
            S::Connect,
            S::Tls,
        ] {
            let w = world();
            let mut radio = MockRadio::new(&w);
            let mut net = MockNet::new(&w, OK);
            net.script.push((stage, 50, Err(NetError::Failed)));
            let r = attempt(&mut radio, &mut net, 2_000);
            assert_eq!(
                r.outcome,
                Outcome::Failed {
                    stage,
                    timed_out: false
                },
                "{stage:?}"
            );
            assert!(net.sent.is_empty());
            assert_eq!(net.stops, 1, "Wi-Fi stopped after {stage:?}");
            assert!(r.restored && radio.zigbee_on);
            assert_eq!(r.stage_ms[stage.index()], Some(50));
            assert!(
                r.stage_ms[stage.index() + 1..S::WifiStop.index()]
                    .iter()
                    .all(Option::is_none)
            );
        }
    }

    #[test]
    fn the_shared_deadline_cancels_the_attempt_and_keeps_time_for_the_return() {
        let w = world();
        let mut radio = MockRadio::new(&w);
        let mut net = MockNet::new(&w, OK);
        // Association takes 1.5 s, DHCP would take another second.
        net.script.push((AlertStage::Associate, 1_500, Ok(())));
        net.script.push((AlertStage::ObtainIp, 1_000, Ok(())));
        let r = attempt(&mut radio, &mut net, 2_000);
        assert_eq!(
            r.outcome,
            Outcome::Failed {
                stage: AlertStage::ObtainIp,
                timed_out: true
            }
        );
        assert!(!net.calls.contains(&AlertStage::Resolve));
        assert!(r.restored);
        // Cancelled at start + budget − reserve; shutdown and restore fit.
        assert!(r.downtime_ms <= 2_000, "{}", r.downtime_ms);
        assert!(!r.over_budget());

        // A stage that ends exactly at the deadline: the next is not started.
        let w = world();
        let mut radio = MockRadio::new(&w);
        let mut net = MockNet::new(&w, OK);
        net.script.push((AlertStage::Associate, 1_685, Ok(())));
        let r = attempt(&mut radio, &mut net, 2_000);
        assert_eq!(
            r.outcome,
            Outcome::Cancelled {
                stage: AlertStage::ObtainIp
            }
        );
    }

    #[test]
    fn a_blocking_stage_is_reported_over_budget_not_hidden() {
        let w = world();
        let mut radio = MockRadio::new(&w);
        let mut net = MockNet::new(&w, OK);
        // The driver's start cannot be interrupted (the mock ignores the
        // deadline for this stage): 3 s.
        net.script.push((AlertStage::WifiStart, 3_000, Ok(())));
        let r = attempt(&mut radio, &mut net, 2_000);
        assert_eq!(
            r.outcome,
            Outcome::Cancelled {
                stage: AlertStage::Associate
            }
        );
        assert!(r.over_budget());
        assert_eq!(r.stage_ms[AlertStage::WifiStart.index()], Some(3_000));
        assert!(r.restored);
    }

    #[test]
    fn a_failure_after_sending_is_ambiguous() {
        for (stage, err) in [
            (AlertStage::Request, NetError::Failed),
            (AlertStage::Response, NetError::Timeout),
        ] {
            let w = world();
            let mut radio = MockRadio::new(&w);
            let mut net = MockNet::new(&w, OK);
            net.script.push((stage, 30, Err(err)));
            let r = attempt(&mut radio, &mut net, 2_000);
            assert_eq!(r.outcome, Outcome::Ambiguous { stage });
            assert!(r.restored);
        }
        // The deadline expires while waiting for the response.
        let w = world();
        let mut radio = MockRadio::new(&w);
        let mut net = MockNet::new(&w, OK);
        net.script.push((AlertStage::Response, 5_000, Ok(())));
        let r = attempt(&mut radio, &mut net, 2_000);
        assert_eq!(
            r.outcome,
            Outcome::Ambiguous {
                stage: AlertStage::Response
            }
        );
    }

    #[test]
    fn restoration_is_retried_and_its_failure_reported() {
        let w = world();
        let mut radio = MockRadio::new(&w);
        radio.resume_failures = 2;
        let mut net = MockNet::new(&w, OK);
        let r = attempt(&mut radio, &mut net, 2_000);
        assert!(r.restored);
        assert_eq!(radio.resumes, 3);
        assert_eq!(r.stage_ms[AlertStage::RestoreZigbee.index()], Some(30));

        let w = world();
        let mut radio = MockRadio::new(&w);
        radio.resume_failures = 10;
        let mut net = MockNet::new(&w, OK);
        let r = attempt(&mut radio, &mut net, 2_000);
        assert!(!r.restored);
        assert_eq!(radio.resumes, u32::from(RESTORE_TRIES));
    }

    #[test]
    fn a_radio_that_cannot_be_released_skips_wifi_but_is_resumed() {
        let w = world();
        let mut radio = MockRadio::new(&w);
        radio.suspend_fails = true;
        let mut net = MockNet::new(&w, OK);
        let r = attempt(&mut radio, &mut net, 2_000);
        assert_eq!(r.outcome, Outcome::SuspendFailed);
        assert!(net.calls.is_empty() && net.stops == 0);
        assert_eq!(radio.resumes, 1);
        assert!(r.restored);
    }

    #[test]
    fn a_probe_stops_after_association_and_restores_zigbee() {
        let w = world();
        let mut radio = MockRadio::new(&w);
        let mut net = MockNet::new(&w, OK);
        let mut clock = WorldClock(&w);
        let r = run_probe(&mut clock, &mut radio, &mut net, 2_000);
        assert_eq!(r.outcome, Outcome::Response(0));
        assert_eq!(net.calls, [AlertStage::WifiStart, AlertStage::Associate]);
        assert_eq!(
            r.stage_ms[AlertStage::Scan.index()],
            Some(0),
            "a probe scans"
        );
        assert!(net.sent.is_empty() && net.stops == 1);
        assert!(r.restored && radio.zigbee_on);
        assert_eq!(r.downtime_ms, 5 + 10 + 10 + 20 + 10);

        let w = world();
        let mut radio = MockRadio::new(&w);
        let mut net = MockNet::new(&w, OK);
        net.script.push((AlertStage::Associate, 5_000, Ok(())));
        let mut clock = WorldClock(&w);
        let r = run_probe(&mut clock, &mut radio, &mut net, 2_000);
        assert_eq!(
            r.outcome,
            Outcome::Failed {
                stage: AlertStage::Associate,
                timed_out: true
            }
        );
        assert!(r.restored && r.downtime_ms <= 2_000);
    }

    #[test]
    fn the_fake_clock_is_usable() {
        let mut c = FakeClock(5);
        assert_eq!(c.now_ms(), 5);
    }
}
