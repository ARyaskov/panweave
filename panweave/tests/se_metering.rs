//! The Metering drivers over the simulator: an ESI reads a meter's
//! profile, puts it in fast poll mode, samples it, takes and fetches a
//! snapshot, changes the supply and hosts a mirror for it — under APS
//! link-key security.

#![cfg(feature = "smart-energy")]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave::aps::layer::Destination;
use panweave::mac::service::MacServiceConfig;
use panweave::runtime::{JoinMode, StackConfig, StackEvent};
use panweave::smart_energy::cluster as c;
use panweave::smart_energy::clusters::metering::extended::{
    ANY_CAUSE, ChangeSupply, ConfigureMirror, DemandLimiting, GetSampledData, GetSnapshot,
    LocalChangeSupply, RequestFastPollMode, ScheduleSnapshot, SetSupplyStatus,
    SetUncontrolledFlowThreshold, SnapshotSchedule, StartSampling, SupplyEvent,
    notification_scheme, sample_type, schedule_confirmation, snapshot_cause, snapshot_confirmation,
    snapshot_schedule, snapshot_type, supply_control, supply_status,
};
use panweave::smart_energy::clusters::metering::{
    GetProfile, IntervalPeriod, ProfileStatus, notification, supply_limit as sl,
};
use panweave::smart_energy::devices;
use panweave::smart_energy_drivers::metering::{
    MeteringClient, MeteringEvent, MeteringServer, MeteringServerEvent,
};
use panweave::smart_energy_endpoints as se;
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::time::{Duration, Instant};
use panweave::types::{Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress};
use panweave_sim::{App, SimStack, Simulator};

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const ESI_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const METER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const EP: Endpoint = Endpoint(10);
const UTC: u32 = 600_000_000;
const MIRROR_ENDPOINTS: &[u8] = &[20, 21];

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    se::apply_profile(&mut cfg);
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    se::apply_profile_to_stack(&mut n);
    let (desc, mut ep) = if role == LogicalDeviceType::Coordinator {
        se::device(EP, devices::ENERGY_SERVICE_INTERFACE, &[], &[c::METERING]).unwrap()
    } else {
        se::metering_device(EP).unwrap()
    };
    if role != LogicalDeviceType::Coordinator {
        // A meter with a contactor and demand limiting.
        let m = ep
            .cluster_mut(c::METERING, panweave::zcl::Role::Server)
            .unwrap();
        panweave::smart_energy::endpoints::add_supply_limit(m).unwrap();
    }
    n.add_endpoint(desc, ep).unwrap();
    if role == LogicalDeviceType::Coordinator {
        // The ESI's first mirror endpoint: a Metering server standing in
        // for the meter, with the client the meter's commands and
        // reports address (D.3.4.4).
        let (desc, ep) = se::device(
            Endpoint(MIRROR_ENDPOINTS[0]),
            devices::ENERGY_SERVICE_INTERFACE,
            &[c::METERING],
            &[c::METERING],
        )
        .unwrap();
        n.add_endpoint(desc, ep).unwrap();
    }
    n
}

#[derive(Default)]
struct Esi {
    driver: Option<MeteringClient>,
    events: Vec<MeteringEvent>,
}

impl App for Esi {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(d) = self.driver.as_mut()
            && let Some(e) = d.on_event(stack, event)
        {
            self.events.push(e);
        }
    }
}

#[derive(Default)]
struct Meter {
    driver: Option<MeteringServer>,
    events: Vec<MeteringServerEvent>,
    reading: u32,
}

impl App for Meter {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(d) = self.driver.as_mut()
            && let Some(e) = d.on_event(stack, event)
        {
            self.events.push(e);
        }
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some(d) = self.driver.as_mut() {
            // The meter reads 1 unit per second.
            self.reading = u32::try_from(now.as_millis() / 1000).unwrap();
            d.sample(stack, sample_type::CONSUMPTION_DELIVERED, self.reading);
            if let Some(e) = d.poll(stack, now) {
                self.events.push(e);
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        // Sample every second.
        Some(Instant::from_millis(0))
    }
}

#[test]
fn meter_answers_profile_fast_poll_sampling_snapshot_supply_and_mirror() {
    let mut sim = Simulator::new();
    let e = sim.add_stack(
        "esi",
        node(LogicalDeviceType::Coordinator, ESI_IEEE, 91),
        Box::new(Esi::default()),
    );
    let m = sim.add_stack(
        "meter",
        node(LogicalDeviceType::Router, METER_IEEE, 92),
        Box::new(Meter::default()),
    );
    {
        let mut client = MeteringClient::new(EP, MIRROR_ENDPOINTS);
        client.clock.set(UTC, Instant::ZERO);
        sim.stack_and_app::<Esi>(e).unwrap().1.driver = Some(client);
        let mut server = MeteringServer::new(EP);
        server.clock.set(UTC, Instant::ZERO);
        assert!(server.add_profile_channel(0, IntervalPeriod::Minutes30, 12));
        server.record_interval(0, 100, UTC - 3600);
        server.record_interval(0, 110, UTC - 1800);
        server.record_interval(0, 120, UTC);
        server.snapshot_causes = snapshot_cause::GENERAL | snapshot_cause::MANUALLY_TRIGGERED;
        server.snapshot_payload_type = snapshot_type::TOU_DELIVERED_NO_BILLING;
        server
            .snapshot_payload
            .extend_from_slice(&[0x5A; 40])
            .unwrap();
        server.supply.capable = true;
        server.supply.restore_allowed = true;
        sim.stack_and_app::<Meter>(m).unwrap().1.driver = Some(server);
    }
    sim.stack(e).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(e)
            .iter()
            .any(|ev| matches!(ev, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(e).permit_join_network(180).unwrap();
    sim.stack(m).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(m)
            .iter()
            .any(|ev| matches!(ev, StackEvent::LinkKeyUpdated))
    }));
    sim.run_for(Duration::from_secs(3));
    let meter_short = sim.stack(m).short_address();
    let meter = Destination::Short {
        address: meter_short,
        endpoint: EP,
    };
    let esi = Destination::Short {
        address: ShortAddress::COORDINATOR,
        endpoint: EP,
    };
    // Get Profile: the three intervals, newest first.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_ref().unwrap().get_profile(
            stack,
            meter,
            &GetProfile {
                channel: 0,
                end_time: 0,
                number_of_periods: 8
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        !x.app::<Esi>(e).unwrap().events.is_empty()
    }));
    match &sim.app::<Esi>(e).unwrap().events[0] {
        MeteringEvent::Profile {
            meter: from,
            end_time,
            status,
            period,
            intervals,
        } => {
            assert_eq!(*from, meter_short);
            assert_eq!(*end_time, UTC);
            assert_eq!(*status, ProfileStatus::Success);
            assert_eq!(*period, Some(IntervalPeriod::Minutes30));
            assert_eq!(intervals.as_slice(), &[120, 110, 100]);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        sim.app::<Meter>(m)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(
                ev,
                MeteringServerEvent::ProfileRequested {
                    status: ProfileStatus::Success,
                    ..
                }
            ))
    );
    // Fast poll mode for 2 minutes at 2 s (the meter's minimum is 5 s).
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_ref().unwrap().request_fast_poll(
            stack,
            meter,
            &RequestFastPollMode {
                update_period: 2,
                duration_minutes: 2
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 2
    }));
    match sim.app::<Esi>(e).unwrap().events[1] {
        MeteringEvent::FastPoll(r) => {
            assert_eq!(r.applied_update_period, 5);
            assert!(r.end_time > UTC && r.end_time <= UTC + 200);
        }
        ref other => panic!("{other:?}"),
    }
    // Sampling every 2 s, four samples; after a while the data comes back.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_ref().unwrap().start_sampling(
            stack,
            meter,
            &StartSampling {
                issuer_event_id: 0x30,
                start_time: 0,
                sample_type: sample_type::CONSUMPTION_DELIVERED,
                interval: 2,
                max_samples: 4
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 3
    }));
    let sample_id = match sim.app::<Esi>(e).unwrap().events[2] {
        MeteringEvent::SamplingStarted(r) => r.sample_id,
        ref other => panic!("{other:?}"),
    };
    assert_eq!(sample_id, 1);
    sim.run_for(Duration::from_secs(12));
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_ref().unwrap().get_sampled_data(
            stack,
            meter,
            &GetSampledData {
                sample_id,
                earliest_time: 0,
                sample_type: sample_type::CONSUMPTION_DELIVERED,
                count: 10
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 4
    }));
    match &sim.app::<Esi>(e).unwrap().events[3] {
        MeteringEvent::SampledData(r) => {
            assert_eq!(r.sample_id, sample_id);
            assert_eq!(r.interval, 2);
            assert_eq!(r.samples.len(), 4);
            assert!(r.samples.windows(2).all(|w| w[1] >= w[0]));
        }
        other => panic!("{other:?}"),
    }
    // Take a snapshot, then fetch it: two fragments reassembled.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(
            app.driver
                .as_ref()
                .unwrap()
                .take_snapshot(stack, meter, snapshot_cause::GENERAL)
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 5
    }));
    let snapshot_id = match sim.app::<Esi>(e).unwrap().events[4] {
        MeteringEvent::SnapshotTaken(r) => {
            assert_eq!(r.confirmation, snapshot_confirmation::ACCEPTED);
            r.snapshot_id
        }
        ref other => panic!("{other:?}"),
    };
    assert!(
        sim.app::<Meter>(m)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(
                ev,
                MeteringServerEvent::SnapshotTaken { snapshot_id: id, .. } if *id == snapshot_id
            ))
    );
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_ref().unwrap().get_snapshot(
            stack,
            meter,
            &GetSnapshot {
                earliest_start: 0,
                latest_end: u32::MAX,
                offset: 0,
                cause: ANY_CAUSE
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 6
    }));
    match &sim.app::<Esi>(e).unwrap().events[5] {
        MeteringEvent::Snapshot(s) => {
            assert_eq!(s.id, snapshot_id);
            assert_eq!(s.payload_type, snapshot_type::TOU_DELIVERED_NO_BILLING);
            assert_eq!(s.payload.as_slice(), &[0x5A; 40]);
            assert_ne!(s.cause & snapshot_cause::MANUALLY_TRIGGERED, 0);
        }
        other => panic!("{other:?}"),
    }
    // A snapshot schedule (D.3.3.3.1.5): every day from a minute from
    // now; the meter confirms, takes the snapshot when due and publishes
    // it to the ESI (D.3.4.5).
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        let now = UTC + u32::try_from(stack.now().as_millis() / 1000).unwrap();
        assert!(
            app.driver.as_ref().unwrap().schedule_snapshot(
                stack,
                meter,
                &ScheduleSnapshot {
                    issuer_event_id: 0x60,
                    command_index: 0,
                    total_commands: 1,
                    schedules: heapless::Vec::from_slice(&[
                        SnapshotSchedule {
                            schedule_id: 1,
                            start_time: now + 60,
                            schedule: snapshot_schedule::build(
                                1,
                                snapshot_schedule::UNIT_DAY,
                                snapshot_schedule::WILDCARD_NONE
                            ),
                            payload_type: snapshot_type::TOU_DELIVERED_NO_BILLING,
                            cause: snapshot_cause::GENERAL,
                        },
                        SnapshotSchedule {
                            schedule_id: 2,
                            start_time: now + 60,
                            schedule: snapshot_schedule::build(
                                1,
                                snapshot_schedule::UNIT_DAY,
                                snapshot_schedule::WILDCARD_NONE
                            ),
                            payload_type: snapshot_type::TOU_DELIVERED_NO_BILLING,
                            cause: snapshot_cause::CHANGE_OF_TARIFF,
                        },
                    ])
                    .unwrap(),
                }
            )
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 7
    }));
    match &sim.app::<Esi>(e).unwrap().events[6] {
        MeteringEvent::SnapshotsScheduled(r) => {
            assert_eq!(r.issuer_event_id, 0x60);
            assert_eq!(
                r.confirmations.as_slice(),
                &[
                    (1, schedule_confirmation::ACCEPTED),
                    (2, schedule_confirmation::CAUSE_NOT_SUPPORTED),
                ]
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(sim.run_until(Duration::from_secs(90), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 8
    }));
    match &sim.app::<Esi>(e).unwrap().events[7] {
        MeteringEvent::Snapshot(s) => {
            assert_ne!(s.id, snapshot_id);
            assert_eq!(s.cause, snapshot_cause::GENERAL);
            assert_eq!(s.payload.as_slice(), &[0x5A; 40]);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        sim.app::<Meter>(m)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(
                ev,
                MeteringServerEvent::SnapshotTaken {
                    cause: snapshot_cause::GENERAL,
                    ..
                }
            ))
    );
    // Change Supply now with an acknowledgement.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_ref().unwrap().change_supply(
            stack,
            meter,
            &ChangeSupply {
                provider_id: 7,
                issuer_event_id: 0x40,
                request_time: 0,
                implementation_time: 0,
                proposed_status: supply_status::OFF_ARMED,
                control: supply_control::ACKNOWLEDGE_REQUIRED
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.len() == 9
    }));
    match sim.app::<Esi>(e).unwrap().events[8] {
        MeteringEvent::SupplyStatus(r) => {
            assert_eq!(r.issuer_event_id, 0x40);
            assert_eq!(r.status, supply_status::OFF_ARMED);
        }
        ref other => panic!("{other:?}"),
    }
    assert!(
        sim.app::<Meter>(m)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(
                ev,
                MeteringServerEvent::SupplyChanged {
                    status: supply_status::OFF_ARMED
                }
            ))
    );
    // A local reconnection from the armed state.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(
            app.driver
                .as_ref()
                .unwrap()
                .local_change_supply(stack, meter, supply_status::ON)
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Meter>(m).unwrap().events.iter().any(|ev| {
            matches!(
                ev,
                MeteringServerEvent::SupplyChanged {
                    status: supply_status::ON
                }
            )
        })
    }));
    // Set Supply Status makes a tamper disconnect the supply, Set
    // Uncontrolled Flow Threshold configures flow detection, and a
    // Reset Load Limit Counter clears the counter.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        let d = app.driver.as_ref().unwrap();
        assert!(d.set_supply_status(
            stack,
            meter,
            &SetSupplyStatus {
                issuer_event_id: 0x50,
                tamper: supply_status::OFF,
                depletion: supply_status::UNCHANGED,
                uncontrolled_flow: supply_status::OFF_ARMED,
                load_limit: supply_status::OFF_ARMED,
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Meter>(m)
            .unwrap()
            .events
            .contains(&MeteringServerEvent::SupplyPolicyChanged)
    }));
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        let d = app.driver.as_ref().unwrap();
        assert!(d.set_uncontrolled_flow_threshold(
            stack,
            meter,
            &SetUncontrolledFlowThreshold {
                provider_id: 7,
                issuer_event_id: 0x51,
                threshold: 250,
                unit: 0x01,
                multiplier: 1,
                divisor: 10,
                stabilisation_period: 20,
                measurement_period: 30,
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Meter>(m)
            .unwrap()
            .events
            .contains(&MeteringServerEvent::UncontrolledFlowConfigured)
    }));
    {
        let (stack, app) = sim.stack_and_app::<Meter>(m).unwrap();
        let d = app.driver.as_mut().unwrap();
        assert_eq!(d.supply.policy.tamper, supply_status::OFF);
        assert_eq!(d.supply.uncontrolled_flow.unwrap().threshold, 250);
        // The demand limit is exceeded twice, then a tamper: the supply
        // arms, then disconnects.
        assert_eq!(
            d.supply_event(stack, SupplyEvent::LoadLimit),
            Some(MeteringServerEvent::SupplyChanged {
                status: supply_status::OFF_ARMED
            })
        );
        assert_eq!(d.supply_event(stack, SupplyEvent::LoadLimit), None);
        assert_eq!(d.supply.load_limit_counter, 2);
        assert_eq!(
            d.supply_event(stack, SupplyEvent::Tamper),
            Some(MeteringServerEvent::SupplyChanged {
                status: supply_status::OFF
            })
        );
    }
    // Demand limiting (D.3.2.2.7.2–D.3.2.2.7.5): the meter's own
    // measurement over the limit disconnects the supply and counts; the
    // driver's poll re-arms it after DemandLimitArmDuration.
    {
        let (stack, app) = sim.stack_and_app::<Meter>(m).unwrap();
        let d = app.driver.as_mut().unwrap();
        assert_eq!(
            d.supply_event(stack, SupplyEvent::Tamper),
            None,
            "already off"
        );
        let _ = d.supply.local_change(&LocalChangeSupply {
            proposed_status: supply_status::ON,
        });
        d.supply.status = supply_status::ON;
        d.supply.demand_limiting = Some(DemandLimiting {
            limit: 12_000,
            integration_period_min: 30,
            subintervals: 6,
            arm_duration_secs: 30,
        });
        assert_eq!(d.demand_measured(stack, 11_000), None);
        assert_eq!(
            d.demand_measured(stack, 12_001),
            Some(MeteringServerEvent::SupplyChanged {
                status: supply_status::OFF_ARMED
            }),
            "the policy's load-limit state"
        );
        assert_eq!(d.supply.load_limit_counter, 3);
        let c = stack
            .zcl
            .cluster(EP, c::METERING, panweave::zcl::Role::Server)
            .unwrap();
        assert_eq!(c.u64(sl::CURRENT_DEMAND_DELIVERED.id), Some(12_001));
        assert_eq!(c.u64(sl::DEMAND_LIMIT.id), Some(12_000));
        assert_eq!(c.u8(sl::LOAD_LIMIT_COUNTER.id), Some(3));
    }
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        let d = app.driver.as_ref().unwrap();
        assert!(d.reset_load_limit_counter(stack, meter, 7, 0x52));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Meter>(m)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .supply
            .load_limit_counter
            == 0
    }));
    // The meter asks the ESI for a mirror and gets the first endpoint.
    {
        let (stack, app) = sim.stack_and_app::<Meter>(m).unwrap();
        assert!(app.driver.as_ref().unwrap().request_mirror(stack, esi));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(ev, MeteringEvent::MirrorRequested { endpoint: 20, .. }))
    }));
    assert_eq!(
        sim.app::<Esi>(e)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .mirrors
            .mirrors()
            .len(),
        1
    );
    // The meter configures its mirror with predefined scheme B and
    // notification reporting; the ESI notes a price and a time sync
    // waiting; the meter's report lands in the mirror and comes back
    // answered with the flags in scheme B's order (D.3.4.4.3).
    let mirror = Destination::Short {
        address: ShortAddress(0x0000),
        endpoint: Endpoint(MIRROR_ENDPOINTS[0]),
    };
    {
        let (stack, app) = sim.stack_and_app::<Meter>(m).unwrap();
        assert!(app.driver.as_ref().unwrap().configure_mirror(
            stack,
            mirror,
            &ConfigureMirror {
                issuer_event_id: 0x70,
                reporting_interval: 60,
                notification_reporting: true,
                scheme: notification_scheme::B,
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(ev, MeteringEvent::MirrorConfigured { .. }))
    }));
    {
        let (_, app) = sim.stack_and_app::<Esi>(e).unwrap();
        let d = app.driver.as_mut().unwrap();
        assert!(d.mirrors.notify(
            MIRROR_ENDPOINTS[0],
            0,
            notification::functional::TIME_SYNC,
            true
        ));
        assert!(d.mirrors.notify(
            MIRROR_ENDPOINTS[0],
            1,
            notification::price::PUBLISH_PRICE,
            true
        ));
        assert!(
            !d.mirrors.notify(MIRROR_ENDPOINTS[1], 0, 1, true),
            "no mirror there"
        );
    }
    let summation = {
        let (stack, app) = sim.stack_and_app::<Meter>(m).unwrap();
        let value = stack
            .zcl
            .cluster(EP, c::METERING, panweave::zcl::Role::Server)
            .unwrap()
            .u64(panweave::smart_energy::clusters::metering::CURRENT_SUMMATION_DELIVERED.id)
            .unwrap();
        assert!(app.driver.as_ref().unwrap().report_to_mirror(
            stack,
            mirror,
            &[panweave::smart_energy::clusters::metering::CURRENT_SUMMATION_DELIVERED.id]
        ));
        value
    };
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Meter>(m)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(ev, MeteringServerEvent::NotificationFlags { .. }))
    }));
    assert!(
        sim.app::<Esi>(e).unwrap().events.iter().any(|ev| matches!(
            ev,
            MeteringEvent::MirrorReported {
                endpoint: Endpoint(20),
                attributes: 1,
                answered: true,
                ..
            }
        )),
        "{:?}",
        sim.app::<Esi>(e).unwrap().events
    );
    assert_eq!(
        sim.stack(e)
            .zcl
            .cluster(
                Endpoint(MIRROR_ENDPOINTS[0]),
                c::METERING,
                panweave::zcl::Role::Server
            )
            .unwrap()
            .u64(panweave::smart_energy::clusters::metering::CURRENT_SUMMATION_DELIVERED.id),
        Some(summation)
    );
    assert!(
        sim.app::<Meter>(m)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(
                ev,
                MeteringServerEvent::NotificationFlags {
                    scheme: notification_scheme::B,
                    flags,
                    count: 5,
                } if flags[0] == notification::functional::TIME_SYNC
                    && flags[1] == notification::price::PUBLISH_PRICE
                    && flags[2..5] == [0, 0, 0]
            ))
    );
    {
        let (stack, app) = sim.stack_and_app::<Meter>(m).unwrap();
        assert!(app.driver.as_ref().unwrap().remove_mirror(stack, esi));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(ev, MeteringEvent::MirrorRemoved { .. }))
    }));
    assert!(
        sim.app::<Esi>(e)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .mirrors
            .mirrors()
            .is_empty()
    );
}
