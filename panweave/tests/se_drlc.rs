//! The DRLC drivers over the simulator: an ESI issues a load control
//! event to a Load Control Device, which reports it received and
//! started, opts out, asks for the scheduled events and sees the event
//! cancelled — under APS link-key security, with the 0–5 s report delays.

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
use panweave::smart_energy::clusters::drlc::{
    CancelLoadControlEvent, EventStatus, GetScheduledEvents, LOAD_ADJUSTMENT_UNUSED,
    LoadControlEvent, OFFSET_UNUSED, Phase, SET_POINT_UNUSED, criticality, device_class,
};
use panweave::smart_energy_drivers::drlc::{DrlcClient, DrlcEvent, DrlcServer, DrlcServerEvent};
use panweave::smart_energy_endpoints as se;
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::time::{Duration, Instant};
use panweave::types::{Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress};
use panweave_sim::{App, SimStack, Simulator};

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const ESI_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const LCD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const EP: Endpoint = Endpoint(10);
const UTC: u32 = 600_000_000;

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
    let (desc, ep) = if role == LogicalDeviceType::Coordinator {
        se::energy_service_interface(EP).unwrap()
    } else {
        se::load_control_device(EP).unwrap()
    };
    n.add_endpoint(desc, ep).unwrap();
    n
}

#[derive(Default)]
struct Esi {
    driver: Option<DrlcServer>,
    events: Vec<DrlcServerEvent>,
}

impl App for Esi {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(d) = self.driver.as_mut()
            && let Some(e) = d.on_event(stack, event)
        {
            self.events.push(e);
        }
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some(d) = self.driver.as_mut() {
            d.poll(stack, now);
        }
    }
}

#[derive(Default)]
struct Lcd {
    driver: Option<DrlcClient>,
    statuses: Vec<EventStatus>,
}

impl App for Lcd {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(d) = self.driver.as_mut()
            && let Some(DrlcEvent::Status(rs)) = d.on_event(stack, event)
        {
            self.statuses.extend(rs.iter().map(|r| r.status));
        }
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some(d) = self.driver.as_mut()
            && let Some(DrlcEvent::Status(rs)) = d.poll(stack, now)
        {
            self.statuses.extend(rs.iter().map(|r| r.status));
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.driver.as_ref().and_then(DrlcClient::deadline)
    }
}

fn reported(sim: &Simulator, e: usize) -> Vec<EventStatus> {
    sim.app::<Esi>(e)
        .unwrap()
        .events
        .iter()
        .filter_map(|ev| match ev {
            DrlcServerEvent::Status { report, .. } => Some(report.event_status),
            DrlcServerEvent::ScheduledEventsRequested { .. } => None,
        })
        .collect()
}

#[test]
fn load_control_events_are_scheduled_reported_and_cancelled() {
    let mut sim = Simulator::new();
    let e = sim.add_stack(
        "esi",
        node(LogicalDeviceType::Coordinator, ESI_IEEE, 71),
        Box::new(Esi::default()),
    );
    let l = sim.add_stack(
        "lcd",
        node(LogicalDeviceType::Router, LCD_IEEE, 72),
        Box::new(Lcd::default()),
    );
    {
        let mut server = DrlcServer::new(EP);
        server.clock.set(UTC, Instant::ZERO);
        sim.stack_and_app::<Esi>(e).unwrap().1.driver = Some(server);
        let mut client = DrlcClient::new(EP, device_class::SIMPLE_MISC_LOADS);
        client.clock.set(UTC, Instant::ZERO);
        sim.stack_and_app::<Lcd>(l).unwrap().1.driver = Some(client);
    }
    sim.stack(e).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(e)
            .iter()
            .any(|ev| matches!(ev, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(e).permit_join_network(180).unwrap();
    sim.stack(l).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(l)
            .iter()
            .any(|ev| matches!(ev, StackEvent::LinkKeyUpdated))
    }));
    sim.run_for(Duration::from_secs(3));
    let lcd_short = sim.stack(l).short_address();
    let lcd = Destination::Short {
        address: lcd_short,
        endpoint: EP,
    };
    let esi = Destination::Short {
        address: ShortAddress::COORDINATOR,
        endpoint: EP,
    };
    // An event for simple loads starting now, without randomization.
    let event = LoadControlEvent {
        issuer_event_id: 0x0000_0101,
        device_class: device_class::SIMPLE_MISC_LOADS | device_class::HVAC,
        utility_enrollment_group: 0,
        start_time: 0,
        duration_minutes: 3,
        criticality_level: criticality::LEVEL_1,
        cooling_temperature_offset: OFFSET_UNUSED,
        heating_temperature_offset: OFFSET_UNUSED,
        cooling_temperature_set_point: SET_POINT_UNUSED,
        heating_temperature_set_point: SET_POINT_UNUSED,
        average_load_adjustment_percentage: LOAD_ADJUSTMENT_UNUSED,
        duty_cycle: 50,
        event_control: 0,
    };
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_mut().unwrap().issue(stack, lcd, event));
    }
    // Received, then Started once the (immediate) start passes; both
    // reach the ESI after the 0–5 s delays.
    assert!(sim.run_until(Duration::from_secs(20), |x| { reported(x, e).len() >= 2 }));
    assert_eq!(
        reported(&sim, e)[..2],
        [EventStatus::Received, EventStatus::Started]
    );
    let report = match &sim.app::<Esi>(e).unwrap().events[1] {
        DrlcServerEvent::Status { client, report } => {
            assert_eq!(*client, lcd_short);
            *report
        }
        other @ DrlcServerEvent::ScheduledEventsRequested { .. } => panic!("{other:?}"),
    };
    assert_eq!(report.issuer_event_id, 0x0101);
    assert_eq!(report.duty_cycle_applied, 50);
    assert_eq!(report.criticality_level_applied, criticality::LEVEL_1);
    assert_eq!(
        sim.app::<Lcd>(l).unwrap().statuses,
        [EventStatus::Received, EventStatus::Started]
    );
    let active = sim
        .app::<Lcd>(l)
        .unwrap()
        .driver
        .as_ref()
        .unwrap()
        .active()
        .copied()
        .unwrap();
    assert_eq!(active.phase, Phase::Active);
    assert_eq!(active.event.issuer_event_id, 0x0101);
    // The user opts out: the ESI hears it.
    {
        let (stack, app) = sim.stack_and_app::<Lcd>(l).unwrap();
        assert!(
            app.driver
                .as_mut()
                .unwrap()
                .set_opt_out(stack, 0x0101, true)
                .is_some()
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reported(x, e).contains(&EventStatus::OptOut)
    }));
    assert!(
        sim.app::<Lcd>(l)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .active()
            .is_none()
    );
    // Get Scheduled Events returns the running event.
    {
        let (stack, app) = sim.stack_and_app::<Lcd>(l).unwrap();
        assert!(app.driver.as_ref().unwrap().request_scheduled_events(
            stack,
            esi,
            &GetScheduledEvents {
                earliest_end_time: 0,
                number_of_events: 0,
                minimum_issuer_event_id: u32::MAX,
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.iter().any(|ev| {
            matches!(
                ev,
                DrlcServerEvent::ScheduledEventsRequested { count: 1, .. }
            )
        })
    }));
    // Cancel: the client reports it and drops the event.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_mut().unwrap().cancel(
            stack,
            lcd,
            &CancelLoadControlEvent {
                issuer_event_id: 0x0101,
                device_class: device_class::SIMPLE_MISC_LOADS,
                utility_enrollment_group: 0,
                use_randomization: false,
                effective_time: 0,
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        reported(x, e).contains(&EventStatus::Cancelled)
    }));
    assert!(
        sim.app::<Lcd>(l)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .scheduler
            .events()
            .is_empty()
    );
}
