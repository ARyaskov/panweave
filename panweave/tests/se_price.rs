//! The Price drivers over the simulator: an ESI publishes prices to an
//! In-Home Display, which acknowledges them and asks for the current and
//! the scheduled prices — under APS link-key security.

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
use panweave::smart_energy::clusters::price::{GetScheduledPrices, PublishPrice, price_control};
use panweave::smart_energy_drivers::price::{
    PriceClient, PriceEvent, PriceServer, PriceServerEvent,
};
use panweave::smart_energy_endpoints as se;
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::time::{Duration, Instant};
use panweave::types::{Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress};
use panweave_sim::{App, SimStack, Simulator};

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const ESI_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const IHD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
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
        se::in_home_display(EP, &[c::PRICE]).unwrap()
    };
    n.add_endpoint(desc, ep).unwrap();
    n
}

#[derive(Default)]
struct Esi {
    driver: Option<PriceServer>,
    events: Vec<PriceServerEvent>,
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
struct Ihd {
    driver: Option<PriceClient>,
    events: Vec<PriceEvent>,
}

impl App for Ihd {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(d) = self.driver.as_mut()
            && let Some(e) = d.on_event(stack, event)
        {
            self.events.push(e);
        }
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some(d) = self.driver.as_mut()
            && let Some(e) = d.poll(stack, now)
        {
            self.events.push(e);
        }
    }
}

#[test]
fn prices_are_published_acknowledged_and_queried() {
    let mut sim = Simulator::new();
    let e = sim.add_stack(
        "esi",
        node(LogicalDeviceType::Coordinator, ESI_IEEE, 81),
        Box::new(Esi::default()),
    );
    let i = sim.add_stack(
        "ihd",
        node(LogicalDeviceType::Router, IHD_IEEE, 82),
        Box::new(Ihd::default()),
    );
    {
        let mut server = PriceServer::new(EP);
        server.clock.set(UTC, Instant::ZERO);
        sim.stack_and_app::<Esi>(e).unwrap().1.driver = Some(server);
        let mut client = PriceClient::new(EP);
        client.clock.set(UTC, Instant::ZERO);
        sim.stack_and_app::<Ihd>(i).unwrap().1.driver = Some(client);
    }
    sim.stack(e).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(e)
            .iter()
            .any(|ev| matches!(ev, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(e).permit_join_network(180).unwrap();
    sim.stack(i).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(i)
            .iter()
            .any(|ev| matches!(ev, StackEvent::LinkKeyUpdated))
    }));
    sim.run_for(Duration::from_secs(3));
    let ihd_short = sim.stack(i).short_address();
    let esi = Destination::Short {
        address: ShortAddress::COORDINATOR,
        endpoint: EP,
    };
    let ihd = Destination::Short {
        address: ihd_short,
        endpoint: EP,
    };
    // A price starting now that must be acknowledged.
    let mut p = PublishPrice::new(0x0000_0007, b"Peak", 0x2001, 0, 0, 120, 2350);
    p.currency = 978;
    p.trailing_digit_and_tier = 0x21;
    p.price_control = price_control::ACKNOWLEDGEMENT_REQUIRED;
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_mut().unwrap().publish(stack, ihd, &p));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        !x.app::<Ihd>(i).unwrap().events.is_empty() && !x.app::<Esi>(e).unwrap().events.is_empty()
    }));
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().events[0],
        PriceEvent::Published {
            provider_id: 7,
            issuer_event_id: 0x2001,
            stored: true
        }
    );
    match sim.app::<Esi>(e).unwrap().events[0] {
        PriceServerEvent::Acknowledged { client, ack } => {
            assert_eq!(client, ihd_short);
            assert_eq!(ack.issuer_event_id, 0x2001);
            assert_eq!(ack.provider_id, 7);
            assert_eq!(ack.control, price_control::ACKNOWLEDGEMENT_REQUIRED);
        }
        other @ PriceServerEvent::Requested { .. } => panic!("{other:?}"),
    }
    let current = {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        app.driver.as_ref().unwrap().current(stack).unwrap()
    };
    assert_eq!(current.price, 2350);
    assert_eq!(current.currency, 978);
    assert_eq!(current.issuer_event_id, 0x2001);
    // A later price without acknowledgement, then Get Scheduled Prices
    // brings both back; Get Current Price only the active one.
    let later = PublishPrice::new(7, b"Off", 0x2002, 0, UTC + 7200, 60, 900);
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_mut().unwrap().publish(stack, ihd, &later));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Ihd>(i).unwrap().events.len() == 2
    }));
    assert_eq!(
        sim.app::<Ihd>(i)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .table
            .prices()
            .len(),
        2
    );
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        assert!(app.driver.as_ref().unwrap().request_scheduled_prices(
            stack,
            esi,
            &GetScheduledPrices {
                start_time: 0,
                number_of_events: 0
            }
        ));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(ev, PriceServerEvent::Requested { count: 2, .. }))
            && x.app::<Ihd>(i).unwrap().events.len() == 4
    }));
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        assert!(
            app.driver
                .as_ref()
                .unwrap()
                .request_current_price(stack, esi)
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Ihd>(i).unwrap().events.len() == 5
    }));
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().events[4],
        PriceEvent::Published {
            provider_id: 7,
            issuer_event_id: 0x2001,
            stored: true
        }
    );
    assert_eq!(
        sim.app::<Esi>(e)
            .unwrap()
            .events
            .iter()
            .filter(|ev| matches!(ev, PriceServerEvent::Requested { count: 1, .. }))
            .count(),
        1
    );
}
