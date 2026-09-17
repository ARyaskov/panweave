//! The Messaging drivers over the simulator: an ESI publishes a message
//! to an In-Home Display, the display confirms it, asks for the last
//! message again, and sees it cancelled — all under APS link-key
//! security.

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
use panweave::smart_energy::clusters::messaging::{
    CONFIRMATION_YES, DisplayMessage, Outcome, message_control,
};
use panweave::smart_energy_drivers::messaging::{
    MessagingClient, MessagingEvent, MessagingServer, MessagingServerEvent,
};
use panweave::smart_energy_endpoints as se;
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::time::{Duration, Instant};
use panweave::types::{Endpoint, ExtendedAddress, Key128, LogicalDeviceType};
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
        se::in_home_display(EP, &[c::MESSAGING]).unwrap()
    };
    n.add_endpoint(desc, ep).unwrap();
    n
}

#[derive(Default)]
struct Esi {
    driver: Option<MessagingServer>,
    events: Vec<MessagingServerEvent>,
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
    driver: Option<MessagingClient>,
    events: Vec<MessagingEvent>,
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
fn esi_messages_reach_the_display_and_are_confirmed() {
    let mut sim = Simulator::new();
    let e = sim.add_stack(
        "esi",
        node(LogicalDeviceType::Coordinator, ESI_IEEE, 61),
        Box::new(Esi::default()),
    );
    let i = sim.add_stack(
        "ihd",
        node(LogicalDeviceType::Router, IHD_IEEE, 62),
        Box::new(Ihd::default()),
    );
    {
        let mut server = MessagingServer::new(EP);
        server.clock.set(UTC, Instant::ZERO);
        sim.stack_and_app::<Esi>(e).unwrap().1.driver = Some(server);
        let mut client = MessagingClient::new(EP);
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
        address: panweave::types::ShortAddress::COORDINATOR,
        endpoint: EP,
    };
    let ihd = Destination::Short {
        address: ihd_short,
        endpoint: EP,
    };
    // Publish a message that needs a confirmation.
    let m = DisplayMessage {
        message_id: 0x1001,
        message_control: message_control::CONFIRMATION_REQUIRED
            | message_control::ENHANCED_CONFIRMATION_REQUIRED
            | (2 << message_control::IMPORTANCE_SHIFT),
        start_time: 0,
        duration_minutes: 30,
        message: b"Peak pricing at 5pm",
        extended_control: Some(0),
    };
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_mut().unwrap().publish(stack, ihd, &m, false));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        !x.app::<Ihd>(i).unwrap().events.is_empty()
    }));
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().events[0],
        MessagingEvent::Displayed {
            message_id: 0x1001,
            protected: false,
            outcome: Outcome::Replaced
        }
    );
    let stored = sim
        .app::<Ihd>(i)
        .unwrap()
        .driver
        .as_ref()
        .unwrap()
        .display
        .current()
        .cloned()
        .unwrap();
    assert_eq!(stored.text.as_slice(), b"Peak pricing at 5pm");
    assert!(stored.awaiting_confirmation());
    assert!(stored.displayed(UTC + 100));
    // The user confirms: the ESI records the enhanced confirmation.
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        assert!(
            app.driver
                .as_mut()
                .unwrap()
                .confirm(stack, esi, CONFIRMATION_YES, b"OK")
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        !x.app::<Esi>(e).unwrap().events.is_empty()
    }));
    match &sim.app::<Esi>(e).unwrap().events[0] {
        MessagingServerEvent::Confirmed {
            client,
            message_id,
            control,
            response,
            ..
        } => {
            assert_eq!(*client, ihd_short);
            assert_eq!(*message_id, 0x1001);
            assert_eq!(*control, CONFIRMATION_YES);
            assert_eq!(response.as_slice(), b"OK");
        }
        other @ MessagingServerEvent::LastMessageRequested { .. } => panic!("{other:?}"),
    }
    // Get Last Message brings the same message back (updated, not
    // replaced) and the ESI notes the request.
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        assert!(
            app.driver
                .as_ref()
                .unwrap()
                .request_last_message(stack, esi)
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Ihd>(i).unwrap().events.len() == 2
    }));
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().events[1],
        MessagingEvent::Displayed {
            message_id: 0x1001,
            protected: false,
            outcome: Outcome::Updated
        }
    );
    assert!(sim.app::<Esi>(e).unwrap().events.iter().any(|ev| matches!(
        ev,
        MessagingServerEvent::LastMessageRequested { answered: true, .. }
    )));
    // Cancel: the display clears.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_mut().unwrap().cancel(stack, ihd, 0x1001, 0));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Ihd>(i).unwrap().events.len() == 3
    }));
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().events[2],
        MessagingEvent::Cleared
    );
    assert!(
        sim.app::<Ihd>(i)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .display
            .current()
            .is_none()
    );
    // With nothing published, Get Last Message is answered NOT_FOUND.
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        assert!(
            app.driver
                .as_ref()
                .unwrap()
                .request_last_message(stack, esi)
        );
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Esi>(e).unwrap().events.iter().any(|ev| {
            matches!(
                ev,
                MessagingServerEvent::LastMessageRequested {
                    answered: false,
                    ..
                }
            )
        })
    }));
    // A second message with a scheduled Cancel All Messages clears once
    // the implementation time comes.
    let m2 = DisplayMessage {
        message_id: 0x1002,
        message_control: 0,
        start_time: 0,
        duration_minutes: 0xFFFF,
        message: b"Tariff change tonight",
        extended_control: Some(0),
    };
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.driver.as_mut().unwrap().publish(stack, ihd, &m2, false));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Ihd>(i).unwrap().events.len() == 4
    }));
    let at = sim.stack(i).now();
    let cancel_at = UTC + u32::try_from(at.as_millis() / 1000).unwrap() + 20;
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(
            app.driver
                .as_mut()
                .unwrap()
                .cancel_all(stack, ihd, cancel_at)
        );
    }
    sim.run_for(Duration::from_secs(5));
    assert!(
        sim.app::<Ihd>(i)
            .unwrap()
            .driver
            .as_ref()
            .unwrap()
            .display
            .current()
            .is_some()
    );
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.app::<Ihd>(i).unwrap().events.len() == 5
    }));
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().events[4],
        MessagingEvent::Cleared
    );
}
