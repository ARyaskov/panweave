//! The Smart Energy life-cycle driver over the simulator: an In-Home
//! Display auto-joins the ESI's network, runs Key Establishment (Annex
//! C.5 vectors), discovers the ESI, binds its Price and Messaging
//! clients to it and reaches steady state — after which a price
//! published to the ESI's bindings reaches the display.

#![cfg(feature = "smart-energy")]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave::aps::layer::Destination;
use panweave::cbke::CbkeDriver;
use panweave::mac::service::MacServiceConfig;
use panweave::runtime::{StackConfig, StackEvent};
use panweave::smart_energy::cluster as c;
use panweave::smart_energy::clusters::price::PublishPrice;
use panweave::smart_energy::commissioning::Phase;
use panweave::smart_energy::key_establishment::{Ecmqv, EcmqvError, Suite, Timing};
use panweave::smart_energy_drivers::commissioning::{SeCommissioning, SeCommissioningEvent};
use panweave::smart_energy_drivers::price::{PriceClient, PriceEvent, PriceServer};
use panweave::smart_energy_endpoints as se;
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::time::{Duration, Instant};
use panweave::types::{Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress};
use panweave_sim::{App, SimStack, Simulator};

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
/// Device 1 of Annex C.5 (the responder / Trust Center).
const ESI_IEEE: ExtendedAddress = ExtendedAddress(1);
/// Device 2 of Annex C.5 (the initiator).
const IHD_IEEE: ExtendedAddress = ExtendedAddress(2);
const ISSUER: ExtendedAddress = ExtendedAddress(0x5445_5354_5345_4341);
const EP: Endpoint = Endpoint(10);
const UTC: u32 = 600_000_000;

const CERT_V: [u8; 48] = [
    0x03, 0x04, 0x5F, 0xDF, 0xC8, 0xD8, 0x5F, 0xFB, 0x8B, 0x39, 0x93, 0xCB, 0x72, 0xDD, 0xCA, 0xA5,
    0x5F, 0x00, 0xB3, 0xE8, 0x7D, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x54, 0x45,
    0x53, 0x54, 0x53, 0x45, 0x43, 0x41, 0x01, 0x09, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const CERT_U: [u8; 48] = [
    0x02, 0x06, 0x15, 0xE0, 0x7D, 0x30, 0xEC, 0xA2, 0xDA, 0xD5, 0x80, 0x02, 0xE6, 0x67, 0xD9, 0x4B,
    0xC1, 0xB4, 0x22, 0x39, 0x83, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x54, 0x45,
    0x53, 0x54, 0x53, 0x45, 0x43, 0x41, 0x01, 0x09, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
/// Device 1's certificate re-issued to the replacement Trust Center
/// (IEEE 3): the subject field changed, the (host-supplied) curve
/// arithmetic being replayed from the vectors anyway.
const CERT_V3: [u8; 48] = {
    let mut c = CERT_V;
    c[29] = 0x03;
    c
};
const QEU: [u8; 22] = [
    0x03, 0x00, 0xE1, 0x17, 0xC8, 0x6D, 0x0E, 0x7C, 0xD1, 0x28, 0xB2, 0xF3, 0x4E, 0x90, 0x76, 0xCF,
    0xF2, 0x4A, 0xF4, 0x6D, 0x72, 0x88,
];
const QEV: [u8; 22] = [
    0x03, 0x06, 0xAB, 0x52, 0x06, 0x22, 0x01, 0xD9, 0x95, 0xB8, 0xB8, 0x59, 0x1F, 0x3F, 0x08, 0x6A,
    0x3A, 0x2E, 0x21, 0x4D, 0x84, 0x5E,
];
const Z: [u8; 21] = [
    0x00, 0xE0, 0xD2, 0xC3, 0xCC, 0xD5, 0xC1, 0x06, 0xA8, 0x9C, 0x4F, 0x6C, 0xC2, 0x6A, 0x5F, 0x7E,
    0xC9, 0xDF, 0x78, 0xA7, 0xBE,
];
const TIMING: Timing = Timing {
    ephemeral_data: 3,
    confirm_key: 6,
};

/// A primitive replaying the Annex C.5 vectors (ADR-0012).
struct Vectors {
    cert: &'static [u8],
    ephemeral: &'static [u8],
}

impl Ecmqv for Vectors {
    fn suite(&self) -> Suite {
        Suite::Suite1
    }
    fn certificate(&self) -> &[u8] {
        self.cert
    }
    fn generate_ephemeral(&mut self, out: &mut [u8]) -> Result<usize, EcmqvError> {
        out[..22].copy_from_slice(self.ephemeral);
        Ok(22)
    }
    fn shared_secret(&mut self, _: &[u8], _: &[u8], out: &mut [u8]) -> Result<usize, EcmqvError> {
        out[..21].copy_from_slice(&Z);
        Ok(21)
    }
}

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
        se::in_home_display(EP, &[c::PRICE, c::MESSAGING]).unwrap()
    };
    n.add_endpoint(desc, ep).unwrap();
    n
}

/// The ESI: CBKE responder and Price server.
struct Esi {
    cbke: CbkeDriver<Vectors>,
    price: PriceServer,
}

impl App for Esi {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        let _ = self.cbke.on_event(stack, event);
        let _ = self.price.on_event(stack, event);
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        let _ = self.cbke.poll(stack, now);
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.cbke.deadline()
    }
}

/// The display: the life-cycle driver and a Price client.
struct Ihd {
    driver: SeCommissioning<Vectors>,
    price: PriceClient,
    events: Vec<SeCommissioningEvent>,
    prices: Vec<PriceEvent>,
}

impl App for Ihd {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(e) = self.driver.on_event(stack, event) {
            self.events.push(e);
        }
        if let Some(e) = self.price.on_event(stack, event) {
            self.prices.push(e);
        }
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some(e) = self.driver.poll(stack, now) {
            self.events.push(e);
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.driver.deadline()
    }
}

#[test]
fn the_display_joins_establishes_its_key_discovers_the_esi_and_binds() {
    let mut sim = Simulator::new();
    let mut esi_price = PriceServer::new(EP);
    esi_price.clock.set(UTC, Instant::ZERO);
    let e = sim.add_stack(
        "esi",
        node(LogicalDeviceType::Coordinator, ESI_IEEE, 101),
        Box::new(Esi {
            cbke: CbkeDriver::new(
                Vectors {
                    cert: &CERT_V,
                    ephemeral: &QEV,
                },
                EP,
                ISSUER,
                TIMING,
            ),
            price: esi_price,
        }),
    );
    let mut ihd_price = PriceClient::new(EP);
    ihd_price.clock.set(UTC, Instant::ZERO);
    let i = sim.add_stack(
        "ihd",
        node(LogicalDeviceType::Router, IHD_IEEE, 102),
        Box::new(Ihd {
            driver: SeCommissioning::new(
                Vectors {
                    cert: &CERT_U,
                    ephemeral: &QEU,
                },
                EP,
                ISSUER,
                TIMING,
                &[c::PRICE, c::MESSAGING],
                Duration::from_mins(3 * 60),
                Duration::from_mins(60),
            ),
            price: ihd_price,
            events: Vec::new(),
            prices: Vec::new(),
        }),
    );
    sim.stack(e).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(e)
            .iter()
            .any(|ev| matches!(ev, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(e).permit_join_network(254).unwrap();
    // The display starts auto-joining: scan, join, CBKE, discovery,
    // binding, steady.
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        app.driver.start(stack);
    }
    assert!(
        sim.run_until(Duration::from_secs(120), |x| {
            x.app::<Ihd>(i)
                .unwrap()
                .events
                .iter()
                .any(|ev| matches!(ev, SeCommissioningEvent::Steady { .. }))
        }),
        "{:?}",
        sim.app::<Ihd>(i).unwrap().events
    );
    let events = &sim.app::<Ihd>(i).unwrap().events;
    assert_eq!(events[0], SeCommissioningEvent::Joined);
    assert_eq!(events[1], SeCommissioningEvent::KeyEstablished);
    assert_eq!(
        events[2],
        SeCommissioningEvent::EsiFound {
            address: ShortAddress::COORDINATOR,
            endpoint: EP
        }
    );
    assert_eq!(events[3], SeCommissioningEvent::Steady { bindings: 2 });
    assert_eq!(sim.app::<Ihd>(i).unwrap().driver.phase(), Phase::Steady);
    let esis = sim.app::<Ihd>(i).unwrap().driver.esis().to_vec();
    assert_eq!(esis.len(), 1);
    assert_eq!(esis[0].ieee, Some(ESI_IEEE));
    // The ESI holds the two bindings towards the display.
    let bound: Vec<_> = sim
        .stack(e)
        .aps
        .bindings
        .iter()
        .map(|b| (b.src_endpoint, b.cluster))
        .collect();
    assert_eq!(bound.len(), 2);
    assert!(bound.contains(&(EP, c::PRICE)));
    assert!(bound.contains(&(EP, c::MESSAGING)));
    // A price published to the bindings reaches the display under the
    // established link key.
    let p = PublishPrice::new(7, b"Bound", 0x3001, 0, 0, 60, 1500);
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert!(app.price.publish(stack, Destination::Bound, &p));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        !x.app::<Ihd>(i).unwrap().prices.is_empty()
    }));
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().prices[0],
        PriceEvent::Published {
            provider_id: 7,
            issuer_event_id: 0x3001,
            stored: true
        }
    );
    // The ESI vanishes: three keep-alive failures start rejoin and
    // recovery; the rejoins and the channel scan fail and the display
    // waits its recovery period on the original channel.
    sim.isolate(e);
    assert!(
        sim.run_until(Duration::from_mins(70), |x| {
            x.app::<Ihd>(i)
                .unwrap()
                .events
                .iter()
                .any(|ev| matches!(ev, SeCommissioningEvent::Recovering))
        }),
        "{:?}",
        sim.app::<Ihd>(i).unwrap().events
    );
    assert_eq!(
        sim.app::<Ihd>(i).unwrap().driver.phase(),
        Phase::RejoinRecovery
    );
    sim.run_for(Duration::from_mins(5));
    assert!(
        sim.app::<Ihd>(i).unwrap().driver.deadline().is_some(),
        "waiting for the next recovery attempt"
    );
    // The ESI is back: the next attempt rejoins, rediscovers and binds
    // again.
    sim.unblock(e, i);
    let before = sim.app::<Ihd>(i).unwrap().events.len();
    assert!(
        sim.run_until(Duration::from_mins(130), |x| {
            x.app::<Ihd>(i).unwrap().events[before..]
                .iter()
                .any(|ev| matches!(ev, SeCommissioningEvent::Steady { .. }))
        }),
        "{:?}",
        sim.app::<Ihd>(i).unwrap().events
    );
    assert_eq!(sim.app::<Ihd>(i).unwrap().driver.phase(), Phase::Steady);
}

#[test]
fn the_display_follows_a_trust_center_swap_out() {
    let mut sim = Simulator::new();
    let esi_app = |cert: &'static [u8], ephemeral: &'static [u8]| {
        let mut price = PriceServer::new(EP);
        price.clock.set(UTC, Instant::ZERO);
        Box::new(Esi {
            cbke: CbkeDriver::new(Vectors { cert, ephemeral }, EP, ISSUER, TIMING),
            price,
        })
    };
    let e1 = sim.add_stack(
        "esi1",
        node(LogicalDeviceType::Coordinator, ESI_IEEE, 111),
        esi_app(&CERT_V, &QEV),
    );
    let mut ihd_price = PriceClient::new(EP);
    ihd_price.clock.set(UTC, Instant::ZERO);
    let i = sim.add_stack(
        "ihd",
        node(LogicalDeviceType::Router, IHD_IEEE, 112),
        Box::new(Ihd {
            driver: SeCommissioning::new(
                Vectors {
                    cert: &CERT_U,
                    ephemeral: &QEU,
                },
                EP,
                ISSUER,
                TIMING,
                &[c::PRICE],
                Duration::from_mins(3 * 60),
                Duration::from_mins(60),
            ),
            price: ihd_price,
            events: Vec::new(),
            prices: Vec::new(),
        }),
    );
    sim.stack(e1).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(e1)
            .iter()
            .any(|ev| matches!(ev, StackEvent::NetworkFormed { .. }))
    }));
    let epid = sim.stack(e1).nwk.nib.extended_pan_id;
    sim.stack(e1).permit_join_network(254).unwrap();
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        app.driver.start(stack);
    }
    assert!(sim.run_until(Duration::from_secs(120), |x| {
        x.app::<Ihd>(i)
            .unwrap()
            .events
            .iter()
            .any(|ev| matches!(ev, SeCommissioningEvent::Steady { .. }))
    }));
    sim.run_for(Duration::from_secs(5));
    // The ESI is backed up (hashed keys), vanishes, and a replacement
    // restores the backup on the same extended PAN.
    let backup = sim.stack(e1).trust_center_backup::<8>().unwrap();
    sim.isolate(e1);
    let mut esi2 = node(LogicalDeviceType::Coordinator, ExtendedAddress(3), 113);
    assert_eq!(esi2.restore_trust_center_backup(&backup), 1);
    let e2 = sim.add_stack("esi2", esi2, esi_app(&CERT_V3, &QEV));
    sim.stack(e2)
        .form_network_with_key(Key128::from_bytes([0xC3; 16]))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(e2)
            .iter()
            .any(|ev| matches!(ev, StackEvent::NetworkFormed { .. }))
    }));
    assert_eq!(sim.stack(e2).nwk.nib.extended_pan_id, epid);
    // Keep-alive failures start the recovery; the rejoin lands on the
    // replacement, the swap-out is followed by Key Establishment with
    // it, and the display rediscovers and binds again.
    let before = sim.app::<Ihd>(i).unwrap().events.len();
    assert!(
        sim.run_until(Duration::from_mins(90), |x| {
            x.app::<Ihd>(i).unwrap().events[before..]
                .iter()
                .any(|ev| matches!(ev, SeCommissioningEvent::Steady { .. }))
        }),
        "{:?}",
        sim.app::<Ihd>(i).unwrap().events
    );
    let events = &sim.app::<Ihd>(i).unwrap().events[before..];
    assert!(events.contains(&SeCommissioningEvent::Recovering));
    assert!(events.contains(&SeCommissioningEvent::TrustCenterSwapped {
        new: ExtendedAddress(3)
    }));
    let swapped = events
        .iter()
        .position(|ev| matches!(ev, SeCommissioningEvent::TrustCenterSwapped { .. }))
        .unwrap();
    let established = events
        .iter()
        .position(|ev| matches!(ev, SeCommissioningEvent::KeyEstablished))
        .unwrap();
    assert!(established > swapped);
    assert_eq!(
        sim.stack(i).aps.aib.trust_center_address,
        ExtendedAddress(3)
    );
    assert_eq!(sim.stack(e2).aps.bindings.len(), 1);
    // The new ESI's bound publish reaches the display under the new key.
    let p = PublishPrice::new(7, b"New", 0x3002, 0, 0, 60, 1600);
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e2).unwrap();
        assert!(app.price.publish(stack, Destination::Bound, &p));
    }
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.app::<Ihd>(i).unwrap().prices.iter().any(|pe| {
            matches!(
                pe,
                PriceEvent::Published {
                    issuer_event_id: 0x3002,
                    ..
                }
            )
        })
    }));
}
