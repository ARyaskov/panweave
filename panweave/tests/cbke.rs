//! The CBKE driver: a router runs the Annex C exchange with the Trust
//! Center by itself after joining, both drivers install the derived
//! link key, and APS-secured traffic works with it.

#![cfg(feature = "smart-energy")]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave::aps::layer::{Destination, TxOptions};
use panweave::cbke::{CbkeDriver, CbkeOutcome};
use panweave::codec::Writer;
use panweave::mac::service::MacServiceConfig;
use panweave::runtime::{JoinMode, StackConfig, StackEvent};
use panweave::security::material::LinkKeyKind;
use panweave::smart_energy::key_establishment::{self as ke, Ecmqv, EcmqvError, Suite, Timing};
use panweave::smart_energy::{PROFILE_ID, devices};
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::time::{Duration, Instant};
use panweave::types::{
    ClusterId, Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress,
};
use panweave::zcl::clusters::basic;
use panweave::zcl::frame::{Direction, Header};
use panweave::zcl::global::command;
use panweave::zcl::layer::EndpointInstance;
use panweave::zdo::descriptor::SimpleDescriptor;
use panweave_sim::{App, SimStack, Simulator};

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
/// Device 1 of Annex C.5 (the responder / Trust Center).
const TC_IEEE: ExtendedAddress = ExtendedAddress(1);
/// Device 2 of Annex C.5 (the initiator).
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(2);
const ISSUER: ExtendedAddress = ExtendedAddress(0x5445_5354_5345_4341);
const EP: Endpoint = Endpoint(10);

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
/// KeyData of Annex C.5.3.3.
const KEY_DATA: [u8; 16] = [
    0x86, 0xD5, 0x8A, 0xAA, 0x99, 0x8E, 0x2F, 0xAE, 0xFA, 0xF9, 0xFE, 0xF4, 0x96, 0x06, 0x54, 0x3A,
];

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

const TIMING: Timing = Timing {
    ephemeral_data: 3,
    confirm_key: 6,
};

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, PROFILE_ID);
    ep.add_instance(basic::server(0x01, b"Panweave", b"SE").unwrap())
        .unwrap();
    ep.add_instance(ke::server(Suite::Suite1.bit()).unwrap())
        .unwrap();
    ep.add_instance(ke::client(Suite::Suite1.bit()).unwrap())
        .unwrap();
    let (servers, clients): (&[ClusterId], &[ClusterId]) = (&[basic::ID, ke::ID], &[ke::ID]);
    let device = if role == LogicalDeviceType::Coordinator {
        devices::ENERGY_SERVICE_INTERFACE
    } else {
        devices::IN_HOME_DISPLAY
    };
    let desc = SimpleDescriptor::new(EP, PROFILE_ID, device, 1, servers, clients).unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

/// An application that owns a driver and records its outcomes.
struct DriverApp {
    driver: CbkeDriver<Vectors>,
    outcomes: Vec<CbkeOutcome>,
    read_answered: bool,
}

impl DriverApp {
    fn new(cert: &'static [u8], ephemeral: &'static [u8], auto: bool) -> Self {
        let driver = CbkeDriver::new(Vectors { cert, ephemeral }, EP, ISSUER, TIMING);
        DriverApp {
            driver: if auto {
                driver.start_after_join()
            } else {
                driver
            },
            outcomes: Vec::new(),
            read_answered: false,
        }
    }
}

impl App for DriverApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(o) = self.driver.on_event(stack, event) {
            self.outcomes.push(o);
        }
        if let StackEvent::ZclResponse(f) = event
            && f.origin.cluster == basic::ID
            && f.origin.header.command == command::READ_ATTRIBUTES_RESPONSE
        {
            self.read_answered = f.origin.aps_secured;
        }
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        if let Some(o) = self.driver.poll(stack, now) {
            self.outcomes.push(o);
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.driver.deadline()
    }
}

#[test]
fn the_driver_runs_cbke_after_joining() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "tc",
        node(LogicalDeviceType::Coordinator, TC_IEEE, 41),
        Box::new(DriverApp::new(&CERT_V, &QEV, false)),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 42),
        Box::new(DriverApp::new(&CERT_U, &QEU, true)),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    // The exchange starts by itself on the Joined event and ends with
    // both sides holding the Annex C.5 key.
    assert!(
        sim.run_until(Duration::from_secs(90), |x| {
            x.app::<DriverApp>(r).unwrap().outcomes.len() == 1
                && x.app::<DriverApp>(c).unwrap().outcomes.len() == 1
        }),
        "router {:?} tc {:?}",
        sim.app::<DriverApp>(r).unwrap().outcomes,
        sim.app::<DriverApp>(c).unwrap().outcomes
    );
    assert_eq!(
        sim.app::<DriverApp>(r).unwrap().outcomes[0],
        CbkeOutcome::Established { partner: TC_IEEE }
    );
    assert_eq!(
        sim.app::<DriverApp>(c).unwrap().outcomes[0],
        CbkeOutcome::Established {
            partner: ROUTER_IEEE
        }
    );
    assert!(!sim.app::<DriverApp>(r).unwrap().driver.is_busy());
    let tc_entry = sim.stack(r).aps.security.entry(TC_IEEE).unwrap();
    assert_eq!(tc_entry.key.as_bytes(), &KEY_DATA);
    assert_eq!(tc_entry.kind, LinkKeyKind::Unique);
    assert_eq!(
        sim.stack(c)
            .aps
            .security
            .entry(ROUTER_IEEE)
            .unwrap()
            .key
            .as_bytes(),
        &KEY_DATA
    );
    // The key works: an APS-secured read of the Trust Center's Basic
    // cluster is answered under it.
    let seq = sim.stack(r).zcl.next_seq();
    let header = Header::global(seq, command::READ_ATTRIBUTES, Direction::ToServer);
    let mut payload = [0u8; 2];
    let mut w = Writer::new(&mut payload);
    panweave::zcl::global::write_attribute_ids(&mut w, &[basic::ZCL_VERSION.id]).unwrap();
    sim.stack(r)
        .zcl
        .send(
            Destination::Short {
                address: ShortAddress::COORDINATOR,
                endpoint: EP,
            },
            PROFILE_ID,
            basic::ID,
            EP,
            &header,
            &payload,
            TxOptions {
                security: true,
                ..TxOptions::ACKED
            },
        )
        .unwrap();
    sim.stack(r).flush();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        x.app::<DriverApp>(r).unwrap().read_answered
    }));
    // A second exchange can be started by hand once the first is over.
    {
        let (stack, app) = sim.stack_and_app::<DriverApp>(r).unwrap();
        app.driver
            .start(stack, ShortAddress::COORDINATOR, TC_IEEE)
            .unwrap();
        assert!(app.driver.is_busy());
    }
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.app::<DriverApp>(r).unwrap().outcomes.len() == 2
    }));
}
