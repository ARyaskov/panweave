//! The Smart Energy Trust Center driver over the simulator: an ESI
//! provisions two devices with install codes, opens the network on the
//! §5.4.1.2 broadcast rule, authenticates the display that runs Key
//! Establishment, backs its hashed key up, and removes the device that
//! never establishes a key once the grace period passes.

#![cfg(feature = "smart-energy")]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave::cbke::CbkeDriver;
use panweave::mac::service::MacServiceConfig;
use panweave::runtime::{JoinMode, StackConfig, StackEvent};
use panweave::security::key_hierarchy::link_key_from_install_code;
use panweave::security::material::LinkKeyKind;
use panweave::security::trust_center::InstallCodePolicy;
use panweave::smart_energy::cluster as c;
use panweave::smart_energy::key_establishment::{Ecmqv, EcmqvError, Suite, Timing};
use panweave::smart_energy::security::{KeyState, Registration};
use panweave::smart_energy_drivers::commissioning::{SeCommissioning, SeCommissioningEvent};
use panweave::smart_energy_drivers::trust_center::{SeTrustCenter, SeTrustCenterEvent};
use panweave::smart_energy_endpoints as se;
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::time::{Duration, Instant};
use panweave::types::{Endpoint, ExtendedAddress, InstallCode, Key128, LogicalDeviceType};
use panweave_security::cipher::SoftwareAes;
use panweave_sim::{App, OnOffApp, SimStack, Simulator};

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const ESI_IEEE: ExtendedAddress = ExtendedAddress(1);
const IHD_IEEE: ExtendedAddress = ExtendedAddress(2);
const LCD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0007);
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
const TIMING: Timing = Timing {
    ephemeral_data: 3,
    confirm_key: 6,
};
const LCD_CODE: [u8; 18] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0xD5, 0xE6,
];
const IHD_CODE: [u8; 18] = [
    0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5, 0x05,
    0xC3, 0xB5,
];

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

fn node(cfg: StackConfig, seed: u64, clients: &[panweave::types::ClusterId]) -> SimStack {
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    se::apply_profile_to_stack(&mut n);
    let (desc, ep) = if n.config.role == LogicalDeviceType::Coordinator {
        se::energy_service_interface(EP).unwrap()
    } else {
        se::in_home_display(EP, clients).unwrap()
    };
    n.add_endpoint(desc, ep).unwrap();
    n
}

struct Esi {
    tc: SeTrustCenter,
    cbke: CbkeDriver<Vectors>,
    events: Vec<SeTrustCenterEvent>,
}

impl App for Esi {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(o) = self.cbke.on_event(stack, event)
            && let Some(e) = self.tc.on_key_establishment(stack, &o, Suite::Suite1.bit())
        {
            self.events.push(e);
        }
        if let Some(e) = self.tc.on_event(stack, event) {
            self.events.push(e);
        }
    }

    fn on_poll(&mut self, stack: &mut SimStack, now: Instant) {
        let _ = self.cbke.poll(stack, now);
        if let Some(e) = self.tc.poll(stack, now) {
            self.events.push(e);
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.tc.deadline(Instant::ZERO).or(self.cbke.deadline())
    }
}

struct Ihd {
    driver: SeCommissioning<Vectors>,
    events: Vec<SeCommissioningEvent>,
}

impl App for Ihd {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        if let Some(e) = self.driver.on_event(stack, event) {
            self.events.push(e);
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
fn the_trust_center_provisions_opens_authenticates_and_prunes() {
    let mut sim = Simulator::new();
    let mut ecfg = StackConfig::new(LogicalDeviceType::Coordinator, ESI_IEEE);
    ecfg.trust_center_policy.allow_joins = true;
    ecfg.trust_center_policy.install_codes = InstallCodePolicy::Required;
    se::apply_profile(&mut ecfg);
    let mut tc = SeTrustCenter::new();
    tc.removal_after = Duration::from_mins(3);
    let e = sim.add_stack(
        "esi",
        node(ecfg, 121, &[]),
        Box::new(Esi {
            tc,
            cbke: CbkeDriver::new(
                Vectors {
                    cert: &CERT_V,
                    ephemeral: &QEV,
                },
                EP,
                ISSUER,
                TIMING,
            ),
            events: Vec::new(),
        }),
    );
    sim.stack(e).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(e)
            .iter()
            .any(|ev| matches!(ev, StackEvent::NetworkFormed { .. }))
    }));
    // Provision the display and a load control device with install
    // codes; the codes' keys become their preconfigured link keys.
    let ihd_code = InstallCode::new(&IHD_CODE).unwrap();
    let mut corrupt = IHD_CODE;
    corrupt[0] ^= 0x01;
    let lcd_code = InstallCode::new(&LCD_CODE).unwrap();
    let (ihd_key, lcd_key) = {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        // A code whose CRC does not check is refused (§5.4.8.1.1).
        assert!(
            app.tc
                .provision(stack, LCD_IEEE, &InstallCode::new(&corrupt).unwrap())
                .is_err()
        );
        let ihd_key = app.tc.provision(stack, IHD_IEEE, &ihd_code).unwrap();
        let lcd_key = app.tc.provision(stack, LCD_IEEE, &lcd_code).unwrap();
        (ihd_key, lcd_key)
    };
    assert_eq!(
        ihd_key,
        link_key_from_install_code::<SoftwareAes>(&ihd_code)
    );
    assert_eq!(sim.app::<Esi>(e).unwrap().tc.devices().len(), 2);
    // Open the network for ten minutes: the broadcast says 254 s.
    {
        let (stack, app) = sim.stack_and_app::<Esi>(e).unwrap();
        assert_eq!(
            app.tc.permit_join(stack, Duration::from_mins(10)),
            Some(SeTrustCenterEvent::PermitJoin(254))
        );
    }
    // The display joins with its install-code key and establishes a
    // key; the Trust Center authenticates it.
    let mut icfg = StackConfig::new(LogicalDeviceType::Router, IHD_IEEE);
    icfg.preconfigured_link_key = (ESI_IEEE, ihd_key, LinkKeyKind::Unique);
    se::apply_profile(&mut icfg);
    let i = sim.add_stack(
        "ihd",
        node(icfg, 122, &[c::PRICE]),
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
            events: Vec::new(),
        }),
    );
    {
        let (stack, app) = sim.stack_and_app::<Ihd>(i).unwrap();
        app.driver.start(stack);
    }
    assert!(
        sim.run_until(Duration::from_secs(120), |x| {
            x.app::<Esi>(e)
                .unwrap()
                .events
                .contains(&SeTrustCenterEvent::Authenticated(IHD_IEEE))
        }),
        "esi {:?} ihd {:?}",
        sim.app::<Esi>(e).unwrap().events,
        sim.app::<Ihd>(i).unwrap().events
    );
    let esi_events = &sim.app::<Esi>(e).unwrap().events;
    assert!(esi_events.contains(&SeTrustCenterEvent::Joined(IHD_IEEE)));
    // The device announce re-broadcast permit joining (the opening
    // broadcast was returned to the caller above).
    let joined = esi_events
        .iter()
        .position(|ev| *ev == SeTrustCenterEvent::Joined(IHD_IEEE))
        .unwrap();
    assert!(
        esi_events[joined..]
            .iter()
            .any(|ev| matches!(ev, SeTrustCenterEvent::PermitJoin(_)))
    );
    let d = sim
        .app::<Esi>(e)
        .unwrap()
        .tc
        .registry
        .get(IHD_IEEE)
        .cloned()
        .unwrap();
    assert_eq!(d.status, Registration::Authenticated);
    assert_eq!(d.key, KeyState::Cbke);
    assert!(d.key_hash.is_some());
    let mut backup = heapless::Vec::new();
    sim.app::<Esi>(e).unwrap().tc.backup(&mut backup);
    assert_eq!(backup.len(), 1);
    assert_eq!(backup[0].ieee, IHD_IEEE);
    assert_eq!(
        Some(backup[0].hashed_key.clone()),
        sim.stack(e).aps.security.swap_out_key(IHD_IEEE)
    );
    // The load control device joins but never establishes a key: after
    // the grace period the Trust Center removes it.
    let mut lcfg = StackConfig::new(LogicalDeviceType::Router, LCD_IEEE);
    lcfg.preconfigured_link_key = (ESI_IEEE, lcd_key, LinkKeyKind::Unique);
    se::apply_profile(&mut lcfg);
    let l = sim.add_stack(
        "lcd",
        node(lcfg, 123, &[c::PRICE]),
        Box::new(OnOffApp::default()),
    );
    sim.stack(l).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.app::<Esi>(e)
            .unwrap()
            .events
            .contains(&SeTrustCenterEvent::Joined(LCD_IEEE))
    }));
    assert!(
        sim.run_until(Duration::from_mins(5), |x| {
            x.app::<Esi>(e)
                .unwrap()
                .events
                .contains(&SeTrustCenterEvent::Removed(LCD_IEEE))
        }),
        "{:?}",
        sim.app::<Esi>(e).unwrap().events
    );
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(l)
            .iter()
            .any(|ev| matches!(ev, StackEvent::Left { .. }))
    }));
    assert_eq!(
        sim.app::<Esi>(e)
            .unwrap()
            .tc
            .registry
            .get(LCD_IEEE)
            .unwrap()
            .status,
        Registration::Left
    );
}
