//! Certificate-based key establishment end to end: a router joins a
//! Trust Center with the preconfigured link key, runs the Annex C
//! exchange over the Key Establishment cluster (the ECMQV primitive
//! replays the C.5 vectors), both sides install the derived link key,
//! and an APS-secured read then succeeds with the new key.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::layer::{Destination, TxOptions};
use panweave_codec::Writer;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_security::material::LinkKeyKind;
use panweave_sim::{App, SimStack, Simulator};
use panweave_smart_energy::key_establishment::{
    self as ke, Ecmqv, EcmqvError, Initiate, Initiator, Outgoing, Responder, Suite, Terminate,
    Timing,
};
use panweave_smart_energy::{PROFILE_ID, devices};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ClusterId, CommandId, Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress,
};
use panweave_zcl::clusters::basic;
use panweave_zcl::frame::{Direction, FrameType, Header};
use panweave_zcl::global::command;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

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

fn send(stack: &mut SimStack, dst: ShortAddress, cmd: u8, direction: Direction, payload: &[u8]) {
    stack
        .zcl
        .send_command(
            Destination::Short {
                address: dst,
                endpoint: EP,
            },
            PROFILE_ID,
            ke::ID,
            EP,
            CommandId(cmd),
            direction,
            None,
            payload,
        )
        .unwrap();
}

/// The initiator (client) side as a simulator application.
struct ClientApp {
    machine: Option<Initiator<Vectors>>,
    remote_cert: Vec<u8>,
    key: Option<Key128>,
    terminated: Option<Terminate>,
    read_answered: bool,
}

impl ClientApp {
    fn new() -> Self {
        ClientApp {
            machine: None,
            remote_cert: Vec::new(),
            key: None,
            terminated: None,
            read_answered: false,
        }
    }

    fn start(&mut self, stack: &mut SimStack) {
        let m = Initiator::new(
            Vectors {
                cert: &CERT_U,
                ephemeral: &QEU,
            },
            ROUTER_IEEE,
            TC_IEEE,
        );
        let mut buf = [0u8; 64];
        let n = m.initiate(TIMING).encode(&mut buf).unwrap();
        send(
            stack,
            ShortAddress::COORDINATOR,
            ke::command::INITIATE_KEY_ESTABLISHMENT,
            Direction::ToServer,
            &buf[..n],
        );
        self.machine = Some(m);
    }

    fn deliver(&mut self, stack: &mut SimStack, out: Outgoing) {
        match out {
            Outgoing::EphemeralData(p) => send(
                stack,
                ShortAddress::COORDINATOR,
                ke::command::EPHEMERAL_DATA,
                Direction::ToServer,
                &p,
            ),
            Outgoing::ConfirmKey(mac) => send(
                stack,
                ShortAddress::COORDINATOR,
                ke::command::CONFIRM_KEY,
                Direction::ToServer,
                &mac,
            ),
            Outgoing::Terminate(t) => {
                self.terminated = Some(t);
                send(
                    stack,
                    ShortAddress::COORDINATOR,
                    ke::command::TERMINATE_KEY_ESTABLISHMENT,
                    Direction::ToServer,
                    &t.encode(),
                );
            }
        }
    }
}

impl App for ClientApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        match event {
            StackEvent::ZclCommand(f)
                if f.origin.cluster == ke::ID
                    && f.origin.header.control.direction == Direction::ToClient =>
            {
                let Some(m) = self.machine.as_mut() else {
                    return;
                };
                match f.origin.header.command.0 {
                    ke::command::INITIATE_KEY_ESTABLISHMENT => {
                        let Ok(rsp) = Initiate::parse(&f.payload) else {
                            return;
                        };
                        self.remote_cert = rsp.certificate.to_vec();
                        let out = m.on_initiate_response::<SoftwareAes>(&rsp, &ISSUER);
                        self.deliver(stack, out);
                    }
                    ke::command::EPHEMERAL_DATA => {
                        let cert = self.remote_cert.clone();
                        let out = m.on_ephemeral_response::<SoftwareAes>(&cert, &f.payload);
                        self.deliver(stack, out);
                    }
                    ke::command::CONFIRM_KEY => {
                        match m.on_confirm_response::<SoftwareAes>(&f.payload) {
                            Ok(key) => {
                                stack.install_link_key(
                                    TC_IEEE,
                                    key.clone(),
                                    LinkKeyKind::Unique,
                                    false,
                                );
                                self.key = Some(key);
                                // Prove the key: an APS-secured read of the
                                // Trust Center's Basic cluster.
                                let seq = stack.zcl.next_seq();
                                let header = Header::global(
                                    seq,
                                    command::READ_ATTRIBUTES,
                                    Direction::ToServer,
                                );
                                let mut payload = [0u8; 2];
                                let mut w = Writer::new(&mut payload);
                                panweave_zcl::global::write_attribute_ids(
                                    &mut w,
                                    &[basic::ZCL_VERSION.id],
                                )
                                .unwrap();
                                stack
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
                            }
                            Err(out) => self.deliver(stack, out),
                        }
                    }
                    ke::command::TERMINATE_KEY_ESTABLISHMENT => {
                        self.terminated = Terminate::parse(&f.payload);
                        m.on_terminate();
                    }
                    _ => {}
                }
            }
            StackEvent::ZclResponse(f)
                if f.origin.cluster == basic::ID
                    && f.origin.header.command == command::READ_ATTRIBUTES_RESPONSE =>
            {
                self.read_answered = f.origin.aps_secured;
            }
            _ => {}
        }
    }
}

/// The responder (server) side as a simulator application.
struct ServerApp {
    machine: Responder<Vectors>,
    key: Option<Key128>,
}

impl ServerApp {
    fn new() -> Self {
        ServerApp {
            machine: Responder::new(
                Vectors {
                    cert: &CERT_V,
                    ephemeral: &QEV,
                },
                TC_IEEE,
                ROUTER_IEEE,
            ),
            key: None,
        }
    }
}

impl App for ServerApp {
    fn on_event(&mut self, stack: &mut SimStack, event: &StackEvent) {
        let StackEvent::ZclCommand(f) = event else {
            return;
        };
        if f.origin.cluster != ke::ID || f.origin.header.control.direction != Direction::ToServer {
            return;
        }
        let origin = f.origin;
        let reply = |stack: &mut SimStack, cmd: u8, payload: &[u8]| {
            stack
                .zcl
                .respond(&origin, CommandId(cmd), FrameType::ClusterSpecific, payload)
                .unwrap();
        };
        match f.origin.header.command.0 {
            ke::command::INITIATE_KEY_ESTABLISHMENT => {
                let Ok(req) = Initiate::parse(&f.payload) else {
                    return;
                };
                match self.machine.on_initiate(&req, &ISSUER, TIMING) {
                    Ok(rsp) => {
                        let mut buf = [0u8; 64];
                        let n = rsp.encode(&mut buf).unwrap();
                        reply(stack, ke::command::INITIATE_KEY_ESTABLISHMENT, &buf[..n]);
                    }
                    Err(t) => reply(stack, ke::command::TERMINATE_KEY_ESTABLISHMENT, &t.encode()),
                }
            }
            ke::command::EPHEMERAL_DATA => {
                match self.machine.on_ephemeral::<SoftwareAes>(&f.payload) {
                    Outgoing::EphemeralData(p) => reply(stack, ke::command::EPHEMERAL_DATA, &p),
                    Outgoing::Terminate(t) => {
                        reply(stack, ke::command::TERMINATE_KEY_ESTABLISHMENT, &t.encode());
                    }
                    Outgoing::ConfirmKey(_) => unreachable!(),
                }
            }
            ke::command::CONFIRM_KEY => match self.machine.on_confirm::<SoftwareAes>(&f.payload) {
                Ok((Outgoing::ConfirmKey(mac), key)) => {
                    stack.install_link_key(ROUTER_IEEE, key.clone(), LinkKeyKind::Unique, false);
                    self.key = Some(key);
                    reply(stack, ke::command::CONFIRM_KEY, &mac);
                }
                Ok(_) => unreachable!(),
                Err(Outgoing::Terminate(t)) => {
                    reply(stack, ke::command::TERMINATE_KEY_ESTABLISHMENT, &t.encode());
                }
                Err(_) => unreachable!(),
            },
            _ => {}
        }
    }
}

#[test]
fn cbke_over_the_key_establishment_cluster_installs_a_working_link_key() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "tc",
        node(LogicalDeviceType::Coordinator, TC_IEEE, 41),
        Box::new(ServerApp::new()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 42),
        Box::new(ClientApp::new()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    }));
    sim.run_for(Duration::from_secs(5));
    let start: Instant = sim.clock.now();
    {
        let (stack, app) = sim.stack_and_app::<ClientApp>(r).unwrap();
        app.start(stack);
    }
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            x.app::<ClientApp>(r).unwrap().read_answered
        }),
        "client: {:?} key {:?}
router events: {:?}
tc events: {:?}",
        sim.app::<ClientApp>(r).unwrap().terminated,
        sim.app::<ClientApp>(r).unwrap().key.is_some(),
        sim.events(r)
            .iter()
            .filter(|e| matches!(e, StackEvent::ZclCommand(_) | StackEvent::ZclResponse(_)))
            .collect::<Vec<_>>(),
        sim.events(c)
            .iter()
            .filter(|e| matches!(e, StackEvent::ZclCommand(_) | StackEvent::ZclResponse(_)))
            .collect::<Vec<_>>()
    );
    let client = sim.app::<ClientApp>(r).unwrap();
    let server = sim.app::<ServerApp>(c).unwrap();
    assert_eq!(client.terminated, None);
    assert_eq!(client.key.as_ref().unwrap().as_bytes(), &KEY_DATA);
    assert_eq!(server.key.as_ref().unwrap().as_bytes(), &KEY_DATA);
    assert!(sim.clock.now().as_millis() > start.as_millis());
    // Both link-key entries are the verified unique key.
    let tc_entry = sim.stack(r).aps.security.entry(TC_IEEE).unwrap();
    assert_eq!(
        tc_entry.attributes,
        panweave_types::KeyAttributes::VerifiedKey
    );
    assert!(sim.stack(c).aps.security.entry(ROUTER_IEEE).is_some());
}
