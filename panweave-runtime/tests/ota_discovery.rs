//! Discovery of the OTA upgrade server (ZCL8 §11.8): a client without a
//! preprogrammed server broadcasts a Match_Desc_req naming the OTA
//! cluster, takes the first server that answers, resolves its IEEE
//! address and stores it in `UpgradeServerID`; a client preprogrammed
//! with a server that is not the Trust Center resolves its network
//! address and asks the Trust Center for an application link key.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::ota::NO_SERVER;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_security::trust_center::AppKeyRequestPolicy;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::{identify, ota};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const SERVER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const CLIENT_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const EP: Endpoint = Endpoint(1);
const OTA_EP: Endpoint = Endpoint(7);

fn client_config() -> ota::ClientConfig {
    ota::ClientConfig {
        manufacturer_code: 0x1234,
        image_type: 1,
        file_version: 0x0100_0000,
        hardware_version: None,
        max_data_size: 48,
        activation_policy: ota::activation_policy::SERVER,
    }
}

/// A node with an Identify server on endpoint 1 and, when asked, an OTA
/// server on endpoint 7 or an OTA client (preprogrammed with `server`)
/// on endpoint 1.
fn node(
    role: LogicalDeviceType,
    ieee: ExtendedAddress,
    seed: u64,
    ota_server: bool,
    ota_client: Option<ExtendedAddress>,
) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    cfg.trust_center_policy.app_key_requests = AppKeyRequestPolicy::Any;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    let mut clients: heapless::Vec<ClusterId, 2> = heapless::Vec::new();
    if let Some(server) = ota_client {
        ep.add_instance(ota::client(&client_config(), server).unwrap())
            .unwrap();
        clients.push(ota::ID).unwrap();
    }
    let desc = SimpleDescriptor::new(
        EP,
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0005),
        1,
        &[identify::ID],
        &clients,
    )
    .unwrap();
    n.add_endpoint(desc, ep).unwrap();
    if ota_server {
        let mut ep = EndpointInstance::new(OTA_EP, ProfileId::HOME_AUTOMATION);
        ep.add_instance(ota::server()).unwrap();
        let desc = SimpleDescriptor::new(
            OTA_EP,
            ProfileId::HOME_AUTOMATION,
            DeviceId(0x0005),
            1,
            &[ota::ID],
            &[],
        )
        .unwrap();
        n.add_endpoint(desc, ep).unwrap();
    }
    n
}

fn ota_server(events: &[StackEvent]) -> Option<(ShortAddress, Endpoint, ExtendedAddress, bool)> {
    events.iter().find_map(|e| match e {
        StackEvent::OtaServer {
            endpoint,
            server,
            server_endpoint,
            ieee,
            key_requested,
        } if *endpoint == EP => Some((*server, *server_endpoint, *ieee, *key_requested)),
        _ => None,
    })
}

fn upgrade_server_id(stack: &SimStack) -> ExtendedAddress {
    ExtendedAddress(
        stack
            .zcl
            .cluster(EP, ota::ID, Role::Client)
            .unwrap()
            .u64(ota::UPGRADE_SERVER_ID.id)
            .unwrap(),
    )
}

/// Forms the network with the coordinator, joins the server router and
/// the client router, and waits for their verified link keys.
fn network(client_server: ExtendedAddress, coordinator_serves: bool) -> (Simulator, usize, usize) {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(
            LogicalDeviceType::Coordinator,
            COORD_IEEE,
            1,
            coordinator_serves,
            None,
        ),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "server",
        node(LogicalDeviceType::Router, SERVER_IEEE, 2, true, None),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "client",
        node(
            LogicalDeviceType::Router,
            CLIENT_IEEE,
            3,
            false,
            Some(client_server),
        ),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    for n in [s, r] {
        sim.stack(n).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| {
            x.events(n)
                .iter()
                .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
        }));
    }
    sim.run_for(Duration::from_secs(40));
    for n in [c, s, r] {
        sim.take_events(n);
    }
    (sim, s, r)
}

#[test]
fn client_discovers_the_first_server_and_stores_its_ieee_address() {
    // Only the router serves OTA: the client finds it by Match_Desc_req,
    // learns its IEEE address and asks for an application link key.
    let (mut sim, s, r) = network(NO_SERVER, false);
    let server_short = sim.stack(s).short_address();
    assert_eq!(upgrade_server_id(sim.stack(r)), NO_SERVER);
    sim.stack(r).discover_ota_server(EP).unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        ota_server(x.events(r)).is_some()
    }));
    assert_eq!(
        ota_server(sim.events(r)),
        Some((server_short, OTA_EP, SERVER_IEEE, true))
    );
    assert_eq!(upgrade_server_id(sim.stack(r)), SERVER_IEEE);
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        x.events(r).iter().any(|e| {
            matches!(
                e,
                StackEvent::ApplicationLinkKey {
                    partner: SERVER_IEEE,
                    initiator: true
                }
            )
        })
    }));
    // A second discovery finds the same server without another key
    // request; an endpoint without an OTA client is refused.
    sim.take_events(r);
    sim.stack(r).discover_ota_server(EP).unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        ota_server(x.events(r)).is_some()
    }));
    assert_eq!(ota_server(sim.events(r)).map(|s| s.3), Some(false));
    assert!(sim.stack(r).discover_ota_server(OTA_EP).is_err());
}

#[test]
fn trust_center_server_needs_no_application_key() {
    // Both the coordinator and the router serve; whoever answers first
    // is taken. The coordinator is nearer (one hop) in this topology
    // and, being the Trust Center, needs no application link key.
    let (mut sim, _s, r) = network(NO_SERVER, true);
    sim.stack(r).discover_ota_server(EP).unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        ota_server(x.events(r)).is_some()
    }));
    let (server, server_endpoint, ieee, key_requested) = ota_server(sim.events(r)).unwrap();
    assert_eq!(server_endpoint, OTA_EP);
    assert_eq!(upgrade_server_id(sim.stack(r)), ieee);
    if ieee == COORD_IEEE {
        assert_eq!(server, ShortAddress::COORDINATOR);
        assert!(!key_requested);
    } else {
        assert_eq!(ieee, SERVER_IEEE);
        assert!(key_requested);
    }
}

#[test]
fn preprogrammed_server_is_located_by_address() {
    let (mut sim, s, r) = network(SERVER_IEEE, false);
    let server_short = sim.stack(s).short_address();
    sim.stack(r).discover_ota_server(EP).unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        ota_server(x.events(r)).is_some()
    }));
    assert_eq!(
        ota_server(sim.events(r)),
        Some((server_short, Endpoint(0), SERVER_IEEE, true))
    );
    // A server that never answers: the discovery times out.
    sim.take_events(r);
    sim.isolate(s);
    sim.stack(r)
        .zcl
        .cluster_mut(EP, ota::ID, Role::Client)
        .unwrap()
        .set(
            ota::UPGRADE_SERVER_ID.id,
            &panweave_zcl::Value::Eui64(0x00AA_0000_0000_0077),
        );
    sim.stack(r).discover_ota_server(EP).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::OtaServerNotFound { endpoint: EP }))
    }));
}
