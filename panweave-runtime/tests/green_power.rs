//! Green Power Basic Proxy over the simulator: a router proxy pairs with
//! the coordinator (acting as a sink at the application level), tunnels a
//! GPD's GPDF as a GP Notification with NWK aliasing, forwards
//! commissioning frames while in commissioning mode, and keeps its Proxy
//! Table across a reboot.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_codec::{Decode, Encode};
use panweave_green_power::cluster::{
    self as gp, CommissioningNotification, CommunicationMode, Notification, Pairing,
    ProxyCommissioningMode, SinkAddress,
};
use panweave_green_power::command;
use panweave_green_power::gpdf::{GpdId, mac_header};
use panweave_green_power::proxy_table::derived_alias;
use panweave_green_power::security::KeyType;
use panweave_mac::frame::{Frame as MacFrame, MacAddress};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    CommandId, DeviceId, ExtendedAddress, GroupAddress, LogicalDeviceType, ShortAddress,
};
use panweave_zcl::frame::Direction;
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::{ClusterDef, ClusterInstance, Role};
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const GPD: GpdId = GpdId::SrcId(0x8765_4321);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    if role == LogicalDeviceType::Coordinator {
        // The sink side is application code: the Green Power EndPoint
        // with a server instance so that notifications reach the app.
        let desc = SimpleDescriptor::new(
            gp::ENDPOINT,
            gp::PROFILE,
            DeviceId(0x0066),
            0,
            &[gp::ID],
            &[gp::ID],
        )
        .unwrap();
        let mut ep = EndpointInstance::new(gp::ENDPOINT, gp::PROFILE);
        let def = ClusterDef {
            id: gp::ID,
            revision: gp::REVISION,
            received: &[],
            generated: &[],
        };
        ep.add_instance(ClusterInstance::new(def, Role::Server))
            .unwrap();
        ep.add_instance(ClusterInstance::new(def, Role::Client))
            .unwrap();
        n.add_endpoint(desc, ep).unwrap();
    }
    n
}

fn gpdf(seq: u8, command: u8) -> Vec<u8> {
    let body = [0x0C, 0x21, 0x43, 0x65, 0x87, command];
    let mut buf = [0u8; 40];
    let n = MacFrame {
        header: mac_header(
            seq,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    buf[..n].to_vec()
}

/// Sends a Green Power cluster command from the coordinator's sink
/// endpoint as a network-wide broadcast.
fn sink_broadcast(sim: &mut Simulator, c: usize, cmd: CommandId, payload: &[u8]) {
    sim.stack(c)
        .zcl
        .send_command(
            Destination::Short {
                address: ShortAddress::BROADCAST_RX_ON,
                endpoint: gp::ENDPOINT,
            },
            gp::PROFILE,
            gp::ID,
            gp::ENDPOINT,
            cmd,
            Direction::ToClient,
            None,
            payload,
        )
        .unwrap();
    sim.stack(c).flush();
}

fn notifications(sim: &Simulator, c: usize) -> Vec<Notification<'_>> {
    sim.events(c)
        .iter()
        .filter_map(|e| match e {
            StackEvent::ZclCommand(f)
                if f.origin.cluster == gp::ID
                    && f.origin.header.command == gp::client_cmd::NOTIFICATION =>
            {
                Notification::decode_exact(&f.payload).ok()
            }
            _ => None,
        })
        .collect()
}

#[test]
fn router_proxy_tunnels_gpdfs_to_the_sink() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "sink",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "proxy",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 42),
        Box::new(OnOffApp::default()),
    );
    sim.stack(r).enable_green_power_proxy().unwrap();
    sim.stack(c)
        .form_network_with_key(NETWORK_KEY.clone())
        .unwrap();
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
    sim.run_for(Duration::from_secs(3));
    let router_short = sim.stack(r).short_address();
    // The sink is a member of the derived group of the GPD.
    let dgroup = derived_alias(&GPD);
    sim.stack(c)
        .aps
        .groups
        .add(GroupAddress(dgroup.0), gp::ENDPOINT)
        .unwrap();
    // Before any pairing the GPDF is ignored.
    sim.take_events(c);
    sim.inject(&gpdf(1, command::TOGGLE));
    sim.run_for(Duration::from_secs(1));
    assert!(notifications(&sim, c).is_empty());
    // GP Pairing (broadcast): derived groupcast for the GPD.
    let pairing = Pairing {
        gpd: GPD,
        add_sink: true,
        remove_gpd: false,
        mode: CommunicationMode::DerivedGroupcast,
        gpd_fixed: false,
        sequence_number_capable: true,
        security_level_raw: 0,
        key_type: KeyType::None,
        sink: Some(SinkAddress::Group(dgroup.0)),
        device_id: Some(0x02),
        frame_counter: Some(0),
        key: None,
        assigned_alias: None,
        groupcast_radius: None,
    };
    let mut buf = [0u8; 64];
    let n = pairing.encode_to_slice(&mut buf).unwrap();
    sink_broadcast(&mut sim, c, gp::server_cmd::PAIRING, &buf[..n]);
    sim.run_for(Duration::from_secs(2));
    assert_eq!(sim.stack(r).green_power_proxy().unwrap().table.len(), 1);
    // The GPD toggles: the proxy tunnels a GP Notification to the derived
    // group with the alias as NWK source.
    sim.take_events(c);
    sim.trace_enabled = true;
    sim.inject(&gpdf(2, command::TOGGLE));
    assert!(sim.run_until(Duration::from_secs(5), |x| !notifications(x, c).is_empty()));
    let n = notifications(&sim, c)[0];
    assert_eq!(n.gpd, GPD);
    assert_eq!(n.command_id, command::TOGGLE);
    assert_eq!(n.frame_counter, 2);
    assert!(n.also_derived_group);
    assert_eq!(n.proxy.map(|p| p.0), Some(router_short));
    let aliased = sim.trace.iter().any(|t| {
        let s = panweave_pcap::summarize(&t.frame);
        s.contains(&format!("NWK data {dgroup} -> 0xfffd")) && s.contains("seq=2 ")
    });
    assert!(
        aliased,
        "GP Notification carries the alias NWK source and sequence"
    );
    let origin = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::ZclCommand(f) if f.origin.cluster == gp::ID => Some(f.origin),
            _ => None,
        })
        .unwrap();
    assert_eq!(origin.src, dgroup, "APS indication reports the alias");
    assert_eq!(origin.header.seq.0, 2, "APS counter = alias sequence");
    // Commissioning mode: a Commissioning GPDF from an unknown GPD is
    // forwarded as a GP Commissioning Notification.
    sim.take_events(c);
    let mode = ProxyCommissioningMode {
        enter: true,
        exit_on_first_pairing: false,
        exit_on_command: true,
        unicast: true,
        window_secs: Some(30),
        channel: None,
    };
    let n = mode.encode_to_slice(&mut buf).unwrap();
    sink_broadcast(
        &mut sim,
        c,
        gp::server_cmd::PROXY_COMMISSIONING_MODE,
        &buf[..n],
    );
    sim.run_for(Duration::from_secs(1));
    assert!(sim.events(r).iter().any(|e| matches!(
        e,
        StackEvent::GreenPowerCommissioningMode { until: Some(_) }
    )));
    let body = [
        0x0C,
        0x42,
        0x00,
        0x00,
        0x00,
        command::COMMISSIONING,
        0x02,
        0x80,
        0x00,
    ];
    let mut frame = [0u8; 40];
    let len = MacFrame {
        header: mac_header(7, MacAddress::Short(ShortAddress(0xffff)), MacAddress::None),
        payload: &body,
    }
    .encode_to_slice(&mut frame)
    .unwrap();
    sim.inject(&frame[..len]);
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(c).iter().any(|e| {
            matches!(
                e,
                StackEvent::ZclCommand(f)
                    if f.origin.cluster == gp::ID
                        && f.origin.header.command == gp::client_cmd::COMMISSIONING_NOTIFICATION
            )
        })
    }));
    let cn = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::ZclCommand(f)
                if f.origin.header.command == gp::client_cmd::COMMISSIONING_NOTIFICATION =>
            {
                CommissioningNotification::decode_exact(&f.payload).ok()
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(cn.gpd, GpdId::SrcId(0x42));
    assert_eq!(cn.command_id, command::COMMISSIONING);
    assert_eq!(cn.payload, &[0x02, 0x80, 0x00]);
    // The window expires by itself.
    sim.run_for(Duration::from_secs(35));
    assert!(
        sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::GreenPowerCommissioningMode { until: None }))
    );
    // The Proxy Table survives a reboot of the proxy.
    let storage = sim.stack(r).storage.clone();
    let mut fresh = node(LogicalDeviceType::Router, ROUTER_IEEE, 43);
    fresh.storage = storage;
    assert!(matches!(
        fresh.restore().unwrap(),
        panweave_runtime::Restored::OnNetwork
    ));
    fresh.enable_green_power_proxy().unwrap();
    let table = &fresh.green_power_proxy().unwrap().table;
    assert_eq!(table.len(), 1);
    let e = table.find(&GPD).unwrap();
    assert!(e.derived_group);
    assert_eq!(e.frame_counter, 2, "last counter persisted with the entry");
}
