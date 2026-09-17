//! Green Power Basic Combo over the simulator: the coordinator sink
//! commissions a GPD tunnelled by a router proxy (multi-hop, with the
//! OOB key protected under the gpLinkKey), announces its alias, pairs the
//! proxy with GP Pairing, executes the GPD's Toggle exactly once whether it
//! arrives directly or tunnelled, removes the pairing on Decommissioning
//! and keeps its Sink Table across a reboot.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::{Encode, Writer};
use panweave_green_power::cluster::CommunicationMode;
use panweave_green_power::command;
use panweave_green_power::commissioning::{Commissioning, KeyField, SecurityCapabilities};
use panweave_green_power::gpdf::{
    ApplicationId, ExtendedFrameControl, FrameType, GpdId, NwkFrameControl, SecurityLevel,
    mac_header, write_header,
};
use panweave_green_power::security::{self, Direction, KeyType};
use panweave_mac::frame::{Frame as MacFrame, MacAddress};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::green_power::SinkOptions;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ProfileId,
    ShortAddress,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const GPD: GpdId = GpdId::SrcId(0x8765_4321);
const ALIAS: ShortAddress = ShortAddress(0x4321);
const OOB_KEY: Key128 = Key128::from_bytes([
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
]);

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
        // The light the GPD switch controls.
        let desc = SimpleDescriptor::new(
            Endpoint(1),
            ProfileId::HOME_AUTOMATION,
            DeviceId(0x0100),
            1,
            &[ClusterId(0), identify::ID, on_off::ID],
            &[],
        )
        .unwrap();
        let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
        ep.add_instance(identify::server().unwrap()).unwrap();
        ep.add_instance(on_off::server().unwrap()).unwrap();
        n.add_endpoint(desc, ep).unwrap();
    }
    n
}

/// A Data GPDF from the GPD, protected with `key` when given.
fn gpdf(
    seq: u8,
    level: SecurityLevel,
    counter: Option<u32>,
    app: &[u8],
    key: Option<&Key128>,
) -> Vec<u8> {
    let e = ExtendedFrameControl {
        application_id: ApplicationId::SrcId,
        security_level: level,
        individual_key: key.is_some(),
        rx_after_tx: false,
        from_proxy: false,
    };
    let fc = NwkFrameControl {
        frame_type: FrameType::Data,
        auto_commissioning: false,
        extension: true,
    };
    let mut hdr = [0u8; 16];
    let mut w = Writer::new(&mut hdr);
    write_header(&mut w, fc, Some(e), Some(&GPD), counter).unwrap();
    let hl = w.position();
    let mut payload = app.to_vec();
    let mic = key.map(|k| {
        security::protect::<SoftwareAes>(
            k,
            level,
            &GPD,
            counter.unwrap(),
            Direction::FromGpd,
            &hdr[..hl],
            &mut payload,
        )
        .unwrap()
    });
    let mut body = hdr[..hl].to_vec();
    body.extend(&payload);
    if let Some(m) = mic {
        body.extend(&m);
    }
    let mut buf = [0u8; 96];
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

fn commissioning_gpdf(seq: u8) -> Vec<u8> {
    let (protected, mic) = security::protect_gpd_key::<SoftwareAes>(
        &Key128::WELL_KNOWN_GLOBAL_TCLK,
        &GPD,
        Direction::FromGpd,
        0,
        &OOB_KEY,
    )
    .unwrap();
    let c = Commissioning {
        device_id: 0x02,
        sequence_number_capable: true,
        rx_on_capable: false,
        pan_id_request: false,
        key_request: false,
        fixed_location: false,
        security: Some(SecurityCapabilities {
            level: 0b10,
            key_type: KeyType::Individual,
            key_encryption: true,
        }),
        key: Some(KeyField {
            bytes: protected,
            mic: Some(mic),
        }),
        outgoing_counter: Some(0x10),
        application: None,
    };
    let mut body = vec![command::COMMISSIONING];
    let mut buf = [0u8; 64];
    let n = c.encode_to_slice(&mut buf).unwrap();
    body.extend(&buf[..n]);
    gpdf(seq, SecurityLevel::None, None, &body, None)
}

fn count(events: &[StackEvent], f: impl Fn(&StackEvent) -> bool) -> usize {
    events.iter().filter(|e| f(e)).count()
}

#[test]
fn combo_sink_commissions_a_gpd_through_a_proxy_and_runs_its_commands() {
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
    sim.stack(c)
        .enable_green_power_sink(SinkOptions::default())
        .unwrap();
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
    sim.take_events(c);
    sim.take_events(r);
    // Multi-hop commissioning: the sink involves the proxies; the GPD is
    // out of the sink's range.
    sim.stack(c)
        .green_power_commission(true, Some(Duration::from_secs(60)))
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(r).iter().any(|e| {
            matches!(
                e,
                StackEvent::GreenPowerCommissioningMode { until: Some(_) }
            )
        })
    }));
    assert!(sim.events(c).iter().any(|e| matches!(
        e,
        StackEvent::GreenPowerCommissioningMode { until: Some(_) }
    )));
    sim.block_injector(c);
    sim.inject(&commissioning_gpdf(1));
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::GreenPowerPaired { .. }))
    }));
    let paired = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::GreenPowerPaired {
                gpd,
                device_id,
                mode,
                alias,
            } => Some((*gpd, *device_id, *mode, *alias)),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        paired,
        (GPD, 0x02, CommunicationMode::DerivedGroupcast, ALIAS)
    );
    let entry = sim
        .stack(c)
        .green_power_sink()
        .unwrap()
        .table
        .find(&GPD)
        .cloned()
        .unwrap();
    assert_eq!(entry.security.as_ref().unwrap().key, Some(OOB_KEY.clone()));
    assert_eq!(entry.frame_counter, 0x10);
    // The sink left commissioning mode on the first pairing and told the
    // proxies; the proxy got the GP Pairing and the alias Device_annce.
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::GreenPowerCommissioningMode { until: None }))
            && x.stack_ref(r)
                .green_power_proxy_ref()
                .is_some_and(|p| p.table.find(&GPD).is_some())
    }));
    assert!(
        sim.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::GreenPowerCommissioningMode { until: None }))
    );
    let proxy_entry = sim
        .stack(r)
        .green_power_proxy()
        .unwrap()
        .table
        .find(&GPD)
        .cloned()
        .unwrap();
    assert!(proxy_entry.derived_group);
    assert_eq!(
        proxy_entry.security.as_ref().unwrap().key,
        Some(OOB_KEY.clone())
    );
    assert_eq!(proxy_entry.key_type(), KeyType::Individual);
    assert!(sim.events(r).iter().any(|e| matches!(
        e,
        StackEvent::DeviceAnnounce { short, ieee, .. } if *short == ALIAS && *ieee == ExtendedAddress::BROADCAST
    )));
    // The sink's Green Power EndPoint joined the derived group.
    assert!(
        sim.stack(c)
            .aps
            .groups
            .contains(panweave_types::GroupAddress(ALIAS.0), Endpoint(242))
    );
    // Operation: the Toggle reaches the sink directly and, tunnelled by
    // the proxy, once more; the light toggles exactly once.
    sim.unblock_injector(c);
    sim.take_events(c);
    sim.inject(&gpdf(
        2,
        SecurityLevel::Mic,
        Some(0x11),
        &[command::TOGGLE],
        Some(&OOB_KEY),
    ));
    sim.run_for(Duration::from_secs(3));
    let evs = sim.take_events(c);
    assert_eq!(
        count(
            &evs,
            |e| matches!(e, StackEvent::GreenPowerCommand { command_id, .. } if *command_id == command::TOGGLE)
        ),
        1
    );
    assert_eq!(
        count(&evs, |e| matches!(
            e,
            StackEvent::OnOff {
                endpoint: Endpoint(1),
                on: true
            }
        )),
        1
    );
    assert_eq!(sim.app::<OnOffApp>(c).unwrap().state, vec![(1, true)]);
    // Out of the sink's range the tunnelled copy alone drives the light.
    sim.block_injector(c);
    sim.inject(&gpdf(
        3,
        SecurityLevel::Mic,
        Some(0x12),
        &[command::TOGGLE],
        Some(&OOB_KEY),
    ));
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(c).iter().any(|e| {
            matches!(
                e,
                StackEvent::OnOff {
                    endpoint: Endpoint(1),
                    on: false
                }
            )
        })
    }));
    assert_eq!(
        sim.stack(c)
            .green_power_sink()
            .unwrap()
            .table
            .find(&GPD)
            .unwrap()
            .frame_counter,
        0x12
    );
    // A replay is ignored.
    sim.take_events(c);
    sim.inject(&gpdf(
        3,
        SecurityLevel::Mic,
        Some(0x12),
        &[command::TOGGLE],
        Some(&OOB_KEY),
    ));
    sim.run_for(Duration::from_secs(3));
    assert!(
        sim.events(c)
            .iter()
            .all(|e| !matches!(e, StackEvent::OnOff { .. }))
    );
    // The Sink Table survives a reboot of the sink.
    let storage = sim.stack(c).storage.clone();
    let mut fresh = node(LogicalDeviceType::Coordinator, COORD_IEEE, 43);
    fresh.storage = storage;
    assert!(matches!(
        fresh.restore().unwrap(),
        panweave_runtime::Restored::OnNetwork
    ));
    fresh
        .enable_green_power_sink(SinkOptions::default())
        .unwrap();
    let table = &fresh.green_power_sink().unwrap().table;
    assert_eq!(table.len(), 1);
    let e = table.find(&GPD).unwrap();
    assert_eq!(e.frame_counter, 0x12);
    assert_eq!(e.security.as_ref().unwrap().key, Some(OOB_KEY.clone()));
    // Decommissioning (tunnelled) removes the pairing on both sides.
    sim.take_events(c);
    sim.inject(&gpdf(
        4,
        SecurityLevel::Mic,
        Some(0x13),
        &[command::DECOMMISSIONING],
        Some(&OOB_KEY),
    ));
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::GreenPowerDecommissioned { gpd } if *gpd == GPD))
    }));
    assert!(sim.stack(c).green_power_sink().unwrap().table.is_empty());
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.stack_ref(r)
            .green_power_proxy_ref()
            .is_some_and(|p| p.table.find(&GPD).is_none())
    }));
}
