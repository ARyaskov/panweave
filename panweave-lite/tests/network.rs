//! A Lite sensor with the full Panweave coordinator (and a router):
//! dynamic link key negotiation, secured rejoin after parent loss,
//! network key update, rejection of replayed and tampered frames,
//! frame-counter persistence failures, packet loss, buffered (indirect)
//! delivery, ZCL reads and reporting, rapid input changes, repeated
//! rejoins. Simulated only; no hardware or certification claim.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_aps::layer::Destination;
use panweave_lite::sensor::{Inputs, SensorKind};
use panweave_lite::{Delivery, LiteEvent, SENSOR_ENDPOINT};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_security::key_hierarchy::link_key_from_install_code;
use panweave_security::material::{InitialJoinAuthentication, LinkKeyEntry, LinkKeyKind};
use panweave_security::trust_center::InstallCodePolicy;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, CommandId, DeviceId, Endpoint, ExtendedAddress, InstallCode, Key128, KeyAttributes,
    LogicalDeviceType, ProfileId,
};
use panweave_zcl::clusters::{basic, ias_zone, power_configuration};
use panweave_zcl::frame::Direction;
use panweave_zcl::global::command;
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::{Role, global};
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD: u64 = 0x00BB_0000_0000_0001;
const ROUTER: u64 = 0x00BB_0000_0000_0002;
const SENSOR: u64 = 0x00BB_0000_0000_0010;

fn full(
    role: LogicalDeviceType,
    ieee: u64,
    seed: u64,
    policy: Option<InstallCodePolicy>,
) -> SimStack {
    let mut cfg = StackConfig::new(role, ExtendedAddress(ieee));
    cfg.trust_center_policy.allow_joins = true;
    if let Some(p) = policy {
        cfg.trust_center_policy.install_codes = p;
    }
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0400),
        0,
        &[ClusterId(0)],
        &[ias_zone::ID, power_configuration::ID],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(ias_zone::client()).unwrap();
    ep.add_instance(power_configuration::client()).unwrap();
    s.add_endpoint(desc, ep).unwrap();
    s
}

struct Net {
    sim: Simulator,
    c: usize,
    r: Option<usize>,
}

fn network(router: bool, policy: Option<InstallCodePolicy>) -> Net {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        full(LogicalDeviceType::Coordinator, COORD, 1, policy),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    let r = router.then(|| {
        let r = sim.add_stack(
            "router",
            full(LogicalDeviceType::Router, ROUTER, 2, None),
            Box::new(OnOffApp::default()),
        );
        sim.stack(r).join(JoinMode::Association).unwrap();
        assert!(sim.run_until(Duration::from_secs(60), |x| {
            x.events(r)
                .iter()
                .any(|e| matches!(e, StackEvent::Joined { .. }))
        }));
        sim.run_for(Duration::from_secs(3));
        sim.stack(c).permit_join_network(254).unwrap();
        r
    });
    Net { sim, c, r }
}

/// Adds the sensor and commissions it; it is enrolled by hand with the
/// coordinator as CIE (the plain coordinator runs no IAS CIE logic).
fn join_sensor(net: &mut Net, config: panweave_lite::LiteConfig) -> usize {
    let node = LiteNode::new(config, LiteStore::default(), SENSOR);
    let d = net.sim.add_device("sensor", Box::new(node));
    lite_mut(&mut net.sim, d)
        .dev
        .initialize(Inputs::default())
        .unwrap();
    lite_mut(&mut net.sim, d).dev.start_commissioning().unwrap();
    assert!(
        net.sim
            .run_until(Duration::from_secs(120), |x| lite(x, d).events.iter().any(
                |e| matches!(
                    e,
                    LiteEvent::Commissioning(panweave_bdb::Outcome::Steering(Ok(())))
                )
            ))
            && net.sim.run_until(Duration::from_secs(30), |x| lite(x, d)
                .dev
                .stack
                .is_operating()),
        "sensor: {:?}",
        lite(&net.sim, d).events
    );
    let c = net.c;
    let coord_short = net.sim.stack(c).short_address();
    let dev = &mut lite_mut(&mut net.sim, d).dev;
    let srv = dev
        .stack
        .zcl
        .cluster_mut(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
        .unwrap();
    ias_zone::restore_enrollment(
        srv,
        &ias_zone::Enrollment {
            cie_address: ExtendedAddress(COORD),
            cie: (coord_short, Endpoint(1)),
            zone_id: Some(7),
        },
    );
    net.sim.run_for(Duration::from_secs(2));
    d
}

fn assert_no_drops(sim: &Simulator, d: usize) {
    let dev = &lite(sim, d).dev;
    assert_eq!(dev.dropped_events, 0, "device events dropped");
    assert_eq!(dev.stack.dropped_events, 0, "stack events dropped");
    assert_eq!(dev.stack.zcl.dropped, 0, "ZCL actions / events dropped");
    assert_eq!(dev.stack.zdo.dropped, 0, "ZDO actions / events dropped");
    assert_eq!(
        dev.stack.aps.stats.actions_dropped, 0,
        "APS actions dropped"
    );
    assert_eq!(dev.stack.aps.stats.events_dropped, 0, "APS events dropped");
}

fn alarm_round_trip(sim: &mut Simulator, d: usize) {
    set_inputs(sim, d, wet());
    wait_confirmed(sim, d, 60);
    set_inputs(sim, d, dry());
    wait_confirmed(sim, d, 60);
}

#[test]
fn joins_with_install_code_key_negotiation_and_reports() {
    let mut net = network(false, Some(InstallCodePolicy::Required));
    let code = InstallCode::new(&[
        0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5,
        0x05, 0xC3, 0xB5,
    ])
    .unwrap();
    let ic_key = link_key_from_install_code::<panweave_security::cipher::SoftwareAes>(&code);
    let mut entry =
        LinkKeyEntry::provisional(ExtendedAddress(SENSOR), ic_key.clone(), LinkKeyKind::Unique);
    entry.initial_join_authentication = InitialJoinAuthentication::InstallCodeKey;
    let c = net.c;
    net.sim.stack(c).aps.install_link_key(entry).unwrap();
    net.sim.stack(c).flush();
    let mut cfg = sensor_config(SENSOR, SensorKind::WaterLeak, b"lite");
    cfg.link_key = (ExtendedAddress(COORD), ic_key.clone(), LinkKeyKind::Unique);
    let d = join_sensor(&mut net, cfg);
    // Both sides hold the same negotiated, verified key, which is not the
    // install-code key.
    let tc = net
        .sim
        .stack(c)
        .aps
        .security
        .entry(ExtendedAddress(SENSOR))
        .unwrap()
        .clone();
    let me = lite(&net.sim, d)
        .dev
        .stack
        .aps
        .security
        .entry(ExtendedAddress(COORD))
        .unwrap()
        .clone();
    assert_eq!(tc.key.as_bytes(), me.key.as_bytes());
    assert_ne!(me.key.as_bytes(), ic_key.as_bytes());
    assert_eq!(me.attributes, KeyAttributes::VerifiedKey);
    alarm_round_trip(&mut net.sim, d);
    assert_no_drops(&net.sim, d);
}

#[test]
fn a_wrong_install_code_key_is_not_admitted() {
    let mut net = network(false, Some(InstallCodePolicy::Required));
    let c = net.c;
    let mut entry = LinkKeyEntry::provisional(
        ExtendedAddress(SENSOR),
        Key128::from_bytes([0x11; 16]),
        LinkKeyKind::Unique,
    );
    entry.initial_join_authentication = InitialJoinAuthentication::InstallCodeKey;
    net.sim.stack(c).aps.install_link_key(entry).unwrap();
    let mut cfg = sensor_config(SENSOR, SensorKind::WaterLeak, b"lite");
    cfg.link_key = (
        ExtendedAddress(COORD),
        Key128::from_bytes([0x22; 16]),
        LinkKeyKind::Unique,
    );
    let node = LiteNode::new(cfg, LiteStore::default(), SENSOR);
    let d = net.sim.add_device("sensor", Box::new(node));
    lite_mut(&mut net.sim, d)
        .dev
        .initialize(Inputs::default())
        .unwrap();
    lite_mut(&mut net.sim, d).dev.start_commissioning().unwrap();
    net.sim.run_for(Duration::from_secs(90));
    assert!(!lite(&net.sim, d).dev.stack.is_operating());
    assert!(!lite(&net.sim, d).events.iter().any(|e| matches!(
        e,
        LiteEvent::Commissioning(panweave_bdb::Outcome::Steering(Ok(())))
    )));
}

#[test]
fn rejoins_through_a_router_after_parent_loss_and_delivers_an_alarm_raised_meanwhile() {
    let mut net = network(true, None);
    let (c, r) = (net.c, net.r.unwrap());
    let router_radio = net.sim.node_radio(r);
    // Join through the coordinator.
    let d = {
        let radio_hint = ();
        let _ = radio_hint;
        let node = LiteNode::new(
            sensor_config(SENSOR, SensorKind::WaterLeak, b"lite"),
            LiteStore::default(),
            SENSOR,
        );
        let d = net.sim.add_device("sensor", Box::new(node));
        let sr = net.sim.device_radio(d);
        net.sim.medium.block(sr, router_radio);
        d
    };
    lite_mut(&mut net.sim, d)
        .dev
        .initialize(Inputs::default())
        .unwrap();
    lite_mut(&mut net.sim, d).dev.start_commissioning().unwrap();
    assert!(net.sim.run_until(Duration::from_secs(120), |x| {
        lite(x, d).dev.stack.is_operating()
    }));
    let coord_short = net.sim.stack(c).short_address();
    {
        let srv = lite_mut(&mut net.sim, d)
            .dev
            .stack
            .zcl
            .cluster_mut(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
            .unwrap();
        ias_zone::restore_enrollment(
            srv,
            &ias_zone::Enrollment {
                cie_address: ExtendedAddress(COORD),
                cie: (coord_short, Endpoint(1)),
                zone_id: Some(1),
            },
        );
    }
    net.sim.run_for(Duration::from_secs(3));
    assert_eq!(
        lite(&net.sim, d).dev.stack.nwk.nib.parent_address,
        coord_short
    );
    // The coordinator vanishes for the sensor; the router is reachable.
    let sr = net.sim.device_radio(d);
    let cr = net.sim.node_radio(c);
    net.sim.medium.block(sr, cr);
    net.sim.medium.unblock(sr, router_radio);
    // Water while the parent is lost.
    set_inputs(&mut net.sim, d, wet());
    assert!(
        net.sim.run_until(Duration::from_secs(240), |x| lite(x, d)
            .events
            .iter()
            .any(|e| matches!(e, LiteEvent::Joined { rejoin: true, .. }))),
        "{:?}",
        lite(&net.sim, d).events
    );
    let router_short = net.sim.stack(r).short_address();
    assert_eq!(
        lite(&net.sim, d).dev.stack.nwk.nib.parent_address,
        router_short,
        "secured rejoin through the router"
    );
    wait_confirmed(&mut net.sim, d, 120);
    assert_eq!(
        lite(&net.sim, d).dev.reporter().published() & ias_zone::zone_status::ALARM1,
        ias_zone::zone_status::ALARM1
    );
    assert_no_drops(&net.sim, d);
}

#[test]
fn follows_a_network_key_update() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::Contact, b"lite"),
    );
    let c = net.c;
    let new_seq = net
        .sim
        .stack(c)
        .update_network_key(Key128::from_bytes([0xC3; 16]))
        .unwrap();
    assert!(
        net.sim.run_until(Duration::from_secs(120), |x| {
            x.device::<LiteNode>(d)
                .unwrap()
                .dev
                .stack
                .nwk
                .security
                .keys
                .active()
                .is_some_and(|k| k.sequence == new_seq)
        }),
        "the sensor did not switch to the new key"
    );
    alarm_round_trip(&mut net.sim, d);
    assert_no_drops(&net.sim, d);
}

/// The last secured frame the coordinator sent the sensor.
fn last_frame_to(sim: &Simulator, from: usize, short: u16) -> Vec<u8> {
    sim.trace
        .iter()
        .rev()
        .find(|t| {
            t.node == from
                && t.frame.len() > 30
                && t.frame.get(5..7) == Some(&short.to_le_bytes()[..])
                // NWK frame control: security bit (0x02 of the high octet).
                && t.frame.get(10).is_some_and(|b| b & 0x02 != 0)
        })
        .map(|t| t.frame.clone())
        .expect("no secured frame to the sensor in the trace")
}

#[test]
fn replayed_and_tampered_frames_are_rejected() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::WaterLeak, b"lite"),
    );
    let c = net.c;
    net.sim.trace_enabled = true;
    // The coordinator reads an attribute: a secured frame to the sensor,
    // delivered indirectly when the sensor polls.
    let short = lite(&net.sim, d).dev.stack.short_address();
    let mut payload = [0u8; 2];
    payload.copy_from_slice(&basic::ZCL_VERSION.id.0.to_le_bytes());
    net.sim
        .stack(c)
        .zcl
        .send_global(
            Destination::Short {
                address: short,
                endpoint: SENSOR_ENDPOINT,
            },
            ProfileId::HOME_AUTOMATION,
            basic::ID,
            Endpoint(1),
            command::READ_ATTRIBUTES,
            Direction::ToServer,
            None,
            &payload,
        )
        .unwrap();
    net.sim.stack(c).flush();
    assert!(net.sim.run_until(Duration::from_secs(20), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclResponse(_)))
    }));
    let frame = last_frame_to(&net.sim, c, short.0);
    let before = lite(&net.sim, d).dev.stack.nwk.stats;
    // Replay with a fresh MAC sequence number: the NWK frame counter is
    // stale.
    let mut replay = frame.clone();
    replay[2] = replay[2].wrapping_add(0x55);
    net.sim.inject(&replay);
    let after = lite(&net.sim, d).dev.stack.nwk.stats;
    assert_eq!(after.replays, before.replays + 1, "{after:?}");
    // A flipped MIC octet.
    let mut tampered = frame;
    tampered[2] = tampered[2].wrapping_add(0x56);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    net.sim.inject(&tampered);
    let after2 = lite(&net.sim, d).dev.stack.nwk.stats;
    assert!(
        after2.security_failures > after.security_failures || after2.replays > after.replays,
        "{after2:?}"
    );
    // Still operating and reporting.
    alarm_round_trip(&mut net.sim, d);
}

#[test]
fn no_frame_is_secured_beyond_an_uncommitted_counter_reservation() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::WaterLeak, b"lite"),
    );
    // A tiny reservation window so that a few frames need a new one.
    {
        let dev = &mut lite_mut(&mut net.sim, d).dev;
        let out = &mut dev.stack.nwk.security.keys.outgoing;
        let next = out.peek();
        *out = panweave_security::frame_counter::OutgoingCounter::restore(next).with_window(4, 1);
    }
    lite(&net.sim, d).store.set_fault(FAULT_IO);
    for i in 0..6 {
        set_inputs(&mut net.sim, d, if i % 2 == 0 { wet() } else { dry() });
        net.sim.run_for(Duration::from_secs(2));
        let out = &lite(&net.sim, d).dev.stack.nwk.security.keys.outgoing;
        assert!(
            out.peek() <= out.reserved_until(),
            "counter {} beyond the committed bound {}",
            out.peek(),
            out.reserved_until()
        );
    }
    // The flash works again: the reservation commits and the pending
    // status gets through.
    lite(&net.sim, d).store.set_fault(FAULT_NONE);
    net.sim.run_for(Duration::from_secs(20));
    wait_confirmed(&mut net.sim, d, 120);
}

#[test]
fn restarts_without_reusing_frame_counters() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::WaterLeak, b"lite"),
    );
    alarm_round_trip(&mut net.sim, d);
    let used = lite(&net.sim, d)
        .dev
        .stack
        .nwk
        .security
        .keys
        .outgoing
        .peek();
    let now = net.sim.clock.now();
    lite_mut(&mut net.sim, d).power_cycle(wet(), now);
    net.sim.settle();
    let restored = lite(&net.sim, d)
        .dev
        .stack
        .nwk
        .security
        .keys
        .outgoing
        .peek();
    assert!(restored >= used, "restored {restored} below used {used}");
    assert!(net.sim.run_until(Duration::from_secs(120), |x| {
        lite(x, d)
            .events
            .iter()
            .any(|e| matches!(e, LiteEvent::Joined { rejoin: true, .. }))
    }));
    // The CIE was restored from flash: the alarm read at start-up is
    // delivered.
    wait_confirmed(&mut net.sim, d, 120);
}

#[test]
fn an_enrolment_write_failure_is_reported_and_retried() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::WaterLeak, b"lite"),
    );
    let key = panweave_storage::Key::with_id(panweave_storage::Kind::Application, 0x0500);
    // The hand-made enrolment above was written.
    assert!(lite(&net.sim, d).store.has(key));
    // A new CIE while the flash fails.
    lite(&net.sim, d).store.set_fault(FAULT_IO);
    {
        let srv = lite_mut(&mut net.sim, d)
            .dev
            .stack
            .zcl
            .cluster_mut(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
            .unwrap();
        ias_zone::restore_enrollment(
            srv,
            &ias_zone::Enrollment {
                cie_address: ExtendedAddress(COORD),
                cie: (panweave_types::ShortAddress(0), Endpoint(1)),
                zone_id: Some(9),
            },
        );
    }
    set_inputs(&mut net.sim, d, wet());
    assert!(
        lite(&net.sim, d)
            .events
            .iter()
            .any(|e| matches!(e, LiteEvent::StorageFailed(_)))
    );
    let failures = lite(&net.sim, d)
        .events
        .iter()
        .filter(|e| matches!(e, LiteEvent::StorageFailed(_)))
        .count();
    net.sim.run_for(Duration::from_secs(12));
    assert_eq!(
        lite(&net.sim, d)
            .events
            .iter()
            .filter(|e| matches!(e, LiteEvent::StorageFailed(_)))
            .count(),
        failures,
        "one event per run of failures"
    );
    lite(&net.sim, d).store.set_fault(FAULT_NONE);
    net.sim.run_for(Duration::from_secs(6));
    let mut buf = [0u8; 16];
    let mut s = lite(&net.sim, d).store.clone();
    let n = panweave_storage::Storage::load(&mut s, key, &mut buf)
        .unwrap()
        .unwrap();
    assert_eq!(
        ias_zone::Enrollment::decode(&buf[..n]).unwrap().zone_id,
        Some(9)
    );
}

#[test]
fn lost_frames_are_retried_until_acknowledged() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::WaterLeak, b"lite"),
    );
    let sr = net.sim.device_radio(d);
    // The next transmissions of the sensor are lost on the air.
    net.sim.medium.drop_next_from(sr, 3);
    set_inputs(&mut net.sim, d, wet());
    wait_confirmed(&mut net.sim, d, 120);
    assert!(net.sim.medium.frames_dropped >= 3);
    assert_no_drops(&net.sim, d);
}

#[test]
fn attributes_are_read_and_battery_reporting_configured_through_the_parent() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::WaterLeak, b"lite-model"),
    );
    let c = net.c;
    let short = lite(&net.sim, d).dev.stack.short_address();
    let dst = Destination::Short {
        address: short,
        endpoint: SENSOR_ENDPOINT,
    };
    // Read Attributes of Basic (the 'static model identifier) and of the
    // IAS Zone (ZoneType): buffered at the parent until the sensor polls.
    let mut ids = [0u8; 4];
    ids[..2].copy_from_slice(&basic::MODEL_IDENTIFIER.id.0.to_le_bytes());
    ids[2..].copy_from_slice(&basic::POWER_SOURCE.id.0.to_le_bytes());
    let send = |sim: &mut Simulator, cluster, cmd: CommandId, payload: &[u8]| {
        sim.stack(c)
            .zcl
            .send_global(
                dst,
                ProfileId::HOME_AUTOMATION,
                cluster,
                Endpoint(1),
                cmd,
                Direction::ToServer,
                None,
                payload,
            )
            .unwrap();
        sim.stack(c).flush();
    };
    send(&mut net.sim, basic::ID, command::READ_ATTRIBUTES, &ids);
    assert!(net.sim.run_until(Duration::from_secs(20), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclResponse(_)))
    }));
    let rsp = net
        .sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::ZclResponse(f) => Some(f.payload.clone()),
            _ => None,
        })
        .unwrap();
    let mut found_model = false;
    for rec in global::Records::<global::ReadAttributeStatus>::new(&rsp) {
        let rec = rec.unwrap();
        if rec.id == basic::MODEL_IDENTIFIER.id {
            assert!(rec.status.is_success());
            assert_eq!(
                rec.value,
                Some(panweave_zcl::Value::String {
                    ty: panweave_zcl::DataType::CharString,
                    bytes: Some(b"lite-model"),
                })
            );
            found_model = true;
        }
    }
    assert!(found_model, "{rsp:?}");
    // Configure Reporting of BatteryPercentageRemaining: min 1 s, max
    // 10 s, change 2.
    let mut cfg = [0u8; 8];
    cfg[0] = 0x00;
    cfg[1..3].copy_from_slice(
        &power_configuration::BATTERY_PERCENTAGE_REMAINING
            .id
            .0
            .to_le_bytes(),
    );
    cfg[3] = 0x20; // uint8
    cfg[4..6].copy_from_slice(&1u16.to_le_bytes());
    cfg[6..8].copy_from_slice(&10u16.to_le_bytes());
    let mut full_cfg = [0u8; 9];
    full_cfg[..8].copy_from_slice(&cfg);
    full_cfg[8] = 2;
    net.sim.take_events(c);
    send(
        &mut net.sim,
        power_configuration::ID,
        command::CONFIGURE_REPORTING,
        &full_cfg,
    );
    assert!(net.sim.run_until(Duration::from_secs(20), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclResponse(_)))
    }));
    // Reports go to bound destinations: the coordinator binds the
    // sensor's Power Configuration to itself (ZDO Bind_req).
    net.sim
        .stack(c)
        .zdo
        .request(
            short,
            panweave_zdo::zdp::cluster::BIND_REQ,
            &panweave_zdo::zdp::BindReq {
                src: ExtendedAddress(SENSOR),
                src_endpoint: SENSOR_ENDPOINT,
                cluster: power_configuration::ID,
                destination: panweave_aps::tables::BindingDestination::Unicast {
                    address: ExtendedAddress(COORD),
                    endpoint: Endpoint(1),
                },
            },
        )
        .unwrap();
    net.sim.stack(c).flush();
    assert!(net.sim.run_until(Duration::from_secs(20), |x| {
        !x.device::<LiteNode>(d)
            .unwrap()
            .dev
            .stack
            .aps
            .bindings
            .is_empty()
    }));
    // A battery reading is reported.
    lite_mut(&mut net.sim, d)
        .dev
        .set_battery(Some(29), Some(150));
    assert!(
        net.sim.run_until(Duration::from_secs(30), |x| x
            .events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclReport(f) if f.origin.cluster == power_configuration::ID))),
        "{:?}",
        net.sim.events(c)
    );
    assert_no_drops(&net.sim, d);
}

#[test]
fn rapid_input_changes_end_in_the_last_state_without_drops() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::Contact, b"lite"),
    );
    for i in 0..20 {
        let inputs = Inputs {
            alarm: i % 2 == 0,
            tamper: i % 5 == 0,
            low_battery: false,
        };
        lite_mut(&mut net.sim, d).dev.set_inputs(inputs);
        net.sim.step(Duration::from_millis(50));
    }
    set_inputs(&mut net.sim, d, dry());
    wait_confirmed(&mut net.sim, d, 120);
    let r = lite(&net.sim, d).dev.reporter();
    assert_eq!(r.published() & panweave_lite::sensor::EVENT_BITS, 0);
    assert_no_drops(&net.sim, d);
}

#[test]
fn repeated_parent_loss_and_rejoin_cycles_keep_the_tables_bounded() {
    let mut net = network(false, None);
    let d = join_sensor(
        &mut net,
        sensor_config(SENSOR, SensorKind::WaterLeak, b"lite"),
    );
    let sr = net.sim.device_radio(d);
    let cr = net.sim.node_radio(net.c);
    for cycle in 0..4 {
        net.sim.medium.block(sr, cr);
        net.sim.run_for(Duration::from_secs(40));
        net.sim.medium.unblock(sr, cr);
        let before = lite(&net.sim, d)
            .events
            .iter()
            .filter(|e| matches!(e, LiteEvent::Joined { .. }))
            .count();
        assert!(
            net.sim.run_until(Duration::from_secs(300), |x| {
                lite(x, d)
                    .events
                    .iter()
                    .filter(|e| matches!(e, LiteEvent::Joined { .. }))
                    .count()
                    > before
                    || x.device::<LiteNode>(d).unwrap().dev.stack.is_operating()
            }),
            "cycle {cycle}: {:?}",
            lite(&net.sim, d).events
        );
        alarm_round_trip(&mut net.sim, d);
        let dev = &lite(&net.sim, d).dev;
        assert!(dev.stack.nwk.neighbors.len() <= 2);
        assert_eq!(dev.reporter().delivery(), Delivery::Confirmed);
    }
    assert_no_drops(&net.sim, d);
}
