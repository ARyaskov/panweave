//! Milestone 1: a virtual coordinator and a virtual end device run the
//! complete protocol stack over a virtual radio medium — formation,
//! discovery, association, Trust Center authorization (network key and
//! unique link key), device announce, ZDO interview and ZCL attribute
//! interaction — with virtual time and a deterministic RNG.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use panweave_aps::Destination;
use panweave_aps::tables::BindingDestination;
use panweave_codec::{Decode, Encode, Writer};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    AttributeId, ClusterId, DeviceId, Endpoint, LogicalDeviceType, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::frame::Direction;
use panweave_zcl::global::{
    self, AttributeValue, ReadAttributeStatus, Records, ReportingConfig, command,
};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::{DataType, Value};
use panweave_zcl::{ClusterDef, Role};
use panweave_zdo::descriptor::SimpleDescriptor;
use panweave_zdo::zdp::{
    ActiveEpReq, BindReq, EndpointListRsp, NodeDescReq, NodeDescRsp, SimpleDescReq, SimpleDescRsp,
    StatusRsp, ZdpStatus, cluster,
};

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: panweave_types::ExtendedAddress =
    panweave_types::ExtendedAddress(0x00AA_0000_0000_0001);
const ED_IEEE: panweave_types::ExtendedAddress =
    panweave_types::ExtendedAddress(0x00AA_0000_0000_0002);

fn on_off_state(sim: &mut Simulator, i: usize) -> bool {
    matches!(
        sim.stack(i)
            .zcl
            .cluster(Endpoint(1), on_off::ID, Role::Server)
            .and_then(|c| c.attributes.value(AttributeId(0))),
        Some(Value::Bool(Some(true)))
    )
}

fn lamp_endpoint() -> (SimpleDescriptor, EndpointInstance<12, 36>) {
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[ClusterId(0x0000), identify::ID, on_off::ID],
        &[],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    (desc, ep)
}

fn controller_endpoint() -> (SimpleDescriptor, EndpointInstance<12, 36>) {
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0005),
        1,
        &[ClusterId(0x0000)],
        &[on_off::ID],
    )
    .unwrap();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_cluster(
        ClusterDef {
            id: on_off::ID,
            revision: 2,
            received: &[],
            generated: &[on_off::CMD_OFF, on_off::CMD_ON, on_off::CMD_TOGGLE],
        },
        Role::Client,
    )
    .unwrap();
    (desc, ep)
}

fn coordinator() -> SimStack {
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, COORD_IEEE);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(1),
        MemoryStorage::new(),
    );
    let (d, e) = controller_endpoint();
    n.add_endpoint(d, e).unwrap();
    n
}

fn end_device() -> SimStack {
    let cfg = StackConfig::new(LogicalDeviceType::EndDevice, ED_IEEE);
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(2),
        MemoryStorage::new(),
    );
    let (d, e) = lamp_endpoint();
    n.add_endpoint(d, e).unwrap();
    n
}

fn zdp_responses(events: &[StackEvent], cluster: ClusterId) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            StackEvent::Zdp(z) if z.cluster == cluster => Some(z.data.to_vec()),
            _ => None,
        })
        .collect()
}

#[test]
fn coordinator_and_end_device_full_stack() {
    let mut sim = Simulator::new();
    let c = sim.add_stack("node", coordinator(), Box::new(OnOffApp::default()));
    let d = sim.add_stack("node", end_device(), Box::new(OnOffApp::default()));

    // --- Formation --------------------------------------------------
    sim.stack(c)
        .form_network_with_key(NETWORK_KEY.clone())
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    let pan = sim.stack(c).pan_id();
    assert_eq!(sim.stack(c).short_address(), ShortAddress::COORDINATOR);
    sim.stack(c).permit_join(180).unwrap();
    sim.stack(c).flush();
    sim.take_events(c);

    // --- Discovery, association, authorization -------------------
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |x| {
            x.events(d)
                .iter()
                .any(|e| matches!(e, StackEvent::Joined { .. }))
        }),
        "end device did not join: {:?} / coord {:?}",
        sim.events(d),
        sim.events(c),
    );
    let ed_short = sim.stack(d).short_address();
    assert!(ed_short.is_unicast());
    assert_eq!(sim.stack(d).pan_id(), pan);
    assert!(sim.events(d).iter().any(|e| matches!(
        e,
        StackEvent::Joined { short, pan_id, rejoin: false } if *short == ed_short && *pan_id == pan
    )));
    // The Trust Center authorized the child and saw its announce; the
    // end device obtained a unique Trust Center link key (BDB §10.2.4).
    assert!(
        sim.run_until(Duration::from_secs(30), |x| {
            x.events(c)
                .iter()
                .any(|e| matches!(e, StackEvent::DeviceAnnounce { ieee, .. } if *ieee == ED_IEEE))
                && x.events(d)
                    .iter()
                    .any(|e| matches!(e, StackEvent::LinkKeyUpdated))
        }),
        "authorization incomplete: coord {:?} / ed {:?}",
        sim.events(c),
        sim.events(d)
    );
    assert!(sim.events(c).iter().any(|e| matches!(
        e,
        StackEvent::DeviceAuthorized { ieee, short } if *ieee == ED_IEEE && *short == ed_short
    )));
    let tc_entry = sim.stack(c).aps.security.entry(ED_IEEE).unwrap();
    assert_eq!(
        tc_entry.attributes,
        panweave_types::KeyAttributes::VerifiedKey
    );
    assert_eq!(
        tc_entry.kind,
        panweave_security::material::LinkKeyKind::Unique
    );
    assert_eq!(sim.stack(d).aps.aib.trust_center_address, COORD_IEEE);
    sim.take_events(c);
    sim.take_events(d);

    // --- ZDO interview ---------------------------------------------
    let mut tlv = [0u8; 8];
    let n = panweave_zdo::fragmentation_parameters_tlv(
        &mut tlv,
        ShortAddress::COORDINATOR,
        sim.stack(c).zdo.node,
    );
    sim.stack(c)
        .zdp_request(
            ed_short,
            cluster::NODE_DESC_REQ,
            &NodeDescReq {
                addr: ed_short,
                tlvs: &tlv[..n],
            },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        !zdp_responses(s.events(c), ClusterId(0x8002)).is_empty()
    }));
    let rsp = zdp_responses(sim.events(c), ClusterId(0x8002)).remove(0);
    let rsp = NodeDescRsp::decode_exact(&rsp).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    let nd = rsp.descriptor.unwrap();
    assert_eq!(nd.logical_type, LogicalDeviceType::EndDevice);
    assert_eq!(nd.server_mask.stack_compliance_revision(), 23);

    sim.stack(c)
        .zdp_request(
            ed_short,
            cluster::ACTIVE_EP_REQ,
            &ActiveEpReq { addr: ed_short },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        !zdp_responses(s.events(c), ClusterId(0x8005)).is_empty()
    }));
    let rsp = zdp_responses(sim.events(c), ClusterId(0x8005)).remove(0);
    let eps = EndpointListRsp::decode_exact(&rsp).unwrap();
    assert_eq!(eps.endpoints, &[1]);

    sim.stack(c)
        .zdp_request(
            ed_short,
            cluster::SIMPLE_DESC_REQ,
            &SimpleDescReq {
                addr: ed_short,
                endpoint: Endpoint(1),
            },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        !zdp_responses(s.events(c), ClusterId(0x8004)).is_empty()
    }));
    let rsp = zdp_responses(sim.events(c), ClusterId(0x8004)).remove(0);
    let sd = SimpleDescRsp::decode_exact(&rsp).unwrap();
    let sd = SimpleDescriptor::decode_exact(sd.descriptor.unwrap()).unwrap();
    assert!(sd.has_input(on_off::ID));
    assert_eq!(sd.device, DeviceId(0x0100));
    sim.take_events(c);

    // --- ZCL: read, command, default response, read again ----------
    let dst = Destination::Short {
        address: ed_short,
        endpoint: Endpoint(1),
    };
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    global::write_attribute_ids(&mut w, &[AttributeId(0)]).unwrap();
    let n = w.position();
    let seq = sim
        .stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            command::READ_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclResponse(f) if f.origin.header.seq == seq))
    }));
    let read = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::ZclResponse(f) if f.origin.header.seq == seq => Some(f.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        read.origin.header.command,
        command::READ_ATTRIBUTES_RESPONSE
    );
    let recs: Vec<ReadAttributeStatus> = Records::new(&read.payload).map(Result::unwrap).collect();
    assert_eq!(recs[0].value, Some(Value::Bool(Some(false))));
    sim.take_events(c);

    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            on_off::CMD_ON,
            Direction::ToServer,
            None,
            &[],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(c).iter().any(|e| matches!(
            e,
            StackEvent::ZclResponse(f) if f.origin.header.seq == seq && f.origin.header.command == command::DEFAULT_RESPONSE
        ))
    }));
    assert!(on_off_state(&mut sim, d), "the lamp turned on");
    let dr = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::ZclResponse(f) if f.origin.header.seq == seq => Some(f.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(dr.payload.as_slice(), &[on_off::CMD_ON.0, 0x00]);
    sim.take_events(c);

    // --- Binding + reporting -----------------------------------------
    sim.stack(c)
        .zdp_request(
            ed_short,
            cluster::BIND_REQ,
            &BindReq {
                src: ED_IEEE,
                src_endpoint: Endpoint(1),
                cluster: on_off::ID,
                destination: BindingDestination::Unicast {
                    address: COORD_IEEE,
                    endpoint: Endpoint(1),
                },
            },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        !zdp_responses(s.events(c), ClusterId(0x8021)).is_empty()
    }));
    let rsp = zdp_responses(sim.events(c), ClusterId(0x8021)).remove(0);
    assert_eq!(
        StatusRsp::decode_exact(&rsp).unwrap().status,
        ZdpStatus::Success
    );
    assert_eq!(sim.stack(d).aps.bindings.len(), 1);

    let cfg = ReportingConfig::Reported {
        id: AttributeId(0),
        ty: DataType::Bool,
        min: 0,
        max: 20,
        change: None,
    };
    let mut cbuf = [0u8; 16];
    let n = cfg.encode_to_slice(&mut cbuf).unwrap();
    let seq = sim
        .stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            command::CONFIGURE_REPORTING,
            Direction::ToServer,
            None,
            &cbuf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.events(c).iter().any(|e| matches!(
            e,
            StackEvent::ZclResponse(f) if f.origin.header.seq == seq && f.origin.header.command == command::CONFIGURE_REPORTING_RESPONSE
        ))
    }));
    sim.take_events(c);
    // Toggle via command: the change is reported to the bound coordinator.
    sim.stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            on_off::ID,
            Endpoint(1),
            on_off::CMD_TOGGLE,
            Direction::ToServer,
            None,
            &[],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| {
            x.events(c)
                .iter()
                .any(|e| matches!(e, StackEvent::ZclReport(_)))
        }),
        "no report: {:?}",
        sim.events(c)
    );
    let rep = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::ZclReport(f) => Some(f.clone()),
            _ => None,
        })
        .unwrap();
    let recs: Vec<AttributeValue> = Records::new(&rep.payload).map(Result::unwrap).collect();
    assert_eq!(
        recs,
        vec![AttributeValue {
            id: AttributeId(0),
            value: Value::Bool(Some(false))
        }]
    );
    assert!(!on_off_state(&mut sim, d));
    // Periodic report at the maximum interval.
    sim.take_events(c);
    assert!(sim.run_until(Duration::from_secs(25), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclReport(_)))
    }));

    // Everything went over the virtual radio.
    assert!(sim.frames > 40, "{}", sim.frames);
    assert_eq!(sim.stack(c).dropped_events, 0);
    assert_eq!(sim.stack(d).dropped_events, 0);
    let _ = Instant::from_millis(0);
}
