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
use panweave_mac::radio::{RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacServiceConfig};
use panweave_runtime::{JoinMode, Stack, StackConfig, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_storage::MemoryStorage;
use panweave_testkit::{TestRng, VirtualClock, VirtualMedium};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    AttributeId, ClusterId, DeviceId, Endpoint, ExtendedAddress, Key128, LogicalDeviceType,
    ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::frame::{Direction, ZclStatus};
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

type Node = Stack<SoftwareAes, TestRng, MemoryStorage<32, 64>>;

const NETWORK_KEY: Key128 = Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);

struct Sim {
    medium: VirtualMedium,
    clock: VirtualClock,
    nodes: Vec<(Node, usize)>,
    events: Vec<Vec<StackEvent>>,
    /// Application state: the end device applies On/Off commands.
    on_off_state: Vec<bool>,
}

impl Sim {
    fn new() -> Self {
        Sim {
            medium: VirtualMedium::new(),
            clock: VirtualClock::new(),
            nodes: Vec::new(),
            events: Vec::new(),
            on_off_state: Vec::new(),
        }
    }

    fn add(&mut self, mut stack: Node) -> usize {
        let radio = self.medium.add_radio();
        stack.poll(self.clock.now());
        self.nodes.push((stack, radio));
        self.events.push(Vec::new());
        self.on_off_state.push(false);
        self.nodes.len() - 1
    }

    /// Drains radio actions and events of every node until nothing moves.
    fn settle(&mut self) {
        loop {
            let mut progressed = false;
            for i in 0..self.nodes.len() {
                while let Some(a) = self.nodes[i].0.next_radio_action() {
                    progressed = true;
                    match a {
                        MacAction::Transmit { frame, .. } => {
                            let radio = self.nodes[i].1;
                            if std::env::var("PW_TRACE").is_ok() {
                                eprintln!(
                                    "t={} node{i} tx {:02x?}",
                                    self.clock.now().as_millis(),
                                    &frame[..]
                                );
                            }
                            let (air, targets) = self.medium.transmit(radio, &frame);
                            if let Some(air) = air {
                                for t in targets {
                                    let j = self.nodes.iter().position(|(_, r)| *r == t).unwrap();
                                    let meta = RxMetadata {
                                        lqi: 200,
                                        rssi_dbm: -40,
                                        timestamp_us: None,
                                        acked_by_hardware: false,
                                        channel: Some(air.channel),
                                    };
                                    self.nodes[j].0.on_radio_frame(&air.bytes, meta);
                                }
                            }
                            self.nodes[i].0.on_tx_complete(Ok(TxResult {
                                acked: false,
                                frame_pending: false,
                                timestamp_us: None,
                            }));
                        }
                        MacAction::SetChannel { channel, .. } => {
                            let radio = self.nodes[i].1;
                            self.medium.set_channel(radio, channel);
                        }
                        MacAction::EnergyDetect { .. } => self.nodes[i].0.on_energy_result(0),
                        MacAction::Configure(_) | MacAction::SetPending { .. } => {}
                    }
                }
                while let Some(e) = self.nodes[i].0.next_event() {
                    progressed = true;
                    self.handle_app_event(i, &e);
                    self.events[i].push(e);
                }
            }
            if !progressed {
                break;
            }
        }
    }

    /// Minimal application: execute On/Off commands on endpoint 1.
    fn handle_app_event(&mut self, i: usize, e: &StackEvent) {
        if let StackEvent::ZclCommand(f) = e
            && f.origin.cluster == on_off::ID
        {
            let stack = &mut self.nodes[i].0;
            let status = match stack
                .zcl
                .cluster_mut(f.origin.endpoint, on_off::ID, Role::Server)
            {
                Some(c) => match on_off::apply(c, f.origin.header.command) {
                    Some(state) => {
                        self.on_off_state[i] = state;
                        ZclStatus::Success
                    }
                    None => ZclStatus::UnsupportedClusterCommand,
                },
                None => ZclStatus::UnsupportedCluster,
            };
            let _ = stack.zcl.default_response(&f.origin, status);
            stack.flush();
        }
    }

    /// Advances virtual time to the next deadline (at most `max`) and
    /// polls everything.
    fn step(&mut self, max: Duration) {
        self.settle();
        let now = self.clock.now();
        let next = self
            .nodes
            .iter()
            .filter_map(|(n, _)| n.next_deadline())
            .min_by_key(|t| t.as_millis())
            .map_or(now.saturating_add(max), |t| {
                if t.as_millis() <= now.as_millis() {
                    now.saturating_add(Duration::from_millis(1))
                } else {
                    t
                }
            });
        let limit = now.saturating_add(max);
        let target = if next.as_millis() > limit.as_millis() {
            limit
        } else {
            next
        };
        self.clock.advance_to(target);
        for (n, _) in &mut self.nodes {
            n.poll(target);
        }
        self.settle();
    }

    /// Runs until `pred` holds on the accumulated events or `timeout`
    /// elapses.
    fn run_until(&mut self, timeout: Duration, mut pred: impl FnMut(&Sim) -> bool) -> bool {
        let end = self.clock.now().saturating_add(timeout);
        loop {
            if pred(self) {
                return true;
            }
            if self.clock.now().as_millis() >= end.as_millis() {
                return false;
            }
            self.step(Duration::from_millis(250));
        }
    }

    fn events(&self, i: usize) -> &[StackEvent] {
        &self.events[i]
    }

    fn take_events(&mut self, i: usize) -> Vec<StackEvent> {
        std::mem::take(&mut self.events[i])
    }
}

fn lamp_endpoint() -> (SimpleDescriptor, EndpointInstance<8, 16>) {
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

fn controller_endpoint() -> (SimpleDescriptor, EndpointInstance<8, 16>) {
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

fn coordinator() -> Node {
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, COORD_IEEE);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = Node::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(1),
        MemoryStorage::new(),
    );
    let (d, e) = controller_endpoint();
    n.add_endpoint(d, e).unwrap();
    n
}

fn end_device() -> Node {
    let cfg = StackConfig::new(LogicalDeviceType::EndDevice, ED_IEEE);
    let mut n = Node::new(
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
    let mut sim = Sim::new();
    let c = sim.add(coordinator());
    let d = sim.add(end_device());

    // --- Formation --------------------------------------------------
    sim.nodes[c]
        .0
        .form_network_with_key(NETWORK_KEY.clone())
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |s| {
        s.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    let pan = sim.nodes[c].0.pan_id();
    assert_eq!(sim.nodes[c].0.short_address(), ShortAddress::COORDINATOR);
    sim.nodes[c].0.permit_join(180).unwrap();
    sim.nodes[c].0.flush();
    sim.take_events(c);

    // --- Discovery, association, authorization -------------------
    sim.nodes[d].0.join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(60), |s| {
            s.events(d)
                .iter()
                .any(|e| matches!(e, StackEvent::Joined { .. }))
        }),
        "end device did not join: {:?} / coord {:?} / coord aps {:?} / ed aps {:?} / ed nwk {:?}",
        sim.events(d),
        sim.events(c),
        sim.nodes[c].0.aps.stats,
        sim.nodes[d].0.aps.stats,
        sim.nodes[d].0.nwk.stats
    );
    let ed_short = sim.nodes[d].0.short_address();
    assert!(ed_short.is_unicast());
    assert_eq!(sim.nodes[d].0.pan_id(), pan);
    assert!(sim.events(d).iter().any(|e| matches!(
        e,
        StackEvent::Joined { short, pan_id, rejoin: false } if *short == ed_short && *pan_id == pan
    )));
    // The Trust Center authorized the child and saw its announce; the
    // end device obtained a unique Trust Center link key (BDB §10.2.4).
    assert!(
        sim.run_until(Duration::from_secs(30), |s| {
            s.events(c)
                .iter()
                .any(|e| matches!(e, StackEvent::DeviceAnnounce { ieee, .. } if *ieee == ED_IEEE))
                && s.events(d)
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
    let tc_entry = sim.nodes[c].0.aps.security.entry(ED_IEEE).unwrap();
    assert_eq!(
        tc_entry.attributes,
        panweave_types::KeyAttributes::VerifiedKey
    );
    assert_eq!(
        tc_entry.kind,
        panweave_security::material::LinkKeyKind::Unique
    );
    assert_eq!(sim.nodes[d].0.aps.aib.trust_center_address, COORD_IEEE);
    sim.take_events(c);
    sim.take_events(d);

    // --- ZDO interview ---------------------------------------------
    let mut tlv = [0u8; 8];
    let n = panweave_zdo::fragmentation_parameters_tlv(
        &mut tlv,
        ShortAddress::COORDINATOR,
        sim.nodes[c].0.zdo.node,
    );
    sim.nodes[c]
        .0
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

    sim.nodes[c]
        .0
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

    sim.nodes[c]
        .0
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
    let seq = sim.nodes[c]
        .0
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
    sim.nodes[c].0.flush();
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        s.events(c)
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

    let seq = sim.nodes[c]
        .0
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
    sim.nodes[c].0.flush();
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        s.events(c).iter().any(|e| matches!(
            e,
            StackEvent::ZclResponse(f) if f.origin.header.seq == seq && f.origin.header.command == command::DEFAULT_RESPONSE
        ))
    }));
    assert!(sim.on_off_state[d], "the lamp turned on");
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
    sim.nodes[c]
        .0
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
    assert_eq!(sim.nodes[d].0.aps.bindings.len(), 1);

    let cfg = ReportingConfig::Reported {
        id: AttributeId(0),
        ty: DataType::Bool,
        min: 0,
        max: 20,
        change: None,
    };
    let mut cbuf = [0u8; 16];
    let n = cfg.encode_to_slice(&mut cbuf).unwrap();
    let seq = sim.nodes[c]
        .0
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
    sim.nodes[c].0.flush();
    assert!(sim.run_until(Duration::from_secs(10), |s| {
        s.events(c).iter().any(|e| matches!(
            e,
            StackEvent::ZclResponse(f) if f.origin.header.seq == seq && f.origin.header.command == command::CONFIGURE_REPORTING_RESPONSE
        ))
    }));
    sim.take_events(c);
    // Toggle via command: the change is reported to the bound coordinator.
    sim.nodes[c]
        .0
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
    sim.nodes[c].0.flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |s| {
            s.events(c)
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
    assert!(!sim.on_off_state[d]);
    // Periodic report at the maximum interval.
    sim.take_events(c);
    assert!(sim.run_until(Duration::from_secs(25), |s| {
        s.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::ZclReport(_)))
    }));

    // Everything went over the virtual radio.
    assert!(sim.medium.frames_sent > 40, "{}", sim.medium.frames_sent);
    assert_eq!(sim.nodes[c].0.dropped_events, 0);
    assert_eq!(sim.nodes[d].0.dropped_events, 0);
    let _ = Instant::from_millis(0);
}
