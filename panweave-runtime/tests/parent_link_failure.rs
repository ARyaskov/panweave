//! Parent link failure handling of an end device (R23.2 §2.5.5.5.6):
//! failed polls count against `:Config_Parent_Link_Retry_Threshold`,
//! then a rejoin starts; while no parent answers, further attempts are
//! paced by `:Config_Rejoin_Interval`, doubling up to
//! `:Config_Max_Rejoin_Interval`, and `:Config_Max_Bind` caps the
//! binding table.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::tables::BindingDestination;
use panweave_codec::Decode;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
};
use panweave_zdo::descriptor::SimpleDescriptor;
use panweave_zdo::zdp::{BindReq, StatusRsp, cluster};

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.sleepy = role == LogicalDeviceType::EndDevice;
    cfg.trust_center_policy.allow_joins = true;
    cfg.poll_interval = Duration::from_millis(1000);
    cfg.zdo.parent_link_retry_threshold = 2;
    cfg.zdo.rejoin_interval_secs = 10;
    cfg.zdo.max_rejoin_interval_secs = 40;
    cfg.zdo.scan_attempts = 1;
    cfg.zdo.max_bind = 2;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[],
        &[],
    )
    .unwrap();
    n.add_endpoint(
        desc,
        panweave_zcl::layer::EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION),
    )
    .unwrap();
    n
}

fn count(events: &[StackEvent], f: impl Fn(&StackEvent) -> bool) -> usize {
    events.iter().filter(|e| f(e)).count()
}

#[test]
fn rejoins_after_the_threshold_and_paces_retries() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1),
        Box::new(OnOffApp::default()),
    );
    let e = sim.add_stack(
        "ed",
        node(LogicalDeviceType::EndDevice, ED_IEEE, 2),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.stack(e).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(e)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    }));
    sim.run_for(Duration::from_secs(5));
    sim.take_events(e);

    // The parent vanishes: polls fail, the threshold is crossed and the
    // rejoin finds nobody.
    sim.isolate(c);
    let failed = |ev: &StackEvent| matches!(ev, StackEvent::JoinFailed(_));
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        count(x.events(e), failed) >= 1
    }));
    let t1 = sim.clock.now();
    assert!(sim.run_until(Duration::from_secs(120), |x| {
        count(x.events(e), failed) >= 2
    }));
    let t2 = sim.clock.now();
    assert!(sim.run_until(Duration::from_secs(120), |x| {
        count(x.events(e), failed) >= 3
    }));
    let t3 = sim.clock.now();
    // Second attempt no sooner than :Config_Rejoin_Interval after the
    // first, the third after twice that.
    let gap1 = t2.saturating_duration_since(t1).as_secs();
    let gap2 = t3.saturating_duration_since(t2).as_secs();
    assert!(gap1 >= 10, "gap1 {gap1}");
    assert!(gap2 >= 20, "gap2 {gap2}");
    assert!(gap2 > gap1, "{gap1} {gap2}");
}

#[test]
fn bind_requests_are_capped_at_config_max_bind() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(
            LogicalDeviceType::Router,
            ExtendedAddress(0x00AA_0000_0000_0003),
            3,
        ),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    }));
    let r_short = sim.stack(r).short_address();
    sim.run_for(Duration::from_secs(5));
    sim.take_events(c);
    // Three Bind_req: the third exceeds :Config_Max_Bind (2).
    let mut statuses = Vec::new();
    for i in 0..3u8 {
        sim.stack(c)
            .zdp_request(
                r_short,
                cluster::BIND_REQ,
                &BindReq {
                    src: ExtendedAddress(0x00AA_0000_0000_0003),
                    src_endpoint: Endpoint(1),
                    cluster: ClusterId(0x0006),
                    destination: BindingDestination::Unicast {
                        address: ExtendedAddress(0x00AA_0000_0000_0100 + u64::from(i)),
                        endpoint: Endpoint(1),
                    },
                },
            )
            .unwrap();
        assert!(sim.run_until(Duration::from_secs(10), |x| {
            x.events(c).iter().any(|e| matches!(e, StackEvent::Zdp(d) if d.cluster == cluster::response_of(cluster::BIND_REQ)))
        }));
        let rsp = sim
            .take_events(c)
            .into_iter()
            .find_map(|e| match e {
                StackEvent::Zdp(d) if d.cluster == cluster::response_of(cluster::BIND_REQ) => {
                    StatusRsp::decode_exact(&d.data).ok()
                }
                _ => None,
            })
            .unwrap();
        statuses.push(rsp.status);
    }
    assert_eq!(
        statuses,
        [
            panweave_zdo::ZdpStatus::Success,
            panweave_zdo::ZdpStatus::Success,
            panweave_zdo::ZdpStatus::InsufficientSpace
        ]
    );
    assert_eq!(sim.stack(r).aps.bindings.len(), 2);
}
