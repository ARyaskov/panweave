//! The R23 network-management ZDP commands beyond Mgmt_NWK_Update:
//! Mgmt_NWK_IEEE_Joining_List (the joining policy gates association and
//! the list is read back and pushed by broadcast), the single-page
//! Mgmt_NWK_Enhanced_Update energy scan, and the Mgmt_NWK_Beacon_Survey
//! of an end device that hears two routers.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::Decode;
use panweave_mac::service::MacServiceConfig;
use panweave_nwk::joining_list::JoiningPolicy;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    Channel, ChannelMask, ClusterId, ExtendedAddress, LogicalDeviceType, ShortAddress,
};
use panweave_zdo::zdp::{
    ChannelList, MgmtNwkBeaconSurveyReq, MgmtNwkBeaconSurveyRsp, MgmtNwkEnhancedUpdateReq,
    MgmtNwkIeeeJoiningListReq, MgmtNwkIeeeJoiningListRsp, MgmtNwkUpdateNotify, ZdpStatus, cluster,
    joining_policy,
};

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const ROUTER2_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);
const ED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0004);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    cfg.scan_duration = 1;
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    )
}

fn joined(events: &[StackEvent]) -> Option<ShortAddress> {
    events.iter().find_map(|e| match e {
        StackEvent::Joined { short, .. } => Some(*short),
        _ => None,
    })
}

fn zdp(events: &[StackEvent], cluster: ClusterId) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        StackEvent::Zdp(z) if z.cluster == cluster => Some(z.data.to_vec()),
        _ => None,
    })
}

#[test]
fn joining_list_gates_association_and_is_read_and_pushed() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 1),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 2),
        Box::new(OnOffApp::default()),
    );
    let r2 = sim.add_stack(
        "router2",
        node(LogicalDeviceType::Router, ROUTER2_IEEE, 3),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    // IEEELIST_JOIN with only the first router listed: the second is
    // refused at association while the first joins.
    sim.stack(c)
        .nwk
        .joining_list
        .set_policy(JoiningPolicy::IeeeListJoin);
    assert!(sim.stack(c).nwk.joining_list.add(ROUTER_IEEE));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(r2).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(120), |x| {
            x.events(r2)
                .iter()
                .any(|e| matches!(e, StackEvent::JoinFailed(_)))
        }),
        "{:?}",
        sim.events(r2)
    );
    assert!(joined(sim.events(r2)).is_none());
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r)).is_some()));
    sim.run_for(Duration::from_secs(3));
    sim.take_events(r);

    // The router reads the list back.
    let rsp_cluster = cluster::response_of(cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ);
    sim.stack(r)
        .zdp_request(
            ShortAddress::COORDINATOR,
            cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ,
            &MgmtNwkIeeeJoiningListReq { start_index: 0 },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        zdp(x.events(r), rsp_cluster).is_some()
    }));
    let data = zdp(sim.events(r), rsp_cluster).unwrap();
    let rsp = MgmtNwkIeeeJoiningListRsp::decode_exact(&data).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert_eq!(rsp.policy, joining_policy::IEEELIST_JOIN);
    assert_eq!((rsp.total, rsp.start_index), (1, 0));
    assert_eq!(rsp.list.iter().next(), Some(ROUTER_IEEE));
    // Applying it, the router now gates its own children the same way.
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::JoiningListUpdated))
    }));
    assert_eq!(
        sim.stack(r).nwk.joining_list.policy,
        JoiningPolicy::IeeeListJoin
    );
    assert_eq!(sim.stack(r).nwk.joining_list.entries(), &[ROUTER_IEEE]);
    sim.take_events(r);
    // An index past the end is INVALID_INDEX.
    sim.stack(r)
        .zdp_request(
            ShortAddress::COORDINATOR,
            cluster::MGMT_NWK_IEEE_JOINING_LIST_REQ,
            &MgmtNwkIeeeJoiningListReq { start_index: 5 },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        zdp(x.events(r), rsp_cluster).is_some()
    }));
    let data = zdp(sim.events(r), rsp_cluster).unwrap();
    assert_eq!(
        MgmtNwkIeeeJoiningListRsp::decode_exact(&data)
            .unwrap()
            .status,
        ZdpStatus::InvalidIndex
    );
    sim.take_events(r);

    // The coordinator admits the second router and pushes the change
    // by broadcast; the first router applies it and the second joins
    // through either.
    assert!(sim.stack(c).nwk.joining_list.add(ROUTER2_IEEE));
    let (uid, policy) = {
        let j = &sim.stack(c).nwk.joining_list;
        (j.update_id, j.policy.raw())
    };
    sim.stack(c)
        .zdo
        .broadcast_joining_list(uid, policy, 2, 0, &[ROUTER_IEEE, ROUTER2_IEEE])
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        x.stack_ref(r).nwk.joining_list.entries().len() == 2
    }));
    sim.stack(r2).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r2)).is_some()));
}

#[test]
fn enhanced_update_scans_a_single_page_and_end_device_surveys_beacons() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 11),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "router",
        node(LogicalDeviceType::Router, ROUTER_IEEE, 12),
        Box::new(OnOffApp::default()),
    );
    let e = sim.add_stack(
        "ed",
        node(LogicalDeviceType::EndDevice, ED_IEEE, 13),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(r)).is_some()));
    sim.stack(e).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| joined(x.events(e)).is_some()));
    sim.run_for(Duration::from_secs(3));
    sim.take_events(c);
    let router_short = sim.stack(r).short_address();
    let ed_short = sim.stack(e).short_address();

    // Enhanced update: an energy scan on one page.
    let notify_cluster = cluster::response_of(cluster::MGMT_NWK_ENHANCED_UPDATE_REQ);
    let mask = ChannelMask::EMPTY
        .with(Channel::new(11).unwrap())
        .with(Channel::new(20).unwrap());
    sim.stack(c)
        .zdp_request(
            router_short,
            cluster::MGMT_NWK_ENHANCED_UPDATE_REQ,
            &MgmtNwkEnhancedUpdateReq {
                channels: ChannelList::single(mask),
                scan_duration: 1,
                scan_count: Some(1),
                update_id: None,
                manager: None,
                configuration: Some(0),
            },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        zdp(x.events(c), notify_cluster).is_some()
    }));
    let data = zdp(sim.events(c), notify_cluster).unwrap();
    let n = MgmtNwkUpdateNotify::decode_exact(&data).unwrap();
    assert_eq!(n.status, ZdpStatus::Success);
    assert_eq!(n.energy.len(), 2);
    sim.take_events(c);
    // An enhanced active scan is not offered by this MAC.
    sim.stack(c)
        .zdp_request(
            router_short,
            cluster::MGMT_NWK_ENHANCED_UPDATE_REQ,
            &MgmtNwkEnhancedUpdateReq {
                channels: ChannelList::single(mask),
                scan_duration: 1,
                scan_count: Some(1),
                update_id: None,
                manager: None,
                configuration: None,
            },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        zdp(x.events(c), notify_cluster).is_some()
    }));
    let data = zdp(sim.events(c), notify_cluster).unwrap();
    assert_eq!(
        MgmtNwkUpdateNotify::decode_exact(&data).unwrap().status,
        ZdpStatus::InvalidRequestType
    );
    sim.take_events(c);

    // Beacon survey of the end device on the operating channel: it
    // hears the coordinator and the router; its parent is reported as
    // the current parent and the other as a potential one.
    let survey_cluster = cluster::response_of(cluster::MGMT_NWK_BEACON_SURVEY_REQ);
    let channel = sim.stack(e).nwk.nib.channel;
    let req = MgmtNwkBeaconSurveyReq {
        channels: ChannelList::single(ChannelMask::EMPTY.with(channel)),
        configuration: 0,
    };
    sim.stack(c)
        .zdp_request(ed_short, cluster::MGMT_NWK_BEACON_SURVEY_REQ, &req)
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        zdp(x.events(c), survey_cluster).is_some()
    }));
    let data = zdp(sim.events(c), survey_cluster).unwrap();
    let rsp = MgmtNwkBeaconSurveyRsp::decode_exact(&data).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success, "{rsp:?}");
    assert!(rsp.results.total >= 2, "{rsp:?}");
    assert_eq!(rsp.results.on_network, rsp.results.total);
    assert!(rsp.results.potential_parents >= 2);
    assert_eq!(rsp.results.other_networks, 0);
    let parent = sim.stack(e).nwk.nib.parent_address;
    assert_eq!(rsp.parents.current, parent);
    assert!(rsp.parents.current_lqa > 0);
    assert_eq!(rsp.parents.others.len(), 1, "{rsp:?}");
    assert_ne!(rsp.parents.others[0].0, parent);
    assert_eq!(rsp.pan_id_conflicts, None);
    sim.take_events(c);
    // The coordinator refuses a survey; the router answers one with no
    // current parent and reports its conflict count.
    sim.stack(r)
        .zdp_request(
            ShortAddress::COORDINATOR,
            cluster::MGMT_NWK_BEACON_SURVEY_REQ,
            &req,
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        zdp(x.events(r), survey_cluster).is_some()
    }));
    let data = zdp(sim.events(r), survey_cluster).unwrap();
    assert_eq!(
        MgmtNwkBeaconSurveyRsp::decode_exact(&data).unwrap().status,
        ZdpStatus::NotPermitted
    );
    sim.stack(c)
        .zdp_request(router_short, cluster::MGMT_NWK_BEACON_SURVEY_REQ, &req)
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        zdp(x.events(c), survey_cluster).is_some()
    }));
    let data = zdp(sim.events(c), survey_cluster).unwrap();
    let rsp = MgmtNwkBeaconSurveyRsp::decode_exact(&data).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert_eq!(rsp.parents.current, ShortAddress(0xFFFF));
    assert_eq!(rsp.pan_id_conflicts, Some(0));
    // A request without the configuration TLV is MISSING_TLV.
    sim.take_events(c);
    sim.stack(c)
        .zdp_request(
            router_short,
            cluster::MGMT_NWK_BEACON_SURVEY_REQ,
            &EmptyPayload,
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        zdp(x.events(c), survey_cluster).is_some()
    }));
    let data = zdp(sim.events(c), survey_cluster).unwrap();
    assert_eq!(
        MgmtNwkBeaconSurveyRsp::decode_exact(&data).unwrap().status,
        ZdpStatus::MissingTlv
    );
}

struct EmptyPayload;

impl panweave_codec::Encode for EmptyPayload {
    fn encoded_len(&self) -> usize {
        0
    }
    fn encode(
        &self,
        _w: &mut panweave_codec::Writer<'_>,
    ) -> Result<(), panweave_codec::CodecError> {
        Ok(())
    }
}
