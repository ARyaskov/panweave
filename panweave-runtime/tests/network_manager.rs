//! Network management at the runtime level: ZDO configuration attributes
//! (`:Config_NWK_Scan_Attempts`, `:Config_NWK_Time_btwn_Scans`), the
//! explicit PAN ID change of a network manager, and frequency agility
//! (R23.2 Annex E): a router reporting interference and the network
//! manager moving the network to another channel.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::{Duration, Instant};
use panweave_types::{Channel, ExtendedAddress, LogicalDeviceType, PanId};

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);

fn node(cfg: StackConfig, seed: u64) -> SimStack {
    SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    )
}

/// Time at which a lone end device configured with `attempts` discovery
/// rounds reports `JoinFailed`.
fn failure_time(attempts: u8) -> Instant {
    let mut sim = Simulator::new();
    let mut cfg = StackConfig::new(LogicalDeviceType::EndDevice, ROUTER_IEEE);
    cfg.zdo.scan_attempts = attempts;
    cfg.scan_duration = 1;
    let e = sim.add_stack("ed", node(cfg, 7), Box::new(OnOffApp::default()));
    sim.stack(e).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(e)
            .iter()
            .any(|e| matches!(e, StackEvent::JoinFailed(_)))
    }));
    sim.stack(e).now()
}

#[test]
fn discovery_repeats_config_nwk_scan_attempts_times() {
    // R23.2 §2.5.4.5.1 / Table 2-135: each extra attempt adds one scan
    // plus :Config_NWK_Time_btwn_Scans (0x0C35 octet durations = 100 ms).
    let one = failure_time(1);
    let three = failure_time(3);
    let extra = three.as_millis().saturating_sub(one.as_millis());
    assert!(extra >= 200, "two more scans 100 ms apart, got {extra} ms");
    assert!(extra < 5_000, "retries stay bounded, got {extra} ms");
}

#[test]
fn network_manager_changes_the_pan_id_explicitly() {
    let mut sim = Simulator::new();
    let mut ccfg = StackConfig::new(LogicalDeviceType::Coordinator, COORD_IEEE);
    ccfg.trust_center_policy.allow_joins = true;
    let c = sim.add_stack("coord", node(ccfg, 41), Box::new(OnOffApp::default()));
    let rcfg = StackConfig::new(LogicalDeviceType::Router, ROUTER_IEEE);
    let r = sim.add_stack("router", node(rcfg, 42), Box::new(OnOffApp::default()));
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
    let old = sim.stack(c).nwk.nib.pan_id;
    // No conflict was detected; the stack never changes the PAN ID by
    // itself (§2.3.4, ADR-0010).
    assert_eq!(sim.stack(c).pan_id_conflicts(), 0);
    // The network manager stages a PAN ID and changes it; the router
    // follows the Network Update after nwkNetworkBroadcastDeliveryTime.
    let staged = PanId(0x4321);
    sim.stack(c).nwk.nib.next_pan_id = staged;
    sim.stack(c).change_pan_id().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::PanIdChanged { pan_id } if *pan_id == staged))
    }));
    assert_ne!(old, staged);
    assert_eq!(sim.stack(c).nwk.nib.pan_id, staged);
    assert_eq!(sim.stack(r).nwk.nib.pan_id, staged);
    assert_eq!(sim.stack(r).mac.pib.pan_id, staged);
    assert!(sim.events(c).iter().any(|e| matches!(
        e,
        StackEvent::PanIdChanged { pan_id } if *pan_id == staged
    )));
}

/// A coordinator and a joined router.
fn pair() -> (Simulator, usize, usize) {
    let mut sim = Simulator::new();
    let mut ccfg = StackConfig::new(LogicalDeviceType::Coordinator, COORD_IEEE);
    ccfg.trust_center_policy.allow_joins = true;
    let c = sim.add_stack("coord", node(ccfg, 41), Box::new(OnOffApp::default()));
    let rcfg = StackConfig::new(LogicalDeviceType::Router, ROUTER_IEEE);
    let r = sim.add_stack("router", node(rcfg, 42), Box::new(OnOffApp::default()));
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
    (sim, c, r)
}

#[test]
fn router_reports_interference_and_the_manager_moves_the_network() {
    let (mut sim, c, r) = pair();
    let channel = sim.stack(c).nwk.nib.channel;
    // The router has been failing a third of its unicasts and its
    // channel is far noisier than the rest of the band.
    sim.stack(r).nwk.nib.tx_total = 60;
    sim.stack(r).nwk.nib.tx_failures = 20;
    sim.channel_energy[usize::from(channel.raw())] = 200;
    assert!(sim.run_until(Duration::from_secs(700), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::InterferenceReported { .. }))
    }));
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::InterferenceReport { .. }))
    }));
    let report = sim
        .events(c)
        .iter()
        .find_map(|e| match e {
            StackEvent::InterferenceReport {
                src,
                channel,
                tx_total,
                tx_failures,
                ..
            } => Some((*src, *channel, *tx_total, *tx_failures)),
            _ => None,
        })
        .unwrap();
    assert_eq!(report, (sim.stack(r).short_address(), channel, 60, 20));
    // The counters restarted with the report (the report itself is the
    // first unicast of the new window).
    assert!(sim.stack(r).nwk.nib.tx_total <= 2);
    assert_eq!(sim.stack(r).nwk.nib.tx_failures, 0);
    // Only the network manager may move the network; it broadcasts the
    // change and both devices end up on the new channel with the new
    // nwkUpdateId, then apsChannelTimer refuses another change.
    let target = Channel::new(if channel.raw() == 20 { 25 } else { 20 }).unwrap();
    assert!(sim.stack(r).change_network_channel(target).is_err());
    let old_id = sim.stack(c).nwk.nib.update_id;
    sim.stack(c).change_network_channel(target).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.stack_ref(c).nwk.nib.channel == target && x.stack_ref(r).nwk.nib.channel == target
    }));
    assert_eq!(sim.stack(c).nwk.nib.update_id, old_id.wrapping_add(1));
    assert_eq!(sim.stack(r).nwk.nib.update_id, old_id.wrapping_add(1));
    assert_eq!(sim.stack(r).mac.pib.channel, target);
    assert!(sim.stack(c).change_network_channel(channel).is_err());
    // Traffic still flows on the new channel.
    sim.take_events(c);
    sim.run_for(Duration::from_secs(40));
    let short = sim.stack(r).short_address();
    sim.stack(c)
        .zdp_request(
            short,
            panweave_zdo::zdp::cluster::NODE_DESC_REQ,
            &panweave_zdo::zdp::NodeDescReq {
                addr: short,
                tlvs: &[],
            },
        )
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(20), |x| {
        x.events(c).iter().any(|e| matches!(
            e,
            StackEvent::Zdp(d) if d.cluster == panweave_zdo::zdp::cluster::response_of(panweave_zdo::zdp::cluster::NODE_DESC_REQ)
        ))
    }));
}
