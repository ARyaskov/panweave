//! The MAC Interface Table (R23.2 Table 3-69, §3.2.2.34–§3.2.2.37) in
//! operation: formation and discovery are confined to the channels an
//! enabled interface supports, the entry records the channel in use and
//! counts unicast traffic, `RoutersAllowed` gates router joins and a
//! disabled interface is refused when it is the last one.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_mac::service::MacServiceConfig;
use panweave_nwk::interface::{DutyCycleThresholds, InterfaceError, SetInterface};
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    Channel, ChannelMask, ChannelPage, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType,
    ProfileId,
};
use panweave_zdo::descriptor::SimpleDescriptor;

const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const ROUTER_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);
const ED_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0003);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
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

#[test]
fn interface_table_confines_channels_and_gates_routers() {
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
    let e = sim.add_stack(
        "ed",
        node(LogicalDeviceType::EndDevice, ED_IEEE, 3),
        Box::new(OnOffApp::default()),
    );
    let ch15 = Channel::new_2_4ghz(15).unwrap();
    // The coordinator's only interface supports channel 15 alone; no
    // routers may join through it.
    let req = SetInterface {
        index: 0,
        state: true,
        channel_to_use: Some((ChannelPage::PAGE_0, ch15)),
        supported_channels: Some(
            heapless::Vec::from_slice(&[ChannelMask::EMPTY.with(ch15)]).unwrap(),
        ),
        routers_allowed: false,
        duty_cycle: DutyCycleThresholds::default(),
        link_cost_scalar: 1,
    };
    sim.stack(c).nwk.interfaces.set_interface(&req).unwrap();
    assert_eq!(
        sim.stack(c).nwk.interfaces.set_interface(&SetInterface {
            state: false,
            ..req.clone()
        }),
        Err(InterfaceError::LastInterface)
    );
    // Formation on channels the interface lacks is refused; on the
    // primary mask it lands on channel 15.
    assert!(
        sim.stack(c)
            .nwk
            .network_formation(
                ChannelMask::EMPTY.with(Channel::new_2_4ghz(20).unwrap()),
                3,
                false
            )
            .is_err()
    );
    sim.stack(c).config.channels = ChannelMask::ALL_2_4GHZ;
    sim.stack(c).form_network().unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    assert_eq!(sim.stack(c).nwk.nib.channel, ch15);
    assert_eq!(
        sim.stack(c).nwk.interfaces.get(0).unwrap().channel_in_use,
        Some((ChannelPage::PAGE_0, ch15))
    );
    sim.stack(c).permit_join_network(254).unwrap();

    // A router is turned away (RoutersAllowed = FALSE); an end device
    // joins and the interface counts the traffic.
    sim.stack(r).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(90), |x| {
        x.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::JoinFailed(_)))
    }));
    assert!(
        sim.events(r)
            .iter()
            .all(|e| !matches!(e, StackEvent::Joined { .. }))
    );
    sim.stack(e).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(e)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    }));
    let info = sim.stack(c).nwk.interfaces.get_interface(0).unwrap();
    assert!(info.entry.counters.rx_ucast > 0);
    assert!(info.entry.counters.tx_ucast_total > 0);
    assert_eq!(info.entry.channel_in_use, Some((ChannelPage::PAGE_0, ch15)));
    // The read reset the counters.
    assert_eq!(
        sim.stack(c)
            .nwk
            .interfaces
            .get(0)
            .unwrap()
            .counters
            .rx_ucast,
        0
    );
}
