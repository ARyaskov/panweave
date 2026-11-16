//! A sleepy joiner must wake to poll for its parent's buffered network
//! key, even before it is authenticated. Drive the join from advertised
//! deadlines rather than an artificial periodic tick.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{ExtendedAddress, Key128, LogicalDeviceType};

const COORDINATOR: ExtendedAddress = ExtendedAddress(0x00D1_0000_0000_0001);
const CHILD: ExtendedAddress = ExtendedAddress(0x00D1_0000_0000_0002);
const NETWORK_KEY: Key128 = Key128::from_bytes([0x52; 16]);

fn stack(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut config = StackConfig::new(role, ieee);
    config.sleepy = role == LogicalDeviceType::EndDevice;
    config.trust_center_policy.allow_joins = true;
    // No endpoints or application timers can supply an incidental wake-up.
    SimStack::new(
        config,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    )
}

#[test]
fn sleepy_joiner_polls_for_its_key_using_advertised_deadlines_only() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coordinator",
        stack(LogicalDeviceType::Coordinator, COORDINATOR, 1),
        Box::new(OnOffApp::default()),
    );
    let d = sim.add_stack(
        "child",
        stack(LogicalDeviceType::EndDevice, CHILD, 2),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |s| s.stack_ref(c).is_operating()));
    sim.stack(c).permit_join_network(254).unwrap();
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(30), |s| {
            let nib = &s.stack_ref(d).nwk.nib;
            nib.joined && !nib.authenticated
        }),
        "the fixture must observe association before network-key receipt"
    );

    // Association has finished, but the sleeping child still needs an
    // immediate MAC data poll to retrieve its parent's buffered key.
    assert_eq!(
        sim.stack_ref(d).next_deadline(),
        Some(sim.stack_ref(d).now())
    );
    let end = sim.clock.now().saturating_add(Duration::from_secs(30));
    while !sim.stack_ref(d).is_operating() && sim.clock.now().as_millis() < end.as_millis() {
        // step chooses the earliest declared deadline; this limit is the
        // test timeout, not a periodic wake-up for the sleeping child.
        sim.step(end.saturating_duration_since(sim.clock.now()));
    }
    assert!(
        sim.stack_ref(d).is_operating(),
        "deadline-driven join failed: {:?}",
        sim.events(d)
    );
    assert!(
        sim.events(d)
            .iter()
            .any(|event| matches!(event, StackEvent::Joined { .. }))
    );
    assert_eq!(
        sim.stack_ref(d)
            .nwk
            .security
            .keys
            .active()
            .map(|slot| &slot.key),
        Some(&NETWORK_KEY)
    );
}
