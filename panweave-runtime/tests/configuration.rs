//! Runtime policies preserve startup identity and synchronize polling.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::Decode;
use panweave_mac::frame::{Frame, FrameType, MacCommand};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{ConfigurationError, JoinMode, PollingPolicy, StackConfig};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{ExtendedAddress, LogicalDeviceType};

fn node(role: LogicalDeviceType, sleepy: bool, address: u64) -> SimStack {
    let mut config = StackConfig::new(role, ExtendedAddress(address));
    config.sleepy = sleepy;
    config.trust_center_policy.allow_joins = true;
    config.trust_center_policy.require_key_exchange = false;
    config.trust_center_policy.dlk_enabled = false;
    SimStack::new(
        config,
        MacServiceConfig::default(),
        TestRng::seed(address),
        MemoryStorage::new(),
    )
}

fn assert_identity(stack: &SimStack, role: LogicalDeviceType, sleepy: bool, address: u64) {
    assert_eq!(stack.config().role, role);
    assert_eq!(stack.config().sleepy, sleepy);
    assert_eq!(stack.config().ieee, ExtendedAddress(address));
    assert_eq!(stack.nwk.nib.device_type, role);
    assert_eq!(stack.nwk.nib.ieee_address, ExtendedAddress(address));
    assert_eq!(stack.nwk.nib.rx_on_when_idle, !sleepy);
    assert_eq!(
        stack.nwk.nib.capability_information,
        stack.config().capability()
    );
    assert_eq!(stack.mac.pib.extended_address, ExtendedAddress(address));
    assert_eq!(stack.zdo.node.logical_type, role);
    assert_eq!(stack.zdo.node.mac_capability, stack.config().capability());
}

#[test]
fn runtime_policy_changes_preserve_identity_and_layer_capabilities() {
    for (role, sleepy) in [
        (LogicalDeviceType::Coordinator, false),
        (LogicalDeviceType::Router, false),
        (LogicalDeviceType::EndDevice, false),
        (LogicalDeviceType::EndDevice, true),
    ] {
        let mut stack = node(role, sleepy, 1);
        stack.trust_center_policy_mut().allow_joins = false;
        let policy = PollingPolicy {
            interval: Duration::from_secs(6),
            fast_interval: Duration::from_millis(200),
            fast_polls: 2,
        };
        stack.set_polling_policy(policy).unwrap();
        assert_eq!(stack.polling_policy(), policy);
        assert!(!stack.config().trust_center_policy.allow_joins);
        assert_identity(&stack, role, sleepy, 1);
    }
}

#[test]
fn zero_polling_intervals_are_refused_without_changing_policy() {
    let mut stack = node(LogicalDeviceType::EndDevice, true, 2);
    let original = stack.polling_policy();
    for policy in [
        PollingPolicy {
            interval: Duration::from_millis(0),
            ..original
        },
        PollingPolicy {
            fast_interval: Duration::from_millis(0),
            ..original
        },
    ] {
        assert_eq!(
            stack.set_polling_policy(policy),
            Err(ConfigurationError::ZeroPollInterval)
        );
        assert_eq!(stack.polling_policy(), original);
    }
}

fn polls(simulator: &Simulator, child: usize) -> usize {
    simulator
        .trace
        .iter()
        .filter(|entry| {
            entry.node == child
                && Frame::decode_exact(&entry.frame).is_ok_and(|frame| {
                    frame.header.frame_control.frame_type() == FrameType::Command
                        && matches!(
                            MacCommand::decode_exact(frame.payload),
                            Ok(MacCommand::DataRequest)
                        )
                })
        })
        .count()
}

#[test]
fn a_running_sleepy_device_reschedules_its_next_poll() {
    let mut simulator = Simulator::new();
    let coordinator = simulator.add_stack(
        "coordinator",
        node(LogicalDeviceType::Coordinator, false, 1),
        Box::new(OnOffApp::default()),
    );
    let child = simulator.add_stack(
        "sleepy",
        node(LogicalDeviceType::EndDevice, true, 2),
        Box::new(OnOffApp::default()),
    );
    simulator.stack(coordinator).form_network().unwrap();
    assert!(simulator.run_until(Duration::from_secs(30), |sim| {
        sim.stack_ref(coordinator).is_operating()
    }));
    simulator
        .stack(coordinator)
        .permit_join_network(120)
        .unwrap();
    simulator.stack(child).join(JoinMode::Association).unwrap();
    assert!(simulator.run_until(Duration::from_secs(60), |sim| {
        sim.stack_ref(child).is_operating()
    }));
    simulator.run_for(Duration::from_secs(10));
    simulator.stack(child).set_fast_polling(false);
    simulator
        .stack(child)
        .set_polling_policy(PollingPolicy {
            interval: Duration::from_secs(30),
            fast_interval: Duration::from_millis(100),
            fast_polls: 0,
        })
        .unwrap();
    simulator.trace_enabled = true;
    simulator.trace.clear();
    simulator.run_for(Duration::from_secs(1));
    assert_eq!(
        polls(&simulator, child),
        0,
        "the previous short deadline was replaced"
    );
    simulator.run_for(Duration::from_secs(30));
    assert!(
        polls(&simulator, child) > 0,
        "the new deadline still produces MAC polls"
    );
    assert_identity(
        simulator.stack_ref(child),
        LogicalDeviceType::EndDevice,
        true,
        2,
    );
}
