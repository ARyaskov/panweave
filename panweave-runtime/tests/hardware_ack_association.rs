//! R21 sleepy-child association with a radio that waits for ACKs but does not retry.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use panweave_codec::{Decode, Encode, Writer};
use panweave_mac::frame::{Frame, FrameType, Header, MacAddress, MacCommand};
use panweave_mac::radio::{RadioCapabilities, RadioError, RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacServiceConfig};
use panweave_runtime::StackConfig;
use panweave_runtime::join_trace::JoinStage;
use panweave_sim::SimStack;
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Instant;
use panweave_types::{ExtendedAddress, Key128, LogicalDeviceType, MacStatus, PanId, ShortAddress};

const TC: ExtendedAddress = ExtendedAddress(1);
const CHILD: ExtendedAddress = ExtendedAddress(2);

fn coordinator() -> SimStack {
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, TC);
    cfg.trust_center_policy.allow_joins = true;
    let mut stack = SimStack::new(
        cfg,
        MacServiceConfig {
            radio: RadioCapabilities {
                auto_ack: true,
                ack_wait: true,
                retries: false,
                ..RadioCapabilities::default()
            },
            ..MacServiceConfig::default()
        },
        TestRng::seed(1),
        MemoryStorage::new(),
    );
    // Use the stack's public formation API and service each radio action below.
    stack
        .form_network_with_key(Key128::from_bytes([0x71; 16]))
        .unwrap();
    for ms in 0..30_000 {
        stack.poll(Instant::from_millis(ms));
        while let Some(action) = stack.next_radio_action() {
            match action {
                MacAction::EnergyDetect { .. } => stack.on_energy_result(0),
                MacAction::Transmit { .. } => stack.on_tx_complete(Ok(TxResult::default())),
                _ => {}
            }
        }
        if stack.is_operating() {
            break;
        }
    }
    assert!(stack.is_operating());
    stack.permit_join_network(60).unwrap();
    while let Some(action) = stack.next_radio_action() {
        if matches!(action, MacAction::Transmit { .. }) {
            stack.on_tx_complete(Ok(TxResult::default()));
        }
    }
    stack
}

fn command(stack: &mut SimStack, child: ExtendedAddress, seq: u8, command: MacCommand) {
    let header = Header::new(
        FrameType::Command,
        seq,
        stack.pan_id(),
        MacAddress::Short(ShortAddress::COORDINATOR),
        PanId::BROADCAST,
        MacAddress::Extended(child),
    );
    let header = Header {
        frame_control: header.frame_control.with_ack_request(true),
        ..header
    };
    let mut bytes = [0; 64];
    let mut w = Writer::new(&mut bytes);
    header.encode(&mut w).unwrap();
    command.encode(&mut w).unwrap();
    let n = w.position();
    stack.on_radio_frame(&bytes[..n], RxMetadata::default());
}

fn response(stack: &mut SimStack) -> Vec<u8> {
    while let Some(action) = stack.next_radio_action() {
        if let MacAction::Transmit { frame, .. } = action {
            let f = Frame::decode_exact(&frame).unwrap();
            assert_eq!(
                f.header.frame_control.frame_type(),
                FrameType::Command,
                "no software ACK"
            );
            assert!(matches!(
                MacCommand::decode_exact(f.payload).unwrap(),
                MacCommand::AssociationResponse {
                    status: MacStatus::Success,
                    ..
                }
            ));
            return frame.to_vec();
        }
    }
    panic!("no association response");
}

#[test]
fn hardware_ack_delivers_association_once_to_nwk_and_trust_center() {
    let mut stack = coordinator();
    command(
        &mut stack,
        CHILD,
        1,
        MacCommand::AssociationRequest {
            capability: panweave_types::MacCapability::from_raw(0x80),
        },
    );
    assert_eq!(stack.mac.indirect_len(), 1);
    assert!(stack.next_radio_action().is_none());
    command(&mut stack, CHILD, 2, MacCommand::DataRequest);
    let first = response(&mut stack);
    command(&mut stack, CHILD, 3, MacCommand::DataRequest);
    stack.on_tx_complete(Ok(TxResult {
        acked: true,
        ..TxResult::default()
    }));
    assert_eq!(stack.nwk.stats.join_indications, 1);
    let mut stages = Vec::new();
    while let Some(record) = stack.next_join_record() {
        stages.push(record.stage);
    }
    assert_eq!(
        stages
            .iter()
            .filter(|s| **s == JoinStage::ChildJoined)
            .count(),
        1
    );
    assert!(
        stages.contains(&JoinStage::Decision),
        "Trust Center processes the join"
    );
    assert!(stages.contains(&JoinStage::KeyTransportSent));
    // Past the old 5 ms software ACK timeout, without polling the child again.
    stack.poll(Instant::from_millis(30_100));
    while let Some(action) = stack.next_radio_action() {
        if let MacAction::Transmit { frame, .. } = action {
            assert_ne!(frame.as_slice(), first);
            stack.on_tx_complete(Ok(TxResult {
                acked: true,
                ..TxResult::default()
            }));
        }
    }
    assert_eq!(stack.nwk.stats.join_indications, 1);
}

#[test]
fn undelivered_association_does_not_reach_trust_center() {
    for fault in [false, true] {
        let mut stack = coordinator();
        command(
            &mut stack,
            CHILD,
            1,
            MacCommand::AssociationRequest {
                capability: panweave_types::MacCapability::from_raw(0x80),
            },
        );
        command(&mut stack, CHILD, 2, MacCommand::DataRequest);
        let first = response(&mut stack);
        if fault {
            stack.on_tx_complete(Err(RadioError::HardwareFault));
        } else {
            for attempt in 0..=panweave_mac::constants::MAX_FRAME_RETRIES {
                if attempt > 0 {
                    assert_eq!(response(&mut stack), first);
                }
                stack.on_tx_complete(Ok(TxResult::default()));
            }
        }
        assert_eq!(stack.nwk.stats.join_indications, 0);
        assert!(stack.nwk.neighbors.by_extended(CHILD).is_none());
        while let Some(record) = stack.next_join_record() {
            assert_eq!(record.stage, JoinStage::AssociationRequest);
        }
        assert!(stack.next_radio_action().is_none());
    }
}

#[test]
fn expired_association_is_removed_without_join_indication() {
    let mut stack = coordinator();
    command(
        &mut stack,
        CHILD,
        1,
        MacCommand::AssociationRequest {
            capability: panweave_types::MacCapability::from_raw(0x80),
        },
    );
    // No child poll before macTransactionPersistenceTime expires.
    stack.poll(Instant::from_millis(100_000));
    assert_eq!(stack.mac.indirect_len(), 0);
    assert_eq!(stack.nwk.stats.join_indications, 0);
    assert!(stack.nwk.neighbors.by_extended(CHILD).is_none());
    while let Some(record) = stack.next_join_record() {
        assert_eq!(record.stage, JoinStage::AssociationRequest);
    }
}

#[test]
fn two_sleepy_children_deliver_independently_after_window_closes() {
    let mut stack = coordinator();
    for child in [CHILD, ExtendedAddress(3)] {
        command(
            &mut stack,
            child,
            1,
            MacCommand::AssociationRequest {
                capability: panweave_types::MacCapability::from_raw(0x80),
            },
        );
    }
    assert_eq!(stack.mac.indirect_len(), 2);
    stack.permit_join_network(0).unwrap();
    // Drain the permit-join broadcast, if any.
    while let Some(action) = stack.next_radio_action() {
        if matches!(action, MacAction::Transmit { .. }) {
            stack.on_tx_complete(Ok(TxResult::default()));
        }
    }
    for (i, child) in [CHILD, ExtendedAddress(3)].into_iter().enumerate() {
        command(&mut stack, child, 2, MacCommand::DataRequest);
        let frame = response(&mut stack);
        assert_eq!(
            Frame::decode_exact(&frame).unwrap().header.dst,
            MacAddress::Extended(child)
        );
        stack.on_tx_complete(Ok(TxResult {
            acked: true,
            ..TxResult::default()
        }));
        assert_eq!(
            stack.nwk.stats.join_indications,
            u32::try_from(i + 1).unwrap()
        );
    }
    let mut joined = Vec::new();
    while let Some(record) = stack.next_join_record() {
        if record.stage == JoinStage::ChildJoined {
            joined.push(record.device);
        }
    }
    assert_eq!(joined, vec![CHILD, ExtendedAddress(3)]);
}
