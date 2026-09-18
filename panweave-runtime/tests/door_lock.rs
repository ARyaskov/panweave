//! A door lock router driven by a coordinator (ZCL8 §7.3): a PIN is
//! programmed over the air (Set PIN Code Response, RF programming event
//! to the bound client), Unlock with Timeout is refused without the
//! required PIN and accepted with it (Unlock Response, the bolt
//! operation reaching the application, the RF operation event with the
//! PIN masked), and the automatic relock fires with a Manual-source
//! Auto Lock event. The Door Lock server outgrows `small-tables`.
#![cfg(not(feature = "small-tables"))]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::Destination;
use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_codec::{Encode, Writer};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, CommandId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
    TransactionSequence,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::door_lock::{self as dl, Action};
use panweave_zcl::clusters::identify;
use panweave_zcl::frame::Direction;
use panweave_zcl::global::{AttributeValue, command};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::Value;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const LOCK_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0004);
const EP: Endpoint = Endpoint(1);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    let (servers, clients, device): (&[ClusterId], &[ClusterId], DeviceId) = match role {
        LogicalDeviceType::Router => {
            ep.add_instance(dl::server(dl::lock_type::DEAD_BOLT, 4, true).unwrap())
                .unwrap();
            (
                &[ClusterId(0), identify::ID, dl::ID],
                &[identify::ID],
                DeviceId(0x000a),
            )
        }
        _ => {
            ep.add_instance(dl::client()).unwrap();
            (
                &[ClusterId(0), identify::ID],
                &[identify::ID, dl::ID],
                DeviceId(0x000b),
            )
        }
    };
    let desc =
        SimpleDescriptor::new(EP, ProfileId::HOME_AUTOMATION, device, 1, servers, clients).unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

fn response(events: &[StackEvent], seq: TransactionSequence, cmd: CommandId) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclCommand(f) | StackEvent::ZclResponse(f)
            if f.origin.header.seq == seq
                && f.origin.cluster == dl::ID
                && f.origin.header.command == cmd =>
        {
            Some(f.payload.to_vec())
        }
        _ => None,
    })
}

fn notification(events: &[StackEvent], cmd: CommandId) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclCommand(f)
            if f.origin.cluster == dl::ID && f.origin.header.command == cmd =>
        {
            Some(f.payload.to_vec())
        }
        _ => None,
    })
}

#[test]
fn pin_programming_unlock_with_timeout_and_auto_relock() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let r = sim.add_stack(
        "lock",
        node(LogicalDeviceType::Router, LOCK_IEEE, 42),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
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
    sim.stack(r)
        .aps
        .bindings
        .bind(BindingEntry {
            src_endpoint: EP,
            cluster: dl::ID,
            destination: BindingDestination::Unicast {
                address: COORD_IEEE,
                endpoint: EP,
            },
        })
        .unwrap();
    sim.run_for(Duration::from_secs(3));
    sim.take_events(c);
    sim.take_events(r);
    let dst = Destination::Short {
        address: sim.stack(r).short_address(),
        endpoint: EP,
    };

    // The installer enables every RF event and requires a PIN.
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    for (id, value) in [
        (
            dl::RF_OPERATION_EVENT_MASK.id,
            Value::Bits {
                width: 2,
                bits: 0xffff,
            },
        ),
        (
            dl::RF_PROGRAMMING_EVENT_MASK.id,
            Value::Bits {
                width: 2,
                bits: 0xffff,
            },
        ),
        (
            dl::MANUAL_OPERATION_EVENT_MASK.id,
            Value::Bits {
                width: 2,
                bits: 0xffff,
            },
        ),
        (dl::REQUIRE_PIN_FOR_RF_OPERATION.id, Value::Bool(Some(true))),
    ] {
        AttributeValue { id, value }.encode(&mut w).unwrap();
    }
    let n = w.position();
    sim.stack(c)
        .zcl
        .send_global(
            dst,
            ProfileId::HOME_AUTOMATION,
            dl::ID,
            EP,
            command::WRITE_ATTRIBUTES,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    sim.run_for(Duration::from_secs(5));
    assert!(
        sim.stack(r)
            .zcl
            .cluster(EP, dl::ID, Role::Server)
            .unwrap()
            .bool(dl::REQUIRE_PIN_FOR_RF_OPERATION.id)
    );
    sim.take_events(c);

    // Set PIN Code for user 2.
    let n = dl::encode_set_pin_code(
        2,
        dl::user_status::OCCUPIED_ENABLED,
        dl::user_type::UNRESTRICTED,
        b"2580",
        &mut buf,
    )
    .unwrap();
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            dl::ID,
            EP,
            dl::CMD_SET_PIN_CODE,
            Direction::ToServer,
            None,
            &buf[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(
        sim.run_until(Duration::from_secs(10), |x| {
            response(x.events(c), seq, dl::CMD_SET_PIN_CODE_RESPONSE).is_some()
                && notification(x.events(c), dl::CMD_PROGRAMMING_EVENT_NOTIFICATION).is_some()
        }),
        "{:?}",
        sim.events(c)
    );
    assert_eq!(
        response(sim.events(c), seq, dl::CMD_SET_PIN_CODE_RESPONSE).unwrap(),
        vec![dl::set_pin_status::SUCCESS]
    );
    let p = notification(sim.events(c), dl::CMD_PROGRAMMING_EVENT_NOTIFICATION).unwrap();
    let ev = dl::ProgrammingEvent::parse(&p).unwrap();
    assert_eq!(
        (ev.source, ev.code, ev.user_id, ev.pin, ev.local_time),
        (
            dl::source::RF,
            dl::programming_event::PIN_ADDED,
            2,
            &[0xff; 4][..],
            dl::NO_TIME
        )
    );
    sim.take_events(c);

    // Unlock with Timeout without the PIN: FAILURE, no bolt movement.
    let payload = [10u8, 0];
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            dl::ID,
            EP,
            dl::CMD_UNLOCK_WITH_TIMEOUT,
            Direction::ToServer,
            None,
            &payload,
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(10), |x| {
        response(x.events(c), seq, dl::CMD_UNLOCK_WITH_TIMEOUT_RESPONSE).is_some()
    }));
    assert_eq!(
        response(sim.events(c), seq, dl::CMD_UNLOCK_WITH_TIMEOUT_RESPONSE).unwrap(),
        vec![1]
    );
    let p = notification(sim.events(c), dl::CMD_OPERATION_EVENT_NOTIFICATION).unwrap();
    assert_eq!(
        dl::OperationEvent::parse(&p).unwrap().code,
        dl::operation_event::UNLOCK_FAILURE_INVALID_PIN
    );
    assert!(
        !sim.events(r)
            .iter()
            .any(|e| matches!(e, StackEvent::DoorLock { .. }))
    );
    sim.take_events(c);

    // With the PIN: SUCCESS, the application unlocks, the event names
    // user 2, and the relock fires 10 s later.
    let mut payload = [0u8; 16];
    payload[..2].copy_from_slice(&10u16.to_le_bytes());
    let n = 2 + dl::encode_operation(b"2580", &mut payload[2..]).unwrap();
    let seq = sim
        .stack(c)
        .zcl
        .send_command(
            dst,
            ProfileId::HOME_AUTOMATION,
            dl::ID,
            EP,
            dl::CMD_UNLOCK_WITH_TIMEOUT,
            Direction::ToServer,
            None,
            &payload[..n],
        )
        .unwrap();
    sim.stack(c).flush();
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        x.events(r).iter().any(|e| {
            matches!(
                e,
                StackEvent::DoorLock {
                    endpoint: EP,
                    action: Action::Unlock,
                    user: 2
                }
            )
        })
    }));
    sim.stack(r)
        .zcl
        .set_lock_state(EP, dl::lock_state::UNLOCKED)
        .unwrap();
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        response(x.events(c), seq, dl::CMD_UNLOCK_WITH_TIMEOUT_RESPONSE) == Some(vec![0])
            && notification(x.events(c), dl::CMD_OPERATION_EVENT_NOTIFICATION).is_some()
    }));
    let p = notification(sim.events(c), dl::CMD_OPERATION_EVENT_NOTIFICATION).unwrap();
    let ev = dl::OperationEvent::parse(&p).unwrap();
    assert_eq!(
        (ev.source, ev.code, ev.user_id),
        (dl::source::RF, dl::operation_event::UNLOCK, 2)
    );
    sim.take_events(c);
    sim.take_events(r);
    assert!(
        sim.run_until(Duration::from_secs(20), |x| {
            x.events(r).iter().any(|e| {
                matches!(
                    e,
                    StackEvent::DoorLock {
                        endpoint: EP,
                        action: Action::Lock,
                        user: dl::NO_USER
                    }
                )
            })
        }),
        "{:?}",
        sim.events(r)
    );
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        notification(x.events(c), dl::CMD_OPERATION_EVENT_NOTIFICATION).is_some()
    }));
    let p = notification(sim.events(c), dl::CMD_OPERATION_EVENT_NOTIFICATION).unwrap();
    let ev = dl::OperationEvent::parse(&p).unwrap();
    assert_eq!(
        (ev.source, ev.code),
        (dl::source::MANUAL, dl::operation_event::AUTO_LOCK)
    );
    // A keypad unlock observed by the application is notified too once
    // its mask allows it.
    {
        let cl = sim
            .stack(r)
            .zcl
            .cluster_mut(EP, dl::ID, Role::Server)
            .unwrap();
        cl.set(
            dl::KEYPAD_OPERATION_EVENT_MASK.id,
            &Value::Bits {
                width: 2,
                bits: 1 << dl::operation_event::UNLOCK,
            },
        );
    }
    sim.take_events(c);
    assert!(
        sim.stack(r)
            .zcl
            .door_lock_operation_event(
                EP,
                dl::source::KEYPAD,
                dl::operation_event::UNLOCK,
                2,
                b"2580"
            )
            .unwrap()
    );
    sim.stack(r).flush();
    assert!(sim.run_until(Duration::from_secs(5), |x| {
        notification(x.events(c), dl::CMD_OPERATION_EVENT_NOTIFICATION).is_some()
    }));
    let p = notification(sim.events(c), dl::CMD_OPERATION_EVENT_NOTIFICATION).unwrap();
    assert_eq!(
        dl::OperationEvent::parse(&p).unwrap().source,
        dl::source::KEYPAD
    );
}
