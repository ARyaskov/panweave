//! Clusters executed by the endpoint dispatcher: On/Off (timed off, global
//! scene), Level Control (transitions, On/Off coupling), Scenes (table,
//! store / recall), Poll Control (check-ins, fast polling) and the Basic
//! Reset to Factory Defaults.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
use panweave_aps::tables::GroupTable;
use panweave_aps::{Destination, TxOptions};
use panweave_codec::{Decode, Encode};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    AttributeId, ClusterId, CommandId, Endpoint, GroupAddress, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::{
    basic, color_control, groups, identify, level, on_off, poll_control, scenes,
};
use panweave_zcl::frame::{Direction, Frame, FrameType, Header, ZclStatus};
use panweave_zcl::global::{
    AttributeValue, DefaultResponse, Records, WriteAttributeStatus, command,
};
use panweave_zcl::layer::{EndpointInstance, Zcl, ZclAction, ZclEvent};
use panweave_zcl::types::DataType;
use panweave_zcl::{Role, Value as V};

const CLIENT: ShortAddress = ShortAddress(0x1234);
const EP: Endpoint = Endpoint(1);
const T0: Instant = Instant::from_millis(1000);

type Node = Zcl<2, 8, 24>;

fn lamp() -> Node {
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(
        basic::server(
            basic::power_source::MAINS_SINGLE_PHASE,
            b"Panweave",
            b"Dimmer",
        )
        .unwrap(),
    )
    .unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(groups::server().unwrap()).unwrap();
    ep.add_instance(scenes::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    ep.add_instance(level::server(1, 254).unwrap()).unwrap();
    zcl.add_endpoint(ep).unwrap();
    zcl.poll_timers(T0);
    zcl
}

fn ind<'a>(cluster: ClusterId, asdu: &'a [u8], broadcast: bool) -> DataIndication<'a> {
    DataIndication {
        src: CLIENT,
        src_endpoint: Endpoint(5),
        src_ieee: None,
        delivery: Delivery::Endpoint(EP),
        profile: ProfileId::HOME_AUTOMATION,
        cluster,
        asdu,
        security: SecurityStatus::NwkKey,
        lqi: 200,
        relayed: None,
        counter: 0,
        nwk_broadcast: broadcast,
    }
}

fn frame(header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 96];
    let n = Frame {
        header: *header,
        payload,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    buf[..n].to_vec()
}

/// Sends a cluster-specific command (to the server) and drains the
/// actions; returns the (header, payload) of the first reply.
fn command(
    zcl: &mut Node,
    groups: &mut GroupTable<4>,
    cluster: ClusterId,
    cmd: CommandId,
    payload: &[u8],
    unicast: bool,
) -> Option<(Header, Vec<u8>)> {
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(0x21),
        cmd,
        Direction::ToServer,
    );
    let bytes = frame(&header, payload);
    // Leftover reports from earlier ticks are not the reply.
    while zcl.next_action().is_some() {}
    let out = zcl.on_data(&ind(cluster, &bytes, !unicast), groups);
    assert!(out.is_none(), "executed by the layer");
    match zcl.next_action()? {
        ZclAction::Send { frame, .. } => {
            let (h, n) = Header::decode_prefix(&frame).unwrap();
            Some((h, frame[n..].to_vec()))
        }
    }
}

fn default_status(reply: Option<(Header, Vec<u8>)>) -> ZclStatus {
    let (h, p) = reply.expect("a reply");
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    DefaultResponse::decode_exact(&p).unwrap().status
}

fn events(zcl: &mut Node) -> Vec<ZclEvent> {
    let mut v = Vec::new();
    while let Some(e) = zcl.next_event() {
        v.push(e);
    }
    v
}

fn level_of(zcl: &Node) -> u8 {
    level::current_level(zcl.cluster(EP, level::ID, Role::Server).unwrap())
}

fn is_on(zcl: &Node) -> bool {
    on_off::is_on(zcl.cluster(EP, on_off::ID, Role::Server).unwrap())
}

#[test]
fn on_with_timed_off_counts_down_and_guards_the_off_state() {
    let mut zcl = lamp();
    let mut g = GroupTable::<4>::new();
    // Accept only when on, while off: discarded.
    let st = default_status(command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_ON_WITH_TIMED_OFF,
        &[0x01, 10, 0, 20, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::Success);
    assert!(!is_on(&zcl));
    // Unconditional: on for 1 s, then guarded off for 2 s.
    let st = default_status(command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_ON_WITH_TIMED_OFF,
        &[0x00, 10, 0, 20, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::Success);
    assert!(is_on(&zcl));
    assert!(events(&mut zcl).contains(&ZclEvent::OnOff {
        endpoint: EP,
        on: true
    }));
    zcl.poll_timers(T0 + Duration::from_millis(900));
    assert!(is_on(&zcl));
    zcl.poll_timers(T0 + Duration::from_millis(1000));
    assert!(!is_on(&zcl), "OnTime elapsed");
    assert!(events(&mut zcl).contains(&ZclEvent::OnOff {
        endpoint: EP,
        on: false
    }));
    let c = zcl.cluster(EP, on_off::ID, Role::Server).unwrap();
    assert_eq!(c.u16(on_off::ON_TIME.id), Some(0));
    assert_eq!(
        c.u16(on_off::OFF_WAIT_TIME.id),
        Some(0),
        "an expired OnTime clears OffWaitTime (§3.8.2.3.6.4)"
    );
    // Switched off by an Off command during the timed-on period: the
    // off state is guarded for OffWaitTime.
    let _ = command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_ON_WITH_TIMED_OFF,
        &[0x00, 10, 0, 20, 0],
        true,
    );
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_OFF, &[], true);
    let c = zcl.cluster(EP, on_off::ID, Role::Server).unwrap();
    assert_eq!(c.u16(on_off::ON_TIME.id), Some(0));
    assert_eq!(c.u16(on_off::OFF_WAIT_TIME.id), Some(20));
    // During the guarded off period a timed-on only shortens the wait.
    let _ = command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_ON_WITH_TIMED_OFF,
        &[0x00, 10, 0, 5, 0],
        true,
    );
    assert!(!is_on(&zcl), "guarded");
    let c = zcl.cluster(EP, on_off::ID, Role::Server).unwrap();
    assert_eq!(c.u16(on_off::OFF_WAIT_TIME.id), Some(5));
    zcl.poll_timers(T0 + Duration::from_millis(1600));
    let c = zcl.cluster(EP, on_off::ID, Role::Server).unwrap();
    assert_eq!(c.u16(on_off::OFF_WAIT_TIME.id), Some(0));
    assert_eq!(c.tick, None);
}

#[test]
fn level_transitions_run_on_the_tick_and_couple_with_on_off() {
    let mut zcl = lamp();
    let mut g = GroupTable::<4>::new();
    // Off + ExecuteIfOff clear: Move to Level is suppressed.
    let st = default_status(command(
        &mut zcl,
        &mut g,
        level::ID,
        level::CMD_MOVE_TO_LEVEL,
        &[100, 10, 0, 0, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::Success);
    assert_eq!(level_of(&zcl), 1);
    // OptionsOverride sets ExecuteIfOff for this command.
    let _ = command(
        &mut zcl,
        &mut g,
        level::ID,
        level::CMD_MOVE_TO_LEVEL,
        &[101, 10, 0, 0x01, 0x01],
        true,
    );
    assert_eq!(level_of(&zcl), 1, "transition just started");
    zcl.poll_timers(T0 + Duration::from_millis(500));
    assert_eq!(level_of(&zcl), 51, "half way after 0.5 s of 1 s");
    let c = zcl.cluster(EP, level::ID, Role::Server).unwrap();
    assert_eq!(c.u16(level::REMAINING_TIME.id), Some(5));
    zcl.poll_timers(T0 + Duration::from_millis(1000));
    assert_eq!(level_of(&zcl), 101);
    assert!(events(&mut zcl).contains(&ZclEvent::Level {
        endpoint: EP,
        level: 101,
        done: true
    }));
    assert!(!is_on(&zcl), "'without On/Off' leaves OnOff alone");

    // Move (with On/Off) up at 100 units/s turns the device on.
    let now = T0 + Duration::from_millis(1000);
    let _ = command(
        &mut zcl,
        &mut g,
        level::ID,
        level::CMD_MOVE_WITH_ON_OFF,
        &[level::MODE_UP, 100, 0, 0],
        true,
    );
    assert!(is_on(&zcl));
    zcl.poll_timers(now + Duration::from_millis(1500));
    assert_ne!(level_of(&zcl), 254, "153 units at 100/s take 1.6 s");
    zcl.poll_timers(now + Duration::from_millis(1600));
    assert_eq!(level_of(&zcl), 254, "reached MaxLevel");
    // Step (with On/Off) down to the minimum turns it off again.
    let now = now + Duration::from_millis(1600);
    let _ = command(
        &mut zcl,
        &mut g,
        level::ID,
        level::CMD_STEP_WITH_ON_OFF,
        &[level::MODE_DOWN, 253, 0, 0, 0, 0],
        true,
    );
    zcl.poll_timers(now);
    assert_eq!(level_of(&zcl), 1);
    assert!(!is_on(&zcl), "minimum level turns off");
    // Stop ends a running move.
    let _ = command(
        &mut zcl,
        &mut g,
        level::ID,
        level::CMD_MOVE_WITH_ON_OFF,
        &[level::MODE_UP, 10, 0, 0],
        true,
    );
    zcl.poll_timers(now + Duration::from_millis(2000));
    assert_eq!(level_of(&zcl), 21);
    let _ = command(&mut zcl, &mut g, level::ID, level::CMD_STOP, &[0, 0], true);
    zcl.poll_timers(now + Duration::from_millis(5000));
    assert_eq!(level_of(&zcl), 21, "stopped where it was");
    let c = zcl.cluster(EP, level::ID, Role::Server).unwrap();
    assert_eq!(c.u16(level::REMAINING_TIME.id), Some(0));

    // Table 3-55: Off fades to the minimum over OnOffTransitionTime and,
    // with OnLevel undefined, restores CurrentLevel afterwards.
    let now = now + Duration::from_millis(5000);
    zcl.cluster_mut(EP, level::ID, Role::Server)
        .unwrap()
        .set_u16(level::ON_OFF_TRANSITION_TIME.id, 10);
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_OFF, &[], true);
    zcl.poll_timers(now + Duration::from_millis(500));
    assert_eq!(level_of(&zcl), 11);
    zcl.poll_timers(now + Duration::from_millis(1000));
    assert_eq!(level_of(&zcl), 21, "restored after the fade");
    // On: from the minimum back up to the stored level.
    let now = now + Duration::from_millis(1000);
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_ON, &[], true);
    assert_eq!(level_of(&zcl), 1);
    zcl.poll_timers(now + Duration::from_millis(1000));
    assert_eq!(level_of(&zcl), 21);
    assert!(is_on(&zcl));
}

#[test]
fn scenes_store_recall_and_the_global_scene() {
    let mut zcl = lamp();
    let mut g = GroupTable::<4>::new();
    g.add(GroupAddress(7), EP).unwrap();
    // Add Scene for a group the endpoint is not in → INVALID_FIELD.
    let (h, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_ADD_SCENE,
        &[9, 0, 1, 0, 0, 0],
        true,
    )
    .unwrap();
    assert_eq!(h.command, scenes::CMD_ADD_SCENE_RESPONSE);
    assert_eq!(p, vec![ZclStatus::InvalidField.raw(), 9, 0, 1]);
    // Add Scene 7/1: On, level 200, 2 s transition, no name.
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_ADD_SCENE,
        &[7, 0, 1, 2, 0, 0, 0x06, 0x00, 1, 1, 0x08, 0x00, 1, 200],
        true,
    )
    .unwrap();
    assert_eq!(p, vec![ZclStatus::Success.raw(), 7, 0, 1]);
    let c = zcl.cluster(EP, scenes::ID, Role::Server).unwrap();
    assert_eq!(c.u8(scenes::SCENE_COUNT.id), Some(1));
    // View Scene echoes the entry.
    let (h, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_VIEW_SCENE,
        &[7, 0, 1],
        true,
    )
    .unwrap();
    assert_eq!(h.command, scenes::CMD_VIEW_SCENE_RESPONSE);
    assert_eq!(
        p,
        vec![0, 7, 0, 1, 2, 0, 0, 0x06, 0x00, 1, 1, 0x08, 0x00, 1, 200]
    );
    // Enhanced View reports tenths.
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_ENHANCED_VIEW_SCENE,
        &[7, 0, 1],
        true,
    )
    .unwrap();
    assert_eq!(p[4..6], [20, 0]);
    // Recall via groupcast: the lamp turns on and fades to 200 over 2 s.
    let out = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_RECALL_SCENE,
        &[7, 0, 1],
        false,
    );
    assert!(out.is_none(), "no response to a groupcast recall");
    assert!(is_on(&zcl));
    let ev = events(&mut zcl);
    assert!(ev.contains(&ZclEvent::SceneRecalled {
        endpoint: EP,
        group: 7,
        scene: 1
    }));
    zcl.poll_timers(T0 + Duration::from_millis(2000));
    assert_eq!(level_of(&zcl), 200);
    let c = zcl.cluster(EP, scenes::ID, Role::Server).unwrap();
    assert!(c.bool(scenes::SCENE_VALID.id));
    assert_eq!(c.u8(scenes::CURRENT_SCENE.id), Some(1));
    assert_eq!(c.u16(scenes::CURRENT_GROUP.id), Some(7));
    // A later On/Off command invalidates the scene.
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_OFF, &[], true);
    let c = zcl.cluster(EP, scenes::ID, Role::Server).unwrap();
    assert!(!c.bool(scenes::SCENE_VALID.id));
    // Store Scene captures the current state (off, level 200).
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_STORE_SCENE,
        &[7, 0, 2],
        true,
    )
    .unwrap();
    assert_eq!(p, vec![0, 7, 0, 2]);
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_VIEW_SCENE,
        &[7, 0, 2],
        true,
    )
    .unwrap();
    assert_eq!(p[7..], [0x06, 0x00, 1, 0, 0x08, 0x00, 1, 200]);
    // Get Scene Membership lists both.
    let (h, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_GET_SCENE_MEMBERSHIP,
        &[7, 0],
        true,
    )
    .unwrap();
    assert_eq!(h.command, scenes::CMD_GET_SCENE_MEMBERSHIP_RESPONSE);
    assert_eq!(p[0], 0);
    assert_eq!(p[1], 14, "capacity");
    assert_eq!(&p[2..5], &[7, 0, 2]);
    let mut listed = p[5..].to_vec();
    listed.sort_unstable();
    assert_eq!(listed, vec![1, 2]);
    // Copy all scenes of group 7 to group 0 (no group).
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_COPY_SCENE,
        &[0x01, 7, 0, 0, 0, 0, 0],
        true,
    )
    .unwrap();
    assert_eq!(p, vec![0, 7, 0, 0]);
    let c = zcl.cluster(EP, scenes::ID, Role::Server).unwrap();
    assert_eq!(c.u8(scenes::SCENE_COUNT.id), Some(4));
    // Remove All Scenes of group 7.
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_REMOVE_ALL_SCENES,
        &[7, 0],
        true,
    )
    .unwrap();
    assert_eq!(p, vec![0, 7, 0]);
    let c = zcl.cluster(EP, scenes::ID, Role::Server).unwrap();
    assert_eq!(c.u8(scenes::SCENE_COUNT.id), Some(2));

    // Global scene: On, level 200 → Off With Effect stores it, On With
    // Recall Global Scene brings it back.
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_ON, &[], true);
    zcl.poll_timers(T0 + Duration::from_millis(3000));
    let _ = command(
        &mut zcl,
        &mut g,
        level::ID,
        level::CMD_MOVE_TO_LEVEL,
        &[150, 0, 0, 0, 0],
        true,
    );
    assert_eq!(level_of(&zcl), 150);
    let _ = events(&mut zcl);
    let st = default_status(command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_OFF_WITH_EFFECT,
        &[on_off::effect::DYING_LIGHT, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::Success);
    assert!(!is_on(&zcl));
    let ev = events(&mut zcl);
    assert!(ev.contains(&ZclEvent::OffWithEffect {
        endpoint: EP,
        effect: on_off::effect::DYING_LIGHT,
        variant: 0
    }));
    let c = zcl.cluster(EP, on_off::ID, Role::Server).unwrap();
    assert!(!c.bool(on_off::GLOBAL_SCENE_CONTROL.id));
    // A second Off With Effect does not overwrite the stored scene.
    let _ = command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_OFF_WITH_EFFECT,
        &[0, 0],
        true,
    );
    let _ = command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_ON_WITH_RECALL_GLOBAL_SCENE,
        &[],
        true,
    );
    assert!(is_on(&zcl));
    zcl.poll_timers(T0 + Duration::from_millis(3100));
    assert_eq!(level_of(&zcl), 150, "global scene level");
    let c = zcl.cluster(EP, on_off::ID, Role::Server).unwrap();
    assert!(c.bool(on_off::GLOBAL_SCENE_CONTROL.id));
    // With GlobalSceneControl set the recall is discarded.
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_OFF, &[], true);
    let _ = command(
        &mut zcl,
        &mut g,
        on_off::ID,
        on_off::CMD_ON_WITH_RECALL_GLOBAL_SCENE,
        &[],
        true,
    );
    assert!(!is_on(&zcl));
}

#[test]
fn poll_control_server_checks_in_and_fast_polls() {
    let mut zcl = Node::new();
    let mut ep = EndpointInstance::new(EP, ProfileId::HOME_AUTOMATION);
    ep.add_instance(poll_control::server(2, 4, 0x28).unwrap())
        .unwrap();
    zcl.add_endpoint(ep).unwrap();
    // Check-in interval: 2 s (8 quarter-seconds), written by the client.
    zcl.cluster_mut(EP, poll_control::ID, Role::Server)
        .unwrap()
        .set(
            poll_control::CHECK_IN_INTERVAL.id,
            &V::Uint { width: 4, value: 8 },
        );
    zcl.poll_timers(T0);
    assert_eq!(zcl.next_deadline(), Some(T0 + Duration::from_secs(2)));
    zcl.poll_timers(T0 + Duration::from_secs(2));
    let ZclAction::Send {
        destination,
        frame: fr,
        cluster,
        options,
        ..
    } = zcl.next_action().expect("check-in");
    assert_eq!(destination, Destination::Bound);
    assert_eq!(cluster, poll_control::ID);
    assert_eq!(options, TxOptions::ACKED);
    let (h, _) = Header::decode_prefix(&fr).unwrap();
    assert_eq!(h.command, poll_control::CMD_CHECK_IN);
    assert_eq!(h.control.direction, Direction::ToClient);
    assert_eq!(
        events(&mut zcl),
        vec![ZclEvent::FastPoll {
            endpoint: EP,
            fast: true,
            interval: Duration::from_millis(500)
        }]
    );
    // Check-in Response: fast poll for 4 quarter-seconds.
    let mut g = GroupTable::<4>::new();
    let st = default_status(command(
        &mut zcl,
        &mut g,
        poll_control::ID,
        poll_control::CMD_CHECK_IN_RESPONSE,
        &[1, 4, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::Success);
    assert_eq!(
        events(&mut zcl),
        vec![ZclEvent::FastPoll {
            endpoint: EP,
            fast: true,
            interval: Duration::from_millis(500)
        }]
    );
    let now = T0 + Duration::from_secs(2);
    zcl.poll_timers(now + Duration::from_millis(999));
    assert!(events(&mut zcl).is_empty());
    zcl.poll_timers(now + Duration::from_millis(1000));
    assert_eq!(
        events(&mut zcl),
        vec![ZclEvent::FastPoll {
            endpoint: EP,
            fast: false,
            interval: Duration::from_millis(5000)
        }]
    );
    // Fast Poll Stop while not fast polling → FAILURE.
    let st = default_status(command(
        &mut zcl,
        &mut g,
        poll_control::ID,
        poll_control::CMD_FAST_POLL_STOP,
        &[],
        true,
    ));
    assert_eq!(st, ZclStatus::Failure);
    // A late Check-in Response → FAILURE; a timeout above the maximum →
    // INVALID_FIELD.
    let st = default_status(command(
        &mut zcl,
        &mut g,
        poll_control::ID,
        poll_control::CMD_CHECK_IN_RESPONSE,
        &[1, 4, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::Failure);
    let st = default_status(command(
        &mut zcl,
        &mut g,
        poll_control::ID,
        poll_control::CMD_CHECK_IN_RESPONSE,
        &[1, 0xff, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::InvalidField);
    // The check-in period is constant: the next one is at T0 + 4 s.
    assert_eq!(zcl.next_deadline(), Some(T0 + Duration::from_secs(4)));
    // Set Long Poll Interval below the minimum → INVALID_VALUE; a valid
    // one is reported.
    let st = default_status(command(
        &mut zcl,
        &mut g,
        poll_control::ID,
        poll_control::CMD_SET_LONG_POLL_INTERVAL,
        &[3, 0, 0, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::InvalidValue);
    let st = default_status(command(
        &mut zcl,
        &mut g,
        poll_control::ID,
        poll_control::CMD_SET_LONG_POLL_INTERVAL,
        &[8, 0, 0, 0],
        true,
    ));
    assert_eq!(st, ZclStatus::Success);
    assert_eq!(
        events(&mut zcl),
        vec![ZclEvent::LongPollInterval {
            endpoint: EP,
            interval: Duration::from_secs(2)
        }]
    );
    // Writing CheckInInterval below LongPollInterval is refused.
    let mut buf = [0u8; 16];
    let n = AttributeValue {
        id: poll_control::CHECK_IN_INTERVAL.id,
        value: V::Uint { width: 4, value: 4 },
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    let header = Header::global(
        panweave_types::TransactionSequence(3),
        command::WRITE_ATTRIBUTES,
        Direction::ToServer,
    );
    let bytes = frame(&header, &buf[..n]);
    assert!(
        zcl.on_data(&ind(poll_control::ID, &bytes, false), &mut g)
            .is_none()
    );
    let ZclAction::Send { frame: fr, .. } = zcl.next_action().unwrap();
    let (_, n) = Header::decode_prefix(&fr).unwrap();
    let st: Vec<WriteAttributeStatus> = Records::new(&fr[n..]).map(Result::unwrap).collect();
    assert_eq!(st[0].status, ZclStatus::InvalidValue);

    // Client side answers a Check-in with its policy.
    let mut client = Node::new();
    let mut ep = EndpointInstance::new(Endpoint(5), ProfileId::HOME_AUTOMATION);
    ep.add_instance(poll_control::client(true, 12)).unwrap();
    client.add_endpoint(ep).unwrap();
    let header = Header::cluster_specific(
        panweave_types::TransactionSequence(9),
        poll_control::CMD_CHECK_IN,
        Direction::ToClient,
    )
    .disable_default_response(true);
    let bytes = frame(&header, &[]);
    let mut i = ind(poll_control::ID, &bytes, false);
    i.delivery = Delivery::Endpoint(Endpoint(5));
    assert!(client.on_data(&i, &mut g).is_none());
    let ZclAction::Send { frame: fr, .. } = client.next_action().unwrap();
    let (h, n) = Header::decode_prefix(&fr).unwrap();
    assert_eq!(h.command, poll_control::CMD_CHECK_IN_RESPONSE);
    assert_eq!(h.control.frame_type, FrameType::ClusterSpecific);
    assert_eq!(h.control.direction, Direction::ToServer);
    assert_eq!(&fr[n..], &[1, 12, 0]);
    assert_eq!(
        events(&mut client),
        vec![ZclEvent::CheckIn {
            endpoint: Endpoint(5),
            src: CLIENT,
            src_endpoint: Endpoint(5)
        }]
    );
}

#[test]
fn reset_to_factory_defaults_restores_attributes_and_reporting() {
    let mut zcl = lamp();
    let mut g = GroupTable::<4>::new();
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_ON, &[], true);
    zcl.cluster_mut(EP, level::ID, Role::Server)
        .unwrap()
        .set_u8(level::ON_LEVEL.id, 77);
    // Reporting reconfigured away from the default.
    let c = zcl.cluster_mut(EP, on_off::ID, Role::Server).unwrap();
    c.attributes
        .get_mut(on_off::ON_OFF.id, None)
        .unwrap()
        .configure_reporting(5, 0xffff, 0, T0);
    assert!(is_on(&zcl));
    let _ = events(&mut zcl);
    let st = default_status(command(
        &mut zcl,
        &mut g,
        basic::ID,
        basic::CMD_RESET_TO_FACTORY_DEFAULTS,
        &[],
        true,
    ));
    assert_eq!(st, ZclStatus::Success);
    assert!(!is_on(&zcl));
    assert_eq!(level_of(&zcl), 1);
    let c = zcl.cluster(EP, level::ID, Role::Server).unwrap();
    assert_eq!(c.u8(level::ON_LEVEL.id), Some(level::ON_LEVEL_UNDEFINED));
    let c = zcl.cluster(EP, on_off::ID, Role::Server).unwrap();
    let rep = c
        .attributes
        .get(on_off::ON_OFF.id, None)
        .unwrap()
        .reporting
        .as_ref()
        .unwrap();
    assert_eq!((rep.min, rep.max), (0, 300), "default reporting restored");
    let c = zcl.cluster(EP, basic::ID, Role::Server).unwrap();
    assert_eq!(
        c.attributes.value(basic::MODEL_IDENTIFIER.id),
        Some(V::String {
            ty: DataType::CharString,
            bytes: Some(b"Dimmer")
        })
    );
    assert_eq!(events(&mut zcl), vec![ZclEvent::FactoryReset]);
    let _ = AttributeId(0);
}

#[test]
fn color_control_through_the_dispatcher_and_scenes() {
    let mut zcl = lamp();
    let mut g = GroupTable::<4>::new();
    g.add(GroupAddress(7), EP).unwrap();
    // Add a colour-temperature lamp to the endpoint.
    zcl.endpoint_mut(EP)
        .unwrap()
        .add_instance(
            color_control::server(
                color_control::capability::HUE_SATURATION
                    | color_control::capability::XY
                    | color_control::capability::COLOR_TEMPERATURE,
                (153, 500),
            )
            .unwrap(),
        )
        .unwrap();
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_ON, &[], true);
    // Move to Color Temperature 300 mireds over 1 s: a Default Response,
    // the Color event stream, then the value.
    let (h, p) = command(
        &mut zcl,
        &mut g,
        color_control::ID,
        color_control::CMD_MOVE_TO_COLOR_TEMPERATURE,
        &[0x2c, 0x01, 10, 0, 0, 0],
        true,
    )
    .unwrap();
    assert_eq!(h.command, command::DEFAULT_RESPONSE);
    assert_eq!(p[1], ZclStatus::Success.raw());
    zcl.poll_timers(T0 + Duration::from_millis(500));
    let c = zcl.cluster(EP, color_control::ID, Role::Server).unwrap();
    let mid = c.u16(color_control::COLOR_TEMPERATURE_MIREDS.id).unwrap();
    assert!((260..=290).contains(&mid), "{mid}");
    assert_eq!(
        c.u8(color_control::COLOR_MODE.id),
        Some(color_control::color_mode::COLOR_TEMPERATURE)
    );
    zcl.poll_timers(T0 + Duration::from_millis(1100));
    let c = zcl.cluster(EP, color_control::ID, Role::Server).unwrap();
    assert_eq!(c.u16(color_control::COLOR_TEMPERATURE_MIREDS.id), Some(300));
    let ev = events(&mut zcl);
    assert!(ev.iter().any(|e| matches!(
        e,
        ZclEvent::Color {
            endpoint: EP,
            mode: color_control::color_mode::COLOR_TEMPERATURE,
            a: 300,
            done: true,
            ..
        }
    )));
    // Store the scene: the colour field set (13 octets) is captured.
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_STORE_SCENE,
        &[7, 0, 3],
        true,
    )
    .unwrap();
    assert_eq!(p, vec![0, 7, 0, 3]);
    let (_, p) = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_VIEW_SCENE,
        &[7, 0, 3],
        true,
    )
    .unwrap();
    let fields: Vec<(ClusterId, Vec<u8>)> = scenes::FieldSets(&p[7..])
        .map(|(c, f)| (c, f.to_vec()))
        .collect();
    let colour = fields
        .iter()
        .find(|(c, _)| *c == color_control::ID)
        .expect("colour field set");
    assert_eq!(colour.1.len(), 13);
    assert_eq!(&colour.1[11..13], &300u16.to_le_bytes());
    // Change the temperature, then recall the scene: it fades back.
    let _ = command(
        &mut zcl,
        &mut g,
        color_control::ID,
        color_control::CMD_MOVE_TO_COLOR_TEMPERATURE,
        &[0xf4, 0x01, 0, 0, 0, 0],
        true,
    );
    zcl.poll_timers(T0 + Duration::from_millis(1200));
    let c = zcl.cluster(EP, color_control::ID, Role::Server).unwrap();
    assert_eq!(c.u16(color_control::COLOR_TEMPERATURE_MIREDS.id), Some(500));
    let _ = command(
        &mut zcl,
        &mut g,
        scenes::ID,
        scenes::CMD_RECALL_SCENE,
        &[7, 0, 3, 0, 0],
        true,
    );
    zcl.poll_timers(T0 + Duration::from_millis(1300));
    let c = zcl.cluster(EP, color_control::ID, Role::Server).unwrap();
    assert_eq!(c.u16(color_control::COLOR_TEMPERATURE_MIREDS.id), Some(300));
    // Off: colour commands are suppressed unless overridden.
    let _ = command(&mut zcl, &mut g, on_off::ID, on_off::CMD_OFF, &[], true);
    let _ = command(
        &mut zcl,
        &mut g,
        color_control::ID,
        color_control::CMD_MOVE_TO_HUE,
        &[100, 0, 0, 0, 0, 0],
        true,
    );
    zcl.poll_timers(T0 + Duration::from_millis(1400));
    let c = zcl.cluster(EP, color_control::ID, Role::Server).unwrap();
    assert_eq!(c.u8(color_control::CURRENT_HUE.id), Some(0));
    assert_eq!(
        c.u8(color_control::COLOR_MODE.id),
        Some(color_control::color_mode::COLOR_TEMPERATURE)
    );
}
