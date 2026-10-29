//! Colour lights, groups and scenes through the hub: Color Control
//! commands confirmed by read-back, the colour state from the interview
//! and reports, group membership, group-addressed commands and scenes.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::model::{ColorMode, ColorState};
use panweave_hub::protocol::{CommandStage, ErrorCode, Event, LightCommand, Request, Response};
use panweave_sim::Simulator;
use panweave_types::time::Duration;

const COLOR_BULB: u64 = 0x00AA_0000_0000_0010;
const OTHER_BULB: u64 = 0x00AA_0000_0000_0011;
const GROUP: u16 = 0x0102;

fn lights() -> (Simulator, usize) {
    let (mut sim, c) = network();
    join(&mut sim, c, "color", color_bulb(COLOR_BULB, 10), COLOR_BULB);
    join(&mut sim, c, "other", color_bulb(OTHER_BULB, 11), OTHER_BULB);
    sim.run_for(Duration::from_secs(5));
    (sim, c)
}

fn color_of(sim: &mut Simulator, c: usize, ieee: u64) -> ColorState {
    match request(sim, c, &Request::GetLightColor { ieee }) {
        Response::LightColor { color, .. } => color,
        other => panic!("{other:?}"),
    }
}

fn on_of(sim: &mut Simulator, c: usize, ieee: u64) -> Option<bool> {
    match request(sim, c, &Request::GetDeviceState { ieee }) {
        Response::DeviceState { state, .. } => state.on,
        other => panic!("{other:?}"),
    }
}

/// Runs `r` (accepted) until its command completes; returns the stage.
fn complete(sim: &mut Simulator, c: usize, r: &Request) -> CommandStage {
    let Response::Accepted { command } = request(sim, c, r) else {
        panic!("{r:?} not accepted")
    };
    match wait_event(
        sim,
        c,
        30,
        |e| matches!(e, Event::CommandCompleted { command: x, .. } | Event::CommandFailed { command: x, .. } if *x == command),
    ) {
        Event::CommandCompleted { stage, .. } => stage,
        e => panic!("{r:?}: {e:?}"),
    }
}

#[test]
fn the_interview_reads_the_colour_capabilities() {
    let (mut sim, c) = lights();
    let color = color_of(&mut sim, c, COLOR_BULB);
    assert!(
        color.supports(ColorState::XY | ColorState::TEMPERATURE),
        "{color:?}"
    );
    assert!(!color.supports(ColorState::HUE_SATURATION));
    assert_eq!((color.mireds_min, color.mireds_max), (Some(153), Some(500)));
    assert!(color.x.is_some() && color.y.is_some(), "{color:?}");
    assert!(
        hub_events(&sim, c)
            .iter()
            .any(|e| matches!(e, Event::LightColorChanged { ieee, color } if *ieee == COLOR_BULB && color.capabilities.is_some()))
    );
    // A light without Color Control has no colour.
    join(&mut sim, c, "bulb", bulb(), BULB);
    assert_eq!(
        request(&mut sim, c, &Request::GetLightColor { ieee: BULB }),
        Response::Error(ErrorCode::NotSupported)
    );
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::Light {
                ieee: BULB,
                endpoint: 0,
                command: LightCommand::SetColorTemperature {
                    mireds: 300,
                    transition_ds: 0
                }
            }
        ),
        Response::Error(ErrorCode::NotSupported)
    );
}

#[test]
fn colour_commands_are_confirmed_and_change_the_colour_state() {
    let (mut sim, c) = lights();
    let stage = complete(
        &mut sim,
        c,
        &Request::Light {
            ieee: COLOR_BULB,
            endpoint: 0,
            command: LightCommand::SetColorTemperature {
                mireds: 300,
                transition_ds: 0,
            },
        },
    );
    assert_eq!(stage, CommandStage::Confirmed);
    sim.run_for(Duration::from_secs(5));
    let color = color_of(&mut sim, c, COLOR_BULB);
    assert_eq!(color.mireds, Some(300), "{color:?}");
    assert_eq!(color.mode, Some(ColorMode::Temperature));

    take_hub_events(&mut sim, c);
    let stage = complete(
        &mut sim,
        c,
        &Request::Light {
            ieee: COLOR_BULB,
            endpoint: 0,
            command: LightCommand::SetColorXy {
                x: 0x4000,
                y: 0x3000,
                transition_ds: 0,
            },
        },
    );
    assert_eq!(stage, CommandStage::Confirmed);
    sim.run_for(Duration::from_secs(5));
    let color = color_of(&mut sim, c, COLOR_BULB);
    assert_eq!(
        (color.x, color.y),
        (Some(0x4000), Some(0x3000)),
        "{color:?}"
    );
    assert_eq!(color.mode, Some(ColorMode::Xy));
    assert!(
        hub_events(&sim, c)
            .iter()
            .any(|e| matches!(e, Event::LightColorChanged { ieee, .. } if *ieee == COLOR_BULB))
    );

    // Out-of-range values are refused before anything is sent.
    for command in [
        LightCommand::SetColorTemperature {
            mireds: 0,
            transition_ds: 0,
        },
        LightCommand::SetColorXy {
            x: 0xff00,
            y: 0,
            transition_ds: 0,
        },
        LightCommand::SetHueSaturation {
            hue: 0xff,
            saturation: 0,
            transition_ds: 0,
        },
    ] {
        assert_eq!(
            request(
                &mut sim,
                c,
                &Request::Light {
                    ieee: COLOR_BULB,
                    endpoint: 0,
                    command
                }
            ),
            Response::Error(ErrorCode::InvalidArgument)
        );
    }
}

#[test]
fn a_group_command_reaches_the_members_only() {
    let (mut sim, c) = lights();
    for ieee in [COLOR_BULB, OTHER_BULB] {
        complete(
            &mut sim,
            c,
            &Request::Light {
                ieee,
                endpoint: 0,
                command: LightCommand::TurnOff,
            },
        );
    }
    let stage = complete(
        &mut sim,
        c,
        &Request::AddGroup {
            ieee: COLOR_BULB,
            endpoint: 0,
            group: GROUP,
        },
    );
    assert_eq!(stage, CommandStage::Responded);
    // Adding it again is not an error.
    complete(
        &mut sim,
        c,
        &Request::AddGroup {
            ieee: COLOR_BULB,
            endpoint: 0,
            group: GROUP,
        },
    );

    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::GroupLight {
                group: GROUP,
                command: LightCommand::TurnOn,
            }
        ),
        Response::Done
    );
    sim.run_for(Duration::from_secs(10));
    assert_eq!(on_of(&mut sim, c, COLOR_BULB), Some(true));
    assert_eq!(on_of(&mut sim, c, OTHER_BULB), Some(false));

    // Removed, it no longer follows the group.
    complete(
        &mut sim,
        c,
        &Request::RemoveGroup {
            ieee: COLOR_BULB,
            endpoint: 0,
            group: GROUP,
        },
    );
    request(
        &mut sim,
        c,
        &Request::GroupLight {
            group: GROUP,
            command: LightCommand::TurnOff,
        },
    );
    sim.run_for(Duration::from_secs(10));
    assert_eq!(on_of(&mut sim, c, COLOR_BULB), Some(true));

    // Reserved and broadcast groups are refused.
    for group in [0, 0xfff8, 0xffff] {
        assert_eq!(
            request(
                &mut sim,
                c,
                &Request::GroupLight {
                    group,
                    command: LightCommand::TurnOn
                }
            ),
            Response::Error(ErrorCode::InvalidArgument)
        );
    }
}

#[test]
fn a_stored_scene_is_recalled_on_the_group() {
    let (mut sim, c) = lights();
    for ieee in [COLOR_BULB, OTHER_BULB] {
        complete(
            &mut sim,
            c,
            &Request::AddGroup {
                ieee,
                endpoint: 0,
                group: GROUP,
            },
        );
        complete(
            &mut sim,
            c,
            &Request::Light {
                ieee,
                endpoint: 0,
                command: LightCommand::SetBrightness {
                    percent: 40,
                    transition_ds: 0,
                },
            },
        );
        let stage = complete(
            &mut sim,
            c,
            &Request::StoreScene {
                ieee,
                endpoint: 0,
                group: GROUP,
                scene: 1,
            },
        );
        assert_eq!(stage, CommandStage::Responded);
    }
    request(
        &mut sim,
        c,
        &Request::GroupLight {
            group: GROUP,
            command: LightCommand::TurnOff,
        },
    );
    sim.run_for(Duration::from_secs(10));
    assert_eq!(on_of(&mut sim, c, COLOR_BULB), Some(false));
    assert_eq!(on_of(&mut sim, c, OTHER_BULB), Some(false));

    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RecallScene {
                group: GROUP,
                scene: 1,
                transition_ds: 0,
            }
        ),
        Response::Done
    );
    sim.run_for(Duration::from_secs(10));
    assert_eq!(on_of(&mut sim, c, COLOR_BULB), Some(true));
    assert_eq!(on_of(&mut sim, c, OTHER_BULB), Some(true));
}
