//! Generic translation of GPD commands to ZCL commands (GP Basic 1.1.2
//! Tables 54 / 55, §A.4.2.4, §A.4.2.5): the mapping a sink without a
//! Translation Table applies to the commands of a paired GPD before
//! executing them on its own endpoints.

use heapless::Vec;
use panweave_types::{ClusterId, CommandId};

use crate::command;

/// Identify cluster.
pub const IDENTIFY_CLUSTER: ClusterId = ClusterId(0x0003);
/// Scenes cluster.
pub const SCENES_CLUSTER: ClusterId = ClusterId(0x0005);
/// On/Off cluster.
pub const ON_OFF_CLUSTER: ClusterId = ClusterId(0x0006);
/// Level Control cluster.
pub const LEVEL_CLUSTER: ClusterId = ClusterId(0x0008);
/// Door Lock cluster.
pub const DOOR_LOCK_CLUSTER: ClusterId = ClusterId(0x0101);
/// Color Control cluster.
pub const COLOR_CLUSTER: ClusterId = ClusterId(0x0300);

/// Identify time of the translated Identify command (0x003c s).
pub const IDENTIFY_TIME: u16 = 0x003c;

/// A ZCL command a GPD command translates to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Translated<'a> {
    /// A cluster-specific command for the paired endpoints.
    Command {
        /// Cluster.
        cluster: ClusterId,
        /// Command.
        command: CommandId,
        /// Payload.
        payload: Vec<u8, 8>,
    },
    /// A Report Attributes (global command 0x0a) for `cluster` with the
    /// attribute records copied from the GPD command.
    Report {
        /// Cluster.
        cluster: ClusterId,
        /// Manufacturer code of a manufacturer-specific report.
        manufacturer: Option<u16>,
        /// Attribute records in ZCL form.
        records: &'a [u8],
    },
}

/// Translates a GPD command (`group` is the pairing's group for the scene
/// commands); `None` for commands without a generic ZCL equivalent
/// (press / release, multi-cluster reporting, manufacturer-defined).
pub fn translate(command_id: u8, payload: &[u8], group: u16) -> Option<Translated<'_>> {
    let cmd = |cluster: ClusterId, command: u8, bytes: &[u8]| -> Option<Translated<'static>> {
        let mut p: Vec<u8, 8> = Vec::new();
        p.extend_from_slice(bytes).ok()?;
        Some(Translated::Command {
            cluster,
            command: CommandId(command),
            payload: p,
        })
    };
    let rate = payload.first().copied().unwrap_or(0xff);
    let step = payload.first().copied().unwrap_or(0);
    let transition = match payload.get(1..3) {
        Some([lo, hi]) => u16::from_le_bytes([*lo, *hi]),
        _ => 0xffff,
    };
    let g = group.to_le_bytes();
    match command_id {
        command::IDENTIFY => cmd(IDENTIFY_CLUSTER, 0x00, &IDENTIFY_TIME.to_le_bytes()),
        0x10..=0x16 => cmd(SCENES_CLUSTER, 0x05, &[g[0], g[1], command_id - 0x10]),
        0x17..=0x1e => cmd(SCENES_CLUSTER, 0x04, &[g[0], g[1], command_id - 0x17]),
        command::OFF => cmd(ON_OFF_CLUSTER, 0x00, &[]),
        command::ON => cmd(ON_OFF_CLUSTER, 0x01, &[]),
        command::TOGGLE => cmd(ON_OFF_CLUSTER, 0x02, &[]),
        command::MOVE_UP => cmd(LEVEL_CLUSTER, 0x01, &[0x00, rate]),
        command::MOVE_DOWN => cmd(LEVEL_CLUSTER, 0x01, &[0x01, rate]),
        command::STEP_UP => level_step(0x02, 0x00, step, transition),
        command::STEP_DOWN => level_step(0x02, 0x01, step, transition),
        command::LEVEL_STOP => cmd(LEVEL_CLUSTER, 0x03, &[]),
        command::MOVE_UP_WITH_ON_OFF => cmd(LEVEL_CLUSTER, 0x05, &[0x00, rate]),
        command::MOVE_DOWN_WITH_ON_OFF => cmd(LEVEL_CLUSTER, 0x05, &[0x01, rate]),
        command::STEP_UP_WITH_ON_OFF => level_step(0x06, 0x00, step, transition),
        command::STEP_DOWN_WITH_ON_OFF => level_step(0x06, 0x01, step, transition),
        // Colour: Move Hue (0x01) / Step Hue (0x02) / Move Saturation
        // (0x04) / Step Saturation (0x05) with the ZCL mode octet; step
        // transition times are one octet in the ZCL hue / saturation
        // steps (tenths of a second, saturated).
        0x40 => cmd(COLOR_CLUSTER, 0x01, &[0x00, 0x00]),
        0x41 => cmd(COLOR_CLUSTER, 0x01, &[0x01, rate]),
        0x42 => cmd(COLOR_CLUSTER, 0x01, &[0x03, rate]),
        0x43 => cmd(
            COLOR_CLUSTER,
            0x02,
            &[0x01, step, short_transition(transition)],
        ),
        0x44 => cmd(
            COLOR_CLUSTER,
            0x02,
            &[0x03, step, short_transition(transition)],
        ),
        0x45 => cmd(COLOR_CLUSTER, 0x04, &[0x00, 0x00]),
        0x46 => cmd(COLOR_CLUSTER, 0x04, &[0x01, rate]),
        0x47 => cmd(COLOR_CLUSTER, 0x04, &[0x03, rate]),
        0x48 => cmd(
            COLOR_CLUSTER,
            0x05,
            &[0x01, step, short_transition(transition)],
        ),
        0x49 => cmd(
            COLOR_CLUSTER,
            0x05,
            &[0x03, step, short_transition(transition)],
        ),
        // Move Color / Step Color: payloads copied (Step Color gains the
        // default transition time when absent).
        0x4a => cmd(COLOR_CLUSTER, 0x08, payload.get(..4)?),
        0x4b => {
            let xy = payload.get(..4)?;
            let t = match payload.get(4..6) {
                Some([lo, hi]) => [*lo, *hi],
                _ => [0xff, 0xff],
            };
            cmd(
                COLOR_CLUSTER,
                0x09,
                &[xy[0], xy[1], xy[2], xy[3], t[0], t[1]],
            )
        }
        0x50 => cmd(DOOR_LOCK_CLUSTER, 0x00, &[]),
        0x51 => cmd(DOOR_LOCK_CLUSTER, 0x01, &[]),
        command::ATTRIBUTE_REPORTING => {
            let cluster = ClusterId(u16::from_le_bytes([*payload.first()?, *payload.get(1)?]));
            Some(Translated::Report {
                cluster,
                manufacturer: None,
                records: payload.get(2..)?,
            })
        }
        command::MANUFACTURER_ATTRIBUTE_REPORTING => {
            let manufacturer = u16::from_le_bytes([*payload.first()?, *payload.get(1)?]);
            let cluster = ClusterId(u16::from_le_bytes([*payload.get(2)?, *payload.get(3)?]));
            Some(Translated::Report {
                cluster,
                manufacturer: Some(manufacturer),
                records: payload.get(4..)?,
            })
        }
        _ => None,
    }
}

fn level_step(command: u8, mode: u8, step: u8, transition: u16) -> Option<Translated<'static>> {
    let t = transition.to_le_bytes();
    let mut p: Vec<u8, 8> = Vec::new();
    p.extend_from_slice(&[mode, step, t[0], t[1]]).ok()?;
    Some(Translated::Command {
        cluster: LEVEL_CLUSTER,
        command: CommandId(command),
        payload: p,
    })
}

fn short_transition(transition: u16) -> u8 {
    u8::try_from(transition).unwrap_or(0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(t: Option<Translated<'_>>) -> (ClusterId, CommandId, Vec<u8, 8>) {
        match t {
            Some(Translated::Command {
                cluster,
                command,
                payload,
            }) => (cluster, command, payload),
            other => panic!("not a command: {other:?}"),
        }
    }

    #[test]
    fn generic_translation_table() {
        let (c, cmd, p) = command(translate(command::TOGGLE, &[], 0));
        assert_eq!((c, cmd), (ON_OFF_CLUSTER, CommandId(0x02)));
        assert!(p.is_empty());
        let (c, cmd, p) = command(translate(command::IDENTIFY, &[], 0));
        assert_eq!(
            (c, cmd, p.as_slice()),
            (IDENTIFY_CLUSTER, CommandId(0x00), &[0x3c, 0x00][..])
        );
        let (c, cmd, p) = command(translate(command::RECALL_SCENE_0 + 3, &[], 0x1234));
        assert_eq!(
            (c, cmd, p.as_slice()),
            (SCENES_CLUSTER, CommandId(0x05), &[0x34, 0x12, 3][..])
        );
        let (_, cmd, p) = command(translate(command::STORE_SCENE_0 + 7, &[], 1));
        assert_eq!((cmd, p.as_slice()), (CommandId(0x04), &[1, 0, 7][..]));
        // Level: Move Down without a rate → 0xff; Step Up with On/Off
        // keeps the transition time; a missing one is 0xffff.
        let (c, cmd, p) = command(translate(command::MOVE_DOWN, &[], 0));
        assert_eq!(
            (c, cmd, p.as_slice()),
            (LEVEL_CLUSTER, CommandId(0x01), &[0x01, 0xff][..])
        );
        let (_, cmd, p) = command(translate(
            command::STEP_UP_WITH_ON_OFF,
            &[10, 0x32, 0x00],
            0,
        ));
        assert_eq!(
            (cmd, p.as_slice()),
            (CommandId(0x06), &[0x00, 10, 0x32, 0x00][..])
        );
        let (_, cmd, p) = command(translate(command::STEP_DOWN, &[5], 0));
        assert_eq!(
            (cmd, p.as_slice()),
            (CommandId(0x02), &[0x01, 5, 0xff, 0xff][..])
        );
        assert_eq!(
            command(translate(command::LEVEL_STOP, &[], 0)).1,
            CommandId(0x03)
        );
        // Colour.
        let (c, cmd, p) = command(translate(0x42, &[7], 0));
        assert_eq!(
            (c, cmd, p.as_slice()),
            (COLOR_CLUSTER, CommandId(0x01), &[0x03, 7][..])
        );
        let (_, cmd, p) = command(translate(0x48, &[4, 0x00, 0x01], 0));
        assert_eq!((cmd, p.as_slice()), (CommandId(0x05), &[0x01, 4, 0xff][..]));
        let (_, cmd, p) = command(translate(0x4b, &[1, 0, 2, 0], 0));
        assert_eq!(
            (cmd, p.as_slice()),
            (CommandId(0x09), &[1, 0, 2, 0, 0xff, 0xff][..])
        );
        assert!(translate(0x4a, &[1, 0], 0).is_none());
        assert_eq!(command(translate(0x51, &[], 0)).0, DOOR_LOCK_CLUSTER);
        // Reporting keeps the records.
        match translate(
            command::ATTRIBUTE_REPORTING,
            &[0x02, 0x04, 0x00, 0x00, 0x29, 0x10, 0x09],
            0,
        ) {
            Some(Translated::Report {
                cluster,
                manufacturer,
                records,
            }) => {
                assert_eq!(cluster, ClusterId(0x0402));
                assert_eq!(manufacturer, None);
                assert_eq!(records, &[0x00, 0x00, 0x29, 0x10, 0x09]);
            }
            other => panic!("{other:?}"),
        }
        assert!(translate(command::PRESS_1_OF_1, &[], 0).is_none());
        assert!(translate(command::RELEASE, &[], 0).is_none());
    }
}
