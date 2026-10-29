//! Green Power messages (0.4): the hub as Green Power Combo Basic sink
//! (feature `green-power`). Green Power Devices — battery-less switches
//! such as the Hue Tap — are not Zigbee devices: they have no network
//! address or IEEE address of their own (a 32-bit SrcId, or an IEEE
//! address and endpoint), and are kept in the stack's Sink Table, not in
//! the hub's registry.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};

use super::ProtocolError;

/// GPD command payload octets carried in [`super::Event::GreenPowerCommand`].
pub const MAX_GPD_PAYLOAD: usize = 16;

/// Paired GPDs per [`super::Response::GreenPowerDevices`] page.
pub const GPD_PAGE: usize = 8;

/// A Green Power Device's identity (GP Basic §A.1.4.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GpdAddress {
    /// ApplicationID 0b000: a 32-bit source identifier.
    SrcId(u32),
    /// ApplicationID 0b010: an IEEE address and endpoint.
    Ieee {
        /// IEEE address.
        ieee: u64,
        /// Endpoint.
        endpoint: u8,
    },
}

/// A paired GPD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GpdInfo {
    /// Its identity.
    pub gpd: GpdAddress,
    /// Its GPD DeviceID (GP Basic Table 51: 0x02 on/off switch, …).
    pub device_id: u8,
}

/// A page of paired GPDs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GpdList {
    /// GPDs paired.
    pub total: u8,
    /// Index of the first entry of this page.
    pub start: u8,
    /// The entries.
    pub devices: Vec<GpdInfo, GPD_PAGE>,
}

pub(crate) fn write_gpd(w: &mut Writer<'_>, g: &GpdAddress) -> Result<(), CodecError> {
    match g {
        GpdAddress::SrcId(id) => {
            w.u8(0)?;
            w.u32_le(*id)
        }
        GpdAddress::Ieee { ieee, endpoint } => {
            w.u8(2)?;
            w.u64_le(*ieee)?;
            w.u8(*endpoint)
        }
    }
}

pub(crate) fn read_gpd(r: &mut Reader<'_>) -> Result<GpdAddress, ProtocolError> {
    match r.u8()? {
        0 => Ok(GpdAddress::SrcId(r.u32_le()?)),
        2 => Ok(GpdAddress::Ieee {
            ieee: r.u64_le()?,
            endpoint: r.u8()?,
        }),
        _ => Err(ProtocolError::Malformed),
    }
}

pub(crate) fn write_list(w: &mut Writer<'_>, l: &GpdList) -> Result<(), CodecError> {
    w.u8(l.total)?;
    w.u8(l.start)?;
    w.u8(u8::try_from(l.devices.len()).unwrap_or(0))?;
    for d in &l.devices {
        write_gpd(w, &d.gpd)?;
        w.u8(d.device_id)?;
    }
    Ok(())
}

pub(crate) fn read_list(r: &mut Reader<'_>) -> Result<GpdList, ProtocolError> {
    let total = r.u8()?;
    let start = r.u8()?;
    let n = r.u8()?;
    let mut devices = Vec::new();
    for _ in 0..n {
        let d = GpdInfo {
            gpd: read_gpd(r)?,
            device_id: r.u8()?,
        };
        devices.push(d).map_err(|_| ProtocolError::TooLarge)?;
    }
    Ok(GpdList {
        total,
        start,
        devices,
    })
}

pub(crate) fn write_payload(w: &mut Writer<'_>, p: &[u8]) -> Result<(), CodecError> {
    let n = p.len().min(MAX_GPD_PAYLOAD);
    w.u8(u8::try_from(n).unwrap_or(0))?;
    w.bytes(p.get(..n).unwrap_or_default())
}

pub(crate) fn read_payload(r: &mut Reader<'_>) -> Result<Vec<u8, MAX_GPD_PAYLOAD>, ProtocolError> {
    let n = usize::from(r.u8()?);
    Vec::from_slice(r.bytes(n)?).map_err(|_| ProtocolError::TooLarge)
}

/// A short name of a GPD command (GP Basic Table 49), for displays and
/// automations; `None` for commands without a common meaning.
pub const fn command_name(command: u8) -> Option<&'static str> {
    Some(match command {
        0x00 => "identify",
        0x10 => "recall_scene_0",
        0x11 => "recall_scene_1",
        0x12 => "recall_scene_2",
        0x13 => "recall_scene_3",
        0x14 => "recall_scene_4",
        0x15 => "recall_scene_5",
        0x16 => "recall_scene_6",
        0x17 => "recall_scene_7",
        0x18 => "store_scene_0",
        0x19 => "store_scene_1",
        0x1a => "store_scene_2",
        0x1b => "store_scene_3",
        0x1c => "store_scene_4",
        0x1d => "store_scene_5",
        0x1e => "store_scene_6",
        0x1f => "store_scene_7",
        0x20 => "off",
        0x21 => "on",
        0x22 => "toggle",
        0x23 => "release",
        0x30 => "move_up",
        0x31 => "move_down",
        0x32 => "step_up",
        0x33 => "step_down",
        0x34 => "level_control_stop",
        0x35 => "move_up_with_on_off",
        0x36 => "move_down_with_on_off",
        0x37 => "step_up_with_on_off",
        0x38 => "step_down_with_on_off",
        0x60 => "press_1_of_1",
        0x61 => "release_1_of_1",
        0x62 => "press_1_of_2",
        0x63 => "release_1_of_2",
        0x64 => "press_2_of_2",
        0x65 => "release_2_of_2",
        0x66 => "short_press_1_of_1",
        0x67 => "short_press_1_of_2",
        0x68 => "short_press_2_of_2",
        0x69 => "press_8bit_vector",
        0x6a => "release_8bit_vector",
        _ => return None,
    })
}

/// Every name [`command_name`] gives, in command order.
pub const COMMAND_NAMES: [&str; 41] = [
    "identify",
    "recall_scene_0",
    "recall_scene_1",
    "recall_scene_2",
    "recall_scene_3",
    "recall_scene_4",
    "recall_scene_5",
    "recall_scene_6",
    "recall_scene_7",
    "store_scene_0",
    "store_scene_1",
    "store_scene_2",
    "store_scene_3",
    "store_scene_4",
    "store_scene_5",
    "store_scene_6",
    "store_scene_7",
    "off",
    "on",
    "toggle",
    "release",
    "move_up",
    "move_down",
    "step_up",
    "step_down",
    "level_control_stop",
    "move_up_with_on_off",
    "move_down_with_on_off",
    "step_up_with_on_off",
    "step_down_with_on_off",
    "press_1_of_1",
    "release_1_of_1",
    "press_1_of_2",
    "release_1_of_2",
    "press_2_of_2",
    "release_2_of_2",
    "short_press_1_of_1",
    "short_press_1_of_2",
    "short_press_2_of_2",
    "press_8bit_vector",
    "release_8bit_vector",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_command_is_listed_once() {
        let named: std::vec::Vec<&str> = (0..=255u8).filter_map(command_name).collect();
        assert_eq!(named.as_slice(), COMMAND_NAMES.as_slice());
    }
}
