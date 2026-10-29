//! The hub as Green Power sink (feature `green-power`): the host opens
//! the commissioning window, a GPD switch commissions over the air, its
//! commands are reported once, and a removed pairing reports nothing.

#![cfg(feature = "green-power")]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_codec::{Encode, Writer};
use panweave_green_power::command;
use panweave_green_power::commissioning::{Commissioning, KeyField, SecurityCapabilities};
use panweave_green_power::gpdf::{
    ApplicationId, ExtendedFrameControl, FrameType, GpdId, NwkFrameControl, SecurityLevel,
    mac_header, write_header,
};
use panweave_green_power::security::{self, Direction, KeyType};
use panweave_hub::protocol::{ErrorCode, Event, GpdAddress, GpdInfo, Request, Response};
use panweave_mac::frame::{Frame as MacFrame, MacAddress};
use panweave_security::cipher::SoftwareAes;
use panweave_types::time::Duration;
use panweave_types::{Key128, ShortAddress};

const SRC_ID: u32 = 0x8765_4321;
const GPD: GpdId = GpdId::SrcId(SRC_ID);
const OOB_KEY: Key128 = Key128::from_bytes([
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
]);

/// A GPDF from the GPD as a raw MAC frame.
fn gpdf(
    seq: u8,
    level: SecurityLevel,
    counter: Option<u32>,
    app: &[u8],
    key: Option<&Key128>,
) -> Vec<u8> {
    let e = ExtendedFrameControl {
        application_id: ApplicationId::SrcId,
        security_level: level,
        individual_key: key.is_some(),
        rx_after_tx: false,
        from_proxy: false,
    };
    let fc = NwkFrameControl {
        frame_type: FrameType::Data,
        auto_commissioning: false,
        extension: true,
    };
    let mut hdr = [0u8; 16];
    let mut w = Writer::new(&mut hdr);
    write_header(&mut w, fc, Some(e), Some(&GPD), counter).unwrap();
    let hl = w.position();
    let mut payload = app.to_vec();
    let mic = key.map(|k| {
        security::protect::<SoftwareAes>(
            k,
            level,
            &GPD,
            counter.unwrap(),
            Direction::FromGpd,
            &hdr[..hl],
            &mut payload,
        )
        .unwrap()
    });
    let mut body = hdr[..hl].to_vec();
    body.extend(&payload);
    if let Some(m) = mic {
        body.extend(&m);
    }
    let mut buf = [0u8; 96];
    let n = MacFrame {
        header: mac_header(
            seq,
            MacAddress::Short(ShortAddress(0xffff)),
            MacAddress::None,
        ),
        payload: &body,
    }
    .encode_to_slice(&mut buf)
    .unwrap();
    buf[..n].to_vec()
}

/// Commissioning of an on/off switch with its own key, protected under
/// the default gpLinkKey.
fn commissioning_gpdf(seq: u8) -> Vec<u8> {
    let (protected, mic) = security::protect_gpd_key::<SoftwareAes>(
        &Key128::WELL_KNOWN_GLOBAL_TCLK,
        &GPD,
        Direction::FromGpd,
        0,
        &OOB_KEY,
    )
    .unwrap();
    let c = Commissioning {
        device_id: 0x02,
        sequence_number_capable: true,
        rx_on_capable: false,
        pan_id_request: false,
        key_request: false,
        fixed_location: false,
        security: Some(SecurityCapabilities {
            level: 0b10,
            key_type: KeyType::Individual,
            key_encryption: true,
        }),
        key: Some(KeyField {
            bytes: protected,
            mic: Some(mic),
        }),
        outgoing_counter: Some(0x10),
        application: None,
    };
    let mut body = vec![command::COMMISSIONING];
    let mut buf = [0u8; 64];
    let n = c.encode_to_slice(&mut buf).unwrap();
    body.extend(&buf[..n]);
    gpdf(seq, SecurityLevel::None, None, &body, None)
}

fn toggle(seq: u8, counter: u32) -> Vec<u8> {
    gpdf(
        seq,
        SecurityLevel::Mic,
        Some(counter),
        &[command::TOGGLE],
        Some(&OOB_KEY),
    )
}

fn commands(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| {
            matches!(e, Event::GreenPowerCommand { gpd, command, .. }
                if *gpd == GpdAddress::SrcId(SRC_ID) && *command == command::TOGGLE)
        })
        .count()
}

#[test]
fn a_gpd_switch_is_paired_and_its_presses_reported() {
    let (mut sim, c) = network();
    take_hub_events(&mut sim, c);
    // Outside the window a commissioning GPDF pairs nothing.
    sim.inject(&commissioning_gpdf(1));
    sim.run_for(Duration::from_secs(3));
    assert!(
        !take_hub_events(&mut sim, c)
            .iter()
            .any(|e| matches!(e, Event::GreenPowerPaired { .. }))
    );

    assert_eq!(
        request(&mut sim, c, &Request::GreenPowerCommission { seconds: 60 }),
        Response::Done
    );
    // The sink's mode change reaches the hub as a stack event.
    sim.run_for(Duration::from_millis(100));
    assert!(
        take_hub_events(&mut sim, c)
            .iter()
            .any(|e| matches!(e, Event::GreenPowerCommissioning { seconds } if *seconds > 50))
    );
    sim.inject(&commissioning_gpdf(2));
    let paired = wait_event(&mut sim, c, 10, |e| {
        matches!(e, Event::GreenPowerPaired { .. })
    });
    assert_eq!(
        paired,
        Event::GreenPowerPaired {
            gpd: GpdAddress::SrcId(SRC_ID),
            device_id: 0x02
        }
    );
    assert_eq!(
        request(&mut sim, c, &Request::ListGreenPowerDevices { start: 0 }),
        Response::GreenPowerDevices(panweave_hub::protocol::GpdList {
            total: 1,
            start: 0,
            devices: heapless::Vec::from_slice(&[GpdInfo {
                gpd: GpdAddress::SrcId(SRC_ID),
                device_id: 0x02
            }])
            .unwrap(),
        })
    );

    // A press is reported once; a replayed frame is not.
    take_hub_events(&mut sim, c);
    sim.inject(&toggle(3, 0x11));
    sim.run_for(Duration::from_secs(3));
    sim.inject(&toggle(3, 0x11));
    sim.run_for(Duration::from_secs(3));
    assert_eq!(commands(&take_hub_events(&mut sim, c)), 1);

    // Removed, it is no longer heard.
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RemoveGreenPowerDevice {
                gpd: GpdAddress::SrcId(SRC_ID)
            }
        ),
        Response::Done
    );
    assert!(
        take_hub_events(&mut sim, c).contains(&Event::GreenPowerRemoved {
            gpd: GpdAddress::SrcId(SRC_ID)
        })
    );
    sim.inject(&toggle(4, 0x12));
    sim.run_for(Duration::from_secs(3));
    assert_eq!(commands(&take_hub_events(&mut sim, c)), 0);
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::RemoveGreenPowerDevice {
                gpd: GpdAddress::SrcId(SRC_ID)
            }
        ),
        Response::Error(ErrorCode::UnknownDevice)
    );
}

#[test]
fn the_commissioning_window_closes_on_request() {
    let (mut sim, c) = network();
    request(&mut sim, c, &Request::GreenPowerCommission { seconds: 60 });
    take_hub_events(&mut sim, c);
    assert_eq!(
        request(&mut sim, c, &Request::GreenPowerCommission { seconds: 0 }),
        Response::Done
    );
    sim.run_for(Duration::from_millis(100));
    assert!(take_hub_events(&mut sim, c).contains(&Event::GreenPowerCommissioning { seconds: 0 }));
    sim.inject(&commissioning_gpdf(5));
    sim.run_for(Duration::from_secs(3));
    assert!(
        !take_hub_events(&mut sim, c)
            .iter()
            .any(|e| matches!(e, Event::GreenPowerPaired { .. }))
    );
}
