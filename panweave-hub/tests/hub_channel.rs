//! Channel energy and channel changes through the hub: an energy scan
//! reports each channel's level, the network moves to the quietest one
//! with its routers, and a driver without energy detection refuses the
//! scan instead of reporting quiet channels.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::protocol::{ErrorCode, Event, LightCommand, Request, Response};
use panweave_hub::{Hub, HubConfig};
use panweave_types::time::Duration;

#[test]
fn the_network_moves_to_the_quietest_channel_with_its_routers() {
    let (mut sim, c) = network();
    join(&mut sim, c, "bulb", bulb(), BULB);
    // Busy everywhere but channel 20.
    for ch in 11..=26 {
        sim.channel_energy[ch] = 200;
    }
    sim.channel_energy[20] = 5;
    take_hub_events(&mut sim, c);

    assert_eq!(
        request(&mut sim, c, &Request::ScanEnergy { duration: 1 }),
        Response::Done
    );
    let Event::EnergyScan { levels } =
        wait_event(&mut sim, c, 30, |e| matches!(e, Event::EnergyScan { .. }))
    else {
        unreachable!()
    };
    assert_eq!(levels.len(), 16);
    assert_eq!(levels.iter().min_by_key(|(_, e)| *e), Some(&(20, 5)));
    assert!(levels.contains(&(11, 200)));
    // One scan at a time; a scan only over 0–5.
    assert_eq!(
        request(&mut sim, c, &Request::ScanEnergy { duration: 6 }),
        Response::Error(ErrorCode::InvalidArgument)
    );

    assert_eq!(
        request(&mut sim, c, &Request::ChangeChannel { channel: 20 }),
        Response::Done
    );
    wait_event(&mut sim, c, 30, |e| {
        matches!(e, Event::ChannelChanged { channel: 20 })
    });
    let Response::NetworkStatus(s) = request(&mut sim, c, &Request::GetNetworkStatus) else {
        panic!()
    };
    assert_eq!(s.network.channel, 20);

    // The bulb followed: commands still reach it.
    sim.run_for(Duration::from_secs(10));
    take_hub_events(&mut sim, c);
    let Response::Accepted { command } = request(
        &mut sim,
        c,
        &Request::Light {
            ieee: BULB,
            endpoint: 0,
            command: LightCommand::TurnOn,
        },
    ) else {
        panic!()
    };
    wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::CommandCompleted { command: x, .. } if *x == command),
    );

    // Another change waits an hour (apsChannelTimer); invalid channels
    // are refused.
    assert_eq!(
        request(&mut sim, c, &Request::ChangeChannel { channel: 25 }),
        Response::Error(ErrorCode::Busy)
    );
    for channel in [10, 27] {
        assert_eq!(
            request(&mut sim, c, &Request::ChangeChannel { channel }),
            Response::Error(ErrorCode::InvalidArgument)
        );
    }
    // Asking for the channel in use is not a change.
    assert_eq!(
        request(&mut sim, c, &Request::ChangeChannel { channel: 20 }),
        Response::Done
    );
}

#[test]
fn a_driver_without_energy_detection_refuses_scans() {
    let (mut sim, c) = network();
    {
        let (stack, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub = Hub::new(
            HubConfig {
                firmware: "test",
                energy_detection: false,
                ..HubConfig::default()
            },
            HubStore::new(),
        );
        app.hub.attach(stack);
    }
    assert_eq!(
        request(&mut sim, c, &Request::ScanEnergy { duration: 1 }),
        Response::Error(ErrorCode::NotSupported)
    );
}
