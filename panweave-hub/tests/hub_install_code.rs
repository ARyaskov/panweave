//! Install codes through the Hub Protocol: a device that knows only the
//! link key derived from its install code joins once the host has given
//! the hub that code, and not before; malformed codes are refused.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::protocol::{ErrorCode, Event, Request, Response};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig};
use panweave_security::SoftwareAes;
use panweave_security::key_hierarchy::link_key_from_install_code;
use panweave_security::material::LinkKeyKind;
use panweave_sim::{OnOffApp, SimStack};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, InstallCode, LogicalDeviceType, ProfileId,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const DEVICE: u64 = 0x00AA_0000_0000_0040;

/// An 18-octet install code with a valid CRC (BDB 3.1 example).
const CODE: [u8; 18] = [
    0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5, 0x05,
    0xC3, 0xB5,
];

/// A plug that joins with the install-code key only.
fn plug() -> SimStack {
    let key = link_key_from_install_code::<SoftwareAes>(&InstallCode::new(&CODE).unwrap());
    let mut cfg = StackConfig::new(LogicalDeviceType::Router, ExtendedAddress(DEVICE));
    cfg.preconfigured_link_key = (ExtendedAddress(HUB), key, LinkKeyKind::Unique);
    cfg.manufacturer_name = b"Sim Devices";
    cfg.model = b"ic-plug";
    let mut s = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(40),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0009),
        1,
        &[ClusterId(0), identify::ID, on_off::ID],
        &[],
    )
    .unwrap();
    s.add_endpoint(desc, ep).unwrap();
    s
}

fn add(code: &[u8]) -> Request {
    Request::AddInstallCode {
        ieee: DEVICE,
        code: heapless::Vec::from_slice(code).unwrap(),
    }
}

fn interviewed(sim: &panweave_sim::Simulator, c: usize) -> bool {
    hub_events(sim, c)
        .iter()
        .any(|e| matches!(e, Event::DeviceInterviewCompleted { ieee, .. } if *ieee == DEVICE))
}

#[test]
fn a_device_joins_with_its_install_code_once_the_hub_has_it() {
    let (mut sim, c) = network();
    let d = sim.add_stack("plug", plug(), Box::new(OnOffApp::default()));
    sim.stack(d).join(JoinMode::Association).unwrap();
    // Without the code the hub cannot give it the network key.
    assert!(!sim.run_until(Duration::from_secs(60), |x| interviewed(x, c)));
    assert!(matches!(
        request(&mut sim, c, &Request::GetDevice { ieee: DEVICE }),
        Response::Error(ErrorCode::UnknownDevice)
    ));

    assert_eq!(request(&mut sim, c, &add(&CODE)), Response::Done);
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(
        sim.run_until(Duration::from_secs(120), |x| interviewed(x, c)),
        "{:?}",
        hub_events(&sim, c)
    );
}

#[test]
fn malformed_install_codes_are_refused() {
    let (mut sim, c) = network();
    let mut bad_crc = CODE;
    bad_crc[17] ^= 1;
    for code in [&bad_crc[..], &CODE[..7], &CODE[..11]] {
        assert_eq!(
            request(&mut sim, c, &add(code)),
            Response::Error(ErrorCode::InvalidArgument)
        );
    }
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::AddInstallCode {
                ieee: 0,
                code: heapless::Vec::from_slice(&CODE).unwrap(),
            }
        ),
        Response::Error(ErrorCode::InvalidArgument)
    );
}
