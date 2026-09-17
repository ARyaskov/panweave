//! Smart Energy endpoint builders produce conforming Table 5-13 devices.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::large_stack_arrays)]

use panweave::endpoints::Built;
use panweave::smart_energy::cluster as c;
use panweave::smart_energy::devices::{self, Device};
use panweave::smart_energy_endpoints::{self as se, BuildError};
use panweave::types::{Endpoint, ProfileId};

fn ep() -> Endpoint {
    Endpoint(1)
}

#[test]
fn every_device_builds_and_conforms() {
    type Builder = fn(Endpoint) -> Result<Built, BuildError>;
    let builders: [Builder; 8] = [
        se::energy_service_interface,
        se::metering_device,
        se::programmable_communicating_thermostat,
        se::load_control_device,
        se::range_extender,
        se::smart_appliance,
        se::prepayment_terminal,
        se::physical_device,
    ];
    let check = |b: Result<Built, BuildError>| {
        let (desc, _ep) = b.expect("builds");
        assert_eq!(desc.profile, ProfileId::SMART_ENERGY);
        let dt = Device::lookup(desc.device).unwrap();
        assert!(
            dt.conforms(&desc.input_clusters, &desc.output_clusters),
            "{}",
            dt.name
        );
        assert!(desc.input_clusters.contains(&c::BASIC));
        assert!(desc.input_clusters.contains(&c::KEY_ESTABLISHMENT));
        assert!(desc.output_clusters.contains(&c::KEY_ESTABLISHMENT));
    };
    for b in builders {
        check(b(ep()));
    }
    check(se::in_home_display(ep(), &[c::PRICE, c::MESSAGING]));
    check(se::remote_communications_device(ep(), true, false));
    let (esi, _) = se::energy_service_interface(ep()).unwrap();
    for m in [
        c::MESSAGING,
        c::PRICE,
        c::DEMAND_RESPONSE_LOAD_CONTROL,
        c::TIME,
    ] {
        assert!(esi.input_clusters.contains(&m));
    }
}

#[test]
fn rules_are_enforced() {
    // An IHD needs at least one of its optional client clusters.
    assert_eq!(
        se::in_home_display(ep(), &[]).err(),
        Some(BuildError::NotConforming)
    );
    // A Remote Communications Device needs a Tunneling side.
    assert_eq!(
        se::remote_communications_device(ep(), false, false).err(),
        Some(BuildError::NotConforming)
    );
    // A cluster the device does not allow is refused.
    assert_eq!(
        se::device(ep(), devices::METERING_DEVICE, &[c::MESSAGING], &[]).err(),
        Some(BuildError::NotConforming)
    );
    assert_eq!(
        se::device(ep(), panweave::types::DeviceId(0x0100), &[], &[]).err(),
        Some(BuildError::UnknownDevice)
    );
    // Optional general clusters of Table 6-1 are accepted.
    let (desc, _) = se::device(
        ep(),
        devices::METERING_DEVICE,
        &[c::IDENTIFY, c::KEEP_ALIVE],
        &[],
    )
    .unwrap();
    assert!(desc.input_clusters.contains(&c::IDENTIFY));
}
