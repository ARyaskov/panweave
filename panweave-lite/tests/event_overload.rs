//! Loss at the observer boundary stops the same input call before the
//! zone reporter can schedule another notification.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use panweave_aps::layer::{DataIndication, Delivery as ApsDelivery, SecurityStatus};
use panweave_lite::sensor::Inputs;
use panweave_lite::{LiteConfig, LiteDevice, LiteEvent, SENSOR_ENDPOINT, SensorKind};
use panweave_security::cipher::SoftwareAes;
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::{Endpoint, ExtendedAddress, Instant, ProfileId, ShortAddress};
use panweave_zcl::Role;
use panweave_zcl::clusters::ias_zone;

#[test]
fn enrollment_observer_overflow_does_not_advance_reporter_after_halt() {
    let config = LiteConfig::new(ExtendedAddress(0x00E2_0000_0000_0001), SensorKind::Contact);
    let mut device = LiteDevice::<SoftwareAes, _, _>::new(
        &config,
        TestRng::seed(1),
        MemoryStorage::<32, 512>::new(),
    )
    .unwrap();
    let inputs = Inputs {
        alarm: true,
        ..Inputs::default()
    };
    device.initialize(inputs).unwrap();
    while device.next_event().is_some() {}

    // Queue four actual Identify transitions without draining the Lite
    // observer. The runtime is drained by LiteDevice::poll each time.
    for seconds in 1..=4 {
        device
            .stack
            .zcl
            .set_identify_time(SENSOR_ENDPOINT, seconds)
            .unwrap();
        device.poll(Instant::from_millis(0));
    }
    assert!(!device.recovery_needed());
    let before = *device.reporter();
    let cie = ExtendedAddress(0x00E2_0000_0000_0002);
    ias_zone::restore_enrollment(
        device
            .stack
            .zcl
            .cluster_mut(SENSOR_ENDPOINT, ias_zone::ID, Role::Server)
            .unwrap(),
        &ias_zone::Enrollment {
            cie_address: cie,
            cie: (ShortAddress(0), Endpoint(1)),
            zone_id: None,
        },
    );
    // An authorized IAS Enroll Response is executed by the public ZCL
    // dispatcher and produces the fifth control notification.
    let frame = [0x01, 0x42, 0x00, 0x00, 7];
    let indication = DataIndication {
        src: ShortAddress(0),
        src_ieee: Some(cie),
        src_endpoint: Endpoint(1),
        delivery: ApsDelivery::Endpoint(SENSOR_ENDPOINT),
        profile: ProfileId::HOME_AUTOMATION,
        cluster: ias_zone::ID,
        asdu: &frame,
        security: SecurityStatus::NwkKey,
        lqi: 200,
        relayed: None,
        counter: 1,
        nwk_broadcast: false,
    };
    assert!(
        device
            .stack
            .zcl
            .on_data(&indication, &mut device.stack.aps.groups)
            .is_none()
    );
    // Match the normal radio-input path: the runtime pumps a received
    // command before the next timer poll. Otherwise a timer-generated
    // ZoneDelivery may legitimately precede the enrollment notification.
    device.stack.flush();
    device.poll(Instant::from_millis(0));

    assert!(device.recovery_needed());
    assert!(!device.bdb.is_on_network());
    assert!(!device.bdb.is_busy());
    assert_eq!(
        *device.reporter(),
        before,
        "the overflow must precede on_reachable"
    );
    assert!(
        matches!(device.next_event(), Some(LiteEvent::EventQueueLoss { control, .. }) if control >= 5)
    );
    assert!(device.next_radio_action().is_none());
    device.set_inputs(Inputs::default());
    device.poll(Instant::from_millis(60_000));
    assert_eq!(device.inputs(), inputs);
    assert_eq!(*device.reporter(), before);
    assert!(device.next_deadline().is_none());
    assert!(
        device.recovery_needed(),
        "draining the gap must not resume the sensor"
    );
}
