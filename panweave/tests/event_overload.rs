//! A slow observer must not leave commissioning or BLE authorization
//! running after it loses a bounded stream of control transitions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use panweave::runtime::{AdoptParams, StackEvent};
use panweave::security::cipher::SoftwareAes;
use panweave::storage::MemoryStorage;
use panweave::testkit::TestRng;
use panweave::types::{
    Channel, DeviceId, Endpoint, ExtendedAddress, Instant, Key128, KeySequenceNumber, PanId,
    ProfileId,
};
use panweave::zcl::clusters::identify;
use panweave::zcl::layer::EndpointInstance;
use panweave::zdo::SimpleDescriptor;
use panweave::{Coordinator, Event};

const IEEE: ExtendedAddress = ExtendedAddress(0x00E1_0000_0000_0001);
#[cfg(feature = "direct")]
const PEER: ExtendedAddress = ExtendedAddress(0x00E1_0000_0000_0002);

#[test]
fn observer_control_overflow_reconciles_bdb_and_invalidates_direct_context() {
    let mut node = Coordinator::new(IEEE)
        .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::<64, 512>::new());
    let mut endpoint = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    endpoint.add_instance(identify::server().unwrap()).unwrap();
    node.add_endpoint(
        SimpleDescriptor::new(
            Endpoint(1),
            ProfileId::HOME_AUTOMATION,
            DeviceId(0x0100),
            1,
            &[identify::ID],
            &[],
        )
        .unwrap(),
        endpoint,
    )
    .unwrap();
    node.stack
        .adopt_network(&AdoptParams {
            extended_pan_id: IEEE,
            pan_id: PanId(0x4321),
            channel: Channel::DEFAULT_2_4GHZ,
            network_address: None,
            key: Key128::from_bytes([0x65; 16]),
            key_sequence: KeySequenceNumber(0),
            update_id: 0,
            trust_center: IEEE,
        })
        .unwrap();
    node.bdb.set_on_network(true);
    #[cfg(feature = "direct")]
    {
        node.direct_power_up();
        node.direct_session_opened(PEER, panweave_direct::auth::Level::Admin);
        assert_eq!(
            node.direct.security.session_level(PEER),
            Some(panweave_direct::auth::Level::Admin)
        );
        assert!(node.open_tunnel(1, 7, PEER));
        assert!(node.direct.security.advertising());
    }
    while node.next_event().is_some() {}
    assert!(node.bdb.is_on_network());

    // poll drains the runtime into the facade after each real Identify
    // transition, so this saturates only the external observer queue.
    for seconds in 1..=17 {
        node.stack
            .zcl
            .set_identify_time(Endpoint(1), seconds)
            .unwrap();
        node.poll(Instant::from_millis(0));
    }
    assert!(node.recovery_needed());
    assert!(!node.stack.is_operating());
    assert!(!node.bdb.is_on_network());
    assert!(!node.bdb.is_busy());
    assert!(
        matches!(node.next_event(), Some(Event::Stack(StackEvent::EventQueueLoss { control, .. })) if control >= 17)
    );
    assert!(node.next_event().is_none());
    assert!(node.next_radio_action().is_none());
    node.poll(Instant::from_millis(60_000));
    assert!(node.next_deadline().is_none());
    assert!(node.recovery_needed());

    #[cfg(feature = "direct")]
    {
        assert!(!node.direct.security.advertising());
        assert_eq!(node.direct.security.session_level(PEER), None);
        assert_eq!(node.direct.tunnels.len(), 0);
        assert!(!node.direct_interface_enabled());
        assert_eq!(
            node.direct_admit(PEER, panweave_direct::tlv::Psk::AdminAuthorization),
            Err(panweave_direct::state::Refusal::InterfaceOff)
        );
        node.direct_power_up();
        assert!(!node.direct.security.advertising());
        assert!(!node.open_tunnel(1, 7, PEER));
    }
}
