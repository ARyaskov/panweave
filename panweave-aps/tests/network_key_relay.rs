//! A sleepy child accepts a network-key update only from its authenticated
//! parent, with NWK security and the Trust Center named in the descriptor.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use panweave_aps::TransportedKey;
use panweave_aps::layer::{Aps, ApsAction, ApsConfig, ApsEvent, DeviceState, NwkView};
use panweave_security::cipher::SoftwareAes;
use panweave_types::{ExtendedAddress, Key128, KeySequenceNumber, ShortAddress};

const TC: ExtendedAddress = ExtendedAddress(1);
const PARENT: ExtendedAddress = ExtendedAddress(2);
const CHILD: ExtendedAddress = ExtendedAddress(3);
const OTHER: ExtendedAddress = ExtendedAddress(4);
const PARENT_SHORT: ShortAddress = ShortAddress(0x1234);
const CHILD_SHORT: ShortAddress = ShortAddress(0x5678);
const KEY: Key128 = Key128::from_bytes([0x6D; 16]);
const SEQUENCE: KeySequenceNumber = KeySequenceNumber(7);

struct View(Option<(ShortAddress, ExtendedAddress)>);

impl NwkView for View {
    fn ieee_of(&self, short: ShortAddress) -> Option<ExtendedAddress> {
        self.0
            .filter(|(address, _)| *address == short)
            .map(|(_, ieee)| ieee)
    }

    fn short_of(&self, ieee: ExtendedAddress) -> Option<ShortAddress> {
        self.0
            .filter(|(_, address)| *address == ieee)
            .map(|(short, _)| short)
    }

    fn unauthenticated_child(&self, _: ExtendedAddress) -> Option<ShortAddress> {
        None
    }

    fn authenticated_parent(&self) -> Option<(ShortAddress, ExtendedAddress)> {
        self.0
    }
}

fn receive_relay(
    parent: Option<(ShortAddress, ExtendedAddress)>,
    sender: (ShortAddress, ExtendedAddress),
    secured: bool,
    key_source: ExtendedAddress,
    destination: ExtendedAddress,
) -> Aps<SoftwareAes> {
    let mut router = Aps::<SoftwareAes>::new(PARENT, ApsConfig::default());
    router.set_network_state(PARENT_SHORT, DeviceState::JoinedAuthorized);
    router
        .relay_network_key_to_child(destination, CHILD_SHORT, &KEY, SEQUENCE, key_source)
        .unwrap();
    let mut frame = loop {
        let action = router
            .next_action()
            .expect("relay must produce a transmission");
        if let ApsAction::NwkData { frame, .. } = action {
            break frame;
        }
    };
    let mut child = Aps::<SoftwareAes>::new(CHILD, ApsConfig::default());
    child.aib.trust_center_address = TC;
    child.set_network_state(CHILD_SHORT, DeviceState::JoinedAuthorized);
    assert!(
        child
            .on_nwk_data(
                &mut frame,
                sender.0,
                CHILD_SHORT,
                Some(sender.1),
                secured,
                200,
                &View(parent),
            )
            .is_none()
    );
    child
}

#[test]
fn authenticated_parent_forwards_the_trust_centers_network_key() {
    let mut child = receive_relay(
        Some((PARENT_SHORT, PARENT)),
        (PARENT_SHORT, PARENT),
        true,
        TC,
        CHILD,
    );
    assert!(matches!(
        child.next_event(),
        Some(ApsEvent::TransportKey {
            src: TC,
            key: TransportedKey::Network { key, sequence: SEQUENCE, source: TC, broadcast: false },
            authorizes: false,
        }) if key == KEY
    ));
    assert_eq!(child.stats.policy_dropped, 0);
    assert!(
        child.next_action().is_some(),
        "accepted relay must be acknowledged"
    );
}

#[test]
fn network_key_relay_rejects_invalid_origin_security_and_descriptor() {
    for (name, parent, sender, secured, source, destination) in [
        ("non-parent", None, (PARENT_SHORT, PARENT), true, TC, CHILD),
        (
            "wrong parent IEEE",
            Some((PARENT_SHORT, OTHER)),
            (PARENT_SHORT, PARENT),
            true,
            TC,
            CHILD,
        ),
        (
            "wrong parent short address",
            Some((ShortAddress(0x4321), PARENT)),
            (PARENT_SHORT, PARENT),
            true,
            TC,
            CHILD,
        ),
        (
            "unsecured",
            Some((PARENT_SHORT, PARENT)),
            (PARENT_SHORT, PARENT),
            false,
            TC,
            CHILD,
        ),
        (
            "wrong Trust Center",
            Some((PARENT_SHORT, PARENT)),
            (PARENT_SHORT, PARENT),
            true,
            OTHER,
            CHILD,
        ),
        (
            "wrong destination",
            Some((PARENT_SHORT, PARENT)),
            (PARENT_SHORT, PARENT),
            true,
            TC,
            OTHER,
        ),
    ] {
        let mut child = receive_relay(parent, sender, secured, source, destination);
        assert!(
            child.next_event().is_none(),
            "{name} relay changed security state"
        );
        assert_eq!(child.stats.policy_dropped, 1, "{name}");
        assert!(
            child.next_action().is_none(),
            "{name} relay was acknowledged"
        );
    }
}
