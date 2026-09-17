//! The APS layer survives arbitrary NWK data indications (with and
//! without a link key installed) and never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_aps::layer::{Aps, ApsConfig, DeviceState, NwkView};
use panweave_security::cipher::SoftwareAes;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_types::time::Instant;
use panweave_types::{ExtendedAddress, Key128, KeyAttributes, ShortAddress};

struct View;

impl NwkView for View {
    fn ieee_of(&self, s: ShortAddress) -> Option<ExtendedAddress> {
        (s == ShortAddress(0x0001)).then_some(ExtendedAddress(0xB))
    }
    fn short_of(&self, i: ExtendedAddress) -> Option<ShortAddress> {
        (i == ExtendedAddress(0xB)).then_some(ShortAddress(0x0001))
    }
    fn unauthenticated_child(&self, _: ExtendedAddress) -> Option<ShortAddress> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let mut aps = Aps::<SoftwareAes, 4, 4, 4, 4>::new(
        ExtendedAddress(0xA),
        ApsConfig {
            is_trust_center: data.first().is_some_and(|b| b & 1 != 0),
            ..ApsConfig::default()
        },
    );
    let mut e = LinkKeyEntry::provisional(
        ExtendedAddress(0xB),
        Key128::from_bytes([3; 16]),
        LinkKeyKind::Unique,
    );
    e.attributes = KeyAttributes::VerifiedKey;
    let _ = aps.security.install(e);
    aps.set_network_state(ShortAddress(0x0000), DeviceState::JoinedAuthorized);
    aps.poll_timers(Instant::from_millis(1000));
    let view = View;
    for chunk in data.split(|b| *b == 0xFE) {
        let mut buf = chunk.to_vec();
        let secured = chunk.len() % 2 == 0;
        let _ = aps.on_nwk_data(
            &mut buf,
            ShortAddress(0x0001),
            ShortAddress(0x0000),
            None,
            secured,
            200,
            &view,
        );
        while aps.next_action().is_some() {}
        while aps.next_event().is_some() {}
    }
    aps.poll_timers(Instant::from_millis(20_000));
});
