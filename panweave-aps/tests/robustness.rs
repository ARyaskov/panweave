//! Property tests: APS header and command decoding never panic and the
//! layer survives arbitrary indications.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::command::ApsCommand;
use panweave_aps::frame::Header;
use panweave_aps::layer::{Aps, ApsConfig, DeviceState, NwkView};
use panweave_codec::{Decode, Encode};
use panweave_security::cipher::SoftwareAes;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_types::time::Instant;
use panweave_types::{ExtendedAddress, Key128, KeyAttributes, ShortAddress};
use proptest::prelude::*;

struct View;

impl NwkView for View {
    fn ieee_of(&self, s: ShortAddress) -> Option<ExtendedAddress> {
        (s == ShortAddress(1)).then_some(ExtendedAddress(0xB))
    }
    fn short_of(&self, i: ExtendedAddress) -> Option<ShortAddress> {
        (i == ExtendedAddress(0xB)).then_some(ShortAddress(1))
    }
    fn unauthenticated_child(&self, _: ExtendedAddress) -> Option<ShortAddress> {
        None
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn aps_decoding_is_total(data in proptest::collection::vec(any::<u8>(), 0..110)) {
        if let Ok((h, n)) = Header::decode_prefix(&data) {
            let mut buf = [0u8; 64];
            if let Ok(m) = h.encode_to_slice(&mut buf) {
                let (again, _) = Header::decode_prefix(&buf[..m]).expect("re-decode");
                prop_assert_eq!(again, h);
            }
            if let Ok(c) = ApsCommand::decode_exact(&data[n..]) {
                let mut out = [0u8; 300];
                if let Ok(k) = c.encode_to_slice(&mut out) {
                    prop_assert!(ApsCommand::decode_exact(&out[..k]).is_ok());
                }
            }
        }
    }

    #[test]
    fn aps_layer_survives_arbitrary_frames(
        frames in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..108), 0..6),
        tc in any::<bool>(),
    ) {
        let mut aps = Aps::<SoftwareAes, 4, 4, 4, 4>::new(
            ExtendedAddress(0xA),
            ApsConfig { is_trust_center: tc, ..ApsConfig::default() },
        );
        let mut e = LinkKeyEntry::provisional(
            ExtendedAddress(0xB),
            Key128::from_bytes([3; 16]),
            LinkKeyKind::Unique,
        );
        e.attributes = KeyAttributes::VerifiedKey;
        let _ = aps.security.install(e);
        aps.set_network_state(ShortAddress(0), DeviceState::JoinedAuthorized);
        aps.poll_timers(Instant::from_millis(1000));
        for (i, f) in frames.into_iter().enumerate() {
            let mut buf = f;
            let _ = aps.on_nwk_data(
                &mut buf,
                ShortAddress(1),
                ShortAddress(0),
                None,
                i % 2 == 0,
                200,
                &View,
            );
            while aps.next_action().is_some() {}
            while aps.next_event().is_some() {}
        }
        aps.poll_timers(Instant::from_millis(20_000));
    }
}
