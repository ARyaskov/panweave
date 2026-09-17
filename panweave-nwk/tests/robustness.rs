//! Property tests: NWK header, command, beacon payload and TLV decoding
//! never panic on arbitrary input.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::tlv::TlvSet;
use panweave_codec::{Decode, Encode};
use panweave_nwk::beacon::BeaconPayload;
use panweave_nwk::command::NwkCommand;
use panweave_nwk::frame::Header;
use panweave_nwk::tlv::GlobalTlvs;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn nwk_decoding_is_total(data in proptest::collection::vec(any::<u8>(), 0..120)) {
        if let Ok((h, n)) = Header::decode_prefix(&data) {
            let mut buf = [0u8; 256];
            if let Ok(m) = h.encode_to_slice(&mut buf) {
                let (again, _) = Header::decode_prefix(&buf[..m]).expect("re-decode");
                prop_assert_eq!(again.encoded_len(), h.encoded_len());
            }
            let _ = NwkCommand::decode_exact(&data[n..]);
        }
        let _ = NwkCommand::decode_exact(&data);
        let _ = BeaconPayload::decode_exact(&data);
        if let Ok(set) = TlvSet::validate(&data, |_| false) {
            let _ = set.key_negotiation_methods();
            let _ = set.fragmentation_parameters();
            let _ = set.router_information();
            let _ = set.configuration_parameters();
            let _ = set.joiner_encapsulation().map(|s| s.iter().count());
        }
    }
}
