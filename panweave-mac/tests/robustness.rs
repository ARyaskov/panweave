//! Property tests: frame decoding never panics on arbitrary input and
//! decoded frames re-encode to equivalent frames.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::{Decode, Encode};
use panweave_mac::frame::{Beacon, Frame, MacCommand};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn frame_decoding_is_total(data in proptest::collection::vec(any::<u8>(), 0..140)) {
        if let Ok(f) = Frame::decode_exact(&data) {
            let mut buf = [0u8; 256];
            if let Ok(n) = f.encode_to_slice(&mut buf) {
                let again = Frame::decode_exact(&buf[..n]).expect("re-decode");
                prop_assert_eq!(again.payload, f.payload);
            }
            let _ = MacCommand::decode_exact(f.payload);
            let _ = Beacon::decode_exact(f.payload);
        }
    }
}
