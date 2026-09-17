//! MAC frame decoding never panics and re-encodes what it decoded.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_codec::{Decode, Encode};
use panweave_mac::frame::{Beacon, Frame, MacCommand};

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = Frame::decode_exact(data) {
        let mut buf = [0u8; 256];
        if let Ok(n) = f.encode_to_slice(&mut buf) {
            let again = Frame::decode_exact(&buf[..n]).expect("re-decode");
            assert_eq!(again.payload, f.payload);
        }
        let _ = MacCommand::decode_exact(f.payload);
        let _ = Beacon::decode_exact(f.payload);
    }
});
