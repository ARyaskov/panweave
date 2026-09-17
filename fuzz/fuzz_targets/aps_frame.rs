//! APS header and command decoding never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_aps::command::ApsCommand;
use panweave_aps::frame::Header;
use panweave_codec::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    if let Ok((h, n)) = Header::decode_prefix(data) {
        let mut buf = [0u8; 64];
        if let Ok(m) = h.encode_to_slice(&mut buf) {
            let (again, _) = Header::decode_prefix(&buf[..m]).expect("re-decode");
            assert_eq!(again, h);
        }
        if let Ok(c) = ApsCommand::decode_exact(&data[n..]) {
            let mut out = [0u8; 300];
            if let Ok(k) = c.encode_to_slice(&mut out) {
                let _ = ApsCommand::decode_exact(&out[..k]);
            }
        }
    }
});
