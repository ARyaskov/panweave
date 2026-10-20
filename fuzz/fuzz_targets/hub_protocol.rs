//! Hub Protocol frames and messages from a host never panic, and every
//! message that decodes re-encodes to the same message.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_hub::protocol::Message;
use panweave_hub::protocol::frame::{FrameDecoder, MAX_BODY, MAX_WIRE};

fuzz_target!(|data: &[u8]| {
    let mut dec = FrameDecoder::new();
    for &b in data {
        if let Some(Ok(body)) = dec.push(b) {
            if let Ok(m) = Message::decode(body) {
                let mut out = [0u8; MAX_BODY];
                let n = m.encode(&mut out).expect("re-encode");
                assert_eq!(Message::decode(&out[..n]).expect("re-decode"), m);
                let mut wire = [0u8; MAX_WIRE];
                m.encode_frame(&mut wire).expect("frame");
            }
        }
    }
    if let Ok(m) = Message::decode(data) {
        let mut out = [0u8; MAX_BODY];
        let n = m.encode(&mut out).expect("re-encode");
        assert_eq!(Message::decode(&out[..n]).expect("re-decode"), m);
    }
});
