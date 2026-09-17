//! NWK header, command and beacon payload decoding never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_codec::{Decode, Encode};
use panweave_nwk::beacon::BeaconPayload;
use panweave_nwk::command::NwkCommand;
use panweave_nwk::frame::Header;

fuzz_target!(|data: &[u8]| {
    if let Ok((h, n)) = Header::decode_prefix(data) {
        let mut buf = [0u8; 256];
        if let Ok(m) = h.encode_to_slice(&mut buf) {
            let (again, _) = Header::decode_prefix(&buf[..m]).expect("re-decode");
            assert_eq!(again.encoded_len(), h.encoded_len());
        }
        let _ = NwkCommand::decode_exact(&data[n..]);
    }
    let _ = NwkCommand::decode_exact(data);
    let _ = BeaconPayload::decode_exact(data);
});
