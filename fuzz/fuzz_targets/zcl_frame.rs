//! ZCL header, values and global command records never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_codec::{Decode, Reader, Writer};
use panweave_zcl::frame::Frame;
use panweave_zcl::global::*;
use panweave_zcl::types::{DataType, Value};

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = Frame::decode_exact(data) {
        for r in Records::<ReadAttributeStatus>::new(f.payload) {
            let _ = r;
        }
        for r in Records::<AttributeValue>::new(f.payload) {
            let _ = r;
        }
        for r in Records::<WriteAttributeStatus>::new(f.payload) {
            let _ = r;
        }
        for r in Records::<ReportingConfig>::new(f.payload) {
            let _ = r;
        }
        for r in Records::<ConfigureReportingStatus>::new(f.payload) {
            let _ = r;
        }
        for r in Records::<ReadReportingConfigStatus>::new(f.payload) {
            let _ = r;
        }
        let _ = DiscoverAttributesResponse::parse(f.payload, false).map(|r| r.iter().count());
        let _ = DiscoverAttributesResponse::parse(f.payload, true).map(|r| r.iter().count());
        let _ = DiscoverCommandsResponse::decode_exact(f.payload);
    }
    if let Some((&ty, rest)) = data.split_first() {
        let mut r = Reader::new(rest);
        let t = DataType::from_id(ty);
        let _ = t.value_len(rest);
        if let Ok(v) = Value::decode(&mut r, t) {
            assert_eq!(v.data_type().id(), ty);
            let mut out = [0u8; 512];
            let mut w = Writer::new(&mut out);
            if v.encode(&mut w).is_ok() {
                assert_eq!(w.position(), v.encoded_len());
            }
        }
    }
});
