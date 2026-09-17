//! Property tests: ZCL frames, records and values never panic and values
//! round-trip.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::{Decode, Reader, Writer};
use panweave_zcl::frame::Frame;
use panweave_zcl::global::*;
use panweave_zcl::types::{DataType, Value};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn zcl_decoding_is_total(data in proptest::collection::vec(any::<u8>(), 0..90)) {
        if let Ok(f) = Frame::decode_exact(&data) {
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
        }
        if let Some((&ty, rest)) = data.split_first() {
            let t = DataType::from_id(ty);
            let _ = t.value_len(rest);
            let mut r = Reader::new(rest);
            if let Ok(v) = Value::decode(&mut r, t) {
                prop_assert_eq!(v.data_type().id(), ty);
                let mut out = [0u8; 256];
                let mut w = Writer::new(&mut out);
                if v.encode(&mut w).is_ok() {
                    prop_assert_eq!(w.position(), v.encoded_len());
                    let mut r2 = Reader::new(w.written());
                    let again = Value::decode(&mut r2, t).expect("re-decode");
                    prop_assert_eq!(again.encoded_len(), v.encoded_len());
                }
            }
        }
    }
}
